package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

const (
	DefaultMaxStorageBytes int64 = 20 * 1024 * 1024 * 1024 // 20 GiB planning target
	DefaultMaxRecordBytes  int64 = evidence.MaxEvidenceBytes // 100 MiB bounded record
	LockFileName                 = ".lock"
	ManifestFileName             = "manifest.json"
	StagingDirName               = "staging"
	BlobsDirName                 = "blobs"
)

var (
	ErrLockBusy             = errors.New("storage lock busy: another writer holds exclusive lock")
	ErrClosed               = errors.New("storage adapter closed")
	ErrMissingIdentity      = errors.New("missing identity")
	ErrExpiredIdentity      = errors.New("expired identity")
	ErrReplayedIdentity     = errors.New("replayed identity")
	ErrScopeMismatch        = errors.New("unrelated owner or object scope")
	ErrInvalidSignature     = errors.New("forged or invalid signature")
	ErrUnauthorized         = errors.New("unauthorized role")
	ErrUnavailableProvider  = errors.New("unavailable identity provider")
	ErrForgedHeader         = errors.New("forged header cannot authorize sensitive action")
	ErrWidenedPath          = errors.New("widened path or invalid identifier")
	ErrOperationConflict    = errors.New("operation ID reused with conflicting parameters")
	ErrDiskFull             = errors.New("disk full: write failed")
	ErrStorageQuotaExceeded = errors.New("storage quota exceeded")
	ErrPayloadTooLarge      = errors.New("payload exceeds maximum record bytes")
	ErrDigestMismatch       = errors.New("payload sha256 does not match declared digest")
	ErrInvalidManifest      = errors.New("invalid evidence manifest fields")
	ErrSealedBytesImmutable = errors.New("sealed source bytes never modified: evidence already exists with different content")
	ErrMissingReference     = errors.New("missing reference: blob not found on disk")
	ErrCorruptedReference   = errors.New("corrupted reference: blob digest mismatch")
	ErrCorruptedManifest    = errors.New("corrupted manifest")
	ErrInterrupted          = errors.New("write interrupted before manifest commit")
)

var (
	identifierRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	digestRegex     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func isValidIdentifier(s string) bool {
	return identifierRegex.MatchString(s) && !strings.Contains(s, "..") && !strings.ContainsAny(s, "/\\")
}

type Identity struct {
	Principal string `json:"principal"`
	Role      string `json:"role"`
	CaseScope string `json:"case_scope"`
	PublicKey string `json:"public_key"`
	ExpiresAt string `json:"expires_at"`
	Signature string `json:"signature"`
	Provider  string `json:"provider,omitempty"`
}

func CanonicalSigningBytes(opID, caseID, evidenceID, sha256Hex, expiresAt string) []byte {
	return []byte(fmt.Sprintf("breachatlas:v1:%s:%s:%s:%s:%s", opID, caseID, evidenceID, sha256Hex, expiresAt))
}

type WriteRequest struct {
	OperationID string            `json:"operation_id"`
	Manifest    evidence.Manifest `json:"manifest"`
	Payload     []byte            `json:"payload"`
	Identity    Identity          `json:"identity"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type WriteResult struct {
	OperationID string `json:"operation_id"`
	Status      string `json:"status"`
	CaseID      string `json:"case_id"`
	EvidenceID  string `json:"evidence_id"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	CommittedAt string `json:"committed_at"`
	IsReplay    bool   `json:"is_replay"`
}

type OperationRecord struct {
	OperationID string `json:"operation_id"`
	CaseID      string `json:"case_id"`
	EvidenceID  string `json:"evidence_id"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	CommittedAt string `json:"committed_at"`
	Principal   string `json:"principal"`
}

type EvidenceRecord struct {
	CaseID      string `json:"case_id"`
	EvidenceID  string `json:"evidence_id"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	MediaType   string `json:"media_type"`
	AcquiredAt  string `json:"acquired_at"`
	CustodyRoot string `json:"custody_root"`
	BlobPath    string `json:"blob_path"`
	CommittedAt string `json:"committed_at"`
}

type StateManifest struct {
	SchemaVersion string                     `json:"schema_version"`
	Generation    int64                      `json:"generation"`
	CommittedAt   string                     `json:"committed_at"`
	TotalBytes    int64                      `json:"total_bytes"`
	Operations    map[string]OperationRecord `json:"operations"`
	Evidence      map[string]EvidenceRecord  `json:"evidence"`
}

type FaultInjection struct {
	FailBeforeStagingSync    bool
	FailBeforeManifestCommit bool
	SimulateDiskFull         bool
}

type Config struct {
	RootDir         string
	MaxStorageBytes int64
	MaxRecordBytes  int64
	SyncDir         bool
	Faults          FaultInjection
}

type Adapter struct {
	cfg      Config
	mu       sync.Mutex
	lockFile *os.File
	state    StateManifest
	closed   bool
}

func syncDir(dirPath string) error {
	d, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func Open(cfg Config) (*Adapter, error) {
	if cfg.RootDir == "" {
		return nil, errors.New("RootDir is required")
	}
	if cfg.MaxStorageBytes <= 0 {
		cfg.MaxStorageBytes = DefaultMaxStorageBytes
	}
	if cfg.MaxRecordBytes <= 0 {
		cfg.MaxRecordBytes = DefaultMaxRecordBytes
	}

	if err := os.MkdirAll(filepath.Join(cfg.RootDir, StagingDirName), 0750); err != nil {
		return nil, fmt.Errorf("failed to create staging dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.RootDir, BlobsDirName), 0750); err != nil {
		return nil, fmt.Errorf("failed to create blobs dir: %w", err)
	}

	lockPath := filepath.Join(cfg.RootDir, LockFileName)
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}

	err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		_ = lockFile.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLockBusy
		}
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	a := &Adapter{
		cfg:      cfg,
		lockFile: lockFile,
		state: StateManifest{
			SchemaVersion: "1",
			Generation:    0,
			Operations:    make(map[string]OperationRecord),
			Evidence:      make(map[string]EvidenceRecord),
		},
	}

	if err := a.recoverUnlocked(context.Background()); err != nil {
		_ = a.closeUnlocked()
		return nil, err
	}

	return a, nil
}

func resolveSafeBlobPath(rootDir, blobRelPath string) (string, error) {
	if strings.TrimSpace(blobRelPath) == "" || strings.ContainsRune(blobRelPath, '\x00') || filepath.IsAbs(blobRelPath) {
		return "", fmt.Errorf("%w: invalid blob_path %q", ErrWidenedPath, blobRelPath)
	}
	for _, seg := range strings.FieldsFunc(blobRelPath, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return "", fmt.Errorf("%w: traversal segment in blob_path %q", ErrWidenedPath, blobRelPath)
		}
	}
	blobsRoot := filepath.Clean(filepath.Join(rootDir, BlobsDirName))
	blobPath := filepath.Clean(filepath.Join(rootDir, filepath.FromSlash(blobRelPath)))
	rel, err := filepath.Rel(blobsRoot, blobPath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: blob_path %q escapes blobs directory", ErrWidenedPath, blobRelPath)
	}
	info, err := os.Lstat(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %s", ErrMissingReference, blobRelPath)
		}
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: symlink rejected at %s", ErrWidenedPath, blobRelPath)
	}
	return blobPath, nil
}

func (a *Adapter) recoverUnlocked(ctx context.Context) error {
	manifestPath := filepath.Join(a.cfg.RootDir, ManifestFileName)
	if data, err := os.ReadFile(manifestPath); err == nil {
		var manifest StateManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			return fmt.Errorf("%w: %s", ErrCorruptedManifest, err)
		}
		if manifest.SchemaVersion != "1" {
			return fmt.Errorf("%w: unsupported schema version %q", ErrCorruptedManifest, manifest.SchemaVersion)
		}
		if manifest.Operations == nil {
			manifest.Operations = make(map[string]OperationRecord)
		}
		if manifest.Evidence == nil {
			manifest.Evidence = make(map[string]EvidenceRecord)
		}
		a.state = manifest
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	// Reconcile orphan staging files left behind by crashes or interruptions
	stagingDir := filepath.Join(a.cfg.RootDir, StagingDirName)
	if entries, err := os.ReadDir(stagingDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".tmp") {
				_ = os.Remove(filepath.Join(stagingDir, entry.Name()))
			}
		}
	}

	// Verify referential integrity of committed evidence (streaming to bound memory)
	for _, rec := range a.state.Evidence {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		blobPath, err := resolveSafeBlobPath(a.cfg.RootDir, rec.BlobPath)
		if err != nil {
			return err
		}
		f, err := os.Open(blobPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%w: %s", ErrMissingReference, rec.BlobPath)
			}
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return err
		}
		if fi.Size() != rec.SizeBytes {
			_ = f.Close()
			return fmt.Errorf("%w: %s size mismatch", ErrCorruptedReference, rec.BlobPath)
		}
		hasher := sha256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			_ = f.Close()
			return err
		}
		_ = f.Close()
		if hex.EncodeToString(hasher.Sum(nil)) != rec.SHA256 {
			return fmt.Errorf("%w: %s digest mismatch", ErrCorruptedReference, rec.BlobPath)
		}
	}

	return nil
}

func (a *Adapter) Recover(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	return a.recoverUnlocked(ctx)
}

func (a *Adapter) authorizeIdentity(req WriteRequest) error {
	id := req.Identity
	if id.Principal == "" || id.PublicKey == "" || id.Signature == "" || id.ExpiresAt == "" {
		return ErrMissingIdentity
	}
	if !isValidIdentifier(id.Principal) {
		return ErrWidenedPath
	}
	if id.Provider != "" && id.Provider != "local" && id.Provider != "breachatlas" {
		return ErrUnavailableProvider
	}
	exp, err := time.Parse(time.RFC3339Nano, id.ExpiresAt)
	if err != nil || time.Now().After(exp) {
		return ErrExpiredIdentity
	}
	if id.Role != "analyst" && id.Role != "lead" && id.Role != "admin" {
		return ErrUnauthorized
	}
	if id.CaseScope != req.Manifest.CaseID {
		return ErrScopeMismatch
	}

	for rawKey, val := range req.Headers {
		key := strings.ToLower(strings.TrimSpace(rawKey))
		trimmedVal := strings.TrimSpace(val)
		switch key {
		case "x-role":
			if trimmedVal != "" && trimmedVal != id.Role {
				return ErrForgedHeader
			}
		case "x-case-scope":
			if trimmedVal != "" && trimmedVal != id.CaseScope {
				return ErrForgedHeader
			}
		case "x-identity-override", "x-forwarded-user", "x-forwarded-host", "x-forwarded-role", "x-auth-user", "x-user-override":
			return ErrForgedHeader
		case "x-provider":
			if trimmedVal != "" && trimmedVal != "local" && trimmedVal != "breachatlas" {
				return ErrUnavailableProvider
			}
		}
	}

	pubBytes, err := hex.DecodeString(id.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return ErrInvalidSignature
	}
	sigBytes, err := hex.DecodeString(id.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}

	canonical := CanonicalSigningBytes(req.OperationID, req.Manifest.CaseID, req.Manifest.EvidenceID, req.Manifest.SHA256, id.ExpiresAt)
	if !ed25519.Verify(pubBytes, canonical, sigBytes) {
		for _, op := range a.state.Operations {
			if op.OperationID != req.OperationID {
				oldCanon := CanonicalSigningBytes(op.OperationID, op.CaseID, op.EvidenceID, op.SHA256, id.ExpiresAt)
				if ed25519.Verify(pubBytes, oldCanon, sigBytes) {
					return ErrReplayedIdentity
				}
			}
		}
		return ErrInvalidSignature
	}

	return nil
}

func (a *Adapter) CommitWrite(ctx context.Context, req WriteRequest) (*WriteResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return nil, ErrClosed
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if req.OperationID == "" {
		return nil, errors.New("operation_id is required")
	}
	if !isValidIdentifier(req.OperationID) {
		return nil, ErrWidenedPath
	}

	if req.Manifest.CaseID == "" || req.Manifest.EvidenceID == "" {
		return nil, errors.New("manifest case_id and evidence_id are required")
	}
	if !isValidIdentifier(req.Manifest.CaseID) || !isValidIdentifier(req.Manifest.EvidenceID) {
		return nil, ErrWidenedPath
	}
	if !digestRegex.MatchString(req.Manifest.SHA256) {
		return nil, ErrDigestMismatch
	}

	// Negative cases: authorize identity before any idempotency lookup or sensitive side effect
	if err := a.authorizeIdentity(req); err != nil {
		return nil, err
	}

	// Stable operation IDs & idempotency: return committed outcome if already replayed
	if existingOp, exists := a.state.Operations[req.OperationID]; exists {
		if existingOp.CaseID != req.Manifest.CaseID || existingOp.EvidenceID != req.Manifest.EvidenceID || existingOp.SHA256 != req.Manifest.SHA256 {
			return nil, ErrOperationConflict
		}
		if existingOp.Principal != req.Identity.Principal && req.Identity.Role != "admin" {
			return nil, ErrScopeMismatch
		}
		return &WriteResult{
			OperationID: req.OperationID,
			Status:      "replayed",
			CaseID:      existingOp.CaseID,
			EvidenceID:  existingOp.EvidenceID,
			SHA256:      existingOp.SHA256,
			SizeBytes:   existingOp.SizeBytes,
			CommittedAt: existingOp.CommittedAt,
			IsReplay:    true,
		}, nil
	}

	if req.Manifest.SizeBytes > a.cfg.MaxRecordBytes || int64(len(req.Payload)) > a.cfg.MaxRecordBytes {
		return nil, ErrPayloadTooLarge
	}
	if req.Manifest.SizeBytes != int64(len(req.Payload)) {
		return nil, errors.New("manifest size_bytes does not match payload length")
	}
	if a.state.TotalBytes+int64(len(req.Payload)) > a.cfg.MaxStorageBytes {
		return nil, ErrStorageQuotaExceeded
	}

	evidenceKey := req.Manifest.CaseID + "/" + req.Manifest.EvidenceID
	if _, exists := a.state.Evidence[evidenceKey]; exists {
		return nil, ErrSealedBytesImmutable
	}

	if a.cfg.Faults.SimulateDiskFull || a.cfg.Faults.FailBeforeStagingSync {
		return nil, ErrDiskFull
	}

	stagingFileName := fmt.Sprintf("%s_%d.tmp", req.OperationID, time.Now().UnixNano())
	stagingPath := filepath.Join(a.cfg.RootDir, StagingDirName, stagingFileName)

	f, err := os.OpenFile(stagingPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create staging file: %w", err)
	}

	hasher := sha256.New()
	writer := io.MultiWriter(f, hasher)
	if _, err := writer.Write(req.Payload); err != nil {
		_ = f.Close()
		_ = os.Remove(stagingPath)
		return nil, fmt.Errorf("failed to write staging data: %w", err)
	}

	computedDigest := hex.EncodeToString(hasher.Sum(nil))
	if computedDigest != req.Manifest.SHA256 {
		_ = f.Close()
		_ = os.Remove(stagingPath)
		return nil, ErrDigestMismatch
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(stagingPath)
		return nil, fmt.Errorf("failed to sync staging file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(stagingPath)
		return nil, err
	}

	if a.cfg.SyncDir {
		_ = syncDir(filepath.Join(a.cfg.RootDir, StagingDirName))
	}

	if a.cfg.Faults.FailBeforeManifestCommit {
		return nil, ErrInterrupted
	}

	blobRelPath := filepath.Join(BlobsDirName, computedDigest)
	blobAbsPath := filepath.Join(a.cfg.RootDir, blobRelPath)

	if err := os.Rename(stagingPath, blobAbsPath); err != nil {
		_ = os.Remove(stagingPath)
		return nil, fmt.Errorf("failed to move staged blob: %w", err)
	}

	if a.cfg.SyncDir {
		_ = syncDir(filepath.Join(a.cfg.RootDir, BlobsDirName))
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	newGeneration := a.state.Generation + 1

	newOps := make(map[string]OperationRecord, len(a.state.Operations)+1)
	for k, v := range a.state.Operations {
		newOps[k] = v
	}
	newEv := make(map[string]EvidenceRecord, len(a.state.Evidence)+1)
	for k, v := range a.state.Evidence {
		newEv[k] = v
	}

	opRec := OperationRecord{
		OperationID: req.OperationID,
		CaseID:      req.Manifest.CaseID,
		EvidenceID:  req.Manifest.EvidenceID,
		SHA256:      computedDigest,
		SizeBytes:   req.Manifest.SizeBytes,
		CommittedAt: now,
		Principal:   req.Identity.Principal,
	}
	newOps[req.OperationID] = opRec

	evRec := EvidenceRecord{
		CaseID:      req.Manifest.CaseID,
		EvidenceID:  req.Manifest.EvidenceID,
		SHA256:      computedDigest,
		SizeBytes:   req.Manifest.SizeBytes,
		MediaType:   req.Manifest.MediaType,
		AcquiredAt:  req.Manifest.AcquiredAt,
		CustodyRoot: req.Manifest.CustodyRoot,
		BlobPath:    blobRelPath,
		CommittedAt: now,
	}
	newEv[evidenceKey] = evRec

	newState := StateManifest{
		SchemaVersion: "1",
		Generation:    newGeneration,
		CommittedAt:   now,
		TotalBytes:    a.state.TotalBytes + req.Manifest.SizeBytes,
		Operations:    newOps,
		Evidence:      newEv,
	}

	stateBytes, err := json.MarshalIndent(newState, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode state: %w", err)
	}

	tmpManifestName := fmt.Sprintf("manifest.%d.tmp", newGeneration)
	tmpManifestPath := filepath.Join(a.cfg.RootDir, StagingDirName, tmpManifestName)

	if err := os.WriteFile(tmpManifestPath, stateBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write state tmp: %w", err)
	}
	tmpF, err := os.Open(tmpManifestPath)
	if err == nil {
		_ = tmpF.Sync()
		_ = tmpF.Close()
	}

	manifestDest := filepath.Join(a.cfg.RootDir, ManifestFileName)
	if err := os.Rename(tmpManifestPath, manifestDest); err != nil {
		_ = os.Remove(tmpManifestPath)
		return nil, fmt.Errorf("failed to commit manifest atomically: %w", err)
	}

	if a.cfg.SyncDir {
		_ = syncDir(a.cfg.RootDir)
	}

	a.state = newState

	return &WriteResult{
		OperationID: req.OperationID,
		Status:      "committed",
		CaseID:      req.Manifest.CaseID,
		EvidenceID:  req.Manifest.EvidenceID,
		SHA256:      computedDigest,
		SizeBytes:   req.Manifest.SizeBytes,
		CommittedAt: now,
		IsReplay:    false,
	}, nil
}

func (a *Adapter) GetEvidence(caseID, evidenceID string) ([]byte, *EvidenceRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return nil, nil, ErrClosed
	}

	if !isValidIdentifier(caseID) || !isValidIdentifier(evidenceID) {
		return nil, nil, ErrWidenedPath
	}

	key := caseID + "/" + evidenceID
	rec, exists := a.state.Evidence[key]
	if !exists {
		return nil, nil, os.ErrNotExist
	}

	blobPath, err := resolveSafeBlobPath(a.cfg.RootDir, rec.BlobPath)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("%w: %s", ErrMissingReference, rec.BlobPath)
		}
		return nil, nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if fi.Size() != rec.SizeBytes {
		return nil, nil, fmt.Errorf("%w: %s size mismatch", ErrCorruptedReference, rec.BlobPath)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}

	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != rec.SHA256 {
		return nil, nil, fmt.Errorf("%w: %s digest mismatch", ErrCorruptedReference, rec.BlobPath)
	}

	return data, &rec, nil
}

func (a *Adapter) GetOperation(opID string) (*OperationRecord, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, ok := a.state.Operations[opID]
	if !ok {
		return nil, false
	}
	return &rec, true
}

func (a *Adapter) CurrentState() StateManifest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state
}

type CaseProjection struct {
	CaseID        string   `json:"case_id"`
	EvidenceCount int      `json:"evidence_count"`
	TotalBytes    int64    `json:"total_bytes"`
	EvidenceIDs   []string `json:"evidence_ids"`
}

type Projection struct {
	TotalCases    int                       `json:"total_cases"`
	TotalEvidence int                       `json:"total_evidence"`
	TotalBytes    int64                     `json:"total_bytes"`
	Cases         map[string]CaseProjection `json:"cases"`
}

func (a *Adapter) RebuildProjection() (*Projection, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return nil, ErrClosed
	}

	proj := &Projection{
		Cases: make(map[string]CaseProjection),
	}

	for _, ev := range a.state.Evidence {
		proj.TotalEvidence++
		proj.TotalBytes += ev.SizeBytes

		cp, exists := proj.Cases[ev.CaseID]
		if !exists {
			cp = CaseProjection{
				CaseID: ev.CaseID,
			}
		}
		cp.EvidenceCount++
		cp.TotalBytes += ev.SizeBytes
		cp.EvidenceIDs = append(cp.EvidenceIDs, ev.EvidenceID)
		proj.Cases[ev.CaseID] = cp
	}

	proj.TotalCases = len(proj.Cases)
	return proj, nil
}

func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closeUnlocked()
}

func (a *Adapter) closeUnlocked() error {
	if a.closed {
		return nil
	}
	a.closed = true
	var err error
	if a.lockFile != nil {
		_ = syscall.Flock(int(a.lockFile.Fd()), syscall.LOCK_UN)
		err = a.lockFile.Close()
		a.lockFile = nil
	}
	return err
}

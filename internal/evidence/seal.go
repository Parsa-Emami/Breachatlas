package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	DefaultMaxSealStorageBytes int64 = 20 * 1024 * 1024 * 1024 // 20 GiB
	DefaultMaxSealRetries      int   = 3
	sealBlobsDir                     = "blobs/sha256"
	sealManifestsDir                 = "manifests"
	sealStagingDir                   = "staging"
	sealIndexFile                    = "seal-index.json"
	sealLockFile                     = ".seal.lock"
)

var (
	ErrSealStoreRequired        = errors.New("seal store root directory is required")
	ErrSealStoreClosed          = errors.New("seal store closed")
	ErrSealLockBusy             = errors.New("seal store lock busy: another writer holds exclusive lock")
	ErrQuarantinedInputRequired = errors.New("completed unsealed quarantined upload is required")
	ErrManifestInvalid          = errors.New("invalid seal manifest metadata")
	ErrSealInterrupted          = errors.New("seal writer interrupted at staged-byte/manifest boundary")
	ErrSealDiskFull             = errors.New("disk full: seal write aborted")
	ErrStorageQuotaExceeded     = errors.New("seal storage quota exceeded")
	ErrOperationConflict        = errors.New("operation_id reused with conflicting seal parameters")
	ErrRetryLimitExceeded       = errors.New("seal retry limit exceeded")
)

// SealFaults enables deterministic failure injection at durability boundaries in tests.
type SealFaults struct {
	SimulateDiskFull              bool
	FailAfterBlobSyncBeforeManifest bool
}

// SealConfig configures a content-addressed evidence seal store.
type SealConfig struct {
	RootDir         string
	QuarantineDir   string
	MaxStorageBytes int64
	MaxRetries      int
	BufferSize      int
	SyncDir         bool
	Faults          SealFaults
}

// SealRequest describes an idempotent request to seal a quarantined upload.
type SealRequest struct {
	OperationID    string             `json:"operation_id"`
	Quarantined    *QuarantinedUpload `json:"quarantined"`
	ExpectedSHA256 string             `json:"expected_sha256,omitempty"`
	AcquiredAt     string             `json:"acquired_at"`
	CustodyRoot    string             `json:"custody_root"`
	Attempt        int                `json:"attempt,omitempty"`
}

// SealedManifest represents a durable, content-addressed sealed evidence manifest.
type SealedManifest struct {
	SchemaVersion    string `json:"schema_version"`
	ManifestDigest   string `json:"manifest_digest"`
	Generation       uint64 `json:"generation"`
	OperationID      string `json:"operation_id"`
	CaseID           string `json:"case_id"`
	EvidenceID       string `json:"evidence_id"`
	SHA256           string `json:"sha256"`
	SizeBytes        int64  `json:"size_bytes"`
	MediaType        string `json:"media_type"`
	AcquiredAt       string `json:"acquired_at"`
	CustodyRoot      string `json:"custody_root"`
	BlobRelPath      string `json:"blob_rel_path"`
	Sealed           bool   `json:"sealed"`
	SealedAt         string `json:"sealed_at"`
	IdempotentReplay bool   `json:"idempotent_replay,omitempty"`
}

// OrphanReport summarizes staging temps and uncommitted orphan blobs discovered during recovery.
type OrphanReport struct {
	CleanedStagingFiles []string `json:"cleaned_staging_files"`
	OrphanBlobs         []string `json:"orphan_blobs"`
	ReclaimedOrphanBlobs []string `json:"reclaimed_orphan_blobs"`
}

type sealIndex struct {
	SchemaVersion string                    `json:"schema_version"`
	Generation    uint64                    `json:"generation"`
	TotalBytes    int64                     `json:"total_bytes"`
	Operations    map[string]SealedManifest `json:"operations"`
	Manifests     map[string]SealedManifest `json:"manifests"` // "caseID/evidenceID" -> SealedManifest
}

// SealStore manages durable content-addressed blob writes and atomic manifest seals.
type SealStore struct {
	mu            sync.Mutex
	cfg           SealConfig
	rootDir       string
	quarantineDir string
	maxStorage    int64
	maxRetries    int
	bufSize       int
	lockFile      *os.File
	closed        bool
	index         sealIndex
}

func resolveSafeExistingOrNewDir(dir string, requiredErr error) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", requiredErr
	}
	if strings.ContainsRune(dir, '\x00') {
		return "", fmt.Errorf("%w: null byte in directory path", ErrPathTraversal)
	}
	for _, seg := range strings.FieldsFunc(dir, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return "", fmt.Errorf("%w: traversal segment in directory path", ErrPathTraversal)
		}
	}
	absDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	exists, err := ensureNoSymlink(absDir)
	if err != nil {
		return "", err
	}
	if !exists {
		if err := os.MkdirAll(absDir, 0750); err != nil {
			return "", fmt.Errorf("create dir %s: %w", absDir, err)
		}
		if _, err := ensureNoSymlink(absDir); err != nil {
			return "", err
		}
	} else {
		info, err := os.Stat(absDir)
		if err != nil {
			return "", err
		}
		if !info.IsDir() {
			return "", fmt.Errorf("%w: %s is not a directory", ErrManifestInvalid, absDir)
		}
	}
	return absDir, nil
}

// OpenSealStore opens or creates a content-addressed seal store under cfg.RootDir,
// acquiring an exclusive writer lock and reconciling uncommitted staging files on startup.
func OpenSealStore(cfg SealConfig) (*SealStore, error) {
	rootDir, err := resolveSafeExistingOrNewDir(cfg.RootDir, ErrSealStoreRequired)
	if err != nil {
		return nil, err
	}

	var quarantineDir string
	if strings.TrimSpace(cfg.QuarantineDir) != "" {
		quarantineDir, err = resolveSafeExistingOrNewDir(cfg.QuarantineDir, ErrQuarantineRequired)
		if err != nil {
			return nil, err
		}
	}

	maxStorage := cfg.MaxStorageBytes
	if maxStorage == 0 {
		maxStorage = DefaultMaxSealStorageBytes
	}
	if maxStorage < 0 {
		return nil, fmt.Errorf("%w: max_storage_bytes must be non-negative", ErrManifestInvalid)
	}

	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = DefaultMaxSealRetries
	}

	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = DefaultStreamBufferSize
	}

	for _, rel := range []string{sealBlobsDir, sealManifestsDir, sealStagingDir} {
		sub := filepath.Join(rootDir, rel)
		if err := os.MkdirAll(sub, 0750); err != nil {
			return nil, fmt.Errorf("create seal store subdir %s: %w", rel, err)
		}
		if _, err := ensureNoSymlink(sub); err != nil {
			return nil, err
		}
	}

	lockPath := filepath.Join(rootDir, sealLockFile)
	if _, err := ensureNoSymlink(lockPath); err != nil {
		return nil, err
	}
	lockF, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open seal lock: %w", err)
	}
	if err := syscall.Flock(int(lockF.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockF.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrSealLockBusy
		}
		return nil, fmt.Errorf("acquire seal lock: %w", err)
	}

	s := &SealStore{
		cfg:           cfg,
		rootDir:       rootDir,
		quarantineDir: quarantineDir,
		maxStorage:    maxStorage,
		maxRetries:    maxRetries,
		bufSize:       bufSize,
		lockFile:      lockF,
		index: sealIndex{
			SchemaVersion: SchemaVersion,
			Operations:    make(map[string]SealedManifest),
			Manifests:     make(map[string]SealedManifest),
		},
	}

	if err := s.recoverOnOpenUnlocked(); err != nil {
		_ = s.closeUnlocked()
		return nil, err
	}

	return s, nil
}

func (s *SealStore) recoverOnOpenUnlocked() error {
	// Clean partial staging files (.tmp) before loading index/manifests so startup only
	// observes complete prior or newly committed manifests.
	if _, err := s.cleanStagingUnlocked(); err != nil {
		return err
	}

	indexPath := filepath.Join(s.rootDir, sealIndexFile)
	if _, err := ensureNoSymlink(indexPath); err != nil {
		return err
	}
	data, err := os.ReadFile(indexPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read seal index: %w", err)
	}

	var idx sealIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return fmt.Errorf("%w: corrupt seal index: %v", ErrManifestInvalid, err)
	}
	if idx.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported seal index version %q", ErrUnsupportedVersion, idx.SchemaVersion)
	}
	if idx.Operations == nil {
		idx.Operations = make(map[string]SealedManifest)
	}
	if idx.Manifests == nil {
		idx.Manifests = make(map[string]SealedManifest)
	}

	// Cross-check each indexed manifest against its durable manifest file and durable blob.
	for k, m := range idx.Manifests {
		manifestFull := filepath.Join(s.rootDir, sealManifestsDir, m.CaseID, m.EvidenceID+".manifest.json")
		if _, err := ensureNoSymlink(manifestFull); err != nil {
			return err
		}
		raw, err := os.ReadFile(manifestFull)
		if err != nil {
			return fmt.Errorf("%w: missing manifest file for %s: %v", ErrManifestInvalid, k, err)
		}
		var onDisk SealedManifest
		if err := json.Unmarshal(raw, &onDisk); err != nil {
			return fmt.Errorf("%w: corrupt manifest file for %s: %v", ErrManifestInvalid, k, err)
		}
		if onDisk.ManifestDigest != m.ManifestDigest || onDisk.SHA256 != m.SHA256 || !onDisk.Sealed {
			return fmt.Errorf("%w: manifest digest mismatch for %s", ErrManifestInvalid, k)
		}
		blobFull := filepath.Join(s.rootDir, onDisk.BlobRelPath)
		if err := checkWithinDir(s.rootDir, blobFull); err != nil {
			return err
		}
		if _, err := hashRegularFile(blobFull, onDisk.SHA256, onDisk.SizeBytes); err != nil {
			return fmt.Errorf("recover committed blob for %s: %w", k, err)
		}
	}

	s.index = idx
	return nil
}

func (s *SealStore) cleanStagingUnlocked() ([]string, error) {
	stagingPath := filepath.Join(s.rootDir, sealStagingDir)
	entries, err := os.ReadDir(stagingPath)
	if err != nil {
		return nil, err
	}
	var cleaned []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".tmp") {
			p := filepath.Join(stagingPath, entry.Name())
			if err := os.Remove(p); err == nil {
				cleaned = append(cleaned, entry.Name())
			}
		}
	}
	sort.Strings(cleaned)
	return cleaned, nil
}

func computeManifestDigest(m SealedManifest) string {
	payload := fmt.Sprintf("breachatlas:manifest:v1:%s:%s:%s:%s:%d:%s:%s:%s:%d",
		m.SchemaVersion, m.CaseID, m.EvidenceID, m.SHA256, m.SizeBytes, m.MediaType, m.AcquiredAt, m.CustodyRoot, m.Generation)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func hashRegularFile(path, expectedSHA string, expectedSize int64) (int64, error) {
	if _, err := ensureNoSymlink(path); err != nil {
		return 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("%w: %s is not a regular file", ErrManifestInvalid, path)
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, err
	}
	if expectedSize >= 0 && n != expectedSize {
		return n, fmt.Errorf("%w: file size %d != expected %d", ErrSizeMismatch, n, expectedSize)
	}
	gotSHA := hex.EncodeToString(h.Sum(nil))
	if expectedSHA != "" && gotSHA != expectedSHA {
		return n, fmt.Errorf("%w: file sha256 %s != expected %s", ErrDigestMismatch, gotSHA, expectedSHA)
	}
	return n, nil
}

// SealQuarantined durably writes and verifies the content-addressed blob before atomically
// committing the sealed evidence manifest. Idempotent replays on OperationID return the
// committed manifest without side effects, while hash/size mismatches and faults abort cleanly.
func (s *SealStore) SealQuarantined(ctx context.Context, req SealRequest) (*SealedManifest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealInterrupted, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrSealStoreClosed
	}

	if err := validateID("operation_id", req.OperationID); err != nil {
		return nil, err
	}
	if req.Attempt < 0 {
		return nil, fmt.Errorf("%w: attempt cannot be negative", ErrManifestInvalid)
	}
	if req.Attempt > s.maxRetries {
		return nil, fmt.Errorf("%w: attempt %d > max %d", ErrRetryLimitExceeded, req.Attempt, s.maxRetries)
	}
	if req.Quarantined == nil {
		return nil, ErrQuarantinedInputRequired
	}
	q := req.Quarantined
	if q.Sealed || q.Status != StatusQuarantined {
		return nil, fmt.Errorf("%w: input must be unsealed quarantined upload", ErrQuarantinedInputRequired)
	}
	if q.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrUnsupportedVersion, q.SchemaVersion, SchemaVersion)
	}
	if err := validateID("case_id", q.CaseID); err != nil {
		return nil, err
	}
	if err := validateID("evidence_id", q.EvidenceID); err != nil {
		return nil, err
	}
	if len(q.MediaType) == 0 || len(q.MediaType) > 127 || !mediaType.MatchString(q.MediaType) {
		return nil, fmt.Errorf("%w: invalid media_type %q", ErrManifestInvalid, q.MediaType)
	}
	if !digest.MatchString(q.SHA256) {
		return nil, fmt.Errorf("%w: invalid quarantined sha256", ErrManifestInvalid)
	}
	if q.SizeBytes < 0 || q.SizeBytes > MaxEvidenceBytes {
		return nil, fmt.Errorf("%w: invalid quarantined size_bytes %d", ErrManifestInvalid, q.SizeBytes)
	}
	if req.ExpectedSHA256 != "" {
		if !digest.MatchString(req.ExpectedSHA256) {
			return nil, fmt.Errorf("%w: invalid expected_sha256", ErrManifestInvalid)
		}
		if req.ExpectedSHA256 != q.SHA256 {
			return nil, fmt.Errorf("%w: expected_sha256 %s != quarantined %s", ErrDigestMismatch, req.ExpectedSHA256, q.SHA256)
		}
	}
	if !timestamp.MatchString(req.AcquiredAt) {
		return nil, fmt.Errorf("%w: invalid acquired_at %q", ErrManifestInvalid, req.AcquiredAt)
	}
	if _, err := time.Parse(time.RFC3339Nano, req.AcquiredAt); err != nil {
		return nil, fmt.Errorf("%w: invalid acquired_at %q", ErrManifestInvalid, req.AcquiredAt)
	}
	if !digest.MatchString(req.CustodyRoot) {
		return nil, fmt.Errorf("%w: invalid custody_root", ErrManifestInvalid)
	}

	// Idempotent replay handling for lost ACKs or repeated requests.
	if existing, ok := s.index.Operations[req.OperationID]; ok {
		if existing.CaseID != q.CaseID || existing.EvidenceID != q.EvidenceID || existing.SHA256 != q.SHA256 || existing.SizeBytes != q.SizeBytes {
			return nil, ErrOperationConflict
		}
		replay := existing
		replay.IdempotentReplay = true
		return &replay, nil
	}

	// Sealed source bytes and committed manifests for a (caseID, evidenceID) are immutable.
	evidenceKey := q.CaseID + "/" + q.EvidenceID
	if _, alreadySealed := s.index.Manifests[evidenceKey]; alreadySealed {
		return nil, fmt.Errorf("%w: %s", ErrSealedBytesImmutable, evidenceKey)
	}

	if s.cfg.Faults.SimulateDiskFull {
		return nil, ErrSealDiskFull
	}

	if s.index.TotalBytes+q.SizeBytes > s.maxStorage {
		return nil, fmt.Errorf("%w: %d + %d > %d", ErrStorageQuotaExceeded, s.index.TotalBytes, q.SizeBytes, s.maxStorage)
	}

	// Locate quarantined payload safely inside quarantineDir (or clean absolute/relative path check).
	if s.quarantineDir == "" {
		return nil, ErrQuarantineRequired
	}
	if strings.ContainsRune(q.QuarantinePath, '\x00') {
		return nil, fmt.Errorf("%w: invalid quarantine path", ErrPathTraversal)
	}
	srcPath := filepath.Join(s.quarantineDir, filepath.Clean(q.QuarantinePath))
	if err := checkWithinDir(s.quarantineDir, srcPath); err != nil {
		return nil, err
	}
	if _, err := ensureNoSymlink(srcPath); err != nil {
		return nil, err
	}

	// Phase 1: Stream-copy & re-hash quarantined bytes into a temporary staging blob file,
	// verify digest & size, fsync, and promote atomically into blobs/sha256/<digest>.
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return nil, fmt.Errorf("open quarantined payload: %w", err)
	}
	defer srcFile.Close()

	blobTmpName := fmt.Sprintf("%s.%d.blob.tmp", req.OperationID, time.Now().UnixNano())
	blobTmpPath := filepath.Join(s.rootDir, sealStagingDir, blobTmpName)
	blobTmpFile, err := os.OpenFile(blobTmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("create staged blob tmp: %w", err)
	}

	cleanupBlobTmp := func() {
		_ = blobTmpFile.Close()
		_ = os.Remove(blobTmpPath)
	}

	hasher := sha256.New()
	buf := make([]byte, s.bufSize)
	var copied int64
	for {
		if err := ctx.Err(); err != nil {
			cleanupBlobTmp()
			return nil, fmt.Errorf("%w: %v", ErrSealInterrupted, err)
		}
		n, rErr := srcFile.Read(buf)
		if n > 0 {
			if copied+int64(n) > q.SizeBytes {
				cleanupBlobTmp()
				return nil, fmt.Errorf("%w: quarantined bytes exceed declared size %d", ErrSizeMismatch, q.SizeBytes)
			}
			chunk := buf[:n]
			if _, wErr := blobTmpFile.Write(chunk); wErr != nil {
				cleanupBlobTmp()
				return nil, fmt.Errorf("%w: %v", ErrSealDiskFull, wErr)
			}
			_, _ = hasher.Write(chunk)
			copied += int64(n)
		}
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			cleanupBlobTmp()
			return nil, fmt.Errorf("read quarantined payload: %w", rErr)
		}
	}

	if copied != q.SizeBytes {
		cleanupBlobTmp()
		return nil, fmt.Errorf("%w: read %d bytes, expected %d", ErrSizeMismatch, copied, q.SizeBytes)
	}
	computedSHA := hex.EncodeToString(hasher.Sum(nil))
	if computedSHA != q.SHA256 {
		cleanupBlobTmp()
		return nil, fmt.Errorf("%w: quarantined payload hash %s != expected %s", ErrDigestMismatch, computedSHA, q.SHA256)
	}

	if err := blobTmpFile.Sync(); err != nil {
		cleanupBlobTmp()
		return nil, fmt.Errorf("sync staged blob: %w", err)
	}
	if err := blobTmpFile.Close(); err != nil {
		_ = os.Remove(blobTmpPath)
		return nil, err
	}

	blobRelPath := filepath.Join(sealBlobsDir, computedSHA)
	blobDestPath := filepath.Join(s.rootDir, blobRelPath)
	if _, err := ensureNoSymlink(blobDestPath); err != nil {
		_ = os.Remove(blobTmpPath)
		return nil, err
	}

	// Never overwrite an already-stored content-addressed blob; verify it instead.
	if _, err := os.Lstat(blobDestPath); err == nil {
		_ = os.Remove(blobTmpPath)
		if _, verifyErr := hashRegularFile(blobDestPath, computedSHA, copied); verifyErr != nil {
			return nil, fmt.Errorf("%w: existing content-addressed blob failed integrity check: %v", ErrCorruptedBlob(verifyErr), verifyErr)
		}
	} else if os.IsNotExist(err) {
		if err := os.Rename(blobTmpPath, blobDestPath); err != nil {
			_ = os.Remove(blobTmpPath)
			return nil, fmt.Errorf("commit content-addressed blob: %w", err)
		}
		if s.cfg.SyncDir {
			syncPath(filepath.Join(s.rootDir, sealBlobsDir))
		}
	} else {
		_ = os.Remove(blobTmpPath)
		return nil, err
	}

	// Boundary injection: file bytes are now durable on disk, BEFORE metadata manifest seal.
	if s.cfg.Faults.FailAfterBlobSyncBeforeManifest {
		return nil, ErrSealInterrupted
	}

	// Phase 2: Commit the immutable manifest file and index atomically.
	newGen := s.index.Generation + 1
	now := time.Now().UTC().Format(time.RFC3339Nano)
	manifest := SealedManifest{
		SchemaVersion: SchemaVersion,
		Generation:    newGen,
		OperationID:   req.OperationID,
		CaseID:        q.CaseID,
		EvidenceID:    q.EvidenceID,
		SHA256:        computedSHA,
		SizeBytes:     copied,
		MediaType:     q.MediaType,
		AcquiredAt:    req.AcquiredAt,
		CustodyRoot:   req.CustodyRoot,
		BlobRelPath:   filepath.ToSlash(blobRelPath),
		Sealed:        true,
		SealedAt:      now,
	}
	manifest.ManifestDigest = computeManifestDigest(manifest)

	caseManifestDir := filepath.Join(s.rootDir, sealManifestsDir, q.CaseID)
	if err := checkWithinDir(filepath.Join(s.rootDir, sealManifestsDir), caseManifestDir); err != nil {
		return nil, err
	}
	if _, err := resolveSafeExistingOrNewDir(caseManifestDir, ErrManifestInvalid); err != nil {
		return nil, err
	}

	manifestDestPath := filepath.Join(caseManifestDir, q.EvidenceID+".manifest.json")
	if _, err := ensureNoSymlink(manifestDestPath); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(manifestDestPath); err == nil {
		return nil, fmt.Errorf("%w: manifest already exists at %s", ErrSealedBytesImmutable, manifestDestPath)
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	manifestTmpPath := filepath.Join(s.rootDir, sealStagingDir, fmt.Sprintf("%s.%d.manifest.tmp", req.OperationID, newGen))
	if err := writeAndSyncFile(manifestTmpPath, manifestBytes); err != nil {
		return nil, fmt.Errorf("write manifest tmp: %w", err)
	}
	if err := os.Rename(manifestTmpPath, manifestDestPath); err != nil {
		_ = os.Remove(manifestTmpPath)
		return nil, fmt.Errorf("commit manifest file: %w", err)
	}
	if s.cfg.SyncDir {
		syncPath(caseManifestDir)
	}

	// Update in-memory clone and atomically replace seal-index.json.
	newOps := make(map[string]SealedManifest, len(s.index.Operations)+1)
	for k, v := range s.index.Operations {
		newOps[k] = v
	}
	newOps[req.OperationID] = manifest

	newManifests := make(map[string]SealedManifest, len(s.index.Manifests)+1)
	for k, v := range s.index.Manifests {
		newManifests[k] = v
	}
	newManifests[evidenceKey] = manifest

	newIdx := sealIndex{
		SchemaVersion: SchemaVersion,
		Generation:    newGen,
		TotalBytes:    s.index.TotalBytes + copied,
		Operations:    newOps,
		Manifests:     newManifests,
	}

	idxBytes, err := json.MarshalIndent(newIdx, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal seal index: %w", err)
	}
	idxTmpPath := filepath.Join(s.rootDir, sealStagingDir, fmt.Sprintf("seal-index.%d.tmp", newGen))
	if err := writeAndSyncFile(idxTmpPath, idxBytes); err != nil {
		return nil, fmt.Errorf("write seal index tmp: %w", err)
	}
	idxDestPath := filepath.Join(s.rootDir, sealIndexFile)
	if err := os.Rename(idxTmpPath, idxDestPath); err != nil {
		_ = os.Remove(idxTmpPath)
		return nil, fmt.Errorf("commit seal index: %w", err)
	}
	if s.cfg.SyncDir {
		syncPath(s.rootDir)
	}

	s.index = newIdx
	out := manifest
	return &out, nil
}

func ErrCorruptedBlob(err error) error {
	if errors.Is(err, ErrDigestMismatch) || errors.Is(err, ErrSizeMismatch) {
		return err
	}
	return ErrDigestMismatch
}

func writeAndSyncFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// RecoverOrphans cleans partial staging files and identifies any durable blobs in blobs/sha256
// that have no committed sealed manifest. When reclaimUnreferencedBlobs is true, those orphan
// blobs are safely deleted without touching any committed sealed blob.
func (s *SealStore) RecoverOrphans(reclaimUnreferencedBlobs bool) (*OrphanReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrSealStoreClosed
	}

	cleanedStaging, err := s.cleanStagingUnlocked()
	if err != nil {
		return nil, err
	}

	referenced := make(map[string]bool, len(s.index.Manifests))
	for _, m := range s.index.Manifests {
		referenced[m.SHA256] = true
	}

	blobsDir := filepath.Join(s.rootDir, sealBlobsDir)
	entries, err := os.ReadDir(blobsDir)
	if err != nil {
		return nil, err
	}

	var orphans []string
	var reclaimed []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !referenced[name] {
			orphans = append(orphans, name)
			if reclaimUnreferencedBlobs {
				if err := os.Remove(filepath.Join(blobsDir, name)); err == nil {
					reclaimed = append(reclaimed, name)
				}
			}
		}
	}
	sort.Strings(orphans)
	sort.Strings(reclaimed)

	return &OrphanReport{
		CleanedStagingFiles:  cleanedStaging,
		OrphanBlobs:          orphans,
		ReclaimedOrphanBlobs: reclaimed,
	}, nil
}

// GetSealedManifest returns the committed SealedManifest for (caseID, evidenceID), if sealed.
func (s *SealStore) GetSealedManifest(caseID, evidenceID string) (*SealedManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrSealStoreClosed
	}
	if err := validateID("case_id", caseID); err != nil {
		return nil, err
	}
	if err := validateID("evidence_id", evidenceID); err != nil {
		return nil, err
	}
	m, ok := s.index.Manifests[caseID+"/"+evidenceID]
	if !ok {
		return nil, os.ErrNotExist
	}
	copyM := m
	return &copyM, nil
}

// ListSealedManifests returns a deterministic snapshot of all committed sealed manifests.
func (s *SealStore) ListSealedManifests() []SealedManifest {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]SealedManifest, 0, len(s.index.Manifests))
	for _, m := range s.index.Manifests {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Generation < out[j].Generation
	})
	return out
}

// Generation returns the current monotonic committed seal generation.
func (s *SealStore) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.index.Generation
}

// TotalBytes returns the cumulative sealed evidence bytes tracked against quota.
func (s *SealStore) TotalBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.index.TotalBytes
}

// RootDir returns the resolved root directory of the seal store.
func (s *SealStore) RootDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rootDir
}

// QuarantineDir returns the configured quarantine directory of the seal store, if any.
func (s *SealStore) QuarantineDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.quarantineDir
}

// Close releases the exclusive file lock held by SealStore.
func (s *SealStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeUnlocked()
}

func (s *SealStore) closeUnlocked() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.lockFile != nil {
		_ = syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
		err := s.lockFile.Close()
		s.lockFile = nil
		return err
	}
	return nil
}

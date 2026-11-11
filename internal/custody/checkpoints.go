package custody

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	CheckpointSchemaVersion = "1"
	DefaultCheckpointDir    = "checkpoints"
	MaxCheckpointBytes      = 64 * 1024 // 64 KiB
)

const (
	CheckpointCodeVerified         = "verified"
	CheckpointCodeRootMismatch     = "root_mismatch"
	CheckpointCodeUntrustedSigner   = "untrusted_signer"
	CheckpointCodeInvalidSignature  = "invalid_signature"
	CheckpointCodeMissingEvidence   = "missing_evidence"
	CheckpointCodeExpired          = "expired_checkpoint"
	CheckpointCodeStaleRevision    = "stale_revision"
	CheckpointCodeInvalidCheckpoint = "invalid_checkpoint"
)

var (
	ErrCheckpointUntrustedSigner   = errors.New("checkpoint signer is not trusted")
	ErrCheckpointInvalidSignature  = errors.New("checkpoint signature is invalid")
	ErrCheckpointExpired          = errors.New("checkpoint is expired")
	ErrCheckpointStaleRevision    = errors.New("checkpoint revision is stale or replayed")
	ErrCheckpointRootMismatch     = errors.New("checkpoint custody root mismatch with ledger")
	ErrCheckpointMissingEvidence  = errors.New("checkpoint evidence or sequence not found in ledger")
	ErrInvalidCheckpoint          = errors.New("invalid checkpoint fields")
	ErrCheckpointStoreClosed      = errors.New("checkpoint store closed")
	ErrCheckpointNotFound         = errors.New("checkpoint not found")
	ErrCheckpointStoreDirRequired = errors.New("checkpoint store root directory is required")
)

// Checkpoint represents an independently published, cryptographically signed attestation of custody state.
type Checkpoint struct {
	SchemaVersion string            `json:"schema_version"`
	CheckpointID  string            `json:"checkpoint_id"`
	CaseID        string            `json:"case_id"`
	EvidenceID    string            `json:"evidence_id"`
	Sequence      uint64            `json:"sequence"`
	CustodyRoot   string            `json:"custody_root"`
	KeyID         string            `json:"key_id"`
	PublicKey     string            `json:"public_key"`
	Signature     string            `json:"signature"`
	IssuedAt      string            `json:"issued_at"`
	ExpiresAt     string            `json:"expires_at,omitempty"`
	Revision      uint64            `json:"revision"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// CanonicalCheckpointBytes produces deterministic bytes representing the signed checkpoint:
// "breachatlas:checkpoint:v1:{SchemaVersion}:{CheckpointID}:{CaseID}:{EvidenceID}:{Sequence}:{CustodyRoot}:{KeyID}:{Revision}:{IssuedAt}:{ExpiresAt}"
func CanonicalCheckpointBytes(chk Checkpoint) []byte {
	return []byte(fmt.Sprintf(
		"breachatlas:checkpoint:v1:%s:%s:%s:%s:%d:%s:%s:%d:%s:%s",
		chk.SchemaVersion,
		chk.CheckpointID,
		chk.CaseID,
		chk.EvidenceID,
		chk.Sequence,
		chk.CustodyRoot,
		chk.KeyID,
		chk.Revision,
		chk.IssuedAt,
		chk.ExpiresAt,
	))
}

// ComputeCheckpointDigest calculates the hex SHA-256 digest of the canonical checkpoint bytes.
func ComputeCheckpointDigest(chk Checkpoint) string {
	h := sha256.Sum256(CanonicalCheckpointBytes(chk))
	return hex.EncodeToString(h[:])
}

// CreateCheckpointRequest specifies parameters for creating a signed custody checkpoint.
type CreateCheckpointRequest struct {
	CheckpointID string            `json:"checkpoint_id"`
	CaseID       string            `json:"case_id"`
	EvidenceID   string            `json:"evidence_id"`
	Sequence     uint64            `json:"sequence,omitempty"`
	CustodyRoot  string            `json:"custody_root,omitempty"`
	KeyID        string            `json:"key_id"`
	Revision     uint64            `json:"revision"`
	IssuedAt     string            `json:"issued_at,omitempty"`
	ExpiresAt    string            `json:"expires_at,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	PrivateKey   ed25519.PrivateKey `json:"-"`
}

// CreateCheckpoint creates and signs a new independent custody root checkpoint.
func CreateCheckpoint(ctx context.Context, ledger *LedgerStore, req CreateCheckpointRequest) (*Checkpoint, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if !isValidIdentifier(req.CaseID) {
		return nil, fmt.Errorf("%w: invalid case_id %q", ErrInvalidCheckpoint, req.CaseID)
	}
	if !isValidIdentifier(req.EvidenceID) {
		return nil, fmt.Errorf("%w: invalid evidence_id %q", ErrInvalidCheckpoint, req.EvidenceID)
	}
	if !isValidIdentifier(req.KeyID) {
		return nil, fmt.Errorf("%w: invalid key_id %q", ErrInvalidCheckpoint, req.KeyID)
	}
	if len(req.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: private key size %d != %d", ErrInvalidCheckpoint, len(req.PrivateKey), ed25519.PrivateKeySize)
	}

	seq := req.Sequence
	custodyRoot := req.CustodyRoot

	if ledger != nil {
		if seq == 0 {
			events, err := ledger.ListEvents(req.CaseID, req.EvidenceID)
			if err != nil {
				return nil, err
			}
			if len(events) == 0 {
				return nil, fmt.Errorf("%w: no events found for %s/%s", ErrCheckpointMissingEvidence, req.CaseID, req.EvidenceID)
			}
			lastEv := events[len(events)-1]
			seq = lastEv.Sequence
			custodyRoot = lastEv.CustodyRoot
		} else {
			ev, err := ledger.GetEvent(req.CaseID, req.EvidenceID, seq)
			if err != nil {
				return nil, fmt.Errorf("%w: sequence %d: %v", ErrCheckpointMissingEvidence, seq, err)
			}
			if custodyRoot == "" {
				custodyRoot = ev.CustodyRoot
			} else if custodyRoot != ev.CustodyRoot {
				return nil, fmt.Errorf("%w: requested root %s != ledger root %s", ErrCheckpointRootMismatch, custodyRoot, ev.CustodyRoot)
			}
		}
	} else {
		if seq == 0 {
			return nil, fmt.Errorf("%w: sequence must be > 0 when ledger is nil", ErrInvalidCheckpoint)
		}
		if !digestRegex.MatchString(custodyRoot) {
			return nil, fmt.Errorf("%w: invalid custody_root %q", ErrInvalidCheckpoint, custodyRoot)
		}
	}

	checkpointID := req.CheckpointID
	if checkpointID == "" {
		checkpointID = fmt.Sprintf("chk-%s-%d-%d", req.EvidenceID, seq, req.Revision)
	}
	if !isValidIdentifier(checkpointID) {
		return nil, fmt.Errorf("%w: invalid checkpoint_id %q", ErrInvalidCheckpoint, checkpointID)
	}

	issuedAt := req.IssuedAt
	var issuedTime time.Time
	if issuedAt == "" {
		issuedTime = time.Now().UTC()
		issuedAt = issuedTime.Format(time.RFC3339Nano)
	} else {
		if !timestampRegex.MatchString(issuedAt) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidTimestamp, issuedAt)
		}
		var err error
		issuedTime, err = time.Parse(time.RFC3339Nano, issuedAt)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidTimestamp, err)
		}
	}

	if req.ExpiresAt != "" {
		if !timestampRegex.MatchString(req.ExpiresAt) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidTimestamp, req.ExpiresAt)
		}
		expiresTime, err := time.Parse(time.RFC3339Nano, req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidTimestamp, err)
		}
		if !expiresTime.After(issuedTime) {
			return nil, fmt.Errorf("%w: expires_at must be after issued_at", ErrInvalidCheckpoint)
		}
	}

	chk := Checkpoint{
		SchemaVersion: CheckpointSchemaVersion,
		CheckpointID:  checkpointID,
		CaseID:        req.CaseID,
		EvidenceID:    req.EvidenceID,
		Sequence:      seq,
		CustodyRoot:   custodyRoot,
		KeyID:         req.KeyID,
		IssuedAt:      issuedAt,
		ExpiresAt:     req.ExpiresAt,
		Revision:      req.Revision,
		Metadata:      req.Metadata,
	}

	pub := req.PrivateKey.Public().(ed25519.PublicKey)
	chk.PublicKey = hex.EncodeToString(pub)

	sig := ed25519.Sign(req.PrivateKey, CanonicalCheckpointBytes(chk))
	chk.Signature = hex.EncodeToString(sig)

	return &chk, nil
}

// CheckpointTracker tracks the last accepted authority checkpoint per evidence chain to enforce anti-rollback and anti-replay invariants.
type CheckpointTracker struct {
	mu       sync.RWMutex
	accepted map[string]Checkpoint // key: caseID + "/" + evidenceID
}

// NewCheckpointTracker initializes a new in-memory checkpoint tracker.
func NewCheckpointTracker() *CheckpointTracker {
	return &CheckpointTracker{
		accepted: make(map[string]Checkpoint),
	}
}

// GetAccepted retrieves the currently accepted checkpoint for an evidence chain.
func (t *CheckpointTracker) GetAccepted(caseID, evidenceID string) (*Checkpoint, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	chk, exists := t.accepted[caseID+"/"+evidenceID]
	if !exists {
		return nil, false
	}
	copied := chk
	return &copied, true
}

// Check verifies that candidate chk does not violate anti-rollback or anti-replay rules relative to accepted state.
func (t *CheckpointTracker) Check(chk Checkpoint, strictReplay bool) error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	last, exists := t.accepted[chk.CaseID+"/"+chk.EvidenceID]
	if !exists {
		return nil
	}

	if chk.Sequence < last.Sequence {
		return fmt.Errorf("%w: candidate sequence %d < last accepted %d", ErrCheckpointStaleRevision, chk.Sequence, last.Sequence)
	}

	if chk.Revision < last.Revision {
		return fmt.Errorf("%w: candidate revision %d < last accepted %d", ErrCheckpointStaleRevision, chk.Revision, last.Revision)
	}

	if strictReplay && chk.Revision <= last.Revision {
		return fmt.Errorf("%w: candidate revision %d <= last accepted %d in strict replay mode", ErrCheckpointStaleRevision, chk.Revision, last.Revision)
	}

	if chk.Revision == last.Revision {
		if chk.CheckpointID != last.CheckpointID || chk.CustodyRoot != last.CustodyRoot || chk.Sequence != last.Sequence {
			return fmt.Errorf("%w: candidate checkpoint %s conflicts with accepted %s at revision %d", ErrCheckpointStaleRevision, chk.CheckpointID, last.CheckpointID, chk.Revision)
		}
	}

	return nil
}

// Record updates the accepted authority for this evidence chain while enforcing anti-rollback.
func (t *CheckpointTracker) Record(chk Checkpoint) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	last, exists := t.accepted[chk.CaseID+"/"+chk.EvidenceID]
	if exists {
		if chk.Sequence < last.Sequence {
			return fmt.Errorf("%w: cannot record candidate sequence %d < accepted %d", ErrCheckpointStaleRevision, chk.Sequence, last.Sequence)
		}
		if chk.Revision < last.Revision {
			return fmt.Errorf("%w: cannot record candidate revision %d < accepted %d", ErrCheckpointStaleRevision, chk.Revision, last.Revision)
		}
		if chk.Revision == last.Revision {
			if chk.CheckpointID != last.CheckpointID || chk.CustodyRoot != last.CustodyRoot || chk.Sequence != last.Sequence {
				return fmt.Errorf("%w: candidate checkpoint %s conflicts with accepted %s at revision %d", ErrCheckpointStaleRevision, chk.CheckpointID, last.CheckpointID, chk.Revision)
			}
		}
	}

	t.accepted[chk.CaseID+"/"+chk.EvidenceID] = chk
	return nil
}

// Count returns the number of distinct evidence chains currently tracked.
func (t *CheckpointTracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.accepted)
}

// VerifyCheckpointOptions configures checkpoint verification options.
type VerifyCheckpointOptions struct {
	TrustedPublicKeys map[string]string // keyID -> hex-encoded Ed25519 public key
	Tracker           *CheckpointTracker
	Now               time.Time
	StrictReplay      bool
}

// CheckpointVerificationResult represents the structured outcome of a checkpoint verification.
type CheckpointVerificationResult struct {
	Verified       bool   `json:"verified"`
	Status         string `json:"status"`
	CheckpointID   string `json:"checkpoint_id"`
	CaseID         string `json:"case_id"`
	EvidenceID     string `json:"evidence_id"`
	Sequence       uint64 `json:"sequence"`
	Revision       uint64 `json:"revision"`
	LedgerRoot     string `json:"ledger_root,omitempty"`
	CheckpointRoot string `json:"checkpoint_root"`
	SignerKeyID    string `json:"signer_key_id"`
	ErrorMessage   string `json:"error_message,omitempty"`
	VerifiedAt     string `json:"verified_at"`
}

// VerifyCheckpoint verifies a signed custody root checkpoint against external trust, signature validity, expiration, anti-rollback tracker, and the custody ledger.
func VerifyCheckpoint(ctx context.Context, ledger *LedgerStore, chk Checkpoint, opts VerifyCheckpointOptions) (*CheckpointVerificationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	res := &CheckpointVerificationResult{
		Verified:       false,
		CheckpointID:   chk.CheckpointID,
		CaseID:         chk.CaseID,
		EvidenceID:     chk.EvidenceID,
		Sequence:       chk.Sequence,
		Revision:       chk.Revision,
		CheckpointRoot: chk.CustodyRoot,
		SignerKeyID:    chk.KeyID,
		VerifiedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}

	if err := ctx.Err(); err != nil {
		return failCheckpoint(res, err)
	}

	// 1. Structural validation
	if chk.SchemaVersion != CheckpointSchemaVersion {
		return failCheckpoint(res, fmt.Errorf("%w: schema_version %q != %q", ErrInvalidCheckpoint, chk.SchemaVersion, CheckpointSchemaVersion))
	}
	if !isValidIdentifier(chk.CheckpointID) {
		return failCheckpoint(res, fmt.Errorf("%w: invalid checkpoint_id %q", ErrInvalidCheckpoint, chk.CheckpointID))
	}
	if !isValidIdentifier(chk.CaseID) {
		return failCheckpoint(res, fmt.Errorf("%w: invalid case_id %q", ErrInvalidCheckpoint, chk.CaseID))
	}
	if !isValidIdentifier(chk.EvidenceID) {
		return failCheckpoint(res, fmt.Errorf("%w: invalid evidence_id %q", ErrInvalidCheckpoint, chk.EvidenceID))
	}
	if !isValidIdentifier(chk.KeyID) {
		return failCheckpoint(res, fmt.Errorf("%w: invalid key_id %q", ErrInvalidCheckpoint, chk.KeyID))
	}
	if chk.Sequence == 0 {
		return failCheckpoint(res, fmt.Errorf("%w: sequence must be > 0", ErrInvalidCheckpoint))
	}
	if !digestRegex.MatchString(chk.CustodyRoot) {
		return failCheckpoint(res, fmt.Errorf("%w: invalid custody_root %q", ErrInvalidCheckpoint, chk.CustodyRoot))
	}
	if !timestampRegex.MatchString(chk.IssuedAt) {
		return failCheckpoint(res, fmt.Errorf("%w: invalid issued_at timestamp %q", ErrInvalidTimestamp, chk.IssuedAt))
	}
	iss, err := time.Parse(time.RFC3339Nano, chk.IssuedAt)
	if err != nil {
		return failCheckpoint(res, fmt.Errorf("%w: parse issued_at: %v", ErrInvalidTimestamp, err))
	}
	if chk.ExpiresAt != "" {
		if !timestampRegex.MatchString(chk.ExpiresAt) {
			return failCheckpoint(res, fmt.Errorf("%w: invalid expires_at timestamp %q", ErrInvalidTimestamp, chk.ExpiresAt))
		}
		exp, err := time.Parse(time.RFC3339Nano, chk.ExpiresAt)
		if err != nil {
			return failCheckpoint(res, fmt.Errorf("%w: parse expires_at: %v", ErrInvalidTimestamp, err))
		}
		if !exp.After(iss) {
			return failCheckpoint(res, fmt.Errorf("%w: expires_at %s must be after issued_at %s", ErrInvalidCheckpoint, chk.ExpiresAt, chk.IssuedAt))
		}
	}

	// 2. Signer trust supplied OUTSIDE bundle
	if opts.TrustedPublicKeys == nil {
		return failCheckpoint(res, fmt.Errorf("%w: trusted public keys map is nil", ErrCheckpointUntrustedSigner))
	}
	trustedPubHex, exists := opts.TrustedPublicKeys[chk.KeyID]
	if !exists || strings.TrimSpace(trustedPubHex) == "" {
		return failCheckpoint(res, fmt.Errorf("%w: key_id %q not in trusted public keys allowlist", ErrCheckpointUntrustedSigner, chk.KeyID))
	}
	trustedPubBytes, err := hex.DecodeString(strings.TrimSpace(trustedPubHex))
	if err != nil || len(trustedPubBytes) != ed25519.PublicKeySize {
		return failCheckpoint(res, fmt.Errorf("%w: trusted public key for %q is invalid hex", ErrCheckpointUntrustedSigner, chk.KeyID))
	}
	if !strings.EqualFold(strings.TrimSpace(chk.PublicKey), strings.TrimSpace(trustedPubHex)) {
		return failCheckpoint(res, fmt.Errorf("%w: bundle public key does not match trusted key for %q", ErrCheckpointUntrustedSigner, chk.KeyID))
	}

	// 3. Cryptographic signature check
	if strings.TrimSpace(chk.Signature) == "" {
		return failCheckpoint(res, fmt.Errorf("%w: missing signature", ErrCheckpointInvalidSignature))
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(chk.Signature))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return failCheckpoint(res, fmt.Errorf("%w: signature length %d != %d", ErrCheckpointInvalidSignature, len(sigBytes), ed25519.SignatureSize))
	}
	canonicalBytes := CanonicalCheckpointBytes(chk)
	if !ed25519.Verify(trustedPubBytes, canonicalBytes, sigBytes) {
		return failCheckpoint(res, fmt.Errorf("%w: Ed25519 signature verification failed", ErrCheckpointInvalidSignature))
	}

	// 4. Expiration check
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if chk.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339Nano, chk.ExpiresAt)
		if err == nil && now.After(exp) {
			return failCheckpoint(res, fmt.Errorf("%w: checkpoint expired at %s (now: %s)", ErrCheckpointExpired, chk.ExpiresAt, now.Format(time.RFC3339Nano)))
		}
	}

	// 5. Anti-rollback / anti-replay check
	if opts.Tracker != nil {
		if err := opts.Tracker.Check(chk, opts.StrictReplay); err != nil {
			return failCheckpoint(res, err)
		}
	}

	// 6. Custody root verification against ledger event at sequence chk.Sequence
	if ledger == nil {
		return failCheckpoint(res, fmt.Errorf("%w: ledger store required to verify custody root", ErrCheckpointMissingEvidence))
	}

	ev, err := ledger.GetEvent(chk.CaseID, chk.EvidenceID, chk.Sequence)
	if err != nil {
		if errors.Is(err, ErrEventNotFound) {
			return failCheckpoint(res, fmt.Errorf("%w: sequence %d not found in custody ledger", ErrCheckpointMissingEvidence, chk.Sequence))
		}
		return failCheckpoint(res, fmt.Errorf("%w: retrieve event %d: %v", ErrCheckpointMissingEvidence, chk.Sequence, err))
	}
	res.LedgerRoot = ev.CustodyRoot

	// Verify ledger internal hash continuity
	chainOk, err := ledger.VerifyChain(chk.CaseID, chk.EvidenceID)
	if err != nil {
		return failCheckpoint(res, fmt.Errorf("%w: custody ledger chain verification failed: %v", ErrCheckpointRootMismatch, err))
	}
	if !chainOk {
		return failCheckpoint(res, fmt.Errorf("%w: custody ledger chain integrity check failed", ErrCheckpointRootMismatch))
	}

	if ev.CustodyRoot != chk.CustodyRoot {
		return failCheckpoint(res, fmt.Errorf("%w: checkpoint custody_root %s != ledger custody_root %s at sequence %d", ErrCheckpointRootMismatch, chk.CustodyRoot, ev.CustodyRoot, chk.Sequence))
	}

	// 7. Success: record accepted authority and mark verified
	if opts.Tracker != nil {
		if err := opts.Tracker.Record(chk); err != nil {
			return failCheckpoint(res, err)
		}
	}
	res.Verified = true
	res.Status = CheckpointCodeVerified
	return res, nil
}

func failCheckpoint(res *CheckpointVerificationResult, err error) (*CheckpointVerificationResult, error) {
	if res == nil {
		res = &CheckpointVerificationResult{}
	}
	res.Verified = false
	if res.VerifiedAt == "" {
		res.VerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	res.ErrorMessage = err.Error()
	res.Status = classifyCheckpointError(err)
	return res, err
}

func classifyCheckpointError(err error) string {
	switch {
	case errors.Is(err, ErrCheckpointUntrustedSigner):
		return CheckpointCodeUntrustedSigner
	case errors.Is(err, ErrCheckpointInvalidSignature):
		return CheckpointCodeInvalidSignature
	case errors.Is(err, ErrCheckpointExpired):
		return CheckpointCodeExpired
	case errors.Is(err, ErrCheckpointStaleRevision):
		return CheckpointCodeStaleRevision
	case errors.Is(err, ErrCheckpointRootMismatch):
		return CheckpointCodeRootMismatch
	case errors.Is(err, ErrCheckpointMissingEvidence), errors.Is(err, ErrEventNotFound):
		return CheckpointCodeMissingEvidence
	default:
		return CheckpointCodeInvalidCheckpoint
	}
}

// CheckpointStore abstracts external storage and retrieval of signed checkpoints.
type CheckpointStore interface {
	SaveCheckpoint(ctx context.Context, chk Checkpoint) error
	GetCheckpoint(ctx context.Context, caseID, evidenceID, checkpointID string) (*Checkpoint, error)
	ListCheckpoints(ctx context.Context, caseID, evidenceID string) ([]Checkpoint, error)
	GetLatestCheckpoint(ctx context.Context, caseID, evidenceID string) (*Checkpoint, error)
	Close() error
}

// FileCheckpointStoreConfig configures durable local filesystem checkpoint storage.
type FileCheckpointStoreConfig struct {
	RootDir string
	SyncDir bool
}

// FileCheckpointStore implements CheckpointStore backed by local filesystem storage.
type FileCheckpointStore struct {
	mu      sync.RWMutex
	rootDir string
	syncDir bool
	closed  bool
}

// OpenFileCheckpointStore initializes a local file-based checkpoint store at rootDir.
func OpenFileCheckpointStore(cfg FileCheckpointStoreConfig) (*FileCheckpointStore, error) {
	if strings.TrimSpace(cfg.RootDir) == "" {
		return nil, ErrCheckpointStoreDirRequired
	}
	if strings.ContainsRune(cfg.RootDir, '\x00') {
		return nil, fmt.Errorf("%w: null byte in root dir", ErrPathTraversal)
	}
	absRoot, err := filepath.Abs(cfg.RootDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if _, err := ensureNoSymlink(absRoot); err != nil {
		return nil, err
	}

	baseDir := filepath.Join(absRoot, DefaultCheckpointDir)
	if err := os.MkdirAll(baseDir, 0o750); err != nil {
		return nil, fmt.Errorf("create checkpoint store base dir: %w", err)
	}

	return &FileCheckpointStore{
		rootDir: baseDir,
		syncDir: cfg.SyncDir,
	}, nil
}

// SaveCheckpoint saves a signed checkpoint atomically to disk.
func (s *FileCheckpointStore) SaveCheckpoint(ctx context.Context, chk Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrCheckpointStoreClosed
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}

	if chk.SchemaVersion != CheckpointSchemaVersion {
		return fmt.Errorf("%w: unsupported schema version %q", ErrInvalidCheckpoint, chk.SchemaVersion)
	}
	if !isValidIdentifier(chk.CaseID) {
		return fmt.Errorf("%w: invalid case_id %q", ErrInvalidCheckpoint, chk.CaseID)
	}
	if !isValidIdentifier(chk.EvidenceID) {
		return fmt.Errorf("%w: invalid evidence_id %q", ErrInvalidCheckpoint, chk.EvidenceID)
	}
	if !isValidIdentifier(chk.CheckpointID) {
		return fmt.Errorf("%w: invalid checkpoint_id %q", ErrInvalidCheckpoint, chk.CheckpointID)
	}
	if !isValidIdentifier(chk.KeyID) {
		return fmt.Errorf("%w: invalid key_id %q", ErrInvalidCheckpoint, chk.KeyID)
	}
	if chk.Sequence == 0 {
		return fmt.Errorf("%w: sequence must be > 0", ErrInvalidCheckpoint)
	}
	if !digestRegex.MatchString(chk.CustodyRoot) {
		return fmt.Errorf("%w: invalid custody_root %q", ErrInvalidCheckpoint, chk.CustodyRoot)
	}

	caseDir := filepath.Join(s.rootDir, chk.CaseID)
	if err := checkWithinDir(s.rootDir, caseDir); err != nil {
		return err
	}
	if err := os.MkdirAll(caseDir, 0o750); err != nil {
		return fmt.Errorf("create case dir: %w", err)
	}

	evidenceDir := filepath.Join(caseDir, chk.EvidenceID)
	if err := checkWithinDir(caseDir, evidenceDir); err != nil {
		return err
	}
	if err := os.MkdirAll(evidenceDir, 0o750); err != nil {
		return fmt.Errorf("create evidence dir: %w", err)
	}

	filePath := filepath.Join(evidenceDir, chk.CheckpointID+".json")
	if err := checkWithinDir(evidenceDir, filePath); err != nil {
		return err
	}
	if _, err := ensureNoSymlink(filePath); err != nil {
		return err
	}

	data, err := json.MarshalIndent(chk, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	data = append(data, '\n')

	if len(data) > MaxCheckpointBytes {
		return fmt.Errorf("%w: checkpoint size %d exceeds %d bytes", ErrInvalidCheckpoint, len(data), MaxCheckpointBytes)
	}

	// Idempotency and anti-overwrite guard: if file already exists, check content identity
	if existingData, err := os.ReadFile(filePath); err == nil {
		if bytes.Equal(existingData, data) {
			return nil // Idempotent write
		}
		return fmt.Errorf("%w: checkpoint %s already exists with different content", ErrImmutableHistory, chk.CheckpointID)
	}

	tmpFile := filepath.Join(evidenceDir, fmt.Sprintf(".tmp-%s-%d.json", chk.CheckpointID, time.Now().UnixNano()))
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("open tmp checkpoint file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("write tmp checkpoint: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("sync tmp checkpoint: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("close tmp checkpoint: %w", err)
	}

	if err := os.Rename(tmpFile, filePath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("commit checkpoint file: %w", err)
	}

	if s.syncDir {
		if df, err := os.Open(evidenceDir); err == nil {
			_ = df.Sync()
			_ = df.Close()
		}
	}

	return nil
}

// GetCheckpoint retrieves a signed checkpoint by ID.
func (s *FileCheckpointStore) GetCheckpoint(ctx context.Context, caseID, evidenceID, checkpointID string) (*Checkpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrCheckpointStoreClosed
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if !isValidIdentifier(caseID) || !isValidIdentifier(evidenceID) || !isValidIdentifier(checkpointID) {
		return nil, ErrInvalidCheckpoint
	}

	filePath := filepath.Join(s.rootDir, caseID, evidenceID, checkpointID+".json")
	if err := checkWithinDir(s.rootDir, filePath); err != nil {
		return nil, err
	}
	if _, err := ensureNoSymlink(filePath); err != nil {
		return nil, err
	}

	fi, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCheckpointNotFound
		}
		return nil, err
	}
	if fi.Size() > MaxCheckpointBytes {
		return nil, fmt.Errorf("%w: checkpoint file exceeds maximum size %d", ErrInvalidCheckpoint, MaxCheckpointBytes)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var chk Checkpoint
	if err := json.Unmarshal(data, &chk); err != nil {
		return nil, fmt.Errorf("%w: unmarshal checkpoint %s: %v", ErrInvalidCheckpoint, filePath, err)
	}

	return &chk, nil
}

// ListCheckpoints returns all stored checkpoints for an evidence chain, ordered by Sequence ascending then Revision ascending.
func (s *FileCheckpointStore) ListCheckpoints(ctx context.Context, caseID, evidenceID string) ([]Checkpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrCheckpointStoreClosed
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if !isValidIdentifier(caseID) || !isValidIdentifier(evidenceID) {
		return nil, ErrInvalidCheckpoint
	}

	evidenceDir := filepath.Join(s.rootDir, caseID, evidenceID)
	if err := checkWithinDir(s.rootDir, evidenceDir); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(evidenceDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []Checkpoint{}, nil
		}
		return nil, err
	}

	var list []Checkpoint
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		p := filepath.Join(evidenceDir, entry.Name())
		if _, err := ensureNoSymlink(p); err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Size() > MaxCheckpointBytes {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var chk Checkpoint
		if err := json.Unmarshal(data, &chk); err != nil {
			continue
		}
		list = append(list, chk)
	}

	sort.Slice(list, func(i, j int) bool {
		if list[i].Sequence != list[j].Sequence {
			return list[i].Sequence < list[j].Sequence
		}
		return list[i].Revision < list[j].Revision
	})

	return list, nil
}

// GetLatestCheckpoint returns the checkpoint with the highest sequence and revision.
func (s *FileCheckpointStore) GetLatestCheckpoint(ctx context.Context, caseID, evidenceID string) (*Checkpoint, error) {
	list, err := s.ListCheckpoints(ctx, caseID, evidenceID)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrCheckpointNotFound
	}
	latest := list[len(list)-1]
	return &latest, nil
}

// Close closes the file checkpoint store.
func (s *FileCheckpointStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

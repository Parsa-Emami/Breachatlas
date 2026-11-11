package retention

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/holds"
)

const (
	SchemaVersion         = "1"
	StateDeletedTombstone = "DELETED_TOMBSTONE"

	ActionDestructionBlocked = "destruction_blocked"
	ActionEvidenceDestroyed  = "evidence_destroyed"
	ActionPolicySet          = "policy_set"

	OutcomeAllowed = "allowed"
	OutcomeBlocked = "blocked"

	stateFileName         = "retention-state.json"
	stagingSubdir         = "staging"
	tombstonesSubdir      = "tombstones"
	auditSubdir           = "audit"
	retentionLockFileName = ".retention.lock"
	tombstoneDomainPrefix = "breachatlas:evidence-tombstone:v1:"
	maxAuditEntryBytes    = 64 * 1024
)

var (
	ErrStoreDirRequired         = errors.New("retention store root directory is required")
	ErrStoreClosed              = errors.New("retention store closed")
	ErrLockBusy                 = errors.New("retention store lock busy: another instance holds exclusive lock")
	ErrAutoRawTTLForbidden      = errors.New("automatic TTL deletion of raw evidence is forbidden")
	ErrExplicitApprovalRequired = errors.New("explicit operator approval is required for evidence destruction")
	ErrHoldActive               = holds.ErrHoldActive
	ErrMissingPrerequisite      = errors.New("missing or unverified evidence/holds prerequisite")
	ErrUnavailableProvider      = errors.New("unavailable retention provider")
	ErrInvalidRetention         = errors.New("invalid retention policy or destruction request")
	ErrRetentionConflict        = errors.New("operation_id reused with conflicting parameters")
	ErrAlreadyDestroyed         = errors.New("evidence already destroyed with immutable tombstone")
	ErrPathTraversal            = errors.New("path traversal or invalid identifier rejected")
	ErrSymlinkRejected          = errors.New("symlink rejected in retention store path")
	ErrCorruptedRetentionState  = errors.New("corrupted persisted retention or audit state")
	ErrInterrupted              = errors.New("retention destruction interrupted before authoritative commit")
	ErrDiskFull                 = errors.New("disk full: retention destruction aborted")
	ErrTombstoneNotFound        = errors.New("evidence tombstone not found")
	ErrTombstoneInvalid         = errors.New("evidence tombstone digest or signature invalid")
)

var (
	identifierRegex  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	timestampRegex   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$`)
	allowedProviders = map[string]bool{
		"":            true,
		"local":       true,
		"breachatlas": true,
	}
)

// RetentionFaults enables fault injection at atomic commit boundaries for restart recovery testing.
type RetentionFaults struct {
	SimulateDiskFull           bool
	FailAfterStageBeforeCommit bool
}

// RetentionConfig configures a durable, concurrency-safe retention and destruction store.
type RetentionConfig struct {
	RootDir     string
	SealStore   *evidence.SealStore
	HoldService *holds.Service
	LedgerStore *custody.LedgerStore
	SyncDir     bool
	Faults      RetentionFaults
}

// RetentionPolicy defines retention governance for a case while prohibiting automatic raw evidence TTL.
type RetentionPolicy struct {
	SchemaVersion           string `json:"schema_version"`
	PolicyID                string `json:"policy_id"`
	CaseID                  string `json:"case_id"`
	AutoDeleteRawEvidence   bool   `json:"auto_delete_raw_evidence"`
	RawTTLSeconds           int64  `json:"raw_ttl_seconds"`
	RequireExplicitApproval bool   `json:"require_explicit_approval"`
	Actor                   string `json:"actor"`
	Reason                  string `json:"reason"`
	UpdatedAt               string `json:"updated_at"`
	Provider                string `json:"provider,omitempty"`
}

// AutoSweepReport proves automated retention checks never destroy raw sealed evidence.
type AutoSweepReport struct {
	CaseID               string   `json:"case_id"`
	EvaluatedCount       int      `json:"evaluated_count"`
	RawDeletedCount      int      `json:"raw_deleted_count"`
	HeldCount            int      `json:"held_count"`
	EligibleCandidateIDs []string `json:"eligible_candidate_ids,omitempty"`
}

// DestroyRequest captures an explicit, attributable operator destruction command.
type DestroyRequest struct {
	SchemaVersion    string             `json:"schema_version"`
	OperationID      string             `json:"operation_id"`
	TombstoneID      string             `json:"tombstone_id"`
	CaseID           string             `json:"case_id"`
	EvidenceID       string             `json:"evidence_id"`
	Operator         string             `json:"operator"`
	Timestamp        string             `json:"timestamp"`
	Reason           string             `json:"reason"`
	Provider         string             `json:"provider,omitempty"`
	ExplicitApproval bool               `json:"explicit_approval"`
	AutomaticTTL     bool               `json:"automatic_ttl,omitempty"`
	KeyID            string             `json:"key_id,omitempty"`
	PrivateKey       ed25519.PrivateKey `json:"-"`
}

// EvidenceTombstone is the immutable cryptographic record of explicit operator destruction.
type EvidenceTombstone struct {
	SchemaVersion     string `json:"schema_version"`
	TombstoneID       string `json:"tombstone_id"`
	OperationID       string `json:"operation_id"`
	CaseID            string `json:"case_id"`
	EvidenceID        string `json:"evidence_id"`
	State             string `json:"state"`
	OriginalSHA256    string `json:"original_sha256"`
	OriginalSizeBytes int64  `json:"original_size_bytes"`
	OriginalMediaType string `json:"original_media_type"`
	CustodyRoot       string `json:"custody_root"`
	Operator          string `json:"operator"`
	Reason            string `json:"reason"`
	DestroyedAt       string `json:"destroyed_at"`
	Provider          string `json:"provider"`
	TombstoneDigest   string `json:"tombstone_digest"`
	Signed            bool   `json:"signed"`
	KeyID             string `json:"key_id,omitempty"`
	PublicKey         string `json:"public_key,omitempty"`
	Signature         string `json:"signature,omitempty"`
	SealedBytesIntact bool   `json:"sealed_bytes_intact"`
}

// DestroyOutcome reports the persisted tombstone state and idempotency status.
type DestroyOutcome struct {
	Tombstone        EvidenceTombstone `json:"tombstone"`
	Generation       uint64            `json:"generation"`
	IdempotentReplay bool              `json:"idempotent_replay,omitempty"`
}

// DestructionAuditEntry records every allowed or hold-blocked destruction attempt.
type DestructionAuditEntry struct {
	SchemaVersion   string   `json:"schema_version"`
	AuditID         string   `json:"audit_id"`
	Sequence        uint64   `json:"sequence"`
	CaseID          string   `json:"case_id"`
	EvidenceID      string   `json:"evidence_id"`
	Action          string   `json:"action"`
	Outcome         string   `json:"outcome"`
	BlockingHoldIDs []string `json:"blocking_hold_ids,omitempty"`
	TombstoneID     string   `json:"tombstone_id,omitempty"`
	Operator        string   `json:"operator"`
	Timestamp       string   `json:"timestamp"`
	Reason          string   `json:"reason"`
	Provider        string   `json:"provider,omitempty"`
}

// RecoveryReport summarizes startup recovery after process restarts or crashes.
type RecoveryReport struct {
	CleanedStagingFiles []string `json:"cleaned_staging_files"`
	RecoveredTombstones int      `json:"recovered_tombstones"`
	RecoveredPolicies   int      `json:"recovered_policies"`
	RecoveredOperations int      `json:"recovered_operations"`
}

type persistedOperation struct {
	RequestFingerprint string         `json:"request_fingerprint"`
	Outcome            DestroyOutcome `json:"outcome"`
}

type persistedRetentionState struct {
	SchemaVersion string                        `json:"schema_version"`
	Generation    uint64                        `json:"generation"`
	Policies      map[string]RetentionPolicy    `json:"policies"`
	Tombstones    map[string]EvidenceTombstone  `json:"tombstones"`
	Operations    map[string]persistedOperation `json:"operations"`
}

// RetentionStore enforces no-automatic-TTL and durable operator destruction tombstones.
type RetentionStore struct {
	mu             sync.Mutex
	cfg            RetentionConfig
	rootDir        string
	lockFile       *os.File
	state          persistedRetentionState
	audits         map[string][]DestructionAuditEntry
	recoveryReport RecoveryReport
	closed         bool
}

func isValidIdentifier(s string) bool {
	return identifierRegex.MatchString(s) && !strings.Contains(s, "..") && !strings.ContainsAny(s, "/\\")
}

func validateTimestamp(ts string) error {
	if strings.TrimSpace(ts) == "" {
		return fmt.Errorf("%w: timestamp is required", ErrInvalidRetention)
	}
	if !timestampRegex.MatchString(ts) {
		return fmt.Errorf("%w: invalid RFC3339 timestamp %q", ErrInvalidRetention, ts)
	}
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		return fmt.Errorf("%w: parse timestamp %v", ErrInvalidRetention, err)
	}
	return nil
}

func ensureNoSymlink(path string) (bool, error) {
	clean := filepath.Clean(path)
	cur := clean
	if filepath.IsAbs(clean) {
		cur = "/"
		parts := strings.Split(strings.TrimPrefix(clean, "/"), string(filepath.Separator))
		for _, p := range parts {
			if p == "" {
				continue
			}
			cur = filepath.Join(cur, p)
			info, err := os.Lstat(cur)
			if err != nil {
				if os.IsNotExist(err) {
					return false, nil
				}
				return false, err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return true, fmt.Errorf("%w: %s", ErrSymlinkRejected, cur)
			}
		}
		return true, nil
	}
	info, err := os.Lstat(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true, fmt.Errorf("%w: %s", ErrSymlinkRejected, clean)
	}
	return true, nil
}

func checkWithinDir(root, target string) error {
	absRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	absTarget, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	rel, err := filepath.Rel(absRoot, absTarget)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %s escapes %s", ErrPathTraversal, absTarget, absRoot)
	}
	return nil
}

func evidenceKey(caseID, evidenceID string) string {
	return caseID + "/" + evidenceID
}

// ComputeTombstoneDigest computes the deterministic SHA-256 digest of a tombstone excluding digest/signature fields.
func ComputeTombstoneDigest(t EvidenceTombstone) string {
	canon := struct {
		SchemaVersion     string `json:"schema_version"`
		TombstoneID       string `json:"tombstone_id"`
		OperationID       string `json:"operation_id"`
		CaseID            string `json:"case_id"`
		EvidenceID        string `json:"evidence_id"`
		State             string `json:"state"`
		OriginalSHA256    string `json:"original_sha256"`
		OriginalSizeBytes int64  `json:"original_size_bytes"`
		OriginalMediaType string `json:"original_media_type"`
		CustodyRoot       string `json:"custody_root"`
		Operator          string `json:"operator"`
		Reason            string `json:"reason"`
		DestroyedAt       string `json:"destroyed_at"`
		Provider          string `json:"provider"`
		Signed            bool   `json:"signed"`
		KeyID             string `json:"key_id,omitempty"`
	}{
		SchemaVersion:     t.SchemaVersion,
		TombstoneID:       t.TombstoneID,
		OperationID:       t.OperationID,
		CaseID:            t.CaseID,
		EvidenceID:        t.EvidenceID,
		State:             t.State,
		OriginalSHA256:    t.OriginalSHA256,
		OriginalSizeBytes: t.OriginalSizeBytes,
		OriginalMediaType: t.OriginalMediaType,
		CustodyRoot:       t.CustodyRoot,
		Operator:          t.Operator,
		Reason:            t.Reason,
		DestroyedAt:       t.DestroyedAt,
		Provider:          t.Provider,
		Signed:            t.Signed,
		KeyID:             t.KeyID,
	}
	raw, _ := json.Marshal(canon)
	sum := sha256.Sum256(append([]byte(tombstoneDomainPrefix), raw...))
	return hex.EncodeToString(sum[:])
}

// CanonicalTombstoneSignaturePayload returns the exact signed Ed25519 payload for an EvidenceTombstone.
func CanonicalTombstoneSignaturePayload(t EvidenceTombstone) []byte {
	return []byte(fmt.Sprintf("%s%s:%s:%s:%s", tombstoneDomainPrefix, t.CaseID, t.EvidenceID, t.TombstoneID, t.TombstoneDigest))
}

// OpenRetentionStore opens or initializes a locked, crash-recoverable RetentionStore.
func OpenRetentionStore(cfg RetentionConfig) (*RetentionStore, error) {
	if strings.TrimSpace(cfg.RootDir) == "" {
		return nil, ErrStoreDirRequired
	}
	absRoot, err := filepath.Abs(filepath.Clean(cfg.RootDir))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if _, err := ensureNoSymlink(absRoot); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absRoot, 0750); err != nil {
		return nil, fmt.Errorf("create retention root: %w", err)
	}
	for _, sub := range []string{stagingSubdir, tombstonesSubdir, auditSubdir} {
		subPath := filepath.Join(absRoot, sub)
		if _, err := ensureNoSymlink(subPath); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(subPath, 0750); err != nil {
			return nil, fmt.Errorf("create retention subdir %s: %w", sub, err)
		}
	}

	lockPath := filepath.Join(absRoot, retentionLockFileName)
	if _, err := ensureNoSymlink(lockPath); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		return nil, fmt.Errorf("open retention lock: %w", err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lf.Close()
		return nil, ErrLockBusy
	}

	s := &RetentionStore{
		cfg:      cfg,
		rootDir:  absRoot,
		lockFile: lf,
		audits:   make(map[string][]DestructionAuditEntry),
		state: persistedRetentionState{
			SchemaVersion: SchemaVersion,
			Policies:      make(map[string]RetentionPolicy),
			Tombstones:    make(map[string]EvidenceTombstone),
			Operations:    make(map[string]persistedOperation),
		},
	}

	if err := s.recoverOnOpen(); err != nil {
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
		_ = lf.Close()
		return nil, err
	}
	return s, nil
}

func (s *RetentionStore) recoverOnOpen() error {
	// Clean interrupted staging files
	stDir := filepath.Join(s.rootDir, stagingSubdir)
	entries, err := os.ReadDir(stDir)
	if err != nil {
		return fmt.Errorf("read retention staging: %w", err)
	}
	for _, ent := range entries {
		p := filepath.Join(stDir, ent.Name())
		_ = os.RemoveAll(p)
		s.recoveryReport.CleanedStagingFiles = append(s.recoveryReport.CleanedStagingFiles, ent.Name())
	}
	sort.Strings(s.recoveryReport.CleanedStagingFiles)

	// Load state JSON if present
	statePath := filepath.Join(s.rootDir, stateFileName)
	if _, err := ensureNoSymlink(statePath); err != nil {
		return err
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read retention state: %w", err)
		}
	} else {
		var loaded persistedRetentionState
		if uErr := json.Unmarshal(raw, &loaded); uErr != nil {
			return fmt.Errorf("%w: parse state JSON: %v", ErrCorruptedRetentionState, uErr)
		}
		if loaded.SchemaVersion != SchemaVersion {
			return fmt.Errorf("%w: unsupported state schema %q", ErrCorruptedRetentionState, loaded.SchemaVersion)
		}
		if loaded.Policies == nil {
			loaded.Policies = make(map[string]RetentionPolicy)
		}
		if loaded.Tombstones == nil {
			loaded.Tombstones = make(map[string]EvidenceTombstone)
		}
		if loaded.Operations == nil {
			loaded.Operations = make(map[string]persistedOperation)
		}
		// Reject any persisted auto-TTL corruption on load
		for cid, p := range loaded.Policies {
			if p.AutoDeleteRawEvidence || p.RawTTLSeconds > 0 {
				return fmt.Errorf("%w: persisted policy for %s enables forbidden raw TTL", ErrCorruptedRetentionState, cid)
			}
		}
		// Verify tombstone digests
		for key, t := range loaded.Tombstones {
			if ComputeTombstoneDigest(t) != t.TombstoneDigest {
				return fmt.Errorf("%w: tombstone %s digest mismatch on load", ErrCorruptedRetentionState, key)
			}
		}
		s.state = loaded
		s.recoveryReport.RecoveredPolicies = len(loaded.Policies)
		s.recoveryReport.RecoveredTombstones = len(loaded.Tombstones)
		s.recoveryReport.RecoveredOperations = len(loaded.Operations)
	}

	// Recover per-evidence audit trails
	if err := s.recoverAudits(); err != nil {
		return err
	}
	return nil
}

func (s *RetentionStore) recoverAudits() error {
	aDir := filepath.Join(s.rootDir, auditSubdir)
	caseDirs, err := os.ReadDir(aDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, cEnt := range caseDirs {
		if !cEnt.IsDir() || !isValidIdentifier(cEnt.Name()) {
			continue
		}
		cPath := filepath.Join(aDir, cEnt.Name())
		files, err := os.ReadDir(cPath)
		if err != nil {
			return err
		}
		for _, fEnt := range files {
			if fEnt.IsDir() || !strings.HasSuffix(fEnt.Name(), ".jsonl") {
				continue
			}
			evID := strings.TrimSuffix(fEnt.Name(), ".jsonl")
			if !isValidIdentifier(evID) {
				continue
			}
			fPath := filepath.Join(cPath, fEnt.Name())
			entries, err := loadAuditFile(fPath, cEnt.Name(), evID)
			if err != nil {
				return err
			}
			s.audits[evidenceKey(cEnt.Name(), evID)] = entries
		}
	}
	return nil
}

func loadAuditFile(path, expectedCaseID, expectedEvID string) ([]DestructionAuditEntry, error) {
	if _, err := ensureNoSymlink(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []DestructionAuditEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), maxAuditEntryBytes)
	expectedSeq := uint64(1)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e DestructionAuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("%w: malformed audit entry JSON: %v", ErrCorruptedRetentionState, err)
		}
		if e.CaseID != expectedCaseID || e.EvidenceID != expectedEvID || e.Sequence != expectedSeq {
			return nil, fmt.Errorf("%w: audit sequence or case/evidence mismatch", ErrCorruptedRetentionState)
		}
		entries = append(entries, e)
		expectedSeq++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan audit %s: %w", path, err)
	}
	return entries, nil
}

// RecoveryReport returns the startup recovery summary.
func (s *RetentionStore) RecoveryReport() RecoveryReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoveryReport
}

// Close closes the RetentionStore and releases its exclusive flock.
func (s *RetentionStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
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

// SetPolicy stores a case retention policy, explicitly rejecting any automatic raw-evidence TTL.
func (s *RetentionStore) SetPolicy(ctx context.Context, p RetentionPolicy) (*RetentionPolicy, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if p.SchemaVersion != "" && p.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported schema version %q", ErrInvalidRetention, p.SchemaVersion)
	}
	p.SchemaVersion = SchemaVersion
	if !isValidIdentifier(p.PolicyID) {
		return nil, fmt.Errorf("%w: invalid policy_id %q", ErrInvalidRetention, p.PolicyID)
	}
	if !isValidIdentifier(p.CaseID) {
		return nil, fmt.Errorf("%w: invalid case_id %q", ErrInvalidRetention, p.CaseID)
	}
	if !allowedProviders[strings.TrimSpace(p.Provider)] {
		return nil, fmt.Errorf("%w: %q", ErrUnavailableProvider, p.Provider)
	}
	if strings.TrimSpace(p.Provider) == "" {
		p.Provider = "local"
	}
	if p.AutoDeleteRawEvidence || p.RawTTLSeconds > 0 {
		return nil, fmt.Errorf("%w: case %s policy %s cannot enable automatic raw-evidence deletion or TTL", ErrAutoRawTTLForbidden, p.CaseID, p.PolicyID)
	}
	if strings.TrimSpace(p.Actor) == "" || !isValidIdentifier(p.Actor) {
		return nil, fmt.Errorf("%w: valid actor is required", ErrInvalidRetention)
	}
	if strings.TrimSpace(p.Reason) == "" {
		return nil, fmt.Errorf("%w: reason is required", ErrInvalidRetention)
	}
	if err := validateTimestamp(p.UpdatedAt); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	if s.cfg.Faults.SimulateDiskFull {
		return nil, ErrDiskFull
	}

	prev, existed := s.state.Policies[p.CaseID]
	s.state.Policies[p.CaseID] = p
	s.state.Generation++
	if err := s.persistStateLocked(); err != nil {
		if existed {
			s.state.Policies[p.CaseID] = prev
		} else {
			delete(s.state.Policies, p.CaseID)
		}
		s.state.Generation--
		return nil, err
	}

	cp := p
	return &cp, nil
}

// EvaluateAutomaticRetention checks sealed items for a case and strictly enforces that ZERO raw
// evidence items are ever deleted automatically by TTL.
func (s *RetentionStore) EvaluateAutomaticRetention(ctx context.Context, caseID string) (*AutoSweepReport, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if !isValidIdentifier(caseID) {
		return nil, fmt.Errorf("%w: invalid case_id %q", ErrInvalidRetention, caseID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	if s.cfg.SealStore == nil || s.cfg.HoldService == nil {
		return nil, fmt.Errorf("%w: SealStore and HoldService are required", ErrMissingPrerequisite)
	}
	if p, ok := s.state.Policies[caseID]; ok && (p.AutoDeleteRawEvidence || p.RawTTLSeconds > 0) {
		return nil, ErrAutoRawTTLForbidden
	}

	manifests := s.cfg.SealStore.ListSealedManifests()
	report := &AutoSweepReport{
		CaseID:          caseID,
		RawDeletedCount: 0, // Guarantee: zero automatic raw-evidence deletions ever occur
	}
	for _, m := range manifests {
		if m.CaseID != caseID {
			continue
		}
		report.EvaluatedCount++
		if _, tombstoned := s.state.Tombstones[evidenceKey(m.CaseID, m.EvidenceID)]; tombstoned {
			continue
		}
		st, err := s.cfg.HoldService.GetEvidenceStatus(m.CaseID, m.EvidenceID)
		if err != nil {
			return nil, fmt.Errorf("%w: inspect hold status for %s/%s: %v", ErrMissingPrerequisite, m.CaseID, m.EvidenceID, err)
		}
		if st.ActiveHoldCount > 0 {
			report.HeldCount++
		} else {
			report.EligibleCandidateIDs = append(report.EligibleCandidateIDs, m.EvidenceID)
		}
	}
	sort.Strings(report.EligibleCandidateIDs)
	return report, nil
}

func fingerprintDestroyRequest(req DestroyRequest) string {
	raw, _ := json.Marshal(struct {
		SchemaVersion    string
		TombstoneID      string
		CaseID           string
		EvidenceID       string
		Operator         string
		Timestamp        string
		Reason           string
		Provider         string
		ExplicitApproval bool
		KeyID            string
	}{
		SchemaVersion:    req.SchemaVersion,
		TombstoneID:      req.TombstoneID,
		CaseID:           req.CaseID,
		EvidenceID:       req.EvidenceID,
		Operator:         req.Operator,
		Timestamp:        req.Timestamp,
		Reason:           req.Reason,
		Provider:         req.Provider,
		ExplicitApproval: req.ExplicitApproval,
		KeyID:            req.KeyID,
	})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// DestroyEvidence enforces legal hold precedence, prohibits automatic TTL destruction,
// audits every blocked or allowed attempt, and records an immutable EvidenceTombstone.
func (s *RetentionStore) DestroyEvidence(ctx context.Context, req DestroyRequest) (*DestroyOutcome, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if req.AutomaticTTL {
		return nil, fmt.Errorf("%w: automatic TTL cannot invoke evidence destruction", ErrAutoRawTTLForbidden)
	}
	if !req.ExplicitApproval {
		return nil, ErrExplicitApprovalRequired
	}
	if req.SchemaVersion != "" && req.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported schema version %q", ErrInvalidRetention, req.SchemaVersion)
	}
	req.SchemaVersion = SchemaVersion
	if !isValidIdentifier(req.OperationID) {
		return nil, fmt.Errorf("%w: invalid operation_id %q", ErrInvalidRetention, req.OperationID)
	}
	if !isValidIdentifier(req.TombstoneID) {
		return nil, fmt.Errorf("%w: invalid tombstone_id %q", ErrInvalidRetention, req.TombstoneID)
	}
	if !isValidIdentifier(req.CaseID) || !isValidIdentifier(req.EvidenceID) {
		return nil, fmt.Errorf("%w: invalid case_id or evidence_id", ErrInvalidRetention)
	}
	if strings.TrimSpace(req.Operator) == "" || !isValidIdentifier(req.Operator) {
		return nil, fmt.Errorf("%w: valid operator is required", ErrInvalidRetention)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return nil, fmt.Errorf("%w: reason is required", ErrInvalidRetention)
	}
	if err := validateTimestamp(req.Timestamp); err != nil {
		return nil, err
	}
	if !allowedProviders[strings.TrimSpace(req.Provider)] {
		return nil, fmt.Errorf("%w: %q", ErrUnavailableProvider, req.Provider)
	}
	if strings.TrimSpace(req.Provider) == "" {
		req.Provider = "local"
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	fp := fingerprintDestroyRequest(req)
	if prevOp, ok := s.state.Operations[req.OperationID]; ok {
		if prevOp.RequestFingerprint != fp {
			return nil, fmt.Errorf("%w: operation_id %q mismatch", ErrRetentionConflict, req.OperationID)
		}
		replay := prevOp.Outcome
		replay.IdempotentReplay = true
		return &replay, nil
	}

	if s.cfg.SealStore == nil || s.cfg.HoldService == nil {
		return nil, fmt.Errorf("%w: SealStore and HoldService prerequisites are required", ErrMissingPrerequisite)
	}

	// Verify prerequisite sealed evidence exists before proceeding
	sm, err := s.cfg.SealStore.GetSealedManifest(req.CaseID, req.EvidenceID)
	if err != nil || sm == nil || !sm.Sealed {
		return nil, fmt.Errorf("%w: sealed evidence %s/%s unavailable: %v", ErrMissingPrerequisite, req.CaseID, req.EvidenceID, err)
	}

	key := evidenceKey(req.CaseID, req.EvidenceID)
	if _, destroyed := s.state.Tombstones[key]; destroyed {
		return nil, fmt.Errorf("%w: evidence %s already tombstoned", ErrAlreadyDestroyed, key)
	}

	// Consult holds service before attempting disposal so active holds are strictly honored and audited
	holdStatus, err := s.cfg.HoldService.GetEvidenceStatus(req.CaseID, req.EvidenceID)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect hold status: %v", ErrMissingPrerequisite, err)
	}
	if holdStatus.ActiveHoldCount > 0 {
		_, _ = s.appendAuditLocked(DestructionAuditEntry{
			CaseID:          req.CaseID,
			EvidenceID:      req.EvidenceID,
			Action:          ActionDestructionBlocked,
			Outcome:         OutcomeBlocked,
			BlockingHoldIDs: holdStatus.ActiveHoldIDs,
			Operator:        req.Operator,
			Timestamp:       req.Timestamp,
			Reason:          req.Reason,
			Provider:        req.Provider,
		})
		return nil, fmt.Errorf("%w: legal holds [%s] block operator destruction of %s", ErrHoldActive, strings.Join(holdStatus.ActiveHoldIDs, ", "), key)
	}

	// Simulate faults before committing authoritative tombstone state
	if s.cfg.Faults.SimulateDiskFull {
		return nil, ErrDiskFull
	}

	// Stage tombstone file first to test crash boundaries cleanly
	tombstone := EvidenceTombstone{
		SchemaVersion:     SchemaVersion,
		TombstoneID:       req.TombstoneID,
		OperationID:       req.OperationID,
		CaseID:            req.CaseID,
		EvidenceID:        req.EvidenceID,
		State:             StateDeletedTombstone,
		OriginalSHA256:    sm.SHA256,
		OriginalSizeBytes: sm.SizeBytes,
		OriginalMediaType: sm.MediaType,
		CustodyRoot:       sm.CustodyRoot,
		Operator:          req.Operator,
		Reason:            req.Reason,
		DestroyedAt:       req.Timestamp,
		Provider:          req.Provider,
		SealedBytesIntact: true,
	}

	if s.cfg.LedgerStore != nil {
		if root, rErr := s.cfg.LedgerStore.CurrentRoot(req.CaseID, req.EvidenceID); rErr == nil && root != "" {
			tombstone.CustodyRoot = root
		}
	}

	if len(req.PrivateKey) == ed25519.PrivateKeySize {
		tombstone.Signed = true
		tombstone.KeyID = req.KeyID
	}
	tombstone.TombstoneDigest = ComputeTombstoneDigest(tombstone)
	if tombstone.Signed {
		pub := req.PrivateKey.Public().(ed25519.PublicKey)
		tombstone.PublicKey = hex.EncodeToString(pub)
		sig := ed25519.Sign(req.PrivateKey, CanonicalTombstoneSignaturePayload(tombstone))
		tombstone.Signature = hex.EncodeToString(sig)
	}

	// Stage individual tombstone JSON before executing atomic transition
	stageTombstonePath := filepath.Join(s.rootDir, stagingSubdir, fmt.Sprintf("tomb-%s-%s.json", req.CaseID, req.TombstoneID))
	tombBytes, err := json.MarshalIndent(tombstone, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeAndSyncFile(stageTombstonePath, append(tombBytes, '\n'), 0640); err != nil {
		return nil, err
	}

	if s.cfg.Faults.FailAfterStageBeforeCommit {
		return nil, ErrInterrupted
	}

	// Enforce atomic deletion check inside holds.Service.DeleteEvidence to serialize against concurrent holds
	_, delErr := s.cfg.HoldService.DeleteEvidence(ctx, holds.DisposalRequest{
		CaseID:     req.CaseID,
		EvidenceID: req.EvidenceID,
		Actor:      req.Operator,
		Timestamp:  req.Timestamp,
		Reason:     req.Reason,
		Provider:   req.Provider,
		PrivateKey: req.PrivateKey,
	})
	if delErr != nil {
		_ = os.Remove(stageTombstonePath)
		if errors.Is(delErr, holds.ErrHoldActive) {
			_, _ = s.appendAuditLocked(DestructionAuditEntry{
				CaseID:     req.CaseID,
				EvidenceID: req.EvidenceID,
				Action:     ActionDestructionBlocked,
				Outcome:    OutcomeBlocked,
				Operator:   req.Operator,
				Timestamp:  req.Timestamp,
				Reason:     req.Reason,
				Provider:   req.Provider,
			})
			return nil, fmt.Errorf("%w: %v", ErrHoldActive, delErr)
		}
		return nil, delErr
	}

	// Commit tombstone file atomically into tombstones/<caseID>/<evidenceID>.json
	tombDir := filepath.Join(s.rootDir, tombstonesSubdir, req.CaseID)
	if err := checkWithinDir(s.rootDir, tombDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(tombDir, 0750); err != nil {
		return nil, err
	}
	finalTombPath := filepath.Join(tombDir, req.EvidenceID+".json")
	if err := os.Rename(stageTombstonePath, finalTombPath); err != nil {
		return nil, fmt.Errorf("commit tombstone: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(tombDir)
	}

	// Update in-memory state and persist authoritative JSON state
	s.state.Generation++
	outcome := DestroyOutcome{
		Tombstone:  tombstone,
		Generation: s.state.Generation,
	}
	s.state.Tombstones[key] = tombstone
	s.state.Operations[req.OperationID] = persistedOperation{
		RequestFingerprint: fp,
		Outcome:            outcome,
	}
	if err := s.persistStateLocked(); err != nil {
		return nil, err
	}

	// Append durable destruction audit entry
	if _, err := s.appendAuditLocked(DestructionAuditEntry{
		CaseID:      req.CaseID,
		EvidenceID:  req.EvidenceID,
		Action:      ActionEvidenceDestroyed,
		Outcome:     OutcomeAllowed,
		TombstoneID: tombstone.TombstoneID,
		Operator:    req.Operator,
		Timestamp:   req.Timestamp,
		Reason:      req.Reason,
		Provider:    req.Provider,
	}); err != nil {
		return nil, err
	}

	return &outcome, nil
}

// GetTombstone returns the immutable tombstone for (caseID, evidenceID) if destroyed.
func (s *RetentionStore) GetTombstone(caseID, evidenceID string) (*EvidenceTombstone, error) {
	if !isValidIdentifier(caseID) || !isValidIdentifier(evidenceID) {
		return nil, fmt.Errorf("%w: invalid case_id or evidence_id", ErrInvalidRetention)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	t, ok := s.state.Tombstones[evidenceKey(caseID, evidenceID)]
	if !ok {
		return nil, ErrTombstoneNotFound
	}
	cp := t
	return &cp, nil
}

// VerifyTombstone checks tombstone digest integrity and optional Ed25519 signature against trusted keys.
func VerifyTombstone(t EvidenceTombstone, trustedPubKeys map[string]string) error {
	if t.SchemaVersion != SchemaVersion || t.State != StateDeletedTombstone {
		return fmt.Errorf("%w: invalid schema or state", ErrTombstoneInvalid)
	}
	if ComputeTombstoneDigest(t) != t.TombstoneDigest {
		return fmt.Errorf("%w: digest mismatch", ErrTombstoneInvalid)
	}
	if t.Signed {
		pubBytes, pErr := hex.DecodeString(strings.TrimSpace(t.PublicKey))
		sigBytes, sErr := hex.DecodeString(strings.TrimSpace(t.Signature))
		if pErr != nil || sErr != nil || len(pubBytes) != ed25519.PublicKeySize || len(sigBytes) != ed25519.SignatureSize {
			return fmt.Errorf("%w: invalid signature encoding", ErrTombstoneInvalid)
		}
		if !ed25519.Verify(pubBytes, CanonicalTombstoneSignaturePayload(t), sigBytes) {
			return fmt.Errorf("%w: Ed25519 signature invalid", ErrTombstoneInvalid)
		}
		if len(trustedPubKeys) > 0 {
			trustedHex, ok := trustedPubKeys[t.KeyID]
			if !ok {
				trustedHex = trustedPubKeys["*"]
			}
			if !strings.EqualFold(strings.TrimSpace(trustedHex), strings.TrimSpace(t.PublicKey)) {
				return fmt.Errorf("%w: untrusted signer key %q", ErrTombstoneInvalid, t.KeyID)
			}
		}
	}
	return nil
}

// AuditTrail returns all recorded destruction audit entries for (caseID, evidenceID).
func (s *RetentionStore) AuditTrail(caseID, evidenceID string) ([]DestructionAuditEntry, error) {
	if !isValidIdentifier(caseID) || !isValidIdentifier(evidenceID) {
		return nil, fmt.Errorf("%w: invalid case_id or evidence_id", ErrInvalidRetention)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	list := s.audits[evidenceKey(caseID, evidenceID)]
	out := make([]DestructionAuditEntry, len(list))
	copy(out, list)
	return out, nil
}

func (s *RetentionStore) persistStateLocked() error {
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := filepath.Join(s.rootDir, stagingSubdir, fmt.Sprintf("state-%d.tmp", s.state.Generation))
	if err := writeAndSyncFile(tmpPath, append(raw, '\n'), 0640); err != nil {
		return err
	}
	dstPath := filepath.Join(s.rootDir, stateFileName)
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic state replace: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(s.rootDir)
	}
	return nil
}

func (s *RetentionStore) appendAuditLocked(entry DestructionAuditEntry) (DestructionAuditEntry, error) {
	key := evidenceKey(entry.CaseID, entry.EvidenceID)
	existing := s.audits[key]
	entry.SchemaVersion = SchemaVersion
	entry.Sequence = uint64(len(existing)) + 1
	entry.AuditID = fmt.Sprintf("raud-%s-%s-%06d", entry.CaseID, entry.EvidenceID, entry.Sequence)

	aCaseDir := filepath.Join(s.rootDir, auditSubdir, entry.CaseID)
	if err := checkWithinDir(s.rootDir, aCaseDir); err != nil {
		return DestructionAuditEntry{}, err
	}
	if err := os.MkdirAll(aCaseDir, 0750); err != nil {
		return DestructionAuditEntry{}, err
	}
	aFile := filepath.Join(aCaseDir, entry.EvidenceID+".jsonl")
	if _, err := ensureNoSymlink(aFile); err != nil {
		return DestructionAuditEntry{}, err
	}

	lineBytes, err := json.Marshal(entry)
	if err != nil {
		return DestructionAuditEntry{}, err
	}
	f, err := os.OpenFile(aFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return DestructionAuditEntry{}, err
	}
	if _, err := f.Write(append(lineBytes, '\n')); err != nil {
		_ = f.Close()
		return DestructionAuditEntry{}, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return DestructionAuditEntry{}, err
	}
	if err := f.Close(); err != nil {
		return DestructionAuditEntry{}, err
	}
	if s.cfg.SyncDir {
		_ = syncDir(aCaseDir)
	}

	s.audits[key] = append(existing, entry)
	return entry, nil
}

func writeAndSyncFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

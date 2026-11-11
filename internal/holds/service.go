package holds

import (
	"bufio"
	"context"
	"crypto/ed25519"
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
)

const (
	SchemaVersion      = "1"
	DefaultHoldsDir    = "holds"
	stateFileName      = "holds-state.json"
	auditDirName       = "audit"
	holdsLockFileName  = ".holds.lock"
	MaxAuditEntryBytes = 64 * 1024 // 64 KiB
)

const (
	HoldStatusActive   = "active"
	HoldStatusReleased = "released"

	DispositionRetained = "retained"
	DispositionDeleted  = "deleted"
	DispositionExpired  = "expired"

	ActionHoldPlaced        = "hold_placed"
	ActionHoldReleased      = "hold_released"
	ActionDeleteBlocked     = "delete_blocked"
	ActionExpirationBlocked = "expiration_blocked"
	ActionEvidenceDeleted   = "evidence_deleted"
	ActionRetentionExpired  = "retention_expired"

	OutcomeAllowed = "allowed"
	OutcomeBlocked = "blocked"
)

var (
	ErrStoreDirRequired        = errors.New("holds root directory is required")
	ErrSealStoreRequired       = errors.New("seal store prerequisite is required")
	ErrServiceClosed           = errors.New("holds service closed")
	ErrLockBusy                = errors.New("holds store lock busy: another instance holds exclusive lock")
	ErrMissingPrerequisite     = errors.New("missing prerequisite")
	ErrMissingActor            = errors.New("actor is required for hold or disposal operation")
	ErrMissingReason           = errors.New("reason is required for hold or disposal operation")
	ErrMissingTimestamp        = errors.New("timestamp is required for hold or disposal operation")
	ErrInvalidTimestamp        = errors.New("invalid RFC3339 timestamp")
	ErrInvalidHold             = errors.New("invalid hold or disposal specification")
	ErrUnavailableProvider     = errors.New("unavailable hold provider")
	ErrHoldActive              = errors.New("operation blocked: active legal hold protects evidence")
	ErrHoldNotFound            = errors.New("legal hold not found")
	ErrHoldAlreadyReleased     = errors.New("legal hold already released")
	ErrHoldConflict            = errors.New("hold_id reused with conflicting parameters")
	ErrEvidenceAlreadyDisposed = errors.New("evidence already disposed")
	ErrCorruptedHoldState      = errors.New("corrupted persisted hold or audit state")
	ErrPathTraversal           = errors.New("path traversal or invalid path component rejected")
	ErrSymlinkRejected         = errors.New("symlink rejected in holds storage path")
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

func isValidIdentifier(s string) bool {
	return identifierRegex.MatchString(s) && !strings.Contains(s, "..") && !strings.ContainsAny(s, "/\\")
}

func validateTimestamp(ts string) (time.Time, error) {
	if strings.TrimSpace(ts) == "" {
		return time.Time{}, ErrMissingTimestamp
	}
	if !timestampRegex.MatchString(ts) {
		return time.Time{}, fmt.Errorf("%w: %q", ErrInvalidTimestamp, ts)
	}
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %v", ErrInvalidTimestamp, err)
	}
	return parsed, nil
}

func ensureNoSymlink(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return true, fmt.Errorf("%w: %s", ErrSymlinkRejected, path)
	}
	return true, nil
}

func checkWithinDir(root, target string) error {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %s escapes root", ErrPathTraversal, target)
	}
	return nil
}

// ServiceConfig configures a durable, concurrency-safe legal hold service.
type ServiceConfig struct {
	RootDir   string
	SealStore *evidence.SealStore
	Ledger    *custody.LedgerStore
	SyncDir   bool
}

// HoldRecord represents a legal hold bound to an evidence artifact inside a case.
type HoldRecord struct {
	SchemaVersion string `json:"schema_version"`
	HoldID        string `json:"hold_id"`
	CaseID        string `json:"case_id"`
	EvidenceID    string `json:"evidence_id"`
	Status        string `json:"status"`
	Reason        string `json:"reason"`
	PlacedBy      string `json:"placed_by"`
	PlacedAt      string `json:"placed_at"`
	ReleasedBy    string `json:"released_by,omitempty"`
	ReleasedAt    string `json:"released_at,omitempty"`
	ReleaseReason string `json:"release_reason,omitempty"`
	Provider      string `json:"provider,omitempty"`
}

// DispositionRecord records the post-release disposal state when no active hold blocks it.
type DispositionRecord struct {
	CaseID      string `json:"case_id"`
	EvidenceID  string `json:"evidence_id"`
	Disposition string `json:"disposition"`
	Actor       string `json:"actor"`
	Timestamp   string `json:"timestamp"`
	Reason      string `json:"reason"`
	Provider    string `json:"provider,omitempty"`
}

// AuditEntry is an immutable, attributable record of every hold or disposal attempt.
type AuditEntry struct {
	SchemaVersion   string   `json:"schema_version"`
	AuditID         string   `json:"audit_id"`
	Sequence        uint64   `json:"sequence"`
	CaseID          string   `json:"case_id"`
	EvidenceID      string   `json:"evidence_id"`
	Action          string   `json:"action"`
	Outcome         string   `json:"outcome"`
	HoldID          string   `json:"hold_id,omitempty"`
	BlockingHoldIDs []string `json:"blocking_hold_ids,omitempty"`
	Actor           string   `json:"actor"`
	Timestamp       string   `json:"timestamp"`
	Reason          string   `json:"reason"`
	Provider        string   `json:"provider,omitempty"`
}

// EvidenceHoldStatus summarizes the active holds and retention disposition for an evidence item.
type EvidenceHoldStatus struct {
	CaseID          string       `json:"case_id"`
	EvidenceID      string       `json:"evidence_id"`
	Sealed          bool         `json:"sealed"`
	ActiveHoldCount int          `json:"active_hold_count"`
	ActiveHoldIDs   []string     `json:"active_hold_ids"`
	Holds           []HoldRecord `json:"holds"`
	Disposition     string       `json:"disposition"`
	AuditCount      int          `json:"audit_count"`
}

// PlaceHoldRequest defines parameters for placing an active legal hold on sealed evidence.
type PlaceHoldRequest struct {
	HoldID     string             `json:"hold_id"`
	CaseID     string             `json:"case_id"`
	EvidenceID string             `json:"evidence_id"`
	Actor      string             `json:"actor"`
	Timestamp  string             `json:"timestamp"`
	Reason     string             `json:"reason"`
	Provider   string             `json:"provider,omitempty"`
	PrivateKey ed25519.PrivateKey `json:"-"`
}

// ReleaseHoldRequest defines parameters for releasing an existing active legal hold.
type ReleaseHoldRequest struct {
	HoldID     string             `json:"hold_id"`
	CaseID     string             `json:"case_id"`
	EvidenceID string             `json:"evidence_id"`
	Actor      string             `json:"actor"`
	Timestamp  string             `json:"timestamp"`
	Reason     string             `json:"reason"`
	Provider   string             `json:"provider,omitempty"`
	PrivateKey ed25519.PrivateKey `json:"-"`
}

// DisposalRequest defines parameters for deleting evidence or expiring its retention.
type DisposalRequest struct {
	CaseID     string             `json:"case_id"`
	EvidenceID string             `json:"evidence_id"`
	Actor      string             `json:"actor"`
	Timestamp  string             `json:"timestamp"`
	Reason     string             `json:"reason"`
	Provider   string             `json:"provider,omitempty"`
	PrivateKey ed25519.PrivateKey `json:"-"`
}

// DisposalResult reports an allowed disposal outcome when no active hold blocks it.
type DisposalResult struct {
	CaseID      string `json:"case_id"`
	EvidenceID  string `json:"evidence_id"`
	Action      string `json:"action"`
	Disposition string `json:"disposition"`
	Actor       string `json:"actor"`
	Timestamp   string `json:"timestamp"`
	Reason      string `json:"reason"`
}

type persistedState struct {
	SchemaVersion string                       `json:"schema_version"`
	NextHoldSeq   uint64                       `json:"next_hold_seq"`
	Holds         map[string]HoldRecord        `json:"holds"`        // holdID -> HoldRecord
	Dispositions  map[string]DispositionRecord `json:"dispositions"` // "caseID/evidenceID" -> DispositionRecord
}

// Service manages legal holds, blocks deletion/expiration while holds remain active,
// and durably audits every hold and disposal attempt.
type Service struct {
	mu        sync.Mutex
	holdsDir  string
	auditDir  string
	statePath string
	lockFile  *os.File
	sealStore *evidence.SealStore
	ledger    *custody.LedgerStore
	syncDir   bool
	closed    bool
	state     persistedState
	audits    map[string][]AuditEntry // "caseID/evidenceID" -> []AuditEntry
}

func evidenceKey(caseID, evidenceID string) string {
	return caseID + "/" + evidenceID
}

func resolveSafeDir(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", ErrStoreDirRequired
	}
	if strings.ContainsRune(root, '\x00') {
		return "", fmt.Errorf("%w: null byte in root dir", ErrPathTraversal)
	}
	for _, seg := range strings.FieldsFunc(root, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return "", fmt.Errorf("%w: traversal segment in root dir", ErrPathTraversal)
		}
	}
	absRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if _, err := ensureNoSymlink(absRoot); err != nil {
		return "", err
	}
	return absRoot, nil
}

// OpenService opens or initializes a durable legal hold service bound to a SealStore.
func OpenService(cfg ServiceConfig) (*Service, error) {
	if cfg.SealStore == nil {
		return nil, ErrSealStoreRequired
	}
	absRoot, err := resolveSafeDir(cfg.RootDir)
	if err != nil {
		return nil, err
	}

	holdsDir := filepath.Join(absRoot, DefaultHoldsDir)
	if err := checkWithinDir(absRoot, holdsDir); err != nil {
		return nil, err
	}
	if _, err := ensureNoSymlink(holdsDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(holdsDir, 0o750); err != nil {
		return nil, fmt.Errorf("create holds dir: %w", err)
	}

	auditDir := filepath.Join(holdsDir, auditDirName)
	if _, err := ensureNoSymlink(auditDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(auditDir, 0o750); err != nil {
		return nil, fmt.Errorf("create holds audit dir: %w", err)
	}

	lockPath := filepath.Join(holdsDir, holdsLockFileName)
	if _, err := ensureNoSymlink(lockPath); err != nil {
		return nil, err
	}
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open holds lock file: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockFile.Close()
		return nil, ErrLockBusy
	}

	svc := &Service{
		holdsDir:  holdsDir,
		auditDir:  auditDir,
		statePath: filepath.Join(holdsDir, stateFileName),
		lockFile:  lockFile,
		sealStore: cfg.SealStore,
		ledger:    cfg.Ledger,
		syncDir:   cfg.SyncDir,
		state: persistedState{
			SchemaVersion: SchemaVersion,
			Holds:         make(map[string]HoldRecord),
			Dispositions:  make(map[string]DispositionRecord),
		},
		audits: make(map[string][]AuditEntry),
	}

	if err := svc.recoverState(); err != nil {
		_ = svc.Close()
		return nil, err
	}
	if err := svc.recoverAudits(); err != nil {
		_ = svc.Close()
		return nil, err
	}

	return svc, nil
}

func (s *Service) recoverState() error {
	exists, err := ensureNoSymlink(s.statePath)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}

	raw, err := os.ReadFile(s.statePath)
	if err != nil {
		return fmt.Errorf("read holds state: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return fmt.Errorf("%w: empty holds-state.json", ErrCorruptedHoldState)
	}

	var loaded persistedState
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return fmt.Errorf("%w: invalid holds-state.json: %v", ErrCorruptedHoldState, err)
	}
	if loaded.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported schema_version %q", ErrCorruptedHoldState, loaded.SchemaVersion)
	}
	if loaded.Holds == nil {
		loaded.Holds = make(map[string]HoldRecord)
	}
	if loaded.Dispositions == nil {
		loaded.Dispositions = make(map[string]DispositionRecord)
	}

	for id, h := range loaded.Holds {
		if h.HoldID != id || !isValidIdentifier(h.HoldID) || !isValidIdentifier(h.CaseID) || !isValidIdentifier(h.EvidenceID) {
			return fmt.Errorf("%w: invalid persisted hold %q", ErrCorruptedHoldState, id)
		}
		if h.Status != HoldStatusActive && h.Status != HoldStatusReleased {
			return fmt.Errorf("%w: invalid status %q for hold %q", ErrCorruptedHoldState, h.Status, id)
		}
		if strings.TrimSpace(h.PlacedBy) == "" || strings.TrimSpace(h.Reason) == "" {
			return fmt.Errorf("%w: missing attribution for hold %q", ErrCorruptedHoldState, id)
		}
		if _, err := validateTimestamp(h.PlacedAt); err != nil {
			return fmt.Errorf("%w: invalid placed_at for hold %q: %v", ErrCorruptedHoldState, id, err)
		}
		if h.Status == HoldStatusReleased {
			if strings.TrimSpace(h.ReleasedBy) == "" || strings.TrimSpace(h.ReleaseReason) == "" {
				return fmt.Errorf("%w: missing release attribution for hold %q", ErrCorruptedHoldState, id)
			}
			if _, err := validateTimestamp(h.ReleasedAt); err != nil {
				return fmt.Errorf("%w: invalid released_at for hold %q: %v", ErrCorruptedHoldState, id, err)
			}
		}
	}

	for k, d := range loaded.Dispositions {
		if k != evidenceKey(d.CaseID, d.EvidenceID) || !isValidIdentifier(d.CaseID) || !isValidIdentifier(d.EvidenceID) {
			return fmt.Errorf("%w: invalid disposition key %q", ErrCorruptedHoldState, k)
		}
		if d.Disposition != DispositionDeleted && d.Disposition != DispositionExpired {
			return fmt.Errorf("%w: invalid disposition %q", ErrCorruptedHoldState, d.Disposition)
		}
		if strings.TrimSpace(d.Actor) == "" || strings.TrimSpace(d.Reason) == "" {
			return fmt.Errorf("%w: missing disposition attribution for %q", ErrCorruptedHoldState, k)
		}
		if _, err := validateTimestamp(d.Timestamp); err != nil {
			return fmt.Errorf("%w: invalid disposition timestamp for %q: %v", ErrCorruptedHoldState, k, err)
		}
	}

	s.state = loaded
	return nil
}

func (s *Service) recoverAudits() error {
	caseEntries, err := os.ReadDir(s.auditDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read holds audit dir: %w", err)
	}

	for _, caseEntry := range caseEntries {
		if !caseEntry.IsDir() {
			continue
		}
		caseID := caseEntry.Name()
		if !isValidIdentifier(caseID) {
			return fmt.Errorf("%w: invalid case directory %q in audit store", ErrCorruptedHoldState, caseID)
		}
		casePath := filepath.Join(s.auditDir, caseID)
		if _, err := ensureNoSymlink(casePath); err != nil {
			return err
		}
		files, err := os.ReadDir(casePath)
		if err != nil {
			return fmt.Errorf("read case audit dir %s: %w", caseID, err)
		}
		for _, fileEntry := range files {
			if fileEntry.IsDir() || !strings.HasSuffix(fileEntry.Name(), ".jsonl") {
				continue
			}
			evidenceID := strings.TrimSuffix(fileEntry.Name(), ".jsonl")
			if !isValidIdentifier(evidenceID) {
				return fmt.Errorf("%w: invalid evidence audit filename %q", ErrCorruptedHoldState, fileEntry.Name())
			}
			entries, err := loadAuditFile(filepath.Join(casePath, fileEntry.Name()), caseID, evidenceID)
			if err != nil {
				return err
			}
			s.audits[evidenceKey(caseID, evidenceID)] = entries
		}
	}
	return nil
}

func loadAuditFile(path, expectedCaseID, expectedEvidenceID string) ([]AuditEntry, error) {
	if _, err := ensureNoSymlink(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	defer f.Close()

	var entries []AuditEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), MaxAuditEntryBytes)
	expectedSeq := uint64(1)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("%w: corrupted audit line: %v", ErrCorruptedHoldState, err)
		}
		if entry.SchemaVersion != SchemaVersion ||
			entry.CaseID != expectedCaseID ||
			entry.EvidenceID != expectedEvidenceID ||
			entry.Sequence != expectedSeq ||
			!isValidIdentifier(entry.AuditID) ||
			strings.TrimSpace(entry.Actor) == "" ||
			strings.TrimSpace(entry.Reason) == "" {
			return nil, fmt.Errorf("%w: invalid audit entry invariants at seq %d", ErrCorruptedHoldState, expectedSeq)
		}
		if _, err := validateTimestamp(entry.Timestamp); err != nil {
			return nil, fmt.Errorf("%w: invalid audit timestamp at seq %d: %v", ErrCorruptedHoldState, expectedSeq, err)
		}
		entries = append(entries, entry)
		expectedSeq++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: scan audit log: %v", ErrCorruptedHoldState, err)
	}
	return entries, nil
}

// Close unlocks and closes the holds service.
func (s *Service) Close() error {
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

func validateAttributionAndTarget(caseID, evidenceID, actor, timestamp, reason, provider string) error {
	if !isValidIdentifier(caseID) {
		return fmt.Errorf("%w: invalid case_id %q", ErrInvalidHold, caseID)
	}
	if !isValidIdentifier(evidenceID) {
		return fmt.Errorf("%w: invalid evidence_id %q", ErrInvalidHold, evidenceID)
	}
	if strings.TrimSpace(actor) == "" {
		return ErrMissingActor
	}
	if !isValidIdentifier(actor) {
		return fmt.Errorf("%w: invalid actor identifier %q", ErrInvalidHold, actor)
	}
	if strings.TrimSpace(reason) == "" {
		return ErrMissingReason
	}
	if _, err := validateTimestamp(timestamp); err != nil {
		return err
	}
	if !allowedProviders[provider] {
		return fmt.Errorf("%w: provider %q not supported", ErrUnavailableProvider, provider)
	}
	return nil
}

func (s *Service) requireSealedEvidence(caseID, evidenceID string) error {
	if s.sealStore == nil {
		return ErrSealStoreRequired
	}
	manifest, err := s.sealStore.GetSealedManifest(caseID, evidenceID)
	if err != nil {
		return fmt.Errorf("%w: sealed evidence %s/%s not available: %v", ErrMissingPrerequisite, caseID, evidenceID, err)
	}
	if manifest == nil || !manifest.Sealed {
		return fmt.Errorf("%w: evidence %s/%s is not sealed", ErrMissingPrerequisite, caseID, evidenceID)
	}
	return nil
}

func (s *Service) activeHoldIDsLocked(caseID, evidenceID string) []string {
	var ids []string
	for _, h := range s.state.Holds {
		if h.CaseID == caseID && h.EvidenceID == evidenceID && h.Status == HoldStatusActive {
			ids = append(ids, h.HoldID)
		}
	}
	sort.Strings(ids)
	return ids
}

func (s *Service) persistStateLocked() error {
	if _, err := ensureNoSymlink(s.statePath); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal holds state: %w", err)
	}
	data = append(data, '\n')

	tmpFile, err := os.CreateTemp(s.holdsDir, ".holds-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp holds state: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp holds state: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp holds state: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp holds state: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("chmod temp holds state: %w", err)
	}
	if err := os.Rename(tmpPath, s.statePath); err != nil {
		return fmt.Errorf("rename holds state: %w", err)
	}
	cleanup = false

	if s.syncDir {
		if df, err := os.Open(s.holdsDir); err == nil {
			_ = df.Sync()
			_ = df.Close()
		}
	}
	return nil
}

func (s *Service) appendAuditLocked(entry AuditEntry) (AuditEntry, error) {
	key := evidenceKey(entry.CaseID, entry.EvidenceID)
	existing := s.audits[key]
	entry.SchemaVersion = SchemaVersion
	entry.Sequence = uint64(len(existing) + 1)
	if entry.AuditID == "" {
		entry.AuditID = fmt.Sprintf("hold-aud-%s-%04d", entry.EvidenceID, entry.Sequence)
	}
	if !isValidIdentifier(entry.AuditID) {
		return AuditEntry{}, fmt.Errorf("%w: invalid audit_id %q", ErrInvalidHold, entry.AuditID)
	}

	caseDir := filepath.Join(s.auditDir, entry.CaseID)
	if err := checkWithinDir(s.auditDir, caseDir); err != nil {
		return AuditEntry{}, err
	}
	if _, err := ensureNoSymlink(caseDir); err != nil {
		return AuditEntry{}, err
	}
	if err := os.MkdirAll(caseDir, 0o750); err != nil {
		return AuditEntry{}, fmt.Errorf("create audit case dir: %w", err)
	}

	filePath := filepath.Join(caseDir, entry.EvidenceID+".jsonl")
	if err := checkWithinDir(caseDir, filePath); err != nil {
		return AuditEntry{}, err
	}
	if _, err := ensureNoSymlink(filePath); err != nil {
		return AuditEntry{}, err
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return AuditEntry{}, fmt.Errorf("marshal audit entry: %w", err)
	}
	if len(data) > MaxAuditEntryBytes {
		return AuditEntry{}, fmt.Errorf("%w: audit entry exceeds max %d bytes", ErrInvalidHold, MaxAuditEntryBytes)
	}
	data = append(data, '\n')

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return AuditEntry{}, fmt.Errorf("open audit file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return AuditEntry{}, fmt.Errorf("write audit entry: %w", err)
	}
	if err := f.Sync(); err != nil {
		return AuditEntry{}, fmt.Errorf("sync audit entry: %w", err)
	}
	if s.syncDir {
		if df, err := os.Open(caseDir); err == nil {
			_ = df.Sync()
			_ = df.Close()
		}
	}

	s.audits[key] = append(existing, entry)
	return entry, nil
}

func (s *Service) mirrorToLedgerLocked(ctx context.Context, entry AuditEntry, privKey ed25519.PrivateKey) error {
	if s.ledger == nil {
		return nil
	}

	// Custody chains enforce non-decreasing timestamps across events. Under concurrent
	// scheduling, two valid callers may arrive in reverse wall-clock timestamp order;
	// preserve the exact caller timestamp in the holds audit log while keeping the custody
	// chain timestamp monotonic if needed.
	ledgerTS := entry.Timestamp
	chain, err := s.ledger.ListEvents(entry.CaseID, entry.EvidenceID)
	if err == nil && len(chain) > 0 {
		lastTS := chain[len(chain)-1].Timestamp
		lastT, errLast := time.Parse(time.RFC3339Nano, lastTS)
		currT, errCurr := time.Parse(time.RFC3339Nano, ledgerTS)
		if errLast == nil && errCurr == nil && currT.Before(lastT) {
			ledgerTS = lastTS
		}
	}

	reason := fmt.Sprintf("[%s:%s] %s", entry.Action, entry.Outcome, entry.Reason)
	if len(entry.BlockingHoldIDs) > 0 {
		reason = fmt.Sprintf("%s (blocking_holds=%s)", reason, strings.Join(entry.BlockingHoldIDs, ","))
	} else if entry.HoldID != "" {
		reason = fmt.Sprintf("%s (hold_id=%s)", reason, entry.HoldID)
	}

	_, err = s.ledger.AppendEvent(ctx, custody.AppendEventRequest{
		CaseID:     entry.CaseID,
		EvidenceID: entry.EvidenceID,
		EventType:  entry.Action,
		Actor:      entry.Actor,
		Timestamp:  ledgerTS,
		Reason:     reason,
		Provider:   entry.Provider,
		PrivateKey: privKey,
	})
	return err
}

// PlaceHold places an active legal hold on sealed evidence and durably audits the reason.
func (s *Service) PlaceHold(ctx context.Context, req PlaceHoldRequest) (*HoldRecord, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if err := validateAttributionAndTarget(req.CaseID, req.EvidenceID, req.Actor, req.Timestamp, req.Reason, req.Provider); err != nil {
		return nil, err
	}
	if req.HoldID != "" && !isValidIdentifier(req.HoldID) {
		return nil, fmt.Errorf("%w: invalid hold_id %q", ErrInvalidHold, req.HoldID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrServiceClosed
	}
	if err := s.requireSealedEvidence(req.CaseID, req.EvidenceID); err != nil {
		return nil, err
	}

	key := evidenceKey(req.CaseID, req.EvidenceID)
	if disp, disposed := s.state.Dispositions[key]; disposed {
		return nil, fmt.Errorf("%w: evidence %s already %s", ErrEvidenceAlreadyDisposed, key, disp.Disposition)
	}

	holdID := req.HoldID
	if holdID == "" {
		nextSeq := s.state.NextHoldSeq + 1
		holdID = fmt.Sprintf("hold-%s-%04d", req.EvidenceID, nextSeq)
		if !isValidIdentifier(holdID) {
			holdID = fmt.Sprintf("hold-%06d", nextSeq)
		}
	}

	if existing, exists := s.state.Holds[holdID]; exists {
		if existing.Status == HoldStatusActive &&
			existing.CaseID == req.CaseID &&
			existing.EvidenceID == req.EvidenceID &&
			existing.Reason == req.Reason &&
			existing.PlacedBy == req.Actor &&
			existing.PlacedAt == req.Timestamp &&
			existing.Provider == req.Provider {
			copyH := existing
			return &copyH, nil
		}
		return nil, fmt.Errorf("%w: hold %q already exists", ErrHoldConflict, holdID)
	}

	prevSeq := s.state.NextHoldSeq
	if req.HoldID == "" {
		s.state.NextHoldSeq = prevSeq + 1
	}

	record := HoldRecord{
		SchemaVersion: SchemaVersion,
		HoldID:        holdID,
		CaseID:        req.CaseID,
		EvidenceID:    req.EvidenceID,
		Status:        HoldStatusActive,
		Reason:        req.Reason,
		PlacedBy:      req.Actor,
		PlacedAt:      req.Timestamp,
		Provider:      req.Provider,
	}

	s.state.Holds[holdID] = record
	if err := s.persistStateLocked(); err != nil {
		delete(s.state.Holds, holdID)
		s.state.NextHoldSeq = prevSeq
		return nil, err
	}

	auditEntry, err := s.appendAuditLocked(AuditEntry{
		CaseID:     req.CaseID,
		EvidenceID: req.EvidenceID,
		Action:     ActionHoldPlaced,
		Outcome:    OutcomeAllowed,
		HoldID:     holdID,
		Actor:      req.Actor,
		Timestamp:  req.Timestamp,
		Reason:     req.Reason,
		Provider:   req.Provider,
	})
	if err != nil {
		delete(s.state.Holds, holdID)
		s.state.NextHoldSeq = prevSeq
		_ = s.persistStateLocked()
		return nil, err
	}

	if err := s.mirrorToLedgerLocked(ctx, auditEntry, req.PrivateKey); err != nil {
		return nil, err
	}

	copyH := record
	return &copyH, nil
}

// ReleaseHold releases an active legal hold with attribution and audit reason.
func (s *Service) ReleaseHold(ctx context.Context, req ReleaseHoldRequest) (*HoldRecord, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if !isValidIdentifier(req.HoldID) {
		return nil, fmt.Errorf("%w: invalid hold_id %q", ErrInvalidHold, req.HoldID)
	}
	if err := validateAttributionAndTarget(req.CaseID, req.EvidenceID, req.Actor, req.Timestamp, req.Reason, req.Provider); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrServiceClosed
	}

	existing, ok := s.state.Holds[req.HoldID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrHoldNotFound, req.HoldID)
	}
	if existing.CaseID != req.CaseID || existing.EvidenceID != req.EvidenceID {
		return nil, fmt.Errorf("%w: hold %s belongs to %s/%s", ErrInvalidHold, req.HoldID, existing.CaseID, existing.EvidenceID)
	}
	if existing.Status == HoldStatusReleased {
		return nil, fmt.Errorf("%w: %s", ErrHoldAlreadyReleased, req.HoldID)
	}

	prev := existing
	existing.Status = HoldStatusReleased
	existing.ReleasedBy = req.Actor
	existing.ReleasedAt = req.Timestamp
	existing.ReleaseReason = req.Reason
	s.state.Holds[req.HoldID] = existing

	if err := s.persistStateLocked(); err != nil {
		s.state.Holds[req.HoldID] = prev
		return nil, err
	}

	auditEntry, err := s.appendAuditLocked(AuditEntry{
		CaseID:     req.CaseID,
		EvidenceID: req.EvidenceID,
		Action:     ActionHoldReleased,
		Outcome:    OutcomeAllowed,
		HoldID:     req.HoldID,
		Actor:      req.Actor,
		Timestamp:  req.Timestamp,
		Reason:     req.Reason,
		Provider:   req.Provider,
	})
	if err != nil {
		s.state.Holds[req.HoldID] = prev
		_ = s.persistStateLocked()
		return nil, err
	}

	if err := s.mirrorToLedgerLocked(ctx, auditEntry, req.PrivateKey); err != nil {
		return nil, err
	}

	copyH := existing
	return &copyH, nil
}

// DeleteEvidence attempts to delete evidence. If any legal hold is active, deletion fails with
// ErrHoldActive, evidence bytes remain completely intact, and the attempt/reason is durably audited.
func (s *Service) DeleteEvidence(ctx context.Context, req DisposalRequest) (*DisposalResult, error) {
	return s.executeDisposal(ctx, req, ActionDeleteBlocked, ActionEvidenceDeleted, DispositionDeleted)
}

// ExpireRetention attempts automated retention expiration. If any legal hold is active, expiration
// fails with ErrHoldActive, evidence bytes remain completely intact, and the reason is durably audited.
func (s *Service) ExpireRetention(ctx context.Context, req DisposalRequest) (*DisposalResult, error) {
	return s.executeDisposal(ctx, req, ActionExpirationBlocked, ActionRetentionExpired, DispositionExpired)
}

func (s *Service) executeDisposal(ctx context.Context, req DisposalRequest, blockedAction, allowedAction, targetDisposition string) (*DisposalResult, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if err := validateAttributionAndTarget(req.CaseID, req.EvidenceID, req.Actor, req.Timestamp, req.Reason, req.Provider); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrServiceClosed
	}
	if err := s.requireSealedEvidence(req.CaseID, req.EvidenceID); err != nil {
		return nil, err
	}

	activeIDs := s.activeHoldIDsLocked(req.CaseID, req.EvidenceID)
	if len(activeIDs) > 0 {
		auditEntry, err := s.appendAuditLocked(AuditEntry{
			CaseID:          req.CaseID,
			EvidenceID:      req.EvidenceID,
			Action:          blockedAction,
			Outcome:         OutcomeBlocked,
			BlockingHoldIDs: activeIDs,
			Actor:           req.Actor,
			Timestamp:       req.Timestamp,
			Reason:          req.Reason,
			Provider:        req.Provider,
		})
		if err != nil {
			return nil, err
		}
		if err := s.mirrorToLedgerLocked(ctx, auditEntry, req.PrivateKey); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: holds [%s] prevent %s (reason: %s)", ErrHoldActive, strings.Join(activeIDs, ", "), allowedAction, req.Reason)
	}

	key := evidenceKey(req.CaseID, req.EvidenceID)
	if disp, disposed := s.state.Dispositions[key]; disposed {
		return nil, fmt.Errorf("%w: evidence %s already %s", ErrEvidenceAlreadyDisposed, key, disp.Disposition)
	}

	s.state.Dispositions[key] = DispositionRecord{
		CaseID:      req.CaseID,
		EvidenceID:  req.EvidenceID,
		Disposition: targetDisposition,
		Actor:       req.Actor,
		Timestamp:   req.Timestamp,
		Reason:      req.Reason,
		Provider:    req.Provider,
	}
	if err := s.persistStateLocked(); err != nil {
		delete(s.state.Dispositions, key)
		return nil, err
	}

	auditEntry, err := s.appendAuditLocked(AuditEntry{
		CaseID:     req.CaseID,
		EvidenceID: req.EvidenceID,
		Action:     allowedAction,
		Outcome:    OutcomeAllowed,
		Actor:      req.Actor,
		Timestamp:  req.Timestamp,
		Reason:     req.Reason,
		Provider:   req.Provider,
	})
	if err != nil {
		delete(s.state.Dispositions, key)
		_ = s.persistStateLocked()
		return nil, err
	}

	if err := s.mirrorToLedgerLocked(ctx, auditEntry, req.PrivateKey); err != nil {
		return nil, err
	}

	return &DisposalResult{
		CaseID:      req.CaseID,
		EvidenceID:  req.EvidenceID,
		Action:      allowedAction,
		Disposition: targetDisposition,
		Actor:       req.Actor,
		Timestamp:   req.Timestamp,
		Reason:      req.Reason,
	}, nil
}

// GetEvidenceStatus returns a deterministic snapshot of holds and disposition for (caseID, evidenceID).
func (s *Service) GetEvidenceStatus(caseID, evidenceID string) (*EvidenceHoldStatus, error) {
	if !isValidIdentifier(caseID) {
		return nil, fmt.Errorf("%w: invalid case_id %q", ErrInvalidHold, caseID)
	}
	if !isValidIdentifier(evidenceID) {
		return nil, fmt.Errorf("%w: invalid evidence_id %q", ErrInvalidHold, evidenceID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrServiceClosed
	}

	sealed := false
	if s.sealStore != nil {
		if m, err := s.sealStore.GetSealedManifest(caseID, evidenceID); err == nil && m != nil && m.Sealed {
			sealed = true
		}
	}

	var holds []HoldRecord
	var activeIDs []string
	for _, h := range s.state.Holds {
		if h.CaseID == caseID && h.EvidenceID == evidenceID {
			holds = append(holds, h)
			if h.Status == HoldStatusActive {
				activeIDs = append(activeIDs, h.HoldID)
			}
		}
	}
	sort.Slice(holds, func(i, j int) bool {
		return holds[i].HoldID < holds[j].HoldID
	})
	sort.Strings(activeIDs)

	disp := DispositionRetained
	if d, ok := s.state.Dispositions[evidenceKey(caseID, evidenceID)]; ok {
		disp = d.Disposition
	}

	return &EvidenceHoldStatus{
		CaseID:          caseID,
		EvidenceID:      evidenceID,
		Sealed:          sealed,
		ActiveHoldCount: len(activeIDs),
		ActiveHoldIDs:   activeIDs,
		Holds:           holds,
		Disposition:     disp,
		AuditCount:      len(s.audits[evidenceKey(caseID, evidenceID)]),
	}, nil
}

// AuditTrail returns a copy of all durable audit entries recorded for (caseID, evidenceID).
func (s *Service) AuditTrail(caseID, evidenceID string) ([]AuditEntry, error) {
	if !isValidIdentifier(caseID) {
		return nil, fmt.Errorf("%w: invalid case_id %q", ErrInvalidHold, caseID)
	}
	if !isValidIdentifier(evidenceID) {
		return nil, fmt.Errorf("%w: invalid evidence_id %q", ErrInvalidHold, evidenceID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrServiceClosed
	}

	src := s.audits[evidenceKey(caseID, evidenceID)]
	out := make([]AuditEntry, len(src))
	for i, e := range src {
		if len(e.BlockingHoldIDs) > 0 {
			ids := make([]string, len(e.BlockingHoldIDs))
			copy(ids, e.BlockingHoldIDs)
			e.BlockingHoldIDs = ids
		}
		out[i] = e
	}
	return out, nil
}

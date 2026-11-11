package findings

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
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

const (
	SchemaVersion               = "1"
	RecordKindObservedFact      = "observed_fact"
	RecordKindAnalystHypothesis = "analyst_hypothesis"

	HypothesisStatusProposed   = "proposed"
	HypothesisStatusSupported  = "corroborated"
	HypothesisStatusRefuted    = "refuted"
	HypothesisStatusSuperseded = "superseded"

	DefaultMaxStorageBytes      = int64(256 * 1024 * 1024)
	DefaultMaxHypothesesPerCase = 10000
	MaxAuthorBytes              = 256
	MaxRationaleBytes           = 8192
	MaxStatementBytes           = 8192
	MaxUILabelBytes             = 128

	casesSubdir      = "cases"
	stagingSubdir    = "staging"
	findingsIdxFile  = "findings-index.json"
	findingsLockFile = ".finding.lock"
)

var (
	ErrFindingStoreRequired  = errors.New("finding store root directory is required")
	ErrFindingStoreClosed    = errors.New("finding store closed")
	ErrFindingLockBusy       = errors.New("finding store lock busy: another writer holds exclusive lock")
	ErrUnsupportedVersion    = errors.New("unsupported findings schema version")
	ErrUnavailableProvider   = errors.New("unavailable findings provider")
	ErrMissingPrerequisite   = errors.New("missing prerequisite for analyst hypothesis or observed fact")
	ErrMissingAuthor         = errors.New("analyst hypothesis requires non-empty author")
	ErrMissingRationale      = errors.New("analyst hypothesis requires non-empty rationale")
	ErrInvalidHypothesis     = errors.New("invalid analyst hypothesis input")
	ErrPromotionForbidden    = errors.New("analyst hypothesis cannot become source evidence or observed fact")
	ErrPathTraversal         = errors.New("path traversal or invalid identifier rejected")
	ErrSymlinkRejected       = errors.New("symlink rejected in finding store path")
	ErrFindingConflict       = errors.New("hypothesis or operation ID reused with conflicting parameters")
	ErrFindingNotFound       = errors.New("analyst hypothesis or case findings not found")
	ErrMalformedFinding      = errors.New("malformed persisted findings or digest mismatch")
	ErrSealedBytesTampered   = errors.New("sealed source bytes modified during findings operation")
	ErrDiskFull              = errors.New("disk full: findings write aborted")
	ErrInterrupted           = errors.New("findings write interrupted before commit")
	ErrFindingQuotaExceeded  = errors.New("finding store quota exceeded")
)

var (
	identifierRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	allowedProviders = map[string]bool{
		"":            true,
		"local":       true,
		"breachatlas": true,
	}
	allowedStatuses = map[string]bool{
		HypothesisStatusProposed:   true,
		HypothesisStatusSupported:  true,
		HypothesisStatusRefuted:    true,
		HypothesisStatusSuperseded: true,
	}
)

// AnalystHypothesis records an analyst interpretation kept structurally and cryptographically
// distinct from observed source evidence. Author and Rationale are mandatory; IsSourceEvidence is always false.
type AnalystHypothesis struct {
	SchemaVersion         string   `json:"schema_version"`
	HypothesisID          string   `json:"hypothesis_id"`
	CaseID                string   `json:"case_id"`
	RecordKind            string   `json:"record_kind"`
	IsSourceEvidence      bool     `json:"is_source_evidence"`
	Author                string   `json:"author"`
	Rationale             string   `json:"rationale"`
	Statement             string   `json:"statement"`
	Status                string   `json:"status"`
	Confidence            *float64 `json:"confidence,omitempty"`
	UILabel               string   `json:"ui_label,omitempty"`
	SupportingEvidenceIDs []string `json:"supporting_evidence_ids,omitempty"`
	SupportingEventIDs    []string `json:"supporting_event_ids,omitempty"`
	ContentDigest         string   `json:"content_digest"`
	CreatedAt             string   `json:"created_at"`
}

// ObservedFact projects an immutable source-bound timeline observation backed by verified SealStore
// bytes and EventIndexStore entries. Analyst notes cannot enter this structure.
type ObservedFact struct {
	SchemaVersion string                  `json:"schema_version"`
	RecordKind    string                  `json:"record_kind"`
	CaseID        string                  `json:"case_id"`
	EvidenceID    string                  `json:"evidence_id"`
	SealedSHA256  string                  `json:"sealed_sha256"`
	CustodyRoot   string                  `json:"custody_root,omitempty"`
	EventIdentity string                  `json:"event_identity"`
	SourceLine    int                     `json:"source_line"`
	EventType     string                  `json:"event_type,omitempty"`
	Summary       string                  `json:"summary,omitempty"`
	Time          timeline.NormalizedTime `json:"time"`
	Fields        map[string]any          `json:"fields,omitempty"`
}

// CaseEpistemicLedger holds strictly separated ObservedFacts and Hypotheses for a case.
type CaseEpistemicLedger struct {
	SchemaVersion string              `json:"schema_version"`
	CaseID        string              `json:"case_id"`
	ObservedFacts []ObservedFact      `json:"observed_facts"`
	Hypotheses    []AnalystHypothesis `json:"hypotheses"`
}

// RecordHypothesisRequest submits a new analyst hypothesis or idempotent replay.
// ClaimSourceEvidence or ClaimRecordKind != "analyst_hypothesis" is rejected with ErrPromotionForbidden.
type RecordHypothesisRequest struct {
	SchemaVersion         string   `json:"schema_version"`
	OperationID           string   `json:"operation_id,omitempty"`
	CaseID                string   `json:"case_id"`
	HypothesisID          string   `json:"hypothesis_id"`
	Provider              string   `json:"provider,omitempty"`
	Author                string   `json:"author"`
	Rationale             string   `json:"rationale"`
	Statement             string   `json:"statement"`
	Status                string   `json:"status,omitempty"`
	Confidence            *float64 `json:"confidence,omitempty"`
	UILabel               string   `json:"ui_label,omitempty"`
	ClaimRecordKind       string   `json:"claim_record_kind,omitempty"`
	ClaimSourceEvidence   bool     `json:"claim_source_evidence,omitempty"`
	SupportingEvidenceIDs []string `json:"supporting_evidence_ids,omitempty"`
	SupportingEventIDs    []string `json:"supporting_event_ids,omitempty"`
}

// RecordOutcome summarizes a committed hypothesis write or idempotent replay.
type RecordOutcome struct {
	CaseID           string            `json:"case_id"`
	HypothesisID     string            `json:"hypothesis_id"`
	Generation       uint64            `json:"generation"`
	Hypothesis       AnalystHypothesis `json:"hypothesis"`
	IdempotentReplay bool              `json:"idempotent_replay,omitempty"`
}

// FindingFaults enables fault injection at atomic commit boundaries for restart tests.
type FindingFaults struct {
	SimulateDiskFull           bool
	FailAfterStageBeforeCommit bool
}

// FindingStoreConfig configures a local FindingStore directory and quotas.
type FindingStoreConfig struct {
	RootDir             string
	MaxStorageBytes     int64
	MaxHypothesesPerCase int
	SyncDir             bool
	Faults              FindingFaults
}

// RecoveryReport reports staging files cleaned and cases/hypotheses verified on startup.
type RecoveryReport struct {
	CleanedStagingFiles []string `json:"cleaned_staging_files"`
	RecoveredCases      int      `json:"recovered_cases"`
	RecoveredHypotheses int      `json:"recovered_hypotheses"`
}

type caseHypothesesFile struct {
	SchemaVersion string              `json:"schema_version"`
	CaseID        string              `json:"case_id"`
	Generation    uint64              `json:"generation"`
	Hypotheses    []AnalystHypothesis `json:"hypotheses"`
}

type persistedCaseMeta struct {
	CaseID          string `json:"case_id"`
	FileSHA256      string `json:"file_sha256"`
	HypothesisCount int    `json:"hypothesis_count"`
}

type findingsIndexManifest struct {
	SchemaVersion string                       `json:"schema_version"`
	Generation    uint64                       `json:"generation"`
	TotalBytes    int64                        `json:"total_bytes"`
	Operations    map[string]RecordOutcome     `json:"operations"`
	Cases         map[string]persistedCaseMeta `json:"cases"`
}

type sealedBlobSnap struct {
	path string
	sha  string
	size int64
}

// FindingStore atomically persists analyst hypotheses separately from verified source evidence
// and checks structural non-promotion invariants across restarts.
type FindingStore struct {
	mu               sync.Mutex
	cfg              FindingStoreConfig
	rootDir          string
	maxStorage       int64
	maxPerCase       int
	lockFile         *os.File
	manifest         findingsIndexManifest
	hypothesesByCase map[string]map[string]AnalystHypothesis
	recoveryReport   RecoveryReport
	closed           bool
}

// OpenFindingStore opens or initializes a locked, crash-recoverable FindingStore.
func OpenFindingStore(cfg FindingStoreConfig) (*FindingStore, error) {
	if strings.TrimSpace(cfg.RootDir) == "" {
		return nil, ErrFindingStoreRequired
	}
	absRoot, err := resolveSafeDir(cfg.RootDir)
	if err != nil {
		return nil, err
	}

	maxStorage := cfg.MaxStorageBytes
	if maxStorage <= 0 {
		maxStorage = DefaultMaxStorageBytes
	}
	maxPerCase := cfg.MaxHypothesesPerCase
	if maxPerCase <= 0 {
		maxPerCase = DefaultMaxHypothesesPerCase
	}

	for _, sub := range []string{casesSubdir, stagingSubdir} {
		subPath := filepath.Join(absRoot, sub)
		if _, err := ensureNoSymlink(subPath); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(subPath, 0750); err != nil {
			return nil, fmt.Errorf("create finding store subdir %s: %w", sub, err)
		}
	}

	lockPath := filepath.Join(absRoot, findingsLockFile)
	if _, err := ensureNoSymlink(lockPath); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		return nil, fmt.Errorf("open finding lock file: %w", err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lf.Close()
		return nil, ErrFindingLockBusy
	}

	store := &FindingStore{
		cfg:              cfg,
		rootDir:          absRoot,
		maxStorage:       maxStorage,
		maxPerCase:       maxPerCase,
		lockFile:         lf,
		hypothesesByCase: make(map[string]map[string]AnalystHypothesis),
		manifest: findingsIndexManifest{
			SchemaVersion: SchemaVersion,
			Operations:    make(map[string]RecordOutcome),
			Cases:         make(map[string]persistedCaseMeta),
		},
	}

	if err := store.recoverOnOpenUnlocked(); err != nil {
		_ = store.closeUnlocked()
		return nil, err
	}
	return store, nil
}

func (s *FindingStore) recoverOnOpenUnlocked() error {
	cleaned, err := s.cleanStagingUnlocked()
	if err != nil {
		return err
	}
	s.recoveryReport.CleanedStagingFiles = cleaned

	indexPath := filepath.Join(s.rootDir, findingsIdxFile)
	if _, err := ensureNoSymlink(indexPath); err != nil {
		return err
	}
	data, err := os.ReadFile(indexPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read findings index: %w", err)
	}

	var manifest findingsIndexManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("%w: corrupt findings index: %v", ErrMalformedFinding, err)
	}
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported findings index version %q", ErrUnsupportedVersion, manifest.SchemaVersion)
	}
	if manifest.Operations == nil {
		manifest.Operations = make(map[string]RecordOutcome)
	}
	if manifest.Cases == nil {
		manifest.Cases = make(map[string]persistedCaseMeta)
	}

	recoveredCount := 0
	loadedCases := make(map[string]map[string]AnalystHypothesis, len(manifest.Cases))

	for caseID, meta := range manifest.Cases {
		if err := validateIdentifier("case_id", caseID); err != nil {
			return err
		}
		casePath := filepath.Join(s.rootDir, casesSubdir, caseID+".hypotheses.json")
		if err := checkWithinDir(s.rootDir, casePath); err != nil {
			return err
		}
		if _, err := ensureNoSymlink(casePath); err != nil {
			return err
		}
		gotSHA, _, err := hashRegularFile(casePath)
		if err != nil {
			return fmt.Errorf("%w: read persisted case hypotheses %s: %v", ErrMalformedFinding, caseID, err)
		}
		if gotSHA != meta.FileSHA256 {
			return fmt.Errorf("%w: case hypotheses %s digest mismatch on recovery", ErrMalformedFinding, caseID)
		}
		raw, err := os.ReadFile(casePath)
		if err != nil {
			return err
		}
		var cf caseHypothesesFile
		if err := json.Unmarshal(raw, &cf); err != nil {
			return fmt.Errorf("%w: decode case hypotheses %s: %v", ErrMalformedFinding, caseID, err)
		}
		if cf.SchemaVersion != SchemaVersion {
			return fmt.Errorf("%w: unsupported case hypotheses schema %q", ErrUnsupportedVersion, cf.SchemaVersion)
		}

		byID := make(map[string]AnalystHypothesis, len(cf.Hypotheses))
		for _, h := range cf.Hypotheses {
			if err := validatePersistedHypothesis(caseID, h); err != nil {
				return err
			}
			byID[h.HypothesisID] = h
		}
		loadedCases[caseID] = byID
		recoveredCount += len(byID)
	}

	s.manifest = manifest
	s.hypothesesByCase = loadedCases
	s.recoveryReport.RecoveredCases = len(loadedCases)
	s.recoveryReport.RecoveredHypotheses = recoveredCount
	return nil
}

func validatePersistedHypothesis(expectedCaseID string, h AnalystHypothesis) error {
	if h.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: hypothesis schema version %q", ErrUnsupportedVersion, h.SchemaVersion)
	}
	if err := validateIdentifier("hypothesis_id", h.HypothesisID); err != nil {
		return err
	}
	if h.CaseID != expectedCaseID {
		return fmt.Errorf("%w: case_id mismatch on recovery", ErrMalformedFinding)
	}
	if h.IsSourceEvidence || h.RecordKind != RecordKindAnalystHypothesis {
		return fmt.Errorf("%w: persisted hypothesis attempted source-evidence promotion", ErrPromotionForbidden)
	}
	if strings.TrimSpace(h.Author) == "" {
		return ErrMissingAuthor
	}
	if strings.TrimSpace(h.Rationale) == "" {
		return ErrMissingRationale
	}
	if strings.TrimSpace(h.Statement) == "" {
		return fmt.Errorf("%w: statement required", ErrInvalidHypothesis)
	}
	expectedDigest, err := computeHypothesisDigest(h)
	if err != nil {
		return err
	}
	if h.ContentDigest != expectedDigest {
		return fmt.Errorf("%w: hypothesis %s content_digest mismatch", ErrMalformedFinding, h.HypothesisID)
	}
	return nil
}

func (s *FindingStore) cleanStagingUnlocked() ([]string, error) {
	stagingDir := filepath.Join(s.rootDir, stagingSubdir)
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return nil, err
	}
	var cleaned []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		full := filepath.Join(stagingDir, entry.Name())
		if err := checkWithinDir(stagingDir, full); err != nil {
			return nil, err
		}
		if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("clean findings staging %s: %w", entry.Name(), err)
		}
		cleaned = append(cleaned, entry.Name())
	}
	sort.Strings(cleaned)
	return cleaned, nil
}

// LastRecoveryReport returns staging cleanup and recovered counts recorded during OpenFindingStore.
func (s *FindingStore) LastRecoveryReport() RecoveryReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return RecoveryReport{
		RecoveredCases:      s.recoveryReport.RecoveredCases,
		RecoveredHypotheses: s.recoveryReport.RecoveredHypotheses,
		CleanedStagingFiles: append([]string(nil), s.recoveryReport.CleanedStagingFiles...),
	}
}

// Close releases the exclusive lock held by FindingStore.
func (s *FindingStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeUnlocked()
}

func (s *FindingStore) closeUnlocked() error {
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

// RecordHypothesis validates mandatory Author and Rationale, rejects source-evidence promotion attempts,
// verifies supporting SealStore and EventIndexStore prerequisites when referenced, and persists
// the analyst hypothesis atomically without touching sealed source bytes.
func (s *FindingStore) RecordHypothesis(
	ctx context.Context,
	sealStore *evidence.SealStore,
	sealRootDir string,
	indexStore *timeline.EventIndexStore,
	req RecordHypothesisRequest,
) (*RecordOutcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrFindingStoreRequired
	}
	if req.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %q", ErrUnsupportedVersion, req.SchemaVersion)
	}
	if err := validateIdentifier("case_id", req.CaseID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("hypothesis_id", req.HypothesisID); err != nil {
		return nil, err
	}
	if req.OperationID != "" {
		if err := validateIdentifier("operation_id", req.OperationID); err != nil {
			return nil, err
		}
	}
	if !allowedProviders[req.Provider] {
		return nil, fmt.Errorf("%w: provider %q unsupported in local-first profile", ErrUnavailableProvider, req.Provider)
	}
	if req.ClaimSourceEvidence || (strings.TrimSpace(req.ClaimRecordKind) != "" && strings.TrimSpace(req.ClaimRecordKind) != RecordKindAnalystHypothesis) {
		return nil, ErrPromotionForbidden
	}

	author, err := validateBoundedText("author", req.Author, MaxAuthorBytes, ErrMissingAuthor)
	if err != nil {
		return nil, err
	}
	rationale, err := validateBoundedText("rationale", req.Rationale, MaxRationaleBytes, ErrMissingRationale)
	if err != nil {
		return nil, err
	}
	statement, err := validateBoundedText("statement", req.Statement, MaxStatementBytes, ErrInvalidHypothesis)
	if err != nil {
		return nil, err
	}

	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = HypothesisStatusProposed
	}
	if !allowedStatuses[status] {
		return nil, fmt.Errorf("%w: unsupported hypothesis status %q", ErrInvalidHypothesis, status)
	}
	if req.Confidence != nil && (*req.Confidence < 0 || *req.Confidence > 1) {
		return nil, fmt.Errorf("%w: confidence %.4f must be within [0, 1]", ErrInvalidHypothesis, *req.Confidence)
	}

	uiLabel := strings.TrimSpace(req.UILabel)
	if uiLabel != "" {
		if !utf8.ValidString(uiLabel) || len(uiLabel) > MaxUILabelBytes {
			return nil, fmt.Errorf("%w: invalid or oversized ui_label", ErrInvalidHypothesis)
		}
	}

	// Verify SealStore prerequisite and supporting evidence/event bindings read-only.
	if sealStore == nil || strings.TrimSpace(sealRootDir) == "" {
		return nil, fmt.Errorf("%w: sealStore and sealRootDir required", ErrMissingPrerequisite)
	}
	absSealRoot, err := resolveSafeDir(sealRootDir)
	if err != nil {
		return nil, err
	}

	supportingEvidence := normalizeUniqueStrings(req.SupportingEvidenceIDs)
	sealedSnaps := make(map[string]sealedBlobSnap, len(supportingEvidence))
	for _, evID := range supportingEvidence {
		if err := validateIdentifier("evidence_id", evID); err != nil {
			return nil, err
		}
		if err := verifyAndSnapshotSealedBlob(ctx, sealStore, absSealRoot, req.CaseID, evID, sealedSnaps); err != nil {
			return nil, err
		}
	}

	supportingEvents := normalizeUniqueStrings(req.SupportingEventIDs)
	if len(supportingEvents) > 0 {
		if indexStore == nil {
			return nil, fmt.Errorf("%w: EventIndexStore required to reference supporting_event_ids", ErrMissingPrerequisite)
		}
		for _, evIdent := range supportingEvents {
			entry, getErr := indexStore.GetEntry(req.CaseID, evIdent)
			if getErr != nil || entry == nil {
				return nil, fmt.Errorf("%w: supporting event %s/%s not indexed: %v", ErrMissingPrerequisite, req.CaseID, evIdent, getErr)
			}
			if err := verifyAndSnapshotSealedBlob(ctx, sealStore, absSealRoot, req.CaseID, entry.EvidenceID, sealedSnaps); err != nil {
				return nil, err
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrFindingStoreClosed
	}

	candidate := AnalystHypothesis{
		SchemaVersion:         SchemaVersion,
		HypothesisID:          req.HypothesisID,
		CaseID:                req.CaseID,
		RecordKind:            RecordKindAnalystHypothesis,
		IsSourceEvidence:      false, // Enforced unconditionally regardless of UILabel.
		Author:                author,
		Rationale:             rationale,
		Statement:             statement,
		Status:                status,
		UILabel:               uiLabel,
		SupportingEvidenceIDs: supportingEvidence,
		SupportingEventIDs:    supportingEvents,
		CreatedAt:             time.Now().UTC().Format(time.RFC3339Nano),
	}
	if req.Confidence != nil {
		v := *req.Confidence
		candidate.Confidence = &v
	}

	// Preserve existing CreatedAt if updating same HypothesisID via new OperationID, or check idempotency first.
	if req.OperationID != "" {
		if prev, ok := s.manifest.Operations[req.OperationID]; ok {
			prevCopy := prev.Hypothesis
			candCmp := candidate
			candCmp.CreatedAt = prevCopy.CreatedAt
			prevDigest, err1 := computeHypothesisDigest(prevCopy)
			candDigest, err2 := computeHypothesisDigest(candCmp)
			if err1 != nil || err2 != nil || prevDigest != candDigest {
				return nil, fmt.Errorf("%w: operation_id %q reused with conflicting parameters", ErrFindingConflict, req.OperationID)
			}
			replay := prev
			replay.IdempotentReplay = true
			return &replay, nil
		}
	}

	digest, err := computeHypothesisDigest(candidate)
	if err != nil {
		return nil, err
	}
	candidate.ContentDigest = digest

	if s.cfg.Faults.SimulateDiskFull {
		return nil, ErrDiskFull
	}

	existing := s.hypothesesByCase[req.CaseID]
	nextCaseMap := make(map[string]AnalystHypothesis, len(existing)+1)
	for k, v := range existing {
		nextCaseMap[k] = cloneHypothesis(v)
	}
	nextCaseMap[candidate.HypothesisID] = candidate
	if len(nextCaseMap) > s.maxPerCase {
		return nil, fmt.Errorf("%w: case %s hypothesis count %d exceeds max %d", ErrFindingQuotaExceeded, req.CaseID, len(nextCaseMap), s.maxPerCase)
	}

	sortedList := sortHypotheses(nextCaseMap)
	nextGen := s.manifest.Generation + 1
	caseDoc := caseHypothesesFile{
		SchemaVersion: SchemaVersion,
		CaseID:        req.CaseID,
		Generation:    nextGen,
		Hypotheses:    sortedList,
	}
	caseBytes, err := json.MarshalIndent(caseDoc, "", "  ")
	if err != nil {
		return nil, err
	}
	caseBytes = append(caseBytes, '\n')
	if s.manifest.TotalBytes+int64(len(caseBytes)) > s.maxStorage {
		return nil, fmt.Errorf("%w: finding store byte quota exceeded", ErrFindingQuotaExceeded)
	}

	tmpCasePath := filepath.Join(s.rootDir, stagingSubdir, fmt.Sprintf("gen-%d-%s.hypotheses.tmp", nextGen, req.CaseID))
	if err := writeSyncFile(tmpCasePath, caseBytes, 0640); err != nil {
		return nil, err
	}
	if s.cfg.Faults.FailAfterStageBeforeCommit {
		return nil, ErrInterrupted
	}

	finalCasePath := filepath.Join(s.rootDir, casesSubdir, req.CaseID+".hypotheses.json")
	if err := checkWithinDir(s.rootDir, finalCasePath); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpCasePath, finalCasePath); err != nil {
		return nil, fmt.Errorf("commit case hypotheses %s: %w", req.CaseID, err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(filepath.Dir(finalCasePath))
	}

	caseSum := sha256.Sum256(caseBytes)
	caseSHA := hex.EncodeToString(caseSum[:])

	outcome := RecordOutcome{
		CaseID:       req.CaseID,
		HypothesisID: candidate.HypothesisID,
		Generation:   nextGen,
		Hypothesis:   cloneHypothesis(candidate),
	}

	nextManifest := s.manifest
	nextManifest.Generation = nextGen
	nextManifest.TotalBytes += int64(len(caseBytes))
	nextOps := make(map[string]RecordOutcome, len(s.manifest.Operations)+1)
	for k, v := range s.manifest.Operations {
		nextOps[k] = v
	}
	if req.OperationID != "" {
		nextOps[req.OperationID] = outcome
	}
	nextCases := make(map[string]persistedCaseMeta, len(s.manifest.Cases)+1)
	for k, v := range s.manifest.Cases {
		nextCases[k] = v
	}
	nextCases[req.CaseID] = persistedCaseMeta{
		CaseID:          req.CaseID,
		FileSHA256:      caseSHA,
		HypothesisCount: len(sortedList),
	}
	nextManifest.Operations = nextOps
	nextManifest.Cases = nextCases

	if err := s.persistManifestUnlocked(nextManifest); err != nil {
		return nil, err
	}
	s.manifest = nextManifest
	s.hypothesesByCase[req.CaseID] = nextCaseMap

	for _, snap := range sealedSnaps {
		postSHA, postSize, hErr := hashRegularFile(snap.path)
		if hErr != nil || postSHA != snap.sha || postSize != snap.size {
			return nil, ErrSealedBytesTampered
		}
	}

	return &outcome, nil
}

// PromoteHypothesisToEvidence explicitly forbids promoting an analyst hypothesis into source
// evidence or an observed fact regardless of UI label or request intent.
func (s *FindingStore) PromoteHypothesisToEvidence(caseID, hypothesisID, requestedUILabel string) error {
	if s == nil {
		return ErrFindingStoreRequired
	}
	if err := validateIdentifier("case_id", caseID); err != nil {
		return err
	}
	if err := validateIdentifier("hypothesis_id", hypothesisID); err != nil {
		return err
	}
	_ = requestedUILabel
	return fmt.Errorf("%w: hypothesis %s/%s remains %q even with UI label", ErrPromotionForbidden, caseID, hypothesisID, RecordKindAnalystHypothesis)
}

// ListHypotheses returns all persisted analyst hypotheses for caseID in deterministic order.
func (s *FindingStore) ListHypotheses(caseID string) ([]AnalystHypothesis, error) {
	if s == nil {
		return nil, ErrFindingStoreRequired
	}
	if err := validateIdentifier("case_id", caseID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrFindingStoreClosed
	}
	caseMap, ok := s.hypothesesByCase[caseID]
	if !ok {
		return []AnalystHypothesis{}, nil
	}
	return sortHypotheses(caseMap), nil
}

// BuildEpistemicLedger produces strictly separated ObservedFacts (from verified EventIndexStore and
// SealStore sealed source evidence) and Hypotheses (from FindingStore). Analyst hypotheses can never
// cross into ObservedFacts.
func (s *FindingStore) BuildEpistemicLedger(
	ctx context.Context,
	sealStore *evidence.SealStore,
	sealRootDir string,
	indexStore *timeline.EventIndexStore,
	caseID string,
) (*CaseEpistemicLedger, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrFindingStoreRequired
	}
	if err := validateIdentifier("case_id", caseID); err != nil {
		return nil, err
	}
	if sealStore == nil || strings.TrimSpace(sealRootDir) == "" || indexStore == nil {
		return nil, fmt.Errorf("%w: sealStore, sealRootDir, and indexStore required to project observed facts", ErrMissingPrerequisite)
	}
	absSealRoot, err := resolveSafeDir(sealRootDir)
	if err != nil {
		return nil, err
	}

	entries, err := indexStore.ListEntries(caseID)
	if err != nil {
		return nil, fmt.Errorf("%w: list indexed events for %s: %v", ErrMissingPrerequisite, caseID, err)
	}

	sealedSnaps := make(map[string]sealedBlobSnap)
	observed := make([]ObservedFact, 0, len(entries))
	for _, entry := range entries {
		if err := verifyAndSnapshotSealedBlob(ctx, sealStore, absSealRoot, caseID, entry.EvidenceID, sealedSnaps); err != nil {
			return nil, err
		}
		sm, sErr := sealStore.GetSealedManifest(caseID, entry.EvidenceID)
		if sErr != nil || sm == nil || !sm.Sealed {
			return nil, fmt.Errorf("%w: sealed manifest %s/%s unavailable", ErrMissingPrerequisite, caseID, entry.EvidenceID)
		}
		observed = append(observed, ObservedFact{
			SchemaVersion: SchemaVersion,
			RecordKind:    RecordKindObservedFact,
			CaseID:        caseID,
			EvidenceID:    entry.EvidenceID,
			SealedSHA256:  sm.SHA256,
			CustodyRoot:   sm.CustodyRoot,
			EventIdentity: entry.EventIdentity,
			SourceLine:    entry.SourceLine,
			EventType:     entry.EventType,
			Summary:       entry.Summary,
			Time:          entry.Time,
			Fields:        entry.Fields,
		})
	}

	hyps, err := s.ListHypotheses(caseID)
	if err != nil {
		return nil, err
	}
	for _, h := range hyps {
		if err := validatePersistedHypothesis(caseID, h); err != nil {
			return nil, err
		}
	}

	for _, snap := range sealedSnaps {
		postSHA, postSize, hErr := hashRegularFile(snap.path)
		if hErr != nil || postSHA != snap.sha || postSize != snap.size {
			return nil, ErrSealedBytesTampered
		}
	}

	return &CaseEpistemicLedger{
		SchemaVersion: SchemaVersion,
		CaseID:        caseID,
		ObservedFacts: observed,
		Hypotheses:    hyps,
	}, nil
}

func (s *FindingStore) persistManifestUnlocked(m findingsIndexManifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := filepath.Join(s.rootDir, stagingSubdir, fmt.Sprintf("findings-index-%d.tmp", m.Generation))
	if err := writeSyncFile(tmp, raw, 0640); err != nil {
		return err
	}
	final := filepath.Join(s.rootDir, findingsIdxFile)
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("commit findings index: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(s.rootDir)
	}
	return nil
}

func verifyAndSnapshotSealedBlob(
	ctx context.Context,
	sealStore *evidence.SealStore,
	absSealRoot, caseID, evidenceID string,
	snaps map[string]sealedBlobSnap,
) error {
	key := caseID + "/" + evidenceID
	if _, exists := snaps[key]; exists {
		return nil
	}
	vr, vErr := evidence.VerifyStoreEvidence(ctx, sealStore, caseID, evidenceID, evidence.VerifyOptions{})
	if vErr != nil || vr == nil || !vr.Verified {
		return fmt.Errorf("%w: sealed evidence %s verification failed: %v", ErrMissingPrerequisite, key, vErr)
	}
	sm, sErr := sealStore.GetSealedManifest(caseID, evidenceID)
	if sErr != nil || sm == nil || !sm.Sealed {
		return fmt.Errorf("%w: sealed manifest %s unavailable", ErrMissingPrerequisite, key)
	}
	blobPath := filepath.Join(absSealRoot, filepath.FromSlash(sm.BlobRelPath))
	if err := checkWithinDir(absSealRoot, blobPath); err != nil {
		return err
	}
	sha, sz, err := hashRegularFile(blobPath)
	if err != nil || sha != sm.SHA256 || sz != sm.SizeBytes {
		return ErrSealedBytesTampered
	}
	snaps[key] = sealedBlobSnap{path: blobPath, sha: sha, size: sz}
	return nil
}

func computeHypothesisDigest(h AnalystHypothesis) (string, error) {
	payload := struct {
		SchemaVersion         string   `json:"schema_version"`
		HypothesisID          string   `json:"hypothesis_id"`
		CaseID                string   `json:"case_id"`
		RecordKind            string   `json:"record_kind"`
		IsSourceEvidence      bool     `json:"is_source_evidence"`
		Author                string   `json:"author"`
		Rationale             string   `json:"rationale"`
		Statement             string   `json:"statement"`
		Status                string   `json:"status"`
		Confidence            *float64 `json:"confidence,omitempty"`
		UILabel               string   `json:"ui_label,omitempty"`
		SupportingEvidenceIDs []string `json:"supporting_evidence_ids,omitempty"`
		SupportingEventIDs    []string `json:"supporting_event_ids,omitempty"`
	}{
		SchemaVersion:         h.SchemaVersion,
		HypothesisID:          h.HypothesisID,
		CaseID:                h.CaseID,
		RecordKind:            h.RecordKind,
		IsSourceEvidence:      h.IsSourceEvidence,
		Author:                h.Author,
		Rationale:             h.Rationale,
		Statement:             h.Statement,
		Status:                h.Status,
		Confidence:            h.Confidence,
		UILabel:               h.UILabel,
		SupportingEvidenceIDs: normalizeUniqueStrings(h.SupportingEvidenceIDs),
		SupportingEventIDs:    normalizeUniqueStrings(h.SupportingEventIDs),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%w: marshal hypothesis digest: %v", ErrMalformedFinding, err)
	}
	prefixed := append([]byte("breachatlas:analyst-hypothesis:v1:"), raw...)
	sum := sha256.Sum256(prefixed)
	return hex.EncodeToString(sum[:]), nil
}

func validateBoundedText(field, raw string, maxBytes int, emptyErr error) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%w: %s is empty", emptyErr, field)
	}
	if !utf8.ValidString(trimmed) {
		return "", fmt.Errorf("%w: %s must be valid UTF-8", ErrInvalidHypothesis, field)
	}
	if len(trimmed) > maxBytes {
		return "", fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidHypothesis, field, maxBytes)
	}
	return trimmed, nil
}

func validateIdentifier(field, value string) error {
	if !identifierRegex.MatchString(value) {
		return fmt.Errorf("%w: invalid %s %q", ErrPathTraversal, field, value)
	}
	return nil
}

func ensureNoSymlink(path string) (bool, error) {
	clean := filepath.Clean(path)
	cur := "/"
	if !filepath.IsAbs(clean) {
		cur = "."
	}
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, fmt.Errorf("lstat %s: %w", cur, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("%w: %s", ErrSymlinkRejected, cur)
		}
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
		return fmt.Errorf("%w: %s escapes root", ErrPathTraversal, target)
	}
	return nil
}

func resolveSafeDir(dir string) (string, error) {
	absDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if _, err := ensureNoSymlink(absDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(absDir, 0750); err != nil {
		return "", fmt.Errorf("create finding root %s: %w", absDir, err)
	}
	return absDir, nil
}

func hashRegularFile(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", 0, fmt.Errorf("%w: %s", ErrSymlinkRejected, path)
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%w: %s is not a regular file", ErrPathTraversal, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func writeSyncFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open staging file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write staging file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync staging file: %w", err)
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

func normalizeUniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func cloneHypothesis(h AnalystHypothesis) AnalystHypothesis {
	cp := h
	cp.SupportingEvidenceIDs = append([]string(nil), h.SupportingEvidenceIDs...)
	cp.SupportingEventIDs = append([]string(nil), h.SupportingEventIDs...)
	if h.Confidence != nil {
		v := *h.Confidence
		cp.Confidence = &v
	}
	return cp
}

func sortHypotheses(m map[string]AnalystHypothesis) []AnalystHypothesis {
	out := make([]AnalystHypothesis, 0, len(m))
	for _, h := range m {
		out = append(out, cloneHypothesis(h))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].HypothesisID < out[j].HypothesisID
	})
	return out
}

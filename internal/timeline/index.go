package timeline

import (
	"context"
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
	"syscall"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/artifacts"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

const (
	DefaultMaxEntriesPerCase = 250000
	casesIndexSubdir         = "cases"
	eventIndexFile           = "timeline-index.json"
	eventLockFile            = ".index.lock"
)

var (
	ErrIndexStoreRequired  = errors.New("timeline event index store root directory is required")
	ErrIndexStoreClosed    = errors.New("timeline event index store closed")
	ErrIndexLockBusy       = errors.New("timeline event index store lock busy: another writer holds exclusive lock")
	ErrUnavailableProvider = errors.New("unavailable timeline indexing provider")
	ErrMalformedPayload    = errors.New("malformed derived payload or record input")
	ErrEntryNotFound       = errors.New("timeline entry or case index not found")
	ErrIndexConflict       = errors.New("operation ID reused with conflicting timeline index parameters")
	ErrIndexQuotaExceeded  = errors.New("timeline event index store quota exceeded")
)

var (
	allowedProviders = map[string]bool{
		"":            true,
		"local":       true,
		"breachatlas": true,
	}
)

// EventIdentityInput supplies the deterministic source-bound fields hashed into a stable EventIdentity.
// Volatile run attributes (ArtifactID, RunID, BatchID, output slice Index, AnalyzedAt) are excluded.
type EventIdentityInput struct {
	CaseID       string         `json:"case_id"`
	InputHashes  []string       `json:"input_hashes"`
	SourceLine   int            `json:"source_line"`
	RawTimestamp string         `json:"raw_timestamp"`
	EventType    string         `json:"event_type,omitempty"`
	Summary      string         `json:"summary,omitempty"`
	Fields       map[string]any `json:"fields,omitempty"`
}

// ComputeEventIdentity calculates a deterministic, order-independent 64-hex SHA-256 identity
// for a derived timeline event so duplicate or reordered analyses converge to the exact same ID.
func ComputeEventIdentity(in EventIdentityInput) (string, error) {
	if err := validateIdentifier("case_id", in.CaseID); err != nil {
		return "", err
	}
	if len(in.InputHashes) == 0 {
		return "", fmt.Errorf("%w: input_hashes required to compute stable event identity", ErrMissingPrerequisite)
	}
	hashes := normalizeUniqueStrings(in.InputHashes)
	for _, h := range hashes {
		if len(h) != 64 {
			return "", fmt.Errorf("%w: invalid input hash %q", ErrInvalidInput, h)
		}
	}

	canonFields := canonicalizeValue(in.Fields)
	payload := struct {
		SchemaVersion string   `json:"schema_version"`
		CaseID        string   `json:"case_id"`
		InputHashes   []string `json:"input_hashes"`
		SourceLine    int      `json:"source_line"`
		RawTimestamp  string   `json:"raw_timestamp"`
		EventType     string   `json:"event_type,omitempty"`
		Summary       string   `json:"summary,omitempty"`
		Fields        any      `json:"fields,omitempty"`
	}{
		SchemaVersion: SchemaVersion,
		CaseID:        in.CaseID,
		InputHashes:   hashes,
		SourceLine:    in.SourceLine,
		RawTimestamp:  in.RawTimestamp,
		EventType:     in.EventType,
		Summary:       in.Summary,
		Fields:        canonFields,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%w: marshal canonical event identity: %v", ErrMalformedPayload, err)
	}
	prefixed := append([]byte("breachatlas:event-identity:v1:"), raw...)
	sum := sha256.Sum256(prefixed)
	return hex.EncodeToString(sum[:]), nil
}

// canonicalizeValue produces deterministic Go structures (sorted map keys serialized via kv pairs)
// so json.Marshal output is invariant across Go map iteration randomness.
type canonicalKV struct {
	Key   string `json:"k"`
	Value any    `json:"v"`
}

func canonicalizeValue(v any) any {
	switch typed := v.(type) {
	case nil:
		return nil
	case map[string]any:
		if len(typed) == 0 {
			return []canonicalKV{}
		}
		keys := make([]string, 0, len(typed))
		for k := range typed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]canonicalKV, 0, len(keys))
		for _, k := range keys {
			out = append(out, canonicalKV{
				Key:   k,
				Value: canonicalizeValue(typed[k]),
			})
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = canonicalizeValue(item)
		}
		return out
	default:
		return typed
	}
}

// TimelineEntry represents one deduplicated, timestamp-normalized timeline event in a case index.
type TimelineEntry struct {
	SchemaVersion       string         `json:"schema_version"`
	EventIdentity       string         `json:"event_identity"`
	CaseID              string         `json:"case_id"`
	EvidenceID          string         `json:"evidence_id"`
	InputHashes         []string       `json:"input_hashes"`
	SourceLine          int            `json:"source_line"`
	EventType           string         `json:"event_type,omitempty"`
	Summary             string         `json:"summary,omitempty"`
	Time                NormalizedTime `json:"time"`
	Fields              map[string]any `json:"fields,omitempty"`
	ToolVersion         string         `json:"tool_version"`
	ConfigHash          string         `json:"config_hash"`
	ObservedArtifactIDs []string       `json:"observed_artifact_ids"`
	FirstIndexedAt      string         `json:"first_indexed_at"`
}

// IndexDerivedRequest indexes events from a verified C16 derived artifact into the case timeline.
type IndexDerivedRequest struct {
	SchemaVersion    string              `json:"schema_version"`
	OperationID      string              `json:"operation_id,omitempty"`
	CaseID           string              `json:"case_id"`
	ArtifactID       string              `json:"artifact_id"`
	Provider         string              `json:"provider,omitempty"`
	ZoneHint         string              `json:"zone_hint,omitempty"`
	SourceConfidence *float64            `json:"source_confidence,omitempty"`
	VerifyOptions    artifacts.VerifyOptions `json:"-"`
}

// IndexableRecord supplies a parsed record with raw timestamp for batch indexing/reordering tests.
type IndexableRecord struct {
	SourceLine       int            `json:"source_line"`
	Timestamp        string         `json:"timestamp"`
	ZoneHint         string         `json:"zone_hint,omitempty"`
	SourceConfidence *float64       `json:"source_confidence,omitempty"`
	EventType        string         `json:"event_type,omitempty"`
	Summary          string         `json:"summary,omitempty"`
	Fields           map[string]any `json:"fields,omitempty"`
}

// IndexRecordsRequest indexes explicit records bound to sealed input hashes, tool version, and config hash.
type IndexRecordsRequest struct {
	SchemaVersion string            `json:"schema_version"`
	OperationID   string            `json:"operation_id,omitempty"`
	CaseID        string            `json:"case_id"`
	EvidenceID    string            `json:"evidence_id"`
	ArtifactID    string            `json:"artifact_id"`
	Provider      string            `json:"provider,omitempty"`
	InputHashes   []string          `json:"input_hashes"`
	ToolVersion   string            `json:"tool_version"`
	ConfigHash    string            `json:"config_hash"`
	Records       []IndexableRecord `json:"records"`
}

// IndexOutcome reports counts of newly indexed vs deduplicated timeline entries.
type IndexOutcome struct {
	CaseID            string   `json:"case_id"`
	ArtifactID        string   `json:"artifact_id"`
	TotalSubmitted    int      `json:"total_submitted"`
	InsertedCount     int      `json:"inserted_count"`
	DeduplicatedCount int      `json:"deduplicated_count"`
	TotalCaseEntries  int      `json:"total_case_entries"`
	EntryIdentities   []string `json:"entry_identities"`
	IdempotentReplay  bool     `json:"idempotent_replay,omitempty"`
}

// IndexFaults enables deterministic fault injection at commit boundaries for restart recovery tests.
type IndexFaults struct {
	SimulateDiskFull           bool
	FailAfterStageBeforeCommit bool
}

// EventIndexConfig configures a durable local EventIndexStore.
type EventIndexConfig struct {
	RootDir           string
	MaxStorageBytes   int64
	MaxEntriesPerCase int
	SyncDir           bool
	Faults            IndexFaults
}

// IndexRecoveryReport reports staging cleanup and recovered case counts on startup.
type IndexRecoveryReport struct {
	CleanedStagingFiles []string `json:"cleaned_staging_files"`
	RecoveredCases      int      `json:"recovered_cases"`
	RecoveredEntries    int      `json:"recovered_entries"`
}

type caseIndexFile struct {
	SchemaVersion string          `json:"schema_version"`
	CaseID        string          `json:"case_id"`
	Generation    uint64          `json:"generation"`
	Entries       []TimelineEntry `json:"entries"`
}

type persistedCaseMeta struct {
	CaseID     string `json:"case_id"`
	FileSHA256 string `json:"file_sha256"`
	EntryCount int    `json:"entry_count"`
}

type eventIndexManifest struct {
	SchemaVersion string                       `json:"schema_version"`
	Generation    uint64                       `json:"generation"`
	TotalBytes    int64                        `json:"total_bytes"`
	Operations    map[string]IndexOutcome      `json:"operations"`
	Cases         map[string]persistedCaseMeta `json:"cases"`
}

// EventIndexStore atomically maintains a deduplicated timeline index keyed by stable derived EventIdentity.
type EventIndexStore struct {
	mu             sync.Mutex
	cfg            EventIndexConfig
	rootDir        string
	maxStorage     int64
	maxEntries     int
	lockFile       *os.File
	closed         bool
	manifest       eventIndexManifest
	entriesByCase  map[string]map[string]TimelineEntry
	recoveryReport IndexRecoveryReport
}

// OpenEventIndexStore opens or creates a bounded local EventIndexStore, acquires an exclusive lock,
// cleans uncommitted staging files, and verifies persisted case index files on disk.
func OpenEventIndexStore(cfg EventIndexConfig) (*EventIndexStore, error) {
	if strings.TrimSpace(cfg.RootDir) == "" {
		return nil, ErrIndexStoreRequired
	}
	rootDir, err := resolveSafeDir(cfg.RootDir)
	if err != nil {
		return nil, err
	}

	maxStorage := cfg.MaxStorageBytes
	if maxStorage == 0 {
		maxStorage = DefaultMaxStorageBytes
	}
	if maxStorage < 0 {
		return nil, fmt.Errorf("%w: max_storage_bytes must be non-negative", ErrInvalidInput)
	}

	maxEntries := cfg.MaxEntriesPerCase
	if maxEntries == 0 {
		maxEntries = DefaultMaxEntriesPerCase
	}
	if maxEntries < 1 {
		return nil, fmt.Errorf("%w: max_entries_per_case must be positive", ErrInvalidInput)
	}

	for _, rel := range []string{casesIndexSubdir, stagingSubdir} {
		sub := filepath.Join(rootDir, rel)
		if err := os.MkdirAll(sub, 0750); err != nil {
			return nil, fmt.Errorf("create event index subdir %s: %w", rel, err)
		}
		if _, err := ensureNoSymlink(sub); err != nil {
			return nil, err
		}
	}

	lockPath := filepath.Join(rootDir, eventLockFile)
	if _, err := ensureNoSymlink(lockPath); err != nil {
		return nil, err
	}
	lockF, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open event index lock: %w", err)
	}
	if err := syscall.Flock(int(lockF.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockF.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrIndexLockBusy
		}
		return nil, fmt.Errorf("acquire event index lock: %w", err)
	}

	s := &EventIndexStore{
		cfg:        cfg,
		rootDir:    rootDir,
		maxStorage: maxStorage,
		maxEntries: maxEntries,
		lockFile:   lockF,
		manifest: eventIndexManifest{
			SchemaVersion: SchemaVersion,
			Operations:    make(map[string]IndexOutcome),
			Cases:         make(map[string]persistedCaseMeta),
		},
		entriesByCase: make(map[string]map[string]TimelineEntry),
	}

	if err := s.recoverOnOpenUnlocked(); err != nil {
		_ = s.closeUnlocked()
		return nil, err
	}
	return s, nil
}

func (s *EventIndexStore) recoverOnOpenUnlocked() error {
	cleaned, err := s.cleanStagingUnlocked()
	if err != nil {
		return err
	}
	s.recoveryReport.CleanedStagingFiles = cleaned

	indexPath := filepath.Join(s.rootDir, eventIndexFile)
	if _, err := ensureNoSymlink(indexPath); err != nil {
		return err
	}
	data, err := os.ReadFile(indexPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read timeline event index: %w", err)
	}

	var manifest eventIndexManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("%w: corrupt timeline event index: %v", ErrMalformedPayload, err)
	}
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported timeline event index version %q", ErrUnsupportedVersion, manifest.SchemaVersion)
	}
	if manifest.Operations == nil {
		manifest.Operations = make(map[string]IndexOutcome)
	}
	if manifest.Cases == nil {
		manifest.Cases = make(map[string]persistedCaseMeta)
	}

	totalRecoveredEntries := 0
	loadedCases := make(map[string]map[string]TimelineEntry, len(manifest.Cases))

	for caseID, meta := range manifest.Cases {
		if err := validateIdentifier("case_id", caseID); err != nil {
			return err
		}
		casePath := filepath.Join(s.rootDir, casesIndexSubdir, caseID+".index.json")
		if err := checkWithinDir(s.rootDir, casePath); err != nil {
			return err
		}
		if _, err := ensureNoSymlink(casePath); err != nil {
			return err
		}
		gotSHA, _, err := hashRegularFile(casePath)
		if err != nil {
			return fmt.Errorf("%w: read persisted case index %s: %v", ErrInvalidInput, caseID, err)
		}
		if gotSHA != meta.FileSHA256 {
			return fmt.Errorf("%w: case index %s digest mismatch on recovery", ErrMalformedPayload, caseID)
		}
		raw, err := os.ReadFile(casePath)
		if err != nil {
			return err
		}
		var cf caseIndexFile
		if err := json.Unmarshal(raw, &cf); err != nil {
			return fmt.Errorf("%w: decode case index %s: %v", ErrMalformedPayload, caseID, err)
		}
		if cf.SchemaVersion != SchemaVersion {
			return fmt.Errorf("%w: unsupported case index schema %q", ErrUnsupportedVersion, cf.SchemaVersion)
		}
		byID := make(map[string]TimelineEntry, len(cf.Entries))
		for _, entry := range cf.Entries {
			byID[entry.EventIdentity] = entry
		}
		loadedCases[caseID] = byID
		totalRecoveredEntries += len(byID)
	}

	s.manifest = manifest
	s.entriesByCase = loadedCases
	s.recoveryReport.RecoveredCases = len(loadedCases)
	s.recoveryReport.RecoveredEntries = totalRecoveredEntries
	return nil
}

func (s *EventIndexStore) cleanStagingUnlocked() ([]string, error) {
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
			return nil, fmt.Errorf("clean index staging %s: %w", entry.Name(), err)
		}
		cleaned = append(cleaned, entry.Name())
	}
	sort.Strings(cleaned)
	return cleaned, nil
}

// LastRecoveryReport returns staging cleanup and recovered case/entry counts from OpenEventIndexStore.
func (s *EventIndexStore) LastRecoveryReport() IndexRecoveryReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return IndexRecoveryReport{
		RecoveredCases:      s.recoveryReport.RecoveredCases,
		RecoveredEntries:    s.recoveryReport.RecoveredEntries,
		CleanedStagingFiles: append([]string(nil), s.recoveryReport.CleanedStagingFiles...),
	}
}

// Close releases the exclusive file lock held by EventIndexStore.
func (s *EventIndexStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeUnlocked()
}

func (s *EventIndexStore) closeUnlocked() error {
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

// IndexDerivedArtifact verifies a C16 derived artifact against ArtifactStore and SealStore,
// normalizes timestamps with C17 rules without fabricating UTC, and indexes entries keyed
// by stable EventIdentity so duplicate or reordered analyses never duplicate timeline rows.
func (s *EventIndexStore) IndexDerivedArtifact(
	ctx context.Context,
	sealStore *evidence.SealStore,
	sealRootDir string,
	artifactStore *artifacts.ArtifactStore,
	artifactRootDir string,
	req IndexDerivedRequest,
) (*IndexOutcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrIndexStoreRequired
	}
	if req.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %q", ErrUnsupportedVersion, req.SchemaVersion)
	}
	if err := validateIdentifier("case_id", req.CaseID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("artifact_id", req.ArtifactID); err != nil {
		return nil, err
	}
	if !allowedProviders[req.Provider] {
		return nil, fmt.Errorf("%w: provider %q unsupported in local-first profile", ErrUnavailableProvider, req.Provider)
	}
	if err := validateZoneHint(req.ZoneHint); err != nil {
		return nil, err
	}
	if sealStore == nil || strings.TrimSpace(sealRootDir) == "" || artifactStore == nil || strings.TrimSpace(artifactRootDir) == "" {
		return nil, fmt.Errorf("%w: sealStore, sealRootDir, artifactStore, and artifactRootDir are required", ErrMissingPrerequisite)
	}

	absArtifactRoot, err := filepath.Abs(filepath.Clean(artifactRootDir))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if _, err := ensureNoSymlink(absArtifactRoot); err != nil {
		return nil, err
	}

	// Verify derived manifest provenance, output payload digest, and read-only sealed inputs.
	vr, err := artifactStore.VerifyStoredArtifact(ctx, sealStore, req.CaseID, req.ArtifactID, req.VerifyOptions)
	if err != nil {
		return nil, fmt.Errorf("%w: derived artifact %s/%s verification failed: %v", ErrMissingPrerequisite, req.CaseID, req.ArtifactID, err)
	}
	if vr == nil || !vr.Verified {
		return nil, fmt.Errorf("%w: derived artifact %s/%s not verified", ErrMissingPrerequisite, req.CaseID, req.ArtifactID)
	}

	dm, err := artifactStore.GetManifest(req.CaseID, req.ArtifactID)
	if err != nil || dm == nil {
		return nil, fmt.Errorf("%w: derived manifest unavailable: %v", ErrMissingPrerequisite, err)
	}

	payloadPath := filepath.Join(absArtifactRoot, filepath.FromSlash(dm.Output.RelPath))
	if err := checkWithinDir(absArtifactRoot, payloadPath); err != nil {
		return nil, err
	}
	gotSHA, gotSize, err := hashRegularFile(payloadPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read derived payload: %v", ErrMalformedPayload, err)
	}
	if gotSHA != dm.Output.SHA256 || gotSize != dm.Output.SizeBytes {
		return nil, fmt.Errorf("%w: derived payload digest mismatch", ErrMalformedPayload)
	}
	rawPayload, err := os.ReadFile(payloadPath)
	if err != nil {
		return nil, err
	}
	var payload artifacts.DerivedPayload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, fmt.Errorf("%w: parse derived payload JSON: %v", ErrMalformedPayload, err)
	}
	if payload.CaseID != req.CaseID {
		return nil, fmt.Errorf("%w: derived payload case_id mismatch", ErrMalformedPayload)
	}

	records := make([]IndexableRecord, 0, len(payload.Records))
	for _, rec := range payload.Records {
		rawTS := strings.TrimSpace(rec.Timestamp)
		if rawTS == "" && rec.Fields != nil {
			if tsVal, ok := rec.Fields["timestamp"].(string); ok {
				rawTS = tsVal
			}
		}
		evType, _ := rec.Fields["event_type"].(string)
		if evType == "" {
			evType, _ = rec.Fields["event"].(string)
		}
		summary, _ := rec.Fields["summary"].(string)
		records = append(records, IndexableRecord{
			SourceLine:       rec.RowNumber,
			Timestamp:        rawTS,
			ZoneHint:         req.ZoneHint,
			SourceConfidence: req.SourceConfidence,
			EventType:        evType,
			Summary:          summary,
			Fields:           rec.Fields,
		})
	}

	return s.IndexRecords(ctx, sealStore, sealRootDir, IndexRecordsRequest{
		SchemaVersion: req.SchemaVersion,
		OperationID:   req.OperationID,
		CaseID:        req.CaseID,
		EvidenceID:    payload.EvidenceID,
		ArtifactID:    req.ArtifactID,
		Provider:      req.Provider,
		InputHashes:   dm.InputHashes,
		ToolVersion:   dm.ToolVersion,
		ConfigHash:    dm.ConfigHash,
		Records:       records,
	})
}

// IndexRecords normalizes timestamps, computes stable EventIdentity values, and deduplicates
// entries against already-indexed events in CaseID while checking sealed source immutability.
func (s *EventIndexStore) IndexRecords(
	ctx context.Context,
	sealStore *evidence.SealStore,
	sealRootDir string,
	req IndexRecordsRequest,
) (*IndexOutcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrIndexStoreRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrIndexStoreClosed
	}
	if req.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %q", ErrUnsupportedVersion, req.SchemaVersion)
	}
	if err := validateIdentifier("case_id", req.CaseID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("evidence_id", req.EvidenceID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("artifact_id", req.ArtifactID); err != nil {
		return nil, err
	}
	if req.OperationID != "" {
		if err := validateIdentifier("operation_id", req.OperationID); err != nil {
			return nil, err
		}
	}
	if !allowedProviders[req.Provider] {
		return nil, fmt.Errorf("%w: provider %q unsupported", ErrUnavailableProvider, req.Provider)
	}
	if len(req.InputHashes) == 0 || strings.TrimSpace(req.ToolVersion) == "" || len(req.ConfigHash) != 64 {
		return nil, fmt.Errorf("%w: input_hashes, tool_version, and 64-hex config_hash are required", ErrMissingPrerequisite)
	}
	if len(req.Records) == 0 {
		return nil, fmt.Errorf("%w: at least one record is required", ErrMalformedPayload)
	}

	// Verify sealed source evidence read-only if SealStore is provided.
	var blobPath, preSHA string
	var preSize int64
	if sealStore != nil {
		if strings.TrimSpace(sealRootDir) == "" {
			return nil, fmt.Errorf("%w: sealRootDir required with sealStore", ErrMissingPrerequisite)
		}
		absSealRoot, err := filepath.Abs(filepath.Clean(sealRootDir))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPathTraversal, err)
		}
		if _, err := ensureNoSymlink(absSealRoot); err != nil {
			return nil, err
		}
		vr, vErr := evidence.VerifyStoreEvidence(ctx, sealStore, req.CaseID, req.EvidenceID, evidence.VerifyOptions{})
		if vErr != nil || vr == nil || !vr.Verified {
			return nil, fmt.Errorf("%w: sealed evidence %s/%s failed verification: %v", ErrMissingPrerequisite, req.CaseID, req.EvidenceID, vErr)
		}
		sm, sErr := sealStore.GetSealedManifest(req.CaseID, req.EvidenceID)
		if sErr != nil || sm == nil || !sm.Sealed {
			return nil, fmt.Errorf("%w: sealed manifest %s/%s unavailable", ErrMissingPrerequisite, req.CaseID, req.EvidenceID)
		}
		blobPath = filepath.Join(absSealRoot, filepath.FromSlash(sm.BlobRelPath))
		if err := checkWithinDir(absSealRoot, blobPath); err != nil {
			return nil, err
		}
		preSHA, preSize, err = hashRegularFile(blobPath)
		if err != nil || preSHA != sm.SHA256 || preSize != sm.SizeBytes {
			return nil, ErrSealedBytesTampered
		}
	}

	sortedHashes := normalizeUniqueStrings(req.InputHashes)
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)

	// Prepare normalized candidate entries before modifying any store state.
	candidates := make([]TimelineEntry, 0, len(req.Records))
	submittedIDs := make([]string, 0, len(req.Records))

	for i, rec := range req.Records {
		nt, err := NormalizeTimestamp(NormalizeRequest{
			RawTimestamp:     rec.Timestamp,
			ZoneHint:         rec.ZoneHint,
			SourceConfidence: rec.SourceConfidence,
		})
		if err != nil {
			return nil, fmt.Errorf("record[%d]: %w", i, err)
		}

		evID, err := ComputeEventIdentity(EventIdentityInput{
			CaseID:       req.CaseID,
			InputHashes:  sortedHashes,
			SourceLine:   rec.SourceLine,
			RawTimestamp: nt.RawTimestamp,
			EventType:    rec.EventType,
			Summary:      rec.Summary,
			Fields:       rec.Fields,
		})
		if err != nil {
			return nil, fmt.Errorf("record[%d]: %w", i, err)
		}

		entry := TimelineEntry{
			SchemaVersion:       SchemaVersion,
			EventIdentity:       evID,
			CaseID:              req.CaseID,
			EvidenceID:          req.EvidenceID,
			InputHashes:         append([]string(nil), sortedHashes...),
			SourceLine:          rec.SourceLine,
			EventType:           rec.EventType,
			Summary:             rec.Summary,
			Time:                nt,
			Fields:              cloneMap(rec.Fields),
			ToolVersion:         req.ToolVersion,
			ConfigHash:          req.ConfigHash,
			ObservedArtifactIDs: []string{req.ArtifactID},
			FirstIndexedAt:      nowStr,
		}
		candidates = append(candidates, entry)
		submittedIDs = append(submittedIDs, evID)
	}

	// Idempotent operation replay / conflict detection.
	if req.OperationID != "" {
		if prev, exists := s.manifest.Operations[req.OperationID]; exists {
			if prev.CaseID != req.CaseID || prev.ArtifactID != req.ArtifactID || !sameStringMultiset(prev.EntryIdentities, submittedIDs) {
				return nil, fmt.Errorf("%w: operation %q previously committed different records", ErrIndexConflict, req.OperationID)
			}
			replay := prev
			replay.IdempotentReplay = true
			return &replay, nil
		}
	}

	if s.cfg.Faults.SimulateDiskFull {
		return nil, ErrDiskFull
	}

	// Merge against existing case entries map cleanly without mutating live map until commit succeeds.
	existing := s.entriesByCase[req.CaseID]
	nextCaseMap := make(map[string]TimelineEntry, len(existing)+len(candidates))
	for k, v := range existing {
		nextCaseMap[k] = cloneEntry(v)
	}

	inserted := 0
	deduplicated := 0
	for _, cand := range candidates {
		if prev, exists := nextCaseMap[cand.EventIdentity]; exists {
			deduplicated++
			prev.ObservedArtifactIDs = normalizeUniqueStrings(append(prev.ObservedArtifactIDs, req.ArtifactID))
			nextCaseMap[cand.EventIdentity] = prev
			continue
		}
		inserted++
		nextCaseMap[cand.EventIdentity] = cand
	}

	if len(nextCaseMap) > s.maxEntries {
		return nil, fmt.Errorf("%w: case %s entry count %d exceeds max %d", ErrIndexQuotaExceeded, req.CaseID, len(nextCaseMap), s.maxEntries)
	}

	sortedEntries := sortTimelineEntries(nextCaseMap)
	nextGen := s.manifest.Generation + 1
	caseDoc := caseIndexFile{
		SchemaVersion: SchemaVersion,
		CaseID:        req.CaseID,
		Generation:    nextGen,
		Entries:       sortedEntries,
	}
	caseBytes, err := json.MarshalIndent(caseDoc, "", "  ")
	if err != nil {
		return nil, err
	}
	caseBytes = append(caseBytes, '\n')
	if s.manifest.TotalBytes+int64(len(caseBytes)) > s.maxStorage {
		return nil, fmt.Errorf("%w: store byte quota exceeded", ErrIndexQuotaExceeded)
	}

	tmpCasePath := filepath.Join(s.rootDir, stagingSubdir, fmt.Sprintf("gen-%d-%s.case.tmp", nextGen, req.CaseID))
	if err := writeSyncFile(tmpCasePath, caseBytes, 0640); err != nil {
		return nil, err
	}

	if s.cfg.Faults.FailAfterStageBeforeCommit {
		return nil, ErrInterrupted
	}

	finalCasePath := filepath.Join(s.rootDir, casesIndexSubdir, req.CaseID+".index.json")
	if err := checkWithinDir(s.rootDir, finalCasePath); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpCasePath, finalCasePath); err != nil {
		return nil, fmt.Errorf("commit case index %s: %w", req.CaseID, err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(filepath.Dir(finalCasePath))
	}

	caseSum := sha256.Sum256(caseBytes)
	caseSHA := hex.EncodeToString(caseSum[:])

	outcome := IndexOutcome{
		CaseID:            req.CaseID,
		ArtifactID:        req.ArtifactID,
		TotalSubmitted:    len(candidates),
		InsertedCount:     inserted,
		DeduplicatedCount: deduplicated,
		TotalCaseEntries:  len(sortedEntries),
		EntryIdentities:   normalizeUniqueStrings(submittedIDs),
	}

	nextManifest := s.manifest
	nextManifest.Generation = nextGen
	nextManifest.TotalBytes += int64(len(caseBytes))
	nextOps := make(map[string]IndexOutcome, len(s.manifest.Operations)+1)
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
		CaseID:     req.CaseID,
		FileSHA256: caseSHA,
		EntryCount: len(sortedEntries),
	}
	nextManifest.Operations = nextOps
	nextManifest.Cases = nextCases

	if err := s.persistManifestUnlocked(nextManifest); err != nil {
		return nil, err
	}
	s.manifest = nextManifest
	s.entriesByCase[req.CaseID] = nextCaseMap

	if blobPath != "" {
		postSHA, postSize, hErr := hashRegularFile(blobPath)
		if hErr != nil || postSHA != preSHA || postSize != preSize {
			return nil, ErrSealedBytesTampered
		}
	}

	return &outcome, nil
}

// ListEntries returns all deduplicated timeline entries for caseID in deterministic canonical order.
func (s *EventIndexStore) ListEntries(caseID string) ([]TimelineEntry, error) {
	if s == nil {
		return nil, ErrIndexStoreRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrIndexStoreClosed
	}
	if err := validateIdentifier("case_id", caseID); err != nil {
		return nil, err
	}
	entriesMap, ok := s.entriesByCase[caseID]
	if !ok {
		return []TimelineEntry{}, nil
	}
	return sortTimelineEntries(entriesMap), nil
}

// GetEntry returns a single deduplicated TimelineEntry by (caseID, eventIdentity).
func (s *EventIndexStore) GetEntry(caseID, eventIdentity string) (*TimelineEntry, error) {
	if s == nil {
		return nil, ErrIndexStoreRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrIndexStoreClosed
	}
	if err := validateIdentifier("case_id", caseID); err != nil {
		return nil, err
	}
	entriesMap, ok := s.entriesByCase[caseID]
	if !ok {
		return nil, fmt.Errorf("%w: case %s", ErrEntryNotFound, caseID)
	}
	entry, ok := entriesMap[eventIdentity]
	if !ok {
		return nil, fmt.Errorf("%w: entry %s/%s", ErrEntryNotFound, caseID, eventIdentity)
	}
	cp := cloneEntry(entry)
	return &cp, nil
}

func (s *EventIndexStore) persistManifestUnlocked(m eventIndexManifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := filepath.Join(s.rootDir, stagingSubdir, fmt.Sprintf("timeline-index-%d.tmp", m.Generation))
	if err := writeSyncFile(tmp, raw, 0640); err != nil {
		return err
	}
	finalPath := filepath.Join(s.rootDir, eventIndexFile)
	if err := os.Rename(tmp, finalPath); err != nil {
		return fmt.Errorf("commit timeline index manifest: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(s.rootDir)
	}
	return nil
}

func sortTimelineEntries(m map[string]TimelineEntry) []TimelineEntry {
	out := make([]TimelineEntry, 0, len(m))
	for _, v := range m {
		out = append(out, cloneEntry(v))
	}
	sort.Slice(out, func(i, j int) bool {
		ti, oki := parseUTC(out[i].Time.NormalizedTimestamp)
		tj, okj := parseUTC(out[j].Time.NormalizedTimestamp)
		if oki != okj {
			return oki
		}
		if oki && !ti.Equal(tj) {
			return ti.Before(tj)
		}
		if out[i].Time.RawTimestamp != out[j].Time.RawTimestamp {
			return out[i].Time.RawTimestamp < out[j].Time.RawTimestamp
		}
		if out[i].SourceLine != out[j].SourceLine {
			return out[i].SourceLine < out[j].SourceLine
		}
		return out[i].EventIdentity < out[j].EventIdentity
	})
	return out
}

func parseUTC(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func normalizeUniqueStrings(in []string) []string {
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

func sameStringMultiset(a, b []string) bool {
	na := normalizeUniqueStrings(a)
	nb := normalizeUniqueStrings(b)
	if len(na) != len(nb) {
		return false
	}
	for i := range na {
		if na[i] != nb[i] {
			return false
		}
	}
	return true
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

func cloneEntry(e TimelineEntry) TimelineEntry {
	cp := e
	cp.InputHashes = append([]string(nil), e.InputHashes...)
	cp.ObservedArtifactIDs = append([]string(nil), e.ObservedArtifactIDs...)
	cp.Time.CandidateUTCs = append([]string(nil), e.Time.CandidateUTCs...)
	cp.Time.CandidateOffsets = append([]string(nil), e.Time.CandidateOffsets...)
	if e.Time.RawConfidence != nil {
		v := *e.Time.RawConfidence
		cp.Time.RawConfidence = &v
	}
	cp.Fields = cloneMap(e.Fields)
	return cp
}

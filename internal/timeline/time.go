package timeline

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

	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

const (
	SchemaVersion           = "1"
	DefaultMaxStorageBytes  = int64(20 * 1024 * 1024 * 1024) // 20 GiB planning target
	DefaultMaxBatchBytes    = int64(16 * 1024 * 1024)        // 16 MiB bounded batch import
	DefaultMaxBatchRecords  = 100000
	batchesSubdir           = "batches"
	stagingSubdir           = "staging"
	indexFileName           = "time-index.json"
	lockFileName            = ".time.lock"

	StatusExplicitOffset = "explicit_offset"
	StatusIANAZone       = "iana_zone"
	StatusUnknownZone    = "unknown_zone"
	StatusDSTAmbiguous   = "dst_ambiguous"
	StatusDSTNonexistent = "dst_nonexistent"

	ConfidenceExact       = 1.0
	ConfidenceAmbiguous   = 0.5
	ConfidenceUnknownZone = 0.25
)

var (
	ErrTimeStoreRequired  = errors.New("timeline time store root directory is required")
	ErrTimeStoreClosed    = errors.New("timeline time store closed")
	ErrTimeLockBusy       = errors.New("timeline time store lock busy: another writer holds exclusive lock")
	ErrUnsupportedVersion = errors.New("unsupported timestamp batch schema version")
	ErrInvalidInput       = errors.New("invalid timestamp normalization input")
	ErrMalformedTimestamp = errors.New("malformed timestamp cannot be parsed")
	ErrOversizedInput     = errors.New("timestamp import batch exceeds configured size or record limits")
	ErrPathTraversal      = errors.New("path traversal or invalid identifier rejected")
	ErrSymlinkRejected    = errors.New("symlink rejected in timeline store path")
	ErrMissingPrerequisite = errors.New("missing or unverified sealed evidence prerequisite")
	ErrSealedBytesTampered = errors.New("sealed source bytes modified during timestamp normalization")
	ErrBatchConflict      = errors.New("batch or operation ID reused with conflicting parameters")
	ErrBatchNotFound      = errors.New("normalized timestamp batch not found")
	ErrInterrupted        = errors.New("timestamp batch import interrupted before authoritative commit")
	ErrDiskFull           = errors.New("disk full: timestamp batch import aborted")
	ErrStorageQuota       = errors.New("timeline store quota exceeded")
)

var identifierRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

var (
	offsetLayouts = []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05Z07:00",
		"2006-01-02T15:04:05.999999999-0700",
		"2006-01-02T15:04:05-0700",
		"2006-01-02 15:04:05.999999999 -0700",
		"2006-01-02 15:04:05 -0700",
		time.RFC1123Z,
	}
	zonelessLayouts = []string{
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006/01/02 15:04:05.999999999",
		"2006/01/02 15:04:05",
	}
)

// NormalizeRequest configures timestamp normalization without discarding raw values.
type NormalizeRequest struct {
	RawTimestamp     string   `json:"raw_timestamp"`
	ZoneHint         string   `json:"zone_hint,omitempty"`
	SourceConfidence *float64 `json:"source_confidence,omitempty"`
}

// NormalizedTime preserves raw input while making UTC, unknown zones, and DST ambiguity explicit.
type NormalizedTime struct {
	RawTimestamp        string   `json:"raw_timestamp"`
	NormalizedTimestamp string   `json:"normalized_timestamp,omitempty"`
	TimezoneStatus      string   `json:"timezone_status"`
	TimezoneOffset      string   `json:"timezone_offset"`
	SourceZone          string   `json:"source_zone,omitempty"`
	Confidence          float64  `json:"confidence"`
	RawConfidence       *float64 `json:"raw_confidence,omitempty"`
	CandidateUTCs       []string `json:"candidate_utcs,omitempty"`
	CandidateOffsets    []string `json:"candidate_offsets,omitempty"`
	AmbiguityReason     string   `json:"ambiguity_reason,omitempty"`
}

// RawEventInput represents one raw timeline record submitted for timestamp normalization.
type RawEventInput struct {
	EventID          string   `json:"event_id"`
	RawTimestamp     string   `json:"raw_timestamp"`
	ZoneHint         string   `json:"zone_hint,omitempty"`
	SourceConfidence *float64 `json:"source_confidence,omitempty"`
	SourceLine       int      `json:"source_line,omitempty"`
	EventType        string   `json:"event_type,omitempty"`
	Summary          string   `json:"summary,omitempty"`
}

// NormalizedEvent preserves event payload and normalized timestamp metadata.
type NormalizedEvent struct {
	EventID    string         `json:"event_id"`
	SourceLine int            `json:"source_line,omitempty"`
	EventType  string         `json:"event_type,omitempty"`
	Summary    string         `json:"summary,omitempty"`
	Time       NormalizedTime `json:"time"`
}

// ImportBatchRequest submits a schema-versioned batch of raw events for durable timestamp normalization.
type ImportBatchRequest struct {
	SchemaVersion string          `json:"schema_version"`
	OperationID   string          `json:"operation_id,omitempty"`
	BatchID       string          `json:"batch_id"`
	CaseID        string          `json:"case_id"`
	EvidenceID    string          `json:"evidence_id,omitempty"`
	Events        []RawEventInput `json:"events"`
	CreatedAt     string          `json:"created_at,omitempty"`
}

// NormalizedBatch represents a durable committed timestamp normalization batch.
type NormalizedBatch struct {
	SchemaVersion    string            `json:"schema_version"`
	Generation       uint64            `json:"generation"`
	OperationID      string            `json:"operation_id,omitempty"`
	BatchID          string            `json:"batch_id"`
	CaseID           string            `json:"case_id"`
	EvidenceID       string            `json:"evidence_id,omitempty"`
	BatchDigest      string            `json:"batch_digest"`
	EventCount       int               `json:"event_count"`
	Events           []NormalizedEvent `json:"events"`
	CommittedAt      string            `json:"committed_at"`
	IdempotentReplay bool              `json:"idempotent_replay,omitempty"`
}

// StoreFaults injects deterministic faults for interrupted-import and disk-full recovery tests.
type StoreFaults struct {
	SimulateDiskFull           bool
	FailAfterStageBeforeCommit bool
}

// TimeStoreConfig configures a bounded durable TimeStore.
type TimeStoreConfig struct {
	RootDir            string
	MaxStorageBytes    int64
	MaxBatchBytes      int64
	MaxRecordsPerBatch int
	SyncDir            bool
	Faults             StoreFaults
}

// RecoveryReport reports uncommitted staging files swept and committed batches recovered on startup.
type RecoveryReport struct {
	CleanedStagingFiles []string `json:"cleaned_staging_files"`
	RecoveredBatches    int      `json:"recovered_batches"`
}

type timeIndex struct {
	SchemaVersion string                     `json:"schema_version"`
	Generation    uint64                     `json:"generation"`
	TotalBytes    int64                      `json:"total_bytes"`
	Operations    map[string]NormalizedBatch `json:"operations"`
	Batches       map[string]NormalizedBatch `json:"batches"` // "caseID/batchID" -> summary metadata
}

// TimeStore atomically persists bounded normalized timestamp batches with restart recovery.
type TimeStore struct {
	mu             sync.Mutex
	cfg            TimeStoreConfig
	rootDir        string
	maxStorage     int64
	maxBatchBytes  int64
	maxRecords     int
	lockFile       *os.File
	closed         bool
	index          timeIndex
	recoveryReport RecoveryReport
}

// NormalizeTimestamp normalizes raw timestamps to UTC when unambiguous, while keeping
// raw_timestamp intact and leaving unknown zones or DST ambiguity explicit rather than fabricating UTC.
func NormalizeTimestamp(req NormalizeRequest) (NormalizedTime, error) {
	if req.SourceConfidence != nil && (*req.SourceConfidence < 0 || *req.SourceConfidence > 1) {
		return NormalizedTime{}, fmt.Errorf("%w: source_confidence must be in [0,1]", ErrInvalidInput)
	}
	raw := req.RawTimestamp
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsRune(raw, '\x00') {
		return NormalizedTime{}, fmt.Errorf("%w: empty or null-containing timestamp", ErrMalformedTimestamp)
	}
	if err := validateZoneHint(req.ZoneHint); err != nil {
		return NormalizedTime{}, err
	}

	var rawConfCopy *float64
	if req.SourceConfidence != nil {
		v := *req.SourceConfidence
		rawConfCopy = &v
	}

	// Per RFC 3339 §4.3, numeric offset "-00:00" (or "-0000") explicitly denotes an unknown local offset.
	if hasRFC3339UnknownOffset(trimmed) {
		return NormalizedTime{
			RawTimestamp:    raw,
			TimezoneStatus:  StatusUnknownZone,
			TimezoneOffset:  "unknown",
			SourceZone:      "unknown",
			Confidence:      chooseConfidence(rawConfCopy, ConfidenceUnknownZone),
			RawConfidence:   rawConfCopy,
			AmbiguityReason: "timestamp carries -00:00 unknown-offset marker; UTC omitted rather than fabricated",
		}, nil
	}

	// 1. Try layouts containing an explicit numeric offset or 'Z'.
	for _, layout := range offsetLayouts {
		if t, err := time.Parse(layout, trimmed); err == nil {
			_, offsetSec := t.Zone()
			return NormalizedTime{
				RawTimestamp:        raw,
				NormalizedTimestamp: t.UTC().Format(time.RFC3339Nano),
				TimezoneStatus:      StatusExplicitOffset,
				TimezoneOffset:      formatOffset(offsetSec),
				Confidence:          chooseConfidence(rawConfCopy, ConfidenceExact),
				RawConfidence:       rawConfCopy,
			}, nil
		}
	}

	// 2. Try zoneless wall-clock layouts; resolve against IANA ZoneHint if provided, else explicit unknown_zone.
	wallStr, wallTime, ok := parseZoneless(trimmed)
	if !ok {
		return NormalizedTime{}, fmt.Errorf("%w: unrecognized timestamp format %q", ErrMalformedTimestamp, raw)
	}

	hint := strings.TrimSpace(req.ZoneHint)
	if hint == "" {
		return NormalizedTime{
			RawTimestamp:    raw,
			TimezoneStatus:  StatusUnknownZone,
			TimezoneOffset:  "unknown",
			SourceZone:      "unknown",
			Confidence:      chooseConfidence(rawConfCopy, ConfidenceUnknownZone),
			RawConfidence:   rawConfCopy,
			AmbiguityReason: "raw timestamp has no timezone offset and no zone hint; UTC omitted rather than fabricated",
		}, nil
	}

	loc, err := time.LoadLocation(hint)
	if err != nil {
		return NormalizedTime{
			RawTimestamp:    raw,
			TimezoneStatus:  StatusUnknownZone,
			TimezoneOffset:  "unknown",
			SourceZone:      hint,
			Confidence:      chooseConfidence(rawConfCopy, ConfidenceUnknownZone),
			RawConfidence:   rawConfCopy,
			AmbiguityReason: fmt.Sprintf("unrecognized timezone %q; UTC omitted rather than fabricated", hint),
		}, nil
	}

	return resolveWallClockInLocation(raw, wallStr, wallTime, loc, rawConfCopy), nil
}

func resolveWallClockInLocation(raw, wallStr string, wall time.Time, loc *time.Location, rawConf *float64) NormalizedTime {
	y, m, d := wall.Date()
	hh, mm, ss := wall.Clock()
	ns := wall.Nanosecond()

	// Collect all distinct offsets observed in loc within +-24h around wall clock.
	ref := time.Date(y, m, d, hh, mm, ss, ns, loc)
	seenOffsets := make(map[int]bool)
	for delta := -24 * time.Hour; delta <= 24*time.Hour; delta += 30 * time.Minute {
		_, off := ref.Add(delta).In(loc).Zone()
		seenOffsets[off] = true
	}

	type candidate struct {
		utc    time.Time
		offset int
	}
	var matches []candidate
	for off := range seenOffsets {
		utc := time.Date(y, m, d, hh, mm, ss, ns, time.UTC).Add(-time.Duration(off) * time.Second)
		local := utc.In(loc)
		ly, lm, ld := local.Date()
		lh, lmin, ls := local.Clock()
		_, gotOff := local.Zone()
		if ly == y && lm == m && ld == d && lh == hh && lmin == mm && ls == ss && local.Nanosecond() == ns && gotOff == off {
			matches = append(matches, candidate{utc: utc, offset: off})
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].utc.Before(matches[j].utc)
	})

	switch len(matches) {
	case 0:
		return NormalizedTime{
			RawTimestamp:    raw,
			TimezoneStatus:  StatusDSTNonexistent,
			TimezoneOffset:  "nonexistent",
			SourceZone:      loc.String(),
			Confidence:      chooseConfidence(rawConf, ConfidenceAmbiguous),
			RawConfidence:   rawConf,
			AmbiguityReason: fmt.Sprintf("wall-clock %s does not exist in %s due to DST spring-forward gap; UTC omitted", wallStr, loc.String()),
		}
	case 1:
		return NormalizedTime{
			RawTimestamp:        raw,
			NormalizedTimestamp: matches[0].utc.Format(time.RFC3339Nano),
			TimezoneStatus:      StatusIANAZone,
			TimezoneOffset:      formatOffset(matches[0].offset),
			SourceZone:          loc.String(),
			Confidence:          chooseConfidence(rawConf, ConfidenceExact),
			RawConfidence:       rawConf,
		}
	default:
		utcs := make([]string, 0, len(matches))
		offs := make([]string, 0, len(matches))
		for _, c := range matches {
			utcs = append(utcs, c.utc.Format(time.RFC3339Nano))
			offs = append(offs, formatOffset(c.offset))
		}
		return NormalizedTime{
			RawTimestamp:     raw,
			TimezoneStatus:   StatusDSTAmbiguous,
			TimezoneOffset:   "ambiguous",
			SourceZone:       loc.String(),
			Confidence:       chooseConfidence(rawConf, ConfidenceAmbiguous),
			RawConfidence:    rawConf,
			CandidateUTCs:    utcs,
			CandidateOffsets: offs,
			AmbiguityReason:  fmt.Sprintf("wall-clock %s is ambiguous across %d DST fold instants in %s; UTC omitted rather than guessed", wallStr, len(matches), loc.String()),
		}
	}
}

func parseZoneless(trimmed string) (string, time.Time, bool) {
	for _, layout := range zonelessLayouts {
		if t, err := time.ParseInLocation(layout, trimmed, time.UTC); err == nil {
			return trimmed, t, true
		}
	}
	return "", time.Time{}, false
}

func hasRFC3339UnknownOffset(s string) bool {
	return strings.HasSuffix(s, "-00:00") || strings.HasSuffix(s, "-0000")
}

func formatOffset(offsetSec int) string {
	sign := "+"
	if offsetSec < 0 {
		sign = "-"
		offsetSec = -offsetSec
	}
	hours := offsetSec / 3600
	mins := (offsetSec % 3600) / 60
	return fmt.Sprintf("%s%02d:%02d", sign, hours, mins)
}

func chooseConfidence(rawConf *float64, fallback float64) float64 {
	if rawConf != nil {
		return *rawConf
	}
	return fallback
}

func validateZoneHint(hint string) error {
	if hint == "" {
		return nil
	}
	if strings.ContainsRune(hint, '\x00') || strings.Contains(hint, "..") || strings.HasPrefix(hint, "/") || strings.ContainsRune(hint, '\\') {
		return fmt.Errorf("%w: unsafe zone_hint %q", ErrPathTraversal, hint)
	}
	return nil
}

func validateIdentifier(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidInput, field)
	}
	if strings.ContainsRune(value, '\x00') || strings.Contains(value, "..") || strings.ContainsAny(value, "/\\") {
		return fmt.Errorf("%w: unsafe %s %q", ErrPathTraversal, field, value)
	}
	if !identifierRegex.MatchString(value) {
		return fmt.Errorf("%w: invalid %s %q", ErrInvalidInput, field, value)
	}
	return nil
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
	if strings.TrimSpace(dir) == "" {
		return "", ErrTimeStoreRequired
	}
	if strings.ContainsRune(dir, '\x00') {
		return "", fmt.Errorf("%w: null byte in root directory", ErrPathTraversal)
	}
	for _, seg := range strings.FieldsFunc(dir, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return "", fmt.Errorf("%w: traversal segment in root directory", ErrPathTraversal)
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
			return "", fmt.Errorf("create time store dir %s: %w", absDir, err)
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
			return "", fmt.Errorf("%w: %s is not a directory", ErrInvalidInput, absDir)
		}
	}
	return absDir, nil
}

// OpenTimeStore opens or initializes a bounded local TimeStore, acquires an exclusive writer lock,
// sweeps orphaned staging files from interrupted imports, and verifies committed batches on disk.
func OpenTimeStore(cfg TimeStoreConfig) (*TimeStore, error) {
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

	maxBatchBytes := cfg.MaxBatchBytes
	if maxBatchBytes == 0 {
		maxBatchBytes = DefaultMaxBatchBytes
	}
	if maxBatchBytes < 1 {
		return nil, fmt.Errorf("%w: max_batch_bytes must be positive", ErrInvalidInput)
	}

	maxRecords := cfg.MaxRecordsPerBatch
	if maxRecords == 0 {
		maxRecords = DefaultMaxBatchRecords
	}
	if maxRecords < 1 {
		return nil, fmt.Errorf("%w: max_records_per_batch must be positive", ErrInvalidInput)
	}

	for _, rel := range []string{batchesSubdir, stagingSubdir} {
		sub := filepath.Join(rootDir, rel)
		if err := os.MkdirAll(sub, 0750); err != nil {
			return nil, fmt.Errorf("create time store subdir %s: %w", rel, err)
		}
		if _, err := ensureNoSymlink(sub); err != nil {
			return nil, err
		}
	}

	lockPath := filepath.Join(rootDir, lockFileName)
	if _, err := ensureNoSymlink(lockPath); err != nil {
		return nil, err
	}
	lockF, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open time lock: %w", err)
	}
	if err := syscall.Flock(int(lockF.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockF.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrTimeLockBusy
		}
		return nil, fmt.Errorf("acquire time lock: %w", err)
	}

	s := &TimeStore{
		cfg:           cfg,
		rootDir:       rootDir,
		maxStorage:    maxStorage,
		maxBatchBytes: maxBatchBytes,
		maxRecords:    maxRecords,
		lockFile:      lockF,
		index: timeIndex{
			SchemaVersion: SchemaVersion,
			Operations:    make(map[string]NormalizedBatch),
			Batches:       make(map[string]NormalizedBatch),
		},
	}

	if err := s.recoverOnOpenUnlocked(); err != nil {
		_ = s.closeUnlocked()
		return nil, err
	}

	return s, nil
}

func (s *TimeStore) recoverOnOpenUnlocked() error {
	cleaned, err := s.cleanStagingUnlocked()
	if err != nil {
		return err
	}
	s.recoveryReport.CleanedStagingFiles = cleaned

	indexPath := filepath.Join(s.rootDir, indexFileName)
	if _, err := ensureNoSymlink(indexPath); err != nil {
		return err
	}
	data, err := os.ReadFile(indexPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read time index: %w", err)
	}

	var idx timeIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return fmt.Errorf("%w: corrupt time index: %v", ErrInvalidInput, err)
	}
	if idx.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported time index version %q", ErrUnsupportedVersion, idx.SchemaVersion)
	}
	if idx.Operations == nil {
		idx.Operations = make(map[string]NormalizedBatch)
	}
	if idx.Batches == nil {
		idx.Batches = make(map[string]NormalizedBatch)
	}

	for key, indexed := range idx.Batches {
		batchPath := filepath.Join(s.rootDir, batchesSubdir, indexed.CaseID, indexed.BatchID+".json")
		if err := checkWithinDir(s.rootDir, batchPath); err != nil {
			return err
		}
		if _, err := ensureNoSymlink(batchPath); err != nil {
			return err
		}
		raw, err := os.ReadFile(batchPath)
		if err != nil {
			return fmt.Errorf("%w: missing batch file for %s: %v", ErrInvalidInput, key, err)
		}
		var onDisk NormalizedBatch
		if err := json.Unmarshal(raw, &onDisk); err != nil {
			return fmt.Errorf("%w: corrupt batch file for %s: %v", ErrInvalidInput, key, err)
		}
		if onDisk.BatchDigest != indexed.BatchDigest {
			return fmt.Errorf("%w: recovered batch digest mismatch for %s", ErrInvalidInput, key)
		}
	}

	s.index = idx
	s.recoveryReport.RecoveredBatches = len(idx.Batches)
	return nil
}

func (s *TimeStore) cleanStagingUnlocked() ([]string, error) {
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
			return nil, fmt.Errorf("clean staging file %s: %w", entry.Name(), err)
		}
		cleaned = append(cleaned, entry.Name())
	}
	sort.Strings(cleaned)
	return cleaned, nil
}

// LastRecoveryReport returns staging cleanup and recovered committed batch counts from startup.
func (s *TimeStore) LastRecoveryReport() RecoveryReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return RecoveryReport{
		RecoveredBatches:    s.recoveryReport.RecoveredBatches,
		CleanedStagingFiles: append([]string(nil), s.recoveryReport.CleanedStagingFiles...),
	}
}

// Close releases the exclusive file lock held by TimeStore.
func (s *TimeStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeUnlocked()
}

func (s *TimeStore) closeUnlocked() error {
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

// ImportBatchJSON decodes, validates bounds/schema/paths, normalizes timestamps, and atomically commits a JSON batch.
func (s *TimeStore) ImportBatchJSON(
	ctx context.Context,
	sealStore *evidence.SealStore,
	sealRootDir string,
	rawJSON []byte,
) (*NormalizedBatch, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if s == nil {
		return nil, ErrTimeStoreRequired
	}
	if int64(len(rawJSON)) > s.maxBatchBytes {
		return nil, fmt.Errorf("%w: input JSON %d bytes exceeds max %d", ErrOversizedInput, len(rawJSON), s.maxBatchBytes)
	}
	var req ImportBatchRequest
	if err := json.Unmarshal(rawJSON, &req); err != nil {
		return nil, fmt.Errorf("%w: invalid batch JSON: %v", ErrMalformedTimestamp, err)
	}
	return s.ImportBatch(ctx, sealStore, sealRootDir, req)
}

// ImportBatch validates schema version, bounds, identifiers, and timestamps, rejecting invalid inputs
// before staging or committing, and optionally verifies sealed source bytes read-only before and after commit.
func (s *TimeStore) ImportBatch(
	ctx context.Context,
	sealStore *evidence.SealStore,
	sealRootDir string,
	req ImportBatchRequest,
) (*NormalizedBatch, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrTimeStoreRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrTimeStoreClosed
	}
	if req.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %q", ErrUnsupportedVersion, req.SchemaVersion)
	}
	if err := validateIdentifier("case_id", req.CaseID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("batch_id", req.BatchID); err != nil {
		return nil, err
	}
	if req.OperationID != "" {
		if err := validateIdentifier("operation_id", req.OperationID); err != nil {
			return nil, err
		}
	}
	if req.EvidenceID != "" {
		if err := validateIdentifier("evidence_id", req.EvidenceID); err != nil {
			return nil, err
		}
	}
	if len(req.Events) == 0 {
		return nil, fmt.Errorf("%w: events slice must be non-empty", ErrInvalidInput)
	}
	if len(req.Events) > s.maxRecords {
		return nil, fmt.Errorf("%w: event count %d exceeds max %d", ErrOversizedInput, len(req.Events), s.maxRecords)
	}

	var blobPath, preSHA string
	var preSize int64
	if sealStore != nil && req.EvidenceID != "" {
		if strings.TrimSpace(sealRootDir) == "" {
			return nil, fmt.Errorf("%w: seal root directory required", ErrMissingPrerequisite)
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
			return nil, fmt.Errorf("%w: sealed evidence %s/%s check failed: %v", ErrMissingPrerequisite, req.CaseID, req.EvidenceID, vErr)
		}
		sm, sErr := sealStore.GetSealedManifest(req.CaseID, req.EvidenceID)
		if sErr != nil || sm == nil || !sm.Sealed {
			return nil, fmt.Errorf("%w: sealed manifest %s/%s unavailable", ErrMissingPrerequisite, req.CaseID, req.EvidenceID)
		}
		blobPath = filepath.Join(absSealRoot, filepath.FromSlash(sm.BlobRelPath))
		if err := checkWithinDir(absSealRoot, blobPath); err != nil {
			return nil, err
		}
		var hErr error
		preSHA, preSize, hErr = hashRegularFile(blobPath)
		if hErr != nil {
			return nil, fmt.Errorf("%w: read sealed blob: %v", ErrMissingPrerequisite, hErr)
		}
		if preSHA != sm.SHA256 || preSize != sm.SizeBytes {
			return nil, ErrSealedBytesTampered
		}
	}

	// Normalize every timestamp before staging so any malformed or unsafe input fails cleanly without writing.
	normalized := make([]NormalizedEvent, 0, len(req.Events))
	for _, ev := range req.Events {
		if err := validateIdentifier("event_id", ev.EventID); err != nil {
			return nil, err
		}
		nt, err := NormalizeTimestamp(NormalizeRequest{
			RawTimestamp:     ev.RawTimestamp,
			ZoneHint:         ev.ZoneHint,
			SourceConfidence: ev.SourceConfidence,
		})
		if err != nil {
			return nil, fmt.Errorf("event %s: %w", ev.EventID, err)
		}
		normalized = append(normalized, NormalizedEvent{
			EventID:    ev.EventID,
			SourceLine: ev.SourceLine,
			EventType:  ev.EventType,
			Summary:    ev.Summary,
			Time:       nt,
		})
	}

	committedAt := req.CreatedAt
	if strings.TrimSpace(committedAt) == "" {
		committedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, err := time.Parse(time.RFC3339Nano, committedAt); err != nil {
		return nil, fmt.Errorf("%w: invalid created_at %q", ErrMalformedTimestamp, committedAt)
	}

	eventsJSON, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(eventsJSON)
	batchDigest := hex.EncodeToString(sum[:])

	batch := NormalizedBatch{
		SchemaVersion: SchemaVersion,
		OperationID:   req.OperationID,
		BatchID:       req.BatchID,
		CaseID:        req.CaseID,
		EvidenceID:    req.EvidenceID,
		BatchDigest:   batchDigest,
		EventCount:    len(normalized),
		Events:        normalized,
		CommittedAt:   committedAt,
	}

	if req.OperationID != "" {
		if prev, exists := s.index.Operations[req.OperationID]; exists {
			if prev.CaseID != batch.CaseID || prev.BatchID != batch.BatchID || prev.BatchDigest != batch.BatchDigest {
				return nil, fmt.Errorf("%w: operation %q previously committed different parameters", ErrBatchConflict, req.OperationID)
			}
			replay := prev
			replay.IdempotentReplay = true
			return &replay, nil
		}
	}

	batchKey := req.CaseID + "/" + req.BatchID
	if prev, exists := s.index.Batches[batchKey]; exists {
		if prev.BatchDigest != batch.BatchDigest {
			return nil, fmt.Errorf("%w: batch %s already exists with different content", ErrBatchConflict, batchKey)
		}
		replay := prev
		replay.IdempotentReplay = true
		return &replay, nil
	}

	if s.cfg.Faults.SimulateDiskFull {
		return nil, ErrDiskFull
	}

	batch.Generation = s.index.Generation + 1
	batchBytes, err := json.MarshalIndent(batch, "", "  ")
	if err != nil {
		return nil, err
	}
	batchBytes = append(batchBytes, '\n')
	if int64(len(batchBytes)) > s.maxBatchBytes {
		return nil, fmt.Errorf("%w: encoded batch %d bytes exceeds max %d", ErrOversizedInput, len(batchBytes), s.maxBatchBytes)
	}
	if s.index.TotalBytes+int64(len(batchBytes)) > s.maxStorage {
		return nil, fmt.Errorf("%w: store quota exceeded", ErrStorageQuota)
	}

	tmpPath := filepath.Join(s.rootDir, stagingSubdir, fmt.Sprintf("gen-%d-%s-%s.batch.tmp", batch.Generation, req.CaseID, req.BatchID))
	if err := writeSyncFile(tmpPath, batchBytes, 0640); err != nil {
		return nil, err
	}

	if s.cfg.Faults.FailAfterStageBeforeCommit {
		return nil, ErrInterrupted
	}

	finalPath := filepath.Join(s.rootDir, batchesSubdir, req.CaseID, req.BatchID+".json")
	if err := checkWithinDir(s.rootDir, finalPath); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(finalPath), 0750); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return nil, fmt.Errorf("commit batch: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(filepath.Dir(finalPath))
	}

	nextIdx := s.index
	nextIdx.Generation = batch.Generation
	nextIdx.TotalBytes += int64(len(batchBytes))
	nextOps := make(map[string]NormalizedBatch, len(s.index.Operations)+1)
	for k, v := range s.index.Operations {
		nextOps[k] = v
	}
	if req.OperationID != "" {
		nextOps[req.OperationID] = batch
	}
	nextBatches := make(map[string]NormalizedBatch, len(s.index.Batches)+1)
	for k, v := range s.index.Batches {
		nextBatches[k] = v
	}
	nextBatches[batchKey] = batch
	nextIdx.Operations = nextOps
	nextIdx.Batches = nextBatches

	if err := s.persistIndexUnlocked(nextIdx); err != nil {
		return nil, err
	}
	s.index = nextIdx

	if blobPath != "" {
		postSHA, postSize, hErr := hashRegularFile(blobPath)
		if hErr != nil || postSHA != preSHA || postSize != preSize {
			return nil, ErrSealedBytesTampered
		}
	}

	out := batch
	return &out, nil
}

// GetBatch retrieves a committed NormalizedBatch by (caseID, batchID).
func (s *TimeStore) GetBatch(caseID, batchID string) (*NormalizedBatch, error) {
	if s == nil {
		return nil, ErrTimeStoreRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrTimeStoreClosed
	}
	if err := validateIdentifier("case_id", caseID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("batch_id", batchID); err != nil {
		return nil, err
	}
	b, ok := s.index.Batches[caseID+"/"+batchID]
	if !ok {
		return nil, fmt.Errorf("%w: %s/%s", ErrBatchNotFound, caseID, batchID)
	}
	copyB := b
	return &copyB, nil
}

func (s *TimeStore) persistIndexUnlocked(idx timeIndex) error {
	raw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := filepath.Join(s.rootDir, stagingSubdir, fmt.Sprintf("time-index-%d.tmp", idx.Generation))
	if err := writeSyncFile(tmp, raw, 0640); err != nil {
		return err
	}
	indexPath := filepath.Join(s.rootDir, indexFileName)
	if err := os.Rename(tmp, indexPath); err != nil {
		return fmt.Errorf("commit time index: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(s.rootDir)
	}
	return nil
}

func hashRegularFile(path string) (string, int64, error) {
	if _, err := ensureNoSymlink(path); err != nil {
		return "", 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%w: %s is not a regular file", ErrInvalidInput, path)
	}
	f, err := os.Open(path) // strictly O_RDONLY
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

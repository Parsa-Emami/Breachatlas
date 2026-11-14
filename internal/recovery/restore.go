package recovery

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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/artifacts"
	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/export"
	"github.com/Parsa-Emami/Breachatlas/internal/holds"
	"github.com/Parsa-Emami/Breachatlas/internal/retention"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

const (
	SchemaVersion           = "1"
	DefaultMaxRestoreBytes  = int64(20 * 1024 * 1024 * 1024) // 20 GiB
	DefaultMaxRetryCount    = 3
	restoreStagingSubdir    = "staging"
	restoreManifestFileName = "restore-manifest.json"
	restoreLockFileName     = ".restore.lock"
)

var (
	ErrRestoreStoreRequired     = errors.New("restore store root directory is required")
	ErrRestoreStoreClosed       = errors.New("restore store closed")
	ErrLockBusy                 = errors.New("restore store lock busy: another writer holds exclusive lock")
	ErrUnsupportedVersion       = errors.New("unsupported restore schema version")
	ErrUnavailableProvider      = errors.New("unavailable restore provider")
	ErrInvalidRequest           = errors.New("invalid restore or consistency request")
	ErrPathTraversal            = errors.New("path traversal or invalid path component rejected")
	ErrSymlinkRejected          = errors.New("symlink rejected in restore path")
	ErrMissingPrerequisite      = errors.New("missing prerequisite store or case artifact for restore")
	ErrBundleVerificationFailed = errors.New("portable export bundle failed offline verification")
	ErrManifestConsistency      = errors.New("manifest and file consistency cross-check failed")
	ErrCustodyRewriteForbidden  = errors.New("custody history rewrite or truncation is forbidden")
	ErrSealedBytesModified      = errors.New("sealed source bytes modified during restore or rebuild")
	ErrRestoreConflict          = errors.New("operation_id reused with conflicting restore parameters")
	ErrRestoreInterrupted       = errors.New("restore interrupted at staged-byte/manifest boundary")
	ErrDiskFull                 = errors.New("disk full: restore aborted")
	ErrQuotaExceeded            = errors.New("restore byte quota exceeded")
	ErrRetryLimitExceeded       = errors.New("restore retry budget exceeded")
)

var (
	identifierRegex  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	digestRegex      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	allowedProviders = map[string]bool{
		"":            true,
		"local":       true,
		"breachatlas": true,
	}
)

// RestoreFaults injects deterministic faults at durability boundaries for crash/restart testing.
type RestoreFaults struct {
	SimulateDiskFull           bool
	FailAfterStageBeforeCommit bool
	FailBeforeManifestCommit   bool
}

// RestoreConfig configures a durable local RestoreStore coordinator.
type RestoreConfig struct {
	RootDir         string
	MaxRestoreBytes int64
	MaxRetryCount   int
	SyncDir         bool
	Faults          RestoreFaults
}

// TargetStores binds the authoritative local stores used during bundle restore or consistency rebuild.
type TargetStores struct {
	SealStore       *evidence.SealStore
	SealRootDir     string
	QuarantineDir   string
	LedgerStore     *custody.LedgerStore
	LedgerRootDir   string
	CheckpointStore *custody.FileCheckpointStore
	ArtifactStore   *artifacts.ArtifactStore
	ArtifactRootDir string
	IndexStore      *timeline.EventIndexStore
	IndexRootDir    string
	HoldService     *holds.Service
	RetentionStore  *retention.RetentionStore
}

// RestoreBundleRequest configures restoration of a verified portable export bundle into target stores.
type RestoreBundleRequest struct {
	SchemaVersion           string                    `json:"schema_version"`
	OperationID             string                    `json:"operation_id"`
	CaseID                  string                    `json:"case_id"`
	BundlePath              string                    `json:"bundle_path"`
	Provider                string                    `json:"provider,omitempty"`
	ZoneHint                string                    `json:"zone_hint,omitempty"`
	SourceConfidence        *float64                  `json:"source_confidence,omitempty"`
	TrustedBundleKeys       map[string]string         `json:"trusted_bundle_keys,omitempty"`
	RequireBundleSignature  bool                      `json:"require_bundle_signature,omitempty"`
	TrustedCheckpointKeys   map[string]string         `json:"trusted_checkpoint_keys,omitempty"`
	RequireCheckpointTrust  bool                      `json:"require_checkpoint_trust,omitempty"`
	CheckpointTracker       *custody.CheckpointTracker `json:"-"`
	StrictCheckpointReplay  bool                      `json:"strict_checkpoint_replay,omitempty"`
	ArtifactVerifyOpts      artifacts.VerifyOptions   `json:"-"`
	Attempt                 int                       `json:"attempt,omitempty"`
	Now                     time.Time                 `json:"-"`
}

// RestoreOutcome summarizes a verified restore operation and immutability guarantees.
type RestoreOutcome struct {
	SchemaVersion          string   `json:"schema_version"`
	OperationID            string   `json:"operation_id"`
	CaseID                 string   `json:"case_id"`
	BundleID               string   `json:"bundle_id"`
	BundleDigest           string   `json:"bundle_digest"`
	Generation             uint64   `json:"generation"`
	RestoredEvidenceCount  int      `json:"restored_evidence_count"`
	ExistingEvidenceCount  int      `json:"existing_evidence_count"`
	RestoredArtifactCount  int      `json:"restored_artifact_count"`
	TimelineRebuilt        bool     `json:"timeline_rebuilt"`
	RebuiltTimelineEntries int      `json:"rebuilt_timeline_entries"`
	TotalRestoredBytes     int64    `json:"total_restored_bytes"`
	EvidenceIDs            []string `json:"evidence_ids"`
	ArtifactIDs            []string `json:"artifact_ids,omitempty"`
	CustodyRewritten       bool     `json:"custody_rewritten"`
	SealedBytesModified    bool     `json:"sealed_bytes_modified"`
	IdempotentReplay       bool     `json:"idempotent_replay,omitempty"`
	CommittedAt            string   `json:"committed_at"`
}

// VerifyAndRebuildRequest configures cross-store consistency verification and derived index rebuild.
type VerifyAndRebuildRequest struct {
	SchemaVersion          string                    `json:"schema_version"`
	OperationID            string                    `json:"operation_id,omitempty"`
	CaseID                 string                    `json:"case_id"`
	Provider               string                    `json:"provider,omitempty"`
	ZoneHint               string                    `json:"zone_hint,omitempty"`
	SourceConfidence       *float64                  `json:"source_confidence,omitempty"`
	TrustedCheckpointKeys  map[string]string         `json:"trusted_checkpoint_keys,omitempty"`
	RequireCheckpoints     bool                      `json:"require_checkpoints,omitempty"`
	CheckpointTracker      *custody.CheckpointTracker `json:"-"`
	ArtifactVerifyOpts     artifacts.VerifyOptions   `json:"-"`
	Attempt                int                       `json:"attempt,omitempty"`
	Now                    time.Time                 `json:"-"`
}

// ConsistencyRebuildOutcome summarizes cross-check validation and derived timeline rebuild results.
type ConsistencyRebuildOutcome struct {
	SchemaVersion          string   `json:"schema_version"`
	OperationID            string   `json:"operation_id,omitempty"`
	CaseID                 string   `json:"case_id"`
	Generation             uint64   `json:"generation"`
	VerifiedEvidenceCount  int      `json:"verified_evidence_count"`
	VerifiedArtifactCount  int      `json:"verified_artifact_count"`
	VerifiedCheckpoints    int      `json:"verified_checkpoints"`
	VerifiedTombstones     int      `json:"verified_tombstones"`
	TimelineRebuilt        bool     `json:"timeline_rebuilt"`
	RebuiltTimelineEntries int      `json:"rebuilt_timeline_entries"`
	CaseIndexSHA256        string   `json:"case_index_sha256,omitempty"`
	EvidenceIDs            []string `json:"evidence_ids"`
	ArtifactIDs            []string `json:"artifact_ids,omitempty"`
	CustodyRewritten       bool     `json:"custody_rewritten"`
	SealedBytesModified    bool     `json:"sealed_bytes_modified"`
	IdempotentReplay       bool     `json:"idempotent_replay,omitempty"`
	VerifiedAt             string   `json:"verified_at"`
}

// RecoveryReport summarizes staging cleanup and persisted operations recovered on OpenRestoreStore.
type RecoveryReport struct {
	CleanedStagingFiles []string `json:"cleaned_staging_files"`
	RecoveredOperations int      `json:"recovered_operations"`
}

type persistedRestoreOp struct {
	Kind               string                     `json:"kind"`
	RequestFingerprint string                     `json:"request_fingerprint"`
	RestoreOutcome     *RestoreOutcome            `json:"restore_outcome,omitempty"`
	RebuildOutcome     *ConsistencyRebuildOutcome `json:"rebuild_outcome,omitempty"`
}

type restoreManifestState struct {
	SchemaVersion string                        `json:"schema_version"`
	Generation    uint64                        `json:"generation"`
	Operations    map[string]persistedRestoreOp `json:"operations"`
}

// RestoreStore coordinates crash-safe cross-store verification, portable bundle restoration,
// and deterministic derived timeline index rebuilding without custody rewrite or sealed-byte mutation.
type RestoreStore struct {
	mu             sync.Mutex
	cfg            RestoreConfig
	rootDir        string
	maxRestore     int64
	maxRetryCount  int
	lockFile       *os.File
	closed         bool
	manifest       restoreManifestState
	recoveryReport RecoveryReport
}

// OpenRestoreStore opens or initializes a locked, crash-recoverable RestoreStore.
func OpenRestoreStore(cfg RestoreConfig) (*RestoreStore, error) {
	rootDir, err := resolveSafeDir(cfg.RootDir, ErrRestoreStoreRequired)
	if err != nil {
		return nil, err
	}

	maxBytes := cfg.MaxRestoreBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxRestoreBytes
	}
	if maxBytes < 0 {
		return nil, fmt.Errorf("%w: max_restore_bytes must be non-negative", ErrInvalidRequest)
	}

	maxRetries := cfg.MaxRetryCount
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetryCount
	}

	stagingDir := filepath.Join(rootDir, restoreStagingSubdir)
	if _, err := ensureNoSymlink(stagingDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stagingDir, 0o750); err != nil {
		return nil, fmt.Errorf("create restore staging dir: %w", err)
	}

	lockPath := filepath.Join(rootDir, restoreLockFileName)
	if _, err := ensureNoSymlink(lockPath); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open restore lock: %w", err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lf.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLockBusy
		}
		return nil, fmt.Errorf("acquire restore lock: %w", err)
	}

	s := &RestoreStore{
		cfg:           cfg,
		rootDir:       rootDir,
		maxRestore:    maxBytes,
		maxRetryCount: maxRetries,
		lockFile:      lf,
		manifest: restoreManifestState{
			SchemaVersion: SchemaVersion,
			Operations:    make(map[string]persistedRestoreOp),
		},
	}

	if err := s.recoverOnOpenUnlocked(); err != nil {
		_ = s.closeUnlocked()
		return nil, err
	}
	return s, nil
}

func (s *RestoreStore) recoverOnOpenUnlocked() error {
	cleaned, err := s.cleanStagingUnlocked()
	if err != nil {
		return err
	}
	s.recoveryReport.CleanedStagingFiles = cleaned

	manifestPath := filepath.Join(s.rootDir, restoreManifestFileName)
	if _, err := ensureNoSymlink(manifestPath); err != nil {
		return err
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read restore manifest: %w", err)
	}
	var loaded restoreManifestState
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return fmt.Errorf("%w: corrupt restore manifest: %v", ErrManifestConsistency, err)
	}
	if loaded.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported restore manifest version %q", ErrUnsupportedVersion, loaded.SchemaVersion)
	}
	if loaded.Operations == nil {
		loaded.Operations = make(map[string]persistedRestoreOp)
	}
	s.manifest = loaded
	s.recoveryReport.RecoveredOperations = len(loaded.Operations)
	return nil
}

func (s *RestoreStore) cleanStagingUnlocked() ([]string, error) {
	stagingDir := filepath.Join(s.rootDir, restoreStagingSubdir)
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return nil, err
	}
	var cleaned []string
	for _, entry := range entries {
		full := filepath.Join(stagingDir, entry.Name())
		if err := checkWithinDir(stagingDir, full); err != nil {
			return nil, err
		}
		if err := os.RemoveAll(full); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("clean restore staging %s: %w", entry.Name(), err)
		}
		cleaned = append(cleaned, entry.Name())
	}
	sort.Strings(cleaned)
	return cleaned, nil
}

// LastRecoveryReport returns staging cleanup and recovered operation counts from OpenRestoreStore.
func (s *RestoreStore) LastRecoveryReport() RecoveryReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return RecoveryReport{
		RecoveredOperations: s.recoveryReport.RecoveredOperations,
		CleanedStagingFiles: append([]string(nil), s.recoveryReport.CleanedStagingFiles...),
	}
}

// Close releases the exclusive flock held by RestoreStore.
func (s *RestoreStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeUnlocked()
}

func (s *RestoreStore) closeUnlocked() error {
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

type fileSnapshot struct {
	path string
	sha  string
	size int64
}

type stagedEvidenceRestore struct {
	entry           export.BoundEvidenceEntry
	blobAbsPath     string
	events          []custody.CustodyEvent
	alreadySealed   bool
	custodyOnDisk   bool
	quarantineBytes int64
}

type stagedArtifactRestore struct {
	entry        export.BoundArtifactEntry
	payloadBytes []byte
}

// RestoreFromBundle verifies a portable export bundle offline, cross-checks all sealed blobs,
// manifests, custody chains, checkpoints, and derived artifacts against target stores without
// modifying sealed source bytes or rewriting existing custody ledgers, stages atomically, and
// deterministically rebuilds the case timeline index.
func (s *RestoreStore) RestoreFromBundle(ctx context.Context, stores TargetStores, req RestoreBundleRequest) (*RestoreOutcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrRestoreStoreRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrRestoreStoreClosed
	}

	if req.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %q", ErrUnsupportedVersion, req.SchemaVersion)
	}
	if err := validateIdentifier("operation_id", req.OperationID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("case_id", req.CaseID); err != nil {
		return nil, err
	}
	if !allowedProviders[req.Provider] {
		return nil, fmt.Errorf("%w: provider %q unsupported in local-first profile", ErrUnavailableProvider, req.Provider)
	}
	if req.Attempt < 0 {
		return nil, fmt.Errorf("%w: attempt cannot be negative", ErrInvalidRequest)
	}
	if req.Attempt > s.maxRetryCount {
		return nil, fmt.Errorf("%w: attempt %d > max %d", ErrRetryLimitExceeded, req.Attempt, s.maxRetryCount)
	}
	if req.SourceConfidence != nil && (*req.SourceConfidence < 0 || *req.SourceConfidence > 1) {
		return nil, fmt.Errorf("%w: source_confidence must be within [0, 1]", ErrInvalidRequest)
	}
	if strings.ContainsRune(req.ZoneHint, '\x00') || strings.Contains(req.ZoneHint, "..") || strings.HasPrefix(req.ZoneHint, "/") || strings.ContainsRune(req.ZoneHint, '\\') {
		return nil, fmt.Errorf("%w: unsafe zone_hint %q", ErrPathTraversal, req.ZoneHint)
	}
	if err := validateSafeInputPath(req.BundlePath); err != nil {
		return nil, err
	}

	resolvedStores, err := resolveAndCheckStores(stores, false)
	if err != nil {
		return nil, err
	}

	absBundlePath, err := filepath.Abs(filepath.Clean(req.BundlePath))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	bundleInfo, err := os.Lstat(absBundlePath)
	if err != nil {
		return nil, fmt.Errorf("%w: bundle path %s: %v", ErrBundleVerificationFailed, absBundlePath, err)
	}
	if bundleInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlinkRejected, absBundlePath)
	}
	bundleDir := absBundlePath
	manifestPath := filepath.Join(bundleDir, export.BundleManifestFile)
	if !bundleInfo.IsDir() {
		bundleDir = filepath.Dir(absBundlePath)
		manifestPath = absBundlePath
	}

	// Verify portable bundle offline before loading/restoring anything.
	verifyRes, vErr := export.VerifyBundle(ctx, absBundlePath, export.VerifyBundleOptions{
		TrustedPublicKeys: req.TrustedBundleKeys,
		RequireSignature:  req.RequireBundleSignature,
		ExpectedCaseID:    req.CaseID,
	})
	if vErr != nil || verifyRes == nil || !verifyRes.Verified {
		errMsg := ""
		if vErr != nil {
			errMsg = vErr.Error()
		} else if verifyRes != nil && len(verifyRes.Errors) > 0 {
			errMsg = strings.Join(verifyRes.Errors, "; ")
		}
		return nil, fmt.Errorf("%w: %s", ErrBundleVerificationFailed, errMsg)
	}

	if _, err := ensureNoSymlink(manifestPath); err != nil {
		return nil, err
	}
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read bundle manifest: %v", ErrBundleVerificationFailed, err)
	}
	var bm export.BundleManifest
	if err := json.Unmarshal(manifestRaw, &bm); err != nil {
		return nil, fmt.Errorf("%w: parse bundle manifest: %v", ErrBundleVerificationFailed, err)
	}
	if bm.CaseID != req.CaseID {
		return nil, fmt.Errorf("%w: bundle case_id %q != request %q", ErrManifestConsistency, bm.CaseID, req.CaseID)
	}
	if len(bm.EvidenceItems) == 0 {
		return nil, fmt.Errorf("%w: bundle contains zero evidence items", ErrBundleVerificationFailed)
	}

	fp := fingerprintRestoreBundle(req, bundleDir, bm.BundleDigest)
	if prev, ok := s.manifest.Operations[req.OperationID]; ok {
		if prev.Kind != "restore_bundle" || prev.RequestFingerprint != fp || prev.RestoreOutcome == nil {
			return nil, fmt.Errorf("%w: operation_id %q reused with conflicting parameters", ErrRestoreConflict, req.OperationID)
		}
		replay := *prev.RestoreOutcome
		replay.EvidenceIDs = append([]string(nil), prev.RestoreOutcome.EvidenceIDs...)
		replay.ArtifactIDs = append([]string(nil), prev.RestoreOutcome.ArtifactIDs...)
		replay.IdempotentReplay = true
		return &replay, nil
	}

	// Snapshot all pre-existing sealed blobs and custody chains for immutability guarantees.
	preBlobSnaps, err := snapshotCaseSealedBlobs(resolvedStores.SealStore, resolvedStores.SealRootDir, req.CaseID)
	if err != nil {
		return nil, err
	}
	preCustodySnaps, err := snapshotCaseCustodyFiles(resolvedStores.LedgerRootDir, req.CaseID)
	if err != nil {
		return nil, err
	}

	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Cross-check every bundle evidence item, manifest, custody chain, checkpoint, and target store consistency.
	stagedEvidence := make([]stagedEvidenceRestore, 0, len(bm.EvidenceItems))
	bundleEvidenceByID := make(map[string]export.BoundEvidenceEntry, len(bm.EvidenceItems))
	var totalRestoreBytes int64
	existingEvidenceCount := 0
	restoredEvidenceCount := 0

	for _, ev := range bm.EvidenceItems {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := validateIdentifier("evidence_id", ev.EvidenceID); err != nil {
			return nil, err
		}
		if _, dup := bundleEvidenceByID[ev.EvidenceID]; dup {
			return nil, fmt.Errorf("%w: duplicate evidence_id %s in bundle", ErrManifestConsistency, ev.EvidenceID)
		}
		if ev.Manifest.CaseID != req.CaseID || ev.Manifest.EvidenceID != ev.EvidenceID {
			return nil, fmt.Errorf("%w: evidence entry %s manifest case/id mismatch", ErrManifestConsistency, ev.EvidenceID)
		}
		if strings.TrimSpace(ev.Manifest.MediaType) == "" || len(ev.Manifest.MediaType) > 127 {
			return nil, fmt.Errorf("%w: evidence %s invalid media_type %q", ErrManifestConsistency, ev.EvidenceID, ev.Manifest.MediaType)
		}
		if _, tErr := time.Parse(time.RFC3339Nano, ev.Manifest.AcquiredAt); tErr != nil {
			return nil, fmt.Errorf("%w: evidence %s invalid acquired_at %q", ErrManifestConsistency, ev.EvidenceID, ev.Manifest.AcquiredAt)
		}

		// Cross-check bundle blob vs manifest file vs entry metadata.
		blobPath := filepath.Join(bundleDir, filepath.FromSlash(ev.BundleBlobRelPath))
		if err := checkWithinDir(bundleDir, blobPath); err != nil {
			return nil, err
		}
		blobSHA, blobSz, err := hashRegularFile(blobPath)
		if err != nil {
			return nil, fmt.Errorf("%w: read bundle blob for %s: %v", ErrManifestConsistency, ev.EvidenceID, err)
		}
		if blobSHA != ev.BlobSHA256 || blobSHA != ev.Manifest.SHA256 || blobSz != ev.BlobSizeBytes || blobSz != ev.Manifest.SizeBytes {
			return nil, fmt.Errorf("%w: blob digest/size mismatch for %s", ErrManifestConsistency, ev.EvidenceID)
		}

		evManifestPath := filepath.Join(bundleDir, filepath.FromSlash(ev.ManifestRelPath))
		if err := checkWithinDir(bundleDir, evManifestPath); err != nil {
			return nil, err
		}
		if _, err := ensureNoSymlink(evManifestPath); err != nil {
			return nil, err
		}
		evManifestRaw, err := os.ReadFile(evManifestPath)
		if err != nil {
			return nil, fmt.Errorf("%w: read bundle manifest file for %s: %v", ErrManifestConsistency, ev.EvidenceID, err)
		}
		var diskManifest evidence.SealedManifest
		if err := json.Unmarshal(evManifestRaw, &diskManifest); err != nil {
			return nil, fmt.Errorf("%w: parse bundle manifest file for %s: %v", ErrManifestConsistency, ev.EvidenceID, err)
		}
		if diskManifest.ManifestDigest != ev.Manifest.ManifestDigest ||
			diskManifest.SHA256 != ev.Manifest.SHA256 ||
			diskManifest.SizeBytes != ev.Manifest.SizeBytes ||
			diskManifest.CustodyRoot != ev.Manifest.CustodyRoot ||
			diskManifest.CaseID != ev.Manifest.CaseID ||
			diskManifest.EvidenceID != ev.Manifest.EvidenceID ||
			!diskManifest.Sealed {
			return nil, fmt.Errorf("%w: bundle sealed manifest diverges from bound entry for %s", ErrManifestConsistency, ev.EvidenceID)
		}

		// Cross-check custody events chain in bundle.
		custodyPath := filepath.Join(bundleDir, filepath.FromSlash(ev.CustodyEventsRelPath))
		if err := checkWithinDir(bundleDir, custodyPath); err != nil {
			return nil, err
		}
		if _, err := ensureNoSymlink(custodyPath); err != nil {
			return nil, err
		}
		events, err := loadCustodyEventsFile(custodyPath)
		if err != nil {
			return nil, fmt.Errorf("%w: read bundle custody events for %s: %v", ErrManifestConsistency, ev.EvidenceID, err)
		}
		if len(events) == 0 || len(events) != ev.CustodyEventCount {
			return nil, fmt.Errorf("%w: custody event count mismatch for %s", ErrManifestConsistency, ev.EvidenceID)
		}
		chainRoot, err := verifyCustodyEventsSlice(req.CaseID, ev.EvidenceID, events)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid custody chain for %s: %v", ErrManifestConsistency, ev.EvidenceID, err)
		}
		if chainRoot != ev.CustodyRoot || (ev.Manifest.CustodyRoot != custody.GenesisPrevHash && !custodyEventsContainRoot(events, ev.Manifest.CustodyRoot)) {
			return nil, fmt.Errorf("%w: custody root mismatch for %s (chain=%s entry=%s manifest=%s)",
				ErrManifestConsistency, ev.EvidenceID, chainRoot, ev.CustodyRoot, ev.Manifest.CustodyRoot)
		}

		// Cross-check checkpoint file vs entry and custody events.
		chkPath := filepath.Join(bundleDir, filepath.FromSlash(ev.CheckpointRelPath))
		if err := checkWithinDir(bundleDir, chkPath); err != nil {
			return nil, err
		}
		if _, err := ensureNoSymlink(chkPath); err != nil {
			return nil, err
		}
		chkRaw, err := os.ReadFile(chkPath)
		if err != nil {
			return nil, fmt.Errorf("%w: read bundle checkpoint for %s: %v", ErrManifestConsistency, ev.EvidenceID, err)
		}
		var diskChk custody.Checkpoint
		if err := json.Unmarshal(chkRaw, &diskChk); err != nil {
			return nil, fmt.Errorf("%w: parse bundle checkpoint for %s: %v", ErrManifestConsistency, ev.EvidenceID, err)
		}
		if diskChk.CheckpointID != ev.Checkpoint.CheckpointID ||
			diskChk.CustodyRoot != ev.Checkpoint.CustodyRoot ||
			diskChk.Sequence != ev.Checkpoint.Sequence ||
			diskChk.Signature != ev.Checkpoint.Signature {
			return nil, fmt.Errorf("%w: checkpoint file diverges from bound entry for %s", ErrManifestConsistency, ev.EvidenceID)
		}
		if ev.Checkpoint.CaseID != req.CaseID || ev.Checkpoint.EvidenceID != ev.EvidenceID {
			return nil, fmt.Errorf("%w: checkpoint case/evidence mismatch for %s", ErrManifestConsistency, ev.EvidenceID)
		}
		if ev.Checkpoint.Sequence == 0 || ev.Checkpoint.Sequence > uint64(len(events)) {
			return nil, fmt.Errorf("%w: checkpoint sequence %d out of range for %s", ErrManifestConsistency, ev.Checkpoint.Sequence, ev.EvidenceID)
		}
		if events[ev.Checkpoint.Sequence-1].CustodyRoot != ev.Checkpoint.CustodyRoot {
			return nil, fmt.Errorf("%w: checkpoint custody_root does not match event sequence %d for %s", ErrManifestConsistency, ev.Checkpoint.Sequence, ev.EvidenceID)
		}
		if err := validateCheckpointStructurePreCommit(ev.Checkpoint); err != nil {
			return nil, fmt.Errorf("%w: checkpoint structure invalid for %s: %v", ErrManifestConsistency, ev.EvidenceID, err)
		}
		if req.RequireCheckpointTrust || len(req.TrustedCheckpointKeys) > 0 {
			if err := verifyCheckpointPreCommit(ev.Checkpoint, req.TrustedCheckpointKeys, req.CheckpointTracker, req.StrictCheckpointReplay, now); err != nil {
				return nil, fmt.Errorf("%w: checkpoint trust/signature check failed for %s: %v", ErrManifestConsistency, ev.EvidenceID, err)
			}
		}

		// Cross-check against existing SealStore state (never overwrite sealed bytes!).
		alreadySealed := false
		if existingSM, getErr := resolvedStores.SealStore.GetSealedManifest(req.CaseID, ev.EvidenceID); getErr == nil && existingSM != nil {
			vr, verErr := evidence.VerifyStoreEvidence(ctx, resolvedStores.SealStore, req.CaseID, ev.EvidenceID, evidence.VerifyOptions{})
			if verErr != nil || vr == nil || !vr.Verified {
				return nil, fmt.Errorf("%w: existing sealed evidence %s/%s failed verification: %v", ErrManifestConsistency, req.CaseID, ev.EvidenceID, verErr)
			}
			if existingSM.SHA256 != ev.Manifest.SHA256 ||
				existingSM.SizeBytes != ev.Manifest.SizeBytes ||
				existingSM.MediaType != ev.Manifest.MediaType ||
				existingSM.CustodyRoot != ev.Manifest.CustodyRoot {
				return nil, fmt.Errorf("%w: existing sealed manifest %s/%s conflicts with restore bundle", ErrManifestConsistency, req.CaseID, ev.EvidenceID)
			}
			alreadySealed = true
			existingEvidenceCount++
		} else if !os.IsNotExist(getErr) {
			return nil, fmt.Errorf("%w: inspect existing sealed manifest %s/%s: %v", ErrManifestConsistency, req.CaseID, ev.EvidenceID, getErr)
		} else {
			restoredEvidenceCount++
			totalRestoreBytes += blobSz
		}

		// Cross-check against existing LedgerStore state (never rewrite or truncate existing custody!).
		custodyOnDisk := false
		existingEvents, lErr := resolvedStores.LedgerStore.ListEvents(req.CaseID, ev.EvidenceID)
		if lErr != nil {
			return nil, fmt.Errorf("%w: inspect custody ledger %s/%s: %v", ErrCustodyRewriteForbidden, req.CaseID, ev.EvidenceID, lErr)
		}
		if len(existingEvents) > 0 {
			if !custodyEventsEqual(existingEvents, events) {
				return nil, fmt.Errorf("%w: restore bundle custody chain for %s/%s conflicts with existing immutable ledger", ErrCustodyRewriteForbidden, req.CaseID, ev.EvidenceID)
			}
			custodyOnDisk = true
		} else if _, statErr := os.Lstat(filepath.Join(resolvedStores.LedgerRootDir, req.CaseID, ev.EvidenceID+".jsonl")); statErr == nil {
			return nil, fmt.Errorf("%w: custody file exists on disk for %s/%s without matching loaded chain", ErrCustodyRewriteForbidden, req.CaseID, ev.EvidenceID)
		}

		bundleEvidenceByID[ev.EvidenceID] = ev
		stagedEvidence = append(stagedEvidence, stagedEvidenceRestore{
			entry:           ev,
			blobAbsPath:     blobPath,
			events:          events,
			alreadySealed:   alreadySealed,
			custodyOnDisk:   custodyOnDisk,
			quarantineBytes: blobSz,
		})
	}

	// Cross-check derived artifacts in bundle.
	stagedArtifacts := make([]stagedArtifactRestore, 0, len(bm.DerivedArtifacts))
	seenArtifacts := make(map[string]bool, len(bm.DerivedArtifacts))
	for _, art := range bm.DerivedArtifacts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := validateIdentifier("artifact_id", art.ArtifactID); err != nil {
			return nil, err
		}
		if seenArtifacts[art.ArtifactID] {
			return nil, fmt.Errorf("%w: duplicate artifact_id %s in bundle", ErrManifestConsistency, art.ArtifactID)
		}
		seenArtifacts[art.ArtifactID] = true
		if art.Manifest.CaseID != req.CaseID || art.Manifest.ArtifactID != art.ArtifactID {
			return nil, fmt.Errorf("%w: derived artifact %s case/id mismatch", ErrManifestConsistency, art.ArtifactID)
		}
		expectedRelPath := filepath.ToSlash(filepath.Join("artifacts", req.CaseID, art.ArtifactID, "output.json"))
		if filepath.ToSlash(filepath.Clean(filepath.FromSlash(art.Manifest.Output.RelPath))) != expectedRelPath {
			return nil, fmt.Errorf("%w: derived artifact %s invalid output.rel_path %q", ErrPathTraversal, art.ArtifactID, art.Manifest.Output.RelPath)
		}
		if _, err := artifacts.VerifyDerivedManifest(ctx, nil, &art.Manifest, req.ArtifactVerifyOpts); err != nil {
			return nil, fmt.Errorf("%w: derived manifest %s verification failed: %v", ErrManifestConsistency, art.ArtifactID, err)
		}
		for _, inp := range art.Manifest.Inputs {
			boundEv, ok := bundleEvidenceByID[inp.EvidenceID]
			if !ok || boundEv.Manifest.SHA256 != inp.SHA256 || boundEv.Manifest.SizeBytes != inp.SizeBytes {
				return nil, fmt.Errorf("%w: derived artifact %s input %s mismatch with bundle evidence", ErrManifestConsistency, art.ArtifactID, inp.EvidenceID)
			}
		}

		artManPath := filepath.Join(bundleDir, filepath.FromSlash(art.ManifestRelPath))
		if err := checkWithinDir(bundleDir, artManPath); err != nil {
			return nil, err
		}
		if _, err := ensureNoSymlink(artManPath); err != nil {
			return nil, err
		}
		artManRaw, err := os.ReadFile(artManPath)
		if err != nil {
			return nil, fmt.Errorf("%w: read derived artifact manifest %s: %v", ErrManifestConsistency, art.ArtifactID, err)
		}
		var diskDM artifacts.DerivedManifest
		if err := json.Unmarshal(artManRaw, &diskDM); err != nil {
			return nil, fmt.Errorf("%w: parse derived artifact manifest %s: %v", ErrManifestConsistency, art.ArtifactID, err)
		}
		if diskDM.ManifestDigest != art.Manifest.ManifestDigest || diskDM.Output.SHA256 != art.Manifest.Output.SHA256 {
			return nil, fmt.Errorf("%w: derived artifact %s manifest digest diverges", ErrManifestConsistency, art.ArtifactID)
		}

		payloadPath := filepath.Join(bundleDir, filepath.FromSlash(art.PayloadRelPath))
		if err := checkWithinDir(bundleDir, payloadPath); err != nil {
			return nil, err
		}
		pSHA, pSz, err := hashRegularFile(payloadPath)
		if err != nil {
			return nil, fmt.Errorf("%w: read derived artifact payload %s: %v", ErrManifestConsistency, art.ArtifactID, err)
		}
		if pSHA != art.PayloadSHA256 || pSHA != art.Manifest.Output.SHA256 || pSz != art.PayloadSizeBytes || pSz != art.Manifest.Output.SizeBytes {
			return nil, fmt.Errorf("%w: derived artifact %s payload digest/size mismatch", ErrManifestConsistency, art.ArtifactID)
		}
		payloadBytes, err := os.ReadFile(payloadPath)
		if err != nil {
			return nil, err
		}
		var parsedPayload artifacts.DerivedPayload
		if err := json.Unmarshal(payloadBytes, &parsedPayload); err != nil {
			return nil, fmt.Errorf("%w: parse derived payload %s: %v", ErrManifestConsistency, art.ArtifactID, err)
		}
		if parsedPayload.CaseID != req.CaseID || parsedPayload.ArtifactID != art.ArtifactID || len(parsedPayload.Records) == 0 {
			return nil, fmt.Errorf("%w: derived payload %s invalid case/id or empty records", ErrManifestConsistency, art.ArtifactID)
		}

		if existingDM, getErr := resolvedStores.ArtifactStore.GetManifest(req.CaseID, art.ArtifactID); getErr == nil && existingDM != nil {
			if existingDM.ManifestDigest != art.Manifest.ManifestDigest || existingDM.Output.SHA256 != art.Manifest.Output.SHA256 {
				return nil, fmt.Errorf("%w: existing derived artifact %s/%s conflicts with restore bundle", ErrManifestConsistency, req.CaseID, art.ArtifactID)
			}
			vr, verErr := resolvedStores.ArtifactStore.VerifyStoredArtifact(ctx, resolvedStores.SealStore, req.CaseID, art.ArtifactID, req.ArtifactVerifyOpts)
			if verErr != nil || vr == nil || !vr.Verified {
				return nil, fmt.Errorf("%w: existing derived artifact %s/%s failed verification: %v", ErrManifestConsistency, req.CaseID, art.ArtifactID, verErr)
			}
		} else if !errors.Is(getErr, artifacts.ErrArtifactNotFound) {
			return nil, fmt.Errorf("%w: inspect existing derived artifact %s/%s: %v", ErrManifestConsistency, req.CaseID, art.ArtifactID, getErr)
		} else {
			totalRestoreBytes += pSz
		}

		stagedArtifacts = append(stagedArtifacts, stagedArtifactRestore{
			entry:        art,
			payloadBytes: payloadBytes,
		})
	}

	if len(stagedArtifacts) > 0 {
		if err := verifyBundleTimelinePreCommit(bundleDir, bm.TimelineRelPath, req, stagedArtifacts); err != nil {
			return nil, err
		}
	}

	// Enforce byte quota and simulated disk-full before staging or committing anything.
	if totalRestoreBytes > s.maxRestore {
		return nil, fmt.Errorf("%w: restore requires %d bytes > max %d", ErrQuotaExceeded, totalRestoreBytes, s.maxRestore)
	}
	if s.cfg.Faults.SimulateDiskFull {
		return nil, ErrDiskFull
	}

	// Phase 1: Stage restore artifacts in RestoreStore/staging/<opID>/ so boundary interrupts leave target stores pristine.
	opStageDir := filepath.Join(s.rootDir, restoreStagingSubdir, req.OperationID)
	if err := checkWithinDir(filepath.Join(s.rootDir, restoreStagingSubdir), opStageDir); err != nil {
		return nil, err
	}
	_ = os.RemoveAll(opStageDir)
	if err := os.MkdirAll(opStageDir, 0o750); err != nil {
		return nil, fmt.Errorf("create restore operation staging dir: %w", err)
	}
	for _, se := range stagedEvidence {
		if !se.custodyOnDisk {
			stageCustPath := filepath.Join(opStageDir, se.entry.EvidenceID+".custody.jsonl.tmp")
			if err := writeCustodyJSONL(stageCustPath, se.events); err != nil {
				return nil, err
			}
		}
	}

	if s.cfg.Faults.FailAfterStageBeforeCommit {
		return nil, ErrRestoreInterrupted
	}

	// Build tentative outcome and stage restore-manifest.json.tmp before authoritative commit.
	evidenceIDs := make([]string, 0, len(stagedEvidence))
	for _, se := range stagedEvidence {
		evidenceIDs = append(evidenceIDs, se.entry.EvidenceID)
	}
	sort.Strings(evidenceIDs)

	artifactIDs := make([]string, 0, len(stagedArtifacts))
	for _, sa := range stagedArtifacts {
		artifactIDs = append(artifactIDs, sa.entry.ArtifactID)
	}
	sort.Strings(artifactIDs)

	nextGen := s.manifest.Generation + 1
	outcome := RestoreOutcome{
		SchemaVersion:         SchemaVersion,
		OperationID:           req.OperationID,
		CaseID:                req.CaseID,
		BundleID:              bm.BundleID,
		BundleDigest:          bm.BundleDigest,
		Generation:            nextGen,
		RestoredEvidenceCount: restoredEvidenceCount,
		ExistingEvidenceCount: existingEvidenceCount,
		RestoredArtifactCount: len(stagedArtifacts),
		TotalRestoredBytes:    totalRestoreBytes,
		EvidenceIDs:           evidenceIDs,
		ArtifactIDs:           artifactIDs,
		CustodyRewritten:      false,
		SealedBytesModified:   false,
		CommittedAt:           now.UTC().Format(time.RFC3339Nano),
	}

	// Pre-stage manifest JSON before target store writes to exercise the manifest-commit fault boundary cleanly.
	stageManifestTmp := filepath.Join(opStageDir, fmt.Sprintf("restore-manifest.%d.tmp", nextGen))
	if err := writeJSONTempFile(stageManifestTmp, s.manifest); err != nil {
		return nil, err
	}

	if s.cfg.Faults.FailBeforeManifestCommit {
		return nil, ErrRestoreInterrupted
	}

	// Phase 2: Commit authoritative target stores in prerequisite order:
	// 1) Custody ledger (only if absent)
	// 2) Quarantine -> SealStore (only if absent)
	// 3) Checkpoints (if CheckpointStore configured)
	// 4) Derived Artifacts
	// 5) Derived Timeline Index Rebuild
	for _, se := range stagedEvidence {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := resolvedStores.LedgerStore.RestoreVerifiedChain(ctx, req.CaseID, se.entry.EvidenceID, se.events); err != nil {
			if errors.Is(err, custody.ErrImmutableHistory) {
				return nil, fmt.Errorf("%w: %v", ErrCustodyRewriteForbidden, err)
			}
			return nil, err
		}
		if req.RequireCheckpointTrust || len(req.TrustedCheckpointKeys) > 0 {
			chkOpts := custody.VerifyCheckpointOptions{
				TrustedPublicKeys: req.TrustedCheckpointKeys,
				Tracker:           req.CheckpointTracker,
				Now:               now,
				StrictReplay:      req.StrictCheckpointReplay,
			}
			if _, chkErr := custody.VerifyCheckpoint(ctx, resolvedStores.LedgerStore, se.entry.Checkpoint, chkOpts); chkErr != nil {
				return nil, fmt.Errorf("%w: checkpoint verification failed for %s: %v", ErrManifestConsistency, se.entry.EvidenceID, chkErr)
			}
		}

		if !se.alreadySealed {
			if err := sealFromBundleEntry(ctx, resolvedStores, req.OperationID, req.CaseID, se); err != nil {
				return nil, err
			}
		}

		if resolvedStores.CheckpointStore != nil {
			if err := resolvedStores.CheckpointStore.SaveCheckpoint(ctx, se.entry.Checkpoint); err != nil {
				return nil, fmt.Errorf("%w: save restored checkpoint for %s: %v", ErrManifestConsistency, se.entry.EvidenceID, err)
			}
		}
	}

	for _, sa := range stagedArtifacts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := resolvedStores.ArtifactStore.RestoreVerifiedArtifact(ctx, resolvedStores.SealStore, sa.entry.Manifest, sa.payloadBytes, req.ArtifactVerifyOpts); err != nil {
			return nil, fmt.Errorf("%w: restore derived artifact %s: %v", ErrManifestConsistency, sa.entry.ArtifactID, err)
		}
	}

	if len(artifactIDs) > 0 {
		idxStore, closeIdx, err := openOrUseIndexStore(resolvedStores, req.CaseID)
		if err != nil {
			return nil, err
		}
		if closeIdx != nil {
			defer closeIdx()
		}
		rebuildOut, err := idxStore.RebuildCaseIndex(
			ctx,
			resolvedStores.SealStore,
			resolvedStores.SealRootDir,
			resolvedStores.ArtifactStore,
			resolvedStores.ArtifactRootDir,
			timeline.RebuildRequest{
				SchemaVersion:    timeline.SchemaVersion,
				CaseID:           req.CaseID,
				ArtifactIDs:      artifactIDs,
				Provider:         req.Provider,
				ZoneHint:         req.ZoneHint,
				SourceConfidence: req.SourceConfidence,
				VerifyOptions:    req.ArtifactVerifyOpts,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("rebuild derived timeline after bundle restore: %w", err)
		}
		outcome.TimelineRebuilt = true
		outcome.RebuiltTimelineEntries = rebuildOut.RebuiltEntries

		if bm.TimelineRelPath != "" {
			if err := verifyRebuiltTimelineMatchesBundle(bundleDir, bm.TimelineRelPath, idxStore, req.CaseID); err != nil {
				return nil, err
			}
		}
	}

	// Post-commit immutability audit: pre-existing sealed blobs and custody chains MUST be bit-identical.
	if err := verifySnapshotsUnchanged(preBlobSnaps, ErrSealedBytesModified); err != nil {
		return nil, err
	}
	if err := verifySnapshotsUnchanged(preCustodySnaps, ErrCustodyRewriteForbidden); err != nil {
		return nil, err
	}
	postBlobSnaps, err := snapshotCaseSealedBlobs(resolvedStores.SealStore, resolvedStores.SealRootDir, req.CaseID)
	if err != nil {
		return nil, err
	}
	if err := verifySnapshotsUnchanged(postBlobSnaps, ErrSealedBytesModified); err != nil {
		return nil, err
	}

	// Commit authoritative restore-manifest.json atomically.
	nextState := cloneRestoreState(s.manifest)
	nextState.Generation = nextGen
	outCopy := outcome
	outCopy.EvidenceIDs = append([]string(nil), outcome.EvidenceIDs...)
	outCopy.ArtifactIDs = append([]string(nil), outcome.ArtifactIDs...)
	nextState.Operations[req.OperationID] = persistedRestoreOp{
		Kind:               "restore_bundle",
		RequestFingerprint: fp,
		RestoreOutcome:     &outCopy,
	}
	if err := s.persistManifestUnlocked(nextState); err != nil {
		return nil, err
	}
	s.manifest = nextState
	_ = os.RemoveAll(opStageDir)

	ret := outcome
	ret.EvidenceIDs = append([]string(nil), outcome.EvidenceIDs...)
	ret.ArtifactIDs = append([]string(nil), outcome.ArtifactIDs...)
	return &ret, nil
}

// VerifyAndRebuildCase cross-checks manifest/file consistency across sealed blobs, manifests,
// append-only custody chains, optional signed checkpoints, derived artifacts, and optional
// retention tombstones, and atomically rebuilds the derived timeline index without custody rewrite.
func (s *RestoreStore) VerifyAndRebuildCase(ctx context.Context, stores TargetStores, req VerifyAndRebuildRequest) (*ConsistencyRebuildOutcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrRestoreStoreRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrRestoreStoreClosed
	}

	if req.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %q", ErrUnsupportedVersion, req.SchemaVersion)
	}
	if req.OperationID != "" {
		if err := validateIdentifier("operation_id", req.OperationID); err != nil {
			return nil, err
		}
	}
	if err := validateIdentifier("case_id", req.CaseID); err != nil {
		return nil, err
	}
	if !allowedProviders[req.Provider] {
		return nil, fmt.Errorf("%w: provider %q unsupported in local-first profile", ErrUnavailableProvider, req.Provider)
	}
	if req.Attempt < 0 {
		return nil, fmt.Errorf("%w: attempt cannot be negative", ErrInvalidRequest)
	}
	if req.Attempt > s.maxRetryCount {
		return nil, fmt.Errorf("%w: attempt %d > max %d", ErrRetryLimitExceeded, req.Attempt, s.maxRetryCount)
	}
	if req.SourceConfidence != nil && (*req.SourceConfidence < 0 || *req.SourceConfidence > 1) {
		return nil, fmt.Errorf("%w: source_confidence must be within [0, 1]", ErrInvalidRequest)
	}

	resolvedStores, err := resolveAndCheckStores(stores, false)
	if err != nil {
		return nil, err
	}

	fp := fingerprintRebuildCase(req)
	if req.OperationID != "" {
		if prev, ok := s.manifest.Operations[req.OperationID]; ok {
			if prev.Kind != "verify_rebuild" || prev.RequestFingerprint != fp || prev.RebuildOutcome == nil {
				return nil, fmt.Errorf("%w: operation_id %q reused with conflicting rebuild parameters", ErrRestoreConflict, req.OperationID)
			}
			replay := *prev.RebuildOutcome
			replay.EvidenceIDs = append([]string(nil), prev.RebuildOutcome.EvidenceIDs...)
			replay.ArtifactIDs = append([]string(nil), prev.RebuildOutcome.ArtifactIDs...)
			replay.IdempotentReplay = true
			return &replay, nil
		}
	}

	preBlobSnaps, err := snapshotCaseSealedBlobs(resolvedStores.SealStore, resolvedStores.SealRootDir, req.CaseID)
	if err != nil {
		return nil, err
	}
	preCustodySnaps, err := snapshotCaseCustodyFiles(resolvedStores.LedgerRootDir, req.CaseID)
	if err != nil {
		return nil, err
	}

	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	allSealed := resolvedStores.SealStore.ListSealedManifests()
	var caseManifests []evidence.SealedManifest
	for _, sm := range allSealed {
		if sm.CaseID == req.CaseID {
			caseManifests = append(caseManifests, sm)
		}
	}
	if len(caseManifests) == 0 {
		return nil, fmt.Errorf("%w: no sealed evidence manifests found for case %s", ErrMissingPrerequisite, req.CaseID)
	}

	evidenceIDs := make([]string, 0, len(caseManifests))
	verifiedCheckpoints := 0
	verifiedTombstones := 0

	for _, sm := range caseManifests {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		vr, vErr := evidence.VerifyStoreEvidence(ctx, resolvedStores.SealStore, req.CaseID, sm.EvidenceID, evidence.VerifyOptions{})
		if vErr != nil || vr == nil || !vr.Verified {
			return nil, fmt.Errorf("%w: sealed evidence %s/%s failed integrity cross-check: %v", ErrManifestConsistency, req.CaseID, sm.EvidenceID, vErr)
		}

		chainOK, cErr := resolvedStores.LedgerStore.VerifyChain(req.CaseID, sm.EvidenceID)
		if cErr != nil || !chainOK {
			return nil, fmt.Errorf("%w: custody chain %s/%s failed verification: %v", ErrManifestConsistency, req.CaseID, sm.EvidenceID, cErr)
		}
		if diskErr := resolvedStores.LedgerStore.VerifyChainFileOnDisk(req.CaseID, sm.EvidenceID); diskErr != nil {
			return nil, fmt.Errorf("%w: on-disk custody file %s/%s failed cross-check: %v", ErrManifestConsistency, req.CaseID, sm.EvidenceID, diskErr)
		}
		events, lErr := resolvedStores.LedgerStore.ListEvents(req.CaseID, sm.EvidenceID)
		if lErr != nil {
			return nil, fmt.Errorf("%w: list custody events %s/%s: %v", ErrManifestConsistency, req.CaseID, sm.EvidenceID, lErr)
		}
		if len(events) == 0 {
			return nil, fmt.Errorf("%w: missing custody events for sealed evidence %s/%s", ErrManifestConsistency, req.CaseID, sm.EvidenceID)
		}
		if sm.CustodyRoot != custody.GenesisPrevHash && !custodyEventsContainRoot(events, sm.CustodyRoot) {
			return nil, fmt.Errorf("%w: sealed manifest custody_root %s for %s/%s not present in custody chain", ErrManifestConsistency, sm.CustodyRoot, req.CaseID, sm.EvidenceID)
		}

		if resolvedStores.CheckpointStore != nil {
			chks, chkErr := resolvedStores.CheckpointStore.ListCheckpoints(ctx, req.CaseID, sm.EvidenceID)
			if chkErr != nil {
				return nil, fmt.Errorf("%w: list checkpoints for %s/%s: %v", ErrManifestConsistency, req.CaseID, sm.EvidenceID, chkErr)
			}
			if req.RequireCheckpoints && len(chks) == 0 {
				return nil, fmt.Errorf("%w: required custody checkpoint missing for %s/%s", ErrManifestConsistency, req.CaseID, sm.EvidenceID)
			}
			for _, chk := range chks {
				if len(req.TrustedCheckpointKeys) > 0 || req.RequireCheckpoints {
					res, vChkErr := custody.VerifyCheckpoint(ctx, resolvedStores.LedgerStore, chk, custody.VerifyCheckpointOptions{
						TrustedPublicKeys: req.TrustedCheckpointKeys,
						Tracker:           req.CheckpointTracker,
						Now:               now,
					})
					if vChkErr != nil || res == nil || !res.Verified {
						return nil, fmt.Errorf("%w: checkpoint %s verification failed for %s/%s: %v", ErrManifestConsistency, chk.CheckpointID, req.CaseID, sm.EvidenceID, vChkErr)
					}
				} else {
					if chk.Sequence == 0 || chk.Sequence > uint64(len(events)) || events[chk.Sequence-1].CustodyRoot != chk.CustodyRoot {
						return nil, fmt.Errorf("%w: checkpoint %s root mismatch with ledger for %s/%s", ErrManifestConsistency, chk.CheckpointID, req.CaseID, sm.EvidenceID)
					}
				}
				verifiedCheckpoints++
			}
		}

		if resolvedStores.RetentionStore != nil {
			tomb, tErr := resolvedStores.RetentionStore.GetTombstone(req.CaseID, sm.EvidenceID)
			if tErr == nil && tomb != nil {
				if vErr := retention.VerifyTombstone(*tomb, nil); vErr != nil {
					return nil, fmt.Errorf("%w: retention tombstone invalid for %s/%s: %v", ErrManifestConsistency, req.CaseID, sm.EvidenceID, vErr)
				}
				if tomb.OriginalSHA256 != sm.SHA256 ||
					tomb.OriginalSizeBytes != sm.SizeBytes ||
					tomb.OriginalMediaType != sm.MediaType ||
					(tomb.CustodyRoot != custody.GenesisPrevHash && !custodyEventsContainRoot(events, tomb.CustodyRoot)) ||
					!tomb.SealedBytesIntact {
					return nil, fmt.Errorf("%w: retention tombstone %s/%s diverges from sealed manifest", ErrManifestConsistency, req.CaseID, sm.EvidenceID)
				}
				verifiedTombstones++
			} else if !errors.Is(tErr, retention.ErrTombstoneNotFound) {
				return nil, fmt.Errorf("%w: inspect retention tombstone %s/%s: %v", ErrManifestConsistency, req.CaseID, sm.EvidenceID, tErr)
			}
		}

		evidenceIDs = append(evidenceIDs, sm.EvidenceID)
	}
	sort.Strings(evidenceIDs)

	// Cross-check every derived artifact manifest & output payload against sealed inputs.
	caseArtifacts, err := resolvedStores.ArtifactStore.ListCaseManifests(req.CaseID)
	if err != nil {
		return nil, fmt.Errorf("%w: list derived artifacts for %s: %v", ErrManifestConsistency, req.CaseID, err)
	}
	artifactIDs := make([]string, 0, len(caseArtifacts))
	for _, dm := range caseArtifacts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		vr, vErr := resolvedStores.ArtifactStore.VerifyStoredArtifact(ctx, resolvedStores.SealStore, req.CaseID, dm.ArtifactID, req.ArtifactVerifyOpts)
		if vErr != nil || vr == nil || !vr.Verified {
			return nil, fmt.Errorf("%w: derived artifact %s/%s failed verification: %v", ErrManifestConsistency, req.CaseID, dm.ArtifactID, vErr)
		}
		artifactIDs = append(artifactIDs, dm.ArtifactID)
	}
	sort.Strings(artifactIDs)

	if s.cfg.Faults.SimulateDiskFull {
		return nil, ErrDiskFull
	}

	// Stage boundary checks before touching derived index or restore manifest.
	stageName := req.OperationID
	if stageName == "" {
		stageName = fmt.Sprintf("rebuild-%s-%d", req.CaseID, s.manifest.Generation+1)
	}
	opStageDir := filepath.Join(s.rootDir, restoreStagingSubdir, stageName)
	if err := checkWithinDir(filepath.Join(s.rootDir, restoreStagingSubdir), opStageDir); err != nil {
		return nil, err
	}
	_ = os.RemoveAll(opStageDir)
	if err := os.MkdirAll(opStageDir, 0o750); err != nil {
		return nil, fmt.Errorf("create rebuild staging dir: %w", err)
	}
	if err := writeJSONTempFile(filepath.Join(opStageDir, "verify.stage.tmp"), map[string]any{
		"case_id":      req.CaseID,
		"evidence_ids": evidenceIDs,
		"artifact_ids": artifactIDs,
	}); err != nil {
		return nil, err
	}
	if s.cfg.Faults.FailAfterStageBeforeCommit {
		return nil, ErrRestoreInterrupted
	}
	if err := writeJSONTempFile(filepath.Join(opStageDir, "rebuild-manifest.tmp"), s.manifest); err != nil {
		return nil, err
	}
	if s.cfg.Faults.FailBeforeManifestCommit {
		return nil, ErrRestoreInterrupted
	}

	nextGen := s.manifest.Generation + 1
	outcome := ConsistencyRebuildOutcome{
		SchemaVersion:         SchemaVersion,
		OperationID:           req.OperationID,
		CaseID:                req.CaseID,
		Generation:            nextGen,
		VerifiedEvidenceCount: len(caseManifests),
		VerifiedArtifactCount: len(caseArtifacts),
		VerifiedCheckpoints:   verifiedCheckpoints,
		VerifiedTombstones:    verifiedTombstones,
		EvidenceIDs:           evidenceIDs,
		ArtifactIDs:           artifactIDs,
		CustodyRewritten:      false,
		SealedBytesModified:   false,
		VerifiedAt:            now.UTC().Format(time.RFC3339Nano),
	}

	if len(artifactIDs) > 0 {
		idxStore, closeIdx, err := openOrUseIndexStore(resolvedStores, req.CaseID)
		if err != nil {
			return nil, err
		}
		if closeIdx != nil {
			defer closeIdx()
		}
		rebuildOut, err := idxStore.RebuildCaseIndex(
			ctx,
			resolvedStores.SealStore,
			resolvedStores.SealRootDir,
			resolvedStores.ArtifactStore,
			resolvedStores.ArtifactRootDir,
			timeline.RebuildRequest{
				SchemaVersion:    timeline.SchemaVersion,
				CaseID:           req.CaseID,
				ArtifactIDs:      artifactIDs,
				Provider:         req.Provider,
				ZoneHint:         req.ZoneHint,
				SourceConfidence: req.SourceConfidence,
				VerifyOptions:    req.ArtifactVerifyOpts,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("rebuild derived timeline index: %w", err)
		}
		outcome.TimelineRebuilt = true
		outcome.RebuiltTimelineEntries = rebuildOut.RebuiltEntries
		outcome.CaseIndexSHA256 = rebuildOut.CaseIndexSHA256
	}

	// Post-rebuild immutability assertions: sealed source bytes and custody chains are bit-identical.
	if err := verifySnapshotsUnchanged(preBlobSnaps, ErrSealedBytesModified); err != nil {
		return nil, err
	}
	if err := verifySnapshotsUnchanged(preCustodySnaps, ErrCustodyRewriteForbidden); err != nil {
		return nil, err
	}

	nextState := cloneRestoreState(s.manifest)
	nextState.Generation = nextGen
	if req.OperationID != "" {
		outCopy := outcome
		outCopy.EvidenceIDs = append([]string(nil), outcome.EvidenceIDs...)
		outCopy.ArtifactIDs = append([]string(nil), outcome.ArtifactIDs...)
		nextState.Operations[req.OperationID] = persistedRestoreOp{
			Kind:               "verify_rebuild",
			RequestFingerprint: fp,
			RebuildOutcome:     &outCopy,
		}
	}
	if err := s.persistManifestUnlocked(nextState); err != nil {
		return nil, err
	}
	s.manifest = nextState
	_ = os.RemoveAll(opStageDir)

	ret := outcome
	ret.EvidenceIDs = append([]string(nil), outcome.EvidenceIDs...)
	ret.ArtifactIDs = append([]string(nil), outcome.ArtifactIDs...)
	return &ret, nil
}

func openOrUseIndexStore(stores TargetStores, caseID string) (*timeline.EventIndexStore, func(), error) {
	if stores.IndexStore != nil {
		return stores.IndexStore, nil, nil
	}
	idxStore, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{
		RootDir: stores.IndexRootDir,
		SyncDir: true,
	})
	if err == nil {
		return idxStore, func() { _ = idxStore.Close() }, nil
	}
	// If the derived timeline index on disk was deleted or corrupted, first attempt surgical repair
	// of ONLY caseID so healthy sibling cases in the same EventIndexStore remain intact.
	if errors.Is(err, timeline.ErrInvalidInput) || errors.Is(err, timeline.ErrMalformedPayload) || errors.Is(err, timeline.ErrUnsupportedVersion) {
		absIdxRoot, pathErr := filepath.Abs(filepath.Clean(stores.IndexRootDir))
		if pathErr != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrPathTraversal, pathErr)
		}
		if _, symErr := ensureNoSymlink(absIdxRoot); symErr != nil {
			return nil, nil, symErr
		}
		if caseID != "" {
			if repairedStore, rErr := trySurgicalCaseIndexRepair(absIdxRoot, caseID); rErr == nil {
				return repairedStore, func() { _ = repairedStore.Close() }, nil
			}
		}
		_ = os.Remove(filepath.Join(absIdxRoot, "timeline-index.json"))
		_ = os.RemoveAll(filepath.Join(absIdxRoot, "cases"))
		idxStore, retryErr := timeline.OpenEventIndexStore(timeline.EventIndexConfig{
			RootDir: absIdxRoot,
			SyncDir: true,
		})
		if retryErr != nil {
			return nil, nil, retryErr
		}
		return idxStore, func() { _ = idxStore.Close() }, nil
	}
	return nil, nil, err
}

func trySurgicalCaseIndexRepair(absIdxRoot, caseID string) (*timeline.EventIndexStore, error) {
	indexPath := filepath.Join(absIdxRoot, "timeline-index.json")
	if _, err := ensureNoSymlink(indexPath); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if ver, _ := doc["schema_version"].(string); ver != timeline.SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported timeline index version %q", ErrUnsupportedVersion, ver)
	}
	if casesMap, ok := doc["cases"].(map[string]any); ok {
		delete(casesMap, caseID)
	}
	casePath := filepath.Join(absIdxRoot, "cases", caseID+".index.json")
	if err := checkWithinDir(absIdxRoot, casePath); err != nil {
		return nil, err
	}
	if _, err := ensureNoSymlink(casePath); err != nil {
		return nil, err
	}
	_ = os.Remove(casePath)

	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	updated = append(updated, '\n')
	tmpPath := filepath.Join(absIdxRoot, "staging", fmt.Sprintf("repair-%s.tmp", caseID))
	if err := os.MkdirAll(filepath.Dir(tmpPath), 0o750); err != nil {
		return nil, err
	}
	if err := writeSyncFile(tmpPath, updated, 0o640); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpPath, indexPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	return timeline.OpenEventIndexStore(timeline.EventIndexConfig{
		RootDir: absIdxRoot,
		SyncDir: true,
	})
}

func sealFromBundleEntry(ctx context.Context, stores TargetStores, opID, caseID string, se stagedEvidenceRestore) error {
	if strings.TrimSpace(stores.QuarantineDir) == "" {
		return fmt.Errorf("%w: quarantine directory required to restore sealed blob", ErrMissingPrerequisite)
	}
	uploadID := shortSafeID("rqu", opID+"-"+se.entry.EvidenceID)
	sealOpID := shortSafeID("rsl", opID+"-"+se.entry.EvidenceID)

	// Clean any orphan quarantine artifacts for this derived uploadID from a previous aborted attempt.
	_ = os.Remove(filepath.Join(stores.QuarantineDir, caseID, uploadID+".part"))
	_ = os.Remove(filepath.Join(stores.QuarantineDir, caseID, uploadID+".bin"))
	_ = os.Remove(filepath.Join(stores.QuarantineDir, caseID, uploadID+".meta.json"))
	_ = os.Remove(filepath.Join(stores.QuarantineDir, caseID, uploadID+".meta.tmp"))

	expectedSize := se.entry.Manifest.SizeBytes
	q, err := evidence.StreamFileIntoQuarantine(ctx, evidence.UploadConfig{
		QuarantineDir: stores.QuarantineDir,
		SyncDir:       true,
		IsSealed: func(cID, eID string) (bool, error) {
			_, gErr := stores.SealStore.GetSealedManifest(cID, eID)
			if gErr == nil {
				return true, nil
			}
			if os.IsNotExist(gErr) {
				return false, nil
			}
			return false, gErr
		},
	}, evidence.UploadRequest{
		SchemaVersion:  evidence.SchemaVersion,
		UploadID:       uploadID,
		CaseID:         caseID,
		EvidenceID:     se.entry.EvidenceID,
		MediaType:      se.entry.Manifest.MediaType,
		Filename:       se.entry.EvidenceID + ".bin",
		ExpectedSize:   &expectedSize,
		ExpectedSHA256: se.entry.Manifest.SHA256,
	}, se.blobAbsPath)
	if err != nil {
		return fmt.Errorf("%w: quarantine staged restore blob %s: %v", ErrManifestConsistency, se.entry.EvidenceID, err)
	}
	defer func() {
		_ = os.Remove(filepath.Join(stores.QuarantineDir, q.QuarantinePath))
		_ = os.Remove(filepath.Join(stores.QuarantineDir, q.MetadataPath))
	}()

	sm, err := stores.SealStore.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    sealOpID,
		Quarantined:    q,
		ExpectedSHA256: se.entry.Manifest.SHA256,
		AcquiredAt:     se.entry.Manifest.AcquiredAt,
		CustodyRoot:    se.entry.Manifest.CustodyRoot,
	})
	if err != nil {
		return fmt.Errorf("%w: seal restored blob %s: %v", ErrManifestConsistency, se.entry.EvidenceID, err)
	}
	if sm.SHA256 != se.entry.Manifest.SHA256 || sm.SizeBytes != se.entry.Manifest.SizeBytes {
		return fmt.Errorf("%w: restored sealed manifest %s digest/size mismatch", ErrManifestConsistency, se.entry.EvidenceID)
	}
	vr, err := evidence.VerifyStoreEvidence(ctx, stores.SealStore, caseID, se.entry.EvidenceID, evidence.VerifyOptions{})
	if err != nil || vr == nil || !vr.Verified {
		return fmt.Errorf("%w: restored sealed evidence %s failed verification: %v", ErrManifestConsistency, se.entry.EvidenceID, err)
	}
	return nil
}

func verifyRebuiltTimelineMatchesBundle(bundleDir, timelineRel string, idxStore *timeline.EventIndexStore, caseID string) error {
	tlPath := filepath.Join(bundleDir, filepath.FromSlash(timelineRel))
	if err := checkWithinDir(bundleDir, tlPath); err != nil {
		return err
	}
	if _, err := ensureNoSymlink(tlPath); err != nil {
		return err
	}
	raw, err := os.ReadFile(tlPath)
	if err != nil {
		return fmt.Errorf("%w: read bundle timeline: %v", ErrManifestConsistency, err)
	}
	var bundled []timeline.TimelineEntry
	if err := json.Unmarshal(raw, &bundled); err != nil {
		return fmt.Errorf("%w: parse bundle timeline: %v", ErrManifestConsistency, err)
	}
	rebuilt, err := idxStore.ListEntries(caseID)
	if err != nil {
		return fmt.Errorf("%w: list rebuilt timeline: %v", ErrManifestConsistency, err)
	}
	if len(rebuilt) != len(bundled) {
		return fmt.Errorf("%w: rebuilt timeline count %d != bundle timeline count %d", ErrManifestConsistency, len(rebuilt), len(bundled))
	}
	rebuiltByID := make(map[string]timeline.TimelineEntry, len(rebuilt))
	for _, e := range rebuilt {
		rebuiltByID[e.EventIdentity] = e
	}
	for _, b := range bundled {
		r, ok := rebuiltByID[b.EventIdentity]
		if !ok {
			return fmt.Errorf("%w: rebuilt timeline missing bundled event_identity %s", ErrManifestConsistency, b.EventIdentity)
		}
		if r.Time.RawTimestamp != b.Time.RawTimestamp {
			return fmt.Errorf("%w: rebuilt timeline event %s raw_timestamp %q != bundle %q", ErrManifestConsistency, b.EventIdentity, r.Time.RawTimestamp, b.Time.RawTimestamp)
		}
	}
	return nil
}

func verifyBundleTimelinePreCommit(
	bundleDir, timelineRel string,
	req RestoreBundleRequest,
	stagedArtifacts []stagedArtifactRestore,
) error {
	expected := make(map[string]string)
	for _, sa := range stagedArtifacts {
		var payload artifacts.DerivedPayload
		if err := json.Unmarshal(sa.payloadBytes, &payload); err != nil {
			return fmt.Errorf("%w: parse derived payload %s: %v", ErrManifestConsistency, sa.entry.ArtifactID, err)
		}
		if len(payload.Records) == 0 {
			return fmt.Errorf("%w: derived payload %s contains zero records", ErrManifestConsistency, sa.entry.ArtifactID)
		}
		for idx, rec := range payload.Records {
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

			nt, err := timeline.NormalizeTimestamp(timeline.NormalizeRequest{
				RawTimestamp:     rawTS,
				ZoneHint:         req.ZoneHint,
				SourceConfidence: req.SourceConfidence,
			})
			if err != nil {
				return fmt.Errorf("%w: artifact %s record[%d] timestamp normalization failed: %v", ErrManifestConsistency, sa.entry.ArtifactID, idx, err)
			}
			evID, err := timeline.ComputeEventIdentity(timeline.EventIdentityInput{
				CaseID:       req.CaseID,
				InputHashes:  sa.entry.Manifest.InputHashes,
				SourceLine:   rec.RowNumber,
				RawTimestamp: nt.RawTimestamp,
				EventType:    evType,
				Summary:      summary,
				Fields:       rec.Fields,
			})
			if err != nil {
				return fmt.Errorf("%w: artifact %s record[%d] event identity failed: %v", ErrManifestConsistency, sa.entry.ArtifactID, idx, err)
			}
			expected[evID] = nt.RawTimestamp
		}
	}

	if timelineRel == "" {
		return nil
	}
	tlPath := filepath.Join(bundleDir, filepath.FromSlash(timelineRel))
	if err := checkWithinDir(bundleDir, tlPath); err != nil {
		return err
	}
	if _, err := ensureNoSymlink(tlPath); err != nil {
		return err
	}
	raw, err := os.ReadFile(tlPath)
	if err != nil {
		return fmt.Errorf("%w: read bundle timeline: %v", ErrManifestConsistency, err)
	}
	var bundled []timeline.TimelineEntry
	if err := json.Unmarshal(raw, &bundled); err != nil {
		return fmt.Errorf("%w: parse bundle timeline: %v", ErrManifestConsistency, err)
	}
	if len(expected) != len(bundled) {
		return fmt.Errorf("%w: derived timeline count %d != bundle timeline count %d", ErrManifestConsistency, len(expected), len(bundled))
	}
	for _, b := range bundled {
		wantRawTS, ok := expected[b.EventIdentity]
		if !ok {
			return fmt.Errorf("%w: derived timeline missing bundled event_identity %s", ErrManifestConsistency, b.EventIdentity)
		}
		if wantRawTS != b.Time.RawTimestamp {
			return fmt.Errorf("%w: derived timeline event %s raw_timestamp %q != bundle %q", ErrManifestConsistency, b.EventIdentity, wantRawTS, b.Time.RawTimestamp)
		}
	}
	return nil
}

func resolveAndCheckStores(stores TargetStores, requireIndexStore bool) (TargetStores, error) {
	if stores.SealStore == nil {
		return stores, fmt.Errorf("%w: SealStore is required", ErrMissingPrerequisite)
	}
	if stores.LedgerStore == nil {
		return stores, fmt.Errorf("%w: LedgerStore is required", ErrMissingPrerequisite)
	}
	if stores.ArtifactStore == nil {
		return stores, fmt.Errorf("%w: ArtifactStore is required", ErrMissingPrerequisite)
	}
	if requireIndexStore && stores.IndexStore == nil {
		return stores, fmt.Errorf("%w: EventIndexStore is required", ErrMissingPrerequisite)
	}
	if !requireIndexStore && stores.IndexStore == nil && strings.TrimSpace(stores.IndexRootDir) == "" {
		return stores, fmt.Errorf("%w: EventIndexStore or IndexRootDir is required", ErrMissingPrerequisite)
	}

	out := stores
	if strings.TrimSpace(out.SealRootDir) == "" {
		out.SealRootDir = stores.SealStore.RootDir()
	}
	if strings.TrimSpace(out.QuarantineDir) == "" {
		out.QuarantineDir = stores.SealStore.QuarantineDir()
	}
	if strings.TrimSpace(out.LedgerRootDir) == "" {
		out.LedgerRootDir = stores.LedgerStore.CustodyDir()
	} else {
		// Accept either parent rootDir (containing custody/) or custodyDir itself.
		cand := filepath.Join(out.LedgerRootDir, custody.DefaultLedgerDir)
		if info, err := os.Stat(cand); err == nil && info.IsDir() {
			out.LedgerRootDir = cand
		}
	}
	if strings.TrimSpace(out.ArtifactRootDir) == "" {
		out.ArtifactRootDir = stores.ArtifactStore.RootDir()
	}
	if strings.TrimSpace(out.SealRootDir) == "" || strings.TrimSpace(out.ArtifactRootDir) == "" {
		return out, fmt.Errorf("%w: seal and artifact root directories are required", ErrMissingPrerequisite)
	}
	if err := validateSafeInputPath(out.SealRootDir); err != nil {
		return out, err
	}
	if out.QuarantineDir != "" {
		if err := validateSafeInputPath(out.QuarantineDir); err != nil {
			return out, err
		}
	}
	if err := validateSafeInputPath(out.LedgerRootDir); err != nil {
		return out, err
	}
	if err := validateSafeInputPath(out.ArtifactRootDir); err != nil {
		return out, err
	}
	if out.IndexRootDir != "" {
		if err := validateSafeInputPath(out.IndexRootDir); err != nil {
			return out, err
		}
	}
	return out, nil
}

func snapshotCaseSealedBlobs(sealStore *evidence.SealStore, sealRootDir, caseID string) ([]fileSnapshot, error) {
	manifests := sealStore.ListSealedManifests()
	var snaps []fileSnapshot
	for _, m := range manifests {
		if m.CaseID != caseID {
			continue
		}
		blobPath := filepath.Join(sealRootDir, filepath.FromSlash(m.BlobRelPath))
		if err := checkWithinDir(sealRootDir, blobPath); err != nil {
			return nil, err
		}
		sha, sz, err := hashRegularFile(blobPath)
		if err != nil {
			return nil, fmt.Errorf("%w: snapshot sealed blob %s/%s: %v", ErrManifestConsistency, caseID, m.EvidenceID, err)
		}
		snaps = append(snaps, fileSnapshot{path: blobPath, sha: sha, size: sz})
	}
	return snaps, nil
}

func snapshotCaseCustodyFiles(custodyDir, caseID string) ([]fileSnapshot, error) {
	caseDir := filepath.Join(custodyDir, caseID)
	if _, err := ensureNoSymlink(caseDir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(caseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var snaps []fileSnapshot
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".jsonl") {
			continue
		}
		p := filepath.Join(caseDir, ent.Name())
		sha, sz, err := hashRegularFile(p)
		if err != nil {
			return nil, fmt.Errorf("%w: snapshot custody file %s: %v", ErrCustodyRewriteForbidden, ent.Name(), err)
		}
		snaps = append(snaps, fileSnapshot{path: p, sha: sha, size: sz})
	}
	return snaps, nil
}

func verifySnapshotsUnchanged(snaps []fileSnapshot, sentinel error) error {
	for _, snap := range snaps {
		sha, sz, err := hashRegularFile(snap.path)
		if err != nil || sha != snap.sha || sz != snap.size {
			return fmt.Errorf("%w: immutable file %s altered (want sha=%s size=%d, got sha=%s size=%d, err=%v)",
				sentinel, filepath.Base(snap.path), snap.sha, snap.size, sha, sz, err)
		}
	}
	return nil
}

func validateCheckpointStructurePreCommit(chk custody.Checkpoint) error {
	if chk.SchemaVersion != custody.CheckpointSchemaVersion {
		return fmt.Errorf("%w: unsupported checkpoint schema %q", custody.ErrInvalidCheckpoint, chk.SchemaVersion)
	}
	if !identifierRegex.MatchString(chk.CheckpointID) {
		return fmt.Errorf("%w: invalid checkpoint_id %q", custody.ErrInvalidCheckpoint, chk.CheckpointID)
	}
	if !identifierRegex.MatchString(chk.KeyID) {
		return fmt.Errorf("%w: invalid key_id %q", custody.ErrInvalidCheckpoint, chk.KeyID)
	}
	if !digestRegex.MatchString(chk.CustodyRoot) {
		return fmt.Errorf("%w: invalid custody_root %q", custody.ErrInvalidCheckpoint, chk.CustodyRoot)
	}
	iss, err := time.Parse(time.RFC3339Nano, chk.IssuedAt)
	if err != nil {
		return fmt.Errorf("%w: invalid issued_at %q", custody.ErrInvalidTimestamp, chk.IssuedAt)
	}
	if chk.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339Nano, chk.ExpiresAt)
		if err != nil {
			return fmt.Errorf("%w: invalid expires_at %q", custody.ErrInvalidTimestamp, chk.ExpiresAt)
		}
		if !exp.After(iss) {
			return fmt.Errorf("%w: expires_at %s must be after issued_at %s", custody.ErrInvalidCheckpoint, chk.ExpiresAt, chk.IssuedAt)
		}
	}
	return nil
}

func verifyCheckpointPreCommit(
	chk custody.Checkpoint,
	trustedKeys map[string]string,
	tracker *custody.CheckpointTracker,
	strictReplay bool,
	now time.Time,
) error {
	if err := validateCheckpointStructurePreCommit(chk); err != nil {
		return err
	}
	if len(trustedKeys) == 0 {
		return fmt.Errorf("%w: trusted checkpoint keys map is empty", custody.ErrCheckpointUntrustedSigner)
	}
	trustedHex, ok := trustedKeys[chk.KeyID]
	if !ok || strings.TrimSpace(trustedHex) == "" {
		return fmt.Errorf("%w: key_id %q not trusted", custody.ErrCheckpointUntrustedSigner, chk.KeyID)
	}
	pubBytes, err := hex.DecodeString(strings.TrimSpace(trustedHex))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid trusted public key", custody.ErrCheckpointUntrustedSigner)
	}
	if !strings.EqualFold(strings.TrimSpace(chk.PublicKey), strings.TrimSpace(trustedHex)) {
		return fmt.Errorf("%w: checkpoint public key mismatch", custody.ErrCheckpointUntrustedSigner)
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(chk.Signature))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid signature encoding", custody.ErrCheckpointInvalidSignature)
	}
	if !ed25519.Verify(pubBytes, custody.CanonicalCheckpointBytes(chk), sigBytes) {
		return fmt.Errorf("%w: Ed25519 verification failed", custody.ErrCheckpointInvalidSignature)
	}
	if chk.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339Nano, chk.ExpiresAt)
		if err != nil {
			return fmt.Errorf("%w: malformed expires_at", custody.ErrInvalidTimestamp)
		}
		if now.After(exp) {
			return fmt.Errorf("%w: checkpoint expired at %s", custody.ErrCheckpointExpired, chk.ExpiresAt)
		}
	}
	if tracker != nil {
		if err := tracker.Check(chk, strictReplay); err != nil {
			return err
		}
	}
	return nil
}

func loadCustodyEventsFile(path string) ([]custody.CustodyEvent, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var events []custody.CustodyEvent
	if err := json.Unmarshal(raw, &events); err != nil {
		return nil, err
	}
	return events, nil
}

func verifyCustodyEventsSlice(caseID, evidenceID string, events []custody.CustodyEvent) (string, error) {
	if len(events) == 0 {
		return "", errors.New("empty custody chain")
	}
	expectedSeq := uint64(1)
	expectedPrevHash := custody.GenesisPrevHash
	expectedPrevRoot := custody.GenesisPrevHash
	for _, ev := range events {
		if ev.CaseID != caseID || ev.EvidenceID != evidenceID {
			return "", fmt.Errorf("event case/evidence mismatch (%s/%s)", ev.CaseID, ev.EvidenceID)
		}
		if ev.Sequence != expectedSeq {
			return "", fmt.Errorf("sequence %d != %d", ev.Sequence, expectedSeq)
		}
		if ev.PrevHash != expectedPrevHash {
			return "", fmt.Errorf("prev_hash mismatch at sequence %d", ev.Sequence)
		}
		digest := custody.ComputeEventDigest(ev)
		if ev.EventDigest != digest {
			return "", fmt.Errorf("event_digest mismatch at sequence %d", ev.Sequence)
		}
		root := custody.ComputeCustodyRoot(expectedPrevRoot, digest)
		if ev.CustodyRoot != root {
			return "", fmt.Errorf("custody_root mismatch at sequence %d", ev.Sequence)
		}
		expectedSeq++
		expectedPrevHash = ev.EventDigest
		expectedPrevRoot = ev.CustodyRoot
	}
	return expectedPrevRoot, nil
}

func custodyEventsEqual(a, b []custody.CustodyEvent) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func custodyEventsContainRoot(events []custody.CustodyEvent, root string) bool {
	for _, ev := range events {
		if ev.CustodyRoot == root {
			return true
		}
	}
	return false
}

func writeCustodyJSONL(path string, events []custody.CustodyEvent) error {
	var buf strings.Builder
	for _, ev := range events {
		raw, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	return writeSyncFile(path, []byte(buf.String()), 0o600)
}

func writeJSONTempFile(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeSyncFile(path, raw, 0o600)
}

func (s *RestoreStore) persistManifestUnlocked(state restoreManifestState) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal restore manifest: %w", err)
	}
	raw = append(raw, '\n')
	tmp := filepath.Join(s.rootDir, restoreStagingSubdir, fmt.Sprintf("restore-manifest.%d.tmp", state.Generation))
	if err := writeSyncFile(tmp, raw, 0o600); err != nil {
		return err
	}
	dst := filepath.Join(s.rootDir, restoreManifestFileName)
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit restore manifest: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(s.rootDir)
	}
	return nil
}

func cloneRestoreState(in restoreManifestState) restoreManifestState {
	ops := make(map[string]persistedRestoreOp, len(in.Operations)+1)
	for k, v := range in.Operations {
		ops[k] = v
	}
	return restoreManifestState{
		SchemaVersion: SchemaVersion,
		Generation:    in.Generation,
		Operations:    ops,
	}
}

type fingerprintArtifactVerifyOpts struct {
	RequireSignature bool
	TrustedKeys      map[string]string
}

func encodeArtifactVerifyOptsForFingerprint(opts artifacts.VerifyOptions) fingerprintArtifactVerifyOpts {
	var keys map[string]string
	if len(opts.TrustedKeys) > 0 {
		keys = make(map[string]string, len(opts.TrustedKeys))
		for k, pub := range opts.TrustedKeys {
			keys[k] = hex.EncodeToString(pub)
		}
	}
	return fingerprintArtifactVerifyOpts{
		RequireSignature: opts.RequireSignature,
		TrustedKeys:      keys,
	}
}

func fingerprintRestoreBundle(req RestoreBundleRequest, bundleDir, bundleDigest string) string {
	payload := struct {
		CaseID                 string
		BundleDir              string
		BundleDigest           string
		Provider               string
		ZoneHint               string
		SourceConfidence       *float64
		RequireBundleSignature bool
		RequireCheckpointTrust bool
		StrictCheckpointReplay bool
		TrustedBundleKeys      map[string]string
		TrustedCheckpointKeys  map[string]string
		ArtifactVerifyOpts     fingerprintArtifactVerifyOpts
	}{
		CaseID:                 req.CaseID,
		BundleDir:              bundleDir,
		BundleDigest:           bundleDigest,
		Provider:               req.Provider,
		ZoneHint:               req.ZoneHint,
		SourceConfidence:       req.SourceConfidence,
		RequireBundleSignature: req.RequireBundleSignature,
		RequireCheckpointTrust: req.RequireCheckpointTrust,
		StrictCheckpointReplay: req.StrictCheckpointReplay,
		TrustedBundleKeys:      req.TrustedBundleKeys,
		TrustedCheckpointKeys:  req.TrustedCheckpointKeys,
		ArtifactVerifyOpts:     encodeArtifactVerifyOptsForFingerprint(req.ArtifactVerifyOpts),
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func fingerprintRebuildCase(req VerifyAndRebuildRequest) string {
	payload := struct {
		CaseID                string
		Provider              string
		ZoneHint              string
		SourceConfidence      *float64
		RequireCheckpoints    bool
		TrustedCheckpointKeys map[string]string
		ArtifactVerifyOpts    fingerprintArtifactVerifyOpts
	}{
		CaseID:                req.CaseID,
		Provider:              req.Provider,
		ZoneHint:              req.ZoneHint,
		SourceConfidence:      req.SourceConfidence,
		RequireCheckpoints:    req.RequireCheckpoints,
		TrustedCheckpointKeys: req.TrustedCheckpointKeys,
		ArtifactVerifyOpts:    encodeArtifactVerifyOptsForFingerprint(req.ArtifactVerifyOpts),
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func shortSafeID(prefix, seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return prefix + "-" + hex.EncodeToString(sum[:16])
}

func validateIdentifier(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidRequest, field)
	}
	if strings.ContainsRune(value, '\x00') || strings.Contains(value, "..") || strings.ContainsAny(value, "/\\") {
		return fmt.Errorf("%w: %s contains unsafe path characters", ErrPathTraversal, field)
	}
	if !identifierRegex.MatchString(value) {
		return fmt.Errorf("%w: invalid %s %q", ErrInvalidRequest, field, value)
	}
	return nil
}

func validateSafeInputPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: path is required", ErrInvalidRequest)
	}
	if strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("%w: null byte in path", ErrPathTraversal)
	}
	for _, seg := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return fmt.Errorf("%w: traversal segment in path %q", ErrPathTraversal, path)
		}
	}
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if _, err := ensureNoSymlink(absPath); err != nil {
		return err
	}
	return nil
}

func resolveSafeDir(dir string, requiredErr error) (string, error) {
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
		if err := os.MkdirAll(absDir, 0o750); err != nil {
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
			return "", fmt.Errorf("%w: %s is not a directory", ErrInvalidRequest, absDir)
		}
	}
	return absDir, nil
}

func ensureNoSymlink(path string) (bool, error) {
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) {
		cur := "/"
		parts := strings.Split(strings.TrimPrefix(clean, "/"), string(filepath.Separator))
		lastExists := false
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
			lastExists = true
		}
		return lastExists, nil
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
		return fmt.Errorf("%w: %s escapes %s", ErrPathTraversal, target, root)
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
		return "", 0, fmt.Errorf("%w: %s is not a regular file", ErrInvalidRequest, path)
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

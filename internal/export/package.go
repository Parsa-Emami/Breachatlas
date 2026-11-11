package export

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
	"github.com/Parsa-Emami/Breachatlas/internal/findings"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

const (
	SchemaVersion           = "1"
	BundleManifestFile      = "bundle-manifest.json"
	DefaultMaxStorageBytes  = int64(20 * 1024 * 1024 * 1024)
	DefaultMaxBundles       = 10000
	bundlesSubdir           = "bundles"
	stagingSubdir           = "staging"
	exportIndexFile         = "export-index.json"
	exportLockFile          = ".export.lock"
	signatureDomainPrefix   = "breachatlas:export-bundle:v1:"
)

var (
	ErrExportStoreRequired       = errors.New("export store root directory is required")
	ErrExportStoreClosed         = errors.New("export store closed")
	ErrExportLockBusy            = errors.New("export store lock busy: another writer holds exclusive lock")
	ErrUnsupportedVersion        = errors.New("unsupported export bundle schema version")
	ErrUnavailableProvider       = errors.New("unavailable export provider")
	ErrMissingPrerequisite       = errors.New("missing prerequisite for portable export bundle")
	ErrCheckpointFailed          = errors.New("custody checkpoint verification failed for export")
	ErrInputBindingMismatch      = errors.New("derived artifact input does not match selected sealed evidence")
	ErrPathTraversal             = errors.New("path traversal or invalid identifier rejected")
	ErrSymlinkRejected           = errors.New("symlink rejected in export store path")
	ErrExportConflict            = errors.New("bundle or operation ID reused with conflicting parameters")
	ErrBundleNotFound            = errors.New("export bundle manifest not found")
	ErrMalformedExport           = errors.New("malformed export index or bundle manifest")
	ErrSealedBytesTampered       = errors.New("sealed source bytes modified during export packaging")
	ErrDiskFull                  = errors.New("disk full: export packaging aborted")
	ErrInterrupted               = errors.New("export packaging interrupted before authoritative commit")
	ErrExportQuotaExceeded       = errors.New("export store quota exceeded")
)

var (
	identifierRegex  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	allowedProviders = map[string]bool{
		"":            true,
		"local":       true,
		"breachatlas": true,
	}
)

// BoundEvidenceEntry binds a verified sealed evidence manifest, raw byte digest, verified custody events,
// and verified signed checkpoint inside a portable export bundle.
type BoundEvidenceEntry struct {
	EvidenceID           string                  `json:"evidence_id"`
	Manifest             evidence.SealedManifest `json:"manifest"`
	BundleBlobRelPath    string                  `json:"bundle_blob_rel_path"`
	BlobSHA256           string                  `json:"blob_sha256"`
	BlobSizeBytes        int64                   `json:"blob_size_bytes"`
	ManifestRelPath      string                  `json:"manifest_rel_path"`
	ManifestSHA256       string                  `json:"manifest_sha256"`
	CustodyEventsRelPath string                  `json:"custody_events_rel_path"`
	CustodyEventsSHA256  string                  `json:"custody_events_sha256"`
	CustodyEventCount    int                     `json:"custody_event_count"`
	CustodyRoot          string                  `json:"custody_root"`
	CheckpointRelPath    string                  `json:"checkpoint_rel_path"`
	CheckpointSHA256     string                  `json:"checkpoint_sha256"`
	Checkpoint           custody.Checkpoint      `json:"checkpoint"`
}

// BoundArtifactEntry binds a verified derived artifact manifest and payload to the exported bundle.
type BoundArtifactEntry struct {
	ArtifactID       string                    `json:"artifact_id"`
	Manifest         artifacts.DerivedManifest `json:"manifest"`
	ManifestRelPath  string                    `json:"manifest_rel_path"`
	ManifestSHA256   string                    `json:"manifest_sha256"`
	PayloadRelPath   string                    `json:"payload_rel_path"`
	PayloadSHA256    string                    `json:"payload_sha256"`
	PayloadSizeBytes int64                     `json:"payload_size_bytes"`
}

// BundleManifest describes a self-contained portable DFIR export package written to bundle-manifest.json.
type BundleManifest struct {
	SchemaVersion     string               `json:"schema_version"`
	BundleID          string               `json:"bundle_id"`
	CaseID            string               `json:"case_id"`
	Provider          string               `json:"provider"`
	CreatedAt         string               `json:"created_at"`
	BundleDigest      string               `json:"bundle_digest"`
	EvidenceItems     []BoundEvidenceEntry `json:"evidence_items"`
	DerivedArtifacts  []BoundArtifactEntry `json:"derived_artifacts,omitempty"`
	TimelineRelPath   string               `json:"timeline_rel_path,omitempty"`
	TimelineSHA256    string               `json:"timeline_sha256,omitempty"`
	TimelineCount     int                  `json:"timeline_count,omitempty"`
	HypothesesRelPath string               `json:"hypotheses_rel_path,omitempty"`
	HypothesesSHA256  string               `json:"hypotheses_sha256,omitempty"`
	HypothesesCount   int                  `json:"hypotheses_count,omitempty"`
	FileChecksums     map[string]string    `json:"file_checksums"`
	Signed            bool                 `json:"signed"`
	KeyID             string               `json:"key_id,omitempty"`
	PublicKey         string               `json:"public_key,omitempty"`
	Signature         string               `json:"signature,omitempty"`
}

// ExportDeps supplies verified local stores and trust options required to assemble an export bundle.
type ExportDeps struct {
	SealStore       *evidence.SealStore
	SealRootDir     string
	LedgerStore     *custody.LedgerStore
	CheckpointStore *custody.FileCheckpointStore
	Checkpoints     map[string]custody.Checkpoint // optional override keyed by evidence_id
	CheckpointOpts  custody.VerifyCheckpointOptions
	ArtifactStore   *artifacts.ArtifactStore
	ArtifactRootDir string
	IndexStore      *timeline.EventIndexStore
	FindingStore    *findings.FindingStore
}

// ExportRequest selects evidence, derived artifacts, and optional Ed25519 bundle signing keys.
type ExportRequest struct {
	SchemaVersion string             `json:"schema_version"`
	OperationID   string             `json:"operation_id,omitempty"`
	BundleID      string             `json:"bundle_id"`
	CaseID        string             `json:"case_id"`
	Provider      string             `json:"provider,omitempty"`
	EvidenceIDs   []string           `json:"evidence_ids"`
	ArtifactIDs   []string           `json:"artifact_ids,omitempty"`
	IncludeTimeline bool             `json:"include_timeline,omitempty"`
	IncludeNotes  bool               `json:"include_notes,omitempty"`
	CreatedAt     string             `json:"created_at,omitempty"`
	KeyID         string             `json:"key_id,omitempty"`
	PrivateKey    ed25519.PrivateKey `json:"-"`
}

// ExportOutcome summarizes a packaged bundle directory and cryptographic digest.
type ExportOutcome struct {
	BundleID         string         `json:"bundle_id"`
	CaseID           string         `json:"case_id"`
	BundleDir        string         `json:"bundle_dir"`
	BundleDigest     string         `json:"bundle_digest"`
	Generation       uint64         `json:"generation"`
	Signed           bool           `json:"signed"`
	Manifest         BundleManifest `json:"manifest"`
	IdempotentReplay bool           `json:"idempotent_replay,omitempty"`
}

// ExportFaults enables fault injection at atomic commit boundaries for restart tests.
type ExportFaults struct {
	SimulateDiskFull           bool
	FailAfterStageBeforeCommit bool
}

// ExportStoreConfig configures durable export packaging storage and quotas.
type ExportStoreConfig struct {
	RootDir         string
	MaxStorageBytes int64
	MaxBundles      int
	SyncDir         bool
	Faults          ExportFaults
}

// RecoveryReport summarizes staging cleanup and verified bundles recovered on startup.
type RecoveryReport struct {
	CleanedStagingFiles []string `json:"cleaned_staging_files"`
	RecoveredBundles    int      `json:"recovered_bundles"`
}

type persistedBundleMeta struct {
	BundleID       string `json:"bundle_id"`
	CaseID         string `json:"case_id"`
	BundleDigest   string `json:"bundle_digest"`
	ManifestSHA256 string `json:"manifest_sha256"`
	TotalBytes     int64  `json:"total_bytes"`
}

type exportIndexManifest struct {
	SchemaVersion string                         `json:"schema_version"`
	Generation    uint64                         `json:"generation"`
	TotalBytes    int64                          `json:"total_bytes"`
	Operations    map[string]ExportOutcome       `json:"operations"`
	Bundles       map[string]persistedBundleMeta `json:"bundles"`
}

type sealedBlobSnap struct {
	path string
	sha  string
	size int64
}

// ExportStore atomically packages and indexes portable evidence/custody/derived bundles.
type ExportStore struct {
	mu             sync.Mutex
	cfg            ExportStoreConfig
	rootDir        string
	maxStorage     int64
	maxBundles     int
	lockFile       *os.File
	manifest       exportIndexManifest
	bundlesByID    map[string]BundleManifest
	recoveryReport RecoveryReport
	closed         bool
}

// CanonicalBundleBytes returns deterministic canonical JSON encoding of BundleManifest excluding
// BundleDigest, PublicKey, and Signature so signing/digest verification remain reproducible.
func CanonicalBundleBytes(m BundleManifest) ([]byte, error) {
	keys := make([]string, 0, len(m.FileChecksums))
	for k := range m.FileChecksums {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type checksumPair struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	pairs := make([]checksumPair, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, checksumPair{Path: k, SHA256: m.FileChecksums[k]})
	}

	evItems := append([]BoundEvidenceEntry(nil), m.EvidenceItems...)
	sort.Slice(evItems, func(i, j int) bool { return evItems[i].EvidenceID < evItems[j].EvidenceID })

	artItems := append([]BoundArtifactEntry(nil), m.DerivedArtifacts...)
	sort.Slice(artItems, func(i, j int) bool { return artItems[i].ArtifactID < artItems[j].ArtifactID })

	canon := struct {
		SchemaVersion     string               `json:"schema_version"`
		BundleID          string               `json:"bundle_id"`
		CaseID            string               `json:"case_id"`
		Provider          string               `json:"provider"`
		CreatedAt         string               `json:"created_at"`
		EvidenceItems     []BoundEvidenceEntry `json:"evidence_items"`
		DerivedArtifacts  []BoundArtifactEntry `json:"derived_artifacts,omitempty"`
		TimelineRelPath   string               `json:"timeline_rel_path,omitempty"`
		TimelineSHA256    string               `json:"timeline_sha256,omitempty"`
		TimelineCount     int                  `json:"timeline_count,omitempty"`
		HypothesesRelPath string               `json:"hypotheses_rel_path,omitempty"`
		HypothesesSHA256  string               `json:"hypotheses_sha256,omitempty"`
		HypothesesCount   int                  `json:"hypotheses_count,omitempty"`
		FileChecksums     []checksumPair       `json:"file_checksums"`
		Signed            bool                 `json:"signed"`
		KeyID             string               `json:"key_id,omitempty"`
	}{
		SchemaVersion:     m.SchemaVersion,
		BundleID:          m.BundleID,
		CaseID:            m.CaseID,
		Provider:          m.Provider,
		CreatedAt:         m.CreatedAt,
		EvidenceItems:     evItems,
		DerivedArtifacts:  artItems,
		TimelineRelPath:   m.TimelineRelPath,
		TimelineSHA256:    m.TimelineSHA256,
		TimelineCount:     m.TimelineCount,
		HypothesesRelPath: m.HypothesesRelPath,
		HypothesesSHA256:  m.HypothesesSHA256,
		HypothesesCount:   m.HypothesesCount,
		FileChecksums:     pairs,
		Signed:            m.Signed,
		KeyID:             m.KeyID,
	}
	return json.Marshal(canon)
}

// ComputeBundleDigest computes the 64-hex SHA-256 digest of CanonicalBundleBytes(m).
func ComputeBundleDigest(m BundleManifest) (string, error) {
	raw, err := CanonicalBundleBytes(m)
	if err != nil {
		return "", fmt.Errorf("%w: encode canonical bundle: %v", ErrMalformedExport, err)
	}
	sum := sha256.Sum256(append([]byte(signatureDomainPrefix), raw...))
	return hex.EncodeToString(sum[:]), nil
}

// CanonicalSignaturePayload builds the exact signed message attested by Ed25519 for a BundleManifest.
func CanonicalSignaturePayload(m BundleManifest) []byte {
	return []byte(fmt.Sprintf("%s%s:%s:%s:%s", signatureDomainPrefix, m.SchemaVersion, m.CaseID, m.BundleID, m.BundleDigest))
}

// OpenExportStore opens or initializes a locked, crash-recoverable ExportStore.
func OpenExportStore(cfg ExportStoreConfig) (*ExportStore, error) {
	if strings.TrimSpace(cfg.RootDir) == "" {
		return nil, ErrExportStoreRequired
	}
	absRoot, err := resolveSafeDir(cfg.RootDir)
	if err != nil {
		return nil, err
	}

	maxStorage := cfg.MaxStorageBytes
	if maxStorage <= 0 {
		maxStorage = DefaultMaxStorageBytes
	}
	maxBundles := cfg.MaxBundles
	if maxBundles <= 0 {
		maxBundles = DefaultMaxBundles
	}

	for _, sub := range []string{bundlesSubdir, stagingSubdir} {
		subPath := filepath.Join(absRoot, sub)
		if _, err := ensureNoSymlink(subPath); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(subPath, 0750); err != nil {
			return nil, fmt.Errorf("create export subdir %s: %w", sub, err)
		}
	}

	lockPath := filepath.Join(absRoot, exportLockFile)
	if _, err := ensureNoSymlink(lockPath); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		return nil, fmt.Errorf("open export lock: %w", err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lf.Close()
		return nil, ErrExportLockBusy
	}

	store := &ExportStore{
		cfg:         cfg,
		rootDir:     absRoot,
		maxStorage:  maxStorage,
		maxBundles:  maxBundles,
		lockFile:    lf,
		bundlesByID: make(map[string]BundleManifest),
		manifest: exportIndexManifest{
			SchemaVersion: SchemaVersion,
			Operations:    make(map[string]ExportOutcome),
			Bundles:       make(map[string]persistedBundleMeta),
		},
	}

	if err := store.recoverOnOpenUnlocked(); err != nil {
		_ = store.closeUnlocked()
		return nil, err
	}
	return store, nil
}

func (s *ExportStore) recoverOnOpenUnlocked() error {
	cleaned, err := s.cleanStagingUnlocked()
	if err != nil {
		return err
	}
	s.recoveryReport.CleanedStagingFiles = cleaned

	indexPath := filepath.Join(s.rootDir, exportIndexFile)
	if _, err := ensureNoSymlink(indexPath); err != nil {
		return err
	}
	data, err := os.ReadFile(indexPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read export index: %w", err)
	}

	var idx exportIndexManifest
	if err := json.Unmarshal(data, &idx); err != nil {
		return fmt.Errorf("%w: decode export index: %v", ErrMalformedExport, err)
	}
	if idx.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: export index schema %q", ErrUnsupportedVersion, idx.SchemaVersion)
	}
	if idx.Operations == nil {
		idx.Operations = make(map[string]ExportOutcome)
	}
	if idx.Bundles == nil {
		idx.Bundles = make(map[string]persistedBundleMeta)
	}

	loaded := make(map[string]BundleManifest, len(idx.Bundles))
	for bundleID, meta := range idx.Bundles {
		if err := validateIdentifier("bundle_id", bundleID); err != nil {
			return err
		}
		mPath := filepath.Join(s.rootDir, bundlesSubdir, bundleID, BundleManifestFile)
		if err := checkWithinDir(s.rootDir, mPath); err != nil {
			return err
		}
		gotSHA, _, err := hashRegularFile(mPath)
		if err != nil {
			return fmt.Errorf("%w: bundle manifest %s missing: %v", ErrMalformedExport, bundleID, err)
		}
		if gotSHA != meta.ManifestSHA256 {
			return fmt.Errorf("%w: bundle %s manifest digest mismatch", ErrMalformedExport, bundleID)
		}
		raw, err := os.ReadFile(mPath)
		if err != nil {
			return err
		}
		var bm BundleManifest
		if err := json.Unmarshal(raw, &bm); err != nil {
			return fmt.Errorf("%w: decode bundle %s: %v", ErrMalformedExport, bundleID, err)
		}
		if bm.SchemaVersion != SchemaVersion || bm.BundleDigest != meta.BundleDigest {
			return fmt.Errorf("%w: bundle %s metadata mismatch", ErrMalformedExport, bundleID)
		}
		loaded[bundleID] = bm
	}

	s.manifest = idx
	s.bundlesByID = loaded
	s.recoveryReport.RecoveredBundles = len(loaded)
	return nil
}

func (s *ExportStore) cleanStagingUnlocked() ([]string, error) {
	stagingDir := filepath.Join(s.rootDir, stagingSubdir)
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
			return nil, fmt.Errorf("clean export staging %s: %w", entry.Name(), err)
		}
		cleaned = append(cleaned, entry.Name())
	}
	sort.Strings(cleaned)
	return cleaned, nil
}

// LastRecoveryReport returns staging cleanup and recovered bundle counts from startup.
func (s *ExportStore) LastRecoveryReport() RecoveryReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return RecoveryReport{
		RecoveredBundles:    s.recoveryReport.RecoveredBundles,
		CleanedStagingFiles: append([]string(nil), s.recoveryReport.CleanedStagingFiles...),
	}
}

// Close releases the exclusive lock held by ExportStore.
func (s *ExportStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeUnlocked()
}

func (s *ExportStore) closeUnlocked() error {
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

// GetBundleManifest returns the committed BundleManifest for bundleID.
func (s *ExportStore) GetBundleManifest(bundleID string) (*BundleManifest, error) {
	if s == nil {
		return nil, ErrExportStoreRequired
	}
	if err := validateIdentifier("bundle_id", bundleID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrExportStoreClosed
	}
	bm, ok := s.bundlesByID[bundleID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBundleNotFound, bundleID)
	}
	cp := bm
	return &cp, nil
}

// PackageCaseBundle binds verified sealed evidence, custody ledgers, verified signed checkpoints,
// verified derived artifacts, and optional timeline/hypotheses into an atomic portable bundle
// directory without modifying any sealed source bytes.
func (s *ExportStore) PackageCaseBundle(ctx context.Context, deps ExportDeps, req ExportRequest) (*ExportOutcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrExportStoreRequired
	}
	if req.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %q", ErrUnsupportedVersion, req.SchemaVersion)
	}
	if err := validateIdentifier("bundle_id", req.BundleID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("case_id", req.CaseID); err != nil {
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

	evIDs := normalizeUniqueStrings(req.EvidenceIDs)
	if len(evIDs) == 0 {
		return nil, fmt.Errorf("%w: at least one sealed evidence_id must be selected", ErrMissingPrerequisite)
	}
	for _, id := range evIDs {
		if err := validateIdentifier("evidence_id", id); err != nil {
			return nil, err
		}
	}

	artIDs := normalizeUniqueStrings(req.ArtifactIDs)
	for _, id := range artIDs {
		if err := validateIdentifier("artifact_id", id); err != nil {
			return nil, err
		}
	}

	if deps.SealStore == nil || strings.TrimSpace(deps.SealRootDir) == "" || deps.LedgerStore == nil {
		return nil, fmt.Errorf("%w: SealStore, SealRootDir, and LedgerStore are required", ErrMissingPrerequisite)
	}
	if len(artIDs) > 0 && (deps.ArtifactStore == nil || strings.TrimSpace(deps.ArtifactRootDir) == "") {
		return nil, fmt.Errorf("%w: ArtifactStore and ArtifactRootDir are required for selected artifacts", ErrMissingPrerequisite)
	}
	if req.IncludeTimeline && deps.IndexStore == nil {
		return nil, fmt.Errorf("%w: IndexStore required when IncludeTimeline is enabled", ErrMissingPrerequisite)
	}
	if req.IncludeNotes && deps.FindingStore == nil {
		return nil, fmt.Errorf("%w: FindingStore required when IncludeNotes is enabled", ErrMissingPrerequisite)
	}
	if len(req.PrivateKey) > 0 {
		if len(req.PrivateKey) != ed25519.PrivateKeySize || strings.TrimSpace(req.KeyID) == "" {
			return nil, fmt.Errorf("%w: valid Ed25519 private key and key_id required for signed export", ErrMissingPrerequisite)
		}
	}

	absSealRoot, err := resolveExistingSafeDir(deps.SealRootDir)
	if err != nil {
		return nil, err
	}
	var absArtifactRoot string
	if len(artIDs) > 0 {
		absArtifactRoot, err = resolveExistingSafeDir(deps.ArtifactRootDir)
		if err != nil {
			return nil, err
		}
	}

	provider := req.Provider
	if provider == "" {
		provider = "local"
	}
	createdAt := strings.TrimSpace(req.CreatedAt)
	if createdAt == "" {
		createdAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, err := time.Parse(time.RFC3339Nano, createdAt); err != nil {
		return nil, fmt.Errorf("%w: invalid created_at %q", ErrMalformedExport, createdAt)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrExportStoreClosed
	}

	// Idempotent operation replay vs conflict detection.
	if req.OperationID != "" {
		if prev, exists := s.manifest.Operations[req.OperationID]; exists {
			if prev.CaseID != req.CaseID || prev.BundleID != req.BundleID || !bundleSelectionsEqual(prev.Manifest, evIDs, artIDs, req.IncludeTimeline, req.IncludeNotes) {
				return nil, fmt.Errorf("%w: operation %q previously packaged different bundle parameters", ErrExportConflict, req.OperationID)
			}
			replay := prev
			replay.IdempotentReplay = true
			return &replay, nil
		}
	}

	if existing, exists := s.bundlesByID[req.BundleID]; exists {
		if existing.CaseID == req.CaseID && bundleSelectionsEqual(existing, evIDs, artIDs, req.IncludeTimeline, req.IncludeNotes) && req.OperationID == "" {
			return nil, fmt.Errorf("%w: bundle %q already exists", ErrExportConflict, req.BundleID)
		}
		return nil, fmt.Errorf("%w: bundle %q already committed with different contents", ErrExportConflict, req.BundleID)
	}

	if len(s.bundlesByID)+1 > s.maxBundles {
		return nil, fmt.Errorf("%w: bundle quota %d exceeded", ErrExportQuotaExceeded, s.maxBundles)
	}
	if s.cfg.Faults.SimulateDiskFull {
		return nil, ErrDiskFull
	}

	nextGen := s.manifest.Generation + 1
	stageBundleDir := filepath.Join(s.rootDir, stagingSubdir, fmt.Sprintf("gen-%d-%s", nextGen, req.BundleID))
	if err := os.RemoveAll(stageBundleDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stageBundleDir, 0750); err != nil {
		return nil, fmt.Errorf("create staged bundle dir: %w", err)
	}
	committed := false
	defer func() {
		if !committed && !s.cfg.Faults.FailAfterStageBeforeCommit {
			_ = os.RemoveAll(stageBundleDir)
		}
	}()

	fileChecksums := make(map[string]string)
	sealedSnaps := make(map[string]sealedBlobSnap, len(evIDs))
	boundEvidence := make([]BoundEvidenceEntry, 0, len(evIDs))
	selectedEvSet := make(map[string]evidence.SealedManifest, len(evIDs))
	var stagedBytes int64

	// 1. Verify and stage selected sealed evidence, custody chain, and signed checkpoints.
	for _, evID := range evIDs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		vr, vErr := evidence.VerifyStoreEvidence(ctx, deps.SealStore, req.CaseID, evID, evidence.VerifyOptions{})
		if vErr != nil || vr == nil || !vr.Verified {
			return nil, fmt.Errorf("%w: evidence %s/%s failed seal verification: %v", ErrMissingPrerequisite, req.CaseID, evID, vErr)
		}
		sm, sErr := deps.SealStore.GetSealedManifest(req.CaseID, evID)
		if sErr != nil || sm == nil || !sm.Sealed {
			return nil, fmt.Errorf("%w: sealed manifest %s/%s unavailable", ErrMissingPrerequisite, req.CaseID, evID)
		}
		srcBlobPath := filepath.Join(absSealRoot, filepath.FromSlash(sm.BlobRelPath))
		if err := checkWithinDir(absSealRoot, srcBlobPath); err != nil {
			return nil, err
		}
		preSHA, preSize, hErr := hashRegularFile(srcBlobPath)
		if hErr != nil || preSHA != sm.SHA256 || preSize != sm.SizeBytes {
			return nil, ErrSealedBytesTampered
		}
		sealedSnaps[evID] = sealedBlobSnap{path: srcBlobPath, sha: preSHA, size: preSize}
		selectedEvSet[evID] = *sm

		// Verify custody chain and load events.
		chainOK, cErr := deps.LedgerStore.VerifyChain(req.CaseID, evID)
		if cErr != nil || !chainOK {
			return nil, fmt.Errorf("%w: custody chain verification failed for %s/%s: %v", ErrCheckpointFailed, req.CaseID, evID, cErr)
		}
		custodyEvents, lErr := deps.LedgerStore.ListEvents(req.CaseID, evID)
		if lErr != nil || len(custodyEvents) == 0 {
			return nil, fmt.Errorf("%w: custody events missing for %s/%s", ErrMissingPrerequisite, req.CaseID, evID)
		}
		curRoot, rErr := deps.LedgerStore.CurrentRoot(req.CaseID, evID)
		if rErr != nil {
			return nil, fmt.Errorf("%w: custody root unavailable for %s/%s: %v", ErrMissingPrerequisite, req.CaseID, evID, rErr)
		}

		// Load and verify signed custody checkpoint.
		chk, chkErr := resolveCheckpoint(ctx, deps, req.CaseID, evID)
		if chkErr != nil {
			return nil, chkErr
		}
		chkRes, vChkErr := custody.VerifyCheckpoint(ctx, deps.LedgerStore, chk, deps.CheckpointOpts)
		if vChkErr != nil || chkRes == nil || !chkRes.Verified {
			return nil, fmt.Errorf("%w: %v", ErrCheckpointFailed, vChkErr)
		}

		// Copy sealed blob read-only into staged bundle.
		relBlob := filepath.ToSlash(filepath.Join("evidence", evID, "blob.dat"))
		dstBlob := filepath.Join(stageBundleDir, filepath.FromSlash(relBlob))
		copiedSHA, copiedSize, copyErr := copyRegularFileVerify(srcBlobPath, dstBlob)
		if copyErr != nil {
			return nil, copyErr
		}
		if copiedSHA != sm.SHA256 || copiedSize != sm.SizeBytes {
			return nil, ErrSealedBytesTampered
		}
		fileChecksums[relBlob] = copiedSHA
		stagedBytes += copiedSize

		relManifest := filepath.ToSlash(filepath.Join("evidence", evID, "manifest.json"))
		mSHA, mSz, err := writeCanonicalJSON(filepath.Join(stageBundleDir, filepath.FromSlash(relManifest)), sm)
		if err != nil {
			return nil, err
		}
		fileChecksums[relManifest] = mSHA
		stagedBytes += mSz

		relCustody := filepath.ToSlash(filepath.Join("evidence", evID, "custody.json"))
		cSHA, cSz, err := writeCanonicalJSON(filepath.Join(stageBundleDir, filepath.FromSlash(relCustody)), custodyEvents)
		if err != nil {
			return nil, err
		}
		fileChecksums[relCustody] = cSHA
		stagedBytes += cSz

		relChk := filepath.ToSlash(filepath.Join("evidence", evID, "checkpoint.json"))
		kSHA, kSz, err := writeCanonicalJSON(filepath.Join(stageBundleDir, filepath.FromSlash(relChk)), chk)
		if err != nil {
			return nil, err
		}
		fileChecksums[relChk] = kSHA
		stagedBytes += kSz

		boundEvidence = append(boundEvidence, BoundEvidenceEntry{
			EvidenceID:           evID,
			Manifest:             *sm,
			BundleBlobRelPath:    relBlob,
			BlobSHA256:           copiedSHA,
			BlobSizeBytes:        copiedSize,
			ManifestRelPath:      relManifest,
			ManifestSHA256:       mSHA,
			CustodyEventsRelPath: relCustody,
			CustodyEventsSHA256:  cSHA,
			CustodyEventCount:    len(custodyEvents),
			CustodyRoot:          curRoot,
			CheckpointRelPath:    relChk,
			CheckpointSHA256:     kSHA,
			Checkpoint:           chk,
		})
	}

	// 2. Verify and stage selected derived artifacts, ensuring all artifact inputs match selected evidence.
	boundArtifacts := make([]BoundArtifactEntry, 0, len(artIDs))
	for _, artID := range artIDs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		vr, vErr := deps.ArtifactStore.VerifyStoredArtifact(ctx, deps.SealStore, req.CaseID, artID, artifacts.VerifyOptions{})
		if vErr != nil || vr == nil || !vr.Verified {
			return nil, fmt.Errorf("%w: derived artifact %s/%s failed verification: %v", ErrMissingPrerequisite, req.CaseID, artID, vErr)
		}
		dm, gErr := deps.ArtifactStore.GetManifest(req.CaseID, artID)
		if gErr != nil || dm == nil {
			return nil, fmt.Errorf("%w: derived manifest %s/%s missing: %v", ErrMissingPrerequisite, req.CaseID, artID, gErr)
		}
		for _, in := range dm.Inputs {
			boundEv, ok := selectedEvSet[in.EvidenceID]
			if !ok || boundEv.SHA256 != in.SHA256 || boundEv.SizeBytes != in.SizeBytes {
				return nil, fmt.Errorf("%w: artifact %s references evidence %s missing or mismatched in selected export", ErrInputBindingMismatch, artID, in.EvidenceID)
			}
		}

		srcPayload := filepath.Join(absArtifactRoot, filepath.FromSlash(dm.Output.RelPath))
		if err := checkWithinDir(absArtifactRoot, srcPayload); err != nil {
			return nil, err
		}
		relPayload := filepath.ToSlash(filepath.Join("artifacts", artID, "output.json"))
		dstPayload := filepath.Join(stageBundleDir, filepath.FromSlash(relPayload))
		pSHA, pSz, pErr := copyRegularFileVerify(srcPayload, dstPayload)
		if pErr != nil {
			return nil, pErr
		}
		if pSHA != dm.Output.SHA256 || pSz != dm.Output.SizeBytes {
			return nil, fmt.Errorf("%w: derived artifact %s output digest mismatch", ErrMalformedExport, artID)
		}
		fileChecksums[relPayload] = pSHA
		stagedBytes += pSz

		relArtManifest := filepath.ToSlash(filepath.Join("artifacts", artID, "manifest.json"))
		amSHA, amSz, err := writeCanonicalJSON(filepath.Join(stageBundleDir, filepath.FromSlash(relArtManifest)), dm)
		if err != nil {
			return nil, err
		}
		fileChecksums[relArtManifest] = amSHA
		stagedBytes += amSz

		boundArtifacts = append(boundArtifacts, BoundArtifactEntry{
			ArtifactID:       artID,
			Manifest:         *dm,
			ManifestRelPath:  relArtManifest,
			ManifestSHA256:   amSHA,
			PayloadRelPath:   relPayload,
			PayloadSHA256:    pSHA,
			PayloadSizeBytes: pSz,
		})
	}

	// 3. Optionally bind read-only indexed timeline entries and separated analyst hypotheses.
	var timelineRel, timelineSHA string
	timelineCount := 0
	if req.IncludeTimeline {
		entries, tErr := deps.IndexStore.ListEntries(req.CaseID)
		if tErr != nil {
			return nil, fmt.Errorf("%w: list timeline entries: %v", ErrMissingPrerequisite, tErr)
		}
		timelineRel = "timeline/entries.json"
		sha, sz, wErr := writeCanonicalJSON(filepath.Join(stageBundleDir, filepath.FromSlash(timelineRel)), entries)
		if wErr != nil {
			return nil, wErr
		}
		timelineSHA = sha
		timelineCount = len(entries)
		fileChecksums[timelineRel] = sha
		stagedBytes += sz
	}

	var hypsRel, hypsSHA string
	hypsCount := 0
	if req.IncludeNotes {
		hyps, hErr := deps.FindingStore.ListHypotheses(req.CaseID)
		if hErr != nil {
			return nil, fmt.Errorf("%w: list hypotheses: %v", ErrMissingPrerequisite, hErr)
		}
		hypsRel = "findings/hypotheses.json"
		sha, sz, wErr := writeCanonicalJSON(filepath.Join(stageBundleDir, filepath.FromSlash(hypsRel)), hyps)
		if wErr != nil {
			return nil, wErr
		}
		hypsSHA = sha
		hypsCount = len(hyps)
		fileChecksums[hypsRel] = sha
		stagedBytes += sz
	}

	signed := len(req.PrivateKey) == ed25519.PrivateKeySize
	bundleManifest := BundleManifest{
		SchemaVersion:     SchemaVersion,
		BundleID:          req.BundleID,
		CaseID:            req.CaseID,
		Provider:          provider,
		CreatedAt:         createdAt,
		EvidenceItems:     boundEvidence,
		DerivedArtifacts:  boundArtifacts,
		TimelineRelPath:   timelineRel,
		TimelineSHA256:    timelineSHA,
		TimelineCount:     timelineCount,
		HypothesesRelPath: hypsRel,
		HypothesesSHA256:  hypsSHA,
		HypothesesCount:   hypsCount,
		FileChecksums:     fileChecksums,
		Signed:            signed,
		KeyID:             req.KeyID,
	}

	digest, err := ComputeBundleDigest(bundleManifest)
	if err != nil {
		return nil, err
	}
	bundleManifest.BundleDigest = digest
	if signed {
		pub := req.PrivateKey.Public().(ed25519.PublicKey)
		bundleManifest.PublicKey = hex.EncodeToString(pub)
		sig := ed25519.Sign(req.PrivateKey, CanonicalSignaturePayload(bundleManifest))
		bundleManifest.Signature = hex.EncodeToString(sig)
	}

	manifestPath := filepath.Join(stageBundleDir, BundleManifestFile)
	manifestSHA, manifestSz, err := writeCanonicalJSON(manifestPath, bundleManifest)
	if err != nil {
		return nil, err
	}
	stagedBytes += manifestSz

	if s.manifest.TotalBytes+stagedBytes > s.maxStorage {
		return nil, fmt.Errorf("%w: export store byte quota exceeded", ErrExportQuotaExceeded)
	}
	if s.cfg.Faults.FailAfterStageBeforeCommit {
		return nil, ErrInterrupted
	}

	finalBundleDir := filepath.Join(s.rootDir, bundlesSubdir, req.BundleID)
	if err := checkWithinDir(s.rootDir, finalBundleDir); err != nil {
		return nil, err
	}
	if _, err := ensureNoSymlink(finalBundleDir); err != nil {
		return nil, err
	}
	if err := os.Rename(stageBundleDir, finalBundleDir); err != nil {
		return nil, fmt.Errorf("commit export bundle %s: %w", req.BundleID, err)
	}
	committed = true
	if s.cfg.SyncDir {
		_ = syncDir(filepath.Dir(finalBundleDir))
	}

	outcome := ExportOutcome{
		BundleID:     req.BundleID,
		CaseID:       req.CaseID,
		BundleDir:    finalBundleDir,
		BundleDigest: digest,
		Generation:   nextGen,
		Signed:       signed,
		Manifest:     bundleManifest,
	}

	nextManifest := s.manifest
	nextManifest.Generation = nextGen
	nextManifest.TotalBytes += stagedBytes
	nextOps := make(map[string]ExportOutcome, len(s.manifest.Operations)+1)
	for k, v := range s.manifest.Operations {
		nextOps[k] = v
	}
	if req.OperationID != "" {
		nextOps[req.OperationID] = outcome
	}
	nextBundles := make(map[string]persistedBundleMeta, len(s.manifest.Bundles)+1)
	for k, v := range s.manifest.Bundles {
		nextBundles[k] = v
	}
	nextBundles[req.BundleID] = persistedBundleMeta{
		BundleID:       req.BundleID,
		CaseID:         req.CaseID,
		BundleDigest:   digest,
		ManifestSHA256: manifestSHA,
		TotalBytes:     stagedBytes,
	}
	nextManifest.Operations = nextOps
	nextManifest.Bundles = nextBundles

	if err := s.persistIndexUnlocked(nextManifest); err != nil {
		return nil, err
	}
	s.manifest = nextManifest
	s.bundlesByID[req.BundleID] = bundleManifest

	// Re-hash every original sealed source blob post-commit to confirm immutability.
	for _, snap := range sealedSnaps {
		postSHA, postSize, hErr := hashRegularFile(snap.path)
		if hErr != nil || postSHA != snap.sha || postSize != snap.size {
			return nil, ErrSealedBytesTampered
		}
	}

	return &outcome, nil
}

func resolveCheckpoint(ctx context.Context, deps ExportDeps, caseID, evidenceID string) (custody.Checkpoint, error) {
	if deps.Checkpoints != nil {
		if chk, ok := deps.Checkpoints[evidenceID]; ok {
			return chk, nil
		}
	}
	if deps.CheckpointStore != nil {
		chk, err := deps.CheckpointStore.GetLatestCheckpoint(ctx, caseID, evidenceID)
		if err == nil && chk != nil {
			return *chk, nil
		}
	}
	return custody.Checkpoint{}, fmt.Errorf("%w: verified custody checkpoint missing for %s/%s", ErrMissingPrerequisite, caseID, evidenceID)
}

func bundleSelectionsEqual(bm BundleManifest, evIDs, artIDs []string, includeTimeline, includeNotes bool) bool {
	if len(bm.EvidenceItems) != len(evIDs) || len(bm.DerivedArtifacts) != len(artIDs) {
		return false
	}
	if (bm.TimelineRelPath != "") != includeTimeline || (bm.HypothesesRelPath != "") != includeNotes {
		return false
	}
	gotEv := make([]string, len(bm.EvidenceItems))
	for i, e := range bm.EvidenceItems {
		gotEv[i] = e.EvidenceID
	}
	sort.Strings(gotEv)
	for i := range evIDs {
		if gotEv[i] != evIDs[i] {
			return false
		}
	}
	gotArt := make([]string, len(bm.DerivedArtifacts))
	for i, a := range bm.DerivedArtifacts {
		gotArt[i] = a.ArtifactID
	}
	sort.Strings(gotArt)
	for i := range artIDs {
		if gotArt[i] != artIDs[i] {
			return false
		}
	}
	return true
}

func (s *ExportStore) persistIndexUnlocked(idx exportIndexManifest) error {
	raw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := filepath.Join(s.rootDir, stagingSubdir, fmt.Sprintf("export-index-%d.tmp", idx.Generation))
	if err := writeSyncFile(tmp, raw, 0640); err != nil {
		return err
	}
	final := filepath.Join(s.rootDir, exportIndexFile)
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("commit export index: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(s.rootDir)
	}
	return nil
}

func writeCanonicalJSON(path string, v any) (string, int64, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return "", 0, err
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", 0, err
	}
	raw = append(raw, '\n')
	if err := writeSyncFile(path, raw, 0640); err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), int64(len(raw)), nil
}

func copyRegularFileVerify(srcPath, dstPath string) (string, int64, error) {
	info, err := os.Lstat(srcPath)
	if err != nil {
		return "", 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", 0, fmt.Errorf("%w: %s", ErrSymlinkRejected, srcPath)
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%w: %s not regular", ErrPathTraversal, srcPath)
	}
	if err := os.MkdirAll(filepath.Dir(dstPath), 0750); err != nil {
		return "", 0, err
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()

	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), in)
	if copyErr != nil {
		_ = out.Close()
		return "", 0, copyErr
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return "", 0, err
	}
	if err := out.Close(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
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
		return "", fmt.Errorf("create export dir %s: %w", absDir, err)
	}
	return absDir, nil
}

func resolveExistingSafeDir(dir string) (string, error) {
	absDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if _, err := ensureNoSymlink(absDir); err != nil {
		return "", err
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
		return "", 0, fmt.Errorf("%w: %s not regular", ErrPathTraversal, path)
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

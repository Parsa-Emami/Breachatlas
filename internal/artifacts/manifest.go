package artifacts

import (
	"bytes"
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

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

const (
	SchemaVersion           = "1"
	DefaultMaxStorageBytes  = int64(20 * 1024 * 1024 * 1024) // 20 GiB planning target
	DefaultMaxPayloadBytes  = int64(64 * 1024 * 1024)        // 64 MiB bounded derived output
	DefaultOutputMediaType  = "application/json"
	artifactsSubdir         = "artifacts"
	manifestsSubdir         = "manifests"
	stagingSubdir           = "staging"
	indexFileName           = "artifact-index.json"
	lockFileName            = ".artifact.lock"
	outputFileName          = "output.json"
)

var (
	ErrArtifactStoreRequired  = errors.New("artifact store root directory is required")
	ErrArtifactStoreClosed    = errors.New("artifact store closed")
	ErrArtifactLockBusy       = errors.New("artifact store lock busy: another writer holds exclusive lock")
	ErrMissingPrerequisite    = errors.New("missing prerequisite for derived artifact")
	ErrInvalidManifest        = errors.New("invalid derived artifact manifest")
	ErrUnsupportedVersion     = errors.New("unsupported derived artifact schema version")
	ErrMalformedPayload       = errors.New("malformed derived artifact payload")
	ErrInputBindingMismatch   = errors.New("derived manifest input hash or metadata does not match sealed input")
	ErrOutputTampered         = errors.New("derived output bytes do not match manifest digest or size")
	ErrToolBindingInvalid     = errors.New("invalid or non-allowlisted analyzer tool binding")
	ErrConfigHashMismatch     = errors.New("missing or malformed analyzer config hash")
	ErrManifestDigestMismatch = errors.New("derived manifest digest mismatch")
	ErrManifestConflict       = errors.New("artifact or operation ID reused with conflicting parameters")
	ErrArtifactNotFound       = errors.New("derived artifact manifest not found")
	ErrUntrustedSigner        = errors.New("derived manifest signer missing or untrusted")
	ErrInvalidSignature       = errors.New("derived manifest Ed25519 signature verification failed")
	ErrPathTraversal          = errors.New("path traversal or invalid identifier rejected")
	ErrSymlinkRejected        = errors.New("symlink rejected in artifact store path")
	ErrInterrupted            = errors.New("derived artifact write interrupted before manifest commit")
	ErrDiskFull               = errors.New("disk full: derived artifact write aborted")
	ErrStorageQuotaExceeded   = errors.New("artifact store quota exceeded")
	ErrSealedBytesTampered    = errors.New("sealed source bytes modified during artifact derivation")
)

var (
	identifierRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	digestRegex     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	mediaTypeRegex  = regexp.MustCompile(`^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$`)
	allowedProviders = map[string]bool{
		"":            true,
		"local":       true,
		"breachatlas": true,
	}
	allowlistedAnalyzers = map[string]bool{
		analyzers.AnalyzerCSV:  true,
		analyzers.AnalyzerJSON: true,
	}
)

// InputBinding binds a single sealed input evidence item into a derived artifact manifest.
type InputBinding struct {
	CaseID      string `json:"case_id"`
	EvidenceID  string `json:"evidence_id"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	MediaType   string `json:"media_type"`
	CustodyRoot string `json:"custody_root,omitempty"`
}

// OutputBinding binds the materialized derived output bytes on disk to the manifest.
type OutputBinding struct {
	ArtifactID  string `json:"artifact_id"`
	MediaType   string `json:"media_type"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	RecordCount int    `json:"record_count"`
	RelPath     string `json:"rel_path"`
}

// DerivedManifest proves the exact provenance linking derived output to sealed input hashes,
// allowlisted tool version, and deterministic analyzer configuration hash.
type DerivedManifest struct {
	SchemaVersion    string         `json:"schema_version"`
	ManifestDigest   string         `json:"manifest_digest"`
	Generation       uint64         `json:"generation"`
	OperationID      string         `json:"operation_id,omitempty"`
	ArtifactID       string         `json:"artifact_id"`
	CaseID           string         `json:"case_id"`
	RunID            string         `json:"run_id,omitempty"`
	Inputs           []InputBinding `json:"inputs"`
	InputHashes      []string       `json:"input_hashes"`
	AnalyzerID       string         `json:"analyzer_id"`
	ToolVersion      string         `json:"tool_version"`
	Provider         string         `json:"provider"`
	ConfigHash       string         `json:"config_hash"`
	NonExecuting     bool           `json:"non_executing"`
	ReadOnly         bool           `json:"read_only"`
	Output           OutputBinding  `json:"output"`
	CreatedAt        string         `json:"created_at"`
	KeyID            string         `json:"key_id,omitempty"`
	PublicKey        string         `json:"public_key,omitempty"`
	Signature        string         `json:"signature,omitempty"`
	IdempotentReplay bool           `json:"idempotent_replay,omitempty"`
}

// DerivedPayload is the deterministic JSON document written for derived analyzer artifacts.
type DerivedPayload struct {
	SchemaVersion string                   `json:"schema_version"`
	CaseID        string                   `json:"case_id"`
	EvidenceID    string                   `json:"evidence_id"`
	ArtifactID    string                   `json:"artifact_id"`
	RunID         string                   `json:"run_id,omitempty"`
	AnalyzerID    string                   `json:"analyzer_id"`
	ToolVersion   string                   `json:"tool_version"`
	ConfigHash    string                   `json:"config_hash"`
	InputHashes   []string                 `json:"input_hashes"`
	AnalyzedAt    string                   `json:"analyzed_at"`
	RecordCount   int                      `json:"record_count"`
	Records       []analyzers.ParsedRecord `json:"records"`
}

// StoreFaults injects deterministic failures at persistence boundaries for recovery testing.
type StoreFaults struct {
	SimulateDiskFull               bool
	FailAfterPayloadBeforeManifest bool
}

// StoreConfig configures a durable local ArtifactStore.
type StoreConfig struct {
	RootDir         string
	MaxStorageBytes int64
	MaxPayloadBytes int64
	SyncDir         bool
	Faults          StoreFaults
}

// DeriveRequest specifies provenance parameters and optional Ed25519 signing credentials.
type DeriveRequest struct {
	OperationID      string             `json:"operation_id,omitempty"`
	ArtifactID       string             `json:"artifact_id"`
	CaseID           string             `json:"case_id"`
	Provider         string             `json:"provider,omitempty"`
	AdditionalInputs []string           `json:"additional_inputs,omitempty"` // extra evidence_ids within CaseID
	CreatedAt        string             `json:"created_at,omitempty"`
	KeyID            string             `json:"key_id,omitempty"`
	PrivateKey       ed25519.PrivateKey `json:"-"`
}

// VerifyOptions configures provenance, signature, and read-only sealed input verification.
type VerifyOptions struct {
	TrustedKeys      map[string]ed25519.PublicKey
	RequireSignature bool
}

// VerificationResult reports verified provenance bindings.
type VerificationResult struct {
	Verified       bool     `json:"verified"`
	ArtifactID     string   `json:"artifact_id"`
	CaseID         string   `json:"case_id"`
	ManifestDigest string   `json:"manifest_digest"`
	InputHashes    []string `json:"input_hashes"`
	ToolVersion    string   `json:"tool_version"`
	ConfigHash     string   `json:"config_hash"`
	OutputSHA256   string   `json:"output_sha256"`
	SignatureValid bool     `json:"signature_valid"`
	InputsVerified bool     `json:"inputs_verified"`
}

// RecoveryReport summarizes uncommitted staging files cleaned on ArtifactStore startup.
type RecoveryReport struct {
	CleanedStagingFiles []string `json:"cleaned_staging_files"`
	RecoveredArtifacts  int      `json:"recovered_artifacts"`
}

type artifactIndex struct {
	SchemaVersion string                     `json:"schema_version"`
	Generation    uint64                     `json:"generation"`
	TotalBytes    int64                      `json:"total_bytes"`
	Operations    map[string]DerivedManifest `json:"operations"`
	Manifests     map[string]DerivedManifest `json:"manifests"` // "caseID/artifactID" -> DerivedManifest
}

// ArtifactStore manages durable local storage and provenance verification of derived artifacts.
type ArtifactStore struct {
	mu             sync.Mutex
	cfg            StoreConfig
	rootDir        string
	maxStorage     int64
	maxPayload     int64
	lockFile       *os.File
	closed         bool
	index          artifactIndex
	recoveryReport RecoveryReport
}

type canonicalManifestPayload struct {
	SchemaVersion string         `json:"schema_version"`
	ArtifactID    string         `json:"artifact_id"`
	CaseID        string         `json:"case_id"`
	RunID         string         `json:"run_id,omitempty"`
	Inputs        []InputBinding `json:"inputs"`
	InputHashes   []string       `json:"input_hashes"`
	AnalyzerID    string         `json:"analyzer_id"`
	ToolVersion   string         `json:"tool_version"`
	Provider      string         `json:"provider"`
	ConfigHash    string         `json:"config_hash"`
	NonExecuting  bool           `json:"non_executing"`
	ReadOnly      bool           `json:"read_only"`
	Output        OutputBinding  `json:"output"`
	CreatedAt     string         `json:"created_at"`
}

// CanonicalManifestBytes returns deterministic canonical bytes representing the manifest provenance bindings.
func CanonicalManifestBytes(m DerivedManifest) ([]byte, error) {
	inputs := make([]InputBinding, len(m.Inputs))
	copy(inputs, m.Inputs)
	sort.Slice(inputs, func(i, j int) bool {
		if inputs[i].CaseID != inputs[j].CaseID {
			return inputs[i].CaseID < inputs[j].CaseID
		}
		if inputs[i].EvidenceID != inputs[j].EvidenceID {
			return inputs[i].EvidenceID < inputs[j].EvidenceID
		}
		return inputs[i].SHA256 < inputs[j].SHA256
	})

	hashes := make([]string, len(m.InputHashes))
	copy(hashes, m.InputHashes)
	sort.Strings(hashes)

	payload := canonicalManifestPayload{
		SchemaVersion: m.SchemaVersion,
		ArtifactID:    m.ArtifactID,
		CaseID:        m.CaseID,
		RunID:         m.RunID,
		Inputs:        inputs,
		InputHashes:   hashes,
		AnalyzerID:    m.AnalyzerID,
		ToolVersion:   m.ToolVersion,
		Provider:      m.Provider,
		ConfigHash:    m.ConfigHash,
		NonExecuting:  m.NonExecuting,
		ReadOnly:      m.ReadOnly,
		Output:        m.Output,
		CreatedAt:     m.CreatedAt,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical derived manifest: %w", err)
	}
	return append([]byte("breachatlas:derived-manifest:v1:"), raw...), nil
}

// ComputeManifestDigest calculates the SHA-256 hex digest over CanonicalManifestBytes.
func ComputeManifestDigest(m DerivedManifest) (string, error) {
	canon, err := CanonicalManifestBytes(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// CanonicalSignaturePayload builds the domain-separated signing payload binding KeyID and ManifestDigest.
func CanonicalSignaturePayload(m DerivedManifest) []byte {
	return []byte(fmt.Sprintf("breachatlas:derived-manifest-sig:v1:%s:%s:%s:%s", m.CaseID, m.ArtifactID, m.KeyID, m.ManifestDigest))
}

func validateIdentifier(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidManifest, field)
	}
	if strings.ContainsRune(value, '\x00') || strings.Contains(value, "..") || strings.ContainsAny(value, "/\\") {
		return fmt.Errorf("%w: %s contains unsafe path characters", ErrPathTraversal, field)
	}
	if !identifierRegex.MatchString(value) {
		return fmt.Errorf("%w: invalid %s %q", ErrInvalidManifest, field, value)
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
		return fmt.Errorf("%w: %s escapes store root", ErrPathTraversal, target)
	}
	return nil
}

func resolveSafeDir(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", ErrArtifactStoreRequired
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
			return "", fmt.Errorf("create artifact store dir %s: %w", absDir, err)
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
			return "", fmt.Errorf("%w: %s is not a directory", ErrInvalidManifest, absDir)
		}
	}
	return absDir, nil
}

// OpenArtifactStore opens or initializes a durable local ArtifactStore, acquires an exclusive
// writer lock, cleans uncommitted staging artifacts from prior interrupted runs, and verifies committed entries.
func OpenArtifactStore(cfg StoreConfig) (*ArtifactStore, error) {
	rootDir, err := resolveSafeDir(cfg.RootDir)
	if err != nil {
		return nil, err
	}

	maxStorage := cfg.MaxStorageBytes
	if maxStorage == 0 {
		maxStorage = DefaultMaxStorageBytes
	}
	if maxStorage < 0 {
		return nil, fmt.Errorf("%w: max_storage_bytes must be non-negative", ErrInvalidManifest)
	}

	maxPayload := cfg.MaxPayloadBytes
	if maxPayload == 0 {
		maxPayload = DefaultMaxPayloadBytes
	}
	if maxPayload < 1 {
		return nil, fmt.Errorf("%w: max_payload_bytes must be positive", ErrInvalidManifest)
	}

	for _, rel := range []string{artifactsSubdir, manifestsSubdir, stagingSubdir} {
		sub := filepath.Join(rootDir, rel)
		if err := os.MkdirAll(sub, 0750); err != nil {
			return nil, fmt.Errorf("create artifact store subdir %s: %w", rel, err)
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
		return nil, fmt.Errorf("open artifact lock: %w", err)
	}
	if err := syscall.Flock(int(lockF.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockF.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrArtifactLockBusy
		}
		return nil, fmt.Errorf("acquire artifact lock: %w", err)
	}

	s := &ArtifactStore{
		cfg:        cfg,
		rootDir:    rootDir,
		maxStorage: maxStorage,
		maxPayload: maxPayload,
		lockFile:   lockF,
		index: artifactIndex{
			SchemaVersion: SchemaVersion,
			Operations:    make(map[string]DerivedManifest),
			Manifests:     make(map[string]DerivedManifest),
		},
	}

	if err := s.recoverOnOpenUnlocked(); err != nil {
		_ = s.closeUnlocked()
		return nil, err
	}

	return s, nil
}

func (s *ArtifactStore) recoverOnOpenUnlocked() error {
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
		return fmt.Errorf("read artifact index: %w", err)
	}

	var idx artifactIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return fmt.Errorf("%w: corrupt artifact index: %v", ErrInvalidManifest, err)
	}
	if idx.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported artifact index version %q", ErrUnsupportedVersion, idx.SchemaVersion)
	}
	if idx.Operations == nil {
		idx.Operations = make(map[string]DerivedManifest)
	}
	if idx.Manifests == nil {
		idx.Manifests = make(map[string]DerivedManifest)
	}

	for key, indexed := range idx.Manifests {
		manifestPath := filepath.Join(s.rootDir, manifestsSubdir, indexed.CaseID, indexed.ArtifactID+".manifest.json")
		if err := checkWithinDir(s.rootDir, manifestPath); err != nil {
			return err
		}
		if _, err := ensureNoSymlink(manifestPath); err != nil {
			return err
		}
		raw, err := os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("%w: missing manifest file for %s: %v", ErrInvalidManifest, key, err)
		}
		var onDisk DerivedManifest
		if err := json.Unmarshal(raw, &onDisk); err != nil {
			return fmt.Errorf("%w: corrupt manifest file for %s: %v", ErrInvalidManifest, key, err)
		}
		if err := ValidateManifestStructure(onDisk); err != nil {
			return fmt.Errorf("%w: manifest %s invalid on recovery: %v", ErrInvalidManifest, key, err)
		}
		if onDisk.ManifestDigest != indexed.ManifestDigest || onDisk.Output.SHA256 != indexed.Output.SHA256 {
			return fmt.Errorf("%w: recovered manifest digest mismatch for %s", ErrManifestDigestMismatch, key)
		}
		if err := s.verifyStoredPayloadUnlocked(onDisk); err != nil {
			return fmt.Errorf("recover derived payload for %s: %w", key, err)
		}
	}

	s.index = idx
	s.recoveryReport.RecoveredArtifacts = len(idx.Manifests)
	return nil
}

func (s *ArtifactStore) cleanStagingUnlocked() ([]string, error) {
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

// LastRecoveryReport returns staging cleanup and recovered manifest counts from OpenArtifactStore.
func (s *ArtifactStore) LastRecoveryReport() RecoveryReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := RecoveryReport{
		RecoveredArtifacts:  s.recoveryReport.RecoveredArtifacts,
		CleanedStagingFiles: append([]string(nil), s.recoveryReport.CleanedStagingFiles...),
	}
	return out
}

// Close releases the exclusive lock held by ArtifactStore.
func (s *ArtifactStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeUnlocked()
}

func (s *ArtifactStore) closeUnlocked() error {
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

// DeriveFromIsolatedRun binds the output of an isolated sandbox analyzer run to its sealed input hashes,
// tool version, and config hash, persisting the artifact and manifest atomically.
func (s *ArtifactStore) DeriveFromIsolatedRun(
	ctx context.Context,
	sealStore *evidence.SealStore,
	sealRootDir string,
	run *analyzers.IsolatedRunResult,
	req DeriveRequest,
) (*DerivedManifest, error) {
	if run == nil {
		return nil, fmt.Errorf("%w: isolated run result is required", ErrMissingPrerequisite)
	}
	if strings.TrimSpace(run.RunID) == "" {
		return nil, fmt.Errorf("%w: isolated run_id is required", ErrMissingPrerequisite)
	}
	if err := validateIdentifier("run_id", run.RunID); err != nil {
		return nil, err
	}
	if run.Analysis == nil {
		return nil, fmt.Errorf("%w: isolated run contains no analysis result", ErrMissingPrerequisite)
	}
	return s.deriveInternal(ctx, sealStore, sealRootDir, run.Analysis, run.RunID, req)
}

// DeriveFromAnalysis binds an AnalysisResult to its sealed input hashes, tool version, and config hash,
// persisting the derived output and manifest atomically.
func (s *ArtifactStore) DeriveFromAnalysis(
	ctx context.Context,
	sealStore *evidence.SealStore,
	sealRootDir string,
	res *analyzers.AnalysisResult,
	req DeriveRequest,
) (*DerivedManifest, error) {
	return s.deriveInternal(ctx, sealStore, sealRootDir, res, "", req)
}

func (s *ArtifactStore) deriveInternal(
	ctx context.Context,
	sealStore *evidence.SealStore,
	sealRootDir string,
	res *analyzers.AnalysisResult,
	runID string,
	req DeriveRequest,
) (*DerivedManifest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrArtifactStoreRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrArtifactStoreClosed
	}

	if err := validateIdentifier("case_id", req.CaseID); err != nil {
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
		return nil, fmt.Errorf("%w: provider %q unsupported in local-first profile", ErrMissingPrerequisite, req.Provider)
	}
	if sealStore == nil || strings.TrimSpace(sealRootDir) == "" {
		return nil, fmt.Errorf("%w: sealed evidence store and root directory are required", ErrMissingPrerequisite)
	}
	if res == nil {
		return nil, fmt.Errorf("%w: analysis result is required", ErrMissingPrerequisite)
	}
	if res.CaseID != req.CaseID {
		return nil, fmt.Errorf("%w: analysis case_id %q does not match request case_id %q", ErrInputBindingMismatch, res.CaseID, req.CaseID)
	}
	if err := validateIdentifier("evidence_id", res.EvidenceID); err != nil {
		return nil, err
	}
	if !allowlistedAnalyzers[res.AnalyzerID] || !res.NonExecuting || !res.ReadOnly {
		return nil, fmt.Errorf("%w: analyzer %q must be allowlisted, non-executing, and read-only", ErrToolBindingInvalid, res.AnalyzerID)
	}
	if strings.TrimSpace(res.ToolVersion) == "" {
		return nil, fmt.Errorf("%w: tool_version is required", ErrToolBindingInvalid)
	}
	if !digestRegex.MatchString(res.ConfigDigest) {
		return nil, fmt.Errorf("%w: invalid config_hash %q", ErrConfigHashMismatch, res.ConfigDigest)
	}
	if !digestRegex.MatchString(res.InputSHA256) {
		return nil, fmt.Errorf("%w: invalid input sha256 %q", ErrInputBindingMismatch, res.InputSHA256)
	}

	// Collect unique input evidence IDs (primary + additional inputs).
	seenIDs := map[string]bool{res.EvidenceID: true}
	inputIDs := []string{res.EvidenceID}
	for _, extraID := range req.AdditionalInputs {
		if err := validateIdentifier("additional_input", extraID); err != nil {
			return nil, err
		}
		if !seenIDs[extraID] {
			seenIDs[extraID] = true
			inputIDs = append(inputIDs, extraID)
		}
	}
	sort.Strings(inputIDs)

	resolvedSealRoot, err := filepath.Abs(filepath.Clean(sealRootDir))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if _, err := ensureNoSymlink(resolvedSealRoot); err != nil {
		return nil, err
	}

	type sealedSnapshot struct {
		blobPath string
		sha256   string
		size     int64
	}
	snapshots := make([]sealedSnapshot, 0, len(inputIDs))
	bindings := make([]InputBinding, 0, len(inputIDs))
	hashSet := make(map[string]bool, len(inputIDs))
	inputHashes := make([]string, 0, len(inputIDs))

	for _, evID := range inputIDs {
		vr, vErr := evidence.VerifyStoreEvidence(ctx, sealStore, req.CaseID, evID, evidence.VerifyOptions{})
		if vErr != nil || vr == nil || !vr.Verified {
			return nil, fmt.Errorf("%w: sealed evidence %s/%s failed read-only verification: %v", ErrMissingPrerequisite, req.CaseID, evID, vErr)
		}
		sm, sErr := sealStore.GetSealedManifest(req.CaseID, evID)
		if sErr != nil || sm == nil || !sm.Sealed {
			return nil, fmt.Errorf("%w: sealed manifest %s/%s unavailable: %v", ErrMissingPrerequisite, req.CaseID, evID, sErr)
		}
		if evID == res.EvidenceID && sm.SHA256 != res.InputSHA256 {
			return nil, fmt.Errorf("%w: analysis input sha256 %s != sealed sha256 %s", ErrInputBindingMismatch, res.InputSHA256, sm.SHA256)
		}
		blobPath := filepath.Join(resolvedSealRoot, filepath.FromSlash(sm.BlobRelPath))
		if err := checkWithinDir(resolvedSealRoot, blobPath); err != nil {
			return nil, err
		}
		preHash, preSize, err := hashRegularFile(blobPath)
		if err != nil {
			return nil, fmt.Errorf("%w: read sealed input blob %s: %v", ErrMissingPrerequisite, evID, err)
		}
		if preHash != sm.SHA256 || preSize != sm.SizeBytes {
			return nil, fmt.Errorf("%w: sealed input blob mismatch for %s", ErrSealedBytesTampered, evID)
		}

		snapshots = append(snapshots, sealedSnapshot{
			blobPath: blobPath,
			sha256:   preHash,
			size:     preSize,
		})
		bindings = append(bindings, InputBinding{
			CaseID:      sm.CaseID,
			EvidenceID:  sm.EvidenceID,
			SHA256:      sm.SHA256,
			SizeBytes:   sm.SizeBytes,
			MediaType:   sm.MediaType,
			CustodyRoot: sm.CustodyRoot,
		})
		if !hashSet[sm.SHA256] {
			hashSet[sm.SHA256] = true
			inputHashes = append(inputHashes, sm.SHA256)
		}
	}
	sort.Strings(inputHashes)

	// Build deterministic derived payload bytes.
	payloadDoc := DerivedPayload{
		SchemaVersion: SchemaVersion,
		CaseID:        req.CaseID,
		EvidenceID:    res.EvidenceID,
		ArtifactID:    req.ArtifactID,
		RunID:         runID,
		AnalyzerID:    res.AnalyzerID,
		ToolVersion:   res.ToolVersion,
		ConfigHash:    res.ConfigDigest,
		InputHashes:   inputHashes,
		AnalyzedAt:    res.AnalyzedAt,
		RecordCount:   res.RecordCount,
		Records:       res.Records,
	}
	if payloadDoc.Records == nil {
		payloadDoc.Records = []analyzers.ParsedRecord{}
	}
	payloadBytes, err := json.MarshalIndent(payloadDoc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: encode derived payload: %v", ErrMalformedPayload, err)
	}
	payloadBytes = append(payloadBytes, '\n')
	if int64(len(payloadBytes)) > s.maxPayload {
		return nil, fmt.Errorf("%w: derived payload %d bytes exceeds max %d", ErrStorageQuotaExceeded, len(payloadBytes), s.maxPayload)
	}

	outSum := sha256.Sum256(payloadBytes)
	outSHA := hex.EncodeToString(outSum[:])
	outSize := int64(len(payloadBytes))
	relPayloadPath := filepath.ToSlash(filepath.Join(artifactsSubdir, req.CaseID, req.ArtifactID, outputFileName))

	createdAt := req.CreatedAt
	if strings.TrimSpace(createdAt) == "" {
		if strings.TrimSpace(res.AnalyzedAt) != "" {
			createdAt = res.AnalyzedAt
		} else {
			createdAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, createdAt); err != nil {
		return nil, fmt.Errorf("%w: invalid created_at timestamp %q", ErrInvalidManifest, createdAt)
	}

	provider := req.Provider
	if provider == "" {
		provider = "local"
	}

	manifest := DerivedManifest{
		SchemaVersion: SchemaVersion,
		OperationID:   req.OperationID,
		ArtifactID:    req.ArtifactID,
		CaseID:        req.CaseID,
		RunID:         runID,
		Inputs:        bindings,
		InputHashes:   inputHashes,
		AnalyzerID:    res.AnalyzerID,
		ToolVersion:   res.ToolVersion,
		Provider:      provider,
		ConfigHash:    res.ConfigDigest,
		NonExecuting:  res.NonExecuting,
		ReadOnly:      res.ReadOnly,
		Output: OutputBinding{
			ArtifactID:  req.ArtifactID,
			MediaType:   DefaultOutputMediaType,
			SHA256:      outSHA,
			SizeBytes:   outSize,
			RecordCount: res.RecordCount,
			RelPath:     relPayloadPath,
		},
		CreatedAt: createdAt,
	}

	digest, err := ComputeManifestDigest(manifest)
	if err != nil {
		return nil, err
	}
	manifest.ManifestDigest = digest

	if len(req.PrivateKey) > 0 || strings.TrimSpace(req.KeyID) != "" {
		if len(req.PrivateKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: invalid Ed25519 private key length", ErrInvalidSignature)
		}
		if err := validateIdentifier("key_id", req.KeyID); err != nil {
			return nil, err
		}
		manifest.KeyID = req.KeyID
		pub := req.PrivateKey.Public().(ed25519.PublicKey)
		manifest.PublicKey = hex.EncodeToString(pub)
		sig := ed25519.Sign(req.PrivateKey, CanonicalSignaturePayload(manifest))
		manifest.Signature = hex.EncodeToString(sig)
	}

	// Idempotent operation replay vs conflict detection.
	if req.OperationID != "" {
		if prev, exists := s.index.Operations[req.OperationID]; exists {
			if prev.CaseID != manifest.CaseID ||
				prev.ArtifactID != manifest.ArtifactID ||
				prev.ToolVersion != manifest.ToolVersion ||
				prev.ConfigHash != manifest.ConfigHash ||
				prev.Output.SHA256 != manifest.Output.SHA256 ||
				!stringSlicesEqual(prev.InputHashes, manifest.InputHashes) {
				return nil, fmt.Errorf("%w: operation %q previously committed different parameters", ErrManifestConflict, req.OperationID)
			}
			replay := prev
			replay.IdempotentReplay = true
			return &replay, nil
		}
	}

	artifactKey := req.CaseID + "/" + req.ArtifactID
	if prev, exists := s.index.Manifests[artifactKey]; exists {
		if prev.ManifestDigest != manifest.ManifestDigest {
			return nil, fmt.Errorf("%w: artifact %s already exists with different provenance digest", ErrManifestConflict, artifactKey)
		}
		replay := prev
		replay.IdempotentReplay = true
		return &replay, nil
	}

	if s.cfg.Faults.SimulateDiskFull {
		return nil, ErrDiskFull
	}
	if s.index.TotalBytes+outSize > s.maxStorage {
		return nil, fmt.Errorf("%w: total bytes %d + %d exceeds max %d", ErrStorageQuotaExceeded, s.index.TotalBytes, outSize, s.maxStorage)
	}

	manifest.Generation = s.index.Generation + 1
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal derived manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')

	stagePrefix := fmt.Sprintf("gen-%d-%s-%s", manifest.Generation, req.CaseID, req.ArtifactID)
	payloadTmp := filepath.Join(s.rootDir, stagingSubdir, stagePrefix+".payload.tmp")
	manifestTmp := filepath.Join(s.rootDir, stagingSubdir, stagePrefix+".manifest.tmp")

	if err := writeSyncFile(payloadTmp, payloadBytes, 0640); err != nil {
		return nil, err
	}
	if err := writeSyncFile(manifestTmp, manifestBytes, 0640); err != nil {
		_ = os.Remove(payloadTmp)
		return nil, err
	}

	if s.cfg.Faults.FailAfterPayloadBeforeManifest {
		return nil, ErrInterrupted
	}

	finalPayloadPath := filepath.Join(s.rootDir, filepath.FromSlash(relPayloadPath))
	if err := checkWithinDir(s.rootDir, finalPayloadPath); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(finalPayloadPath), 0750); err != nil {
		return nil, fmt.Errorf("create derived artifact dir: %w", err)
	}
	if err := os.Rename(payloadTmp, finalPayloadPath); err != nil {
		return nil, fmt.Errorf("commit derived payload: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(filepath.Dir(finalPayloadPath))
	}

	finalManifestPath := filepath.Join(s.rootDir, manifestsSubdir, req.CaseID, req.ArtifactID+".manifest.json")
	if err := checkWithinDir(s.rootDir, finalManifestPath); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(finalManifestPath), 0750); err != nil {
		return nil, fmt.Errorf("create derived manifest dir: %w", err)
	}
	if err := os.Rename(manifestTmp, finalManifestPath); err != nil {
		return nil, fmt.Errorf("commit derived manifest: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(filepath.Dir(finalManifestPath))
	}

	// Update and persist index atomically.
	nextIndex := s.index
	nextIndex.Generation = manifest.Generation
	nextIndex.TotalBytes += outSize
	nextOps := make(map[string]DerivedManifest, len(s.index.Operations)+1)
	for k, v := range s.index.Operations {
		nextOps[k] = v
	}
	if req.OperationID != "" {
		nextOps[req.OperationID] = manifest
	}
	nextManifests := make(map[string]DerivedManifest, len(s.index.Manifests)+1)
	for k, v := range s.index.Manifests {
		nextManifests[k] = v
	}
	nextManifests[artifactKey] = manifest
	nextIndex.Operations = nextOps
	nextIndex.Manifests = nextManifests

	if err := s.persistIndexUnlocked(nextIndex); err != nil {
		return nil, err
	}
	s.index = nextIndex

	// Re-verify all sealed source blobs remained strictly untouched on disk.
	for _, snap := range snapshots {
		postHash, postSize, err := hashRegularFile(snap.blobPath)
		if err != nil {
			return nil, fmt.Errorf("%w: post-derivation sealed blob check failed: %v", ErrSealedBytesTampered, err)
		}
		if postHash != snap.sha256 || postSize != snap.size {
			return nil, ErrSealedBytesTampered
		}
	}

	out := manifest
	return &out, nil
}

func (s *ArtifactStore) persistIndexUnlocked(idx artifactIndex) error {
	raw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal artifact index: %w", err)
	}
	raw = append(raw, '\n')
	tmp := filepath.Join(s.rootDir, stagingSubdir, fmt.Sprintf("index-%d.tmp", idx.Generation))
	if err := writeSyncFile(tmp, raw, 0640); err != nil {
		return err
	}
	indexPath := filepath.Join(s.rootDir, indexFileName)
	if err := os.Rename(tmp, indexPath); err != nil {
		return fmt.Errorf("commit artifact index: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(s.rootDir)
	}
	return nil
}

// GetManifest retrieves a committed DerivedManifest for (caseID, artifactID).
func (s *ArtifactStore) GetManifest(caseID, artifactID string) (*DerivedManifest, error) {
	if s == nil {
		return nil, ErrArtifactStoreRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrArtifactStoreClosed
	}
	if err := validateIdentifier("case_id", caseID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("artifact_id", artifactID); err != nil {
		return nil, err
	}
	m, ok := s.index.Manifests[caseID+"/"+artifactID]
	if !ok {
		return nil, fmt.Errorf("%w: %s/%s", ErrArtifactNotFound, caseID, artifactID)
	}
	copyM := m
	return &copyM, nil
}

// RootDir returns the resolved root directory of the artifact store.
func (s *ArtifactStore) RootDir() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rootDir
}

// ListCaseManifests returns all committed DerivedManifests for caseID sorted deterministically by ArtifactID.
func (s *ArtifactStore) ListCaseManifests(caseID string) ([]DerivedManifest, error) {
	if s == nil {
		return nil, ErrArtifactStoreRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrArtifactStoreClosed
	}
	if err := validateIdentifier("case_id", caseID); err != nil {
		return nil, err
	}
	var out []DerivedManifest
	for _, m := range s.index.Manifests {
		if m.CaseID == caseID {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ArtifactID < out[j].ArtifactID
	})
	return out, nil
}

// RestoreVerifiedArtifact verifies provenance, optional Ed25519 signature, read-only sealed inputs,
// and exact output payload digest before atomically committing a restored derived artifact and manifest.
func (s *ArtifactStore) RestoreVerifiedArtifact(
	ctx context.Context,
	sealStore *evidence.SealStore,
	m DerivedManifest,
	payloadBytes []byte,
	opts VerifyOptions,
) (*DerivedManifest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrArtifactStoreRequired
	}
	if sealStore == nil {
		return nil, fmt.Errorf("%w: sealStore is required to restore verified artifact", ErrMissingPrerequisite)
	}

	if _, err := VerifyDerivedManifest(ctx, sealStore, &m, opts); err != nil {
		return nil, err
	}

	if int64(len(payloadBytes)) > s.maxPayload {
		return nil, fmt.Errorf("%w: derived payload %d bytes exceeds max %d", ErrStorageQuotaExceeded, len(payloadBytes), s.maxPayload)
	}
	sum := sha256.Sum256(payloadBytes)
	gotSHA := hex.EncodeToString(sum[:])
	gotSize := int64(len(payloadBytes))
	if gotSize != m.Output.SizeBytes || gotSHA != m.Output.SHA256 {
		return nil, fmt.Errorf("%w: restored payload mismatch (got sha256=%s size=%d, manifest sha256=%s size=%d)",
			ErrOutputTampered, gotSHA, gotSize, m.Output.SHA256, m.Output.SizeBytes)
	}

	var payload DerivedPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("%w: parse restored payload JSON: %v", ErrMalformedPayload, err)
	}
	if payload.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: payload schema_version %q", ErrUnsupportedVersion, payload.SchemaVersion)
	}
	if payload.CaseID != m.CaseID || payload.ArtifactID != m.ArtifactID {
		return nil, fmt.Errorf("%w: payload case/artifact %s/%s != manifest %s/%s", ErrInputBindingMismatch, payload.CaseID, payload.ArtifactID, m.CaseID, m.ArtifactID)
	}
	if payload.AnalyzerID != m.AnalyzerID || payload.ToolVersion != m.ToolVersion || payload.ConfigHash != m.ConfigHash {
		return nil, fmt.Errorf("%w: payload tool/config provenance does not match manifest", ErrToolBindingInvalid)
	}
	if payload.RecordCount != m.Output.RecordCount || len(payload.Records) != m.Output.RecordCount {
		return nil, fmt.Errorf("%w: payload record count %d/%d != manifest %d", ErrMalformedPayload, payload.RecordCount, len(payload.Records), m.Output.RecordCount)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrArtifactStoreClosed
	}

	expectedRelPath := filepath.ToSlash(filepath.Join(artifactsSubdir, m.CaseID, m.ArtifactID, outputFileName))
	if filepath.ToSlash(filepath.Clean(filepath.FromSlash(m.Output.RelPath))) != expectedRelPath {
		return nil, fmt.Errorf("%w: invalid output.rel_path %q (expected %q)", ErrPathTraversal, m.Output.RelPath, expectedRelPath)
	}

	finalPayloadPath := filepath.Join(s.rootDir, filepath.FromSlash(expectedRelPath))
	if err := checkWithinDir(filepath.Join(s.rootDir, artifactsSubdir), finalPayloadPath); err != nil {
		return nil, err
	}
	if _, err := ensureNoSymlink(finalPayloadPath); err != nil {
		return nil, err
	}

	if m.OperationID != "" {
		if prev, exists := s.index.Operations[m.OperationID]; exists {
			if prev.CaseID != m.CaseID || prev.ArtifactID != m.ArtifactID || prev.ManifestDigest != m.ManifestDigest || prev.Output.SHA256 != m.Output.SHA256 {
				return nil, fmt.Errorf("%w: operation %q previously committed different artifact", ErrManifestConflict, m.OperationID)
			}
			if err := s.verifyStoredPayloadUnlocked(prev); err != nil {
				return nil, err
			}
			replay := prev
			replay.IdempotentReplay = true
			return &replay, nil
		}
	}

	artifactKey := m.CaseID + "/" + m.ArtifactID
	if prev, exists := s.index.Manifests[artifactKey]; exists {
		if prev.ManifestDigest != m.ManifestDigest || prev.Output.SHA256 != m.Output.SHA256 {
			return nil, fmt.Errorf("%w: artifact %s already exists with different provenance digest", ErrManifestConflict, artifactKey)
		}
		if err := s.verifyStoredPayloadUnlocked(prev); err != nil {
			return nil, err
		}
		replay := prev
		replay.IdempotentReplay = true
		return &replay, nil
	}

	if s.cfg.Faults.SimulateDiskFull {
		return nil, ErrDiskFull
	}
	if s.index.TotalBytes+gotSize > s.maxStorage {
		return nil, fmt.Errorf("%w: total bytes %d + %d exceeds max %d", ErrStorageQuotaExceeded, s.index.TotalBytes, gotSize, s.maxStorage)
	}

	restored := m
	restored.Generation = s.index.Generation + 1
	restored.IdempotentReplay = false

	manifestBytes, err := json.MarshalIndent(restored, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal restored derived manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')

	stagePrefix := fmt.Sprintf("restore-gen-%d-%s-%s", restored.Generation, restored.CaseID, restored.ArtifactID)
	payloadTmp := filepath.Join(s.rootDir, stagingSubdir, stagePrefix+".payload.tmp")
	manifestTmp := filepath.Join(s.rootDir, stagingSubdir, stagePrefix+".manifest.tmp")

	if err := writeSyncFile(payloadTmp, payloadBytes, 0640); err != nil {
		return nil, err
	}
	if err := writeSyncFile(manifestTmp, manifestBytes, 0640); err != nil {
		_ = os.Remove(payloadTmp)
		return nil, err
	}

	if s.cfg.Faults.FailAfterPayloadBeforeManifest {
		return nil, ErrInterrupted
	}

	if err := os.MkdirAll(filepath.Dir(finalPayloadPath), 0750); err != nil {
		_ = os.Remove(payloadTmp)
		_ = os.Remove(manifestTmp)
		return nil, fmt.Errorf("create restored artifact dir: %w", err)
	}
	if err := os.Rename(payloadTmp, finalPayloadPath); err != nil {
		_ = os.Remove(payloadTmp)
		_ = os.Remove(manifestTmp)
		return nil, fmt.Errorf("commit restored payload: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(filepath.Dir(finalPayloadPath))
	}

	finalManifestPath := filepath.Join(s.rootDir, manifestsSubdir, restored.CaseID, restored.ArtifactID+".manifest.json")
	if err := checkWithinDir(s.rootDir, finalManifestPath); err != nil {
		_ = os.Remove(manifestTmp)
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(finalManifestPath), 0750); err != nil {
		_ = os.Remove(manifestTmp)
		return nil, fmt.Errorf("create restored manifest dir: %w", err)
	}
	if err := os.Rename(manifestTmp, finalManifestPath); err != nil {
		_ = os.Remove(manifestTmp)
		return nil, fmt.Errorf("commit restored manifest: %w", err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(filepath.Dir(finalManifestPath))
	}

	nextIndex := s.index
	nextIndex.Generation = restored.Generation
	nextIndex.TotalBytes += gotSize
	nextOps := make(map[string]DerivedManifest, len(s.index.Operations)+1)
	for k, v := range s.index.Operations {
		nextOps[k] = v
	}
	if restored.OperationID != "" {
		nextOps[restored.OperationID] = restored
	}
	nextManifests := make(map[string]DerivedManifest, len(s.index.Manifests)+1)
	for k, v := range s.index.Manifests {
		nextManifests[k] = v
	}
	nextManifests[artifactKey] = restored
	nextIndex.Operations = nextOps
	nextIndex.Manifests = nextManifests

	if err := s.persistIndexUnlocked(nextIndex); err != nil {
		return nil, err
	}
	s.index = nextIndex

	out := restored
	return &out, nil
}

// VerifyStoredArtifact performs full provenance, disk payload digest, sealed input binding,
// and optional Ed25519 signature verification for a persisted artifact.
func (s *ArtifactStore) VerifyStoredArtifact(
	ctx context.Context,
	sealStore *evidence.SealStore,
	caseID string,
	artifactID string,
	opts VerifyOptions,
) (*VerificationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrArtifactStoreRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrArtifactStoreClosed
	}
	if err := validateIdentifier("case_id", caseID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("artifact_id", artifactID); err != nil {
		return nil, err
	}

	indexed, ok := s.index.Manifests[caseID+"/"+artifactID]
	if !ok {
		return nil, fmt.Errorf("%w: %s/%s", ErrArtifactNotFound, caseID, artifactID)
	}

	manifestPath := filepath.Join(s.rootDir, manifestsSubdir, caseID, artifactID+".manifest.json")
	if err := checkWithinDir(s.rootDir, manifestPath); err != nil {
		return nil, err
	}
	if _, err := ensureNoSymlink(manifestPath); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read manifest file: %v", ErrInvalidManifest, err)
	}
	var onDisk DerivedManifest
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		return nil, fmt.Errorf("%w: parse manifest JSON: %v", ErrInvalidManifest, err)
	}
	if onDisk.ManifestDigest != indexed.ManifestDigest {
		return nil, fmt.Errorf("%w: on-disk manifest digest != indexed digest", ErrManifestDigestMismatch)
	}

	if err := s.verifyStoredPayloadUnlocked(onDisk); err != nil {
		return nil, err
	}

	return VerifyDerivedManifest(ctx, sealStore, &onDisk, opts)
}

func (s *ArtifactStore) verifyStoredPayloadUnlocked(m DerivedManifest) error {
	if strings.TrimSpace(m.Output.RelPath) == "" {
		return fmt.Errorf("%w: output rel_path missing", ErrInvalidManifest)
	}
	fullPath := filepath.Join(s.rootDir, filepath.FromSlash(m.Output.RelPath))
	if err := checkWithinDir(s.rootDir, fullPath); err != nil {
		return err
	}
	gotSHA, gotSize, err := hashRegularFile(fullPath)
	if err != nil {
		return fmt.Errorf("%w: read derived payload: %v", ErrOutputTampered, err)
	}
	if gotSize != m.Output.SizeBytes || gotSHA != m.Output.SHA256 {
		return fmt.Errorf("%w: derived output payload mismatch (got sha256=%s size=%d, manifest sha256=%s size=%d)", ErrOutputTampered, gotSHA, gotSize, m.Output.SHA256, m.Output.SizeBytes)
	}
	return nil
}

// ValidateManifestStructure verifies all required fields, digests, tool bindings, and input hashes
// of a DerivedManifest without consulting disk or SealStore.
func ValidateManifestStructure(m DerivedManifest) error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schema_version %q", ErrUnsupportedVersion, m.SchemaVersion)
	}
	if err := validateIdentifier("case_id", m.CaseID); err != nil {
		return err
	}
	if err := validateIdentifier("artifact_id", m.ArtifactID); err != nil {
		return err
	}
	if m.RunID != "" {
		if err := validateIdentifier("run_id", m.RunID); err != nil {
			return err
		}
	}
	if !allowlistedAnalyzers[m.AnalyzerID] || !m.NonExecuting || !m.ReadOnly {
		return fmt.Errorf("%w: analyzer %q must be allowlisted, non-executing, and read-only", ErrToolBindingInvalid, m.AnalyzerID)
	}
	if strings.TrimSpace(m.ToolVersion) == "" {
		return fmt.Errorf("%w: tool_version must not be empty", ErrToolBindingInvalid)
	}
	if !allowedProviders[m.Provider] {
		return fmt.Errorf("%w: provider %q not allowed", ErrToolBindingInvalid, m.Provider)
	}
	if !digestRegex.MatchString(m.ConfigHash) {
		return fmt.Errorf("%w: config_hash must be 64 lowercase hex characters", ErrConfigHashMismatch)
	}
	if len(m.Inputs) == 0 || len(m.InputHashes) == 0 {
		return fmt.Errorf("%w: derived manifest must include at least one input binding and input hash", ErrInputBindingMismatch)
	}

	expectedSet := make(map[string]bool, len(m.Inputs))
	seenInputs := make(map[string]bool, len(m.Inputs))
	for i, inp := range m.Inputs {
		if err := validateIdentifier(fmt.Sprintf("inputs[%d].case_id", i), inp.CaseID); err != nil {
			return err
		}
		if inp.CaseID != m.CaseID {
			return fmt.Errorf("%w: input case_id %q does not match manifest case_id %q", ErrInputBindingMismatch, inp.CaseID, m.CaseID)
		}
		if err := validateIdentifier(fmt.Sprintf("inputs[%d].evidence_id", i), inp.EvidenceID); err != nil {
			return err
		}
		pairKey := inp.CaseID + "/" + inp.EvidenceID
		if seenInputs[pairKey] {
			return fmt.Errorf("%w: duplicate input binding %s", ErrInputBindingMismatch, pairKey)
		}
		seenInputs[pairKey] = true
		if !digestRegex.MatchString(inp.SHA256) {
			return fmt.Errorf("%w: inputs[%d].sha256 invalid", ErrInputBindingMismatch, i)
		}
		if inp.SizeBytes < 0 {
			return fmt.Errorf("%w: inputs[%d].size_bytes negative", ErrInputBindingMismatch, i)
		}
		if !mediaTypeRegex.MatchString(inp.MediaType) {
			return fmt.Errorf("%w: inputs[%d].media_type invalid", ErrInputBindingMismatch, i)
		}
		expectedSet[inp.SHA256] = true
	}

	actualSet := make(map[string]bool, len(m.InputHashes))
	for _, h := range m.InputHashes {
		if !digestRegex.MatchString(h) {
			return fmt.Errorf("%w: invalid input hash %q", ErrInputBindingMismatch, h)
		}
		actualSet[h] = true
	}
	if len(actualSet) != len(expectedSet) {
		return fmt.Errorf("%w: input_hashes count mismatch with inputs", ErrInputBindingMismatch)
	}
	for h := range expectedSet {
		if !actualSet[h] {
			return fmt.Errorf("%w: input_hashes missing input sha256 %s", ErrInputBindingMismatch, h)
		}
	}

	if m.Output.ArtifactID != m.ArtifactID {
		return fmt.Errorf("%w: output.artifact_id %q != manifest.artifact_id %q", ErrInvalidManifest, m.Output.ArtifactID, m.ArtifactID)
	}
	if !mediaTypeRegex.MatchString(m.Output.MediaType) {
		return fmt.Errorf("%w: invalid output.media_type", ErrInvalidManifest)
	}
	if !digestRegex.MatchString(m.Output.SHA256) {
		return fmt.Errorf("%w: invalid output.sha256", ErrOutputTampered)
	}
	if m.Output.SizeBytes < 0 || m.Output.RecordCount < 0 {
		return fmt.Errorf("%w: output size_bytes and record_count must be non-negative", ErrInvalidManifest)
	}
	if strings.TrimSpace(m.Output.RelPath) == "" || strings.ContainsRune(m.Output.RelPath, '\x00') || filepath.IsAbs(m.Output.RelPath) || strings.HasPrefix(m.Output.RelPath, "/") {
		return fmt.Errorf("%w: invalid output.rel_path %q", ErrPathTraversal, m.Output.RelPath)
	}
	for _, seg := range strings.FieldsFunc(m.Output.RelPath, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return fmt.Errorf("%w: traversal segment in output.rel_path", ErrPathTraversal)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, m.CreatedAt); err != nil {
		return fmt.Errorf("%w: invalid created_at timestamp", ErrInvalidManifest)
	}

	computed, err := ComputeManifestDigest(m)
	if err != nil {
		return err
	}
	if !digestRegex.MatchString(m.ManifestDigest) || m.ManifestDigest != computed {
		return fmt.Errorf("%w: manifest_digest %q != computed %q", ErrManifestDigestMismatch, m.ManifestDigest, computed)
	}

	return nil
}

// VerifyDerivedManifest verifies structural provenance invariants, optional Ed25519 signature,
// and read-only correspondence against sealed inputs in sealStore.
func VerifyDerivedManifest(
	ctx context.Context,
	sealStore *evidence.SealStore,
	m *DerivedManifest,
	opts VerifyOptions,
) (*VerificationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("%w: manifest is required", ErrInvalidManifest)
	}

	if err := ValidateManifestStructure(*m); err != nil {
		return nil, err
	}

	sigValid := false
	hasSig := strings.TrimSpace(m.Signature) != "" || strings.TrimSpace(m.PublicKey) != "" || strings.TrimSpace(m.KeyID) != ""
	if opts.RequireSignature && !hasSig {
		return nil, fmt.Errorf("%w: signature required but missing", ErrUntrustedSigner)
	}
	if hasSig {
		if err := validateIdentifier("key_id", m.KeyID); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUntrustedSigner, err)
		}
		pubBytes, err := hex.DecodeString(m.PublicKey)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: invalid Ed25519 public key", ErrUntrustedSigner)
		}
		sigBytes, err := hex.DecodeString(m.Signature)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			return nil, fmt.Errorf("%w: invalid Ed25519 signature encoding", ErrInvalidSignature)
		}
		if opts.TrustedKeys != nil {
			trustedPub, ok := opts.TrustedKeys[m.KeyID]
			if !ok || !bytes.Equal(trustedPub, pubBytes) {
				return nil, fmt.Errorf("%w: key_id %q is not trusted", ErrUntrustedSigner, m.KeyID)
			}
		}
		if !ed25519.Verify(ed25519.PublicKey(pubBytes), CanonicalSignaturePayload(*m), sigBytes) {
			return nil, ErrInvalidSignature
		}
		sigValid = true
	}

	inputsVerified := false
	if sealStore != nil {
		for _, inp := range m.Inputs {
			vr, err := evidence.VerifyStoreEvidence(ctx, sealStore, inp.CaseID, inp.EvidenceID, evidence.VerifyOptions{})
			if err != nil || vr == nil || !vr.Verified {
				return nil, fmt.Errorf("%w: sealed evidence %s/%s failed read-only check: %v", ErrMissingPrerequisite, inp.CaseID, inp.EvidenceID, err)
			}
			sm, err := sealStore.GetSealedManifest(inp.CaseID, inp.EvidenceID)
			if err != nil || sm == nil || !sm.Sealed {
				return nil, fmt.Errorf("%w: sealed manifest %s/%s unavailable", ErrMissingPrerequisite, inp.CaseID, inp.EvidenceID)
			}
			if sm.SHA256 != inp.SHA256 || sm.SizeBytes != inp.SizeBytes {
				return nil, fmt.Errorf("%w: sealed input %s/%s differs from derived manifest binding", ErrInputBindingMismatch, inp.CaseID, inp.EvidenceID)
			}
		}
		inputsVerified = true
	}

	return &VerificationResult{
		Verified:       true,
		ArtifactID:     m.ArtifactID,
		CaseID:         m.CaseID,
		ManifestDigest: m.ManifestDigest,
		InputHashes:    append([]string(nil), m.InputHashes...),
		ToolVersion:    m.ToolVersion,
		ConfigHash:     m.ConfigHash,
		OutputSHA256:   m.Output.SHA256,
		SignatureValid: sigValid,
		InputsVerified: inputsVerified,
	}, nil
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
		return "", 0, fmt.Errorf("%w: %s is not a regular file", ErrInvalidManifest, path)
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

func stringSlicesEqual(a, b []string) bool {
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

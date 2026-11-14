package release

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

var (
	ErrStaleOrExpiredRevision      = errors.New("release revision is expired, stale, or replayed against accepted authority")
	ErrNewerDataOverwriteForbidden = errors.New("cannot discard or overwrite newer accepted host data with an older backup")
)

// BuildRecipe models source/BUILD_RECIPE.json for verifying the documented source-build alternative.
type BuildRecipe struct {
	SchemaVersion string   `json:"schemaVersion"`
	Project       string   `json:"project"`
	SourceCommit  string   `json:"sourceCommit"`
	Archive       string   `json:"archive"`
	ArchiveSHA256 string   `json:"archiveSha256"`
	Reproducible  bool     `json:"reproducible"`
	BuildCommands []string `json:"buildCommands"`
}

// TrustedReleasePolicy enforces independent Ed25519 key trust, monotonic revisions, and expiry checks.
type TrustedReleasePolicy struct {
	TrustedKeys                   map[string]ed25519.PublicKey
	MinRevision                   uint64
	VerifyTime                    time.Time
	RequireSourceBuildAlternative bool
}

// HostAuthorityState tracks accepted release binaries and the monotonic authority high-water mark on a host.
type HostAuthorityState struct {
	SchemaVersion           string `json:"schema_version"`
	CurrentVersion          string `json:"current_version"`
	CurrentRevision         uint64 `json:"current_revision"`
	HighestAcceptedRevision uint64 `json:"highest_accepted_revision"`
	PreviousVersion         string `json:"previous_version,omitempty"`
	PreviousRevision        uint64 `json:"previous_revision,omitempty"`
	TrustedKeyID            string `json:"trusted_key_id"`
	UpdatedAt               string `json:"updated_at"`
}

// UpgradeConfig drives an atomic release install or upgrade while preserving DataDir contents.
type UpgradeConfig struct {
	InstallRoot                string
	DataDir                    string
	CandidateReleaseDir        string
	Policy                     TrustedReleasePolicy
	OverwriteDataWithOldBackup bool
	Now                        time.Time
}

// UpgradeOutcome reports the committed install/upgrade state and preserved host data inventory.
type UpgradeOutcome struct {
	Authority         HostAuthorityState `json:"authority"`
	Verification      VerificationResult `json:"verification"`
	PreservedDataFile int                `json:"preserved_data_files"`
	PriorVersion      string             `json:"prior_version,omitempty"`
}

// RollbackConfig drives a binary-only rollback without overwriting newer accepted host data.
type RollbackConfig struct {
	InstallRoot                string
	DataDir                    string
	TargetReleaseDir           string
	Policy                     TrustedReleasePolicy
	OverwriteDataWithOldBackup bool
	Now                        time.Time
}

// RollbackOutcome reports the rolled-back binary version alongside preserved newer host data.
type RollbackOutcome struct {
	Authority         HostAuthorityState `json:"authority"`
	Verification      VerificationResult `json:"verification"`
	PreservedDataFile int                `json:"preserved_data_files"`
	RolledBackFrom    string             `json:"rolled_back_from"`
}

// SignReleaseVersion attaches Ed25519 provenance, version, revision, issuedAt, and expiresAt to a manifest.
func SignReleaseVersion(manifest ReleaseManifest, priv ed25519.PrivateKey, keyID, releaseVersion string, revision uint64, issuedAt, expiresAt time.Time) (ReleaseManifest, error) {
	if keyID == "" {
		return ReleaseManifest{}, fmt.Errorf("%w: provenance key ID required", ErrSignatureInvalid)
	}
	if revision == 0 {
		return ReleaseManifest{}, fmt.Errorf("%w: provenance revision must be >= 1", ErrStaleOrExpiredRevision)
	}
	if !expiresAt.After(issuedAt) {
		return ReleaseManifest{}, fmt.Errorf("%w: expiry must be after issuedAt", ErrStaleOrExpiredRevision)
	}
	annotated := manifest
	annotated.ReleaseVersion = releaseVersion
	annotated.ProvenanceRevision = revision
	annotated.ProvenanceIssuedAt = issuedAt.UTC().Format(time.RFC3339)
	annotated.ProvenanceExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	return SignManifest(annotated, priv, keyID)
}

// SignReleaseDirectory signs release.json inside dir with Ed25519 and refreshes SHA256SUMS.txt.
func SignReleaseDirectory(dir string, priv ed25519.PrivateKey, keyID, releaseVersion string, revision uint64, issuedAt, expiresAt time.Time) (ReleaseManifest, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return ReleaseManifest{}, err
	}
	if _, err := ensureSafeFile(absDir, ReleaseManifestFile); err != nil {
		return ReleaseManifest{}, fmt.Errorf("%w: %v", ErrIncompleteWebOnlyArtifact, err)
	}
	raw, err := os.ReadFile(filepath.Join(absDir, ReleaseManifestFile))
	if err != nil {
		return ReleaseManifest{}, err
	}
	var manifest ReleaseManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return ReleaseManifest{}, fmt.Errorf("%w: invalid manifest JSON: %v", ErrIncompleteWebOnlyArtifact, err)
	}
	signed, err := SignReleaseVersion(manifest, priv, keyID, releaseVersion, revision, issuedAt, expiresAt)
	if err != nil {
		return ReleaseManifest{}, err
	}
	encoded, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return ReleaseManifest{}, err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(absDir, ReleaseManifestFile), encoded, 0o644); err != nil {
		return ReleaseManifest{}, err
	}
	if err := writeChecksums(absDir); err != nil {
		return ReleaseManifest{}, err
	}
	return signed, nil
}

// VerifyTrustedRelease validates release authenticity against an independently pinned Ed25519 key,
// checks expiration and monotonic revision authority, verifies checksums/SBOM/source archive,
// and validates the documented source-build recipe.
func VerifyTrustedRelease(ctx context.Context, dir string, policy TrustedReleasePolicy) (VerificationResult, error) {
	if err := ctx.Err(); err != nil {
		return VerificationResult{}, err
	}
	if len(policy.TrustedKeys) == 0 {
		return VerificationResult{}, fmt.Errorf("%w: no independently trusted Ed25519 keys configured", ErrSignatureInvalid)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("%w: %v", ErrInvalidReleasePath, err)
	}
	if _, err := ensureSafeFile(absDir, ReleaseManifestFile); err != nil {
		return VerificationResult{}, fmt.Errorf("%w: %v", ErrIncompleteWebOnlyArtifact, err)
	}
	raw, err := os.ReadFile(filepath.Join(absDir, ReleaseManifestFile))
	if err != nil {
		return VerificationResult{}, fmt.Errorf("%w: %v", ErrIncompleteWebOnlyArtifact, err)
	}
	var manifest ReleaseManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return VerificationResult{}, fmt.Errorf("%w: malformed manifest: %v", ErrIncompleteWebOnlyArtifact, err)
	}

	trustedKey, ok := policy.TrustedKeys[manifest.ProvenanceKeyID]
	if !ok || len(trustedKey) != ed25519.PublicKeySize {
		return VerificationResult{}, fmt.Errorf("%w: untrusted or unknown provenanceKeyId %q", ErrSignatureInvalid, manifest.ProvenanceKeyID)
	}
	if manifest.ProvenancePublicKey != "" && manifest.ProvenancePublicKey != hex.EncodeToString(trustedKey) {
		return VerificationResult{}, fmt.Errorf("%w: manifest public key mismatch for key ID %q", ErrSignatureInvalid, manifest.ProvenanceKeyID)
	}

	vr, err := VerifyReleaseDirectory(ctx, absDir, trustedKey, true)
	if err != nil {
		return VerificationResult{}, err
	}

	verifyNow := policy.VerifyTime.UTC()
	if verifyNow.IsZero() {
		verifyNow = time.Now().UTC()
	}
	if manifest.ProvenanceRevision == 0 || (policy.MinRevision > 0 && manifest.ProvenanceRevision < policy.MinRevision) {
		return VerificationResult{}, fmt.Errorf("%w: revision %d below minimum accepted authority %d", ErrStaleOrExpiredRevision, manifest.ProvenanceRevision, policy.MinRevision)
	}
	if manifest.ProvenanceExpiresAt == "" {
		return VerificationResult{}, fmt.Errorf("%w: missing provenanceExpiresAt", ErrStaleOrExpiredRevision)
	}
	expiresAt, err := time.Parse(time.RFC3339, manifest.ProvenanceExpiresAt)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("%w: invalid provenanceExpiresAt: %v", ErrStaleOrExpiredRevision, err)
	}
	if !expiresAt.After(verifyNow) {
		return VerificationResult{}, fmt.Errorf("%w: release expired at %s (verify time %s)", ErrStaleOrExpiredRevision, expiresAt.Format(time.RFC3339), verifyNow.Format(time.RFC3339))
	}
	if manifest.ProvenanceIssuedAt != "" {
		issuedAt, err := time.Parse(time.RFC3339, manifest.ProvenanceIssuedAt)
		if err != nil || !expiresAt.After(issuedAt) {
			return VerificationResult{}, fmt.Errorf("%w: invalid provenanceIssuedAt/provenanceExpiresAt window", ErrStaleOrExpiredRevision)
		}
	}

	// Verify the documented source-build alternative (BUILD_RECIPE.json matches source archive).
	recipeOK, err := verifyBuildRecipe(absDir)
	if err != nil {
		if policy.RequireSourceBuildAlternative {
			return VerificationResult{}, err
		}
	} else {
		vr.SourceBuildRecipeReady = recipeOK
	}
	if policy.RequireSourceBuildAlternative && !vr.SourceBuildRecipeReady {
		return VerificationResult{}, fmt.Errorf("%w: documented source-build alternative verification failed", ErrIncompleteWebOnlyArtifact)
	}
	return vr, nil
}

func verifyBuildRecipe(absDir string) (bool, error) {
	if _, err := ensureSafeFile(absDir, BuildRecipeFile); err != nil {
		return false, fmt.Errorf("%w: missing %s: %v", ErrIncompleteWebOnlyArtifact, BuildRecipeFile, err)
	}
	raw, err := os.ReadFile(filepath.Join(absDir, BuildRecipeFile))
	if err != nil {
		return false, err
	}
	var recipe BuildRecipe
	if err := json.Unmarshal(raw, &recipe); err != nil {
		return false, fmt.Errorf("%w: malformed %s: %v", ErrIncompleteWebOnlyArtifact, BuildRecipeFile, err)
	}
	if !recipe.Reproducible || len(recipe.BuildCommands) == 0 || recipe.Archive == "" {
		return false, fmt.Errorf("%w: incomplete source build recipe", ErrIncompleteWebOnlyArtifact)
	}
	archiveDigest, err := hashSafeFile(absDir, recipe.Archive)
	if err != nil {
		return false, fmt.Errorf("%w: source archive check failed: %v", ErrIncompleteWebOnlyArtifact, err)
	}
	if recipe.ArchiveSHA256 != "" && archiveDigest != recipe.ArchiveSHA256 {
		return false, fmt.Errorf("%w: BUILD_RECIPE archiveSha256 mismatch", ErrChecksumMismatch)
	}
	return true, nil
}

// InstallOrUpgradeRelease atomically installs or upgrades binaries under InstallRoot/current
// while preserving DataDir and enforcing monotonic authority revisions.
func InstallOrUpgradeRelease(ctx context.Context, cfg UpgradeConfig) (UpgradeOutcome, error) {
	if err := ctx.Err(); err != nil {
		return UpgradeOutcome{}, err
	}
	if cfg.InstallRoot == "" || cfg.DataDir == "" || cfg.CandidateReleaseDir == "" {
		return UpgradeOutcome{}, fmt.Errorf("%w: InstallRoot, DataDir, and CandidateReleaseDir are required", ErrInvalidReleasePath)
	}
	if err := os.MkdirAll(cfg.InstallRoot, 0o755); err != nil {
		return UpgradeOutcome{}, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return UpgradeOutcome{}, err
	}
	unlock, err := acquireHostLock(cfg.InstallRoot)
	if err != nil {
		return UpgradeOutcome{}, err
	}
	defer unlock()

	beforeData, err := snapshotDataDigests(cfg.DataDir)
	if err != nil {
		return UpgradeOutcome{}, err
	}
	if cfg.OverwriteDataWithOldBackup && len(beforeData) > 0 {
		return UpgradeOutcome{}, fmt.Errorf("%w: upgrade cannot overwrite existing accepted host data", ErrNewerDataOverwriteForbidden)
	}

	authPath := filepath.Join(cfg.InstallRoot, "authority.json")
	existingAuth, hasAuth, err := readAuthorityState(authPath)
	if err != nil {
		return UpgradeOutcome{}, err
	}

	policy := cfg.Policy
	policy.RequireSourceBuildAlternative = true
	if hasAuth && existingAuth.HighestAcceptedRevision+1 > policy.MinRevision {
		policy.MinRevision = existingAuth.HighestAcceptedRevision + 1
	}

	vr, err := VerifyTrustedRelease(ctx, cfg.CandidateReleaseDir, policy)
	if err != nil {
		return UpgradeOutcome{}, err
	}

	currentDir := filepath.Join(cfg.InstallRoot, "current")
	previousDir := filepath.Join(cfg.InstallRoot, "previous")
	if err := swapReleaseTreeAtomic(cfg.InstallRoot, cfg.CandidateReleaseDir, currentDir, previousDir); err != nil {
		return UpgradeOutcome{}, err
	}

	now := cfg.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nextAuth := HostAuthorityState{
		SchemaVersion:           "1",
		CurrentVersion:          vr.ReleaseVersion,
		CurrentRevision:         vr.ProvenanceRevision,
		HighestAcceptedRevision: vr.ProvenanceRevision,
		TrustedKeyID:            vr.ProvenanceKeyID,
		UpdatedAt:               now.Format(time.RFC3339),
	}
	if hasAuth {
		nextAuth.PreviousVersion = existingAuth.CurrentVersion
		nextAuth.PreviousRevision = existingAuth.CurrentRevision
		if existingAuth.HighestAcceptedRevision > nextAuth.HighestAcceptedRevision {
			nextAuth.HighestAcceptedRevision = existingAuth.HighestAcceptedRevision
		}
	}
	if err := writeJSONAtomic(authPath, nextAuth); err != nil {
		return UpgradeOutcome{}, err
	}

	if err := assertDataPreserved(cfg.DataDir, beforeData); err != nil {
		return UpgradeOutcome{}, err
	}

	return UpgradeOutcome{
		Authority:         nextAuth,
		Verification:      vr,
		PreservedDataFile: len(beforeData),
		PriorVersion:      nextAuth.PreviousVersion,
	}, nil
}

// RollbackRelease restores a previously verified signed release binary tree under InstallRoot/current
// without modifying DataDir and while preserving the authority high-water mark against replays.
func RollbackRelease(ctx context.Context, cfg RollbackConfig) (RollbackOutcome, error) {
	if err := ctx.Err(); err != nil {
		return RollbackOutcome{}, err
	}
	if cfg.InstallRoot == "" || cfg.DataDir == "" {
		return RollbackOutcome{}, fmt.Errorf("%w: InstallRoot and DataDir are required", ErrInvalidReleasePath)
	}
	unlock, err := acquireHostLock(cfg.InstallRoot)
	if err != nil {
		return RollbackOutcome{}, err
	}
	defer unlock()

	beforeData, err := snapshotDataDigests(cfg.DataDir)
	if err != nil {
		return RollbackOutcome{}, err
	}
	if cfg.OverwriteDataWithOldBackup && len(beforeData) > 0 {
		return RollbackOutcome{}, fmt.Errorf("%w: rollback refused attempt to replace newer accepted host data with an older backup", ErrNewerDataOverwriteForbidden)
	}

	authPath := filepath.Join(cfg.InstallRoot, "authority.json")
	existingAuth, hasAuth, err := readAuthorityState(authPath)
	if err != nil {
		return RollbackOutcome{}, err
	}
	if !hasAuth {
		return RollbackOutcome{}, fmt.Errorf("%w: no existing host authority state to roll back from", ErrIncompleteWebOnlyArtifact)
	}

	targetDir := cfg.TargetReleaseDir
	if targetDir == "" {
		targetDir = filepath.Join(cfg.InstallRoot, "previous")
	}
	policy := cfg.Policy
	policy.MinRevision = 1
	policy.RequireSourceBuildAlternative = true

	vr, err := VerifyTrustedRelease(ctx, targetDir, policy)
	if err != nil {
		return RollbackOutcome{}, err
	}

	currentDir := filepath.Join(cfg.InstallRoot, "current")
	previousDir := filepath.Join(cfg.InstallRoot, "previous")
	// Stage from targetDir before rotating current -> previous so targetDir == previous works cleanly.
	stagedDir := filepath.Join(cfg.InstallRoot, fmt.Sprintf(".staging-rollback-%d", time.Now().UnixNano()))
	_ = os.RemoveAll(stagedDir)
	defer os.RemoveAll(stagedDir)
	if _, err := copyTreeWithQuota(targetDir, stagedDir, DefaultMaxReleaseBytes, FaultNone); err != nil {
		return RollbackOutcome{}, err
	}
	if err := swapPreparedStagingAtomic(cfg.InstallRoot, stagedDir, currentDir, previousDir); err != nil {
		return RollbackOutcome{}, err
	}

	now := cfg.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nextAuth := HostAuthorityState{
		SchemaVersion:           "1",
		CurrentVersion:          vr.ReleaseVersion,
		CurrentRevision:         vr.ProvenanceRevision,
		HighestAcceptedRevision: existingAuth.HighestAcceptedRevision,
		PreviousVersion:         existingAuth.CurrentVersion,
		PreviousRevision:        existingAuth.CurrentRevision,
		TrustedKeyID:            vr.ProvenanceKeyID,
		UpdatedAt:               now.Format(time.RFC3339),
	}
	if err := writeJSONAtomic(authPath, nextAuth); err != nil {
		return RollbackOutcome{}, err
	}

	if err := assertDataPreserved(cfg.DataDir, beforeData); err != nil {
		return RollbackOutcome{}, err
	}

	return RollbackOutcome{
		Authority:         nextAuth,
		Verification:      vr,
		PreservedDataFile: len(beforeData),
		RolledBackFrom:    existingAuth.CurrentVersion,
	}, nil
}

func acquireHostLock(installRoot string) (func(), error) {
	lockPath := filepath.Join(installRoot, ".install.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("install lock busy: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func swapReleaseTreeAtomic(installRoot, srcDir, currentDir, previousDir string) error {
	stagedDir := filepath.Join(installRoot, fmt.Sprintf(".staging-install-%d", time.Now().UnixNano()))
	_ = os.RemoveAll(stagedDir)
	defer os.RemoveAll(stagedDir)
	if _, err := copyTreeWithQuota(srcDir, stagedDir, DefaultMaxReleaseBytes, FaultNone); err != nil {
		return err
	}
	return swapPreparedStagingAtomic(installRoot, stagedDir, currentDir, previousDir)
}

func swapPreparedStagingAtomic(installRoot, stagedDir, currentDir, previousDir string) error {
	backupPrev := filepath.Join(installRoot, fmt.Sprintf(".backup-prev-%d", time.Now().UnixNano()))
	hadPrevious := false
	if _, err := os.Lstat(previousDir); err == nil {
		hadPrevious = true
		if err := os.Rename(previousDir, backupPrev); err != nil {
			return err
		}
	}
	hadCurrent := false
	if _, err := os.Lstat(currentDir); err == nil {
		hadCurrent = true
		if err := os.Rename(currentDir, previousDir); err != nil {
			if hadPrevious {
				_ = os.Rename(backupPrev, previousDir)
			}
			return err
		}
	}
	if err := os.Rename(stagedDir, currentDir); err != nil {
		if hadCurrent {
			_ = os.Rename(previousDir, currentDir)
		}
		if hadPrevious {
			_ = os.Rename(backupPrev, previousDir)
		}
		return err
	}
	if hadPrevious {
		_ = os.RemoveAll(backupPrev)
	}
	return nil
}

func snapshotDataDigests(dataDir string) (map[string]string, error) {
	digests := make(map[string]string)
	if _, err := os.Lstat(dataDir); os.IsNotExist(err) {
		return digests, nil
	}
	err := filepath.WalkDir(dataDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dataDir, path)
		if err != nil {
			return err
		}
		sum, err := hashFileAbs(path)
		if err != nil {
			return err
		}
		digests[filepath.ToSlash(rel)] = sum
		return nil
	})
	return digests, err
}

func assertDataPreserved(dataDir string, before map[string]string) error {
	after, err := snapshotDataDigests(dataDir)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(before))
	for k := range before {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		got, ok := after[k]
		if !ok || got != before[k] {
			return fmt.Errorf("%w: host data file %q was modified or discarded", ErrNewerDataOverwriteForbidden, k)
		}
	}
	return nil
}

func readAuthorityState(path string) (HostAuthorityState, bool, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return HostAuthorityState{}, false, nil
	}
	if err != nil {
		return HostAuthorityState{}, false, err
	}
	var state HostAuthorityState
	if err := json.Unmarshal(raw, &state); err != nil {
		return HostAuthorityState{}, false, err
	}
	if strings.TrimSpace(state.SchemaVersion) == "" {
		return HostAuthorityState{}, false, fmt.Errorf("invalid authority state schema version")
	}
	return state, true, nil
}

func writeJSONAtomic(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

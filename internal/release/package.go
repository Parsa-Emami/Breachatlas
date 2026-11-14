package release

import (
	"archive/tar"
	"compress/gzip"
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
	"syscall"
)

const (
	SchemaVersion           = "1"
	ScopeCompleteOpenSource = "complete-open-source"
	DefaultMaxReleaseBytes  = int64(512 * 1024 * 1024) // 512 MiB default bound
	ReleaseManifestFile     = "release.json"
	ChecksumsFile           = "SHA256SUMS.txt"
	SBOMFile                = "sbom.spdx.json"
	NoticesFile             = "THIRD_PARTY_NOTICES.md"
	BuildRecipeFile         = "source/BUILD_RECIPE.json"
	SourceArchiveFile       = "source/breachatlas-source.tar.gz"
	signatureDomainPrefix   = "breachatlas:release-provenance:v1:"
)

var (
	ErrIncompleteWebOnlyArtifact  = errors.New("incomplete or web-only artifact cannot satisfy complete-product release")
	ErrRestrictedOrUnknownLicense = errors.New("unknown or restricted non-permissive license rejected")
	ErrChecksumMismatch           = errors.New("release SHA256SUMS verification failed")
	ErrSignatureInvalid           = errors.New("release Ed25519 provenance signature invalid")
	ErrInterruptedStaging         = errors.New("release writer interrupted at staged-byte/manifest boundary")
	ErrOperationConflict          = errors.New("release operation ID replayed with conflicting inputs")
	ErrReleaseQuotaExceeded       = errors.New("release packaging quota or disk space exceeded")
	ErrSealedSourceModified       = errors.New("sealed source bytes modified during or after packaging")
	ErrInvalidReleasePath         = errors.New("unsafe path traversal or symlink rejected in release tree")
)

var (
	safeIDRegex     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	allowedLicenses = map[string]bool{
		"Apache-2.0":   true,
		"MIT":          true,
		"BSD-3-Clause": true,
		"BSD-2-Clause": true,
		"ISC":          true,
		"MPL-2.0":      true,
		"Artistic-2.0": true,
	}
)

// FaultPoint simulates crash/interruption at atomic release boundaries.
type FaultPoint string

const (
	FaultNone                     FaultPoint = ""
	FaultKillAfterStagedBytes     FaultPoint = "kill_after_staged_bytes"
	FaultKillAfterManifestWrite   FaultPoint = "kill_after_manifest_write"
	FaultQuotaExhaustedDuringCopy FaultPoint = "quota_exhausted_during_copy"
	FaultLostAckAfterCommit       FaultPoint = "lost_ack_after_commit"
)

type ComponentDigest struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	PackageCount int    `json:"packageCount,omitempty"`
}

type ReleaseComponents struct {
	EngineBinary      ComponentDigest `json:"engineBinary"`
	OfflineVerifier   ComponentDigest `json:"offlineVerifier"`
	WebUI             ComponentDigest `json:"webUi"`
	SourceArchive     ComponentDigest `json:"sourceArchive"`
	BuildRecipe       ComponentDigest `json:"buildRecipe"`
	SBOM              ComponentDigest `json:"sbom"`
	ThirdPartyNotices ComponentDigest `json:"thirdPartyNotices"`
	NginxTemplate     ComponentDigest `json:"nginxTemplate"`
	SystemdUnit       ComponentDigest `json:"systemdUnit"`
}

type ReleaseManifest struct {
	SchemaVersion        string            `json:"schemaVersion"`
	Project              string            `json:"project"`
	Scope                string            `json:"scope"`
	ReleaseVersion       string            `json:"releaseVersion,omitempty"`
	EngineReady          bool              `json:"engineReady"`
	OfflineVerifierReady bool              `json:"offlineVerifierReady"`
	Reproducible         bool              `json:"reproducible"`
	SourceCommit         string            `json:"sourceCommit"`
	Dirty                bool              `json:"dirty"`
	Components           ReleaseComponents `json:"components"`
	ProvenanceKeyID      string            `json:"provenanceKeyId,omitempty"`
	ProvenancePublicKey  string            `json:"provenancePublicKey,omitempty"`
	ProvenanceRevision   uint64            `json:"provenanceRevision,omitempty"`
	ProvenanceIssuedAt   string            `json:"provenanceIssuedAt,omitempty"`
	ProvenanceExpiresAt  string            `json:"provenanceExpiresAt,omitempty"`
	ProvenanceSignature  string            `json:"provenanceSignature,omitempty"`
}

type SPDXPackage struct {
	Name             string `json:"name"`
	SPDXID           string `json:"SPDXID"`
	VersionInfo      string `json:"versionInfo"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
}

type SPDXDocument struct {
	SPDXVersion  string        `json:"spdxVersion"`
	DataLicense  string        `json:"dataLicense"`
	SPDXID       string        `json:"SPDXID"`
	Name         string        `json:"name"`
	Packages     []SPDXPackage `json:"packages"`
}

type VerificationResult struct {
	Valid                  bool   `json:"valid"`
	Scope                  string `json:"scope"`
	ReleaseVersion         string `json:"release_version,omitempty"`
	EngineReady            bool   `json:"engine_ready"`
	OfflineVerifierReady   bool   `json:"offline_verifier_ready"`
	SourceBuildRecipeReady bool   `json:"source_build_recipe_ready"`
	VerifiedFiles          int    `json:"verified_files"`
	SBOMPackages           int    `json:"sbom_packages"`
	SourceArchiveFiles     int    `json:"source_archive_files"`
	SignatureVerified      bool   `json:"signature_verified"`
	ProvenanceKeyID        string `json:"provenance_key_id,omitempty"`
	ProvenanceRevision     uint64 `json:"provenance_revision,omitempty"`
	SourceCommit           string `json:"source_commit"`
}

type PackageConfig struct {
	SourceReleaseDir string
	TargetRoot       string
	OperationID      string
	MaxReleaseBytes  int64
	SigningKey       ed25519.PrivateKey
	SigningKeyID     string
	Fault            FaultPoint
	SealedSourcePath string
}

type PackageOutcome struct {
	Manifest          ReleaseManifest `json:"manifest"`
	Replayed          bool            `json:"replayed"`
	StagedCleanedUp   int             `json:"staged_cleaned_up"`
	TotalReleaseBytes int64           `json:"total_release_bytes"`
}

type operationLedgerEntry struct {
	OperationID string          `json:"operation_id"`
	InputDigest string          `json:"input_digest"`
	Manifest    ReleaseManifest `json:"manifest"`
	TotalBytes  int64           `json:"total_bytes"`
}

// VerifyReleaseDirectory validates that dir contains a complete reproducible BreachAtlas release
// (engine binary, offline verifier, web UI, ops templates, offline contracts, reproducible source
// archive + build recipe, SPDX SBOM with permissive licenses, upstream notices, release.json,
// and intact SHA256SUMS.txt). Web-only or incomplete artifacts fail explicitly.
func VerifyReleaseDirectory(ctx context.Context, dir string, trustedPubKey ed25519.PublicKey, requireSignature bool) (VerificationResult, error) {
	if err := ctx.Err(); err != nil {
		return VerificationResult{}, err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("%w: %v", ErrInvalidReleasePath, err)
	}
	info, err := os.Lstat(absDir)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("%w: %v", ErrIncompleteWebOnlyArtifact, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return VerificationResult{}, fmt.Errorf("%w: release path must be a real directory", ErrInvalidReleasePath)
	}

	manifestPath := filepath.Join(absDir, ReleaseManifestFile)
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("%w: missing %s: %v", ErrIncompleteWebOnlyArtifact, ReleaseManifestFile, err)
	}
	var manifest ReleaseManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return VerificationResult{}, fmt.Errorf("%w: malformed %s: %v", ErrIncompleteWebOnlyArtifact, ReleaseManifestFile, err)
	}
	if manifest.Project != "BreachAtlas" || manifest.Scope != ScopeCompleteOpenSource || !manifest.EngineReady || !manifest.OfflineVerifierReady {
		return VerificationResult{}, fmt.Errorf("%w: scope=%q engineReady=%v offlineVerifierReady=%v", ErrIncompleteWebOnlyArtifact, manifest.Scope, manifest.EngineReady, manifest.OfflineVerifierReady)
	}

	// Verify Ed25519 provenance signature if required or present.
	sigVerified := false
	if manifest.ProvenanceSignature != "" || requireSignature {
		if manifest.ProvenanceSignature == "" {
			return VerificationResult{}, fmt.Errorf("%w: missing provenance signature", ErrSignatureInvalid)
		}
		pub := trustedPubKey
		if len(pub) == 0 && manifest.ProvenancePublicKey != "" {
			decodedPub, err := hex.DecodeString(manifest.ProvenancePublicKey)
			if err != nil || len(decodedPub) != ed25519.PublicKeySize {
				return VerificationResult{}, fmt.Errorf("%w: invalid provenancePublicKey", ErrSignatureInvalid)
			}
			pub = ed25519.PublicKey(decodedPub)
		}
		if len(pub) != ed25519.PublicKeySize {
			return VerificationResult{}, fmt.Errorf("%w: missing trusted Ed25519 public key", ErrSignatureInvalid)
		}
		if err := VerifyManifestSignature(manifest, pub); err != nil {
			return VerificationResult{}, err
		}
		sigVerified = true
	}

	// Verify required physical deliverables exist without symlinks and match declared digests.
	requiredFiles := []ComponentDigest{
		manifest.Components.EngineBinary,
		manifest.Components.OfflineVerifier,
		manifest.Components.WebUI,
		manifest.Components.SourceArchive,
		manifest.Components.BuildRecipe,
		manifest.Components.SBOM,
		manifest.Components.ThirdPartyNotices,
		manifest.Components.NginxTemplate,
		manifest.Components.SystemdUnit,
	}
	if len(requiredFiles) == 0 {
		return VerificationResult{}, ErrIncompleteWebOnlyArtifact
	}
	requiredRelPaths := []string{
		"bin/breachatlas",
		"bin/verify",
		"web/index.html",
		SourceArchiveFile,
		BuildRecipeFile,
		SBOMFile,
		NoticesFile,
		"ops/web/nginx.conf.template",
		"ops/web/service.systemd",
		"ops/runtime-requirements.json",
		"docs/engineering/toolchain-lock.json",
		"docs/release/ARTIFACTS.md",
		"LICENSE",
		"NOTICE",
	}
	for _, rel := range requiredRelPaths {
		if _, err := ensureSafeFile(absDir, rel); err != nil {
			return VerificationResult{}, fmt.Errorf("%w: required deliverable %s: %v", ErrIncompleteWebOnlyArtifact, rel, err)
		}
	}
	for _, comp := range requiredFiles {
		if comp.Path == "" {
			return VerificationResult{}, fmt.Errorf("%w: missing component path in release manifest", ErrIncompleteWebOnlyArtifact)
		}
		digest, err := hashSafeFile(absDir, comp.Path)
		if err != nil {
			return VerificationResult{}, fmt.Errorf("%w: %s: %v", ErrIncompleteWebOnlyArtifact, comp.Path, err)
		}
		if comp.SHA256 != "" && digest != comp.SHA256 {
			return VerificationResult{}, fmt.Errorf("%w: component %s digest mismatch (manifest=%s actual=%s)", ErrChecksumMismatch, comp.Path, comp.SHA256, digest)
		}
	}

	// Verify executable bit on packaged Go binaries.
	for _, binRel := range []string{"bin/breachatlas", "bin/verify"} {
		st, err := os.Lstat(filepath.Join(absDir, binRel))
		if err != nil || st.Mode()&0111 == 0 {
			return VerificationResult{}, fmt.Errorf("%w: packaged binary %s is not executable", ErrIncompleteWebOnlyArtifact, binRel)
		}
	}

	// Verify SPDX SBOM & permissive open-source licenses.
	sbomRaw, err := os.ReadFile(filepath.Join(absDir, SBOMFile))
	if err != nil {
		return VerificationResult{}, fmt.Errorf("%w: %v", ErrIncompleteWebOnlyArtifact, err)
	}
	sbomDoc, err := VerifySPDXDocument(sbomRaw)
	if err != nil {
		return VerificationResult{}, err
	}

	// Verify reproducible tar.gz source archive is readable and contains core files.
	archiveFiles, err := verifySourceArchive(filepath.Join(absDir, SourceArchiveFile))
	if err != nil {
		return VerificationResult{}, err
	}

	// Verify SHA256SUMS.txt covers exact directory file set with no mismatch or unsafe paths.
	verifiedCount, err := VerifyChecksums(absDir)
	if err != nil {
		return VerificationResult{}, err
	}

	return VerificationResult{
		Valid:                  true,
		Scope:                  manifest.Scope,
		ReleaseVersion:         manifest.ReleaseVersion,
		EngineReady:            manifest.EngineReady,
		OfflineVerifierReady:   manifest.OfflineVerifierReady,
		SourceBuildRecipeReady: manifest.Reproducible,
		VerifiedFiles:          verifiedCount,
		SBOMPackages:           len(sbomDoc.Packages),
		SourceArchiveFiles:     archiveFiles,
		SignatureVerified:      sigVerified,
		ProvenanceKeyID:        manifest.ProvenanceKeyID,
		ProvenanceRevision:     manifest.ProvenanceRevision,
		SourceCommit:           manifest.SourceCommit,
	}, nil
}

// VerifySPDXDocument validates SPDX 2.3 format and rejects unknown or restricted licenses.
func VerifySPDXDocument(raw []byte) (SPDXDocument, error) {
	var doc SPDXDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return SPDXDocument{}, fmt.Errorf("%w: invalid SPDX SBOM JSON: %v", ErrIncompleteWebOnlyArtifact, err)
	}
	if doc.SPDXVersion != "SPDX-2.3" || len(doc.Packages) == 0 {
		return SPDXDocument{}, fmt.Errorf("%w: SBOM missing SPDX-2.3 header or packages", ErrIncompleteWebOnlyArtifact)
	}
	for _, pkg := range doc.Packages {
		lic := strings.TrimSpace(pkg.LicenseConcluded)
		if lic == "" {
			lic = strings.TrimSpace(pkg.LicenseDeclared)
		}
		if !allowedLicenses[lic] {
			return SPDXDocument{}, fmt.Errorf("%w: package %q has license %q", ErrRestrictedOrUnknownLicense, pkg.Name, lic)
		}
		if strings.TrimSpace(pkg.LicenseDeclared) != "" && !allowedLicenses[strings.TrimSpace(pkg.LicenseDeclared)] {
			return SPDXDocument{}, fmt.Errorf("%w: package %q has declared license %q", ErrRestrictedOrUnknownLicense, pkg.Name, pkg.LicenseDeclared)
		}
	}
	return doc, nil
}

func verifySourceArchive(archivePath string) (int, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return 0, fmt.Errorf("%w: cannot open source archive: %v", ErrIncompleteWebOnlyArtifact, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid gzip in source archive: %v", ErrIncompleteWebOnlyArtifact, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	count := 0
	hasGoMod := false
	hasPkgJson := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("%w: corrupt tar stream in source archive: %v", ErrIncompleteWebOnlyArtifact, err)
		}
		if filepath.IsAbs(hdr.Name) || strings.Contains(hdr.Name, "..") {
			return 0, fmt.Errorf("%w: unsafe tar entry %q", ErrInvalidReleasePath, hdr.Name)
		}
		if hdr.Name == "go.mod" {
			hasGoMod = true
		}
		if hdr.Name == "package.json" {
			hasPkgJson = true
		}
		count++
	}
	if count == 0 || !hasGoMod || !hasPkgJson {
		return 0, fmt.Errorf("%w: source archive missing go.mod or package.json", ErrIncompleteWebOnlyArtifact)
	}
	return count, nil
}

// VerifyChecksums ensures SHA256SUMS.txt accurately matches every file in absDir (and detects extra/missing files).
func VerifyChecksums(absDir string) (int, error) {
	raw, err := os.ReadFile(filepath.Join(absDir, ChecksumsFile))
	if err != nil {
		return 0, fmt.Errorf("%w: missing %s: %v", ErrChecksumMismatch, ChecksumsFile, err)
	}
	recorded := make(map[string]string)
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 {
			return 0, fmt.Errorf("%w: malformed checksum line %q", ErrChecksumMismatch, line)
		}
		rel := filepath.ToSlash(parts[1])
		if filepath.IsAbs(rel) || strings.Contains(rel, "..") {
			return 0, fmt.Errorf("%w: unsafe checksum path %q", ErrInvalidReleasePath, rel)
		}
		recorded[rel] = parts[0]
	}

	actual := make(map[string]string)
	err = filepath.WalkDir(absDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink in release tree: %s", ErrInvalidReleasePath, path)
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(absDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ChecksumsFile {
			return nil
		}
		sum, err := hashFileAbs(path)
		if err != nil {
			return err
		}
		actual[rel] = sum
		return nil
	})
	if err != nil {
		return 0, err
	}

	if len(recorded) != len(actual) {
		return 0, fmt.Errorf("%w: checksum manifest count (%d) does not match actual files (%d)", ErrChecksumMismatch, len(recorded), len(actual))
	}
	for rel, expectedHash := range recorded {
		gotHash, ok := actual[rel]
		if !ok {
			return 0, fmt.Errorf("%w: missing file %s listed in %s", ErrChecksumMismatch, rel, ChecksumsFile)
		}
		if gotHash != expectedHash {
			return 0, fmt.Errorf("%w: hash mismatch for %s", ErrChecksumMismatch, rel)
		}
	}
	return len(actual), nil
}

// SignManifest creates a canonical Ed25519 signature over the release provenance payload.
func SignManifest(manifest ReleaseManifest, priv ed25519.PrivateKey, keyID string) (ReleaseManifest, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return ReleaseManifest{}, fmt.Errorf("%w: invalid Ed25519 private key length", ErrSignatureInvalid)
	}
	pub := priv.Public().(ed25519.PublicKey)
	signed := manifest
	signed.ProvenanceKeyID = keyID
	signed.ProvenancePublicKey = hex.EncodeToString(pub)
	signed.ProvenanceSignature = ""
	payload, err := canonicalManifestSignPayload(signed)
	if err != nil {
		return ReleaseManifest{}, err
	}
	sig := ed25519.Sign(priv, payload)
	signed.ProvenanceSignature = hex.EncodeToString(sig)
	return signed, nil
}

// VerifyManifestSignature verifies an Ed25519 provenance signature on a ReleaseManifest.
func VerifyManifestSignature(manifest ReleaseManifest, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid Ed25519 public key length", ErrSignatureInvalid)
	}
	if manifest.ProvenancePublicKey != "" && manifest.ProvenancePublicKey != hex.EncodeToString(pub) {
		return fmt.Errorf("%w: manifest public key does not match trusted key", ErrSignatureInvalid)
	}
	sigBytes, err := hex.DecodeString(manifest.ProvenanceSignature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature hex", ErrSignatureInvalid)
	}
	unsigned := manifest
	unsigned.ProvenanceSignature = ""
	payload, err := canonicalManifestSignPayload(unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sigBytes) {
		return fmt.Errorf("%w: Ed25519 signature verification failed", ErrSignatureInvalid)
	}
	return nil
}

func canonicalManifestSignPayload(m ReleaseManifest) ([]byte, error) {
	m.ProvenanceSignature = ""
	encoded, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append([]byte(signatureDomainPrefix), encoded...), nil
}

// RecoverStaging removes orphaned temporary staging directories inside targetRoot
// so restart exposes only a complete prior or new authoritative release directory.
func RecoverStaging(targetRoot string) (int, error) {
	entries, err := os.ReadDir(targetRoot)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	cleaned := 0
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".staging-") || strings.HasPrefix(name, ".backup-") {
			if err := os.RemoveAll(filepath.Join(targetRoot, name)); err != nil {
				return cleaned, err
			}
			cleaned++
		}
	}
	return cleaned, nil
}

// PackageCompleteRelease verifies SourceReleaseDir, enforces MaxReleaseBytes quota and
// sealed source immutability, optionally signs provenance with Ed25519, stages files
// atomically under TargetRoot, and maintains a bounded idempotent operation ledger.
func PackageCompleteRelease(ctx context.Context, cfg PackageConfig) (PackageOutcome, error) {
	if err := ctx.Err(); err != nil {
		return PackageOutcome{}, err
	}
	if !safeIDRegex.MatchString(cfg.OperationID) {
		return PackageOutcome{}, fmt.Errorf("%w: invalid operation ID %q", ErrInvalidReleasePath, cfg.OperationID)
	}
	if cfg.TargetRoot == "" {
		return PackageOutcome{}, fmt.Errorf("%w: TargetRoot required", ErrInvalidReleasePath)
	}
	if err := os.MkdirAll(cfg.TargetRoot, 0o755); err != nil {
		return PackageOutcome{}, err
	}

	// Clean up any leftover interrupted staging dirs from an earlier crash.
	cleaned, err := RecoverStaging(cfg.TargetRoot)
	if err != nil {
		return PackageOutcome{}, err
	}

	// Acquire exclusive advisory flock on targetRoot/.release.lock.
	lockPath := filepath.Join(cfg.TargetRoot, ".release.lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return PackageOutcome{}, err
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return PackageOutcome{}, fmt.Errorf("release lock busy: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	// Measure sealed source bytes BEFORE verification/packaging if provided.
	var sealedBefore string
	if cfg.SealedSourcePath != "" {
		sealedBefore, err = hashFileAbs(cfg.SealedSourcePath)
		if err != nil {
			return PackageOutcome{}, fmt.Errorf("%w: cannot read sealed source: %v", ErrSealedSourceModified, err)
		}
	}

	// Verify the input release directory is a complete open-source release (rejects web-only).
	vr, err := VerifyReleaseDirectory(ctx, cfg.SourceReleaseDir, nil, false)
	if err != nil {
		return PackageOutcome{}, err
	}

	sourceChecksums, err := hashFileAbs(filepath.Join(cfg.SourceReleaseDir, ChecksumsFile))
	if err != nil {
		return PackageOutcome{}, err
	}
	inputDigest := fmt.Sprintf("%s|%s|%d", vr.SourceCommit, sourceChecksums, cfg.MaxReleaseBytes)

	ledgerPath := filepath.Join(cfg.TargetRoot, "release-ops.json")
	ledger, err := readLedger(ledgerPath)
	if err != nil {
		return PackageOutcome{}, err
	}
	if existing, ok := ledger[cfg.OperationID]; ok {
		if existing.InputDigest != inputDigest {
			return PackageOutcome{}, fmt.Errorf("%w: operation %s already committed with different release contents", ErrOperationConflict, cfg.OperationID)
		}
		// Replay of already-committed operation (e.g. after lost ACK): verify live current tree and return idempotently.
		currentDir := filepath.Join(cfg.TargetRoot, "current")
		if _, err := VerifyReleaseDirectory(ctx, currentDir, nil, false); err != nil {
			return PackageOutcome{}, err
		}
		return PackageOutcome{
			Manifest:          existing.Manifest,
			Replayed:          true,
			StagedCleanedUp:   cleaned,
			TotalReleaseBytes: existing.TotalBytes,
		}, nil
	}

	maxBytes := cfg.MaxReleaseBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxReleaseBytes
	}

	stagingDir := filepath.Join(cfg.TargetRoot, ".staging-"+cfg.OperationID)
	_ = os.RemoveAll(stagingDir)
	defer os.RemoveAll(stagingDir)

	totalBytes, err := copyTreeWithQuota(cfg.SourceReleaseDir, stagingDir, maxBytes, cfg.Fault)
	if err != nil {
		return PackageOutcome{}, err
	}

	if cfg.Fault == FaultKillAfterStagedBytes {
		return PackageOutcome{}, fmt.Errorf("%w: simulated kill after staged bytes", ErrInterruptedStaging)
	}

	// Read manifest and optionally attach Ed25519 provenance signature inside stagingDir.
	mBytes, err := os.ReadFile(filepath.Join(stagingDir, ReleaseManifestFile))
	if err != nil {
		return PackageOutcome{}, err
	}
	var manifest ReleaseManifest
	if err := json.Unmarshal(mBytes, &manifest); err != nil {
		return PackageOutcome{}, err
	}
	if len(cfg.SigningKey) == ed25519.PrivateKeySize {
		manifest, err = SignManifest(manifest, cfg.SigningKey, cfg.SigningKeyID)
		if err != nil {
			return PackageOutcome{}, err
		}
	}
	updatedManifest, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return PackageOutcome{}, err
	}
	updatedManifest = append(updatedManifest, '\n')
	if err := os.WriteFile(filepath.Join(stagingDir, ReleaseManifestFile), updatedManifest, 0o644); err != nil {
		return PackageOutcome{}, err
	}

	// Recompute SHA256SUMS.txt inside stagingDir so any provenance signature is included.
	if err := writeChecksums(stagingDir); err != nil {
		return PackageOutcome{}, err
	}

	if cfg.Fault == FaultKillAfterManifestWrite {
		return PackageOutcome{}, fmt.Errorf("%w: simulated kill at manifest commit boundary", ErrInterruptedStaging)
	}

	// Ensure sealed source file was never modified before swapping staging -> current.
	if cfg.SealedSourcePath != "" {
		sealedAfter, err := hashFileAbs(cfg.SealedSourcePath)
		if err != nil || sealedAfter != sealedBefore {
			return PackageOutcome{}, ErrSealedSourceModified
		}
	}

	// Atomically promote stagingDir -> current.
	currentDir := filepath.Join(cfg.TargetRoot, "current")
	backupDir := filepath.Join(cfg.TargetRoot, ".backup-"+cfg.OperationID)
	_ = os.RemoveAll(backupDir)

	hadCurrent := false
	if _, err := os.Lstat(currentDir); err == nil {
		hadCurrent = true
		if err := os.Rename(currentDir, backupDir); err != nil {
			return PackageOutcome{}, err
		}
	}
	if err := os.Rename(stagingDir, currentDir); err != nil {
		if hadCurrent {
			_ = os.Rename(backupDir, currentDir)
		}
		return PackageOutcome{}, err
	}
	if hadCurrent {
		_ = os.RemoveAll(backupDir)
	}

	// Persist idempotent operation ledger atomically.
	ledger[cfg.OperationID] = operationLedgerEntry{
		OperationID: cfg.OperationID,
		InputDigest: inputDigest,
		Manifest:    manifest,
		TotalBytes:  totalBytes,
	}
	if err := writeLedgerAtomic(ledgerPath, ledger); err != nil {
		return PackageOutcome{}, err
	}

	if cfg.Fault == FaultLostAckAfterCommit {
		return PackageOutcome{}, fmt.Errorf("%w: simulated lost ACK after authoritative commit", ErrInterruptedStaging)
	}

	return PackageOutcome{
		Manifest:          manifest,
		Replayed:          false,
		StagedCleanedUp:   cleaned,
		TotalReleaseBytes: totalBytes,
	}, nil
}

func copyTreeWithQuota(srcRoot, dstRoot string, maxBytes int64, fault FaultPoint) (int64, error) {
	var total int64
	if err := os.MkdirAll(dstRoot, 0o755); err != nil {
		return 0, err
	}
	var copiedFiles int
	err := filepath.WalkDir(srcRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink rejected %s", ErrInvalidReleasePath, path)
		}
		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dstRoot, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		if total > maxBytes || (fault == FaultQuotaExhaustedDuringCopy && copiedFiles >= 2) {
			return fmt.Errorf("%w: release size (%d bytes) exceeds quota (%d bytes)", ErrReleaseQuotaExceeded, total, maxBytes)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mode := info.Mode() & 0o755
		if mode == 0 {
			mode = 0o644
		}
		copiedFiles++
		return os.WriteFile(target, data, mode)
	})
	return total, err
}

func writeChecksums(rootDir string) error {
	var rels []string
	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ChecksumsFile {
			return nil
		}
		rels = append(rels, rel)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(rels)
	var b strings.Builder
	for _, rel := range rels {
		sum, err := hashFileAbs(filepath.Join(rootDir, rel))
		if err != nil {
			return err
		}
		b.WriteString(sum)
		b.WriteString("  ")
		b.WriteString(rel)
		b.WriteByte('\n')
	}
	return os.WriteFile(filepath.Join(rootDir, ChecksumsFile), []byte(b.String()), 0o644)
}

func ensureSafeFile(baseDir, rel string) (string, error) {
	clean := filepath.Clean(rel)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return "", ErrInvalidReleasePath
	}
	cur := baseDir
	for _, part := range strings.Split(filepath.ToSlash(clean), "/") {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		if err != nil {
			return "", err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", ErrInvalidReleasePath
		}
	}
	st, err := os.Lstat(cur)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", rel)
	}
	return cur, nil
}

func hashSafeFile(baseDir, rel string) (string, error) {
	abs, err := ensureSafeFile(baseDir, rel)
	if err != nil {
		return "", err
	}
	return hashFileAbs(abs)
}

func hashFileAbs(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readLedger(path string) (map[string]operationLedgerEntry, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return make(map[string]operationLedgerEntry), nil
	}
	if err != nil {
		return nil, err
	}
	var ledger map[string]operationLedgerEntry
	if err := json.Unmarshal(raw, &ledger); err != nil {
		return nil, err
	}
	if ledger == nil {
		ledger = make(map[string]operationLedgerEntry)
	}
	return ledger, nil
}

func writeLedgerAtomic(path string, ledger map[string]operationLedgerEntry) error {
	raw, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

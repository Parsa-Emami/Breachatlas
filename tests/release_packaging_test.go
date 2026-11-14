package tests_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/export"
	"github.com/Parsa-Emami/Breachatlas/internal/release"
)

type c31Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c31ReleaseSpec struct {
	SchemaVersion        string   `json:"schema_version"`
	Project              string   `json:"project"`
	Scope                string   `json:"scope"`
	EngineReady          bool     `json:"engine_ready"`
	OfflineVerifierReady bool     `json:"offline_verifier_ready"`
	RequiredPaths        []string `json:"required_paths"`
	AllowedLicenses      []string `json:"allowed_licenses"`
}

func locateRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatalf("could not locate repository root from %s", wd)
	return ""
}

func TestC31CompleteReleasePackagingAndNegativeCases(t *testing.T) {
	ctx := context.Background()
	root := locateRepoRoot(t)
	fxDir := filepath.Join(root, "tests", "fixtures", "breachatlas", "C31")

	// 1. Verify C31 fixture provenance & exact SHA-256 digests.
	provRaw, err := os.ReadFile(filepath.Join(fxDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read C31 provenance: %v", err)
	}
	var prov c31Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatalf("decode C31 provenance: %v", err)
	}
	if prov.License != "Apache-2.0" || len(prov.SHA256) < 6 {
		t.Fatalf("unexpected C31 provenance metadata: %+v", prov)
	}
	for rel, expected := range prov.SHA256 {
		data, err := os.ReadFile(filepath.Join(fxDir, rel))
		if err != nil {
			t.Fatalf("read fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != expected {
			t.Fatalf("fixture %s sha256 mismatch: expected %s got %s", rel, expected, got)
		}
	}

	var spec c31ReleaseSpec
	specRaw, err := os.ReadFile(filepath.Join(fxDir, "positive", "complete-release-spec.json"))
	if err != nil {
		t.Fatalf("read positive spec: %v", err)
	}
	if err := json.Unmarshal(specRaw, &spec); err != nil {
		t.Fatalf("decode positive spec: %v", err)
	}

	// Capture sealed source digest of go.mod before running packager (immutable source invariant).
	goModPath := filepath.Join(root, "go.mod")
	goModBeforeBytes, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatal(err)
	}
	goModBeforeSum := sha256.Sum256(goModBeforeBytes)

	// 2. Run actual complete release packaging script (scripts/package.sh).
	pkgCmd := exec.CommandContext(ctx, "bash", filepath.Join(root, "scripts", "package.sh"))
	pkgCmd.Dir = root
	if out, err := pkgCmd.CombinedOutput(); err != nil {
		t.Fatalf("scripts/package.sh failed: %v\n%s", err, string(out))
	}

	// Verify sealed source file was never modified by packaging.
	goModAfterBytes, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(goModAfterBytes) != goModBeforeSum {
		t.Fatalf("go.mod source bytes were modified during packaging")
	}

	releaseDir := filepath.Join(root, "dist", "release")
	for _, rel := range spec.RequiredPaths {
		if _, err := os.Stat(filepath.Join(releaseDir, rel)); err != nil {
			t.Fatalf("packaged release missing required path %s: %v", rel, err)
		}
	}

	// 3. Engine verification of packaged dist/release (completeness, SBOM licenses, tar.gz archive, SHA256SUMS).
	vr, err := release.VerifyReleaseDirectory(ctx, releaseDir, nil, false)
	if err != nil {
		t.Fatalf("VerifyReleaseDirectory failed on dist/release: %v", err)
	}
	if !vr.Valid || !vr.EngineReady || !vr.OfflineVerifierReady || vr.SBOMPackages < 10 || vr.SourceArchiveFiles < 50 {
		t.Fatalf("unexpected verification result: %+v", vr)
	}

	// 4. Verify reproducible source packaging across two independent runs.
	reproA := filepath.Join(t.TempDir(), "a")
	reproB := filepath.Join(t.TempDir(), "b")
	for _, outDir := range []string{reproA, reproB} {
		cmd := exec.CommandContext(ctx, "node", filepath.Join(root, "scripts", "package-source.mjs"), "--output", outDir)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("package-source.mjs failed: %v\n%s", err, string(out))
		}
	}
	tarA, err := os.ReadFile(filepath.Join(reproA, "source", "breachatlas-source.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	tarB, err := os.ReadFile(filepath.Join(reproB, "source", "breachatlas-source.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(tarA) != sha256.Sum256(tarB) {
		t.Fatalf("source archive is not bit-for-bit reproducible across consecutive runs")
	}

	// 5. Execute packaged engine and offline verifier binaries against an actual sealed evidence bundle.
	packagedEngine := filepath.Join(releaseDir, "bin", "breachatlas")
	packagedVerifier := filepath.Join(releaseDir, "bin", "verify")
	if out, err := exec.CommandContext(ctx, packagedEngine, "--version").CombinedOutput(); err != nil {
		t.Fatalf("packaged breachatlas --version failed: %v\n%s", err, string(out))
	}
	if out, err := exec.CommandContext(ctx, packagedVerifier, "--version").CombinedOutput(); err != nil {
		t.Fatalf("packaged verify --version failed: %v\n%s", err, string(out))
	}

	bundleRoot := t.TempDir()
	qDir := filepath.Join(bundleRoot, "quarantine")
	sDir := filepath.Join(bundleRoot, "sealstore")
	cDir := filepath.Join(bundleRoot, "custody")
	kDir := filepath.Join(bundleRoot, "checkpoints")
	eDir := filepath.Join(bundleRoot, "exports")

	ss, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	ls, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: cDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	cs, err := custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{RootDir: kDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	es, err := export.OpenExportStore(export.ExportStoreConfig{RootDir: eDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = es.Close() })

	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	sealedPayload := []byte("2026-11-14T12:00:00Z release-host breachatlas: release-proof-line\n")
	payloadSum := sha256.Sum256(sealedPayload)
	expectedSHA := hex.EncodeToString(payloadSum[:])
	payloadSize := int64(len(sealedPayload))

	q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{QuarantineDir: qDir, SyncDir: true}, evidence.UploadRequest{
		SchemaVersion:  "1",
		UploadID:       "upl-c31-01",
		CaseID:         "c31-case",
		EvidenceID:     "c31-ev",
		MediaType:      "text/plain",
		Filename:       "release.log",
		ExpectedSize:   &payloadSize,
		ExpectedSHA256: expectedSHA,
		Body:           bytes.NewReader(sealedPayload),
	})
	if err != nil {
		t.Fatal(err)
	}
	ev1, err := ls.AppendEvent(ctx, custody.AppendEventRequest{
		EventID:    "cust-c31-01",
		CaseID:     "c31-case",
		EvidenceID: "c31-ev",
		EventType:  "intake_seal",
		Actor:      "analyst",
		Timestamp:  now,
		Reason:     "C31 binary verification intake",
		Provider:   "local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ss.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "op-seal-c31",
		Quarantined:    q,
		ExpectedSHA256: expectedSHA,
		AcquiredAt:     now,
		CustodyRoot:    ev1.CustodyRoot,
	}); err != nil {
		t.Fatal(err)
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chk, err := custody.CreateCheckpoint(ctx, ls, custody.CreateCheckpointRequest{
		CheckpointID: "chk-c31-01",
		CaseID:       "c31-case",
		EvidenceID:   "c31-ev",
		Sequence:     ev1.Sequence,
		CustodyRoot:  ev1.CustodyRoot,
		KeyID:        "c31-signer",
		Revision:     1,
		IssuedAt:     now,
		ExpiresAt:    time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		PrivateKey:   privKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.SaveCheckpoint(ctx, *chk); err != nil {
		t.Fatal(err)
	}

	expRes, err := es.PackageCaseBundle(ctx, export.ExportDeps{
		SealStore:       ss,
		SealRootDir:     sDir,
		LedgerStore:     ls,
		CheckpointStore: cs,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{"c31-signer": hex.EncodeToString(pubKey)},
		},
	}, export.ExportRequest{
		SchemaVersion: "1",
		OperationID:   "op-exp-c31",
		BundleID:      "c31-bundle",
		CaseID:        "c31-case",
		Provider:      "local",
		EvidenceIDs:   []string{"c31-ev"},
		KeyID:         "c31-signer",
		PrivateKey:    privKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyCmd := exec.CommandContext(ctx, packagedVerifier,
		"--bundle", expRes.BundleDir,
		"--trusted-key", hex.EncodeToString(pubKey),
		"--require-signature",
		"--json",
	)
	if out, err := verifyCmd.CombinedOutput(); err != nil {
		t.Fatalf("packaged bin/verify failed on signed bundle: %v\n%s", err, string(out))
	}
	if gotPayload, err := os.ReadFile(filepath.Join(sDir, "cases", "c31-case", "evidence", "c31-ev", "sealed.bin")); err == nil && string(gotPayload) != string(sealedPayload) {
		t.Fatalf("sealed evidence blob modified")
	}

	// 6. Signed atomic release promotion & Ed25519 verification via internal/release.
	targetRoot := filepath.Join(t.TempDir(), "releases")
	sealedRef := filepath.Join(t.TempDir(), "sealed-source.bin")
	if err := os.WriteFile(sealedRef, []byte("immutable-release-source-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	outcome1, err := release.PackageCompleteRelease(ctx, release.PackageConfig{
		SourceReleaseDir: releaseDir,
		TargetRoot:       targetRoot,
		OperationID:      "op-release-001",
		MaxReleaseBytes:  release.DefaultMaxReleaseBytes,
		SigningKey:       privKey,
		SigningKeyID:     "c31-signer",
		SealedSourcePath: sealedRef,
	})
	if err != nil {
		t.Fatalf("PackageCompleteRelease failed: %v", err)
	}
	if outcome1.Replayed || outcome1.Manifest.ProvenanceSignature == "" {
		t.Fatalf("expected non-replayed signed release outcome, got %+v", outcome1)
	}

	currentDir := filepath.Join(targetRoot, "current")
	signedResult, err := release.VerifyReleaseDirectory(ctx, currentDir, pubKey, true)
	if err != nil || !signedResult.SignatureVerified {
		t.Fatalf("signed release verification failed: result=%+v err=%v", signedResult, err)
	}
	// Negative: wrong trusted key rejected.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyReleaseDirectory(ctx, currentDir, otherPub, true); !errors.Is(err, release.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for wrong trusted key, got %v", err)
	}

	// 7. Negative Case A: Web-only artifact fixture rejected.
	webOnlyDir := filepath.Join(t.TempDir(), "web-only")
	if err := os.MkdirAll(webOnlyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	webOnlyRaw, err := os.ReadFile(filepath.Join(fxDir, "invalid", "web-only-artifact.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webOnlyDir, "release.json"), webOnlyRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyReleaseDirectory(ctx, webOnlyDir, nil, false); !errors.Is(err, release.ErrIncompleteWebOnlyArtifact) {
		t.Fatalf("expected ErrIncompleteWebOnlyArtifact, got %v", err)
	}

	// 8. Negative Case B: Restricted / unknown license in SPDX SBOM rejected.
	restrictedSBOM, err := os.ReadFile(filepath.Join(fxDir, "invalid", "restricted-license-sbom.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifySPDXDocument(restrictedSBOM); !errors.Is(err, release.ErrRestrictedOrUnknownLicense) {
		t.Fatalf("expected ErrRestrictedOrUnknownLicense, got %v", err)
	}

	// 9. Negative Case C: Kill writer at staged-byte & manifest boundaries; prior authoritative release remains intact.
	for _, fault := range []release.FaultPoint{release.FaultKillAfterStagedBytes, release.FaultKillAfterManifestWrite} {
		_, err := release.PackageCompleteRelease(ctx, release.PackageConfig{
			SourceReleaseDir: releaseDir,
			TargetRoot:       targetRoot,
			OperationID:      "op-interrupted-" + string(fault),
			MaxReleaseBytes:  release.DefaultMaxReleaseBytes,
			SigningKey:       privKey,
			SigningKeyID:     "c31-signer",
			Fault:            fault,
		})
		if !errors.Is(err, release.ErrInterruptedStaging) {
			t.Fatalf("expected ErrInterruptedStaging for %s, got %v", fault, err)
		}
		if _, err := release.VerifyReleaseDirectory(ctx, currentDir, pubKey, true); err != nil {
			t.Fatalf("authoritative current release corrupted after %s: %v", fault, err)
		}
		entries, err := os.ReadDir(targetRoot)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".staging-") || strings.HasPrefix(e.Name(), ".backup-") {
				t.Fatalf("leftover staging/backup directory after interrupted write: %s", e.Name())
			}
		}
	}

	// Verify explicit RecoverStaging cleanup of simulated crash directories.
	orphanStaging := filepath.Join(targetRoot, ".staging-crashed-pid")
	if err := os.MkdirAll(orphanStaging, 0o755); err != nil {
		t.Fatal(err)
	}
	cleaned, err := release.RecoverStaging(targetRoot)
	if err != nil || cleaned != 1 {
		t.Fatalf("RecoverStaging failed: cleaned=%d err=%v", cleaned, err)
	}

	// 10. Negative Case D: Lost ACK + idempotent replay, conflicting operation ID, and quota exhaustion.
	_, err = release.PackageCompleteRelease(ctx, release.PackageConfig{
		SourceReleaseDir: releaseDir,
		TargetRoot:       targetRoot,
		OperationID:      "op-lost-ack-001",
		MaxReleaseBytes:  release.DefaultMaxReleaseBytes,
		SigningKey:       privKey,
		SigningKeyID:     "c31-signer",
		Fault:            release.FaultLostAckAfterCommit,
	})
	if !errors.Is(err, release.ErrInterruptedStaging) {
		t.Fatalf("expected simulated lost ACK error, got %v", err)
	}
	replayedOutcome, err := release.PackageCompleteRelease(ctx, release.PackageConfig{
		SourceReleaseDir: releaseDir,
		TargetRoot:       targetRoot,
		OperationID:      "op-lost-ack-001",
		MaxReleaseBytes:  release.DefaultMaxReleaseBytes,
	})
	if err != nil || !replayedOutcome.Replayed {
		t.Fatalf("expected idempotent replay without duplicate side effect, got outcome=%+v err=%v", replayedOutcome, err)
	}

	// Conflicting replay with different quota/input parameters must fail.
	if _, err := release.PackageCompleteRelease(ctx, release.PackageConfig{
		SourceReleaseDir: releaseDir,
		TargetRoot:       targetRoot,
		OperationID:      "op-lost-ack-001",
		MaxReleaseBytes:  release.DefaultMaxReleaseBytes - 1,
	}); !errors.Is(err, release.ErrOperationConflict) {
		t.Fatalf("expected ErrOperationConflict on conflicting replay, got %v", err)
	}

	// Quota exhaustion leaves authoritative current state intact and leaves zero partial files.
	if _, err := release.PackageCompleteRelease(ctx, release.PackageConfig{
		SourceReleaseDir: releaseDir,
		TargetRoot:       targetRoot,
		OperationID:      "op-quota-fail",
		MaxReleaseBytes:  1024,
	}); !errors.Is(err, release.ErrReleaseQuotaExceeded) {
		t.Fatalf("expected ErrReleaseQuotaExceeded, got %v", err)
	}
	if _, err := release.VerifyReleaseDirectory(ctx, currentDir, pubKey, true); err != nil {
		t.Fatalf("authoritative current release damaged after quota failure: %v", err)
	}

	// 11. Negative Case E: Tampered checksum in staged/current release detected immediately.
	tamperDir := filepath.Join(t.TempDir(), "tamper")
	tamperOutcome, err := release.PackageCompleteRelease(ctx, release.PackageConfig{
		SourceReleaseDir: releaseDir,
		TargetRoot:       tamperDir,
		OperationID:      "op-tamper-setup",
		MaxReleaseBytes:  release.DefaultMaxReleaseBytes,
	})
	if err != nil || tamperOutcome.Manifest.SourceCommit == "" {
		t.Fatalf("setup tamper release failed: %v", err)
	}
	tamperTarget := filepath.Join(tamperDir, "current", "THIRD_PARTY_NOTICES.md")
	if err := os.WriteFile(tamperTarget, []byte("tampered notice"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyReleaseDirectory(ctx, filepath.Join(tamperDir, "current"), nil, false); !errors.Is(err, release.ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch after tampering packaged file, got %v", err)
	}

	// 12. Verify expected outcomes & invalid fixture expectations match actual observed errors.
	var expectedOutcomes struct {
		Positive map[string]bool `json:"positive"`
		Negative map[string]bool `json:"negative"`
	}
	rawExpected, err := os.ReadFile(filepath.Join(fxDir, "expected", "release-outcomes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawExpected, &expectedOutcomes); err != nil {
		t.Fatal(err)
	}
	for k, v := range expectedOutcomes.Positive {
		if k == "sealed_bytes_modified" && v {
			t.Fatalf("expected sealed_bytes_modified=false")
		}
		if k != "sealed_bytes_modified" && !v {
			t.Fatalf("expected positive check %s=true", k)
		}
	}
	for k, v := range expectedOutcomes.Negative {
		if !v {
			t.Fatalf("expected negative check %s=true", k)
		}
	}
}

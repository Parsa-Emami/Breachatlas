package tests_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/export"
)

type c24Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c24PositiveFixture struct {
	SchemaVersion    string `json:"schema_version"`
	CaseID           string `json:"case_id"`
	EvidenceID       string `json:"evidence_id"`
	ArtifactID       string `json:"artifact_id"`
	BundleIDSigned   string `json:"bundle_id_signed"`
	BundleIDUnsigned string `json:"bundle_id_unsigned"`
	KeyID            string `json:"key_id"`
	TrustedKeyID     string `json:"trusted_key_id"`
	UntrustedKeyID   string `json:"untrusted_key_id"`
	ZoneHint         string `json:"zone_hint"`
	PayloadSample    string `json:"payload_sample"`
}

type c24TamperedCase struct {
	Name                         string `json:"name"`
	TargetFile                   string `json:"target_file"`
	TamperAction                 string `json:"tamper_action"`
	ExpectedEvidenceIntegrity    string `json:"expected_evidence_integrity,omitempty"`
	ExpectedCustodyRootIntegrity string `json:"expected_custody_root_integrity,omitempty"`
	ExpectedSignatureStatus      string `json:"expected_signature_status,omitempty"`
	ExpectedVerified             bool   `json:"expected_verified"`
}

type c24NegativeCasesFixture struct {
	SchemaVersion string            `json:"schema_version"`
	Cases         []c24TamperedCase `json:"cases"`
}

type c24ExpectedResultsFixture struct {
	SchemaVersion string `json:"schema_version"`
	TrustedSigned struct {
		BundleVersion          string `json:"bundle_version"`
		Verified               bool   `json:"verified"`
		EvidenceIntegrity      string `json:"evidence_integrity"`
		CustodyRootIntegrity   string `json:"custody_root_integrity"`
		SignatureStatus        string `json:"signature_status"`
		SignatureValid         bool   `json:"signature_valid"`
		RawTimestampsPreserved bool   `json:"raw_timestamps_preserved"`
		RequiresServer         bool   `json:"requires_server"`
	} `json:"trusted_signed"`
	ValidUnsigned struct {
		BundleVersion          string `json:"bundle_version"`
		Verified               bool   `json:"verified"`
		EvidenceIntegrity      string `json:"evidence_integrity"`
		CustodyRootIntegrity   string `json:"custody_root_integrity"`
		SignatureStatus        string `json:"signature_status"`
		SignatureValid         bool   `json:"signature_valid"`
		RawTimestampsPreserved bool   `json:"raw_timestamps_preserved"`
		RequiresServer         bool   `json:"requires_server"`
	} `json:"valid_unsigned"`
}

func getC24FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		cand := filepath.Join(dir, "tests", "fixtures", "breachatlas", "C24")
		if info, err := os.Stat(cand); err == nil && info.IsDir() {
			return cand
		}
	}
	t.Fatalf("could not locate tests/fixtures/breachatlas/C24 from %s", wd)
	return ""
}

func loadC24JSON[T any](t *testing.T, rel string) T {
	t.Helper()
	p := filepath.Join(getC24FixturesDir(t), filepath.FromSlash(rel))
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("load C24 fixture %s: %v", rel, err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal C24 fixture %s: %v", rel, err)
	}
	return out
}

func buildVerifyBinaryForTest(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "verify")

	// Locate repo root
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := wd
	for dir := wd; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			repoRoot = dir
			break
		}
	}

	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/verify")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build cmd/verify binary: %v\nOutput: %s", err, string(out))
	}
	return binPath
}

func makeTestC23Fixture(fx c24PositiveFixture) c23PositiveFixture {
	c23Fx := c23PositiveFixture{
		CaseID:          fx.CaseID,
		PayloadJSONL:    fx.PayloadSample,
		ZoneHint:        fx.ZoneHint,
		CheckpointKeyID: fx.TrustedKeyID,
	}
	c23Fx.Hypothesis.HypothesisID = "hyp-001"
	c23Fx.Hypothesis.Author = "analyst-mina"
	c23Fx.Hypothesis.Rationale = "Synthetic login spike hypothesis"
	c23Fx.Hypothesis.Statement = "Lateral movement suspected via account alice"
	c23Fx.Hypothesis.UILabel = "Lateral Movement"
	return c23Fx
}

func TestC24FixturesAndProvenance(t *testing.T) {
	prov := loadC24JSON[c24Provenance](t, "provenance.json")
	if prov.Task != "C24" || prov.License != "Apache-2.0" {
		t.Fatalf("unexpected C24 provenance: %+v", prov)
	}
	if len(prov.SHA256) != 3 {
		t.Fatalf("expected 3 hashed C24 fixture files, got %d", len(prov.SHA256))
	}
	dir := getC24FixturesDir(t)
	for rel, want := range prov.SHA256 {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("missing C24 fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("fixture %s sha mismatch: got %s want %s", rel, got, want)
		}
	}
}

func TestOfflineVerifyTrustedSignedBundle(t *testing.T) {
	fx := loadC24JSON[c24PositiveFixture](t, "positive/valid-bundle-verification.json")
	expected := loadC24JSON[c24ExpectedResultsFixture](t, "expected-output/offline-verification-results.json")
	env := setupC23Env(t)

	c23Fx := makeTestC23Fixture(fx)
	seeded := seedFullCaseForC23(t, env, c23Fx, fx.EvidenceID, fx.ArtifactID, true)

	bPub, bPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bPubHex := hex.EncodeToString(bPub)

	deps := export.ExportDeps{
		SealStore:       env.sealStore,
		SealRootDir:     env.sDir,
		LedgerStore:     env.ledgerStore,
		CheckpointStore: env.checkpointStore,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{fx.TrustedKeyID: seeded.chkPubHex},
		},
		ArtifactStore:   env.artifactStore,
		ArtifactRootDir: env.aDir,
		IndexStore:      env.indexStore,
		FindingStore:    env.findingStore,
	}

	out, err := env.exportStore.PackageCaseBundle(context.Background(), deps, export.ExportRequest{
		SchemaVersion:   "1",
		OperationID:     "op-c24-signed-001",
		BundleID:        fx.BundleIDSigned,
		CaseID:          fx.CaseID,
		Provider:        "local",
		EvidenceIDs:     []string{fx.EvidenceID},
		ArtifactIDs:     []string{fx.ArtifactID},
		IncludeTimeline: true,
		IncludeNotes:    true,
		KeyID:           fx.TrustedKeyID,
		PrivateKey:      bPriv,
	})
	if err != nil {
		t.Fatalf("PackageCaseBundle signed: %v", err)
	}

	// Verify using domain verifier with trusted key
	res, err := export.VerifyBundle(context.Background(), out.BundleDir, export.VerifyBundleOptions{
		TrustedPublicKeys: map[string]string{fx.TrustedKeyID: bPubHex},
		RequireSignature:  true,
		ExpectedBundleID:  fx.BundleIDSigned,
		ExpectedCaseID:    fx.CaseID,
	})
	if err != nil {
		t.Fatalf("VerifyBundle error: %v", err)
	}

	if !res.Verified {
		t.Fatalf("expected bundle to verify, got errors: %v", res.Errors)
	}
	if res.EvidenceIntegrity != expected.TrustedSigned.EvidenceIntegrity {
		t.Fatalf("evidence integrity: got %s want %s", res.EvidenceIntegrity, expected.TrustedSigned.EvidenceIntegrity)
	}
	if res.CustodyRootIntegrity != expected.TrustedSigned.CustodyRootIntegrity {
		t.Fatalf("custody root integrity: got %s want %s", res.CustodyRootIntegrity, expected.TrustedSigned.CustodyRootIntegrity)
	}
	if string(res.SignatureStatus) != expected.TrustedSigned.SignatureStatus {
		t.Fatalf("signature status: got %s want %s", res.SignatureStatus, expected.TrustedSigned.SignatureStatus)
	}
	if !res.SignatureValid {
		t.Fatalf("expected signature_valid = true")
	}
	if !res.RawTimestampsPreserved {
		t.Fatalf("expected raw_timestamps_preserved = true")
	}
	if res.RequiresServer {
		t.Fatalf("expected requires_server = false")
	}
	if res.EvidenceCount != 1 || res.ArtifactCount != 1 || res.TimelineCount != 1 || res.HypothesesCount != 1 {
		t.Fatalf("counts mismatch: ev=%d art=%d time=%d hyp=%d", res.EvidenceCount, res.ArtifactCount, res.TimelineCount, res.HypothesesCount)
	}
}

func TestOfflineVerifyUnsignedBundleAndStatusDistinctness(t *testing.T) {
	fx := loadC24JSON[c24PositiveFixture](t, "positive/valid-bundle-verification.json")
	expected := loadC24JSON[c24ExpectedResultsFixture](t, "expected-output/offline-verification-results.json")
	env := setupC23Env(t)

	c23Fx := c23PositiveFixture{
		CaseID:          fx.CaseID,
		PayloadJSONL:    fx.PayloadSample,
		ZoneHint:        fx.ZoneHint,
		CheckpointKeyID: fx.TrustedKeyID,
	}
	seeded := seedFullCaseForC23(t, env, c23Fx, fx.EvidenceID, fx.ArtifactID, false)

	deps := export.ExportDeps{
		SealStore:       env.sealStore,
		SealRootDir:     env.sDir,
		LedgerStore:     env.ledgerStore,
		CheckpointStore: env.checkpointStore,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{fx.TrustedKeyID: seeded.chkPubHex},
		},
		ArtifactStore:   env.artifactStore,
		ArtifactRootDir: env.aDir,
		IndexStore:      env.indexStore,
		FindingStore:    env.findingStore,
	}

	// Package unsigned bundle
	out, err := env.exportStore.PackageCaseBundle(context.Background(), deps, export.ExportRequest{
		SchemaVersion: "1",
		OperationID:   "op-c24-unsigned-001",
		BundleID:      fx.BundleIDUnsigned,
		CaseID:        fx.CaseID,
		Provider:      "local",
		EvidenceIDs:   []string{fx.EvidenceID},
	})
	if err != nil {
		t.Fatalf("PackageCaseBundle unsigned: %v", err)
	}

	// 1. Verify without requiring signature: passes integrity with distinct status "unsigned"
	resUnsigned, err := export.VerifyBundle(context.Background(), out.BundleDir, export.VerifyBundleOptions{
		RequireSignature: false,
	})
	if err != nil {
		t.Fatalf("VerifyBundle unsigned error: %v", err)
	}
	if !resUnsigned.Verified {
		t.Fatalf("expected unsigned bundle to pass integrity verification, got errors: %v", resUnsigned.Errors)
	}
	if string(resUnsigned.SignatureStatus) != expected.ValidUnsigned.SignatureStatus {
		t.Fatalf("expected signature_status %q, got %q", expected.ValidUnsigned.SignatureStatus, resUnsigned.SignatureStatus)
	}
	if resUnsigned.SignatureValid {
		t.Fatalf("unsigned bundle must have signature_valid = false")
	}
	if resUnsigned.EvidenceIntegrity != "MATCH" || resUnsigned.CustodyRootIntegrity != "MATCH" {
		t.Fatalf("expected MATCH for integrity, got ev=%s cust=%s", resUnsigned.EvidenceIntegrity, resUnsigned.CustodyRootIntegrity)
	}

	// 2. Acceptance requirement: Unsigned and trusted-signature status remain distinct.
	// If RequireSignature is true, unsigned bundle must fail!
	resRequireSig, err := export.VerifyBundle(context.Background(), out.BundleDir, export.VerifyBundleOptions{
		RequireSignature: true,
	})
	if err != nil {
		t.Fatalf("VerifyBundle with require-signature error: %v", err)
	}
	if resRequireSig.Verified {
		t.Fatalf("expected unsigned bundle to fail verification when RequireSignature is true")
	}
	if resRequireSig.SignatureStatus != export.SignatureStatusUnsigned {
		t.Fatalf("expected signature status to remain %q, got %q", export.SignatureStatusUnsigned, resRequireSig.SignatureStatus)
	}
}

func TestOfflineVerifyUntrustedSignerNegativeCase(t *testing.T) {
	fx := loadC24JSON[c24PositiveFixture](t, "positive/valid-bundle-verification.json")
	env := setupC23Env(t)

	c23Fx := c23PositiveFixture{
		CaseID:          fx.CaseID,
		PayloadJSONL:    fx.PayloadSample,
		ZoneHint:        fx.ZoneHint,
		CheckpointKeyID: fx.TrustedKeyID,
	}
	seeded := seedFullCaseForC23(t, env, c23Fx, fx.EvidenceID, fx.ArtifactID, false)

	// Sign bundle with rogue key
	roguePub, roguePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = roguePub

	// Authorized trusted key
	trustedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustedPubHex := hex.EncodeToString(trustedPub)

	deps := export.ExportDeps{
		SealStore:       env.sealStore,
		SealRootDir:     env.sDir,
		LedgerStore:     env.ledgerStore,
		CheckpointStore: env.checkpointStore,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{fx.TrustedKeyID: seeded.chkPubHex},
		},
		ArtifactStore:   env.artifactStore,
		ArtifactRootDir: env.aDir,
		IndexStore:      env.indexStore,
		FindingStore:    env.findingStore,
	}

	out, err := env.exportStore.PackageCaseBundle(context.Background(), deps, export.ExportRequest{
		SchemaVersion: "1",
		OperationID:   "op-c24-untrusted-001",
		BundleID:      "bnd-c24-rogue-001",
		CaseID:        fx.CaseID,
		Provider:      "local",
		EvidenceIDs:   []string{fx.EvidenceID},
		KeyID:         fx.UntrustedKeyID,
		PrivateKey:    roguePriv,
	})
	if err != nil {
		t.Fatalf("package rogue bundle: %v", err)
	}

	// Verify supplying trusted key that does not match rogue signer
	res, err := export.VerifyBundle(context.Background(), out.BundleDir, export.VerifyBundleOptions{
		TrustedPublicKeys: map[string]string{fx.TrustedKeyID: trustedPubHex},
		RequireSignature:  true,
	})
	if err != nil {
		t.Fatalf("VerifyBundle error: %v", err)
	}

	// Negative case: wrong or untrusted signer must not produce trusted success
	if res.Verified {
		t.Fatalf("untrusted signer produced verified success!")
	}
	if res.SignatureStatus != export.SignatureStatusUntrusted {
		t.Fatalf("expected signature_status %q, got %q", export.SignatureStatusUntrusted, res.SignatureStatus)
	}
	if res.SignatureValid {
		t.Fatalf("expected signature_valid = false for untrusted signer")
	}
}

func TestOfflineVerifyTamperedFilesNegativeCases(t *testing.T) {
	fx := loadC24JSON[c24PositiveFixture](t, "positive/valid-bundle-verification.json")
	env := setupC23Env(t)

	c23Fx := makeTestC23Fixture(fx)
	seeded := seedFullCaseForC23(t, env, c23Fx, fx.EvidenceID, fx.ArtifactID, true)

	bPub, bPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bPubHex := hex.EncodeToString(bPub)

	deps := export.ExportDeps{
		SealStore:       env.sealStore,
		SealRootDir:     env.sDir,
		LedgerStore:     env.ledgerStore,
		CheckpointStore: env.checkpointStore,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{fx.TrustedKeyID: seeded.chkPubHex},
		},
		ArtifactStore:   env.artifactStore,
		ArtifactRootDir: env.aDir,
		IndexStore:      env.indexStore,
		FindingStore:    env.findingStore,
	}

	// Helper to create a fresh bundle copy for tampering
	createBundleCopy := func(t *testing.T, id string) string {
		t.Helper()
		out, err := env.exportStore.PackageCaseBundle(context.Background(), deps, export.ExportRequest{
			SchemaVersion:   "1",
			OperationID:     "op-tamper-" + id,
			BundleID:        id,
			CaseID:          fx.CaseID,
			Provider:        "local",
			EvidenceIDs:     []string{fx.EvidenceID},
			ArtifactIDs:     []string{fx.ArtifactID},
			IncludeTimeline: true,
			IncludeNotes:    true,
			KeyID:           fx.TrustedKeyID,
			PrivateKey:      bPriv,
		})
		if err != nil {
			t.Fatalf("package bundle copy %s: %v", id, err)
		}
		// Copy entire directory to isolate mutations
		targetDir := filepath.Join(t.TempDir(), id)
		if err := copyDir(out.BundleDir, targetDir); err != nil {
			t.Fatalf("copy bundle dir: %v", err)
		}
		return targetDir
	}

	opts := export.VerifyBundleOptions{
		TrustedPublicKeys: map[string]string{fx.TrustedKeyID: bPubHex},
		RequireSignature:  true,
	}

	// 1. Invariant: Sealed source bytes never modified. Tamper one byte in blob.dat!
	t.Run("TamperedEvidenceBlobByte", func(t *testing.T) {
		bundleDir := createBundleCopy(t, "bnd-tamper-blob")
		blobPath := filepath.Join(bundleDir, "evidence", fx.EvidenceID, "blob.dat")
		data, err := os.ReadFile(blobPath)
		if err != nil {
			t.Fatal(err)
		}
		data[0] ^= 0xFF // Flip byte
		if err := os.WriteFile(blobPath, data, 0640); err != nil {
			t.Fatal(err)
		}

		res, err := export.VerifyBundle(context.Background(), bundleDir, opts)
		if err != nil {
			t.Fatal(err)
		}
		if res.Verified {
			t.Fatalf("tampered blob byte produced verified success!")
		}
		if res.EvidenceIntegrity != "MISMATCH" {
			t.Fatalf("expected evidence integrity MISMATCH, got %s", res.EvidenceIntegrity)
		}
	})

	// 2. Missing evidence file
	t.Run("MissingEvidenceBlob", func(t *testing.T) {
		bundleDir := createBundleCopy(t, "bnd-missing-blob")
		blobPath := filepath.Join(bundleDir, "evidence", fx.EvidenceID, "blob.dat")
		if err := os.Remove(blobPath); err != nil {
			t.Fatal(err)
		}

		res, err := export.VerifyBundle(context.Background(), bundleDir, opts)
		if err != nil {
			t.Fatal(err)
		}
		if res.Verified {
			t.Fatalf("missing blob produced verified success!")
		}
		if res.EvidenceIntegrity != "MISMATCH" {
			t.Fatalf("expected evidence integrity MISMATCH, got %s", res.EvidenceIntegrity)
		}
	})

	// 3. Tampered custody event chain
	t.Run("TamperedCustodyEvent", func(t *testing.T) {
		bundleDir := createBundleCopy(t, "bnd-tamper-custody")
		custodyPath := filepath.Join(bundleDir, "evidence", fx.EvidenceID, "custody.json")
		var events []custody.CustodyEvent
		raw, err := os.ReadFile(custodyPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &events); err != nil {
			t.Fatal(err)
		}
		events[0].Actor = "attacker-mallory"
		tamperedBytes, _ := json.Marshal(events)
		if err := os.WriteFile(custodyPath, tamperedBytes, 0640); err != nil {
			t.Fatal(err)
		}

		res, err := export.VerifyBundle(context.Background(), bundleDir, opts)
		if err != nil {
			t.Fatal(err)
		}
		if res.Verified {
			t.Fatalf("tampered custody chain produced verified success!")
		}
	})

	// 4. Tampered signature bytes
	t.Run("TamperedSignatureBytes", func(t *testing.T) {
		bundleDir := createBundleCopy(t, "bnd-tamper-sig")
		manifestPath := filepath.Join(bundleDir, "bundle-manifest.json")
		raw, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		var m export.BundleManifest
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		// Corrupt signature
		sigBytes, _ := hex.DecodeString(m.Signature)
		sigBytes[0] ^= 0xAA
		m.Signature = hex.EncodeToString(sigBytes)
		tamperedManifest, _ := json.Marshal(m)
		if err := os.WriteFile(manifestPath, tamperedManifest, 0640); err != nil {
			t.Fatal(err)
		}

		res, err := export.VerifyBundle(context.Background(), bundleDir, opts)
		if err != nil {
			t.Fatal(err)
		}
		if res.Verified {
			t.Fatalf("corrupted signature produced verified success!")
		}
		if res.SignatureStatus != export.SignatureStatusInvalid {
			t.Fatalf("expected signature_status %q, got %q", export.SignatureStatusInvalid, res.SignatureStatus)
		}
	})
}

func TestOfflineVerifyCLIBinaryExecution(t *testing.T) {
	fx := loadC24JSON[c24PositiveFixture](t, "positive/valid-bundle-verification.json")
	binPath := buildVerifyBinaryForTest(t)
	env := setupC23Env(t)

	c23Fx := makeTestC23Fixture(fx)
	seeded := seedFullCaseForC23(t, env, c23Fx, fx.EvidenceID, fx.ArtifactID, true)

	bPub, bPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bPubHex := hex.EncodeToString(bPub)

	deps := export.ExportDeps{
		SealStore:       env.sealStore,
		SealRootDir:     env.sDir,
		LedgerStore:     env.ledgerStore,
		CheckpointStore: env.checkpointStore,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{fx.TrustedKeyID: seeded.chkPubHex},
		},
		ArtifactStore:   env.artifactStore,
		ArtifactRootDir: env.aDir,
		IndexStore:      env.indexStore,
		FindingStore:    env.findingStore,
	}

	// 1. Pack signed bundle
	signedOut, err := env.exportStore.PackageCaseBundle(context.Background(), deps, export.ExportRequest{
		SchemaVersion:   "1",
		OperationID:     "op-cli-signed-001",
		BundleID:        "bnd-cli-signed-001",
		CaseID:          fx.CaseID,
		Provider:        "local",
		EvidenceIDs:     []string{fx.EvidenceID},
		ArtifactIDs:     []string{fx.ArtifactID},
		IncludeTimeline: true,
		IncludeNotes:    true,
		KeyID:           fx.TrustedKeyID,
		PrivateKey:      bPriv,
	})
	if err != nil {
		t.Fatalf("package signed bundle: %v", err)
	}

	// 2. Pack unsigned bundle
	unsignedOut, err := env.exportStore.PackageCaseBundle(context.Background(), deps, export.ExportRequest{
		SchemaVersion: "1",
		OperationID:   "op-cli-unsigned-001",
		BundleID:      "bnd-cli-unsigned-001",
		CaseID:        fx.CaseID,
		Provider:      "local",
		EvidenceIDs:   []string{fx.EvidenceID},
	})
	if err != nil {
		t.Fatalf("package unsigned bundle: %v", err)
	}

	// Subtest A: CLI verify trusted signed bundle with JSON output
	t.Run("CLITrustedSignedJSON", func(t *testing.T) {
		cmd := exec.Command(binPath,
			"-bundle", signedOut.BundleDir,
			"-trusted-key", bPubHex,
			"-trusted-key-id", fx.TrustedKeyID,
			"-require-signature",
			"-json",
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			t.Fatalf("CLI command failed: %v\nStderr: %s\nStdout: %s", err, stderr.String(), stdout.String())
		}

		var res export.BundleVerificationResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("parse CLI JSON output: %v\nOutput: %s", err, stdout.String())
		}
		if !res.Verified || res.SignatureStatus != export.SignatureStatusTrusted || !res.SignatureValid {
			t.Fatalf("unexpected verification result: %+v", res)
		}
		if res.RequiresServer {
			t.Fatalf("standalone verifier must require no server")
		}
	})

	// Subtest B: CLI verify unsigned bundle without signature requirement
	t.Run("CLIUnsignedValid", func(t *testing.T) {
		cmd := exec.Command(binPath, "-bundle", unsignedOut.BundleDir, "-json")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			t.Fatalf("CLI command failed: %v\nStderr: %s", err, stderr.String())
		}

		var res export.BundleVerificationResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("parse CLI JSON: %v", err)
		}
		if !res.Verified || res.SignatureStatus != export.SignatureStatusUnsigned || res.SignatureValid {
			t.Fatalf("unexpected unsigned result: %+v", res)
		}
	})

	// Subtest C: CLI verify unsigned bundle with -require-signature -> must exit 1
	t.Run("CLIUnsignedRequireSignatureFails", func(t *testing.T) {
		cmd := exec.Command(binPath, "-bundle", unsignedOut.BundleDir, "-require-signature", "-json")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err == nil {
			t.Fatalf("expected command to exit with error when unsigned bundle has -require-signature")
		}
		var res export.BundleVerificationResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("parse CLI JSON: %v", err)
		}
		if res.Verified {
			t.Fatalf("expected verified=false")
		}
	})

	// Subtest D: CLI verify positional argument and human readable output
	t.Run("CLIPositionalArgumentHumanOutput", func(t *testing.T) {
		cmd := exec.Command(binPath, signedOut.BundleDir, "-trusted-key", bPubHex)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("command failed: %v\nStderr: %s", err, stderr.String())
		}
		outStr := stdout.String()
		if !strings.Contains(outStr, "BreachAtlas Offline Bundle Verification: PASSED") {
			t.Fatalf("expected PASSED banner, got:\n%s", outStr)
		}
		if !strings.Contains(outStr, "Signature Status:       trusted_signed") {
			t.Fatalf("expected trusted_signed status, got:\n%s", outStr)
		}
	})

	// Subtest E: CLI missing arguments -> exit code 2
	t.Run("CLIMissingArgumentsExitCode2", func(t *testing.T) {
		cmd := exec.Command(binPath)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err == nil {
			t.Fatalf("expected error on missing arguments")
		}
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 2 {
			t.Fatalf("expected exit code 2, got %v", err)
		}
	})

	// Subtest F: Legacy C01 positive and invalid fixture compatibility
	t.Run("CLILegacyC01Fixtures", func(t *testing.T) {
		c01Pos := filepath.Join(getC24FixturesDir(t), "..", "C01", "positive", "export-bundle.json")
		cmdPos := exec.Command(binPath, c01Pos, "-json")
		var stdoutPos bytes.Buffer
		cmdPos.Stdout = &stdoutPos
		if err := cmdPos.Run(); err != nil {
			t.Fatalf("verify C01 positive fixture failed: %v", err)
		}
		var posRes export.BundleVerificationResult
		if err := json.Unmarshal(stdoutPos.Bytes(), &posRes); err != nil || !posRes.Verified {
			t.Fatalf("unexpected C01 positive res: %+v", posRes)
		}

		c01Inv := filepath.Join(getC24FixturesDir(t), "..", "C01", "invalid", "invalid-signature-export.json")
		cmdInv := exec.Command(binPath, c01Inv, "-json")
		var stdoutInv bytes.Buffer
		cmdInv.Stdout = &stdoutInv
		if err := cmdInv.Run(); err == nil {
			t.Fatalf("expected C01 invalid fixture to fail")
		}
	})
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}

// Ensure unused import warning prevention if any
var _ = time.Now

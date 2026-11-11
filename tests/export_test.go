package tests_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/artifacts"
	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/export"
	"github.com/Parsa-Emami/Breachatlas/internal/findings"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

type c23Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c23PositiveFixture struct {
	SchemaVersion    string `json:"schema_version"`
	CaseID           string `json:"case_id"`
	EvidenceID       string `json:"evidence_id"`
	ArtifactID       string `json:"artifact_id"`
	BundleIDSigned   string `json:"bundle_id_signed"`
	BundleIDUnsigned string `json:"bundle_id_unsigned"`
	OperationID      string `json:"operation_id"`
	PayloadJSONL     string `json:"payload_jsonl"`
	ZoneHint         string `json:"zone_hint"`
	CheckpointKeyID  string `json:"checkpoint_key_id"`
	BundleKeyID      string `json:"bundle_key_id"`
	Hypothesis       struct {
		HypothesisID string `json:"hypothesis_id"`
		Author       string `json:"author"`
		Rationale    string `json:"rationale"`
		Statement    string `json:"statement"`
		UILabel      string `json:"ui_label"`
	} `json:"hypothesis"`
}

type c23NegativePrereqFixture struct {
	SchemaVersion string `json:"schema_version"`
	Cases         []struct {
		Name          string `json:"name"`
		EvidenceID    string `json:"evidence_id,omitempty"`
		ArtifactID    string `json:"artifact_id,omitempty"`
		Provider      string `json:"provider,omitempty"`
		SchemaVersion string `json:"schema_version,omitempty"`
		ExpectedError string `json:"expected_error"`
	} `json:"cases"`
}

type c23NegativeCheckpointFixture struct {
	SchemaVersion string `json:"schema_version"`
	Cases         []struct {
		Name          string `json:"name"`
		ExpectedError string `json:"expected_error"`
	} `json:"cases"`
}

type c23Env struct {
	root            string
	qDir            string
	sDir            string
	custDir         string
	chkDir          string
	scDir           string
	aDir            string
	idxDir          string
	findDir         string
	expDir          string
	sealStore       *evidence.SealStore
	ledgerStore     *custody.LedgerStore
	checkpointStore *custody.FileCheckpointStore
	registry        *analyzers.Registry
	sandbox         *analyzers.Sandbox
	artifactStore   *artifacts.ArtifactStore
	indexStore      *timeline.EventIndexStore
	findingStore    *findings.FindingStore
	exportStore     *export.ExportStore
}

func getC23FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "fixtures", "breachatlas", "C23")
	if filepath.Base(wd) != "tests" {
		dir = filepath.Join(wd, "tests", "fixtures", "breachatlas", "C23")
	}
	return dir
}

func loadC23JSON[T any](t *testing.T, rel string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(getC23FixturesDir(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read C23 fixture %s: %v", rel, err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal C23 fixture %s: %v", rel, err)
	}
	return out
}

func setupC23Env(t *testing.T) *c23Env {
	t.Helper()
	root := t.TempDir()
	qDir := filepath.Join(root, "quarantine")
	sDir := filepath.Join(root, "sealstore")
	custDir := filepath.Join(root, "custody")
	chkDir := filepath.Join(root, "checkpoints")
	scDir := filepath.Join(root, "scratch")
	aDir := filepath.Join(root, "artifacts")
	idxDir := filepath.Join(root, "timeline-index")
	findDir := filepath.Join(root, "findings")
	expDir := filepath.Join(root, "exports")

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sealStore.Close() })

	ledgerStore, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: custDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledgerStore.Close() })

	chkStore, err := custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{RootDir: chkDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = chkStore.Close() })

	reg, err := analyzers.NewRegistry(analyzers.RegistryConfig{SealStore: sealStore, SealRootDir: sDir, Provider: "local"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := analyzers.NewSandbox(reg, analyzers.DefaultSandboxConfig(scDir))
	if err != nil {
		t.Fatal(err)
	}
	aStore, err := artifacts.OpenArtifactStore(artifacts.StoreConfig{RootDir: aDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aStore.Close() })

	idxStore, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: idxDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = idxStore.Close() })

	fStore, err := findings.OpenFindingStore(findings.FindingStoreConfig{RootDir: findDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fStore.Close() })

	eStore, err := export.OpenExportStore(export.ExportStoreConfig{RootDir: expDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eStore.Close() })

	return &c23Env{
		root:            root,
		qDir:            qDir,
		sDir:            sDir,
		custDir:         custDir,
		chkDir:          chkDir,
		scDir:           scDir,
		aDir:            aDir,
		idxDir:          idxDir,
		findDir:         findDir,
		expDir:          expDir,
		sealStore:       sealStore,
		ledgerStore:     ledgerStore,
		checkpointStore: chkStore,
		registry:        reg,
		sandbox:         sb,
		artifactStore:   aStore,
		indexStore:      idxStore,
		findingStore:    fStore,
		exportStore:     eStore,
	}
}

type c23SeededCase struct {
	blobPath   string
	blobSHA    string
	blobSize   int64
	chkPubHex  string
	chkPriv    ed25519.PrivateKey
	checkpoint *custody.Checkpoint
}

func seedFullCaseForC23(t *testing.T, env *c23Env, fx c23PositiveFixture, evidenceID, artifactID string, withNotes bool) c23SeededCase {
	t.Helper()
	ctx := context.Background()
	raw := []byte(fx.PayloadJSONL)
	sum := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(sum[:])
	sz := int64(len(raw))

	q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{
		QuarantineDir: env.qDir,
		BufferSize:    64,
		SyncDir:       true,
	}, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-" + fx.CaseID + "-" + evidenceID,
		CaseID:        fx.CaseID,
		EvidenceID:    evidenceID,
		MediaType:     "application/json",
		Filename:      evidenceID + ".jsonl",
		ExpectedSize:  &sz,
		Body:          strings.NewReader(fx.PayloadJSONL),
	})
	if err != nil {
		t.Fatalf("quarantine %s: %v", evidenceID, err)
	}

	if _, err := env.ledgerStore.AppendEvent(ctx, custody.AppendEventRequest{
		EventID:    "cust-" + evidenceID + "-01",
		CaseID:     fx.CaseID,
		EvidenceID: evidenceID,
		EventType:  "intake_seal",
		Actor:      "analyst-mina",
		Timestamp:  "2026-10-05T12:10:00Z",
		Reason:     "Initial forensic intake and quarantine seal.",
	}); err != nil {
		t.Fatalf("append custody %s: %v", evidenceID, err)
	}
	curRoot, err := env.ledgerStore.CurrentRoot(fx.CaseID, evidenceID)
	if err != nil {
		t.Fatalf("custody root %s: %v", evidenceID, err)
	}

	sm, err := env.sealStore.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "seal-" + fx.CaseID + "-" + evidenceID,
		Quarantined:    q,
		ExpectedSHA256: shaHex,
		AcquiredAt:     "2026-10-05T12:10:00Z",
		CustodyRoot:    curRoot,
	})
	if err != nil {
		t.Fatalf("seal %s: %v", evidenceID, err)
	}
	blobPath := filepath.Join(env.sDir, filepath.FromSlash(sm.BlobRelPath))

	chkPub, chkPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chk, err := custody.CreateCheckpoint(ctx, env.ledgerStore, custody.CreateCheckpointRequest{
		CheckpointID: "chk-" + evidenceID + "-01",
		CaseID:       fx.CaseID,
		EvidenceID:   evidenceID,
		Sequence:     1,
		CustodyRoot:  curRoot,
		KeyID:        fx.CheckpointKeyID,
		Revision:     1,
		IssuedAt:     time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		PrivateKey:   chkPriv,
	})
	if err != nil {
		t.Fatalf("create checkpoint %s: %v", evidenceID, err)
	}
	if err := env.checkpointStore.SaveCheckpoint(ctx, *chk); err != nil {
		t.Fatalf("save checkpoint %s: %v", evidenceID, err)
	}

	runRes, err := env.sandbox.RunIsolated(ctx, analyzers.IsolatedRunRequest{
		RunID:      "run-" + artifactID,
		CaseID:     fx.CaseID,
		EvidenceID: evidenceID,
		AnalyzerID: analyzers.AnalyzerJSON,
		Provider:   "local",
		Options:    analyzers.DefaultParseOptions(),
	})
	if err != nil {
		t.Fatalf("sandbox run %s: %v", artifactID, err)
	}
	if _, err := env.artifactStore.DeriveFromIsolatedRun(ctx, env.sealStore, env.sDir, runRes, artifacts.DeriveRequest{
		OperationID: "drv-" + artifactID,
		CaseID:      fx.CaseID,
		ArtifactID:  artifactID,
		Provider:    "local",
	}); err != nil {
		t.Fatalf("derive %s: %v", artifactID, err)
	}

	if _, err := env.indexStore.IndexDerivedArtifact(ctx, env.sealStore, env.sDir, env.artifactStore, env.aDir, timeline.IndexDerivedRequest{
		SchemaVersion: "1",
		OperationID:   "idx-" + artifactID,
		CaseID:        fx.CaseID,
		ArtifactID:    artifactID,
		Provider:      "local",
		ZoneHint:      fx.ZoneHint,
	}); err != nil {
		t.Fatalf("index %s: %v", artifactID, err)
	}

	if withNotes {
		if _, err := env.findingStore.RecordHypothesis(ctx, env.sealStore, env.sDir, env.indexStore, findings.RecordHypothesisRequest{
			SchemaVersion:         "1",
			OperationID:           "hyp-" + fx.Hypothesis.HypothesisID,
			CaseID:                fx.CaseID,
			HypothesisID:          fx.Hypothesis.HypothesisID,
			Author:                fx.Hypothesis.Author,
			Rationale:             fx.Hypothesis.Rationale,
			Statement:             fx.Hypothesis.Statement,
			UILabel:               fx.Hypothesis.UILabel,
			SupportingEvidenceIDs: []string{evidenceID},
		}); err != nil {
			t.Fatalf("record hypothesis: %v", err)
		}
	}

	return c23SeededCase{
		blobPath:   blobPath,
		blobSHA:    shaHex,
		blobSize:   sz,
		chkPubHex:  hex.EncodeToString(chkPub),
		chkPriv:    chkPriv,
		checkpoint: chk,
	}
}

func assertSealedBlobUnchangedC23(t *testing.T, blobPath, expectedSHA string, expectedSize int64) {
	t.Helper()
	raw, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read sealed blob %s: %v", blobPath, err)
	}
	sum := sha256.Sum256(raw)
	if gotSHA := hex.EncodeToString(sum[:]); int64(len(raw)) != expectedSize || gotSHA != expectedSHA {
		t.Fatalf("sealed source bytes modified! got size=%d sha=%s want size=%d sha=%s", len(raw), gotSHA, expectedSize, expectedSHA)
	}
}

func TestC23FixturesAndProvenance(t *testing.T) {
	prov := loadC23JSON[c23Provenance](t, "provenance.json")
	if prov.Task != "C23" || prov.License != "Apache-2.0" {
		t.Fatalf("unexpected C23 provenance: %+v", prov)
	}
	if len(prov.SHA256) != 4 {
		t.Fatalf("expected 4 hashed C23 fixture files, got %d", len(prov.SHA256))
	}
	dir := getC23FixturesDir(t)
	for rel, want := range prov.SHA256 {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("missing C23 fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("fixture %s sha mismatch: got %s want %s", rel, got, want)
		}
	}
}

func TestC23PortableBundleBinding(t *testing.T) {
	fx := loadC23JSON[c23PositiveFixture](t, "positive/portable-case-export.json")
	env := setupC23Env(t)
	seeded := seedFullCaseForC23(t, env, fx, fx.EvidenceID, fx.ArtifactID, true)

	bPub, bPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	deps := export.ExportDeps{
		SealStore:       env.sealStore,
		SealRootDir:     env.sDir,
		LedgerStore:     env.ledgerStore,
		CheckpointStore: env.checkpointStore,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{fx.CheckpointKeyID: seeded.chkPubHex},
		},
		ArtifactStore:   env.artifactStore,
		ArtifactRootDir: env.aDir,
		IndexStore:      env.indexStore,
		FindingStore:    env.findingStore,
	}

	// 1. Signed portable bundle with evidence, derived artifact, checkpoint, timeline, and separated hypotheses.
	signedOut, err := env.exportStore.PackageCaseBundle(context.Background(), deps, export.ExportRequest{
		SchemaVersion:   "1",
		OperationID:     fx.OperationID,
		BundleID:        fx.BundleIDSigned,
		CaseID:          fx.CaseID,
		Provider:        "local",
		EvidenceIDs:     []string{fx.EvidenceID},
		ArtifactIDs:     []string{fx.ArtifactID},
		IncludeTimeline: true,
		IncludeNotes:    true,
		KeyID:           fx.BundleKeyID,
		PrivateKey:      bPriv,
	})
	if err != nil {
		t.Fatalf("PackageCaseBundle signed: %v", err)
	}
	if !signedOut.Signed || signedOut.Manifest.Signature == "" || signedOut.Manifest.BundleDigest == "" {
		t.Fatalf("expected signed bundle digest & signature, got %+v", signedOut)
	}
	if len(signedOut.Manifest.EvidenceItems) != 1 || len(signedOut.Manifest.DerivedArtifacts) != 1 {
		t.Fatalf("expected 1 bound evidence & 1 bound artifact, got %+v", signedOut.Manifest)
	}
	if signedOut.Manifest.TimelineCount != 2 || signedOut.Manifest.HypothesesCount != 1 {
		t.Fatalf("expected timeline=2 and hypotheses=1 bound cleanly, got timeline=%d hyps=%d", signedOut.Manifest.TimelineCount, signedOut.Manifest.HypothesesCount)
	}

	// Verify Ed25519 signature & every packed file checksum on disk.
	sigBytes, err := hex.DecodeString(signedOut.Manifest.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(bPub, export.CanonicalSignaturePayload(signedOut.Manifest), sigBytes) {
		t.Fatalf("Ed25519 bundle signature verification failed")
	}
	for rel, expectedSHA := range signedOut.Manifest.FileChecksums {
		rawFile, rErr := os.ReadFile(filepath.Join(signedOut.BundleDir, filepath.FromSlash(rel)))
		if rErr != nil {
			t.Fatalf("missing packed file %s: %v", rel, rErr)
		}
		sum := sha256.Sum256(rawFile)
		if got := hex.EncodeToString(sum[:]); got != expectedSHA {
			t.Fatalf("packed file %s sha mismatch: got %s want %s", rel, got, expectedSHA)
		}
	}

	// Verify packed hypotheses remain separated non-evidence inside findings/hypotheses.json.
	rawHyps, err := os.ReadFile(filepath.Join(signedOut.BundleDir, filepath.FromSlash(signedOut.Manifest.HypothesesRelPath)))
	if err != nil {
		t.Fatal(err)
	}
	var exportedHyps []findings.AnalystHypothesis
	if err := json.Unmarshal(rawHyps, &exportedHyps); err != nil {
		t.Fatal(err)
	}
	if len(exportedHyps) != 1 || exportedHyps[0].IsSourceEvidence || exportedHyps[0].RecordKind != findings.RecordKindAnalystHypothesis {
		t.Fatalf("exported hypothesis lost non-evidence boundary: %+v", exportedHyps)
	}

	// 2. Unsigned portable bundle keeps Signed == false distinctly.
	unsignedOut, err := env.exportStore.PackageCaseBundle(context.Background(), deps, export.ExportRequest{
		SchemaVersion: "1",
		BundleID:      fx.BundleIDUnsigned,
		CaseID:        fx.CaseID,
		EvidenceIDs:   []string{fx.EvidenceID},
		ArtifactIDs:   []string{fx.ArtifactID},
	})
	if err != nil {
		t.Fatalf("PackageCaseBundle unsigned: %v", err)
	}
	if unsignedOut.Signed || unsignedOut.Manifest.Signature != "" || unsignedOut.Manifest.BundleDigest == "" {
		t.Fatalf("expected unsigned status cleanly recorded, got %+v", unsignedOut)
	}

	assertSealedBlobUnchangedC23(t, seeded.blobPath, seeded.blobSHA, seeded.blobSize)
}

func TestC23NegativeMissingPrereqAndCheckpoints(t *testing.T) {
	posFx := loadC23JSON[c23PositiveFixture](t, "positive/portable-case-export.json")
	prereqFx := loadC23JSON[c23NegativePrereqFixture](t, "invalid/missing-prerequisites.json")
	chkFx := loadC23JSON[c23NegativeCheckpointFixture](t, "invalid/tampered-or-untrusted-checkpoint.json")

	env := setupC23Env(t)
	seeded := seedFullCaseForC23(t, env, posFx, posFx.EvidenceID, posFx.ArtifactID, false)
	// Also seed a second evidence item & artifact that won't be selected in cross-binding mismatch test.
	_ = seedFullCaseForC23(t, env, posFx, "ev-c23-other", "art-c23-other", false)

	baseDeps := export.ExportDeps{
		SealStore:       env.sealStore,
		SealRootDir:     env.sDir,
		LedgerStore:     env.ledgerStore,
		CheckpointStore: env.checkpointStore,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{posFx.CheckpointKeyID: seeded.chkPubHex},
		},
		ArtifactStore:   env.artifactStore,
		ArtifactRootDir: env.aDir,
	}

	for _, tc := range prereqFx.Cases {
		t.Run("prereq_"+tc.Name, func(t *testing.T) {
			req := export.ExportRequest{
				SchemaVersion: "1",
				BundleID:      "bundle-neg-" + tc.Name,
				CaseID:        posFx.CaseID,
				EvidenceIDs:   []string{posFx.EvidenceID},
				ArtifactIDs:   []string{posFx.ArtifactID},
			}
			deps := baseDeps
			switch tc.Name {
			case "empty_evidence_selection":
				req.EvidenceIDs = nil
			case "missing_seal_store_evidence":
				req.EvidenceIDs = []string{tc.EvidenceID}
				req.ArtifactIDs = nil
			case "missing_checkpoint":
				deps.CheckpointStore = nil
				deps.Checkpoints = nil
			case "missing_derived_artifact":
				req.ArtifactIDs = []string{tc.ArtifactID}
			case "artifact_bound_to_unselected_evidence":
				req.EvidenceIDs = []string{posFx.EvidenceID}
				req.ArtifactIDs = []string{"art-c23-other"}
			case "unavailable_remote_provider":
				req.Provider = tc.Provider
			case "unsupported_schema_version":
				req.SchemaVersion = tc.SchemaVersion
			}

			_, err := env.exportStore.PackageCaseBundle(context.Background(), deps, req)
			switch tc.ExpectedError {
			case "ErrMissingPrerequisite":
				if !errors.Is(err, export.ErrMissingPrerequisite) {
					t.Fatalf("expected ErrMissingPrerequisite, got %v", err)
				}
			case "ErrInputBindingMismatch":
				if !errors.Is(err, export.ErrInputBindingMismatch) {
					t.Fatalf("expected ErrInputBindingMismatch, got %v", err)
				}
			case "ErrUnavailableProvider":
				if !errors.Is(err, export.ErrUnavailableProvider) {
					t.Fatalf("expected ErrUnavailableProvider, got %v", err)
				}
			case "ErrUnsupportedVersion":
				if !errors.Is(err, export.ErrUnsupportedVersion) {
					t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
				}
			default:
				t.Fatalf("unknown expected_error %q", tc.ExpectedError)
			}
		})
	}

	for _, tc := range chkFx.Cases {
		t.Run("chk_"+tc.Name, func(t *testing.T) {
			deps := baseDeps
			switch tc.Name {
			case "untrusted_checkpoint_signer":
				deps.CheckpointOpts = custody.VerifyCheckpointOptions{
					TrustedPublicKeys: map[string]string{"other-key": seeded.chkPubHex},
				}
			case "expired_checkpoint":
				deps.CheckpointOpts = custody.VerifyCheckpointOptions{
					TrustedPublicKeys: map[string]string{posFx.CheckpointKeyID: seeded.chkPubHex},
					Now:               time.Now().UTC().Add(48 * time.Hour),
				}
			case "tampered_checkpoint_root":
				badChk := *seeded.checkpoint
				badChk.CustodyRoot = strings.Repeat("f", 64)
				deps.Checkpoints = map[string]custody.Checkpoint{posFx.EvidenceID: badChk}
			}

			_, err := env.exportStore.PackageCaseBundle(context.Background(), deps, export.ExportRequest{
				SchemaVersion: "1",
				BundleID:      "bundle-neg-" + tc.Name,
				CaseID:        posFx.CaseID,
				EvidenceIDs:   []string{posFx.EvidenceID},
			})
			if !errors.Is(err, export.ErrCheckpointFailed) {
				t.Fatalf("expected ErrCheckpointFailed, got %v", err)
			}
		})
	}

	// Path traversal and exclusive lock contention checks.
	if _, err := env.exportStore.PackageCaseBundle(context.Background(), baseDeps, export.ExportRequest{
		SchemaVersion: "1",
		BundleID:      "../escape",
		CaseID:        posFx.CaseID,
		EvidenceIDs:   []string{posFx.EvidenceID},
	}); !errors.Is(err, export.ErrPathTraversal) {
		t.Fatalf("expected ErrPathTraversal on bad bundle_id, got %v", err)
	}
	if _, err := export.OpenExportStore(export.ExportStoreConfig{RootDir: env.expDir}); !errors.Is(err, export.ErrExportLockBusy) {
		t.Fatalf("expected ErrExportLockBusy on concurrent open, got %v", err)
	}

	assertSealedBlobUnchangedC23(t, seeded.blobPath, seeded.blobSHA, seeded.blobSize)
}

func TestC23RestartRecoveryAndReplay(t *testing.T) {
	fx := loadC23JSON[c23PositiveFixture](t, "positive/portable-case-export.json")
	env := setupC23Env(t)
	seeded := seedFullCaseForC23(t, env, fx, fx.EvidenceID, fx.ArtifactID, false)

	deps := export.ExportDeps{
		SealStore:       env.sealStore,
		SealRootDir:     env.sDir,
		LedgerStore:     env.ledgerStore,
		CheckpointStore: env.checkpointStore,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{fx.CheckpointKeyID: seeded.chkPubHex},
		},
		ArtifactStore:   env.artifactStore,
		ArtifactRootDir: env.aDir,
	}

	// Simulate mid-commit crash with FailAfterStageBeforeCommit.
	_ = env.exportStore.Close()
	faultStore, err := export.OpenExportStore(export.ExportStoreConfig{
		RootDir: env.expDir,
		SyncDir: true,
		Faults:  export.ExportFaults{FailAfterStageBeforeCommit: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := export.ExportRequest{
		SchemaVersion: "1",
		OperationID:   fx.OperationID,
		BundleID:      fx.BundleIDUnsigned,
		CaseID:        fx.CaseID,
		EvidenceIDs:   []string{fx.EvidenceID},
		ArtifactIDs:   []string{fx.ArtifactID},
	}
	if _, err := faultStore.PackageCaseBundle(context.Background(), deps, req); !errors.Is(err, export.ErrInterrupted) {
		t.Fatalf("expected ErrInterrupted during crash fault, got %v", err)
	}
	_ = faultStore.Close()

	// Reopen cleanly: orphan staged bundle cleaned and zero bundles recovered.
	reopened, err := export.OpenExportStore(export.ExportStoreConfig{RootDir: env.expDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep := reopened.LastRecoveryReport(); len(rep.CleanedStagingFiles) == 0 || rep.RecoveredBundles != 0 {
		t.Fatalf("unexpected recovery report after interrupted export: %+v", rep)
	}

	// Commit cleanly, close, and restart again.
	firstOut, err := reopened.PackageCaseBundle(context.Background(), deps, req)
	if err != nil {
		t.Fatalf("commit export after recovery: %v", err)
	}
	_ = reopened.Close()

	restarted, err := export.OpenExportStore(export.ExportStoreConfig{RootDir: env.expDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Close() }()

	if rep := restarted.LastRecoveryReport(); rep.RecoveredBundles != 1 {
		t.Fatalf("expected 1 recovered bundle after restart, got %+v", rep)
	}
	bm, err := restarted.GetBundleManifest(fx.BundleIDUnsigned)
	if err != nil || bm.BundleDigest != firstOut.BundleDigest {
		t.Fatalf("restarted bundle manifest mismatch: bm=%v err=%v", bm, err)
	}

	// Repeat operation after restart: idempotent replay succeeds, conflicting reuse fails.
	replay, err := restarted.PackageCaseBundle(context.Background(), deps, req)
	if err != nil || !replay.IdempotentReplay || replay.BundleDigest != firstOut.BundleDigest {
		t.Fatalf("expected idempotent replay after restart, got replay=%v err=%v", replay, err)
	}
	conflictReq := req
	conflictReq.ArtifactIDs = nil
	if _, err := restarted.PackageCaseBundle(context.Background(), deps, conflictReq); !errors.Is(err, export.ErrExportConflict) {
		t.Fatalf("expected ErrExportConflict on altered replay params, got %v", err)
	}

	assertSealedBlobUnchangedC23(t, seeded.blobPath, seeded.blobSHA, seeded.blobSize)
}

func TestC23ConcurrentExportRace(t *testing.T) {
	fx := loadC23JSON[c23PositiveFixture](t, "positive/portable-case-export.json")
	env := setupC23Env(t)
	seeded := seedFullCaseForC23(t, env, fx, fx.EvidenceID, fx.ArtifactID, false)

	deps := export.ExportDeps{
		SealStore:       env.sealStore,
		SealRootDir:     env.sDir,
		LedgerStore:     env.ledgerStore,
		CheckpointStore: env.checkpointStore,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{fx.CheckpointKeyID: seeded.chkPubHex},
		},
		ArtifactStore:   env.artifactStore,
		ArtifactRootDir: env.aDir,
	}

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 6; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			bid := fmt.Sprintf("bundle-race-%02d", i)
			out, err := env.exportStore.PackageCaseBundle(context.Background(), deps, export.ExportRequest{
				SchemaVersion: "1",
				OperationID:   "op-" + bid,
				BundleID:      bid,
				CaseID:        fx.CaseID,
				EvidenceIDs:   []string{fx.EvidenceID},
				ArtifactIDs:   []string{fx.ArtifactID},
			})
			if err != nil {
				errs <- err
				return
			}
			got, gErr := env.exportStore.GetBundleManifest(bid)
			if gErr != nil || got.BundleDigest != out.BundleDigest {
				errs <- fmt.Errorf("readback %s failed: got=%v err=%v", bid, got, gErr)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent C23 error: %v", err)
		}
	}

	assertSealedBlobUnchangedC23(t, seeded.blobPath, seeded.blobSHA, seeded.blobSize)
}

package tests_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/Parsa-Emami/Breachatlas/internal/holds"
	"github.com/Parsa-Emami/Breachatlas/internal/recovery"
	"github.com/Parsa-Emami/Breachatlas/internal/retention"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

type c26Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c26PositiveFixture struct {
	SchemaVersion      string  `json:"schema_version"`
	CaseID             string  `json:"case_id"`
	EvidenceID         string  `json:"evidence_id"`
	ArtifactID         string  `json:"artifact_id"`
	BundleID           string  `json:"bundle_id"`
	OperationIDRestore string  `json:"operation_id_restore"`
	OperationIDRebuild string  `json:"operation_id_rebuild"`
	KeyIDCheckpoint    string  `json:"key_id_checkpoint"`
	KeyIDBundle        string  `json:"key_id_bundle"`
	KeyIDArtifact      string  `json:"key_id_artifact"`
	ZoneHint           string  `json:"zone_hint"`
	SourceConfidence   float64 `json:"source_confidence"`
	Provider           string  `json:"provider"`
	PayloadJSONL       string  `json:"payload_jsonl"`
	CustodyEvents      []struct {
		EventID       string `json:"event_id"`
		EventType     string `json:"event_type"`
		Actor         string `json:"actor"`
		Timestamp     string `json:"timestamp"`
		Reason        string `json:"reason"`
		FromCustodian string `json:"from_custodian,omitempty"`
		ToCustodian   string `json:"to_custodian,omitempty"`
	} `json:"custody_events"`
	Hypothesis struct {
		HypothesisID string `json:"hypothesis_id"`
		Author       string `json:"author"`
		Rationale    string `json:"rationale"`
		Statement    string `json:"statement"`
		UILabel      string `json:"ui_label"`
	} `json:"hypothesis"`
}

type c26NegativeCasesFixture struct {
	SchemaVersion string `json:"schema_version"`
	Cases         []struct {
		Name             string `json:"name"`
		Fault            string `json:"fault,omitempty"`
		MaxRestoreBytes  int64  `json:"max_restore_bytes,omitempty"`
		MaxRetryCount    int    `json:"max_retry_count,omitempty"`
		Attempt          int    `json:"attempt,omitempty"`
		ReuseOperationID bool   `json:"reuse_operation_id,omitempty"`
		ConcurrentOpen   bool   `json:"concurrent_open,omitempty"`
		Mutation         string `json:"mutation,omitempty"`
		BundlePath       string `json:"bundle_path,omitempty"`
		Provider         string `json:"provider,omitempty"`
		ExpectedError    string `json:"expected_error"`
	} `json:"cases"`
}

type c26ExpectedOutcomesFixture struct {
	SchemaVersion string `json:"schema_version"`
	BundleRestore struct {
		Verified               bool `json:"verified"`
		CustodyRewritten       bool `json:"custody_rewritten"`
		SealedBytesModified    bool `json:"sealed_bytes_modified"`
		TimelineRebuilt        bool `json:"timeline_rebuilt"`
		RebuiltTimelineEntries int  `json:"rebuilt_timeline_entries"`
		RawTimestampsPreserved bool `json:"raw_timestamps_preserved"`
		SearchParity           bool `json:"search_parity"`
	} `json:"bundle_restore"`
	ConsistencyRebuild struct {
		VerifiedEvidenceCount  int  `json:"verified_evidence_count"`
		VerifiedArtifactCount  int  `json:"verified_artifact_count"`
		CustodyRewritten       bool `json:"custody_rewritten"`
		SealedBytesModified    bool `json:"sealed_bytes_modified"`
		TimelineRebuilt        bool `json:"timeline_rebuilt"`
		RebuiltTimelineEntries int  `json:"rebuilt_timeline_entries"`
		SearchParity           bool `json:"search_parity"`
	} `json:"consistency_rebuild"`
	AckLossReplay struct {
		IdempotentReplay    bool `json:"idempotent_replay"`
		CustodyRewritten    bool `json:"custody_rewritten"`
		SealedBytesModified bool `json:"sealed_bytes_modified"`
	} `json:"ack_loss_replay"`
}

type c26Workspace struct {
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
	holdsDir        string
	retDir          string
	recDir          string
	sealStore       *evidence.SealStore
	ledgerStore     *custody.LedgerStore
	checkpointStore *custody.FileCheckpointStore
	registry        *analyzers.Registry
	sandbox         *analyzers.Sandbox
	artifactStore   *artifacts.ArtifactStore
	indexStore      *timeline.EventIndexStore
	findingStore    *findings.FindingStore
	exportStore     *export.ExportStore
	holdService     *holds.Service
	retStore        *retention.RetentionStore
	restoreStore    *recovery.RestoreStore
}

func getC26FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		cand := filepath.Join(dir, "tests", "fixtures", "breachatlas", "C26")
		if info, err := os.Stat(cand); err == nil && info.IsDir() {
			return cand
		}
	}
	t.Fatalf("could not locate tests/fixtures/breachatlas/C26 from %s", wd)
	return ""
}

func loadC26JSON[T any](t *testing.T, rel string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(getC26FixturesDir(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read C26 fixture %s: %v", rel, err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal C26 fixture %s: %v", rel, err)
	}
	return out
}

func setupC26Workspace(t *testing.T, withRestoreStore bool) *c26Workspace {
	t.Helper()
	root := t.TempDir()
	ws := &c26Workspace{
		root:     root,
		qDir:     filepath.Join(root, "quarantine"),
		sDir:     filepath.Join(root, "sealstore"),
		custDir:  filepath.Join(root, "custody"),
		chkDir:   filepath.Join(root, "checkpoints"),
		scDir:    filepath.Join(root, "scratch"),
		aDir:     filepath.Join(root, "artifacts"),
		idxDir:   filepath.Join(root, "timeline-index"),
		findDir:  filepath.Join(root, "findings"),
		expDir:   filepath.Join(root, "exports"),
		holdsDir: filepath.Join(root, "holds"),
		retDir:   filepath.Join(root, "retention"),
		recDir:   filepath.Join(root, "recovery"),
	}

	var err error
	ws.sealStore, err = evidence.OpenSealStore(evidence.SealConfig{RootDir: ws.sDir, QuarantineDir: ws.qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.sealStore.Close() })

	ws.ledgerStore, err = custody.OpenLedgerStore(custody.LedgerConfig{RootDir: ws.custDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.ledgerStore.Close() })

	ws.checkpointStore, err = custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{RootDir: ws.chkDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.checkpointStore.Close() })

	ws.registry, err = analyzers.NewRegistry(analyzers.RegistryConfig{SealStore: ws.sealStore, SealRootDir: ws.sDir, Provider: "local"})
	if err != nil {
		t.Fatal(err)
	}
	ws.sandbox, err = analyzers.NewSandbox(ws.registry, analyzers.DefaultSandboxConfig(ws.scDir))
	if err != nil {
		t.Fatal(err)
	}

	ws.artifactStore, err = artifacts.OpenArtifactStore(artifacts.StoreConfig{RootDir: ws.aDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.artifactStore.Close() })

	ws.indexStore, err = timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: ws.idxDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.indexStore.Close() })

	ws.findingStore, err = findings.OpenFindingStore(findings.FindingStoreConfig{RootDir: ws.findDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.findingStore.Close() })

	ws.exportStore, err = export.OpenExportStore(export.ExportStoreConfig{RootDir: ws.expDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.exportStore.Close() })

	ws.holdService, err = holds.OpenService(holds.ServiceConfig{
		RootDir:   ws.holdsDir,
		SealStore: ws.sealStore,
		Ledger:    ws.ledgerStore,
		SyncDir:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.holdService.Close() })

	ws.retStore, err = retention.OpenRetentionStore(retention.RetentionConfig{
		RootDir:     ws.retDir,
		SealStore:   ws.sealStore,
		HoldService: ws.holdService,
		LedgerStore: ws.ledgerStore,
		SyncDir:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.retStore.Close() })

	if withRestoreStore {
		ws.restoreStore, err = recovery.OpenRestoreStore(recovery.RestoreConfig{RootDir: ws.recDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ws.restoreStore.Close() })
	}

	return ws
}

func (ws *c26Workspace) targetStores() recovery.TargetStores {
	return recovery.TargetStores{
		SealStore:       ws.sealStore,
		SealRootDir:     ws.sDir,
		QuarantineDir:   ws.qDir,
		LedgerStore:     ws.ledgerStore,
		LedgerRootDir:   ws.custDir,
		CheckpointStore: ws.checkpointStore,
		ArtifactStore:   ws.artifactStore,
		ArtifactRootDir: ws.aDir,
		IndexStore:      ws.indexStore,
		IndexRootDir:    ws.idxDir,
		HoldService:     ws.holdService,
		RetentionStore:  ws.retStore,
	}
}

type c26SeededBundle struct {
	bundleDir      string
	bundleDigest   string
	blobPath       string
	blobSHA        string
	custodyFile    string
	custodyFileSHA string
	custodyRoot    string
	chkPubHex      string
	bndPubHex      string
	artPub         ed25519.PublicKey
	baselineSearch *timeline.SearchResult
}

func seedCaseAndPackageBundleC26(t *testing.T, ws *c26Workspace, fx c26PositiveFixture, caseID, evidenceID, artifactID, bundleID string) c26SeededBundle {
	t.Helper()
	ctx := context.Background()
	raw := []byte(fx.PayloadJSONL)
	sum := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(sum[:])
	sz := int64(len(raw))

	q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{
		QuarantineDir: ws.qDir,
		BufferSize:    64,
		SyncDir:       true,
	}, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-" + caseID + "-" + evidenceID,
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		MediaType:     "application/json",
		Filename:      evidenceID + ".jsonl",
		ExpectedSize:  &sz,
		Body:          strings.NewReader(fx.PayloadJSONL),
	})
	if err != nil {
		t.Fatalf("quarantine %s: %v", evidenceID, err)
	}

	for _, ev := range fx.CustodyEvents {
		if _, err := ws.ledgerStore.AppendEvent(ctx, custody.AppendEventRequest{
			EventID:       ev.EventID + "-" + evidenceID,
			CaseID:        caseID,
			EvidenceID:    evidenceID,
			EventType:     ev.EventType,
			Actor:         ev.Actor,
			Timestamp:     ev.Timestamp,
			Reason:        ev.Reason,
			FromCustodian: ev.FromCustodian,
			ToCustodian:   ev.ToCustodian,
		}); err != nil {
			t.Fatalf("append custody %s: %v", ev.EventID, err)
		}
	}
	curRoot, err := ws.ledgerStore.CurrentRoot(caseID, evidenceID)
	if err != nil {
		t.Fatalf("current custody root: %v", err)
	}

	sm, err := ws.sealStore.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "seal-" + caseID + "-" + evidenceID,
		Quarantined:    q,
		ExpectedSHA256: shaHex,
		AcquiredAt:     "2026-11-01T07:00:00Z",
		CustodyRoot:    curRoot,
	})
	if err != nil {
		t.Fatalf("seal %s: %v", evidenceID, err)
	}
	blobPath := filepath.Join(ws.sDir, filepath.FromSlash(sm.BlobRelPath))

	chkPub, chkPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chkPubHex := hex.EncodeToString(chkPub)
	chk, err := custody.CreateCheckpoint(ctx, ws.ledgerStore, custody.CreateCheckpointRequest{
		CheckpointID: "chk-" + evidenceID + "-01",
		CaseID:       caseID,
		EvidenceID:   evidenceID,
		Sequence:     uint64(len(fx.CustodyEvents)),
		CustodyRoot:  curRoot,
		KeyID:        fx.KeyIDCheckpoint,
		Revision:     1,
		IssuedAt:     time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		PrivateKey:   chkPriv,
	})
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	if err := ws.checkpointStore.SaveCheckpoint(ctx, *chk); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}

	runRes, err := ws.sandbox.RunIsolated(ctx, analyzers.IsolatedRunRequest{
		RunID:      "run-" + artifactID,
		CaseID:     caseID,
		EvidenceID: evidenceID,
		AnalyzerID: analyzers.AnalyzerJSON,
		Provider:   fx.Provider,
		Options:    analyzers.DefaultParseOptions(),
	})
	if err != nil {
		t.Fatalf("sandbox run: %v", err)
	}

	artPub, artPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ws.artifactStore.DeriveFromIsolatedRun(ctx, ws.sealStore, ws.sDir, runRes, artifacts.DeriveRequest{
		OperationID: "drv-" + artifactID,
		CaseID:      caseID,
		ArtifactID:  artifactID,
		Provider:    fx.Provider,
		KeyID:       fx.KeyIDArtifact,
		PrivateKey:  artPriv,
	}); err != nil {
		t.Fatalf("derive artifact: %v", err)
	}

	conf := fx.SourceConfidence
	if _, err := ws.indexStore.IndexDerivedArtifact(ctx, ws.sealStore, ws.sDir, ws.artifactStore, ws.aDir, timeline.IndexDerivedRequest{
		SchemaVersion:    "1",
		OperationID:      "idx-" + artifactID,
		CaseID:           caseID,
		ArtifactID:       artifactID,
		Provider:         fx.Provider,
		ZoneHint:         fx.ZoneHint,
		SourceConfidence: &conf,
		VerifyOptions: artifacts.VerifyOptions{
			TrustedKeys:      map[string]ed25519.PublicKey{fx.KeyIDArtifact: artPub},
			RequireSignature: true,
		},
	}); err != nil {
		t.Fatalf("index derived artifact: %v", err)
	}

	if _, err := ws.findingStore.RecordHypothesis(ctx, ws.sealStore, ws.sDir, ws.indexStore, findings.RecordHypothesisRequest{
		SchemaVersion:         "1",
		OperationID:           "hyp-" + caseID,
		HypothesisID:          fx.Hypothesis.HypothesisID,
		CaseID:                caseID,
		Author:                fx.Hypothesis.Author,
		Rationale:             fx.Hypothesis.Rationale,
		Statement:             fx.Hypothesis.Statement,
		UILabel:               fx.Hypothesis.UILabel,
		SupportingEvidenceIDs: []string{evidenceID},
	}); err != nil {
		t.Fatalf("record hypothesis: %v", err)
	}

	baselineSearch, err := ws.indexStore.Search(ctx, timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        caseID,
		Provider:      fx.Provider,
		MaxResults:    50,
	})
	if err != nil {
		t.Fatalf("baseline search: %v", err)
	}

	bndPub, bndPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bndPubHex := hex.EncodeToString(bndPub)
	expOut, err := ws.exportStore.PackageCaseBundle(ctx, export.ExportDeps{
		SealStore:       ws.sealStore,
		SealRootDir:     ws.sDir,
		LedgerStore:     ws.ledgerStore,
		CheckpointStore: ws.checkpointStore,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{fx.KeyIDCheckpoint: chkPubHex},
		},
		ArtifactStore:   ws.artifactStore,
		ArtifactRootDir: ws.aDir,
		IndexStore:      ws.indexStore,
		FindingStore:    ws.findingStore,
	}, export.ExportRequest{
		SchemaVersion:   "1",
		OperationID:     "exp-" + bundleID,
		BundleID:        bundleID,
		CaseID:          caseID,
		Provider:        fx.Provider,
		EvidenceIDs:     []string{evidenceID},
		ArtifactIDs:     []string{artifactID},
		IncludeTimeline: true,
		IncludeNotes:    true,
		KeyID:           fx.KeyIDBundle,
		PrivateKey:      bndPriv,
	})
	if err != nil {
		t.Fatalf("package bundle: %v", err)
	}

	custFile := filepath.Join(ws.ledgerStore.CustodyDir(), caseID, evidenceID+".jsonl")
	custSHA := hashFileHexC26(t, custFile)

	return c26SeededBundle{
		bundleDir:      expOut.BundleDir,
		bundleDigest:   expOut.BundleDigest,
		blobPath:       blobPath,
		blobSHA:        shaHex,
		custodyFile:    custFile,
		custodyFileSHA: custSHA,
		custodyRoot:    curRoot,
		chkPubHex:      chkPubHex,
		bndPubHex:      bndPubHex,
		artPub:         artPub,
		baselineSearch: baselineSearch,
	}
}

func hashFileHexC26(t *testing.T, p string) string {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read file %s: %v", p, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func copyDirRecursiveC26(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o640)
	})
	if err != nil {
		t.Fatalf("copy dir %s -> %s: %v", src, dst, err)
	}
}

func TestC26FixturesAndProvenance(t *testing.T) {
	prov := loadC26JSON[c26Provenance](t, "provenance.json")
	if prov.Task != "C26" || prov.License != "Apache-2.0" {
		t.Fatalf("unexpected C26 provenance: %+v", prov)
	}
	if len(prov.SHA256) != 3 {
		t.Fatalf("expected 3 hashed C26 fixture files, got %d", len(prov.SHA256))
	}
	dir := getC26FixturesDir(t)
	for rel, want := range prov.SHA256 {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("missing C26 fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("fixture %s sha mismatch: got %s want %s", rel, got, want)
		}
	}

	pos := loadC26JSON[c26PositiveFixture](t, "positive/restore-case-consistency.json")
	if pos.CaseID == "" || len(pos.CustodyEvents) == 0 {
		t.Fatalf("invalid positive fixture: %+v", pos)
	}
	neg := loadC26JSON[c26NegativeCasesFixture](t, "invalid/restore-negative-cases.json")
	if len(neg.Cases) < 10 {
		t.Fatalf("expected comprehensive negative fixture cases, got %d", len(neg.Cases))
	}
	exp := loadC26JSON[c26ExpectedOutcomesFixture](t, "expected-output/restore-outcomes.json")
	if !exp.BundleRestore.Verified || exp.BundleRestore.CustodyRewritten || exp.BundleRestore.SealedBytesModified {
		t.Fatalf("unexpected expected outcomes fixture: %+v", exp)
	}
}

func TestRestoreCrossChecksAndTimelineRebuildWithoutCustodyRewrite(t *testing.T) {
	ctx := context.Background()
	fx := loadC26JSON[c26PositiveFixture](t, "positive/restore-case-consistency.json")
	expected := loadC26JSON[c26ExpectedOutcomesFixture](t, "expected-output/restore-outcomes.json")

	srcWS := setupC26Workspace(t, true)
	seeded := seedCaseAndPackageBundleC26(t, srcWS, fx, fx.CaseID, fx.EvidenceID, fx.ArtifactID, fx.BundleID)
	conf := fx.SourceConfidence

	// Part A: Corrupt derived timeline index on disk, verify consistency cross-checks & rebuild without custody rewrite.
	_ = srcWS.indexStore.Close()
	corruptCaseIdxPath := filepath.Join(srcWS.idxDir, "cases", fx.CaseID+".index.json")
	if err := os.WriteFile(corruptCaseIdxPath, []byte(`{"corrupted":true}`), 0o640); err != nil {
		t.Fatalf("corrupt derived index: %v", err)
	}

	// VerifyAndRebuildCase with IndexRootDir (replaces corrupted derived index automatically).
	storesForRebuild := srcWS.targetStores()
	storesForRebuild.IndexStore = nil
	rebuildOut, err := srcWS.restoreStore.VerifyAndRebuildCase(ctx, storesForRebuild, recovery.VerifyAndRebuildRequest{
		SchemaVersion:         "1",
		OperationID:           fx.OperationIDRebuild,
		CaseID:                fx.CaseID,
		Provider:              fx.Provider,
		ZoneHint:              fx.ZoneHint,
		SourceConfidence:      &conf,
		TrustedCheckpointKeys: map[string]string{fx.KeyIDCheckpoint: seeded.chkPubHex},
		RequireCheckpoints:    true,
		ArtifactVerifyOpts: artifacts.VerifyOptions{
			TrustedKeys:      map[string]ed25519.PublicKey{fx.KeyIDArtifact: seeded.artPub},
			RequireSignature: true,
		},
	})
	if err != nil {
		t.Fatalf("VerifyAndRebuildCase: %v", err)
	}
	if rebuildOut.VerifiedEvidenceCount != expected.ConsistencyRebuild.VerifiedEvidenceCount ||
		rebuildOut.VerifiedArtifactCount != expected.ConsistencyRebuild.VerifiedArtifactCount ||
		rebuildOut.CustodyRewritten != expected.ConsistencyRebuild.CustodyRewritten ||
		rebuildOut.SealedBytesModified != expected.ConsistencyRebuild.SealedBytesModified ||
		rebuildOut.TimelineRebuilt != expected.ConsistencyRebuild.TimelineRebuilt ||
		rebuildOut.RebuiltTimelineEntries != expected.ConsistencyRebuild.RebuiltTimelineEntries {
		t.Fatalf("unexpected rebuild outcome: %+v", rebuildOut)
	}

	// Confirm sealed source bytes and custody .jsonl file remain bit-identical after rebuild.
	if got := hashFileHexC26(t, seeded.blobPath); got != seeded.blobSHA {
		t.Fatalf("sealed blob modified after rebuild: got %s want %s", got, seeded.blobSHA)
	}
	if got := hashFileHexC26(t, seeded.custodyFile); got != seeded.custodyFileSHA {
		t.Fatalf("custody file rewritten after rebuild: got %s want %s", got, seeded.custodyFileSHA)
	}

	// Reopen EventIndexStore and verify search parity + preserved raw timestamps / DST ambiguity.
	reopenedIdx, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: srcWS.idxDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen rebuilt EventIndexStore: %v", err)
	}
	defer func() { _ = reopenedIdx.Close() }()
	srcWS.indexStore = reopenedIdx

	rebuiltSearch, err := reopenedIdx.Search(ctx, timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		Provider:      fx.Provider,
		MaxResults:    50,
	})
	if err != nil {
		t.Fatalf("search rebuilt index: %v", err)
	}
	if rebuiltSearch.ResultDigest != seeded.baselineSearch.ResultDigest {
		t.Fatalf("search digest parity mismatch after rebuild: got %s want %s", rebuiltSearch.ResultDigest, seeded.baselineSearch.ResultDigest)
	}

	// Part B: Restore into a clean target host workspace from the signed portable export bundle.
	dstWS := setupC26Workspace(t, true)
	restoreOut, err := dstWS.restoreStore.RestoreFromBundle(ctx, dstWS.targetStores(), recovery.RestoreBundleRequest{
		SchemaVersion:          "1",
		OperationID:            fx.OperationIDRestore,
		CaseID:                 fx.CaseID,
		BundlePath:             seeded.bundleDir,
		Provider:               fx.Provider,
		ZoneHint:               fx.ZoneHint,
		SourceConfidence:       &conf,
		TrustedBundleKeys:      map[string]string{fx.KeyIDBundle: seeded.bndPubHex},
		RequireBundleSignature: true,
		TrustedCheckpointKeys:  map[string]string{fx.KeyIDCheckpoint: seeded.chkPubHex},
		RequireCheckpointTrust: true,
		ArtifactVerifyOpts: artifacts.VerifyOptions{
			TrustedKeys:      map[string]ed25519.PublicKey{fx.KeyIDArtifact: seeded.artPub},
			RequireSignature: true,
		},
	})
	if err != nil {
		t.Fatalf("RestoreFromBundle: %v", err)
	}
	if restoreOut.BundleDigest != seeded.bundleDigest ||
		restoreOut.RestoredEvidenceCount != 1 ||
		restoreOut.RestoredArtifactCount != 1 ||
		restoreOut.CustodyRewritten != expected.BundleRestore.CustodyRewritten ||
		restoreOut.SealedBytesModified != expected.BundleRestore.SealedBytesModified ||
		restoreOut.TimelineRebuilt != expected.BundleRestore.TimelineRebuilt ||
		restoreOut.RebuiltTimelineEntries != expected.BundleRestore.RebuiltTimelineEntries {
		t.Fatalf("unexpected restore outcome: %+v", restoreOut)
	}

	// Verify restored custody chain and root match source bit-for-bit.
	dstRoot, err := dstWS.ledgerStore.CurrentRoot(fx.CaseID, fx.EvidenceID)
	if err != nil || dstRoot != seeded.custodyRoot {
		t.Fatalf("restored custody root %q != source %q (err=%v)", dstRoot, seeded.custodyRoot, err)
	}
	srcEvents, _ := srcWS.ledgerStore.ListEvents(fx.CaseID, fx.EvidenceID)
	dstEvents, _ := dstWS.ledgerStore.ListEvents(fx.CaseID, fx.EvidenceID)
	if len(dstEvents) != len(srcEvents) {
		t.Fatalf("restored custody event count %d != %d", len(dstEvents), len(srcEvents))
	}
	for i := range srcEvents {
		if srcEvents[i] != dstEvents[i] {
			t.Fatalf("restored custody event[%d] differs: got %+v want %+v", i, dstEvents[i], srcEvents[i])
		}
	}

	// Verify restored sealed evidence, derived artifact, and timeline search parity + raw timestamps.
	vrSeal, err := evidence.VerifyStoreEvidence(ctx, dstWS.sealStore, fx.CaseID, fx.EvidenceID, evidence.VerifyOptions{})
	if err != nil || !vrSeal.Verified {
		t.Fatalf("restored seal verification failed: %v", err)
	}
	vrArt, err := dstWS.artifactStore.VerifyStoredArtifact(ctx, dstWS.sealStore, fx.CaseID, fx.ArtifactID, artifacts.VerifyOptions{
		TrustedKeys:      map[string]ed25519.PublicKey{fx.KeyIDArtifact: seeded.artPub},
		RequireSignature: true,
	})
	if err != nil || !vrArt.Verified {
		t.Fatalf("restored artifact verification failed: %v", err)
	}
	dstSearch, err := dstWS.indexStore.Search(ctx, timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		Provider:      fx.Provider,
		MaxResults:    50,
	})
	if err != nil {
		t.Fatalf("search restored timeline: %v", err)
	}
	if dstSearch.ResultDigest != seeded.baselineSearch.ResultDigest {
		t.Fatalf("restored search digest %s != baseline %s", dstSearch.ResultDigest, seeded.baselineSearch.ResultDigest)
	}

	// Verify raw timestamps and ambiguous DST entries survived restore + rebuild intact.
	foundAmbiguous := false
	for _, e := range dstSearch.Entries {
		if strings.TrimSpace(e.Time.RawTimestamp) == "" {
			t.Fatalf("lost raw_timestamp on entry %s", e.EventIdentity)
		}
		if e.Time.RawTimestamp == "2026-11-01 01:30:00" {
			foundAmbiguous = true
			if e.Time.TimezoneStatus != timeline.StatusDSTAmbiguous || len(e.Time.CandidateUTCs) != 2 {
				t.Fatalf("expected explicit ambiguous DST preserved, got %+v", e.Time)
			}
		}
	}
	if !foundAmbiguous {
		t.Fatalf("expected ambiguous DST entry preserved in restored timeline")
	}

	// Verify restart persistence across target stores and RetentionStore tombstone consistency cross-check.
	_ = dstWS.restoreStore.Close()
	reopenedRestore, err := recovery.OpenRestoreStore(recovery.RestoreConfig{RootDir: dstWS.recDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen restore store: %v", err)
	}
	dstWS.restoreStore = reopenedRestore
	if rep := reopenedRestore.LastRecoveryReport(); rep.RecoveredOperations != 1 {
		t.Fatalf("expected 1 recovered operation after restart, got %+v", rep)
	}

	// Release any hold (none active) and record explicit destruction tombstone on source WS, then verify consistency rebuild honors tombstones without modifying sealed bytes.
	if _, err := srcWS.retStore.DestroyEvidence(ctx, retention.DestroyRequest{
		SchemaVersion:    "1",
		OperationID:      "op-c26-tomb-01",
		TombstoneID:      "tomb-c26-01",
		CaseID:           fx.CaseID,
		EvidenceID:       fx.EvidenceID,
		Operator:         "operator-aria",
		Timestamp:        "2026-11-02T00:00:00Z",
		Reason:           "Post-export retention tombstone verification",
		Provider:         fx.Provider,
		ExplicitApproval: true,
	}); err != nil {
		t.Fatalf("destroy evidence for tombstone check: %v", err)
	}
	tombRebuild, err := srcWS.restoreStore.VerifyAndRebuildCase(ctx, srcWS.targetStores(), recovery.VerifyAndRebuildRequest{
		SchemaVersion: "1",
		OperationID:   "op-c26-rebuild-post-tomb",
		CaseID:        fx.CaseID,
		Provider:      fx.Provider,
		ZoneHint:      fx.ZoneHint,
	})
	if err != nil {
		t.Fatalf("VerifyAndRebuildCase with tombstone: %v", err)
	}
	if tombRebuild.VerifiedTombstones != 1 || tombRebuild.CustodyRewritten || tombRebuild.SealedBytesModified {
		t.Fatalf("unexpected tombstone rebuild outcome: %+v", tombRebuild)
	}
}

func TestRestoreBoundaryCrashRecovery(t *testing.T) {
	ctx := context.Background()
	fx := loadC26JSON[c26PositiveFixture](t, "positive/restore-case-consistency.json")

	srcWS := setupC26Workspace(t, false)
	priorBundle := seedCaseAndPackageBundleC26(t, srcWS, fx, "case-c26-prior", "ev-c26-prior", "art-c26-prior", "bnd-c26-prior")
	newBundle := seedCaseAndPackageBundleC26(t, srcWS, fx, fx.CaseID, fx.EvidenceID, fx.ArtifactID, fx.BundleID)
	conf := fx.SourceConfidence

	// Setup target workspace and commit prior Case A first as authoritative baseline.
	dstWS := setupC26Workspace(t, false)
	baseStore, err := recovery.OpenRestoreStore(recovery.RestoreConfig{RootDir: dstWS.recDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := baseStore.RestoreFromBundle(ctx, dstWS.targetStores(), recovery.RestoreBundleRequest{
		SchemaVersion:          "1",
		OperationID:            "op-prior-restore",
		CaseID:                 "case-c26-prior",
		BundlePath:             priorBundle.bundleDir,
		Provider:               fx.Provider,
		ZoneHint:               fx.ZoneHint,
		SourceConfidence:       &conf,
		TrustedBundleKeys:      map[string]string{fx.KeyIDBundle: priorBundle.bndPubHex},
		RequireBundleSignature: true,
	}); err != nil {
		t.Fatalf("seed prior baseline restore: %v", err)
	}
	_ = baseStore.Close()

	for _, faultKind := range []string{"FailAfterStageBeforeCommit", "FailBeforeManifestCommit"} {
		t.Run(faultKind, func(t *testing.T) {
			faults := recovery.RestoreFaults{}
			if faultKind == "FailAfterStageBeforeCommit" {
				faults.FailAfterStageBeforeCommit = true
			} else {
				faults.FailBeforeManifestCommit = true
			}

			faultStore, err := recovery.OpenRestoreStore(recovery.RestoreConfig{
				RootDir: dstWS.recDir,
				SyncDir: true,
				Faults:  faults,
			})
			if err != nil {
				t.Fatal(err)
			}

			_, err = faultStore.RestoreFromBundle(ctx, dstWS.targetStores(), recovery.RestoreBundleRequest{
				SchemaVersion:          "1",
				OperationID:            "op-crash-" + faultKind,
				CaseID:                 fx.CaseID,
				BundlePath:             newBundle.bundleDir,
				Provider:               fx.Provider,
				ZoneHint:               fx.ZoneHint,
				SourceConfidence:       &conf,
				TrustedBundleKeys:      map[string]string{fx.KeyIDBundle: newBundle.bndPubHex},
				RequireBundleSignature: true,
			})
			if !errors.Is(err, recovery.ErrRestoreInterrupted) {
				t.Fatalf("expected ErrRestoreInterrupted for %s, got %v", faultKind, err)
			}
			_ = faultStore.Close()

			// Restart cleanly: staging must be cleaned and ONLY prior authoritative state exposed.
			recoveredStore, err := recovery.OpenRestoreStore(recovery.RestoreConfig{RootDir: dstWS.recDir, SyncDir: true})
			if err != nil {
				t.Fatalf("reopen after %s: %v", faultKind, err)
			}
			if rep := recoveredStore.LastRecoveryReport(); len(rep.CleanedStagingFiles) == 0 {
				t.Fatalf("expected staging cleanup on restart after %s, got %+v", faultKind, rep)
			}

			// Prior case remains intact.
			if vr, vErr := evidence.VerifyStoreEvidence(ctx, dstWS.sealStore, "case-c26-prior", "ev-c26-prior", evidence.VerifyOptions{}); vErr != nil || !vr.Verified {
				t.Fatalf("prior authoritative case corrupted after %s: %v", faultKind, vErr)
			}
			// Aborted new case must NOT be partially present in any authoritative store.
			if _, gErr := dstWS.sealStore.GetSealedManifest(fx.CaseID, fx.EvidenceID); !os.IsNotExist(gErr) {
				t.Fatalf("aborted case leaked into SealStore after %s: %v", faultKind, gErr)
			}
			if evs, _ := dstWS.ledgerStore.ListEvents(fx.CaseID, fx.EvidenceID); len(evs) != 0 {
				t.Fatalf("aborted case leaked into LedgerStore after %s: %d events", faultKind, len(evs))
			}
			if _, aErr := dstWS.artifactStore.GetManifest(fx.CaseID, fx.ArtifactID); !errors.Is(aErr, artifacts.ErrArtifactNotFound) {
				t.Fatalf("aborted case leaked into ArtifactStore after %s: %v", faultKind, aErr)
			}
			if entries, _ := dstWS.indexStore.ListEntries(fx.CaseID); len(entries) != 0 {
				t.Fatalf("aborted case leaked into EventIndexStore after %s: %d entries", faultKind, len(entries))
			}
			_ = recoveredStore.Close()
		})
	}

	// Retry cleanly without fault injection: full new authoritative state commits cleanly.
	cleanStore, err := recovery.OpenRestoreStore(recovery.RestoreConfig{RootDir: dstWS.recDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanStore.Close() }()
	out, err := cleanStore.RestoreFromBundle(ctx, dstWS.targetStores(), recovery.RestoreBundleRequest{
		SchemaVersion:          "1",
		OperationID:            "op-clean-after-crash",
		CaseID:                 fx.CaseID,
		BundlePath:             newBundle.bundleDir,
		Provider:               fx.Provider,
		ZoneHint:               fx.ZoneHint,
		SourceConfidence:       &conf,
		TrustedBundleKeys:      map[string]string{fx.KeyIDBundle: newBundle.bndPubHex},
		RequireBundleSignature: true,
	})
	if err != nil {
		t.Fatalf("clean retry after crash recovery failed: %v", err)
	}
	if out.RestoredEvidenceCount != 1 || !out.TimelineRebuilt || out.CustodyRewritten || out.SealedBytesModified {
		t.Fatalf("unexpected clean retry outcome: %+v", out)
	}
}

func TestRestoreReplayQuotaLockAndNegativeCases(t *testing.T) {
	ctx := context.Background()
	fx := loadC26JSON[c26PositiveFixture](t, "positive/restore-case-consistency.json")
	neg := loadC26JSON[c26NegativeCasesFixture](t, "invalid/restore-negative-cases.json")
	expected := loadC26JSON[c26ExpectedOutcomesFixture](t, "expected-output/restore-outcomes.json")

	srcWS := setupC26Workspace(t, false)
	seeded := seedCaseAndPackageBundleC26(t, srcWS, fx, fx.CaseID, fx.EvidenceID, fx.ArtifactID, fx.BundleID)
	conf := fx.SourceConfidence

	// 1. ACK-loss idempotent replay on committed restore.
	replayWS := setupC26Workspace(t, true)
	req := recovery.RestoreBundleRequest{
		SchemaVersion:          "1",
		OperationID:            fx.OperationIDRestore,
		CaseID:                 fx.CaseID,
		BundlePath:             seeded.bundleDir,
		Provider:               fx.Provider,
		ZoneHint:               fx.ZoneHint,
		SourceConfidence:       &conf,
		TrustedBundleKeys:      map[string]string{fx.KeyIDBundle: seeded.bndPubHex},
		RequireBundleSignature: true,
	}
	firstOut, err := replayWS.restoreStore.RestoreFromBundle(ctx, replayWS.targetStores(), req)
	if err != nil {
		t.Fatalf("first restore: %v", err)
	}
	if firstOut.IdempotentReplay {
		t.Fatalf("first restore unexpectedly marked as replay")
	}

	// Capture custody and sealed blob hashes before ACK-loss replay.
	dstBlobPath := filepath.Join(replayWS.sDir, "blobs", "sha256", seeded.blobSHA)
	dstCustodyPath := filepath.Join(replayWS.ledgerStore.CustodyDir(), fx.CaseID, fx.EvidenceID+".jsonl")
	preBlobHash := hashFileHexC26(t, dstBlobPath)
	preCustodyHash := hashFileHexC26(t, dstCustodyPath)

	replayOut, err := replayWS.restoreStore.RestoreFromBundle(ctx, replayWS.targetStores(), req)
	if err != nil {
		t.Fatalf("ACK-loss replay failed: %v", err)
	}
	if replayOut.IdempotentReplay != expected.AckLossReplay.IdempotentReplay ||
		replayOut.CustodyRewritten != expected.AckLossReplay.CustodyRewritten ||
		replayOut.SealedBytesModified != expected.AckLossReplay.SealedBytesModified ||
		replayOut.Generation != firstOut.Generation {
		t.Fatalf("unexpected ACK-loss replay outcome: %+v", replayOut)
	}
	if hashFileHexC26(t, dstBlobPath) != preBlobHash {
		t.Fatalf("sealed blob modified during replay")
	}
	if hashFileHexC26(t, dstCustodyPath) != preCustodyHash {
		t.Fatalf("custody chain modified during replay")
	}

	// 2. Drive every negative case declared in tests/fixtures/breachatlas/C26/invalid/restore-negative-cases.json.
	for _, nc := range neg.Cases {
		t.Run(nc.Name, func(t *testing.T) {
			switch {
			case nc.Fault == "FailAfterStageBeforeCommit" || nc.Fault == "FailBeforeManifestCommit":
				ws := setupC26Workspace(t, false)
				faults := recovery.RestoreFaults{
					FailAfterStageBeforeCommit: nc.Fault == "FailAfterStageBeforeCommit",
					FailBeforeManifestCommit:   nc.Fault == "FailBeforeManifestCommit",
				}
				rs, err := recovery.OpenRestoreStore(recovery.RestoreConfig{RootDir: ws.recDir, SyncDir: true, Faults: faults})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = rs.Close() }()
				_, err = rs.RestoreFromBundle(ctx, ws.targetStores(), req)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

			case nc.Fault == "SimulateDiskFull":
				ws := setupC26Workspace(t, false)
				rs, err := recovery.OpenRestoreStore(recovery.RestoreConfig{
					RootDir: ws.recDir,
					SyncDir: true,
					Faults:  recovery.RestoreFaults{SimulateDiskFull: true},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = rs.Close() }()
				_, err = rs.RestoreFromBundle(ctx, ws.targetStores(), req)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)
				if _, gErr := ws.sealStore.GetSealedManifest(fx.CaseID, fx.EvidenceID); !os.IsNotExist(gErr) {
					t.Fatalf("disk-full failure left partial SealStore state: %v", gErr)
				}

			case nc.MaxRestoreBytes > 0:
				ws := setupC26Workspace(t, false)
				rs, err := recovery.OpenRestoreStore(recovery.RestoreConfig{
					RootDir:         ws.recDir,
					MaxRestoreBytes: nc.MaxRestoreBytes,
					SyncDir:         true,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = rs.Close() }()
				_, err = rs.RestoreFromBundle(ctx, ws.targetStores(), req)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

			case nc.MaxRetryCount > 0:
				ws := setupC26Workspace(t, false)
				rs, err := recovery.OpenRestoreStore(recovery.RestoreConfig{
					RootDir:       ws.recDir,
					MaxRetryCount: nc.MaxRetryCount,
					SyncDir:       true,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = rs.Close() }()
				r2 := req
				r2.Attempt = nc.Attempt
				_, err = rs.RestoreFromBundle(ctx, ws.targetStores(), r2)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

			case nc.ReuseOperationID:
				conflictReq := req
				conflictReq.ZoneHint = "Europe/Berlin"
				_, err := replayWS.restoreStore.RestoreFromBundle(ctx, replayWS.targetStores(), conflictReq)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

			case nc.ConcurrentOpen:
				_, err := recovery.OpenRestoreStore(recovery.RestoreConfig{RootDir: replayWS.recDir})
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

			case nc.Mutation == "divergent_custody_chain":
				ws := setupC26Workspace(t, true)
				// Seed an existing divergent custody chain for the same (caseID, evidenceID).
				if _, err := ws.ledgerStore.AppendEvent(ctx, custody.AppendEventRequest{
					EventID:    "cust-existing-divergent-01",
					CaseID:     fx.CaseID,
					EvidenceID: fx.EvidenceID,
					EventType:  "intake_seal",
					Actor:      "operator-existing",
					Timestamp:  "2026-11-01T06:00:00Z",
					Reason:     "Pre-existing authoritative custody history must never be rewritten.",
				}); err != nil {
					t.Fatal(err)
				}
				existingCustPath := filepath.Join(ws.ledgerStore.CustodyDir(), fx.CaseID, fx.EvidenceID+".jsonl")
				beforeHash := hashFileHexC26(t, existingCustPath)

				_, err := ws.restoreStore.RestoreFromBundle(ctx, ws.targetStores(), req)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

				if afterHash := hashFileHexC26(t, existingCustPath); afterHash != beforeHash {
					t.Fatalf("existing custody file mutated on rejected restore: got %s want %s", afterHash, beforeHash)
				}

			case nc.Mutation == "tamper_bundle_blob":
				ws := setupC26Workspace(t, true)
				badDir := filepath.Join(t.TempDir(), "bundle-bad-blob")
				copyDirRecursiveC26(t, seeded.bundleDir, badDir)
				blobInBundle := filepath.Join(badDir, "evidence", fx.EvidenceID, "blob.dat")
				raw, err := os.ReadFile(blobInBundle)
				if err != nil {
					t.Fatal(err)
				}
				raw[0] ^= 0xff
				if err := os.WriteFile(blobInBundle, raw, 0o640); err != nil {
					t.Fatal(err)
				}
				r2 := req
				r2.BundlePath = badDir
				_, err = ws.restoreStore.RestoreFromBundle(ctx, ws.targetStores(), r2)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

			case nc.Mutation == "tamper_bundle_artifact":
				ws := setupC26Workspace(t, true)
				badDir := filepath.Join(t.TempDir(), "bundle-bad-art")
				copyDirRecursiveC26(t, seeded.bundleDir, badDir)
				artInBundle := filepath.Join(badDir, "artifacts", fx.ArtifactID, "output.json")
				if err := os.WriteFile(artInBundle, []byte(`{"tampered":true}`), 0o640); err != nil {
					t.Fatal(err)
				}
				r2 := req
				r2.BundlePath = badDir
				_, err = ws.restoreStore.RestoreFromBundle(ctx, ws.targetStores(), r2)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

			case nc.Mutation == "tamper_bundle_custody":
				ws := setupC26Workspace(t, true)
				badDir := filepath.Join(t.TempDir(), "bundle-bad-custody")
				copyDirRecursiveC26(t, seeded.bundleDir, badDir)
				custInBundle := filepath.Join(badDir, "evidence", fx.EvidenceID, "custody.json")
				raw, err := os.ReadFile(custInBundle)
				if err != nil {
					t.Fatal(err)
				}
				tampered := strings.Replace(string(raw), "analyst-mina", "attacker-x", 1)
				if err := os.WriteFile(custInBundle, []byte(tampered), 0o640); err != nil {
					t.Fatal(err)
				}
				r2 := req
				r2.BundlePath = badDir
				_, err = ws.restoreStore.RestoreFromBundle(ctx, ws.targetStores(), r2)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

			case nc.Mutation == "delete_bundle_manifest":
				ws := setupC26Workspace(t, true)
				badDir := filepath.Join(t.TempDir(), "bundle-missing-manifest")
				copyDirRecursiveC26(t, seeded.bundleDir, badDir)
				if err := os.Remove(filepath.Join(badDir, export.BundleManifestFile)); err != nil {
					t.Fatal(err)
				}
				r2 := req
				r2.BundlePath = badDir
				_, err = ws.restoreStore.RestoreFromBundle(ctx, ws.targetStores(), r2)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

			case nc.BundlePath != "":
				ws := setupC26Workspace(t, true)
				r2 := req
				r2.BundlePath = nc.BundlePath
				_, err := ws.restoreStore.RestoreFromBundle(ctx, ws.targetStores(), r2)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

			case nc.Mutation == "symlink_bundle_dir":
				ws := setupC26Workspace(t, true)
				symPath := filepath.Join(t.TempDir(), "bundle-symlink")
				if err := os.Symlink(seeded.bundleDir, symPath); err != nil {
					t.Fatalf("create bundle symlink: %v", err)
				}
				r2 := req
				r2.BundlePath = symPath
				_, err := ws.restoreStore.RestoreFromBundle(ctx, ws.targetStores(), r2)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

			case nc.Provider != "":
				ws := setupC26Workspace(t, true)
				r2 := req
				r2.Provider = nc.Provider
				_, err := ws.restoreStore.RestoreFromBundle(ctx, ws.targetStores(), r2)
				assertExpectedRecoveryErr(t, err, nc.ExpectedError)

			default:
				t.Fatalf("unhandled negative case: %+v", nc)
			}
		})
	}

	// 3. Additional sealed-source-immutability check: conflicting sealed blob on target host fails with ErrManifestConsistency without altering existing sealed bytes.
	conflictWS := setupC26Workspace(t, true)
	otherPayload := []byte("{\"timestamp\":\"2026-11-01T00:00:00Z\",\"event_type\":\"other\"}\n")
	otherSum := sha256.Sum256(otherPayload)
	otherSHA := hex.EncodeToString(otherSum[:])
	otherSz := int64(len(otherPayload))
	qOther, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{QuarantineDir: conflictWS.qDir, SyncDir: true}, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-existing-conflict",
		CaseID:        fx.CaseID,
		EvidenceID:    fx.EvidenceID,
		MediaType:     "application/json",
		Filename:      "existing.jsonl",
		ExpectedSize:  &otherSz,
		Body:          strings.NewReader(string(otherPayload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	existingSM, err := conflictWS.sealStore.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "seal-existing-conflict",
		Quarantined:    qOther,
		ExpectedSHA256: otherSHA,
		AcquiredAt:     "2026-11-01T00:00:00Z",
		CustodyRoot:    custody.GenesisPrevHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	existingBlobPath := filepath.Join(conflictWS.sDir, filepath.FromSlash(existingSM.BlobRelPath))
	beforeExistingSHA := hashFileHexC26(t, existingBlobPath)

	_, err = conflictWS.restoreStore.RestoreFromBundle(ctx, conflictWS.targetStores(), req)
	if !errors.Is(err, recovery.ErrManifestConsistency) {
		t.Fatalf("expected ErrManifestConsistency when existing sealed evidence conflicts, got %v", err)
	}
	if afterExistingSHA := hashFileHexC26(t, existingBlobPath); afterExistingSHA != beforeExistingSHA {
		t.Fatalf("existing sealed source bytes modified on rejected restore: got %s want %s", afterExistingSHA, beforeExistingSHA)
	}
}

func assertExpectedRecoveryErr(t *testing.T, got error, expectedName string) {
	t.Helper()
	var want error
	switch expectedName {
	case "ErrRestoreInterrupted":
		want = recovery.ErrRestoreInterrupted
	case "ErrDiskFull":
		want = recovery.ErrDiskFull
	case "ErrQuotaExceeded":
		want = recovery.ErrQuotaExceeded
	case "ErrRetryLimitExceeded":
		want = recovery.ErrRetryLimitExceeded
	case "ErrRestoreConflict":
		want = recovery.ErrRestoreConflict
	case "ErrLockBusy":
		want = recovery.ErrLockBusy
	case "ErrCustodyRewriteForbidden":
		want = recovery.ErrCustodyRewriteForbidden
	case "ErrBundleVerificationFailed":
		want = recovery.ErrBundleVerificationFailed
	case "ErrPathTraversal":
		want = recovery.ErrPathTraversal
	case "ErrSymlinkRejected":
		want = recovery.ErrSymlinkRejected
	case "ErrUnavailableProvider":
		want = recovery.ErrUnavailableProvider
	case "ErrManifestConsistency":
		want = recovery.ErrManifestConsistency
	default:
		t.Fatalf("unknown expected error %q", expectedName)
	}
	if !errors.Is(got, want) {
		t.Fatalf("expected error %v (%s), got %v", want, expectedName, got)
	}
}

func TestRestoreEdgeCasesAndConcurrentSafety(t *testing.T) {
	ctx := context.Background()
	fx := loadC26JSON[c26PositiveFixture](t, "positive/restore-case-consistency.json")

	srcWS := setupC26Workspace(t, true)
	seeded := seedCaseAndPackageBundleC26(t, srcWS, fx, fx.CaseID, fx.EvidenceID, fx.ArtifactID, fx.BundleID)
	conf := fx.SourceConfidence

	// 1. Untrusted checkpoint signer and untrusted derived artifact signer are rejected before any store mutation.
	untrustedWS := setupC26Workspace(t, true)
	_, roguePubHex := generateKeyPairHexC26(t)
	_, err := untrustedWS.restoreStore.RestoreFromBundle(ctx, untrustedWS.targetStores(), recovery.RestoreBundleRequest{
		SchemaVersion:          "1",
		OperationID:            "op-untrusted-chk",
		CaseID:                 fx.CaseID,
		BundlePath:             seeded.bundleDir,
		Provider:               fx.Provider,
		ZoneHint:               fx.ZoneHint,
		SourceConfidence:       &conf,
		TrustedBundleKeys:      map[string]string{fx.KeyIDBundle: seeded.bndPubHex},
		RequireBundleSignature: true,
		TrustedCheckpointKeys:  map[string]string{fx.KeyIDCheckpoint: roguePubHex},
		RequireCheckpointTrust: true,
	})
	if !errors.Is(err, recovery.ErrManifestConsistency) {
		t.Fatalf("expected ErrManifestConsistency on untrusted checkpoint key, got %v", err)
	}
	if _, gErr := untrustedWS.sealStore.GetSealedManifest(fx.CaseID, fx.EvidenceID); !os.IsNotExist(gErr) {
		t.Fatalf("untrusted checkpoint leaked into SealStore: %v", gErr)
	}

	rogueArtPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = untrustedWS.restoreStore.RestoreFromBundle(ctx, untrustedWS.targetStores(), recovery.RestoreBundleRequest{
		SchemaVersion:          "1",
		OperationID:            "op-untrusted-art",
		CaseID:                 fx.CaseID,
		BundlePath:             seeded.bundleDir,
		Provider:               fx.Provider,
		ZoneHint:               fx.ZoneHint,
		SourceConfidence:       &conf,
		TrustedBundleKeys:      map[string]string{fx.KeyIDBundle: seeded.bndPubHex},
		RequireBundleSignature: true,
		ArtifactVerifyOpts: artifacts.VerifyOptions{
			TrustedKeys:      map[string]ed25519.PublicKey{fx.KeyIDArtifact: rogueArtPub},
			RequireSignature: true,
		},
	})
	if !errors.Is(err, recovery.ErrManifestConsistency) {
		t.Fatalf("expected ErrManifestConsistency on untrusted artifact key, got %v", err)
	}

	// 2. Full store close/reopen restart durability after RestoreFromBundle.
	dstWS := setupC26Workspace(t, true)
	req := recovery.RestoreBundleRequest{
		SchemaVersion:          "1",
		OperationID:            "op-restart-durability",
		CaseID:                 fx.CaseID,
		BundlePath:             seeded.bundleDir,
		Provider:               fx.Provider,
		ZoneHint:               fx.ZoneHint,
		SourceConfidence:       &conf,
		TrustedBundleKeys:      map[string]string{fx.KeyIDBundle: seeded.bndPubHex},
		RequireBundleSignature: true,
		TrustedCheckpointKeys:  map[string]string{fx.KeyIDCheckpoint: seeded.chkPubHex},
		RequireCheckpointTrust: true,
		ArtifactVerifyOpts: artifacts.VerifyOptions{
			TrustedKeys:      map[string]ed25519.PublicKey{fx.KeyIDArtifact: seeded.artPub},
			RequireSignature: true,
		},
	}
	if _, err := dstWS.restoreStore.RestoreFromBundle(ctx, dstWS.targetStores(), req); err != nil {
		t.Fatalf("RestoreFromBundle: %v", err)
	}

	// Close ALL target stores and reopen from disk.
	_ = dstWS.sealStore.Close()
	_ = dstWS.ledgerStore.Close()
	_ = dstWS.checkpointStore.Close()
	_ = dstWS.artifactStore.Close()
	_ = dstWS.indexStore.Close()
	_ = dstWS.restoreStore.Close()

	reSeal, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: dstWS.sDir, QuarantineDir: dstWS.qDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen SealStore: %v", err)
	}
	defer func() { _ = reSeal.Close() }()
	reLedger, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: dstWS.custDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen LedgerStore: %v", err)
	}
	defer func() { _ = reLedger.Close() }()
	reChk, err := custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{RootDir: dstWS.chkDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen FileCheckpointStore: %v", err)
	}
	defer func() { _ = reChk.Close() }()
	reArt, err := artifacts.OpenArtifactStore(artifacts.StoreConfig{RootDir: dstWS.aDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen ArtifactStore: %v", err)
	}
	defer func() { _ = reArt.Close() }()
	reIdx, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: dstWS.idxDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen EventIndexStore: %v", err)
	}
	defer func() { _ = reIdx.Close() }()
	reRestore, err := recovery.OpenRestoreStore(recovery.RestoreConfig{RootDir: dstWS.recDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen RestoreStore: %v", err)
	}
	defer func() { _ = reRestore.Close() }()

	if vr, err := evidence.VerifyStoreEvidence(ctx, reSeal, fx.CaseID, fx.EvidenceID, evidence.VerifyOptions{}); err != nil || !vr.Verified {
		t.Fatalf("post-restart SealStore verification failed: %v", err)
	}
	if ok, err := reLedger.VerifyChain(fx.CaseID, fx.EvidenceID); err != nil || !ok {
		t.Fatalf("post-restart LedgerStore verification failed: %v", err)
	}
	if chk, err := reChk.GetLatestCheckpoint(ctx, fx.CaseID, fx.EvidenceID); err != nil {
		t.Fatalf("post-restart GetLatestCheckpoint: %v", err)
	} else if _, vErr := custody.VerifyCheckpoint(ctx, reLedger, *chk, custody.VerifyCheckpointOptions{
		TrustedPublicKeys: map[string]string{fx.KeyIDCheckpoint: seeded.chkPubHex},
	}); vErr != nil {
		t.Fatalf("post-restart VerifyCheckpoint: %v", vErr)
	}
	if sr, err := reIdx.Search(ctx, timeline.SearchRequest{SchemaVersion: "1", CaseID: fx.CaseID, Provider: fx.Provider}); err != nil || sr.ResultDigest != seeded.baselineSearch.ResultDigest {
		t.Fatalf("post-restart Search parity failed: err=%v digest=%v", err, sr)
	}

	// 3. Concurrent idempotent replays under -race serialize cleanly.
	reStores := recovery.TargetStores{
		SealStore:       reSeal,
		SealRootDir:     dstWS.sDir,
		QuarantineDir:   dstWS.qDir,
		LedgerStore:     reLedger,
		LedgerRootDir:   dstWS.custDir,
		CheckpointStore: reChk,
		ArtifactStore:   reArt,
		ArtifactRootDir: dstWS.aDir,
		IndexStore:      reIdx,
		IndexRootDir:    dstWS.idxDir,
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, rErr := reRestore.RestoreFromBundle(ctx, reStores, req)
			if rErr != nil {
				errs <- rErr
				return
			}
			if !out.IdempotentReplay || out.CustodyRewritten || out.SealedBytesModified {
				errs <- errors.New("unexpected concurrent replay result")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent replay failed: %v", e)
	}

	// 4. Append a post-seal custody event, completely remove idxDir, and verify VerifyAndRebuildCase still succeeds cleanly.
	if _, err := reLedger.AppendEvent(ctx, custody.AppendEventRequest{
		EventID:    "cust-post-seal-03",
		CaseID:     fx.CaseID,
		EvidenceID: fx.EvidenceID,
		EventType:  "analysis_review",
		Actor:      "custodian-ali",
		Timestamp:  "2026-11-02T01:00:00Z",
		Reason:     "Post-restore chain extension before local rebuild.",
	}); err != nil {
		t.Fatalf("append post-seal custody event: %v", err)
	}
	_ = reIdx.Close()
	if err := os.RemoveAll(dstWS.idxDir); err != nil {
		t.Fatal(err)
	}
	postSealRebuildStores := reStores
	postSealRebuildStores.IndexStore = nil
	rebuildOut, err := reRestore.VerifyAndRebuildCase(ctx, postSealRebuildStores, recovery.VerifyAndRebuildRequest{
		SchemaVersion:         "1",
		OperationID:           "op-post-seal-rebuild",
		CaseID:                fx.CaseID,
		Provider:              fx.Provider,
		ZoneHint:              fx.ZoneHint,
		SourceConfidence:      &conf,
		TrustedCheckpointKeys: map[string]string{fx.KeyIDCheckpoint: seeded.chkPubHex},
		RequireCheckpoints:    true,
	})
	if err != nil {
		t.Fatalf("VerifyAndRebuildCase after post-seal custody + wiped idxDir: %v", err)
	}
	if !rebuildOut.TimelineRebuilt || rebuildOut.RebuiltTimelineEntries != 3 || rebuildOut.CustodyRewritten || rebuildOut.SealedBytesModified {
		t.Fatalf("unexpected post-seal rebuild outcome: %+v", rebuildOut)
	}

	// 5. Bit-rot in sealed blob fails VerifyAndRebuildCase with ErrManifestConsistency.
	blobFile := filepath.Join(dstWS.sDir, "blobs", "sha256", seeded.blobSHA)
	blobRaw, err := os.ReadFile(blobFile)
	if err != nil {
		t.Fatal(err)
	}
	blobRaw[0] ^= 0x01
	if err := os.WriteFile(blobFile, blobRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reRestore.VerifyAndRebuildCase(ctx, postSealRebuildStores, recovery.VerifyAndRebuildRequest{
		SchemaVersion: "1",
		OperationID:   "op-bitrot-rebuild",
		CaseID:        fx.CaseID,
		Provider:      fx.Provider,
	}); !errors.Is(err, recovery.ErrManifestConsistency) {
		t.Fatalf("expected ErrManifestConsistency on sealed blob bit-rot, got %v", err)
	}
}

func generateKeyPairHexC26(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, hex.EncodeToString(pub)
}

func TestRestoreAdversarialBreakage(t *testing.T) {
	ctx := context.Background()
	fx := loadC26JSON[c26PositiveFixture](t, "positive/restore-case-consistency.json")
	conf := fx.SourceConfidence

	t.Run("corrupt_one_case_index_preserves_other_healthy_cases", func(t *testing.T) {
		ws := setupC26Workspace(t, true)
		seedCaseAndPackageBundleC26(t, ws, fx, "case-healthy-a", "ev-a", "art-a", "bnd-a")
		seedCaseAndPackageBundleC26(t, ws, fx, "case-corrupt-b", "ev-b", "art-b", "bnd-b")

		baselineA, err := ws.indexStore.Search(ctx, timeline.SearchRequest{
			SchemaVersion: "1",
			CaseID:        "case-healthy-a",
			Provider:      fx.Provider,
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = ws.indexStore.Close()

		corruptBPath := filepath.Join(ws.idxDir, "cases", "case-corrupt-b.index.json")
		if err := os.WriteFile(corruptBPath, []byte(`{"corrupted":true}`), 0o640); err != nil {
			t.Fatal(err)
		}

		stores := ws.targetStores()
		stores.IndexStore = nil
		if _, err := ws.restoreStore.VerifyAndRebuildCase(ctx, stores, recovery.VerifyAndRebuildRequest{
			SchemaVersion: "1",
			OperationID:   "op-repair-b",
			CaseID:        "case-corrupt-b",
			Provider:      fx.Provider,
			ZoneHint:      fx.ZoneHint,
		}); err != nil {
			t.Fatalf("VerifyAndRebuildCase(case-corrupt-b): %v", err)
		}

		reIdx, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: ws.idxDir, SyncDir: true})
		if err != nil {
			t.Fatalf("reopen EventIndexStore: %v", err)
		}
		defer func() { _ = reIdx.Close() }()
		ws.indexStore = reIdx

		afterA, err := reIdx.Search(ctx, timeline.SearchRequest{
			SchemaVersion: "1",
			CaseID:        "case-healthy-a",
			Provider:      fx.Provider,
		})
		if err != nil {
			t.Fatalf("healthy case-healthy-a was wiped during case-corrupt-b repair: %v", err)
		}
		if afterA.ResultDigest != baselineA.ResultDigest {
			t.Fatalf("case-healthy-a search digest changed: got %s want %s", afterA.ResultDigest, baselineA.ResultDigest)
		}
	})

	t.Run("detects_on_disk_custody_tampering_while_ledger_open", func(t *testing.T) {
		ws := setupC26Workspace(t, true)
		seeded := seedCaseAndPackageBundleC26(t, ws, fx, fx.CaseID, fx.EvidenceID, fx.ArtifactID, fx.BundleID)

		if err := os.WriteFile(seeded.custodyFile, []byte("{\"corrupt\":true}\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		_, err := ws.restoreStore.VerifyAndRebuildCase(ctx, ws.targetStores(), recovery.VerifyAndRebuildRequest{
			SchemaVersion: "1",
			OperationID:   "op-detect-disk-custody-tamper",
			CaseID:        fx.CaseID,
			Provider:      fx.Provider,
		})
		if !errors.Is(err, recovery.ErrManifestConsistency) {
			t.Fatalf("expected ErrManifestConsistency when custody .jsonl tampered on disk, got %v", err)
		}
	})

	t.Run("fingerprint_detects_trust_and_verify_opts_conflict", func(t *testing.T) {
		ws := setupC26Workspace(t, true)
		seeded := seedCaseAndPackageBundleC26(t, ws, fx, fx.CaseID, fx.EvidenceID, fx.ArtifactID, fx.BundleID)
		_, roguePubHex := generateKeyPairHexC26(t)

		if _, err := ws.restoreStore.VerifyAndRebuildCase(ctx, ws.targetStores(), recovery.VerifyAndRebuildRequest{
			SchemaVersion:         "1",
			OperationID:           "op-fp-rebuild",
			CaseID:                fx.CaseID,
			Provider:              fx.Provider,
			ZoneHint:              fx.ZoneHint,
			TrustedCheckpointKeys: map[string]string{fx.KeyIDCheckpoint: seeded.chkPubHex},
			RequireCheckpoints:    true,
		}); err != nil {
			t.Fatal(err)
		}
		_, err := ws.restoreStore.VerifyAndRebuildCase(ctx, ws.targetStores(), recovery.VerifyAndRebuildRequest{
			SchemaVersion:         "1",
			OperationID:           "op-fp-rebuild",
			CaseID:                fx.CaseID,
			Provider:              fx.Provider,
			ZoneHint:              fx.ZoneHint,
			TrustedCheckpointKeys: map[string]string{fx.KeyIDCheckpoint: roguePubHex},
			RequireCheckpoints:    true,
		})
		if !errors.Is(err, recovery.ErrRestoreConflict) {
			t.Fatalf("expected ErrRestoreConflict on different TrustedCheckpointKeys, got %v", err)
		}

		dstWS := setupC26Workspace(t, true)
		if _, err := dstWS.restoreStore.RestoreFromBundle(ctx, dstWS.targetStores(), recovery.RestoreBundleRequest{
			SchemaVersion:          "1",
			OperationID:            "op-fp-bundle",
			CaseID:                 fx.CaseID,
			BundlePath:             seeded.bundleDir,
			Provider:               fx.Provider,
			ZoneHint:               fx.ZoneHint,
			SourceConfidence:       &conf,
			TrustedBundleKeys:      map[string]string{fx.KeyIDBundle: seeded.bndPubHex},
			RequireBundleSignature: true,
			ArtifactVerifyOpts: artifacts.VerifyOptions{
				TrustedKeys:      map[string]ed25519.PublicKey{fx.KeyIDArtifact: seeded.artPub},
				RequireSignature: true,
			},
		}); err != nil {
			t.Fatal(err)
		}
		_, err = dstWS.restoreStore.RestoreFromBundle(ctx, dstWS.targetStores(), recovery.RestoreBundleRequest{
			SchemaVersion:          "1",
			OperationID:            "op-fp-bundle",
			CaseID:                 fx.CaseID,
			BundlePath:             seeded.bundleDir,
			Provider:               fx.Provider,
			ZoneHint:               fx.ZoneHint,
			SourceConfidence:       &conf,
			TrustedBundleKeys:      map[string]string{fx.KeyIDBundle: seeded.bndPubHex},
			RequireBundleSignature: true,
			ArtifactVerifyOpts: artifacts.VerifyOptions{
				RequireSignature: false,
			},
		})
		if !errors.Is(err, recovery.ErrRestoreConflict) {
			t.Fatalf("expected ErrRestoreConflict on different ArtifactVerifyOpts, got %v", err)
		}
	})

	t.Run("restore_verified_artifact_rejects_non_artifact_relpath", func(t *testing.T) {
		ws := setupC26Workspace(t, true)
		seedCaseAndPackageBundleC26(t, ws, fx, fx.CaseID, fx.EvidenceID, fx.ArtifactID, fx.BundleID)
		sm, err := ws.sealStore.GetSealedManifest(fx.CaseID, fx.EvidenceID)
		if err != nil {
			t.Fatal(err)
		}

		payload := artifacts.DerivedPayload{
			SchemaVersion: artifacts.SchemaVersion,
			CaseID:        fx.CaseID,
			EvidenceID:    fx.EvidenceID,
			ArtifactID:    "art-evil-relpath",
			AnalyzerID:    analyzers.AnalyzerJSON,
			ToolVersion:   "breachatlas-analyzer-json/1.0.0",
			ConfigHash:    strings.Repeat("a", 64),
			InputHashes:   []string{sm.SHA256},
			AnalyzedAt:    "2026-11-01T08:00:00Z",
			RecordCount:   1,
			Records:       []analyzers.ParsedRecord{{RowNumber: 1, Timestamp: "2026-11-01T05:30:00Z"}},
		}
		payloadBytes, _ := json.MarshalIndent(payload, "", "  ")
		payloadBytes = append(payloadBytes, '\n')
		sum := sha256.Sum256(payloadBytes)

		m := artifacts.DerivedManifest{
			SchemaVersion: artifacts.SchemaVersion,
			ArtifactID:    "art-evil-relpath",
			CaseID:        fx.CaseID,
			Inputs: []artifacts.InputBinding{{
				CaseID:      sm.CaseID,
				EvidenceID:  sm.EvidenceID,
				SHA256:      sm.SHA256,
				SizeBytes:   sm.SizeBytes,
				MediaType:   sm.MediaType,
				CustodyRoot: sm.CustodyRoot,
			}},
			InputHashes:  []string{sm.SHA256},
			AnalyzerID:   analyzers.AnalyzerJSON,
			ToolVersion:  "breachatlas-analyzer-json/1.0.0",
			Provider:     "local",
			ConfigHash:   strings.Repeat("a", 64),
			NonExecuting: true,
			ReadOnly:     true,
			Output: artifacts.OutputBinding{
				ArtifactID:  "art-evil-relpath",
				MediaType:   artifacts.DefaultOutputMediaType,
				SHA256:      hex.EncodeToString(sum[:]),
				SizeBytes:   int64(len(payloadBytes)),
				RecordCount: 1,
				RelPath:     "artifact-index.json",
			},
			CreatedAt: "2026-11-01T08:00:00Z",
		}
		m.ManifestDigest, err = artifacts.ComputeManifestDigest(m)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ws.artifactStore.RestoreVerifiedArtifact(ctx, ws.sealStore, m, payloadBytes, artifacts.VerifyOptions{})
		if err == nil {
			t.Fatalf("expected RestoreVerifiedArtifact to reject Output.RelPath targeting artifact-index.json")
		}
	})

	t.Run("bundle_checkpoint_or_timeline_mismatch_leaves_zero_partial_writes", func(t *testing.T) {
		srcWS := setupC26Workspace(t, false)
		seeded := seedCaseAndPackageBundleC26(t, srcWS, fx, fx.CaseID, fx.EvidenceID, fx.ArtifactID, fx.BundleID)

		// Corrupt bundle timeline.json raw_timestamp and re-compute unsigned BundleDigest + FileChecksums.
		badDir := filepath.Join(t.TempDir(), "bundle-bad-timeline")
		copyDirRecursiveC26(t, seeded.bundleDir, badDir)
		bmRaw, err := os.ReadFile(filepath.Join(badDir, export.BundleManifestFile))
		if err != nil {
			t.Fatal(err)
		}
		var bm export.BundleManifest
		if err := json.Unmarshal(bmRaw, &bm); err != nil {
			t.Fatal(err)
		}
		tlPath := filepath.Join(badDir, filepath.FromSlash(bm.TimelineRelPath))
		tlRaw, err := os.ReadFile(tlPath)
		if err != nil {
			t.Fatal(err)
		}
		var tlEntries []timeline.TimelineEntry
		if err := json.Unmarshal(tlRaw, &tlEntries); err != nil {
			t.Fatal(err)
		}
		tlEntries[0].Time.RawTimestamp = "2026-11-01T99:99:99Z"
		modTL, _ := json.MarshalIndent(tlEntries, "", "  ")
		if err := os.WriteFile(tlPath, modTL, 0o640); err != nil {
			t.Fatal(err)
		}
		tlSum := sha256.Sum256(modTL)
		bm.FileChecksums[bm.TimelineRelPath] = hex.EncodeToString(tlSum[:])
		bm.TimelineSHA256 = hex.EncodeToString(tlSum[:])
		bm.Signed = false
		bm.KeyID = ""
		bm.PublicKey = ""
		bm.Signature = ""
		bm.BundleDigest, err = export.ComputeBundleDigest(bm)
		if err != nil {
			t.Fatal(err)
		}
		newBMRaw, _ := json.MarshalIndent(bm, "", "  ")
		if err := os.WriteFile(filepath.Join(badDir, export.BundleManifestFile), newBMRaw, 0o640); err != nil {
			t.Fatal(err)
		}

		dstWS := setupC26Workspace(t, true)
		_, err = dstWS.restoreStore.RestoreFromBundle(ctx, dstWS.targetStores(), recovery.RestoreBundleRequest{
			SchemaVersion:    "1",
			OperationID:      "op-bad-timeline-precheck",
			CaseID:           fx.CaseID,
			BundlePath:       badDir,
			Provider:         fx.Provider,
			ZoneHint:         fx.ZoneHint,
			SourceConfidence: &conf,
		})
		if !errors.Is(err, recovery.ErrManifestConsistency) {
			t.Fatalf("expected ErrManifestConsistency on timeline mismatch, got %v", err)
		}
		if _, gErr := dstWS.sealStore.GetSealedManifest(fx.CaseID, fx.EvidenceID); !os.IsNotExist(gErr) {
			t.Fatalf("failed RestoreFromBundle left partial SealStore state: %v", gErr)
		}
		if evs, _ := dstWS.ledgerStore.ListEvents(fx.CaseID, fx.EvidenceID); len(evs) != 0 {
			t.Fatalf("failed RestoreFromBundle left partial LedgerStore state: %d events", len(evs))
		}
	})

	t.Run("corrupt_restore_manifest_fails_closed_on_open", func(t *testing.T) {
		recDir := filepath.Join(t.TempDir(), "recovery")
		rs, err := recovery.OpenRestoreStore(recovery.RestoreConfig{RootDir: recDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		_ = rs.Close()

		if err := os.WriteFile(filepath.Join(recDir, "restore-manifest.json"), []byte("{not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := recovery.OpenRestoreStore(recovery.RestoreConfig{RootDir: recDir, SyncDir: true}); !errors.Is(err, recovery.ErrManifestConsistency) {
			t.Fatalf("expected ErrManifestConsistency on corrupt restore-manifest.json, got %v", err)
		}
	})

	t.Run("missing_disk_custody_detected_by_restore_verified_chain_and_rebuild", func(t *testing.T) {
		ws := setupC26Workspace(t, true)
		seeded := seedCaseAndPackageBundleC26(t, ws, fx, fx.CaseID, fx.EvidenceID, fx.ArtifactID, fx.BundleID)
		events, err := ws.ledgerStore.ListEvents(fx.CaseID, fx.EvidenceID)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(seeded.custodyFile); err != nil {
			t.Fatal(err)
		}
		if err := ws.ledgerStore.RestoreVerifiedChain(ctx, fx.CaseID, fx.EvidenceID, events); !errors.Is(err, custody.ErrImmutableHistory) {
			t.Fatalf("expected ErrImmutableHistory when on-disk custody file missing for loaded chain, got %v", err)
		}
		if _, err := ws.restoreStore.VerifyAndRebuildCase(ctx, ws.targetStores(), recovery.VerifyAndRebuildRequest{
			SchemaVersion: "1",
			OperationID:   "op-missing-custody-disk",
			CaseID:        fx.CaseID,
			Provider:      fx.Provider,
		}); !errors.Is(err, recovery.ErrManifestConsistency) {
			t.Fatalf("expected ErrManifestConsistency when on-disk custody file missing, got %v", err)
		}
	})

	t.Run("multi_evidence_partial_overlap_restore_preserves_existing_and_imports_missing", func(t *testing.T) {
		srcWS := setupC26Workspace(t, false)
		caseID := "case-multi-overlap"
		ev1 := "ev-overlap-01"
		ev2 := "ev-overlap-02"
		art1 := "art-overlap-01"

		// Helper to seed evidence + custody + checkpoint on a workspace.
		seedEv := func(ws *c26Workspace, evID string, payload string, chkPriv ed25519.PrivateKey) (string, string) {
			raw := []byte(payload)
			sum := sha256.Sum256(raw)
			shaHex := hex.EncodeToString(sum[:])
			sz := int64(len(raw))
			q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{QuarantineDir: ws.qDir, SyncDir: true}, evidence.UploadRequest{
				SchemaVersion: "1",
				UploadID:      "upl-" + evID,
				CaseID:        caseID,
				EvidenceID:    evID,
				MediaType:     "application/json",
				Filename:      evID + ".jsonl",
				ExpectedSize:  &sz,
				Body:          strings.NewReader(payload),
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, cev := range fx.CustodyEvents {
				if _, err := ws.ledgerStore.AppendEvent(ctx, custody.AppendEventRequest{
					EventID:       cev.EventID + "-" + evID,
					CaseID:        caseID,
					EvidenceID:    evID,
					EventType:     cev.EventType,
					Actor:         cev.Actor,
					Timestamp:     cev.Timestamp,
					Reason:        cev.Reason,
					FromCustodian: cev.FromCustodian,
					ToCustodian:   cev.ToCustodian,
				}); err != nil {
					t.Fatal(err)
				}
			}
			curRoot, err := ws.ledgerStore.CurrentRoot(caseID, evID)
			if err != nil {
				t.Fatal(err)
			}
			sm, err := ws.sealStore.SealQuarantined(ctx, evidence.SealRequest{
				OperationID:    "seal-" + evID,
				Quarantined:    q,
				ExpectedSHA256: shaHex,
				AcquiredAt:     "2026-11-01T07:00:00Z",
				CustodyRoot:    curRoot,
			})
			if err != nil {
				t.Fatal(err)
			}
			chk, err := custody.CreateCheckpoint(ctx, ws.ledgerStore, custody.CreateCheckpointRequest{
				CheckpointID: "chk-" + evID,
				CaseID:       caseID,
				EvidenceID:   evID,
				Sequence:     uint64(len(fx.CustodyEvents)),
				CustodyRoot:  curRoot,
				KeyID:        fx.KeyIDCheckpoint,
				Revision:     1,
				IssuedAt:     "2026-11-01T08:00:00Z",
				ExpiresAt:    "2030-11-01T08:00:00Z",
				PrivateKey:   chkPriv,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := ws.checkpointStore.SaveCheckpoint(ctx, *chk); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(ws.sDir, filepath.FromSlash(sm.BlobRelPath)), filepath.Join(ws.ledgerStore.CustodyDir(), caseID, evID+".jsonl")
		}

		chkPub, chkPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		chkPubHex := hex.EncodeToString(chkPub)
		seedEv(srcWS, ev1, fx.PayloadJSONL, chkPriv)
		payload2 := "{\"timestamp\":\"2026-11-01T09:00:00Z\",\"event_type\":\"network_conn\",\"summary\":\"Second evidence item\"}\n"
		seedEv(srcWS, ev2, payload2, chkPriv)

		runRes, err := srcWS.sandbox.RunIsolated(ctx, analyzers.IsolatedRunRequest{
			RunID:      "run-" + art1,
			CaseID:     caseID,
			EvidenceID: ev1,
			AnalyzerID: analyzers.AnalyzerJSON,
			Provider:   fx.Provider,
			Options:    analyzers.DefaultParseOptions(),
		})
		if err != nil {
			t.Fatal(err)
		}
		artPub, artPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := srcWS.artifactStore.DeriveFromIsolatedRun(ctx, srcWS.sealStore, srcWS.sDir, runRes, artifacts.DeriveRequest{
			OperationID: "drv-" + art1,
			CaseID:      caseID,
			ArtifactID:  art1,
			Provider:    fx.Provider,
			KeyID:       fx.KeyIDArtifact,
			PrivateKey:  artPriv,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := srcWS.indexStore.IndexDerivedArtifact(ctx, srcWS.sealStore, srcWS.sDir, srcWS.artifactStore, srcWS.aDir, timeline.IndexDerivedRequest{
			SchemaVersion:    "1",
			OperationID:      "idx-" + art1,
			CaseID:           caseID,
			ArtifactID:       art1,
			Provider:         fx.Provider,
			ZoneHint:         fx.ZoneHint,
			SourceConfidence: &conf,
			VerifyOptions: artifacts.VerifyOptions{
				TrustedKeys:      map[string]ed25519.PublicKey{fx.KeyIDArtifact: artPub},
				RequireSignature: true,
			},
		}); err != nil {
			t.Fatal(err)
		}
		bndPub, bndPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		expOut, err := srcWS.exportStore.PackageCaseBundle(ctx, export.ExportDeps{
			SealStore:       srcWS.sealStore,
			SealRootDir:     srcWS.sDir,
			LedgerStore:     srcWS.ledgerStore,
			CheckpointStore: srcWS.checkpointStore,
			CheckpointOpts: custody.VerifyCheckpointOptions{
				TrustedPublicKeys: map[string]string{fx.KeyIDCheckpoint: chkPubHex},
			},
			ArtifactStore:   srcWS.artifactStore,
			ArtifactRootDir: srcWS.aDir,
			IndexStore:      srcWS.indexStore,
		}, export.ExportRequest{
			SchemaVersion:   "1",
			OperationID:     "exp-overlap",
			BundleID:        "bnd-overlap",
			CaseID:          caseID,
			Provider:        fx.Provider,
			EvidenceIDs:     []string{ev1, ev2},
			ArtifactIDs:     []string{art1},
			IncludeTimeline: true,
			KeyID:           fx.KeyIDBundle,
			PrivateKey:      bndPriv,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Target workspace already has ev1 sealed and custodied locally, but lacks ev2 and art1.
		dstWS := setupC26Workspace(t, true)
		existingBlobPath, existingCustPath := seedEv(dstWS, ev1, fx.PayloadJSONL, chkPriv)
		preBlobSHA := hashFileHexC26(t, existingBlobPath)
		preCustSHA := hashFileHexC26(t, existingCustPath)

		out, err := dstWS.restoreStore.RestoreFromBundle(ctx, dstWS.targetStores(), recovery.RestoreBundleRequest{
			SchemaVersion:          "1",
			OperationID:            "op-partial-overlap",
			CaseID:                 caseID,
			BundlePath:             expOut.BundleDir,
			Provider:               fx.Provider,
			ZoneHint:               fx.ZoneHint,
			SourceConfidence:       &conf,
			TrustedBundleKeys:      map[string]string{fx.KeyIDBundle: hex.EncodeToString(bndPub)},
			RequireBundleSignature: true,
			TrustedCheckpointKeys:  map[string]string{fx.KeyIDCheckpoint: chkPubHex},
			RequireCheckpointTrust: true,
			ArtifactVerifyOpts: artifacts.VerifyOptions{
				TrustedKeys:      map[string]ed25519.PublicKey{fx.KeyIDArtifact: artPub},
				RequireSignature: true,
			},
		})
		if err != nil {
			t.Fatalf("partial-overlap RestoreFromBundle failed: %v", err)
		}
		if out.ExistingEvidenceCount != 1 || out.RestoredEvidenceCount != 1 || out.CustodyRewritten || out.SealedBytesModified {
			t.Fatalf("unexpected partial-overlap outcome: %+v", out)
		}
		if hashFileHexC26(t, existingBlobPath) != preBlobSHA || hashFileHexC26(t, existingCustPath) != preCustSHA {
			t.Fatalf("existing evidence blob or custody rewritten during partial-overlap restore")
		}
		if vr, err := evidence.VerifyStoreEvidence(ctx, dstWS.sealStore, caseID, ev2, evidence.VerifyOptions{}); err != nil || !vr.Verified {
			t.Fatalf("missing ev2 not sealed cleanly: %v", err)
		}
	})

	t.Run("duplicate_evidence_id_in_bundle_rejected_cleanly", func(t *testing.T) {
		srcWS := setupC26Workspace(t, false)
		seeded := seedCaseAndPackageBundleC26(t, srcWS, fx, fx.CaseID, fx.EvidenceID, fx.ArtifactID, fx.BundleID)
		badDir := filepath.Join(t.TempDir(), "bundle-dup-ev")
		copyDirRecursiveC26(t, seeded.bundleDir, badDir)

		bmRaw, err := os.ReadFile(filepath.Join(badDir, export.BundleManifestFile))
		if err != nil {
			t.Fatal(err)
		}
		var bm export.BundleManifest
		if err := json.Unmarshal(bmRaw, &bm); err != nil {
			t.Fatal(err)
		}
		bm.EvidenceItems = append(bm.EvidenceItems, bm.EvidenceItems[0])
		bm.Signed = false
		bm.KeyID = ""
		bm.PublicKey = ""
		bm.Signature = ""
		bm.BundleDigest, err = export.ComputeBundleDigest(bm)
		if err != nil {
			t.Fatal(err)
		}
		newBMRaw, _ := json.MarshalIndent(bm, "", "  ")
		if err := os.WriteFile(filepath.Join(badDir, export.BundleManifestFile), newBMRaw, 0o640); err != nil {
			t.Fatal(err)
		}

		dstWS := setupC26Workspace(t, true)
		if _, err := dstWS.restoreStore.RestoreFromBundle(ctx, dstWS.targetStores(), recovery.RestoreBundleRequest{
			SchemaVersion:    "1",
			OperationID:      "op-dup-ev",
			CaseID:           fx.CaseID,
			BundlePath:       badDir,
			Provider:         fx.Provider,
			ZoneHint:         fx.ZoneHint,
			SourceConfidence: &conf,
		}); !errors.Is(err, recovery.ErrManifestConsistency) {
			t.Fatalf("expected ErrManifestConsistency on duplicate evidence_id, got %v", err)
		}
	})
}



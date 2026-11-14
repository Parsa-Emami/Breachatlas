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
	"path/filepath"
	"strings"
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

type c30Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c30WorkflowInput struct {
	SchemaVersion    string  `json:"schema_version"`
	CaseID           string  `json:"case_id"`
	EvidenceID       string  `json:"evidence_id"`
	ArtifactID       string  `json:"artifact_id"`
	BundleID         string  `json:"bundle_id"`
	HoldID           string  `json:"hold_id"`
	Filename         string  `json:"filename"`
	MediaType        string  `json:"media_type"`
	Provider         string  `json:"provider"`
	ZoneHint         string  `json:"zone_hint"`
	SourceConfidence float64 `json:"source_confidence"`
	AcquiredAt       string  `json:"acquired_at"`
	Actor            string  `json:"actor"`
	CustodyReason    string  `json:"custody_reason"`
	HoldReason       string  `json:"hold_reason"`
	PayloadJSONL     string  `json:"payload_jsonl"`
}

type c30ExpectedOutcomes struct {
	SchemaVersion            string  `json:"schema_version"`
	TimelineCount            int     `json:"timeline_count"`
	PreservedRawTimestamp    string  `json:"preserved_raw_timestamp"`
	PreservedTimezoneOffset  string  `json:"preserved_timezone_offset"`
	PreservedConfidence      float64 `json:"preserved_confidence"`
	HoldActive               bool    `json:"hold_active"`
	SealedBytesModified      bool    `json:"sealed_bytes_modified"`
	CustodyRewritten         bool    `json:"custody_rewritten"`
	OfflineVerifiedNoServer  bool    `json:"offline_verified_without_server"`
}

func getC30FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		cand := filepath.Join(dir, "tests", "fixtures", "breachatlas", "C30")
		if info, err := os.Stat(cand); err == nil && info.IsDir() {
			return cand
		}
	}
	t.Fatalf("could not locate C30 fixtures dir from %s", wd)
	return ""
}

func TestC30FixturesAndFullWorkflowRestartRestore(t *testing.T) {
	ctx := context.Background()
	fxDir := getC30FixturesDir(t)

	provRaw, err := os.ReadFile(filepath.Join(fxDir, "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var prov c30Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatal(err)
	}
	if prov.Task != "C30" || prov.License != "Apache-2.0" || len(prov.SHA256) < 3 {
		t.Fatalf("invalid C30 provenance metadata: %+v", prov)
	}
	for rel, expected := range prov.SHA256 {
		data, err := os.ReadFile(filepath.Join(fxDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != expected {
			t.Fatalf("fixture checksum mismatch for %s", rel)
		}
	}

	var input c30WorkflowInput
	rawIn, _ := os.ReadFile(filepath.Join(fxDir, "positive", "workflow-input.json"))
	if err := json.Unmarshal(rawIn, &input); err != nil {
		t.Fatal(err)
	}
	var expected c30ExpectedOutcomes
	rawOut, _ := os.ReadFile(filepath.Join(fxDir, "expected-output", "acceptance-outcomes.json"))
	if err := json.Unmarshal(rawOut, &expected); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	openStores := func() (
		*evidence.SealStore,
		*custody.LedgerStore,
		*custody.FileCheckpointStore,
		*analyzers.Sandbox,
		*artifacts.ArtifactStore,
		*timeline.EventIndexStore,
		*findings.FindingStore,
		*export.ExportStore,
		*holds.Service,
		*retention.RetentionStore,
		*recovery.RestoreStore,
		func(),
	) {
		qDir := filepath.Join(root, "quarantine")
		sDir := filepath.Join(root, "sealstore")
		cDir := filepath.Join(root, "custody")
		kDir := filepath.Join(root, "checkpoints")
		scDir := filepath.Join(root, "scratch")
		aDir := filepath.Join(root, "artifacts")
		iDir := filepath.Join(root, "timeline-index")
		fDir := filepath.Join(root, "findings")
		eDir := filepath.Join(root, "exports")
		hDir := filepath.Join(root, "holds")
		rtDir := filepath.Join(root, "retention")
		rcDir := filepath.Join(root, "recovery")

		ss, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		ls, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: cDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		cs, err := custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{RootDir: kDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		reg, err := analyzers.NewRegistry(analyzers.RegistryConfig{SealStore: ss, SealRootDir: sDir, Provider: "local"})
		if err != nil {
			t.Fatal(err)
		}
		sbx, err := analyzers.NewSandbox(reg, analyzers.DefaultSandboxConfig(scDir))
		if err != nil {
			t.Fatal(err)
		}
		as, err := artifacts.OpenArtifactStore(artifacts.StoreConfig{RootDir: aDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		ix, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: iDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		fs, err := findings.OpenFindingStore(findings.FindingStoreConfig{RootDir: fDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		es, err := export.OpenExportStore(export.ExportStoreConfig{RootDir: eDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		hs, err := holds.OpenService(holds.ServiceConfig{RootDir: hDir, SealStore: ss, Ledger: ls, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		rt, err := retention.OpenRetentionStore(retention.RetentionConfig{RootDir: rtDir, SealStore: ss, HoldService: hs, LedgerStore: ls, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		rc, err := recovery.OpenRestoreStore(recovery.RestoreConfig{RootDir: rcDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		closeAll := func() {
			_ = rc.Close()
			_ = rt.Close()
			_ = hs.Close()
			_ = es.Close()
			_ = fs.Close()
			_ = ix.Close()
			_ = as.Close()
			_ = cs.Close()
			_ = ls.Close()
			_ = ss.Close()
		}
		return ss, ls, cs, sbx, as, ix, fs, es, hs, rt, rc, closeAll
	}

	ss, ls, cs, sbx, as, ix, fs, es, hs, rt, _, closeRun1 := openStores()

	payloadBytes := []byte(input.PayloadJSONL)
	sum := sha256.Sum256(payloadBytes)
	expectedSHA := hex.EncodeToString(sum[:])
	sz := int64(len(payloadBytes))

	q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{QuarantineDir: filepath.Join(root, "quarantine"), SyncDir: true}, evidence.UploadRequest{
		SchemaVersion:  "1",
		UploadID:       "upl-c30-01",
		CaseID:         input.CaseID,
		EvidenceID:     input.EvidenceID,
		MediaType:      input.MediaType,
		Filename:       input.Filename,
		ExpectedSize:   &sz,
		ExpectedSHA256: expectedSHA,
		Body:           bytes.NewReader(payloadBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ls.AppendEvent(ctx, custody.AppendEventRequest{
		EventID:    "cust-c30-01",
		CaseID:     input.CaseID,
		EvidenceID: input.EvidenceID,
		EventType:  "intake_seal",
		Actor:      input.Actor,
		Timestamp:  input.AcquiredAt,
		Reason:     input.CustodyReason,
		Provider:   input.Provider,
	}); err != nil {
		t.Fatal(err)
	}
	curRoot, _ := ls.CurrentRoot(input.CaseID, input.EvidenceID)
	sm, err := ss.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "seal-c30-01",
		Quarantined:    q,
		ExpectedSHA256: expectedSHA,
		AcquiredAt:     input.AcquiredAt,
		CustodyRoot:    curRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Append post-seal custody transfer & checkpoint
	if _, err := ls.AppendEvent(ctx, custody.AppendEventRequest{
		EventID:    "cust-c30-02",
		CaseID:     input.CaseID,
		EvidenceID: input.EvidenceID,
		EventType:  "custody_transfer",
		Actor:      input.Actor,
		Timestamp:  "2026-11-14T08:10:00+03:30",
		Reason:     "Post-seal handoff to analyzer",
		Provider:   input.Provider,
	}); err != nil {
		t.Fatal(err)
	}

	// Timeline analysis & index
	runRes, err := sbx.RunIsolated(ctx, analyzers.IsolatedRunRequest{
		RunID:      "run-c30-01",
		CaseID:     input.CaseID,
		EvidenceID: input.EvidenceID,
		AnalyzerID: analyzers.AnalyzerJSON,
		Provider:   input.Provider,
		Options:    analyzers.DefaultParseOptions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	artPub, artPriv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := as.DeriveFromIsolatedRun(ctx, ss, filepath.Join(root, "sealstore"), runRes, artifacts.DeriveRequest{
		OperationID: "drv-c30-01",
		CaseID:      input.CaseID,
		ArtifactID:  input.ArtifactID,
		Provider:    input.Provider,
		KeyID:       "art-key-1",
		PrivateKey:  artPriv,
	}); err != nil {
		t.Fatal(err)
	}
	conf := input.SourceConfidence
	if _, err := ix.IndexDerivedArtifact(ctx, ss, filepath.Join(root, "sealstore"), as, filepath.Join(root, "artifacts"), timeline.IndexDerivedRequest{
		SchemaVersion:    "1",
		OperationID:      "idx-c30-01",
		CaseID:           input.CaseID,
		ArtifactID:       input.ArtifactID,
		Provider:         input.Provider,
		ZoneHint:         input.ZoneHint,
		SourceConfidence: &conf,
		VerifyOptions: artifacts.VerifyOptions{
			TrustedKeys:      map[string]ed25519.PublicKey{"art-key-1": artPub},
			RequireSignature: true,
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Place hold & reject delete/expire
	if _, err := hs.PlaceHold(ctx, holds.PlaceHoldRequest{
		HoldID:     input.HoldID,
		CaseID:     input.CaseID,
		EvidenceID: input.EvidenceID,
		Actor:      "legal-counsel",
		Timestamp:  "2026-11-14T08:15:00+03:30",
		Reason:     input.HoldReason,
		Provider:   input.Provider,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := hs.DeleteEvidence(ctx, holds.DisposalRequest{
		CaseID:     input.CaseID,
		EvidenceID: input.EvidenceID,
		Actor:      "ops",
		Timestamp:  "2026-11-14T08:16:00+03:30",
		Reason:     "test delete",
		Provider:   input.Provider,
	}); !errors.Is(err, holds.ErrHoldActive) {
		t.Fatalf("expected ErrHoldActive on delete, got %v", err)
	}

	// Save latest checkpoint and export signed bundle
	chkPub, chkPriv, _ := ed25519.GenerateKey(rand.Reader)
	chkPubHex := hex.EncodeToString(chkPub)
	evList, _ := ls.ListEvents(input.CaseID, input.EvidenceID)
	lastEv := evList[len(evList)-1]
	chk, err := custody.CreateCheckpoint(ctx, ls, custody.CreateCheckpointRequest{
		CheckpointID: "chk-c30-01",
		CaseID:       input.CaseID,
		EvidenceID:   input.EvidenceID,
		Sequence:     lastEv.Sequence,
		CustodyRoot:  lastEv.CustodyRoot,
		KeyID:        "chk-key-1",
		Revision:     1,
		IssuedAt:     time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		PrivateKey:   chkPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.SaveCheckpoint(ctx, *chk); err != nil {
		t.Fatal(err)
	}

	bndPub, bndPriv, _ := ed25519.GenerateKey(rand.Reader)
	bndPubHex := hex.EncodeToString(bndPub)
	expOut, err := es.PackageCaseBundle(ctx, export.ExportDeps{
		SealStore:       ss,
		SealRootDir:     filepath.Join(root, "sealstore"),
		LedgerStore:     ls,
		CheckpointStore: cs,
		CheckpointOpts:  custody.VerifyCheckpointOptions{TrustedPublicKeys: map[string]string{"chk-key-1": chkPubHex}},
		ArtifactStore:   as,
		ArtifactRootDir: filepath.Join(root, "artifacts"),
		IndexStore:      ix,
		FindingStore:    fs,
	}, export.ExportRequest{
		SchemaVersion:   "1",
		OperationID:     "exp-c30-01",
		BundleID:        input.BundleID,
		CaseID:          input.CaseID,
		Provider:        input.Provider,
		EvidenceIDs:     []string{input.EvidenceID},
		ArtifactIDs:     []string{input.ArtifactID},
		IncludeTimeline: true,
		KeyID:           "bnd-key-1",
		PrivateKey:      bndPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = rt

	// Close stores and verify offline without server
	closeRun1()

	verRes, err := export.VerifyBundle(ctx, expOut.BundleDir, export.VerifyBundleOptions{
		TrustedPublicKeys: map[string]string{"bnd-key-1": bndPubHex},
		RequireSignature:  true,
	})
	if err != nil || !verRes.Verified || verRes.RequiresServer != expected.OfflineVerifiedNoServer && verRes.RequiresServer {
		t.Fatalf("offline verification failed: res=%+v err=%v", verRes, err)
	}

	// Simulate derived timeline index removal across restart and reopen stores
	_ = os.RemoveAll(filepath.Join(root, "timeline-index", "cases", input.CaseID+".json"))
	ss2, ls2, cs2, _, as2, ix2, _, _, hs2, rt2, rc2, closeRun2 := openStores()
	defer closeRun2()

	rebuildOut, err := rc2.VerifyAndRebuildCase(ctx, recovery.TargetStores{
		SealStore:       ss2,
		SealRootDir:     filepath.Join(root, "sealstore"),
		QuarantineDir:   filepath.Join(root, "quarantine"),
		LedgerStore:     ls2,
		LedgerRootDir:   filepath.Join(root, "custody"),
		CheckpointStore: cs2,
		ArtifactStore:   as2,
		ArtifactRootDir: filepath.Join(root, "artifacts"),
		IndexStore:      ix2,
		IndexRootDir:    filepath.Join(root, "timeline-index"),
		HoldService:     hs2,
		RetentionStore:  rt2,
	}, recovery.VerifyAndRebuildRequest{
		SchemaVersion:         "1",
		OperationID:           "reb-c30-01",
		CaseID:                input.CaseID,
		Provider:              input.Provider,
		ZoneHint:              input.ZoneHint,
		TrustedCheckpointKeys: map[string]string{"chk-key-1": chkPubHex},
		RequireCheckpoints:    true,
		ArtifactVerifyOpts: artifacts.VerifyOptions{
			TrustedKeys:      map[string]ed25519.PublicKey{"art-key-1": artPub},
			RequireSignature: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rebuildOut.SealedBytesModified != expected.SealedBytesModified ||
		rebuildOut.CustodyRewritten != expected.CustodyRewritten ||
		rebuildOut.RebuiltTimelineEntries != expected.TimelineCount {
		t.Fatalf("unexpected rebuild outcome: %+v", rebuildOut)
	}

	// Sealed bytes immutability check after restart + recovery
	sealedPath := filepath.Join(root, "sealstore", filepath.FromSlash(sm.BlobRelPath))
	onDiskBytes, err := os.ReadFile(sealedPath)
	if err != nil || !bytes.Equal(onDiskBytes, payloadBytes) || !strings.Contains(string(onDiskBytes), expected.PreservedRawTimestamp) {
		t.Fatalf("sealed source bytes altered after workflow+restart+recovery")
	}
}

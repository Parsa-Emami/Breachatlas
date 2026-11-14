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

type c33Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

func TestC33UXWorkflowNegativeCasesAndNMinusOneCompatibility(t *testing.T) {
	ctx := context.Background()
	rootRepo := locateRepoRoot(t)
	fxDir := filepath.Join(rootRepo, "tests", "fixtures", "breachatlas", "C33")

	// 1. Verify C33 fixture provenance & SHA-256 digests.
	provRaw, err := os.ReadFile(filepath.Join(fxDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read C33 provenance: %v", err)
	}
	var prov c33Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatalf("decode C33 provenance: %v", err)
	}
	if prov.Task != "C33" || prov.License != "Apache-2.0" || len(prov.SHA256) < 3 {
		t.Fatalf("invalid C33 provenance: %+v", prov)
	}
	for rel, expected := range prov.SHA256 {
		data, err := os.ReadFile(filepath.Join(fxDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != expected {
			t.Fatalf("fixture %s sha256 mismatch", rel)
		}
	}

	var pos struct {
		SchemaVersion             string   `json:"schema_version"`
		CaseID                    string   `json:"case_id"`
		EvidenceID                string   `json:"evidence_id"`
		ArtifactID                string   `json:"artifact_id"`
		BundleID                  string   `json:"bundle_id"`
		HoldID                    string   `json:"hold_id"`
		Filename                  string   `json:"filename"`
		MediaType                 string   `json:"media_type"`
		Provider                  string   `json:"provider"`
		ZoneHint                  string   `json:"zone_hint"`
		SourceConfidence          float64  `json:"source_confidence"`
		AcquiredAt                string   `json:"acquired_at"`
		Actor                     string   `json:"actor"`
		CustodyReason             string   `json:"custody_reason"`
		HoldReason                string   `json:"hold_reason"`
		PayloadJSONL              string   `json:"payload_jsonl"`
		ObservedSupportedPlatform []string `json:"observed_supported_platforms"`
		NMinus1                   struct {
			LegacyBundle json.RawMessage `json:"legacy_single_file_bundle"`
		} `json:"n_minus_1_compatibility"`
	}
	posRaw, err := os.ReadFile(filepath.Join(fxDir, "positive", "workflow-and-n-minus-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(posRaw, &pos); err != nil {
		t.Fatal(err)
	}

	// 2. Verify docs/evidence/ux.json advertises only observed supported platforms.
	uxRaw, err := os.ReadFile(filepath.Join(rootRepo, "docs", "evidence", "ux.json"))
	if err != nil {
		t.Fatalf("read docs/evidence/ux.json: %v", err)
	}
	var uxDoc struct {
		ObservedSupportedPlatforms []string `json:"observed_supported_platforms"`
		SealedSourceBytesModified  bool     `json:"sealed_source_bytes_modified"`
	}
	if err := json.Unmarshal(uxRaw, &uxDoc); err != nil {
		t.Fatalf("decode ux.json: %v", err)
	}
	if len(uxDoc.ObservedSupportedPlatforms) != 1 || uxDoc.ObservedSupportedPlatforms[0] != "Linux x86_64" {
		t.Fatalf("unexpected observed_supported_platforms in ux.json: %v", uxDoc.ObservedSupportedPlatforms)
	}
	if uxDoc.SealedSourceBytesModified {
		t.Fatalf("expected sealed_source_bytes_modified=false")
	}

	// 3. Verify N-1 compatible single-file export fixture offline.
	n1Dir := t.TempDir()
	n1Path := filepath.Join(n1Dir, "n-minus-1-bundle.json")
	if err := os.WriteFile(n1Path, pos.NMinus1.LegacyBundle, 0o600); err != nil {
		t.Fatal(err)
	}
	n1Res, err := export.VerifyBundle(ctx, n1Path, export.VerifyBundleOptions{
		TrustedPublicKeys: map[string]string{"bnd-n-minus-1-key": "trusted-placeholder"},
		RequireSignature:  true,
	})
	if err != nil || !n1Res.Verified || n1Res.RequiresServer {
		t.Fatalf("N-1 bundle offline verification failed: res=%+v err=%v", n1Res, err)
	}

	// 4. Execute real vertical slice on Go stores and test all C33 negative cases.
	root := t.TempDir()
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
	defer ss.Close()
	ls, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: cDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ls.Close()
	cs, err := custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{RootDir: kDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	reg, err := analyzers.NewRegistry(analyzers.RegistryConfig{SealStore: ss, SealRootDir: sDir, Provider: pos.Provider})
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
	defer as.Close()
	ix, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: iDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ix.Close()
	fs, err := findings.OpenFindingStore(findings.FindingStoreConfig{RootDir: fDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	es, err := export.OpenExportStore(export.ExportStoreConfig{RootDir: eDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer es.Close()
	hs, err := holds.OpenService(holds.ServiceConfig{RootDir: hDir, SealStore: ss, Ledger: ls, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	rt, err := retention.OpenRetentionStore(retention.RetentionConfig{RootDir: rtDir, SealStore: ss, HoldService: hs, LedgerStore: ls, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()

	payloadBytes := []byte(pos.PayloadJSONL)
	sum := sha256.Sum256(payloadBytes)
	expectedSHA := hex.EncodeToString(sum[:])
	sz := int64(len(payloadBytes))

	q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{QuarantineDir: qDir, SyncDir: true}, evidence.UploadRequest{
		SchemaVersion:  "1",
		UploadID:       "upl-c33-01",
		CaseID:         pos.CaseID,
		EvidenceID:     pos.EvidenceID,
		MediaType:      pos.MediaType,
		Filename:       pos.Filename,
		ExpectedSize:   &sz,
		ExpectedSHA256: expectedSHA,
		Body:           bytes.NewReader(payloadBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ls.AppendEvent(ctx, custody.AppendEventRequest{
		EventID:    "cust-c33-01",
		CaseID:     pos.CaseID,
		EvidenceID: pos.EvidenceID,
		EventType:  "intake_seal",
		Actor:      pos.Actor,
		Timestamp:  pos.AcquiredAt,
		Reason:     pos.CustodyReason,
		Provider:   pos.Provider,
	}); err != nil {
		t.Fatal(err)
	}
	curRoot, _ := ls.CurrentRoot(pos.CaseID, pos.EvidenceID)
	sm, err := ss.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "seal-c33-01",
		Quarantined:    q,
		ExpectedSHA256: expectedSHA,
		AcquiredAt:     pos.AcquiredAt,
		CustodyRoot:    curRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	sealedPath := filepath.Join(sDir, filepath.FromSlash(sm.BlobRelPath))

	runRes, err := sbx.RunIsolated(ctx, analyzers.IsolatedRunRequest{
		RunID:      "run-c33-01",
		CaseID:     pos.CaseID,
		EvidenceID: pos.EvidenceID,
		AnalyzerID: analyzers.AnalyzerJSON,
		Provider:   pos.Provider,
		Options:    analyzers.DefaultParseOptions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	artPub, artPriv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := as.DeriveFromIsolatedRun(ctx, ss, sDir, runRes, artifacts.DeriveRequest{
		OperationID: "drv-c33-01",
		CaseID:      pos.CaseID,
		ArtifactID:  pos.ArtifactID,
		Provider:    pos.Provider,
		KeyID:       "art-key-c33",
		PrivateKey:  artPriv,
	}); err != nil {
		t.Fatal(err)
	}
	conf := pos.SourceConfidence
	if _, err := ix.IndexDerivedArtifact(ctx, ss, sDir, as, aDir, timeline.IndexDerivedRequest{
		SchemaVersion:    "1",
		OperationID:      "idx-c33-01",
		CaseID:           pos.CaseID,
		ArtifactID:       pos.ArtifactID,
		Provider:         pos.Provider,
		ZoneHint:         pos.ZoneHint,
		SourceConfidence: &conf,
		VerifyOptions: artifacts.VerifyOptions{
			TrustedKeys:      map[string]ed25519.PublicKey{"art-key-c33": artPub},
			RequireSignature: true,
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Checkpoint authority & Negative Case 2: expired/stale/replayed revision cannot replace last valid accepted authority.
	chkPub, chkPriv, _ := ed25519.GenerateKey(rand.Reader)
	chkPubHex := hex.EncodeToString(chkPub)
	untrustedPub, untrustedPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = untrustedPub

	baseNow := time.Date(2026, 11, 14, 14, 0, 0, 0, time.UTC)
	evList, _ := ls.ListEvents(pos.CaseID, pos.EvidenceID)
	lastEv := evList[len(evList)-1]

	validChk, err := custody.CreateCheckpoint(ctx, ls, custody.CreateCheckpointRequest{
		CheckpointID: "chk-c33-rev2",
		CaseID:       pos.CaseID,
		EvidenceID:   pos.EvidenceID,
		Sequence:     lastEv.Sequence,
		CustodyRoot:  lastEv.CustodyRoot,
		KeyID:        "chk-key-c33",
		Revision:     2,
		IssuedAt:     baseNow.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:    baseNow.Add(24 * time.Hour).Format(time.RFC3339),
		PrivateKey:   chkPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.SaveCheckpoint(ctx, *validChk); err != nil {
		t.Fatal(err)
	}
	tracker := custody.NewCheckpointTracker()
	chkOpts := custody.VerifyCheckpointOptions{
		TrustedPublicKeys: map[string]string{"chk-key-c33": chkPubHex},
		Tracker:           tracker,
		Now:               baseNow,
		StrictReplay:      true,
	}
	if res, err := custody.VerifyCheckpoint(ctx, ls, *validChk, chkOpts); err != nil || !res.Verified {
		t.Fatalf("expected valid checkpoint rev=2 to verify: res=%+v err=%v", res, err)
	}

	// Expired checkpoint (rev=3) must fail and not replace rev=2.
	expiredChk, err := custody.CreateCheckpoint(ctx, ls, custody.CreateCheckpointRequest{
		CheckpointID: "chk-c33-expired",
		CaseID:       pos.CaseID,
		EvidenceID:   pos.EvidenceID,
		Sequence:     lastEv.Sequence,
		CustodyRoot:  lastEv.CustodyRoot,
		KeyID:        "chk-key-c33",
		Revision:     3,
		IssuedAt:     baseNow.Add(-2 * time.Hour).Format(time.RFC3339),
		ExpiresAt:    baseNow.Add(-1 * time.Minute).Format(time.RFC3339),
		PrivateKey:   chkPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.VerifyCheckpoint(ctx, ls, *expiredChk, chkOpts); !errors.Is(err, custody.ErrCheckpointExpired) {
		t.Fatalf("expected ErrCheckpointExpired, got %v", err)
	}

	// Stale revision (rev=1 < accepted rev=2) must fail and not replace rev=2.
	staleChk, err := custody.CreateCheckpoint(ctx, ls, custody.CreateCheckpointRequest{
		CheckpointID: "chk-c33-stale",
		CaseID:       pos.CaseID,
		EvidenceID:   pos.EvidenceID,
		Sequence:     lastEv.Sequence,
		CustodyRoot:  lastEv.CustodyRoot,
		KeyID:        "chk-key-c33",
		Revision:     1,
		IssuedAt:     baseNow.Add(-30 * time.Minute).Format(time.RFC3339),
		ExpiresAt:    baseNow.Add(12 * time.Hour).Format(time.RFC3339),
		PrivateKey:   chkPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.VerifyCheckpoint(ctx, ls, *staleChk, chkOpts); !errors.Is(err, custody.ErrCheckpointStaleRevision) {
		t.Fatalf("expected ErrCheckpointStaleRevision for stale rev=1, got %v", err)
	}

	// Replayed revision (rev=2 <= accepted rev=2 in StrictReplay) must fail.
	if _, err := custody.VerifyCheckpoint(ctx, ls, *validChk, chkOpts); !errors.Is(err, custody.ErrCheckpointStaleRevision) {
		t.Fatalf("expected ErrCheckpointStaleRevision for replayed rev=2, got %v", err)
	}

	// Untrusted signer checkpoint must fail.
	untrustedChk, err := custody.CreateCheckpoint(ctx, ls, custody.CreateCheckpointRequest{
		CheckpointID: "chk-c33-untrusted",
		CaseID:       pos.CaseID,
		EvidenceID:   pos.EvidenceID,
		Sequence:     lastEv.Sequence,
		CustodyRoot:  lastEv.CustodyRoot,
		KeyID:        "untrusted-key-c33",
		Revision:     4,
		IssuedAt:     baseNow.Add(-10 * time.Minute).Format(time.RFC3339),
		ExpiresAt:    baseNow.Add(12 * time.Hour).Format(time.RFC3339),
		PrivateKey:   untrustedPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.VerifyCheckpoint(ctx, ls, *untrustedChk, chkOpts); !errors.Is(err, custody.ErrCheckpointUntrustedSigner) {
		t.Fatalf("expected ErrCheckpointUntrustedSigner, got %v", err)
	}

	acceptedAfter, ok := tracker.GetAccepted(pos.CaseID, pos.EvidenceID)
	if !ok || acceptedAfter.CheckpointID != "chk-c33-rev2" || acceptedAfter.Revision != 2 {
		t.Fatalf("accepted authority mutated by rejected checkpoints: %+v", acceptedAfter)
	}

	// Export signed bundle & test Negative Case 1 (modified byte, missing evidence, untrusted signer)
	bndPub, bndPriv, _ := ed25519.GenerateKey(rand.Reader)
	bndPubHex := hex.EncodeToString(bndPub)
	expOut, err := es.PackageCaseBundle(ctx, export.ExportDeps{
		SealStore:       ss,
		SealRootDir:     sDir,
		LedgerStore:     ls,
		CheckpointStore: cs,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{"chk-key-c33": chkPubHex},
			Now:               baseNow,
		},
		ArtifactStore:   as,
		ArtifactRootDir: aDir,
		IndexStore:      ix,
		FindingStore:    fs,
	}, export.ExportRequest{
		SchemaVersion:   "1",
		OperationID:     "exp-c33-01",
		BundleID:        pos.BundleID,
		CaseID:          pos.CaseID,
		Provider:        pos.Provider,
		EvidenceIDs:     []string{pos.EvidenceID},
		ArtifactIDs:     []string{pos.ArtifactID},
		IncludeTimeline: true,
		KeyID:           "bnd-key-c33",
		PrivateKey:      bndPriv,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Untrusted signer on authentic bundle
	untrustedRes, err := export.VerifyBundle(ctx, expOut.BundleDir, export.VerifyBundleOptions{
		TrustedPublicKeys: map[string]string{"other-key": hex.EncodeToString(untrustedPub)},
		RequireSignature:  true,
	})
	if err != nil || untrustedRes.Verified || untrustedRes.SignatureStatus != export.SignatureStatusUntrusted {
		t.Fatalf("expected untrusted_signer failure, got %+v err=%v", untrustedRes, err)
	}

	// One modified byte in copied bundle
	modCopy := filepath.Join(t.TempDir(), "modified-byte-bundle")
	if err := copyBundleTree(expOut.BundleDir, modCopy); err != nil {
		t.Fatal(err)
	}
	blobCopyPath := filepath.Join(modCopy, "evidence", pos.EvidenceID, "blob.dat")
	blobRaw, err := os.ReadFile(blobCopyPath)
	if err != nil || len(blobRaw) == 0 {
		t.Fatalf("read copied blob: %v", err)
	}
	blobRaw[0] ^= 0x01
	if err := os.WriteFile(blobCopyPath, blobRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	modRes, err := export.VerifyBundle(ctx, modCopy, export.VerifyBundleOptions{
		TrustedPublicKeys: map[string]string{"bnd-key-c33": bndPubHex},
		RequireSignature:  true,
	})
	if err != nil || modRes.Verified || modRes.EvidenceIntegrity != "MISMATCH" {
		t.Fatalf("expected modified byte failure, got %+v err=%v", modRes, err)
	}

	// Missing evidence file in copied bundle
	missCopy := filepath.Join(t.TempDir(), "missing-evidence-bundle")
	if err := copyBundleTree(expOut.BundleDir, missCopy); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(missCopy, "evidence", pos.EvidenceID, "blob.dat")); err != nil {
		t.Fatal(err)
	}
	missRes, err := export.VerifyBundle(ctx, missCopy, export.VerifyBundleOptions{
		TrustedPublicKeys: map[string]string{"bnd-key-c33": bndPubHex},
		RequireSignature:  true,
	})
	if err != nil || missRes.Verified || missRes.EvidenceIntegrity != "MISMATCH" {
		t.Fatalf("expected missing evidence failure, got %+v err=%v", missRes, err)
	}

	// Interrupted restore boundary rollback test
	rcInterrupted, err := recovery.OpenRestoreStore(recovery.RestoreConfig{
		RootDir: rcDir,
		SyncDir: true,
		Faults:  recovery.RestoreFaults{FailAfterStageBeforeCommit: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	restoreTargetRoot := t.TempDir()
	tSS, _ := evidence.OpenSealStore(evidence.SealConfig{RootDir: filepath.Join(restoreTargetRoot, "seal"), QuarantineDir: filepath.Join(restoreTargetRoot, "q"), SyncDir: true})
	tLS, _ := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: filepath.Join(restoreTargetRoot, "cust"), SyncDir: true})
	tCS, _ := custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{RootDir: filepath.Join(restoreTargetRoot, "chk"), SyncDir: true})
	tAS, _ := artifacts.OpenArtifactStore(artifacts.StoreConfig{RootDir: filepath.Join(restoreTargetRoot, "art"), SyncDir: true})
	tIX, _ := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: filepath.Join(restoreTargetRoot, "idx"), SyncDir: true})
	tHS, _ := holds.OpenService(holds.ServiceConfig{RootDir: filepath.Join(restoreTargetRoot, "holds"), SealStore: tSS, Ledger: tLS, SyncDir: true})
	tRT, _ := retention.OpenRetentionStore(retention.RetentionConfig{RootDir: filepath.Join(restoreTargetRoot, "ret"), SealStore: tSS, HoldService: tHS, LedgerStore: tLS, SyncDir: true})
	defer func() {
		_ = tRT.Close()
		_ = tHS.Close()
		_ = tIX.Close()
		_ = tAS.Close()
		_ = tCS.Close()
		_ = tLS.Close()
		_ = tSS.Close()
	}()
	_, intErr := rcInterrupted.RestoreFromBundle(ctx, recovery.TargetStores{
		SealStore:       tSS,
		SealRootDir:     filepath.Join(restoreTargetRoot, "seal"),
		QuarantineDir:   filepath.Join(restoreTargetRoot, "q"),
		LedgerStore:     tLS,
		LedgerRootDir:   filepath.Join(restoreTargetRoot, "cust"),
		CheckpointStore: tCS,
		ArtifactStore:   tAS,
		ArtifactRootDir: filepath.Join(restoreTargetRoot, "art"),
		IndexStore:      tIX,
		IndexRootDir:    filepath.Join(restoreTargetRoot, "idx"),
		HoldService:     tHS,
		RetentionStore:  tRT,
	}, recovery.RestoreBundleRequest{
		SchemaVersion:          "1",
		OperationID:            "op-c33-interrupted-01",
		CaseID:                 pos.CaseID,
		BundlePath:             expOut.BundleDir,
		Provider:               pos.Provider,
		ZoneHint:               pos.ZoneHint,
		TrustedBundleKeys:      map[string]string{"bnd-key-c33": bndPubHex},
		RequireBundleSignature: true,
		TrustedCheckpointKeys:  map[string]string{"chk-key-c33": chkPubHex},
		RequireCheckpointTrust: true,
		ArtifactVerifyOpts: artifacts.VerifyOptions{
			TrustedKeys:      map[string]ed25519.PublicKey{"art-key-c33": artPub},
			RequireSignature: true,
		},
	})
	_ = rcInterrupted.Close()
	if !errors.Is(intErr, recovery.ErrRestoreInterrupted) {
		t.Fatalf("expected ErrRestoreInterrupted, got %v", intErr)
	}

	// Negative Case 3: Sealed source bytes never modified.
	onDiskBytes, err := os.ReadFile(sealedPath)
	if err != nil || !bytes.Equal(onDiskBytes, payloadBytes) {
		t.Fatalf("sealed source bytes modified after C33 positive and negative operations")
	}
}

func copyBundleTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o600)
	})
}

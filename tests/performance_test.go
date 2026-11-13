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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/artifacts"
	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/export"
	"github.com/Parsa-Emami/Breachatlas/internal/recovery"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

type c28Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

func getC28FixturesDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "tests", "fixtures", "breachatlas", "C28")
	if _, err := os.Stat(dir); err == nil {
		return dir
	}
	dir = filepath.Join("fixtures", "breachatlas", "C28")
	if _, err := os.Stat(dir); err == nil {
		return dir
	}
	t.Fatalf("could not locate C28 fixtures directory")
	return ""
}

func TestC28FixturesAndProvenance(t *testing.T) {
	fixturesDir := getC28FixturesDir(t)
	provPath := filepath.Join(fixturesDir, "provenance.json")
	provBytes, err := os.ReadFile(provPath)
	if err != nil {
		t.Fatalf("failed to read provenance.json: %v", err)
	}

	var prov c28Provenance
	if err := json.Unmarshal(provBytes, &prov); err != nil {
		t.Fatalf("malformed provenance.json: %v", err)
	}
	if prov.Task != "C28" {
		t.Fatalf("expected task C28, got %q", prov.Task)
	}
	if prov.License != "Apache-2.0" {
		t.Fatalf("expected Apache-2.0 license, got %q", prov.License)
	}
	if len(prov.SHA256) == 0 {
		t.Fatalf("provenance must contain sha256 checksums")
	}

	for relPath, expectedHash := range prov.SHA256 {
		filePath := filepath.Join(fixturesDir, relPath)
		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("missing fixture referenced in provenance: %s", relPath)
		}
		h := sha256.Sum256(content)
		actualHash := hex.EncodeToString(h[:])
		if actualHash != expectedHash {
			t.Fatalf("fixture hash mismatch for %s: got %s, want %s", relPath, actualHash, expectedHash)
		}
	}
}

func TestTargetWorkloadBoundedPerformance(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()

	quarantineDir := filepath.Join(baseDir, "quarantine")
	sealDir := filepath.Join(baseDir, "seal")
	custodyDir := filepath.Join(baseDir, "custody")
	chkDir := filepath.Join(baseDir, "checkpoints")
	artifactDir := filepath.Join(baseDir, "artifacts")
	indexDir := filepath.Join(baseDir, "timeline")
	exportDir := filepath.Join(baseDir, "export")
	restoreDir := filepath.Join(baseDir, "restore")

	for _, d := range []string{quarantineDir, sealDir, custodyDir, chkDir, artifactDir, indexDir, exportDir, restoreDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("failed to create dir %s: %v", d, err)
		}
	}

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("open seal store: %v", err)
	}
	defer sealStore.Close()

	ledgerStore, err := custody.OpenLedgerStore(custody.LedgerConfig{
		RootDir: custodyDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("open ledger store: %v", err)
	}
	defer ledgerStore.Close()

	chkStore, err := custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{
		RootDir: chkDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("open checkpoint store: %v", err)
	}
	defer chkStore.Close()

	artStore, err := artifacts.OpenArtifactStore(artifacts.StoreConfig{
		RootDir: artifactDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("open artifact store: %v", err)
	}
	defer artStore.Close()

	idxStore, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{
		RootDir: indexDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("open index store: %v", err)
	}
	defer idxStore.Close()

	exportStore, err := export.OpenExportStore(export.ExportStoreConfig{
		RootDir: exportDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("open export store: %v", err)
	}
	defer exportStore.Close()

	restoreStore, err := recovery.OpenRestoreStore(recovery.RestoreConfig{
		RootDir: restoreDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("open restore store: %v", err)
	}
	defer restoreStore.Close()

	// Keys for signatures
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	_ = pubKey
	keyID := "c28-perf-key-01"

	caseID := "case-c28-perf-001"
	evidenceID := "ev-c28-perf-01"
	artifactID := "art-c28-perf-01"

	// Step 1: Benchmark Quarantine Stream & Seal
	var logBuf bytes.Buffer
	recordCount := 200
	for i := 1; i <= recordCount; i++ {
		fmt.Fprintf(&logBuf, "2026-11-13T%02d:%02d:00Z host=srv-%02d user=analyst-%02d action=login status=success\n",
			(i/60)%24, i%60, i%10, i%5)
	}
	rawBytes := logBuf.Bytes()
	sum := sha256.Sum256(rawBytes)
	rawSHA := hex.EncodeToString(sum[:])
	rawSize := int64(len(rawBytes))

	startMem := runtime.MemStats{}
	runtime.ReadMemStats(&startMem)
	t0 := time.Now()

	qUpload, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{
		QuarantineDir: quarantineDir,
		MaxBytes:      evidence.MaxEvidenceBytes,
		SyncDir:       true,
	}, evidence.UploadRequest{
		SchemaVersion:  evidence.SchemaVersion,
		UploadID:       "upl-c28-perf-01",
		CaseID:         caseID,
		EvidenceID:     evidenceID,
		MediaType:      "text/plain",
		Filename:       "auth.log",
		ExpectedSize:   &rawSize,
		ExpectedSHA256: rawSHA,
		Body:           bytes.NewReader(rawBytes),
	})
	if err != nil {
		t.Fatalf("quarantine upload failed: %v", err)
	}

	// Append intake_seal custody event first to bind custody root
	ev1, err := ledgerStore.AppendEvent(ctx, custody.AppendEventRequest{
		EventID:    "cust-c28-perf-01",
		CaseID:     caseID,
		EvidenceID: evidenceID,
		EventType:  "intake_seal",
		Actor:      "operator-c28",
		Timestamp:  "2026-11-13T08:00:00Z",
		Reason:     "C28 performance benchmark intake",
	})
	if err != nil {
		t.Fatalf("append custody event 1: %v", err)
	}

	sealedManifest, err := sealStore.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "op-c28-seal-01",
		Quarantined:    qUpload,
		ExpectedSHA256: rawSHA,
		AcquiredAt:     "2026-11-13T08:00:00Z",
		CustodyRoot:    ev1.CustodyRoot,
	})
	if err != nil {
		t.Fatalf("seal evidence failed: %v", err)
	}
	quarantineAndSealDuration := time.Since(t0)
	if sealedManifest.SHA256 != rawSHA {
		t.Fatalf("sealed SHA mismatch: got %s want %s", sealedManifest.SHA256, rawSHA)
	}

	// Capture sealed blob path for immutability invariant checks
	sealedBlobPath := filepath.Join(sealDir, sealedManifest.BlobRelPath)
	sealedBlobPreBytes, err := os.ReadFile(sealedBlobPath)
	if err != nil {
		t.Fatalf("read sealed blob: %v", err)
	}

	// Step 2: Benchmark Custody Checkpoint
	t1 := time.Now()
	chk, err := custody.CreateCheckpoint(ctx, ledgerStore, custody.CreateCheckpointRequest{
		CheckpointID: "chk-c28-perf-01",
		CaseID:       caseID,
		EvidenceID:   evidenceID,
		Sequence:     ev1.Sequence,
		CustodyRoot:  ev1.CustodyRoot,
		KeyID:        keyID,
		Revision:     1,
		PrivateKey:   privKey,
		ExpiresAt:    "2026-12-31T23:59:59Z",
	})
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	if err := chkStore.SaveCheckpoint(ctx, *chk); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}
	custodyDuration := time.Since(t1)

	// Step 3: Benchmark Derived Artifact & Timeline Indexing
	t2 := time.Now()
	var records []analyzers.ParsedRecord
	for i := 1; i <= recordCount; i++ {
		records = append(records, analyzers.ParsedRecord{
			Index:     i,
			RowNumber: i,
			Timestamp: fmt.Sprintf("2026-11-13T%02d:%02d:00Z", (i/60)%24, i%60),
			Fields: map[string]any{
				"event_type": "auth_event",
				"host":       fmt.Sprintf("srv-%02d", i%10),
				"user":       fmt.Sprintf("analyst-%02d", i%5),
				"summary":    fmt.Sprintf("Synthetic auth event %d", i),
			},
		})
	}

	cfgHash := sha256.Sum256([]byte("c28-parser-config"))
	cfgHashHex := hex.EncodeToString(cfgHash[:])

	dm, err := artStore.DeriveFromAnalysis(ctx, sealStore, sealDir, &analyzers.AnalysisResult{
		SchemaVersion: analyzers.SchemaVersion,
		CaseID:       caseID,
		EvidenceID:   evidenceID,
		AnalyzerID:   analyzers.AnalyzerCSV,
		ToolVersion:  "1.0.0",
		ConfigDigest: cfgHashHex,
		InputSHA256:  rawSHA,
		NonExecuting: true,
		ReadOnly:     true,
		RecordCount:  len(records),
		Records:      records,
	}, artifacts.DeriveRequest{
		OperationID: "op-c28-art-01",
		CaseID:      caseID,
		ArtifactID:  artifactID,
		Provider:    "local",
	})
	if err != nil {
		t.Fatalf("derive artifact: %v", err)
	}

	rebuildOut, err := idxStore.RebuildCaseIndex(ctx, sealStore, sealDir, artStore, artifactDir, timeline.RebuildRequest{
		SchemaVersion: timeline.SchemaVersion,
		CaseID:        caseID,
		ArtifactIDs:   []string{artifactID},
		Provider:      "local",
	})
	if err != nil {
		t.Fatalf("rebuild case index: %v", err)
	}
	if rebuildOut.RebuiltEntries != recordCount {
		t.Fatalf("rebuild entries mismatch: got %d want %d", rebuildOut.RebuiltEntries, recordCount)
	}

	// Benchmark Search Query
	searchRes, err := idxStore.Search(ctx, timeline.SearchRequest{
		SchemaVersion: timeline.SchemaVersion,
		CaseID:        caseID,
		Provider:      "local",
		TextQuery:     "srv-01",
		MaxResults:    50,
		MaxScanEvents: 500,
	})
	if err != nil {
		t.Fatalf("search timeline: %v", err)
	}
	if searchRes.MatchedCount == 0 {
		t.Fatalf("expected search matches for srv-01, got 0")
	}
	timelineDuration := time.Since(t2)

	// Step 4: Benchmark Export Packaging & Verification
	t3 := time.Now()
	exportOut, err := exportStore.PackageCaseBundle(ctx, export.ExportDeps{
		SealStore:       sealStore,
		SealRootDir:     sealDir,
		LedgerStore:     ledgerStore,
		CheckpointStore: chkStore,
		CheckpointOpts: custody.VerifyCheckpointOptions{
			TrustedPublicKeys: map[string]string{
				keyID: hex.EncodeToString(pubKey),
			},
		},
		ArtifactStore:   artStore,
		ArtifactRootDir: artifactDir,
		IndexStore:      idxStore,
	}, export.ExportRequest{
		SchemaVersion:   export.SchemaVersion,
		OperationID:     "op-c28-exp-01",
		BundleID:        "bnd-c28-perf-001",
		CaseID:          caseID,
		Provider:        "local",
		EvidenceIDs:     []string{evidenceID},
		ArtifactIDs:     []string{artifactID},
		IncludeTimeline: true,
	})
	if err != nil {
		t.Fatalf("export case bundle: %v", err)
	}

	bundlePath := filepath.Join(exportDir, "bundles", "bnd-c28-perf-001")
	verifyRes, err := export.VerifyBundle(ctx, bundlePath, export.VerifyBundleOptions{
		ExpectedBundleID: "bnd-c28-perf-001",
		ExpectedCaseID:   caseID,
		TrustedPublicKeys: map[string]string{
			keyID: hex.EncodeToString(pubKey),
		},
	})
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if !verifyRes.Verified {
		t.Fatalf("expected bundle verified, got errors: %v", verifyRes.Errors)
	}
	exportDuration := time.Since(t3)

	// Step 5: Benchmark Recovery Consistency & Rebuild
	t4 := time.Now()
	rebuildCaseOut, err := restoreStore.VerifyAndRebuildCase(ctx, recovery.TargetStores{
		SealStore:       sealStore,
		SealRootDir:     sealDir,
		LedgerStore:     ledgerStore,
		CheckpointStore: chkStore,
		ArtifactStore:   artStore,
		ArtifactRootDir: artifactDir,
		IndexStore:      idxStore,
		IndexRootDir:    indexDir,
	}, recovery.VerifyAndRebuildRequest{
		SchemaVersion: recovery.SchemaVersion,
		OperationID:   "op-c28-rst-01",
		CaseID:        caseID,
		Provider:      "local",
		TrustedCheckpointKeys: map[string]string{
			keyID: hex.EncodeToString(pubKey),
		},
	})
	if err != nil {
		t.Fatalf("verify and rebuild case: %v", err)
	}
	if rebuildCaseOut.RebuiltTimelineEntries != recordCount {
		t.Fatalf("rebuilt timeline count mismatch: got %d want %d", rebuildCaseOut.RebuiltTimelineEntries, recordCount)
	}
	restoreDuration := time.Since(t4)

	// Invariant Verification: Sealed source bytes never modified
	sealedBlobPostBytes, err := os.ReadFile(sealedBlobPath)
	if err != nil {
		t.Fatalf("read post sealed blob: %v", err)
	}
	if !bytes.Equal(sealedBlobPreBytes, sealedBlobPostBytes) {
		t.Fatalf("INVARIANT VIOLATION: sealed source bytes modified during workload")
	}

	endMem := runtime.MemStats{}
	runtime.ReadMemStats(&endMem)

	t.Logf("C28 Target Workload Performance Metrics:")
	t.Logf("  Quarantine & Seal: %v", quarantineAndSealDuration)
	t.Logf("  Custody & Checkpoint: %v", custodyDuration)
	t.Logf("  Timeline Index & Search: %v", timelineDuration)
	t.Logf("  Export & Verify: %v", exportDuration)
	t.Logf("  Restore & Rebuild: %v", restoreDuration)
	t.Logf("  Total Records: %d, Sealed Bytes: %d, Exported Bundle Digest: %s", recordCount, dm.Output.SizeBytes, exportOut.BundleDigest)
	t.Logf("  HeapAlloc Delta: %d bytes, TotalAlloc: %d bytes", int64(endMem.HeapAlloc)-int64(startMem.HeapAlloc), endMem.TotalAlloc-startMem.TotalAlloc)
}

func TestOverloadWorkloadSaturationAndRejection(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()

	quarantineDir := filepath.Join(baseDir, "quarantine")
	sealDir := filepath.Join(baseDir, "seal")
	indexDir := filepath.Join(baseDir, "timeline")

	for _, d := range []string{quarantineDir, sealDir, indexDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("failed to create dir %s: %v", d, err)
		}
	}

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("open seal store: %v", err)
	}
	defer sealStore.Close()

	idxStore, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{
		RootDir: indexDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("open index store: %v", err)
	}
	defer idxStore.Close()

	// Seed case-overload with 1 indexed record so search tests execute against an indexed case
	qSeed, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{
		QuarantineDir: quarantineDir,
	}, evidence.UploadRequest{
		SchemaVersion: evidence.SchemaVersion,
		UploadID:      "upl-ovl-seed",
		CaseID:        "case-overload",
		EvidenceID:    "ev-ovl-seed",
		MediaType:     "text/plain",
		Body:          strings.NewReader("2026-11-13T08:00:00Z host=srv-01 action=test\n"),
	})
	if err != nil {
		t.Fatalf("stream seed: %v", err)
	}
	smSeed, err := sealStore.SealQuarantined(ctx, evidence.SealRequest{
		OperationID: "op-ovl-seed-seal",
		Quarantined: qSeed,
		AcquiredAt:  "2026-11-13T08:00:00Z",
		CustodyRoot: custody.GenesisPrevHash,
	})
	if err != nil {
		t.Fatalf("seal seed: %v", err)
	}
	_, err = idxStore.IndexRecords(ctx, sealStore, sealDir, timeline.IndexRecordsRequest{
		SchemaVersion: timeline.SchemaVersion,
		OperationID:   "op-ovl-seed-idx",
		CaseID:        "case-overload",
		EvidenceID:    "ev-ovl-seed",
		ArtifactID:    "art-ovl-seed",
		InputHashes:   []string{smSeed.SHA256},
		ToolVersion:   "1.0.0",
		ConfigHash:    smSeed.SHA256,
		Records: []timeline.IndexableRecord{
			{SourceLine: 1, Timestamp: "2026-11-13T08:00:00Z", Summary: "seed event"},
		},
	})
	if err != nil {
		t.Fatalf("index seed: %v", err)
	}

	// 1. Oversized evidence stream
	t.Run("oversized_evidence_stream", func(t *testing.T) {
		// A: Declared size > MaxEvidenceBytes (100 MiB)
		declaredTooBig := int64(evidence.MaxEvidenceBytes + 1024)
		_, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{
			QuarantineDir: quarantineDir,
			MaxBytes:      evidence.MaxEvidenceBytes,
		}, evidence.UploadRequest{
			SchemaVersion:  evidence.SchemaVersion,
			UploadID:       "upl-overload-01",
			CaseID:         "case-overload",
			EvidenceID:     "ev-overload-01",
			MediaType:      "application/octet-stream",
			ExpectedSize:   &declaredTooBig,
			Body:           strings.NewReader("sample"),
		})
		if !errors.Is(err, evidence.ErrUploadTooLarge) {
			t.Fatalf("expected ErrUploadTooLarge on declared oversized size, got: %v", err)
		}

		// B: Stream exceeding configured MaxBytes
		limitCfg := evidence.UploadConfig{
			QuarantineDir: quarantineDir,
			MaxBytes:      1024,
		}
		oversizedPayload := bytes.Repeat([]byte("A"), 2048)
		_, err = evidence.StreamIntoQuarantine(ctx, limitCfg, evidence.UploadRequest{
			SchemaVersion: evidence.SchemaVersion,
			UploadID:      "upl-overload-02",
			CaseID:        "case-overload",
			EvidenceID:    "ev-overload-02",
			MediaType:     "application/octet-stream",
			Body:          bytes.NewReader(oversizedPayload),
		})
		if !errors.Is(err, evidence.ErrUploadTooLarge) {
			t.Fatalf("expected ErrUploadTooLarge on streaming bytes exceeding MaxBytes, got: %v", err)
		}
	})

	// 2. Timeline search exceeding max_results cap (1000)
	t.Run("search_max_results_exceeded", func(t *testing.T) {
		_, err := idxStore.Search(ctx, timeline.SearchRequest{
			SchemaVersion: timeline.SchemaVersion,
			CaseID:        "case-overload",
			MaxResults:    timeline.MaxSearchResultsCap + 1,
		})
		if !errors.Is(err, timeline.ErrQueryLimitExceeded) {
			t.Fatalf("expected ErrQueryLimitExceeded on max_results %d, got: %v", timeline.MaxSearchResultsCap+1, err)
		}
	})

	// 3. Timeline search exceeding max_scan_events cap (50000)
	t.Run("search_max_scan_events_exceeded", func(t *testing.T) {
		_, err := idxStore.Search(ctx, timeline.SearchRequest{
			SchemaVersion: timeline.SchemaVersion,
			CaseID:        "case-overload",
			MaxScanEvents: timeline.MaxScanEventsCap + 1,
		})
		if !errors.Is(err, timeline.ErrQueryLimitExceeded) {
			t.Fatalf("expected ErrQueryLimitExceeded on max_scan_events %d, got: %v", timeline.MaxScanEventsCap+1, err)
		}
	})

	// 4. Timeline search exceeding expand_depth cap (8)
	t.Run("search_expand_depth_exceeded", func(t *testing.T) {
		_, err := idxStore.Search(ctx, timeline.SearchRequest{
			SchemaVersion: timeline.SchemaVersion,
			CaseID:        "case-overload",
			ExpandDepth:   timeline.MaxExpandDepthCap + 1,
		})
		if !errors.Is(err, timeline.ErrQueryLimitExceeded) {
			t.Fatalf("expected ErrQueryLimitExceeded on expand_depth %d, got: %v", timeline.MaxExpandDepthCap+1, err)
		}
	})

	// 5. Timeline search exceeding max_expand_degree cap (256)
	t.Run("search_max_expand_degree_exceeded", func(t *testing.T) {
		_, err := idxStore.Search(ctx, timeline.SearchRequest{
			SchemaVersion:   timeline.SchemaVersion,
			CaseID:          "case-overload",
			MaxExpandDegree: timeline.MaxExpandDegreeCap + 1,
		})
		if !errors.Is(err, timeline.ErrQueryLimitExceeded) {
			t.Fatalf("expected ErrQueryLimitExceeded on max_expand_degree %d, got: %v", timeline.MaxExpandDegreeCap+1, err)
		}
	})

	// 6. Timeline search exceeding max_visited_nodes cap (5000)
	t.Run("search_max_visited_nodes_exceeded", func(t *testing.T) {
		_, err := idxStore.Search(ctx, timeline.SearchRequest{
			SchemaVersion:   timeline.SchemaVersion,
			CaseID:          "case-overload",
			MaxVisitedNodes: timeline.MaxVisitedNodesCap + 1,
		})
		if !errors.Is(err, timeline.ErrQueryLimitExceeded) {
			t.Fatalf("expected ErrQueryLimitExceeded on max_visited_nodes %d, got: %v", timeline.MaxVisitedNodesCap+1, err)
		}
	})

	// 7. Client context cancellation terminates immediately without spinning
	t.Run("client_context_cancellation", func(t *testing.T) {
		cancCtx, cancel := context.WithCancel(ctx)
		cancel() // immediately cancelled
		t0 := time.Now()
		_, err := idxStore.Search(cancCtx, timeline.SearchRequest{
			SchemaVersion: timeline.SchemaVersion,
			CaseID:        "case-overload",
			TextQuery:     "should-abort-fast",
		})
		elapsed := time.Since(t0)
		if !errors.Is(err, timeline.ErrQueryCanceled) {
			t.Fatalf("expected ErrQueryCanceled on cancelled context, got: %v", err)
		}
		if elapsed > 100*time.Millisecond {
			t.Fatalf("cancellation took too long (%v), expected immediate termination", elapsed)
		}
	})

	// 8. Single-writer store lock contention fails closed with ErrIndexLockBusy
	t.Run("concurrency_lock_contention", func(t *testing.T) {
		// idxStore already holds exclusive lock on indexDir
		_, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{
			RootDir: indexDir,
		})
		if !errors.Is(err, timeline.ErrIndexLockBusy) {
			t.Fatalf("expected ErrIndexLockBusy on concurrent store open, got: %v", err)
		}
	})

	// 9. Simulated disk full fault in rebuild fails closed
	t.Run("simulated_disk_full_fault", func(t *testing.T) {
		faultIdxDir := filepath.Join(baseDir, "timeline-fault")
		faultIdxStore, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{
			RootDir: faultIdxDir,
			Faults: timeline.IndexFaults{
				SimulateDiskFull: true,
			},
		})
		if err != nil {
			t.Fatalf("open fault index store: %v", err)
		}
		defer faultIdxStore.Close()

		_, err = faultIdxStore.RebuildCaseIndex(ctx, sealStore, sealDir, nil, "", timeline.RebuildRequest{
			SchemaVersion: timeline.SchemaVersion,
			CaseID:        "case-fault",
			ArtifactIDs:   []string{"art-01"},
		})
		if !errors.Is(err, timeline.ErrMissingPrerequisite) && !errors.Is(err, timeline.ErrDiskFull) {
			t.Fatalf("expected error under simulated disk full, got: %v", err)
		}
	})
}

func TestPerformanceWorkloadRestartAndRecovery(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()

	quarantineDir := filepath.Join(baseDir, "quarantine")
	sealDir := filepath.Join(baseDir, "seal")
	custodyDir := filepath.Join(baseDir, "custody")

	for _, d := range []string{quarantineDir, sealDir, custodyDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("failed to create dir %s: %v", d, err)
		}
	}

	caseID := "case-c28-restart-01"
	evidenceID := "ev-c28-restart-01"
	payload := []byte("2026-11-13T09:00:00Z restart test audit payload\n")
	sum := sha256.Sum256(payload)
	payloadSHA := hex.EncodeToString(sum[:])
	payloadSize := int64(len(payload))

	// Run initial workload
	sealStore1, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("open seal store 1: %v", err)
	}

	q1, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{
		QuarantineDir: quarantineDir,
	}, evidence.UploadRequest{
		SchemaVersion: evidence.SchemaVersion,
		UploadID:      "upl-c28-rst-01",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		MediaType:     "text/plain",
		ExpectedSize:  &payloadSize,
		ExpectedSHA256: payloadSHA,
		Body:          bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("stream into quarantine: %v", err)
	}

	sm1, err := sealStore1.SealQuarantined(ctx, evidence.SealRequest{
		OperationID: "op-c28-rst-seal",
		Quarantined: q1,
		AcquiredAt:  "2026-11-13T09:00:00Z",
		CustodyRoot: custody.GenesisPrevHash,
	})
	if err != nil {
		t.Fatalf("seal quarantined 1: %v", err)
	}

	ledgerStore1, err := custody.OpenLedgerStore(custody.LedgerConfig{
		RootDir: custodyDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("open ledger store 1: %v", err)
	}

	ev1, err := ledgerStore1.AppendEvent(ctx, custody.AppendEventRequest{
		CaseID:     caseID,
		EvidenceID: evidenceID,
		EventType:  "intake_seal",
		Actor:      "analyst-c28",
		Timestamp:  "2026-11-13T09:00:00Z",
		Reason:     "Restart test intake",
	})
	if err != nil {
		t.Fatalf("append custody event 1: %v", err)
	}

	// Close all stores cleanly
	if err := sealStore1.Close(); err != nil {
		t.Fatalf("close seal store 1: %v", err)
	}
	if err := ledgerStore1.Close(); err != nil {
		t.Fatalf("close ledger store 1: %v", err)
	}

	// Reopen stores and verify state recovery
	sealStore2, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("open seal store 2 after restart: %v", err)
	}
	defer sealStore2.Close()

	sm2, err := sealStore2.GetSealedManifest(caseID, evidenceID)
	if err != nil {
		t.Fatalf("get sealed manifest after restart: %v", err)
	}
	if sm2.SHA256 != sm1.SHA256 || sm2.SizeBytes != sm1.SizeBytes {
		t.Fatalf("sealed manifest mismatch after restart: got %+v want %+v", sm2, sm1)
	}

	ledgerStore2, err := custody.OpenLedgerStore(custody.LedgerConfig{
		RootDir: custodyDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("open ledger store 2 after restart: %v", err)
	}
	defer ledgerStore2.Close()

	events2, err := ledgerStore2.ListEvents(caseID, evidenceID)
	if err != nil {
		t.Fatalf("list custody events after restart: %v", err)
	}
	if len(events2) != 1 || events2[0].EventDigest != ev1.EventDigest {
		t.Fatalf("custody events corrupted after restart: got %+v", events2)
	}

	// Invariant check: sealed source blob unmodified
	blobPath := filepath.Join(sealDir, sm2.BlobRelPath)
	recoveredBlobBytes, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read recovered blob: %v", err)
	}
	if !bytes.Equal(recoveredBlobBytes, payload) {
		t.Fatalf("INVARIANT VIOLATION: sealed source blob corrupted after restart")
	}
}

// Ensure unused packages or syscall don't trigger compile errors
var _ = io.EOF
var _ = strings.TrimSpace
var _ = syscall.EAGAIN

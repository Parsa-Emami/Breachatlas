package tests_test

import (
	"context"
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

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

type c17Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c17ExpectedEvent struct {
	NormalizedTimestamp string   `json:"normalized_timestamp"`
	TimezoneStatus      string   `json:"timezone_status"`
	TimezoneOffset      string   `json:"timezone_offset"`
	CandidateUTCs       []string `json:"candidate_utcs,omitempty"`
	Confidence          float64  `json:"confidence"`
}

type c17ExpectedOutput struct {
	SchemaVersion    string                      `json:"schema_version"`
	Task             string                      `json:"task"`
	Requirement      string                      `json:"requirement"`
	Invariants       []string                    `json:"invariants"`
	ExpectedPositive map[string]c17ExpectedEvent `json:"expected_positive"`
}

func getC17FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "fixtures", "breachatlas", "C17")
	if filepath.Base(wd) != "tests" {
		dir = filepath.Join(wd, "tests", "fixtures", "breachatlas", "C17")
	}
	return dir
}

func readC17Raw(t *testing.T, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(getC17FixturesDir(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return raw
}

func loadC17JSON[T any](t *testing.T, rel string) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(readC17Raw(t, rel), &out); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", rel, err)
	}
	return out
}

func sealBlobForC17(t *testing.T, qDir string, sealStore *evidence.SealStore, sealDir, caseID, evidenceID, payload string) (string, string, int64) {
	t.Helper()
	qCfg := evidence.UploadConfig{QuarantineDir: qDir, BufferSize: 64, SyncDir: true}
	raw := []byte(payload)
	sum := sha256.Sum256(raw)
	sz := int64(len(raw))
	shaHex := hex.EncodeToString(sum[:])

	q, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-" + evidenceID,
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		MediaType:     "text/plain",
		Filename:      evidenceID + ".log",
		ExpectedSize:  &sz,
		Body:          strings.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("quarantine %s: %v", evidenceID, err)
	}
	m, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
		OperationID:    "seal-" + caseID + "-" + evidenceID,
		Quarantined:    q,
		ExpectedSHA256: shaHex,
		AcquiredAt:     "2026-10-15T08:14:22+03:30",
		CustodyRoot:    custody.GenesisPrevHash,
	})
	if err != nil {
		t.Fatalf("seal %s: %v", evidenceID, err)
	}
	return filepath.Join(sealDir, filepath.FromSlash(m.BlobRelPath)), shaHex, sz
}

func assertSealedBlobUnchangedC17(t *testing.T, blobPath, expectedSHA string, expectedSize int64) {
	t.Helper()
	raw, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read sealed blob %s: %v", blobPath, err)
	}
	sum := sha256.Sum256(raw)
	gotSHA := hex.EncodeToString(sum[:])
	if int64(len(raw)) != expectedSize || gotSHA != expectedSHA {
		t.Fatalf("sealed source bytes modified! got size=%d sha256=%s, want size=%d sha256=%s", len(raw), gotSHA, expectedSize, expectedSHA)
	}
}

func TestC17FixturesAndProvenance(t *testing.T) {
	prov := loadC17JSON[c17Provenance](t, "provenance.json")
	if prov.Task != "C17" || prov.License != "Apache-2.0" {
		t.Fatalf("unexpected C17 provenance: %+v", prov)
	}
	if len(prov.SHA256) < 8 {
		t.Fatalf("expected all C17 fixtures in provenance.json, got %d", len(prov.SHA256))
	}
	dir := getC17FixturesDir(t)
	for rel, want := range prov.SHA256 {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("missing fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("fixture %s digest mismatch: got %s want %s", rel, got, want)
		}
	}
	exp := loadC17JSON[c17ExpectedOutput](t, "expected-output/time-outcomes.json")
	if exp.Task != "C17" || exp.Requirement != "F11" {
		t.Fatalf("unexpected C17 expected output: %+v", exp)
	}
}

func TestC17NormalizePreservesRawValuesAndExplicitAmbiguity(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	qDir := filepath.Join(root, "quarantine")
	sDir := filepath.Join(root, "sealstore")
	tDir := filepath.Join(root, "timestore")

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sealStore.Close()

	tsStore, err := timeline.OpenTimeStore(timeline.TimeStoreConfig{RootDir: tDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tsStore.Close()

	expOut := loadC17JSON[c17ExpectedOutput](t, "expected-output/time-outcomes.json")
	explicitReq := loadC17JSON[timeline.ImportBatchRequest](t, "positive/explicit-offset-events.json")
	blobPath, sealedSHA, sealedSize := sealBlobForC17(t, qDir, sealStore, sDir, explicitReq.CaseID, explicitReq.EvidenceID, "2026-10-15T08:14:22+03:30 ssh_login\n")

	explicitBatch, err := tsStore.ImportBatch(ctx, sealStore, sDir, explicitReq)
	if err != nil {
		t.Fatalf("import explicit batch failed: %v", err)
	}
	ambigBatch, err := tsStore.ImportBatchJSON(ctx, nil, "", readC17Raw(t, "positive/ambiguous-and-unknown-zone-events.json"))
	if err != nil {
		t.Fatalf("import ambiguous/unknown-zone batch failed: %v", err)
	}

	allEvents := append(append([]timeline.NormalizedEvent{}, explicitBatch.Events...), ambigBatch.Events...)
	rawLookup := make(map[string]string)
	for _, ev := range explicitReq.Events {
		rawLookup[ev.EventID] = ev.RawTimestamp
	}
	ambigReq := loadC17JSON[timeline.ImportBatchRequest](t, "positive/ambiguous-and-unknown-zone-events.json")
	for _, ev := range ambigReq.Events {
		rawLookup[ev.EventID] = ev.RawTimestamp
	}

	for _, ev := range allEvents {
		want, ok := expOut.ExpectedPositive[ev.EventID]
		if !ok {
			t.Fatalf("unexpected event_id %s", ev.EventID)
		}
		if ev.Time.RawTimestamp != rawLookup[ev.EventID] {
			t.Fatalf("%s: raw_timestamp lost! got %q want %q", ev.EventID, ev.Time.RawTimestamp, rawLookup[ev.EventID])
		}
		if ev.Time.NormalizedTimestamp != want.NormalizedTimestamp {
			t.Fatalf("%s: normalized_timestamp = %q, want %q (must never fabricate UTC)", ev.EventID, ev.Time.NormalizedTimestamp, want.NormalizedTimestamp)
		}
		if ev.Time.TimezoneStatus != want.TimezoneStatus {
			t.Fatalf("%s: timezone_status = %q, want %q", ev.EventID, ev.Time.TimezoneStatus, want.TimezoneStatus)
		}
		if ev.Time.TimezoneOffset != want.TimezoneOffset {
			t.Fatalf("%s: timezone_offset = %q, want %q", ev.EventID, ev.Time.TimezoneOffset, want.TimezoneOffset)
		}
		if ev.Time.Confidence != want.Confidence {
			t.Fatalf("%s: confidence = %v, want %v", ev.EventID, ev.Time.Confidence, want.Confidence)
		}
		if len(want.CandidateUTCs) > 0 {
			if len(ev.Time.CandidateUTCs) != len(want.CandidateUTCs) {
				t.Fatalf("%s: candidate_utcs = %v, want %v", ev.EventID, ev.Time.CandidateUTCs, want.CandidateUTCs)
			}
			for i := range want.CandidateUTCs {
				if ev.Time.CandidateUTCs[i] != want.CandidateUTCs[i] {
					t.Fatalf("%s: candidate_utcs[%d] = %q, want %q", ev.EventID, i, ev.Time.CandidateUTCs[i], want.CandidateUTCs[i])
				}
			}
		}
	}

	t.Run("unrecognized-iana-zone-hint-stays-explicit-unknown-zone", func(t *testing.T) {
		res, err := timeline.NormalizeTimestamp(timeline.NormalizeRequest{
			RawTimestamp: "2026-10-15 08:14:22",
			ZoneHint:     "Mars/Olympus_Mons",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.NormalizedTimestamp != "" || res.TimezoneStatus != timeline.StatusUnknownZone {
			t.Fatalf("expected explicit unknown_zone without fabricated UTC, got %+v", res)
		}
	})

	assertSealedBlobUnchangedC17(t, blobPath, sealedSHA, sealedSize)
}

func TestC17NegativeCasesRejectedBeforeCommit(t *testing.T) {
	ctx := context.Background()
	tDir := t.TempDir()
	tsStore, err := timeline.OpenTimeStore(timeline.TimeStoreConfig{
		RootDir:       tDir,
		MaxBatchBytes: 320,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tsStore.Close()

	t.Run("malformed-timestamp", func(t *testing.T) {
		raw := readC17Raw(t, "invalid/malformed-timestamp.json")
		if _, err := tsStore.ImportBatchJSON(ctx, nil, "", raw); !errors.Is(err, timeline.ErrMalformedTimestamp) {
			t.Fatalf("expected ErrMalformedTimestamp, got %v", err)
		}
		if _, err := tsStore.GetBatch("case-c17-neg", "batch-c17-malformed"); !errors.Is(err, timeline.ErrBatchNotFound) {
			t.Fatalf("rejected batch must not commit: %v", err)
		}
	})

	t.Run("unsupported-version", func(t *testing.T) {
		raw := readC17Raw(t, "invalid/unsupported-version.json")
		if _, err := tsStore.ImportBatchJSON(ctx, nil, "", raw); !errors.Is(err, timeline.ErrUnsupportedVersion) {
			t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
		}
		if _, err := tsStore.GetBatch("case-c17-neg", "batch-c17-unsup"); !errors.Is(err, timeline.ErrBatchNotFound) {
			t.Fatalf("unsupported batch must not commit: %v", err)
		}
	})

	t.Run("oversized-batch-json", func(t *testing.T) {
		raw := readC17Raw(t, "invalid/oversized-batch.json")
		if _, err := tsStore.ImportBatchJSON(ctx, nil, "", raw); !errors.Is(err, timeline.ErrOversizedInput) {
			t.Fatalf("expected ErrOversizedInput, got %v", err)
		}
	})

	t.Run("oversized-record-count", func(t *testing.T) {
		smallRecDir := t.TempDir()
		s2, err := timeline.OpenTimeStore(timeline.TimeStoreConfig{
			RootDir:            smallRecDir,
			MaxRecordsPerBatch: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer s2.Close()
		_, err = s2.ImportBatch(ctx, nil, "", timeline.ImportBatchRequest{
			SchemaVersion: "1",
			BatchID:       "b-over-rec",
			CaseID:        "c-over-rec",
			Events: []timeline.RawEventInput{
				{EventID: "e1", RawTimestamp: "2026-10-15T08:14:22Z"},
				{EventID: "e2", RawTimestamp: "2026-10-15T08:15:22Z"},
			},
		})
		if !errors.Is(err, timeline.ErrOversizedInput) {
			t.Fatalf("expected ErrOversizedInput for record count, got %v", err)
		}
	})

	t.Run("traversal-and-symlink-rejected", func(t *testing.T) {
		raw := readC17Raw(t, "invalid/traversal-identifier.json")
		if _, err := tsStore.ImportBatchJSON(ctx, nil, "", raw); !errors.Is(err, timeline.ErrPathTraversal) {
			t.Fatalf("expected ErrPathTraversal on batch_id, got %v", err)
		}
		if _, err := timeline.NormalizeTimestamp(timeline.NormalizeRequest{
			RawTimestamp: "2026-10-15 08:14:22",
			ZoneHint:     "../../etc/passwd",
		}); !errors.Is(err, timeline.ErrPathTraversal) {
			t.Fatalf("expected ErrPathTraversal on zone_hint, got %v", err)
		}

		symParent := t.TempDir()
		realTarget := t.TempDir()
		symLink := filepath.Join(symParent, "store-link")
		if err := os.Symlink(realTarget, symLink); err != nil {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		if _, err := timeline.OpenTimeStore(timeline.TimeStoreConfig{RootDir: symLink}); !errors.Is(err, timeline.ErrSymlinkRejected) {
			t.Fatalf("expected ErrSymlinkRejected for symlink root, got %v", err)
		}
	})

	t.Run("lock-busy-disk-full-and-closed", func(t *testing.T) {
		if _, err := timeline.OpenTimeStore(timeline.TimeStoreConfig{RootDir: tDir}); !errors.Is(err, timeline.ErrTimeLockBusy) {
			t.Fatalf("expected ErrTimeLockBusy, got %v", err)
		}

		dfDir := filepath.Join(t.TempDir(), "diskfull-time")
		dfStore, err := timeline.OpenTimeStore(timeline.TimeStoreConfig{
			RootDir: dfDir,
			Faults:  timeline.StoreFaults{SimulateDiskFull: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dfStore.ImportBatch(ctx, nil, "", timeline.ImportBatchRequest{
			SchemaVersion: "1",
			BatchID:       "b-df",
			CaseID:        "c-df",
			Events:        []timeline.RawEventInput{{EventID: "e1", RawTimestamp: "2026-10-15T08:14:22Z"}},
		}); !errors.Is(err, timeline.ErrDiskFull) {
			t.Fatalf("expected ErrDiskFull, got %v", err)
		}
		_ = dfStore.Close()
		if _, err := dfStore.GetBatch("c-df", "b-df"); !errors.Is(err, timeline.ErrTimeStoreClosed) {
			t.Fatalf("expected ErrTimeStoreClosed, got %v", err)
		}
	})
}

func TestC17InterruptedImportAndRestartRecovery(t *testing.T) {
	ctx := context.Background()
	fx := loadC17JSON[timeline.ImportBatchRequest](t, "invalid/interrupted-import.json")

	root := t.TempDir()
	qDir := filepath.Join(root, "quarantine")
	sDir := filepath.Join(root, "sealstore")
	tDir := filepath.Join(root, "timestore")

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	blobPath, sealedSHA, sealedSize := sealBlobForC17(t, qDir, sealStore, sDir, fx.CaseID, fx.EvidenceID, "2026-11-01T01:30:00 America/New_York\n")

	// Step 1: Commit a valid prior batch cleanly.
	s1, err := timeline.OpenTimeStore(timeline.TimeStoreConfig{RootDir: tDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	committed, err := s1.ImportBatch(ctx, sealStore, sDir, timeline.ImportBatchRequest{
		SchemaVersion: "1",
		OperationID:   "op-prior-valid",
		BatchID:       "batch-prior-valid",
		CaseID:        fx.CaseID,
		EvidenceID:    fx.EvidenceID,
		Events: []timeline.RawEventInput{
			{EventID: "ev-prior-1", RawTimestamp: "2026-10-15T08:14:22+03:30"},
		},
	})
	if err != nil {
		t.Fatalf("prior valid commit failed: %v", err)
	}
	_ = s1.Close()

	// Step 2: Reopen with FailAfterStageBeforeCommit to interrupt the second import.
	sCrash, err := timeline.OpenTimeStore(timeline.TimeStoreConfig{
		RootDir: tDir,
		SyncDir: true,
		Faults:  timeline.StoreFaults{FailAfterStageBeforeCommit: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sCrash.ImportBatch(ctx, sealStore, sDir, fx)
	if !errors.Is(err, timeline.ErrInterrupted) {
		t.Fatalf("expected ErrInterrupted, got %v", err)
	}
	// Incomplete import must NOT look complete.
	if _, err := sCrash.GetBatch(fx.CaseID, fx.BatchID); !errors.Is(err, timeline.ErrBatchNotFound) {
		t.Fatalf("incomplete batch visible after interruption: %v", err)
	}
	_ = sCrash.Close()

	// Step 3: Restart cleanly, verify staging cleanup + prior data preservation, then repeat import.
	sRecovered, err := timeline.OpenTimeStore(timeline.TimeStoreConfig{RootDir: tDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen after crash failed: %v", err)
	}
	defer sRecovered.Close()

	rep := sRecovered.LastRecoveryReport()
	if len(rep.CleanedStagingFiles) == 0 || rep.RecoveredBatches != 1 {
		t.Fatalf("expected cleaned staging files and 1 recovered batch, got %+v", rep)
	}
	gotPrior, err := sRecovered.GetBatch(fx.CaseID, "batch-prior-valid")
	if err != nil || gotPrior.BatchDigest != committed.BatchDigest {
		t.Fatalf("prior valid batch lost or altered across restart: got=%+v err=%v", gotPrior, err)
	}

	retried, err := sRecovered.ImportBatch(ctx, sealStore, sDir, fx)
	if err != nil {
		t.Fatalf("repeat import after restart failed: %v", err)
	}
	if retried.Events[0].Time.TimezoneStatus != timeline.StatusDSTAmbiguous || retried.Events[0].Time.NormalizedTimestamp != "" {
		t.Fatalf("retried DST ambiguous timestamp invalid: %+v", retried.Events[0].Time)
	}

	// Idempotent replay after commit succeeds; conflicting operation fails.
	replay, err := sRecovered.ImportBatch(ctx, sealStore, sDir, fx)
	if err != nil || !replay.IdempotentReplay {
		t.Fatalf("expected idempotent replay, got replay=%+v err=%v", replay, err)
	}
	badConflict := fx
	badConflict.BatchID = "different-batch-id"
	if _, err := sRecovered.ImportBatch(ctx, sealStore, sDir, badConflict); !errors.Is(err, timeline.ErrBatchConflict) {
		t.Fatalf("expected ErrBatchConflict, got %v", err)
	}

	_ = sealStore.Close()
	assertSealedBlobUnchangedC17(t, blobPath, sealedSHA, sealedSize)
}

func TestC17ConcurrentNormalizationAndRace(t *testing.T) {
	ctx := context.Background()
	tStore, err := timeline.OpenTimeStore(timeline.TimeStoreConfig{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer tStore.Close()

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := timeline.ImportBatchRequest{
				SchemaVersion: "1",
				OperationID:   fmt.Sprintf("op-race-%d", i),
				BatchID:       fmt.Sprintf("batch-race-%d", i),
				CaseID:        "case-c17-race",
				Events: []timeline.RawEventInput{
					{EventID: "e1", RawTimestamp: "2026-10-15T08:14:22+03:30"},
					{EventID: "e2", RawTimestamp: "2026-11-01T01:30:00", ZoneHint: "America/New_York"},
				},
			}
			if _, err := tStore.ImportBatch(ctx, nil, "", req); err != nil {
				errs <- err
				return
			}
			b, err := tStore.GetBatch("case-c17-race", fmt.Sprintf("batch-race-%d", i))
			if err != nil || b.EventCount != 2 {
				errs <- fmt.Errorf("get batch failed: %v", err)
				return
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent time store failure: %v", err)
	}
}

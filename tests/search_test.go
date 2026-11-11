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
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/artifacts"
	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

type c19Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c19RecordFixture struct {
	RowNumber int            `json:"row_number"`
	Timestamp string         `json:"timestamp"`
	EventType string         `json:"event_type"`
	Summary   string         `json:"summary"`
	Fields    map[string]any `json:"fields"`
}

type c19PositiveRebuildFixture struct {
	SchemaVersion string             `json:"schema_version"`
	CaseID        string             `json:"case_id"`
	EvidenceID    string             `json:"evidence_id"`
	ZoneHint      string             `json:"zone_hint"`
	Records       []c19RecordFixture `json:"records"`
}

type c19DeterminismFixture struct {
	SchemaVersion         string             `json:"schema_version"`
	CaseID                string             `json:"case_id"`
	EvidenceID            string             `json:"evidence_id"`
	BaselineRecords       []c19RecordFixture `json:"baseline_records"`
	SemanticChangedRecord []c19RecordFixture `json:"semantic_changed_records"`
}

type c19CyclicFixture struct {
	SchemaVersion string             `json:"schema_version"`
	CaseID        string             `json:"case_id"`
	EvidenceID    string             `json:"evidence_id"`
	CyclicRecords []c19RecordFixture `json:"cyclic_records"`
	HighDegreeHub struct {
		FanoutCount              int    `json:"fanout_count"`
		MaxExpandDegree          int    `json:"max_expand_degree"`
		ExpectedTruncationReason string `json:"expected_truncation_reason"`
	} `json:"high_degree_hub"`
}

type c19LimitsFixture struct {
	SchemaVersion string `json:"schema_version"`
	CaseID        string `json:"case_id"`
	Cases         []struct {
		Name             string `json:"name"`
		MaxResults       int    `json:"max_results,omitempty"`
		MaxScanEvents    int    `json:"max_scan_events,omitempty"`
		TimeoutMS        int    `json:"timeout_ms,omitempty"`
		ExpiredDeadline  bool   `json:"expired_deadline,omitempty"`
		Canceled         bool   `json:"canceled,omitempty"`
		ExpectedStatus   string `json:"expected_status,omitempty"`
		ExpectedError    string `json:"expected_error"`
	} `json:"cases"`
}

type c19Env struct {
	root          string
	qDir          string
	sDir          string
	scDir         string
	aDir          string
	idxDir        string
	sealStore     *evidence.SealStore
	registry      *analyzers.Registry
	sandbox       *analyzers.Sandbox
	artifactStore *artifacts.ArtifactStore
	indexStore    *timeline.EventIndexStore
}

func getC19FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "fixtures", "breachatlas", "C19")
	if filepath.Base(wd) != "tests" {
		dir = filepath.Join(wd, "tests", "fixtures", "breachatlas", "C19")
	}
	return dir
}

func loadC19JSON[T any](t *testing.T, rel string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(getC19FixturesDir(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", rel, err)
	}
	return out
}

func setupC19Env(t *testing.T) *c19Env {
	t.Helper()
	root := t.TempDir()
	qDir := filepath.Join(root, "quarantine")
	sDir := filepath.Join(root, "sealstore")
	scDir := filepath.Join(root, "scratch")
	aDir := filepath.Join(root, "artifacts")
	idxDir := filepath.Join(root, "timeline-index")

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sealStore.Close() })

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

	return &c19Env{
		root:          root,
		qDir:          qDir,
		sDir:          sDir,
		scDir:         scDir,
		aDir:          aDir,
		idxDir:        idxDir,
		sealStore:     sealStore,
		registry:      reg,
		sandbox:       sb,
		artifactStore: aStore,
		indexStore:    idxStore,
	}
}

func encodeRecordsJSONL(t *testing.T, recs []c19RecordFixture) string {
	t.Helper()
	var lines []string
	for _, r := range recs {
		obj := make(map[string]any, len(r.Fields)+3)
		for k, v := range r.Fields {
			obj[k] = v
		}
		obj["timestamp"] = r.Timestamp
		obj["event_type"] = r.EventType
		obj["summary"] = r.Summary
		raw, err := json.Marshal(obj)
		if err != nil {
			t.Fatalf("marshal jsonl record: %v", err)
		}
		lines = append(lines, string(raw))
	}
	return strings.Join(lines, "\n") + "\n"
}

func sealAndDeriveC19(t *testing.T, env *c19Env, caseID, evidenceID, artifactID, jsonl string) (string, string, int64) {
	t.Helper()
	qCfg := evidence.UploadConfig{QuarantineDir: env.qDir, BufferSize: 64, SyncDir: true}
	raw := []byte(jsonl)
	sum := sha256.Sum256(raw)
	sz := int64(len(raw))
	shaHex := hex.EncodeToString(sum[:])

	q, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-" + caseID + "-" + evidenceID,
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		MediaType:     "application/json",
		Filename:      evidenceID + ".jsonl",
		ExpectedSize:  &sz,
		Body:          strings.NewReader(jsonl),
	})
	if err != nil {
		t.Fatalf("quarantine %s: %v", evidenceID, err)
	}
	sm, err := env.sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
		OperationID:    "seal-" + caseID + "-" + evidenceID,
		Quarantined:    q,
		ExpectedSHA256: shaHex,
		AcquiredAt:     "2026-06-15T10:00:00Z",
		CustodyRoot:    custody.GenesisPrevHash,
	})
	if err != nil {
		t.Fatalf("seal %s: %v", evidenceID, err)
	}
	blobPath := filepath.Join(env.sDir, filepath.FromSlash(sm.BlobRelPath))

	runRes, err := env.sandbox.RunIsolated(context.Background(), analyzers.IsolatedRunRequest{
		RunID:      "run-" + artifactID,
		CaseID:     caseID,
		EvidenceID: evidenceID,
		AnalyzerID: analyzers.AnalyzerJSON,
		Provider:   "local",
		Options:    analyzers.DefaultParseOptions(),
	})
	if err != nil {
		t.Fatalf("sandbox run %s: %v", artifactID, err)
	}
	_, err = env.artifactStore.DeriveFromIsolatedRun(context.Background(), env.sealStore, env.sDir, runRes, artifacts.DeriveRequest{
		OperationID: "drv-" + caseID + "-" + artifactID,
		CaseID:      caseID,
		ArtifactID:  artifactID,
		Provider:    "local",
	})
	if err != nil {
		t.Fatalf("derive artifact %s: %v", artifactID, err)
	}
	return blobPath, shaHex, sz
}

func assertSealedBlobUnchangedC19(t *testing.T, blobPath, expectedSHA string, expectedSize int64) {
	t.Helper()
	raw, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read sealed blob %s: %v", blobPath, err)
	}
	sum := sha256.Sum256(raw)
	gotSHA := hex.EncodeToString(sum[:])
	if int64(len(raw)) != expectedSize || gotSHA != expectedSHA {
		t.Fatalf("sealed bytes modified! got size=%d sha=%s want size=%d sha=%s", len(raw), gotSHA, expectedSize, expectedSHA)
	}
}

func TestC19FixturesAndProvenance(t *testing.T) {
	prov := loadC19JSON[c19Provenance](t, "provenance.json")
	if prov.Task != "C19" || prov.License != "Apache-2.0" {
		t.Fatalf("unexpected C19 provenance: %+v", prov)
	}
	if len(prov.SHA256) != 5 {
		t.Fatalf("expected 5 hashed C19 fixture files, got %d", len(prov.SHA256))
	}
	dir := getC19FixturesDir(t)
	for rel, expected := range prov.SHA256 {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("missing C19 fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != expected {
			t.Fatalf("fixture %s sha mismatch: got %s want %s", rel, got, expected)
		}
	}
}

func TestC19IndexRebuildAndBoundedQuery(t *testing.T) {
	fx := loadC19JSON[c19PositiveRebuildFixture](t, "positive/bounded-query-and-rebuild.json")
	env := setupC19Env(t)

	// Split records across two derived artifacts (including one overlapping event to test dedup on rebuild).
	blob1, sha1, sz1 := sealAndDeriveC19(t, env, fx.CaseID, fx.EvidenceID+"-a", "art-c19-01", encodeRecordsJSONL(t, fx.Records[:2]))
	blob2, sha2, sz2 := sealAndDeriveC19(t, env, fx.CaseID, fx.EvidenceID+"-b", "art-c19-02", encodeRecordsJSONL(t, fx.Records[2:]))

	srcConf := 0.92
	for _, artID := range []string{"art-c19-01", "art-c19-02"} {
		if _, err := env.indexStore.IndexDerivedArtifact(context.Background(), env.sealStore, env.sDir, env.artifactStore, env.aDir, timeline.IndexDerivedRequest{
			SchemaVersion:    "1",
			OperationID:      "idx-" + artID,
			CaseID:           fx.CaseID,
			ArtifactID:       artID,
			Provider:         "local",
			ZoneHint:         fx.ZoneHint,
			SourceConfidence: &srcConf,
		}); err != nil {
			t.Fatalf("index %s: %v", artID, err)
		}
	}

	// Execute baseline bounded query with pagination and graph expansion.
	origPage1, err := env.indexStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		Provider:      "local",
		MaxResults:    2,
		MaxScanEvents: 100,
		ExpandDepth:   2,
	})
	if err != nil {
		t.Fatalf("baseline search page 1: %v", err)
	}
	if origPage1.Status != timeline.SearchStatusTruncated || !origPage1.Truncated || origPage1.TruncationReason != timeline.TruncationMaxResults {
		t.Fatalf("expected truncated max_results page 1, got status=%s truncated=%v reason=%s", origPage1.Status, origPage1.Truncated, origPage1.TruncationReason)
	}
	if !origPage1.HasMore || origPage1.NextOffset != 2 || len(origPage1.Entries) != 2 {
		t.Fatalf("unexpected page 1 pagination: %+v", origPage1)
	}
	if len(origPage1.RelatedEdges) == 0 {
		t.Fatalf("expected bounded graph expansion edges on depth=2, got none")
	}

	// Time-range + text filter verification.
	filtered, err := env.indexStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		TextQuery:     "collector",
		StartTimeUTC:  "2026-06-15T09:04:00Z",
		EndTimeUTC:    "2026-06-15T09:16:00Z",
		MaxResults:    10,
	})
	if err != nil {
		t.Fatalf("filtered search: %v", err)
	}
	if filtered.Status != timeline.SearchStatusComplete || filtered.Truncated || len(filtered.Entries) != 2 {
		t.Fatalf("expected 2 filtered complete results, got status=%s len=%d", filtered.Status, len(filtered.Entries))
	}
	if filtered.Entries[0].Time.RawTimestamp != "2026-06-15 05:05:00" || filtered.Entries[0].Time.NormalizedTimestamp != "2026-06-15T09:05:00Z" {
		t.Fatalf("expected raw and normalized timestamps preserved, got %+v", filtered.Entries[0].Time)
	}

	// Destroy the persisted timeline index directory completely, then rebuild from verified ArtifactStore + SealStore.
	_ = env.indexStore.Close()
	if err := os.RemoveAll(env.idxDir); err != nil {
		t.Fatalf("remove index dir: %v", err)
	}

	// Simulate interrupted rebuild first; staging cleanup must recover cleanly on next open.
	faultStore, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{
		RootDir: env.idxDir,
		SyncDir: true,
		Faults:  timeline.IndexFaults{FailAfterStageBeforeCommit: true},
	})
	if err != nil {
		t.Fatalf("open fault store: %v", err)
	}
	_, err = faultStore.RebuildCaseIndex(context.Background(), env.sealStore, env.sDir, env.artifactStore, env.aDir, timeline.RebuildRequest{
		SchemaVersion:    "1",
		CaseID:           fx.CaseID,
		ZoneHint:         fx.ZoneHint,
		SourceConfidence: &srcConf,
	})
	if !errors.Is(err, timeline.ErrInterrupted) {
		t.Fatalf("expected ErrInterrupted on simulated crash during rebuild, got %v", err)
	}
	_ = faultStore.Close()

	rebuiltStore, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: env.idxDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen store after interrupted rebuild: %v", err)
	}
	defer func() { _ = rebuiltStore.Close() }()
	if rep := rebuiltStore.LastRecoveryReport(); len(rep.CleanedStagingFiles) == 0 {
		t.Fatalf("expected orphan rebuild staging file cleanup on reopen, got %+v", rep)
	}

	outcome, err := rebuiltStore.RebuildCaseIndex(context.Background(), env.sealStore, env.sDir, env.artifactStore, env.aDir, timeline.RebuildRequest{
		SchemaVersion:    "1",
		CaseID:           fx.CaseID,
		Provider:         "local",
		ZoneHint:         fx.ZoneHint,
		SourceConfidence: &srcConf,
	})
	if err != nil {
		t.Fatalf("RebuildCaseIndex: %v", err)
	}
	if outcome.ArtifactsProcessed != 2 || outcome.RebuiltEntries != len(fx.Records) {
		t.Fatalf("unexpected rebuild outcome: %+v", outcome)
	}

	rebuiltPage1, err := rebuiltStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		Provider:      "local",
		MaxResults:    2,
		MaxScanEvents: 100,
		ExpandDepth:   2,
	})
	if err != nil {
		t.Fatalf("rebuilt search page 1: %v", err)
	}
	if rebuiltPage1.ResultDigest != origPage1.ResultDigest {
		t.Fatalf("rebuilt search digest mismatch: got %s want %s", rebuiltPage1.ResultDigest, origPage1.ResultDigest)
	}

	// Missing case prerequisites must fail explicitly on rebuild.
	_, err = rebuiltStore.RebuildCaseIndex(context.Background(), env.sealStore, env.sDir, env.artifactStore, env.aDir, timeline.RebuildRequest{
		SchemaVersion: "1",
		CaseID:        "case-missing-c19",
	})
	if !errors.Is(err, timeline.ErrMissingPrerequisite) {
		t.Fatalf("expected ErrMissingPrerequisite for unknown case rebuild, got %v", err)
	}

	assertSealedBlobUnchangedC19(t, blob1, sha1, sz1)
	assertSealedBlobUnchangedC19(t, blob2, sha2, sz2)
}

func TestC19NegativeCyclicHighDegreeAndDeadline(t *testing.T) {
	cycFx := loadC19JSON[c19CyclicFixture](t, "invalid/cyclic-high-degree-events.json")
	limFx := loadC19JSON[c19LimitsFixture](t, "invalid/over-limit-and-deadline.json")
	env := setupC19Env(t)

	// 1. Cyclic reference graph (node-a <-> node-b).
	blobCyc, shaCyc, szCyc := sealAndDeriveC19(t, env, cycFx.CaseID, cycFx.EvidenceID, "art-cyclic", encodeRecordsJSONL(t, cycFx.CyclicRecords))
	if _, err := env.indexStore.IndexDerivedArtifact(context.Background(), env.sealStore, env.sDir, env.artifactStore, env.aDir, timeline.IndexDerivedRequest{
		SchemaVersion: "1",
		CaseID:        cycFx.CaseID,
		ArtifactID:    "art-cyclic",
	}); err != nil {
		t.Fatalf("index cyclic artifact: %v", err)
	}

	cycRes, err := env.indexStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        cycFx.CaseID,
		TextQuery:     "node-a",
		MaxResults:    5,
		ExpandDepth:   6,
	})
	if err != nil {
		t.Fatalf("cyclic search returned unexpected error: %v", err)
	}
	if !cycRes.CycleDetected || !cycRes.Truncated || cycRes.Status != timeline.SearchStatusTruncated || cycRes.TruncationReason != timeline.TruncationCycleDetected {
		t.Fatalf("expected bounded cycle truncation, got status=%s truncated=%v reason=%s cycle=%v", cycRes.Status, cycRes.Truncated, cycRes.TruncationReason, cycRes.CycleDetected)
	}

	// 2. High-degree hub (48 fanout nodes) exceeding MaxExpandDegree and MaxScanEvents.
	hubCase := "case-c19-hub"
	relatedIDs := make([]string, 0, cycFx.HighDegreeHub.FanoutCount)
	hubRecs := make([]c19RecordFixture, 0, cycFx.HighDegreeHub.FanoutCount+1)
	for i := 1; i <= cycFx.HighDegreeHub.FanoutCount; i++ {
		nid := fmt.Sprintf("leaf-%03d", i)
		relatedIDs = append(relatedIDs, nid)
		hubRecs = append(hubRecs, c19RecordFixture{
			RowNumber: i + 1,
			Timestamp: fmt.Sprintf("2026-08-02T00:%02d:%02dZ", i/60, i%60),
			EventType: "leaf_event",
			Summary:   "Leaf node " + nid,
			Fields:    map[string]any{"node_id": nid},
		})
	}
	hubRecs = append([]c19RecordFixture{{
		RowNumber: 1,
		Timestamp: "2026-08-02T00:00:00Z",
		EventType: "hub_event",
		Summary:   "High-degree seed hub",
		Fields: map[string]any{
			"node_id":           "hub-root",
			"related_event_ids": relatedIDs,
		},
	}}, hubRecs...)

	blobHub, shaHub, szHub := sealAndDeriveC19(t, env, hubCase, "ev-hub", "art-hub", encodeRecordsJSONL(t, hubRecs))
	if _, err := env.indexStore.IndexDerivedArtifact(context.Background(), env.sealStore, env.sDir, env.artifactStore, env.aDir, timeline.IndexDerivedRequest{
		SchemaVersion: "1",
		CaseID:        hubCase,
		ArtifactID:    "art-hub",
	}); err != nil {
		t.Fatalf("index hub artifact: %v", err)
	}

	degRes, err := env.indexStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion:   "1",
		CaseID:          hubCase,
		EventTypes:      []string{"hub_event"},
		MaxResults:      10,
		ExpandDepth:     2,
		MaxExpandDegree: cycFx.HighDegreeHub.MaxExpandDegree,
	})
	if err != nil {
		t.Fatalf("high-degree search error: %v", err)
	}
	if degRes.Status != timeline.SearchStatusTruncated || !degRes.Truncated || degRes.TruncationReason != cycFx.HighDegreeHub.ExpectedTruncationReason {
		t.Fatalf("expected max_degree truncation, got status=%s truncated=%v reason=%s", degRes.Status, degRes.Truncated, degRes.TruncationReason)
	}
	if len(degRes.RelatedEdges) != cycFx.HighDegreeHub.MaxExpandDegree {
		t.Fatalf("expected bounded %d edges, got %d", cycFx.HighDegreeHub.MaxExpandDegree, len(degRes.RelatedEdges))
	}

	scanRes, err := env.indexStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        hubCase,
		MaxResults:    50,
		MaxScanEvents: 10,
	})
	if err != nil {
		t.Fatalf("scan-bounded search error: %v", err)
	}
	if scanRes.Status != timeline.SearchStatusTruncated || scanRes.TruncationReason != timeline.TruncationMaxScanEvents || scanRes.ScannedCount != 10 {
		t.Fatalf("expected max_scan_events truncation at 10, got status=%s reason=%s scanned=%d", scanRes.Status, scanRes.TruncationReason, scanRes.ScannedCount)
	}

	// 3. Hard-cap, negative input, deadline exceeded, and context cancellation cases from fixture.
	for _, tc := range limFx.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			var cancel context.CancelFunc
			if tc.ExpiredDeadline {
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			} else if tc.Canceled {
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			res, qErr := env.indexStore.Search(ctx, timeline.SearchRequest{
				SchemaVersion: "1",
				CaseID:        hubCase,
				MaxResults:    tc.MaxResults,
				MaxScanEvents: tc.MaxScanEvents,
				Timeout:       time.Duration(tc.TimeoutMS) * time.Millisecond,
			})
			switch tc.ExpectedError {
			case "ErrQueryLimitExceeded":
				if !errors.Is(qErr, timeline.ErrQueryLimitExceeded) {
					t.Fatalf("expected ErrQueryLimitExceeded, got %v", qErr)
				}
			case "ErrInvalidInput":
				if !errors.Is(qErr, timeline.ErrInvalidInput) {
					t.Fatalf("expected ErrInvalidInput, got %v", qErr)
				}
			case "ErrQueryDeadlineExceeded":
				if !errors.Is(qErr, timeline.ErrQueryDeadlineExceeded) || !errors.Is(qErr, context.DeadlineExceeded) {
					t.Fatalf("expected ErrQueryDeadlineExceeded, got %v", qErr)
				}
				if res == nil || res.Status != tc.ExpectedStatus {
					t.Fatalf("expected status %s, got %+v", tc.ExpectedStatus, res)
				}
			case "ErrQueryCanceled":
				if !errors.Is(qErr, timeline.ErrQueryCanceled) || !errors.Is(qErr, context.Canceled) {
					t.Fatalf("expected ErrQueryCanceled, got %v", qErr)
				}
				if res == nil || res.Status != tc.ExpectedStatus {
					t.Fatalf("expected status %s, got %+v", tc.ExpectedStatus, res)
				}
			default:
				t.Fatalf("unhandled fixture expected_error %q", tc.ExpectedError)
			}
		})
	}

	// Unsupported provider & unindexed case checks.
	if _, err := env.indexStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        hubCase,
		Provider:      "remote-saas",
	}); !errors.Is(err, timeline.ErrUnavailableProvider) {
		t.Fatalf("expected ErrUnavailableProvider, got %v", err)
	}
	if _, err := env.indexStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        "case-not-indexed",
	}); !errors.Is(err, timeline.ErrEntryNotFound) {
		t.Fatalf("expected ErrEntryNotFound, got %v", err)
	}

	assertSealedBlobUnchangedC19(t, blobCyc, shaCyc, szCyc)
	assertSealedBlobUnchangedC19(t, blobHub, shaHub, szHub)
}

func TestC19DeterminismAndSemanticSensitivity(t *testing.T) {
	fx := loadC19JSON[c19DeterminismFixture](t, "positive/reordered-vs-semantic-diff.json")

	// Environment A indexes baseline records in forward order [rec0, rec1].
	envA := setupC19Env(t)
	blobA1, shaA1, szA1 := sealAndDeriveC19(t, envA, fx.CaseID, fx.EvidenceID+"-1", "art-det-1", encodeRecordsJSONL(t, fx.BaselineRecords[:1]))
	blobA2, shaA2, szA2 := sealAndDeriveC19(t, envA, fx.CaseID, fx.EvidenceID+"-2", "art-det-2", encodeRecordsJSONL(t, fx.BaselineRecords[1:]))
	if _, err := envA.indexStore.RebuildCaseIndex(context.Background(), envA.sealStore, envA.sDir, envA.artifactStore, envA.aDir, timeline.RebuildRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		ArtifactIDs:   []string{"art-det-1", "art-det-2"},
	}); err != nil {
		t.Fatalf("rebuild envA: %v", err)
	}
	resA, err := envA.indexStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		MaxResults:    10,
	})
	if err != nil {
		t.Fatalf("search envA: %v", err)
	}

	// Environment B uses identical sealed inputs indexed in reverse order [rec1, rec0].
	envB := setupC19Env(t)
	_, _, _ = sealAndDeriveC19(t, envB, fx.CaseID, fx.EvidenceID+"-2", "art-det-2", encodeRecordsJSONL(t, fx.BaselineRecords[1:]))
	_, _, _ = sealAndDeriveC19(t, envB, fx.CaseID, fx.EvidenceID+"-1", "art-det-1", encodeRecordsJSONL(t, fx.BaselineRecords[:1]))
	if _, err := envB.indexStore.RebuildCaseIndex(context.Background(), envB.sealStore, envB.sDir, envB.artifactStore, envB.aDir, timeline.RebuildRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		ArtifactIDs:   []string{"art-det-2", "art-det-1"},
	}); err != nil {
		t.Fatalf("rebuild envB: %v", err)
	}
	resB, err := envB.indexStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		MaxResults:    10,
	})
	if err != nil {
		t.Fatalf("search envB: %v", err)
	}

	if resA.ResultDigest != resB.ResultDigest {
		t.Fatalf("reordered identical input changed result_digest: A=%s B=%s", resA.ResultDigest, resB.ResultDigest)
	}

	// Environment C mutates a semantic fact (qname + summary on record 0) and checks distinct effect.
	envC := setupC19Env(t)
	_, _, _ = sealAndDeriveC19(t, envC, fx.CaseID, fx.EvidenceID+"-1", "art-det-1", encodeRecordsJSONL(t, fx.SemanticChangedRecord[:1]))
	_, _, _ = sealAndDeriveC19(t, envC, fx.CaseID, fx.EvidenceID+"-2", "art-det-2", encodeRecordsJSONL(t, fx.SemanticChangedRecord[1:]))
	if _, err := envC.indexStore.RebuildCaseIndex(context.Background(), envC.sealStore, envC.sDir, envC.artifactStore, envC.aDir, timeline.RebuildRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
	}); err != nil {
		t.Fatalf("rebuild envC: %v", err)
	}
	resC, err := envC.indexStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		MaxResults:    10,
	})
	if err != nil {
		t.Fatalf("search envC: %v", err)
	}
	if resC.ResultDigest == resA.ResultDigest {
		t.Fatalf("semantic change failed to produce distinct result_digest: %s", resC.ResultDigest)
	}
	if resC.Entries[0].EventIdentity == resA.Entries[0].EventIdentity {
		t.Fatalf("semantic change failed to produce distinct EventIdentity")
	}

	exfilResA, err := envA.indexStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		TextQuery:     "external-exfil.example",
	})
	if err != nil || len(exfilResA.Entries) != 0 {
		t.Fatalf("baseline index unexpectedly matched changed domain: len=%d err=%v", len(exfilResA.Entries), err)
	}
	exfilResC, err := envC.indexStore.Search(context.Background(), timeline.SearchRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		TextQuery:     "external-exfil.example",
	})
	if err != nil || len(exfilResC.Entries) != 1 {
		t.Fatalf("changed index should match external-exfil.example once: len=%d err=%v", len(exfilResC.Entries), err)
	}

	assertSealedBlobUnchangedC19(t, blobA1, shaA1, szA1)
	assertSealedBlobUnchangedC19(t, blobA2, shaA2, szA2)
}

func TestC19ConcurrentSearchAndRebuildRace(t *testing.T) {
	fx := loadC19JSON[c19PositiveRebuildFixture](t, "positive/bounded-query-and-rebuild.json")
	env := setupC19Env(t)

	blob, sha, sz := sealAndDeriveC19(t, env, fx.CaseID, fx.EvidenceID, "art-race", encodeRecordsJSONL(t, fx.Records))
	if _, err := env.indexStore.RebuildCaseIndex(context.Background(), env.sealStore, env.sDir, env.artifactStore, env.aDir, timeline.RebuildRequest{
		SchemaVersion: "1",
		CaseID:        fx.CaseID,
		ZoneHint:      fx.ZoneHint,
	}); err != nil {
		t.Fatalf("initial rebuild: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				if _, err := env.indexStore.RebuildCaseIndex(context.Background(), env.sealStore, env.sDir, env.artifactStore, env.aDir, timeline.RebuildRequest{
					SchemaVersion: "1",
					CaseID:        fx.CaseID,
					ZoneHint:      fx.ZoneHint,
				}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				res, err := env.indexStore.Search(context.Background(), timeline.SearchRequest{
					SchemaVersion: "1",
					CaseID:        fx.CaseID,
					MaxResults:    4,
					ExpandDepth:   2,
				})
				if err != nil {
					errs <- err
					return
				}
				if len(res.Entries) != len(fx.Records) {
					errs <- fmt.Errorf("expected %d entries during concurrent rebuild/search, got %d", len(fx.Records), len(res.Entries))
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent search/rebuild error: %v", err)
		}
	}

	assertSealedBlobUnchangedC19(t, blob, sha, sz)
}

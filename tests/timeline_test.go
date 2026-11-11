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

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/artifacts"
	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

type c18Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

func getC18FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "fixtures", "breachatlas", "C18")
	if filepath.Base(wd) != "tests" {
		dir = filepath.Join(wd, "tests", "fixtures", "breachatlas", "C18")
	}
	return dir
}

func loadC18JSON[T any](t *testing.T, rel string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(getC18FixturesDir(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", rel, err)
	}
	return out
}

type c18Env struct {
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

func setupC18Env(t *testing.T) *c18Env {
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

	return &c18Env{
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

func sealPayloadForC18(t *testing.T, qDir string, sealStore *evidence.SealStore, sealDir, caseID, evidenceID, mediaType, payload string) (string, string, int64) {
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
		MediaType:     mediaType,
		Filename:      evidenceID + ".dat",
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

func assertSealedBlobUnchangedC18(t *testing.T, blobPath, expectedSHA string, expectedSize int64) {
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

func TestC18FixturesAndProvenance(t *testing.T) {
	prov := loadC18JSON[c18Provenance](t, "provenance.json")
	if prov.Task != "C18" || prov.License != "Apache-2.0" {
		t.Fatalf("unexpected C18 provenance: %+v", prov)
	}
	if len(prov.SHA256) < 7 {
		t.Fatalf("expected all C18 fixtures hashed, got %d", len(prov.SHA256))
	}
	dir := getC18FixturesDir(t)
	for rel, want := range prov.SHA256 {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("missing fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("fixture %s sha256 mismatch: got %s want %s", rel, got, want)
		}
	}
	exp := loadC18JSON[struct {
		SchemaVersion string   `json:"schema_version"`
		Task          string   `json:"task"`
		Requirement   string   `json:"requirement"`
		Invariants    []string `json:"invariants"`
	}](t, "expected-output/timeline-index-outcomes.json")
	if exp.Task != "C18" || exp.Requirement != "F12" {
		t.Fatalf("unexpected C18 expected output metadata: %+v", exp)
	}
}

func TestC18DuplicateAndReorderedAnalysisDeduplication(t *testing.T) {
	ctx := context.Background()
	env := setupC18Env(t)

	dupFx := loadC18JSON[struct {
		SchemaVersion         string `json:"schema_version"`
		CaseID                string `json:"case_id"`
		EvidenceID            string `json:"evidence_id"`
		AnalyzerID            string `json:"analyzer_id"`
		Provider              string `json:"provider"`
		MediaType             string `json:"media_type"`
		Payload               string `json:"payload"`
		ExpectedUniqueEntries int    `json:"expected_unique_entries"`
	}](t, "positive/duplicate-reordered-analysis.json")

	blobPath, sealedSHA, sealedSize := sealPayloadForC18(
		t, env.qDir, env.sealStore, env.sDir,
		dupFx.CaseID, dupFx.EvidenceID, dupFx.MediaType, dupFx.Payload,
	)

	// Run analysis #1 -> derive artifact #1 -> index into timeline.
	run1, err := env.sandbox.RunIsolated(ctx, analyzers.IsolatedRunRequest{
		RunID:      "run-dup-1",
		CaseID:     dupFx.CaseID,
		EvidenceID: dupFx.EvidenceID,
		AnalyzerID: dupFx.AnalyzerID,
		Provider:   dupFx.Provider,
	})
	if err != nil {
		t.Fatalf("run1: %v", err)
	}
	art1, err := env.artifactStore.DeriveFromIsolatedRun(ctx, env.sealStore, env.sDir, run1, artifacts.DeriveRequest{
		OperationID: "op-derive-dup-1",
		ArtifactID:  "art-dup-1",
		CaseID:      dupFx.CaseID,
		Provider:    dupFx.Provider,
	})
	if err != nil {
		t.Fatalf("derive art1: %v", err)
	}
	out1, err := env.indexStore.IndexDerivedArtifact(ctx, env.sealStore, env.sDir, env.artifactStore, env.aDir, timeline.IndexDerivedRequest{
		SchemaVersion: "1",
		OperationID:   "op-idx-dup-1",
		CaseID:        dupFx.CaseID,
		ArtifactID:    art1.ArtifactID,
		Provider:      dupFx.Provider,
	})
	if err != nil {
		t.Fatalf("index art1: %v", err)
	}
	if out1.InsertedCount != dupFx.ExpectedUniqueEntries || out1.DeduplicatedCount != 0 || out1.TotalCaseEntries != dupFx.ExpectedUniqueEntries {
		t.Fatalf("unexpected outcome for first pass: %+v", out1)
	}

	// Run analysis #2 (different RunID & ArtifactID, same sealed evidence) -> MUST NOT duplicate timeline entries!
	run2, err := env.sandbox.RunIsolated(ctx, analyzers.IsolatedRunRequest{
		RunID:      "run-dup-2",
		CaseID:     dupFx.CaseID,
		EvidenceID: dupFx.EvidenceID,
		AnalyzerID: dupFx.AnalyzerID,
		Provider:   dupFx.Provider,
	})
	if err != nil {
		t.Fatalf("run2: %v", err)
	}
	art2, err := env.artifactStore.DeriveFromIsolatedRun(ctx, env.sealStore, env.sDir, run2, artifacts.DeriveRequest{
		OperationID: "op-derive-dup-2",
		ArtifactID:  "art-dup-2",
		CaseID:      dupFx.CaseID,
		Provider:    dupFx.Provider,
	})
	if err != nil {
		t.Fatalf("derive art2: %v", err)
	}
	out2, err := env.indexStore.IndexDerivedArtifact(ctx, env.sealStore, env.sDir, env.artifactStore, env.aDir, timeline.IndexDerivedRequest{
		SchemaVersion: "1",
		OperationID:   "op-idx-dup-2",
		CaseID:        dupFx.CaseID,
		ArtifactID:    art2.ArtifactID,
		Provider:      dupFx.Provider,
	})
	if err != nil {
		t.Fatalf("index art2: %v", err)
	}
	if out2.InsertedCount != 0 || out2.DeduplicatedCount != dupFx.ExpectedUniqueEntries || out2.TotalCaseEntries != dupFx.ExpectedUniqueEntries {
		t.Fatalf("duplicate analysis created duplicate entries! outcome=%+v", out2)
	}

	entries, err := env.indexStore.ListEntries(dupFx.CaseID)
	if err != nil || len(entries) != dupFx.ExpectedUniqueEntries {
		t.Fatalf("ListEntries mismatch: len=%d err=%v", len(entries), err)
	}
	for _, entry := range entries {
		if len(entry.ObservedArtifactIDs) != 2 {
			t.Fatalf("expected entry %s observed in both artifacts, got %v", entry.EventIdentity, entry.ObservedArtifactIDs)
		}
	}

	t.Run("reordered-analysis-converges-to-identical-identities-and-sort-order", func(t *testing.T) {
		ordFx := loadC18JSON[struct {
			SchemaVersion       string                     `json:"schema_version"`
			CaseID              string                     `json:"case_id"`
			EvidenceID          string                     `json:"evidence_id"`
			ArtifactID          string                     `json:"artifact_id"`
			ReorderedArtifactID string                     `json:"reordered_artifact_id"`
			ToolVersion         string                     `json:"tool_version"`
			Records             []timeline.IndexableRecord `json:"records"`
		}](t, "positive/multi-zone-timeline-ordering.json")

		_, ordSHA, ordSize := sealPayloadForC18(t, env.qDir, env.sealStore, env.sDir, ordFx.CaseID, ordFx.EvidenceID, "application/json", "reordered-synthetic")
		cfgHash := analyzers.ConfigDigest("json", ordFx.ToolVersion, analyzers.DefaultParseOptions())

		// Forward ingestion.
		fwdOut, err := env.indexStore.IndexRecords(ctx, env.sealStore, env.sDir, timeline.IndexRecordsRequest{
			SchemaVersion: "1",
			OperationID:   "op-ord-fwd",
			CaseID:        ordFx.CaseID,
			EvidenceID:    ordFx.EvidenceID,
			ArtifactID:    ordFx.ArtifactID,
			InputHashes:   []string{ordSHA},
			ToolVersion:   ordFx.ToolVersion,
			ConfigHash:    cfgHash,
			Records:       ordFx.Records,
		})
		if err != nil || fwdOut.InsertedCount != 3 {
			t.Fatalf("forward index failed: out=%+v err=%v", fwdOut, err)
		}

		// Reverse record order + new ArtifactID into same store -> zero duplicates!
		reversed := make([]timeline.IndexableRecord, len(ordFx.Records))
		for i := range ordFx.Records {
			reversed[i] = ordFx.Records[len(ordFx.Records)-1-i]
		}
		revOut, err := env.indexStore.IndexRecords(ctx, env.sealStore, env.sDir, timeline.IndexRecordsRequest{
			SchemaVersion: "1",
			OperationID:   "op-ord-rev",
			CaseID:        ordFx.CaseID,
			EvidenceID:    ordFx.EvidenceID,
			ArtifactID:    ordFx.ReorderedArtifactID,
			InputHashes:   []string{ordSHA},
			ToolVersion:   ordFx.ToolVersion,
			ConfigHash:    cfgHash,
			Records:       reversed,
		})
		if err != nil {
			t.Fatalf("reverse index failed: %v", err)
		}
		if revOut.InsertedCount != 0 || revOut.DeduplicatedCount != 3 || revOut.TotalCaseEntries != 3 {
			t.Fatalf("reordered analysis produced duplicate entries! out=%+v", revOut)
		}

		// Also ingest reversed-only into a fresh independent store and compare full sorted output.
		freshIdx, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: t.TempDir(), SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		defer freshIdx.Close()
		if _, err := freshIdx.IndexRecords(ctx, env.sealStore, env.sDir, timeline.IndexRecordsRequest{
			SchemaVersion: "1",
			OperationID:   "op-fresh-rev",
			CaseID:        ordFx.CaseID,
			EvidenceID:    ordFx.EvidenceID,
			ArtifactID:    ordFx.ReorderedArtifactID,
			InputHashes:   []string{ordSHA},
			ToolVersion:   ordFx.ToolVersion,
			ConfigHash:    cfgHash,
			Records:       reversed,
		}); err != nil {
			t.Fatal(err)
		}

		listMain, _ := env.indexStore.ListEntries(ordFx.CaseID)
		listFresh, _ := freshIdx.ListEntries(ordFx.CaseID)
		if len(listMain) != 3 || len(listFresh) != 3 {
			t.Fatalf("unexpected lengths: main=%d fresh=%d", len(listMain), len(listFresh))
		}
		for i := range listMain {
			if listMain[i].EventIdentity != listFresh[i].EventIdentity {
				t.Fatalf("order/identity mismatch at [%d]: main=%s fresh=%s", i, listMain[i].EventIdentity, listFresh[i].EventIdentity)
			}
		}
		// DST ambiguous event must remain explicit (last after exact UTC timestamps) with NormalizedTimestamp == "".
		if listMain[2].Time.TimezoneStatus != timeline.StatusDSTAmbiguous || listMain[2].Time.NormalizedTimestamp != "" {
			t.Fatalf("expected explicit dst_ambiguous preserved, got %+v", listMain[2].Time)
		}

		ordBlob := filepath.Join(env.sDir, "blobs", "sha256", ordSHA[:2], ordSHA+".blob")
		if _, statErr := os.Stat(ordBlob); statErr == nil {
			assertSealedBlobUnchangedC18(t, ordBlob, ordSHA, ordSize)
		}
	})

	assertSealedBlobUnchangedC18(t, blobPath, sealedSHA, sealedSize)
}

func TestC18NegativeCasesAndBoundaryChecks(t *testing.T) {
	ctx := context.Background()
	env := setupC18Env(t)

	missingFx := loadC18JSON[timeline.IndexDerivedRequest](t, "invalid/missing-derived-prerequisite.json")
	unavailFx := loadC18JSON[timeline.IndexDerivedRequest](t, "invalid/unavailable-provider.json")
	malformedFx := loadC18JSON[timeline.IndexRecordsRequest](t, "invalid/malformed-records.json")

	t.Run("missing-derived-prerequisite", func(t *testing.T) {
		_, err := env.indexStore.IndexDerivedArtifact(ctx, env.sealStore, env.sDir, env.artifactStore, env.aDir, missingFx)
		if !errors.Is(err, timeline.ErrMissingPrerequisite) {
			t.Fatalf("expected ErrMissingPrerequisite, got %v", err)
		}
	})

	t.Run("unavailable-provider", func(t *testing.T) {
		_, err := env.indexStore.IndexDerivedArtifact(ctx, env.sealStore, env.sDir, env.artifactStore, env.aDir, unavailFx)
		if !errors.Is(err, timeline.ErrUnavailableProvider) {
			t.Fatalf("expected ErrUnavailableProvider, got %v", err)
		}
	})

	t.Run("malformed-empty-records-and-bad-timestamp", func(t *testing.T) {
		malformedFx.InputHashes = []string{strings.Repeat("a", 64)}
		malformedFx.ConfigHash = strings.Repeat("b", 64)
		if _, err := env.indexStore.IndexRecords(ctx, nil, "", malformedFx); !errors.Is(err, timeline.ErrMalformedPayload) {
			t.Fatalf("expected ErrMalformedPayload for empty records, got %v", err)
		}

		badTS := malformedFx
		badTS.Records = []timeline.IndexableRecord{{SourceLine: 1, Timestamp: "invalid-ts-value"}}
		if _, err := env.indexStore.IndexRecords(ctx, nil, "", badTS); !errors.Is(err, timeline.ErrMalformedTimestamp) {
			t.Fatalf("expected ErrMalformedTimestamp, got %v", err)
		}
	})

	t.Run("unsupported-version-traversal-symlink-and-locks", func(t *testing.T) {
		if _, err := env.indexStore.IndexRecords(ctx, nil, "", timeline.IndexRecordsRequest{
			SchemaVersion: "99",
			CaseID:        "case-neg",
			EvidenceID:    "ev-neg",
			ArtifactID:    "art-neg",
		}); !errors.Is(err, timeline.ErrUnsupportedVersion) {
			t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
		}

		if _, err := env.indexStore.ListEntries("../escape"); !errors.Is(err, timeline.ErrPathTraversal) {
			t.Fatalf("expected ErrPathTraversal, got %v", err)
		}

		symParent := t.TempDir()
		realTarget := t.TempDir()
		symRoot := filepath.Join(symParent, "idx-link")
		if err := os.Symlink(realTarget, symRoot); err == nil {
			if _, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: symRoot}); !errors.Is(err, timeline.ErrSymlinkRejected) {
				t.Fatalf("expected ErrSymlinkRejected, got %v", err)
			}
		}

		if _, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: env.idxDir}); !errors.Is(err, timeline.ErrIndexLockBusy) {
			t.Fatalf("expected ErrIndexLockBusy, got %v", err)
		}
	})

	t.Run("idempotent-replay-conflict-disk-full-and-closed", func(t *testing.T) {
		validReq := timeline.IndexRecordsRequest{
			SchemaVersion: "1",
			OperationID:   "op-idemp-1",
			CaseID:        "case-c18-idemp",
			EvidenceID:    "ev-c18-idemp",
			ArtifactID:    "art-c18-idemp",
			InputHashes:   []string{strings.Repeat("a", 64)},
			ToolVersion:   "breachatlas-csv/1.0.0",
			ConfigHash:    strings.Repeat("b", 64),
			Records:       []timeline.IndexableRecord{{SourceLine: 1, Timestamp: "2026-10-15T08:14:22Z"}},
		}
		if _, err := env.indexStore.IndexRecords(ctx, nil, "", validReq); err != nil {
			t.Fatal(err)
		}
		replay, err := env.indexStore.IndexRecords(ctx, nil, "", validReq)
		if err != nil || !replay.IdempotentReplay {
			t.Fatalf("expected idempotent replay, got out=%+v err=%v", replay, err)
		}

		conflict := validReq
		conflict.Records = []timeline.IndexableRecord{{SourceLine: 2, Timestamp: "2026-10-15T09:00:00Z"}}
		if _, err := env.indexStore.IndexRecords(ctx, nil, "", conflict); !errors.Is(err, timeline.ErrIndexConflict) {
			t.Fatalf("expected ErrIndexConflict, got %v", err)
		}

		dfStore, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{
			RootDir: t.TempDir(),
			Faults:  timeline.IndexFaults{SimulateDiskFull: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dfStore.IndexRecords(ctx, nil, "", validReq); !errors.Is(err, timeline.ErrDiskFull) {
			t.Fatalf("expected ErrDiskFull, got %v", err)
		}
		_ = dfStore.Close()
		if _, err := dfStore.ListEntries("case-c18-idemp"); !errors.Is(err, timeline.ErrIndexStoreClosed) {
			t.Fatalf("expected ErrIndexStoreClosed, got %v", err)
		}
	})
}

func TestC18RestartRecoveryAndReingestion(t *testing.T) {
	ctx := context.Background()
	fx := loadC18JSON[struct {
		SchemaVersion string `json:"schema_version"`
		OperationID   string `json:"operation_id"`
		CaseID        string `json:"case_id"`
		EvidenceID    string `json:"evidence_id"`
		ArtifactID    string `json:"artifact_id"`
		MediaType     string `json:"media_type"`
		Payload       string `json:"payload"`
	}](t, "invalid/interrupted-index-commit.json")

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
	blobPath, sealedSHA, sealedSize := sealPayloadForC18(t, qDir, sealStore, sDir, fx.CaseID, fx.EvidenceID, fx.MediaType, fx.Payload)

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

	runRes, err := sb.RunIsolated(ctx, analyzers.IsolatedRunRequest{
		RunID:      "run-c18-rec-1",
		CaseID:     fx.CaseID,
		EvidenceID: fx.EvidenceID,
		AnalyzerID: analyzers.AnalyzerCSV,
	})
	if err != nil {
		t.Fatal(err)
	}
	derived, err := aStore.DeriveFromIsolatedRun(ctx, sealStore, sDir, runRes, artifacts.DeriveRequest{
		OperationID: "op-derive-rec-1",
		ArtifactID:  fx.ArtifactID,
		CaseID:      fx.CaseID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Step 1: Index initial batch cleanly.
	idx1, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: idxDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = idx1.IndexRecords(ctx, sealStore, sDir, timeline.IndexRecordsRequest{
		SchemaVersion: "1",
		OperationID:   "op-initial-1",
		CaseID:        fx.CaseID,
		EvidenceID:    fx.EvidenceID,
		ArtifactID:    "art-initial-1",
		InputHashes:   []string{sealedSHA},
		ToolVersion:   analyzers.ToolVersionCSV,
		ConfigHash:    derived.ConfigHash,
		Records: []timeline.IndexableRecord{
			{SourceLine: 99, Timestamp: "2026-10-15T08:00:00Z", EventType: "initial_boot", Summary: "prior committed entry"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = idx1.Close()

	// Step 2: Reopen with FailAfterStageBeforeCommit and interrupt derived artifact indexing.
	idxCrash, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{
		RootDir: idxDir,
		SyncDir: true,
		Faults:  timeline.IndexFaults{FailAfterStageBeforeCommit: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = idxCrash.IndexDerivedArtifact(ctx, sealStore, sDir, aStore, aDir, timeline.IndexDerivedRequest{
		SchemaVersion: "1",
		OperationID:   fx.OperationID,
		CaseID:        fx.CaseID,
		ArtifactID:    fx.ArtifactID,
	})
	if !errors.Is(err, timeline.ErrInterrupted) {
		t.Fatalf("expected ErrInterrupted, got %v", err)
	}
	// Incomplete commit must NOT change visible entry count.
	beforeList, _ := idxCrash.ListEntries(fx.CaseID)
	if len(beforeList) != 1 {
		t.Fatalf("expected prior 1 entry only, got %d", len(beforeList))
	}
	_ = idxCrash.Close()

	// Step 3: Restart cleanly, verify staging cleanup & preserved prior entry, complete indexing & repeat without duplicates.
	idxRecovered, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: idxDir, SyncDir: true})
	if err != nil {
		t.Fatalf("restart open failed: %v", err)
	}
	defer idxRecovered.Close()

	rec := idxRecovered.LastRecoveryReport()
	if len(rec.CleanedStagingFiles) == 0 || rec.RecoveredCases != 1 || rec.RecoveredEntries != 1 {
		t.Fatalf("unexpected recovery report: %+v", rec)
	}

	out, err := idxRecovered.IndexDerivedArtifact(ctx, sealStore, sDir, aStore, aDir, timeline.IndexDerivedRequest{
		SchemaVersion: "1",
		OperationID:   fx.OperationID,
		CaseID:        fx.CaseID,
		ArtifactID:    fx.ArtifactID,
	})
	if err != nil || out.InsertedCount != 1 || out.TotalCaseEntries != 2 {
		t.Fatalf("post-restart indexing failed: out=%+v err=%v", out, err)
	}

	// Re-index same records under a different OperationID & ArtifactID -> zero duplicates!
	outRepeat, err := idxRecovered.IndexDerivedArtifact(ctx, sealStore, sDir, aStore, aDir, timeline.IndexDerivedRequest{
		SchemaVersion: "1",
		OperationID:   "op-repeat-after-restart",
		CaseID:        fx.CaseID,
		ArtifactID:    fx.ArtifactID,
	})
	if err != nil || outRepeat.InsertedCount != 0 || outRepeat.DeduplicatedCount != 1 || outRepeat.TotalCaseEntries != 2 {
		t.Fatalf("repeat after restart duplicated entries: out=%+v err=%v", outRepeat, err)
	}

	_ = aStore.Close()
	_ = sealStore.Close()
	assertSealedBlobUnchangedC18(t, blobPath, sealedSHA, sealedSize)
}

func TestC18ConcurrentIndexingAndRace(t *testing.T) {
	ctx := context.Background()
	idxStore, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer idxStore.Close()

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	cfgHash := strings.Repeat("c", 64)
	inHash := strings.Repeat("d", 64)

	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Half reverse order, half forward order; all describe the same 2 sealed records.
			recs := []timeline.IndexableRecord{
				{SourceLine: 1, Timestamp: "2026-10-15T08:14:22+03:30", EventType: "login", Fields: map[string]any{"user": "alice"}},
				{SourceLine: 2, Timestamp: "2026-10-15T08:15:00+03:30", EventType: "logout", Fields: map[string]any{"user": "alice"}},
			}
			if i%2 == 1 {
				recs[0], recs[1] = recs[1], recs[0]
			}
			if _, err := idxStore.IndexRecords(ctx, nil, "", timeline.IndexRecordsRequest{
				SchemaVersion: "1",
				OperationID:   fmt.Sprintf("op-race-%d", i),
				CaseID:        "case-c18-race",
				EvidenceID:    "ev-c18-race",
				ArtifactID:    fmt.Sprintf("art-race-%d", i),
				InputHashes:   []string{inHash},
				ToolVersion:   analyzers.ToolVersionCSV,
				ConfigHash:    cfgHash,
				Records:       recs,
			}); err != nil {
				errs <- err
				return
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent timeline indexing failed: %v", err)
	}

	entries, err := idxStore.ListEntries("case-c18-race")
	if err != nil || len(entries) != 2 {
		t.Fatalf("expected exactly 2 deduplicated entries across %d concurrent runs, got len=%d err=%v", workers, len(entries), err)
	}
}

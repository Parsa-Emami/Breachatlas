package tests_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

type c14Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c14PositiveFixture struct {
	SchemaVersion          string `json:"schema_version"`
	CaseID                 string `json:"case_id"`
	EvidenceID             string `json:"evidence_id"`
	AnalyzerID             string `json:"analyzer_id"`
	Provider               string `json:"provider"`
	MediaType              string `json:"media_type"`
	Payload                string `json:"payload"`
	ExpectedRecordCount    int    `json:"expected_record_count"`
	ExpectedFirstTimestamp string `json:"expected_first_timestamp"`
}

type c14InvalidFixture struct {
	SchemaVersion   string `json:"schema_version"`
	CaseID          string `json:"case_id"`
	EvidenceID      string `json:"evidence_id"`
	AnalyzerID      string `json:"analyzer_id"`
	ToolVersion     string `json:"tool_version"`
	Provider        string `json:"provider"`
	Payload         string `json:"payload"`
	NonExecuting    bool   `json:"non_executing"`
	Executing       bool   `json:"executing"`
	ReadOnly        bool   `json:"read_only"`
	ExpectedFailure string `json:"expected_failure"`
}

type stubMockAnalyzer struct {
	desc analyzers.Descriptor
}

func (s *stubMockAnalyzer) Descriptor() analyzers.Descriptor {
	return s.desc
}

func (s *stubMockAnalyzer) Parse(_ context.Context, _ io.Reader, _ analyzers.ParseOptions) (*analyzers.ParseOutput, error) {
	return &analyzers.ParseOutput{AnalyzerID: s.desc.ID}, nil
}

func getC14FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "fixtures", "breachatlas", "C14")
	if filepath.Base(wd) != "tests" {
		dir = filepath.Join(wd, "tests", "fixtures", "breachatlas", "C14")
	}
	return dir
}

func sealPayloadForAnalyzerTests(t *testing.T, quarantineDir string, sealStore *evidence.SealStore, sealDir, caseID, evidenceID, mediaType, payload string) (string, [32]byte) {
	t.Helper()
	qCfg := evidence.UploadConfig{QuarantineDir: quarantineDir, BufferSize: 64, SyncDir: true}
	payloadBytes := []byte(payload)
	sum := sha256.Sum256(payloadBytes)
	size := int64(len(payloadBytes))

	q, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-" + evidenceID,
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		MediaType:     mediaType,
		Filename:      evidenceID + ".dat",
		ExpectedSize:  &size,
		Body:          strings.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("quarantine upload %s: %v", evidenceID, err)
	}

	m, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
		OperationID:    "seal-" + evidenceID,
		Quarantined:    q,
		ExpectedSHA256: hex.EncodeToString(sum[:]),
		AcquiredAt:     "2026-11-11T09:05:00Z",
		CustodyRoot:    custody.GenesisPrevHash,
	})
	if err != nil {
		t.Fatalf("seal %s: %v", evidenceID, err)
	}

	blobPath := filepath.Join(sealDir, filepath.FromSlash(m.BlobRelPath))
	raw, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read sealed blob %s: %v", blobPath, err)
	}
	return blobPath, sha256.Sum256(raw)
}

func TestC14FixturesProvenanceAndAllowlistedAnalysis(t *testing.T) {
	fixturesDir := getC14FixturesDir(t)

	// 1. Verify C14 provenance & Apache-2.0 hashes
	provRaw, err := os.ReadFile(filepath.Join(fixturesDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read provenance.json: %v", err)
	}
	var prov c14Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatalf("unmarshal provenance.json: %v", err)
	}
	if prov.License != "Apache-2.0" {
		t.Fatalf("expected Apache-2.0 license, got %q", prov.License)
	}
	if len(prov.SHA256) < 9 {
		t.Fatalf("expected at least 9 hashed fixtures, got %d", len(prov.SHA256))
	}
	for relPath, expectedHash := range prov.SHA256 {
		content, err := os.ReadFile(filepath.Join(fixturesDir, relPath))
		if err != nil {
			t.Fatalf("read fixture %s: %v", relPath, err)
		}
		sum := sha256.Sum256(content)
		if got := hex.EncodeToString(sum[:]); got != expectedHash {
			t.Fatalf("fixture %s sha256 mismatch: got %s, want %s", relPath, got, expectedHash)
		}
	}

	// Verify expected-output/outcomes.json
	outcomesRaw, err := os.ReadFile(filepath.Join(fixturesDir, "expected-output", "outcomes.json"))
	if err != nil {
		t.Fatalf("read expected-output/outcomes.json: %v", err)
	}
	var outcomes map[string]any
	if err := json.Unmarshal(outcomesRaw, &outcomes); err != nil {
		t.Fatalf("unmarshal outcomes.json: %v", err)
	}

	// 2. Setup SealStore and verify only shipped non-executing CSV & JSON analyzers are enabled
	rootTmp := t.TempDir()
	quarantineDir := filepath.Join(rootTmp, "quarantine")
	sealDir := filepath.Join(rootTmp, "sealstore")

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("open seal store: %v", err)
	}

	reg, err := analyzers.NewRegistry(analyzers.RegistryConfig{
		SealStore:   sealStore,
		SealRootDir: sealDir,
		Provider:    "local",
	})
	if err != nil {
		_ = sealStore.Close()
		t.Fatalf("new analyzer registry: %v", err)
	}

	descs := reg.Allowlisted()
	if len(descs) != 2 || descs[0].ID != analyzers.AnalyzerCSV || descs[1].ID != analyzers.AnalyzerJSON {
		_ = sealStore.Close()
		t.Fatalf("expected strictly [csv, json] allowlisted, got %+v", descs)
	}
	for _, d := range descs {
		if !d.NonExecuting || d.Executing || !d.ReadOnly || d.ConfigDigest == "" || d.Version == "" {
			_ = sealStore.Close()
			t.Fatalf("invalid descriptor invariant: %+v", d)
		}
	}

	// 3. Run both positive CSV and JSON fixtures against real sealed evidence
	posFiles := []string{
		"positive/valid-csv-timeline.json",
		"positive/valid-json-events.json",
	}
	type recordedRun struct {
		fix      c14PositiveFixture
		blobPath string
		blobSHA  [32]byte
		firstRes *analyzers.AnalysisResult
	}
	var runs []recordedRun

	ctx := context.Background()
	for _, rel := range posFiles {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, rel))
		if err != nil {
			_ = sealStore.Close()
			t.Fatalf("read %s: %v", rel, err)
		}
		var fix c14PositiveFixture
		if err := json.Unmarshal(raw, &fix); err != nil {
			_ = sealStore.Close()
			t.Fatalf("unmarshal %s: %v", rel, err)
		}

		blobPath, blobSHA := sealPayloadForAnalyzerTests(
			t, quarantineDir, sealStore, sealDir, fix.CaseID, fix.EvidenceID, fix.MediaType, fix.Payload,
		)

		res, err := reg.RunAnalysis(ctx, analyzers.RunRequest{
			AnalyzerID: fix.AnalyzerID,
			CaseID:     fix.CaseID,
			EvidenceID: fix.EvidenceID,
			Provider:   fix.Provider,
		})
		if err != nil {
			_ = sealStore.Close()
			t.Fatalf("%s RunAnalysis failed: %v", rel, err)
		}
		if res.RecordCount != fix.ExpectedRecordCount || len(res.Records) != fix.ExpectedRecordCount {
			_ = sealStore.Close()
			t.Fatalf("%s expected %d records, got %d", rel, fix.ExpectedRecordCount, res.RecordCount)
		}
		if res.Records[0].Timestamp != fix.ExpectedFirstTimestamp {
			_ = sealStore.Close()
			t.Fatalf("%s expected first timestamp %q, got %q", rel, fix.ExpectedFirstTimestamp, res.Records[0].Timestamp)
		}
		if !res.NonExecuting || !res.ReadOnly || res.InputSHA256 != hex.EncodeToString(blobSHA[:]) {
			_ = sealStore.Close()
			t.Fatalf("%s metadata mismatch: %+v", rel, res)
		}
		assertBlobUnchanged(t, blobPath, blobSHA)

		runs = append(runs, recordedRun{fix: fix, blobPath: blobPath, blobSHA: blobSHA, firstRes: res})
	}

	// 4. Simulate engine restart: close SealStore, reopen, create fresh Registry, repeat & verify determinism
	if err := sealStore.Close(); err != nil {
		t.Fatalf("close seal store: %v", err)
	}
	sealStoreRestarted, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("reopen seal store: %v", err)
	}
	defer sealStoreRestarted.Close()

	regRestarted, err := analyzers.NewRegistry(analyzers.RegistryConfig{
		SealStore:   sealStoreRestarted,
		SealRootDir: sealDir,
	})
	if err != nil {
		t.Fatalf("recreate analyzer registry after restart: %v", err)
	}

	restartedDescs := regRestarted.Allowlisted()
	if len(restartedDescs) != 2 || restartedDescs[0].ConfigDigest != descs[0].ConfigDigest || restartedDescs[1].ConfigDigest != descs[1].ConfigDigest {
		t.Fatalf("allowlist/config digests changed across restart: before=%+v after=%+v", descs, restartedDescs)
	}

	for _, run := range runs {
		res2, err := regRestarted.RunAnalysis(ctx, analyzers.RunRequest{
			AnalyzerID: run.fix.AnalyzerID,
			CaseID:     run.fix.CaseID,
			EvidenceID: run.fix.EvidenceID,
			Provider:   run.fix.Provider,
		})
		if err != nil {
			t.Fatalf("post-restart RunAnalysis failed for %s: %v", run.fix.EvidenceID, err)
		}
		if res2.InputSHA256 != run.firstRes.InputSHA256 ||
			res2.ToolVersion != run.firstRes.ToolVersion ||
			res2.ConfigDigest != run.firstRes.ConfigDigest ||
			res2.RecordCount != run.firstRes.RecordCount {
			t.Fatalf("post-restart non-deterministic result for %s: before=%+v after=%+v", run.fix.EvidenceID, run.firstRes, res2)
		}
		assertBlobUnchanged(t, run.blobPath, run.blobSHA)
	}
}

func TestC14NegativeCasesAndContractEnforcement(t *testing.T) {
	fixturesDir := getC14FixturesDir(t)
	rootTmp := t.TempDir()
	quarantineDir := filepath.Join(rootTmp, "quarantine")
	sealDir := filepath.Join(rootTmp, "sealstore")

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("open seal store: %v", err)
	}
	defer sealStore.Close()

	// Seed sealed blobs matching fixture IDs
	blobPathCSV, blobSHACSV := sealPayloadForAnalyzerTests(
		t, quarantineDir, sealStore, sealDir,
		"CASE-C14-001", "EVID-C14-CSV-001", "text/csv",
		"timestamp,host\n2026-11-11T09:00:00Z,web-01\n",
	)
	blobPathJSON, blobSHAJSON := sealPayloadForAnalyzerTests(
		t, quarantineDir, sealStore, sealDir,
		"CASE-C14-001", "EVID-C14-JSON-001", "application/json",
		`{"timestamp":"2026-11-11T09:10:00Z","event":"ok"}`+"\n",
	)

	// Reject unavailable provider on NewRegistry
	if _, err := analyzers.NewRegistry(analyzers.RegistryConfig{
		SealStore:   sealStore,
		SealRootDir: sealDir,
		Provider:    "remote-saas",
	}); !errors.Is(err, analyzers.ErrUnavailableProvider) {
		t.Fatalf("expected ErrUnavailableProvider on NewRegistry, got %v", err)
	}

	reg, err := analyzers.NewRegistry(analyzers.RegistryConfig{
		SealStore:   sealStore,
		SealRootDir: sealDir,
	})
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	ctx := context.Background()

	// 1. invalid/unlisted-analyzer.json
	rawUnlisted, _ := os.ReadFile(filepath.Join(fixturesDir, "invalid/unlisted-analyzer.json"))
	var fixUnlisted c14InvalidFixture
	_ = json.Unmarshal(rawUnlisted, &fixUnlisted)
	if _, err := reg.RunAnalysis(ctx, analyzers.RunRequest{
		AnalyzerID: fixUnlisted.AnalyzerID,
		CaseID:     fixUnlisted.CaseID,
		EvidenceID: fixUnlisted.EvidenceID,
		Provider:   fixUnlisted.Provider,
	}); !errors.Is(err, analyzers.ErrAnalyzerNotAllowlisted) {
		t.Fatalf("expected ErrAnalyzerNotAllowlisted, got %v", err)
	}

	// 2. invalid/executing-parser-rejected.json
	rawExec, _ := os.ReadFile(filepath.Join(fixturesDir, "invalid/executing-parser-rejected.json"))
	var fixExec c14InvalidFixture
	_ = json.Unmarshal(rawExec, &fixExec)
	if err := reg.Register(&stubMockAnalyzer{
		desc: analyzers.Descriptor{
			ID:           fixExec.AnalyzerID,
			Version:      fixExec.ToolVersion,
			NonExecuting: fixExec.NonExecuting,
			Executing:    fixExec.Executing,
			ReadOnly:     fixExec.ReadOnly,
		},
	}); !errors.Is(err, analyzers.ErrExecutingParserForbidden) {
		t.Fatalf("expected ErrExecutingParserForbidden on Register, got %v", err)
	}

	// Also reject registering non-allowlisted custom parser even if non-executing
	if err := reg.Register(&stubMockAnalyzer{
		desc: analyzers.Descriptor{
			ID:           "yaml-custom",
			Version:      "1.0.0",
			NonExecuting: true,
			Executing:    false,
			ReadOnly:     true,
		},
	}); !errors.Is(err, analyzers.ErrAnalyzerNotAllowlisted) {
		t.Fatalf("expected ErrAnalyzerNotAllowlisted for custom yaml-custom, got %v", err)
	}

	// 3. invalid/unavailable-provider.json
	rawProv, _ := os.ReadFile(filepath.Join(fixturesDir, "invalid/unavailable-provider.json"))
	var fixProv c14InvalidFixture
	_ = json.Unmarshal(rawProv, &fixProv)
	if _, err := reg.RunAnalysis(ctx, analyzers.RunRequest{
		AnalyzerID: fixProv.AnalyzerID,
		CaseID:     fixProv.CaseID,
		EvidenceID: fixProv.EvidenceID,
		Provider:   fixProv.Provider,
	}); !errors.Is(err, analyzers.ErrUnavailableProvider) {
		t.Fatalf("expected ErrUnavailableProvider, got %v", err)
	}

	// 4. invalid/malformed-csv.json and invalid/malformed-json.json
	for _, tc := range []string{"invalid/malformed-csv.json", "invalid/malformed-json.json"} {
		raw, _ := os.ReadFile(filepath.Join(fixturesDir, tc))
		var fix c14InvalidFixture
		_ = json.Unmarshal(raw, &fix)
		_, gotErr := reg.ParseStream(ctx, fix.AnalyzerID, fix.Provider, strings.NewReader(fix.Payload), analyzers.DefaultParseOptions())
		if !errors.Is(gotErr, analyzers.ErrMalformedInput) {
			t.Fatalf("%s: expected ErrMalformedInput, got %v", tc, gotErr)
		}
	}

	// 5. invalid/missing-sealed-prerequisite.json
	rawMissing, _ := os.ReadFile(filepath.Join(fixturesDir, "invalid/missing-sealed-prerequisite.json"))
	var fixMissing c14InvalidFixture
	_ = json.Unmarshal(rawMissing, &fixMissing)
	if _, err := reg.RunAnalysis(ctx, analyzers.RunRequest{
		AnalyzerID: fixMissing.AnalyzerID,
		CaseID:     fixMissing.CaseID,
		EvidenceID: fixMissing.EvidenceID,
		Provider:   fixMissing.Provider,
	}); !errors.Is(err, analyzers.ErrMissingPrerequisite) {
		t.Fatalf("expected ErrMissingPrerequisite for unsealed evidence, got %v", err)
	}

	// 6. Missing SealStore prerequisite & path traversal checks
	regNoStore, err := analyzers.NewRegistry(analyzers.RegistryConfig{})
	if err != nil {
		t.Fatalf("new stream-only registry: %v", err)
	}
	if _, err := regNoStore.RunAnalysis(ctx, analyzers.RunRequest{
		AnalyzerID: analyzers.AnalyzerCSV,
		CaseID:     "CASE-C14-001",
		EvidenceID: "EVID-C14-CSV-001",
	}); !errors.Is(err, analyzers.ErrMissingPrerequisite) {
		t.Fatalf("expected ErrMissingPrerequisite without SealStore, got %v", err)
	}
	if _, err := reg.RunAnalysis(ctx, analyzers.RunRequest{
		AnalyzerID: analyzers.AnalyzerCSV,
		CaseID:     "../escape",
		EvidenceID: "EVID-C14-CSV-001",
	}); !errors.Is(err, analyzers.ErrPathTraversal) {
		t.Fatalf("expected ErrPathTraversal for bad case_id, got %v", err)
	}

	assertBlobUnchanged(t, blobPathCSV, blobSHACSV)
	assertBlobUnchanged(t, blobPathJSON, blobSHAJSON)
}

func TestC14BoundedParsersNDJSONAndConcurrentReadOnlySafety(t *testing.T) {
	ctx := context.Background()
	reg, err := analyzers.NewRegistry(analyzers.RegistryConfig{})
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}

	// NDJSON (JSON Lines) parsing succeeds cleanly
	ndjson := "{\"timestamp\":\"2026-11-11T01:00:00Z\",\"ev\":\"one\"}\n{\"timestamp\":\"2026-11-11T01:05:00Z\",\"ev\":\"two\"}\n"
	out, err := reg.ParseStream(ctx, analyzers.AnalyzerJSON, "local", strings.NewReader(ndjson), analyzers.DefaultParseOptions())
	if err != nil {
		t.Fatalf("NDJSON ParseStream failed: %v", err)
	}
	if out.RecordCount != 2 || out.Records[1].Timestamp != "2026-11-11T01:05:00Z" {
		t.Fatalf("unexpected NDJSON parse result: %+v", out)
	}

	// Bounds & malformed parser edge cases
	smallOpts := analyzers.ParseOptions{
		MaxInputBytes:   32,
		MaxRecords:      2,
		MaxFieldsPerRow: 2,
		MaxJSONDepth:    3,
	}
	if _, err := reg.ParseStream(ctx, analyzers.AnalyzerCSV, "local", strings.NewReader("a,b\n"+strings.Repeat("x,y\n", 10)), smallOpts); !errors.Is(err, analyzers.ErrInputTooLarge) {
		t.Fatalf("expected ErrInputTooLarge for oversized stream, got %v", err)
	}
	if _, err := reg.ParseStream(ctx, analyzers.AnalyzerCSV, "local", strings.NewReader("a,b,c\n1,2,3\n"), smallOpts); !errors.Is(err, analyzers.ErrInputTooLarge) {
		t.Fatalf("expected ErrInputTooLarge for excessive CSV columns, got %v", err)
	}
	if _, err := reg.ParseStream(ctx, analyzers.AnalyzerCSV, "local", strings.NewReader("a,a\n1,2\n"), analyzers.DefaultParseOptions()); !errors.Is(err, analyzers.ErrMalformedInput) {
		t.Fatalf("expected ErrMalformedInput for duplicate CSV headers, got %v", err)
	}
	if _, err := reg.ParseStream(ctx, analyzers.AnalyzerCSV, "local", strings.NewReader("a,b\n"), analyzers.DefaultParseOptions()); !errors.Is(err, analyzers.ErrMalformedInput) {
		t.Fatalf("expected ErrMalformedInput for header-only CSV, got %v", err)
	}
	if _, err := reg.ParseStream(ctx, analyzers.AnalyzerJSON, "local", strings.NewReader(`{"a":{"b":{"c":{"d":1}}}}`), smallOpts); !errors.Is(err, analyzers.ErrMalformedInput) {
		t.Fatalf("expected ErrMalformedInput for deep JSON nesting, got %v", err)
	}
	if _, err := reg.ParseStream(ctx, analyzers.AnalyzerJSON, "local", strings.NewReader(`[{"a":1}] trailing`), analyzers.DefaultParseOptions()); !errors.Is(err, analyzers.ErrMalformedInput) {
		t.Fatalf("expected ErrMalformedInput for trailing JSON garbage, got %v", err)
	}

	// Concurrent read-only RunAnalysis against shared sealed blob
	rootTmp := t.TempDir()
	quarantineDir := filepath.Join(rootTmp, "q")
	sealDir := filepath.Join(rootTmp, "s")
	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sealDir, QuarantineDir: quarantineDir, SyncDir: true})
	if err != nil {
		t.Fatalf("open seal store: %v", err)
	}
	defer sealStore.Close()

	blobPath, blobSHA := sealPayloadForAnalyzerTests(
		t, quarantineDir, sealStore, sealDir,
		"CASE-C14-CONC", "EVID-C14-CONC", "text/csv",
		"timestamp,msg\n2026-11-11T12:00:00Z,ok\n",
	)
	concReg, err := analyzers.NewRegistry(analyzers.RegistryConfig{SealStore: sealStore, SealRootDir: sealDir})
	if err != nil {
		t.Fatalf("new conc registry: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := concReg.RunAnalysis(ctx, analyzers.RunRequest{
				AnalyzerID: analyzers.AnalyzerCSV,
				CaseID:     "CASE-C14-CONC",
				EvidenceID: "EVID-C14-CONC",
			})
			if err != nil {
				errs <- err
				return
			}
			if res.RecordCount != 1 {
				errs <- fmt.Errorf("expected 1 record, got %d", res.RecordCount)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	assertBlobUnchanged(t, blobPath, blobSHA)
}

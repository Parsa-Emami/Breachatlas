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
	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

type c15Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c15PositiveFixture struct {
	SchemaVersion          string `json:"schema_version"`
	RunID                  string `json:"run_id"`
	CaseID                 string `json:"case_id"`
	EvidenceID             string `json:"evidence_id"`
	AnalyzerID             string `json:"analyzer_id"`
	Provider               string `json:"provider"`
	MediaType              string `json:"media_type"`
	Payload                string `json:"payload"`
	ExpectedRecordCount    int    `json:"expected_record_count"`
	ExpectedNetworkBlocked bool   `json:"expected_network_blocked"`
	ExpectedReadOnly       bool   `json:"expected_read_only"`
}

type c15NetFixture struct {
	SchemaVersion   string `json:"schema_version"`
	RunID           string `json:"run_id"`
	CaseID          string `json:"case_id"`
	EvidenceID      string `json:"evidence_id"`
	AnalyzerID      string `json:"analyzer_id"`
	Provider        string `json:"provider"`
	TargetNetwork   string `json:"target_network"`
	TargetAddress   string `json:"target_address"`
	ExpectedFailure string `json:"expected_failure"`
}

type c15TimeoutFixture struct {
	SchemaVersion   string `json:"schema_version"`
	RunID           string `json:"run_id"`
	CaseID          string `json:"case_id"`
	EvidenceID      string `json:"evidence_id"`
	AnalyzerID      string `json:"analyzer_id"`
	Provider        string `json:"provider"`
	TimeoutMs       int    `json:"timeout_ms"`
	SimulatedHangMs int    `json:"simulated_hang_ms"`
	ExpectedFailure string `json:"expected_failure"`
}

type c15EscapeFixture struct {
	SchemaVersion   string `json:"schema_version"`
	RunID           string `json:"run_id"`
	CaseID          string `json:"case_id"`
	EvidenceID      string `json:"evidence_id"`
	AnalyzerID      string `json:"analyzer_id"`
	Provider        string `json:"provider"`
	EscapePath      string `json:"escape_path"`
	ExpectedFailure string `json:"expected_failure"`
}

type c15QuotaFixture struct {
	SchemaVersion       string `json:"schema_version"`
	RunID               string `json:"run_id"`
	CaseID              string `json:"case_id"`
	EvidenceID          string `json:"evidence_id"`
	AnalyzerID          string `json:"analyzer_id"`
	Provider            string `json:"provider"`
	ScratchLimitBytes   int64  `json:"scratch_limit_bytes"`
	AttemptedWriteBytes int64  `json:"attempted_write_bytes"`
	ExpectedFailure     string `json:"expected_failure"`
}

type c15MutationFixture struct {
	SchemaVersion   string `json:"schema_version"`
	RunID           string `json:"run_id"`
	CaseID          string `json:"case_id"`
	EvidenceID      string `json:"evidence_id"`
	AnalyzerID      string `json:"analyzer_id"`
	Provider        string `json:"provider"`
	MutationAttempt string `json:"mutation_attempt"`
	ExpectedFailure string `json:"expected_failure"`
}

type c15OrphanFixture struct {
	SchemaVersion                string   `json:"schema_version"`
	RunID                        string   `json:"run_id"`
	CaseID                       string   `json:"case_id"`
	EvidenceID                   string   `json:"evidence_id"`
	SimulatedAbandonedDirs       []string `json:"simulated_abandoned_directories"`
	ExpectedAction               string   `json:"expected_action"`
}

func getC15FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "fixtures", "breachatlas", "C15")
	if filepath.Base(wd) != "tests" {
		dir = filepath.Join(wd, "tests", "fixtures", "breachatlas", "C15")
	}
	return dir
}

func sealPayloadForC15(t *testing.T, quarantineDir string, sealStore *evidence.SealStore, sealDir, caseID, evidenceID, mediaType, payload string) (string, [32]byte) {
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

func setupC15Environment(t *testing.T) (*evidence.SealStore, *analyzers.Registry, *analyzers.Sandbox, string, string) {
	t.Helper()
	rootTmp := t.TempDir()
	quarantineDir := filepath.Join(rootTmp, "quarantine")
	sealDir := filepath.Join(rootTmp, "sealstore")
	scratchDir := filepath.Join(rootTmp, "scratch")

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

	box, err := analyzers.NewSandbox(reg, analyzers.DefaultSandboxConfig(scratchDir))
	if err != nil {
		_ = sealStore.Close()
		t.Fatalf("new sandbox: %v", err)
	}

	return sealStore, reg, box, sealDir, quarantineDir
}

// TestC15FixturesAndProvenance validates all C15 fixture files and hashes against provenance.json.
func TestC15FixturesAndProvenance(t *testing.T) {
	fixturesDir := getC15FixturesDir(t)

	provRaw, err := os.ReadFile(filepath.Join(fixturesDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read provenance.json: %v", err)
	}
	var prov c15Provenance
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

		var parsed any
		if err := json.Unmarshal(content, &parsed); err != nil {
			t.Fatalf("fixture %s is invalid JSON syntax: %v", relPath, err)
		}
	}

	// Verify isolation outcomes and invariants
	outcomesRaw, err := os.ReadFile(filepath.Join(fixturesDir, "expected-output", "isolation-outcomes.json"))
	if err != nil {
		t.Fatalf("read expected-output/isolation-outcomes.json: %v", err)
	}
	var outcomes struct {
		SchemaVersion string                    `json:"schema_version"`
		Cases         map[string]map[string]any `json:"cases"`
		Invariants    []string                  `json:"invariants"`
	}
	if err := json.Unmarshal(outcomesRaw, &outcomes); err != nil {
		t.Fatalf("unmarshal isolation-outcomes.json: %v", err)
	}
	if len(outcomes.Cases) < 8 {
		t.Fatalf("expected at least 8 outcome cases, got %d", len(outcomes.Cases))
	}
	if len(outcomes.Invariants) < 5 {
		t.Fatalf("expected at least 5 invariants, got %d", len(outcomes.Invariants))
	}
}

// TestC15ReadOnlyEvidenceIntegrity verifies O_RDONLY open, write attempt rejection, and post-analysis byte immutability.
func TestC15ReadOnlyEvidenceIntegrity(t *testing.T) {
	sealStore, _, box, sealDir, quarantineDir := setupC15Environment(t)
	defer sealStore.Close()

	fixturesDir := getC15FixturesDir(t)
	csvRaw, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "isolated-csv-analysis.json"))
	if err != nil {
		t.Fatalf("read positive csv fixture: %v", err)
	}
	var fix c15PositiveFixture
	if err := json.Unmarshal(csvRaw, &fix); err != nil {
		t.Fatalf("unmarshal positive csv fixture: %v", err)
	}

	blobPath, initialHash := sealPayloadForC15(t, quarantineDir, sealStore, sealDir, fix.CaseID, fix.EvidenceID, fix.MediaType, fix.Payload)

	// 1. Verify OpenEvidence strictly permits O_RDONLY and rejects any write or non-read-only flag
	fReadOnly, err := box.OpenEvidence(fix.CaseID, fix.EvidenceID, os.O_RDONLY)
	if err != nil {
		t.Fatalf("open read-only evidence failed: %v", err)
	}
	_ = fReadOnly.Close()

	// Load invalid/evidence-mutation-blocked.json fixture
	mutRaw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "evidence-mutation-blocked.json"))
	if err != nil {
		t.Fatalf("read evidence-mutation-blocked fixture: %v", err)
	}
	var mutFix c15MutationFixture
	if err := json.Unmarshal(mutRaw, &mutFix); err != nil {
		t.Fatalf("unmarshal evidence-mutation-blocked fixture: %v", err)
	}
	if mutFix.ExpectedFailure != "evidence_write_forbidden" {
		t.Fatalf("unexpected failure declaration in fixture: %s", mutFix.ExpectedFailure)
	}

	forbiddenFlags := []struct {
		name string
		flag int
	}{
		{"O_WRONLY", os.O_WRONLY},
		{"O_RDWR", os.O_RDWR},
		{"O_APPEND", os.O_APPEND},
		{"O_CREATE", os.O_CREATE},
		{"O_TRUNC", os.O_TRUNC},
		{"O_WRONLY|O_CREATE", os.O_WRONLY | os.O_CREATE},
		{"CustomNonReadOnlyFlag", 0x8000},
	}
	for _, tc := range forbiddenFlags {
		t.Run(tc.name, func(t *testing.T) {
			f, err := box.OpenEvidence(fix.CaseID, fix.EvidenceID, tc.flag)
			if f != nil {
				_ = f.Close()
				t.Fatalf("expected nil file for write flag %s", tc.name)
			}
			if !errors.Is(err, analyzers.ErrEvidenceWriteForbidden) {
				t.Fatalf("expected ErrEvidenceWriteForbidden for %s, got %v", tc.name, err)
			}
		})
	}

	// 2. Run isolated analysis and assert pre/post byte immutability
	res, err := box.RunIsolated(context.Background(), analyzers.IsolatedRunRequest{
		RunID:      fix.RunID,
		CaseID:     fix.CaseID,
		EvidenceID: fix.EvidenceID,
		AnalyzerID: fix.AnalyzerID,
		Provider:   fix.Provider,
	})
	if err != nil {
		t.Fatalf("RunIsolated failed: %v", err)
	}
	if !res.ReadOnlyVerified {
		t.Fatalf("expected ReadOnlyVerified=true")
	}
	if !res.NetworkBlocked {
		t.Fatalf("expected NetworkBlocked=true")
	}
	if res.Analysis == nil || res.Analysis.RecordCount != fix.ExpectedRecordCount {
		t.Fatalf("unexpected record count: %v", res.Analysis)
	}

	postBytes, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read blob after analysis: %v", err)
	}
	if sha256.Sum256(postBytes) != initialHash {
		t.Fatalf("sealed source bytes were mutated during analysis")
	}

	// Also verify isolated JSON analysis
	jsonRaw, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "isolated-json-analysis.json"))
	if err != nil {
		t.Fatalf("read positive json fixture: %v", err)
	}
	var jsonFix c15PositiveFixture
	if err := json.Unmarshal(jsonRaw, &jsonFix); err != nil {
		t.Fatalf("unmarshal positive json fixture: %v", err)
	}
	jsonBlob, initialJSONHash := sealPayloadForC15(t, quarantineDir, sealStore, sealDir, jsonFix.CaseID, jsonFix.EvidenceID, jsonFix.MediaType, jsonFix.Payload)
	jsonRes, err := box.RunIsolated(context.Background(), analyzers.IsolatedRunRequest{
		RunID:      jsonFix.RunID,
		CaseID:     jsonFix.CaseID,
		EvidenceID: jsonFix.EvidenceID,
		AnalyzerID: jsonFix.AnalyzerID,
		Provider:   jsonFix.Provider,
	})
	if err != nil {
		t.Fatalf("RunIsolated for JSON failed: %v", err)
	}
	if !jsonRes.ReadOnlyVerified || !jsonRes.NetworkBlocked {
		t.Fatalf("expected JSON isolation verified")
	}
	if jsonRes.Analysis == nil || jsonRes.Analysis.RecordCount != jsonFix.ExpectedRecordCount {
		t.Fatalf("unexpected JSON record count: %v", jsonRes.Analysis)
	}
	postJSONBytes, _ := os.ReadFile(jsonBlob)
	if sha256.Sum256(postJSONBytes) != initialJSONHash {
		t.Fatalf("sealed JSON source bytes were mutated during analysis")
	}

	// 3. Negative case: simulated evidence modification is caught fail-closed even when worker returns nil
	_, err = box.RunIsolatedFunc(context.Background(), analyzers.IsolatedRunRequest{
		RunID:      "run-tamper-test",
		CaseID:     fix.CaseID,
		EvidenceID: fix.EvidenceID,
		AnalyzerID: fix.AnalyzerID,
	}, func(ctx context.Context, sc *analyzers.ScratchController, netGuard *analyzers.NetworkGuard) error {
		return os.WriteFile(blobPath, []byte("tampered evidence data"), 0644)
	})
	if !errors.Is(err, analyzers.ErrEvidenceModified) {
		t.Fatalf("expected ErrEvidenceModified on evidence tampering, got: %v", err)
	}

	// 4. Critical Negative case: evidence modification is caught fail-closed even when worker returns an error!
	// Re-seal fresh evidence to test tamper-on-error precedence.
	blobPath2, _ := sealPayloadForC15(t, quarantineDir, sealStore, sealDir, "CASE-MUT2", "EVID-MUT2", "text/csv", "col1,col2\nval1,val2\n")
	_, err = box.RunIsolatedFunc(context.Background(), analyzers.IsolatedRunRequest{
		RunID:      "run-tamper-with-error",
		CaseID:     "CASE-MUT2",
		EvidenceID: "EVID-MUT2",
		AnalyzerID: "csv",
	}, func(ctx context.Context, sc *analyzers.ScratchController, netGuard *analyzers.NetworkGuard) error {
		_ = os.WriteFile(blobPath2, []byte("tampered data before error"), 0644)
		return errors.New("simulated analyzer worker failure")
	})
	if !errors.Is(err, analyzers.ErrEvidenceModified) {
		t.Fatalf("expected ErrEvidenceModified to take precedence over worker error, got: %v", err)
	}

	// 5. Deletion/truncation of sealed evidence during execution is caught as ErrEvidenceModified
	blobPath3, _ := sealPayloadForC15(t, quarantineDir, sealStore, sealDir, "CASE-MUT3", "EVID-MUT3", "text/csv", "colA,colB\nvalA,valB\n")
	_, err = box.RunIsolatedFunc(context.Background(), analyzers.IsolatedRunRequest{
		RunID:      "run-tamper-delete",
		CaseID:     "CASE-MUT3",
		EvidenceID: "EVID-MUT3",
		AnalyzerID: "csv",
	}, func(ctx context.Context, sc *analyzers.ScratchController, netGuard *analyzers.NetworkGuard) error {
		return os.Remove(blobPath3)
	})
	if !errors.Is(err, analyzers.ErrEvidenceModified) {
		t.Fatalf("expected ErrEvidenceModified on evidence deletion, got: %v", err)
	}
}

// TestC15PrivateScratchIsolation verifies 0700 permissions, path escapes, symlink escapes, quota bounds, and cleanup.
func TestC15PrivateScratchIsolation(t *testing.T) {
	sealStore, _, box, _, _ := setupC15Environment(t)
	defer sealStore.Close()

	fixturesDir := getC15FixturesDir(t)

	// 1. Verify dedicated scratch allocation permissions are 0700
	sc, err := box.AllocateScratch("test-scratch-01")
	if err != nil {
		t.Fatalf("allocate scratch: %v", err)
	}
	defer sc.Cleanup()

	fi, err := os.Stat(sc.Dir())
	if err != nil {
		t.Fatalf("stat scratch dir: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0700 {
		t.Fatalf("expected scratch dir permissions 0700, got %#o", perm)
	}

	// 2. Traversal and path escapes rejected using fixture and additional edge cases
	escRaw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "scratch-traversal-escape.json"))
	if err != nil {
		t.Fatalf("read scratch-traversal-escape fixture: %v", err)
	}
	var escFix c15EscapeFixture
	if err := json.Unmarshal(escRaw, &escFix); err != nil {
		t.Fatalf("unmarshal scratch-traversal-escape fixture: %v", err)
	}

	escapeCases := []string{
		escFix.EscapePath,
		"../escape.txt",
		"../../etc/shadow",
		"subdir/../../escape.txt",
		"/tmp/evil.txt",
		"a/b/../../../c",
		"null\x00byte.txt",
		".",
		"",
	}
	for _, escape := range escapeCases {
		t.Run("Escape/"+escape, func(t *testing.T) {
			if err := sc.WriteFile(escape, []byte("payload"), 0600); !errors.Is(err, analyzers.ErrSandboxEscaped) {
				t.Fatalf("expected ErrSandboxEscaped for WriteFile %q, got: %v", escape, err)
			}
			if _, err := sc.CreateFile(escape); !errors.Is(err, analyzers.ErrSandboxEscaped) {
				t.Fatalf("expected ErrSandboxEscaped for CreateFile %q, got: %v", escape, err)
			}
			if _, err := sc.OpenFile(escape, os.O_RDONLY, 0); !errors.Is(err, analyzers.ErrSandboxEscaped) {
				t.Fatalf("expected ErrSandboxEscaped for OpenFile %q, got: %v", escape, err)
			}
			if _, err := sc.ReadFile(escape); !errors.Is(err, analyzers.ErrSandboxEscaped) {
				t.Fatalf("expected ErrSandboxEscaped for ReadFile %q, got: %v", escape, err)
			}
			if err := sc.RemoveFile(escape); !errors.Is(err, analyzers.ErrSandboxEscaped) {
				t.Fatalf("expected ErrSandboxEscaped for RemoveFile %q, got: %v", escape, err)
			}
		})
	}

	// 3. Symlink escape rejected
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	_ = os.WriteFile(outsideFile, []byte("secret content"), 0600)

	symlinkPath := filepath.Join(sc.Dir(), "link-outside")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if err := sc.WriteFile("link-outside/evil.txt", []byte("evil"), 0600); !errors.Is(err, analyzers.ErrSandboxEscaped) {
		t.Fatalf("expected ErrSandboxEscaped for symlink escape write, got: %v", err)
	}

	// 4. Scratch quota enforcement using invalid/scratch-quota-exceeded.json
	quotaRaw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "scratch-quota-exceeded.json"))
	if err != nil {
		t.Fatalf("read scratch-quota-exceeded fixture: %v", err)
	}
	var quotaFix c15QuotaFixture
	if err := json.Unmarshal(quotaRaw, &quotaFix); err != nil {
		t.Fatalf("unmarshal scratch-quota-exceeded fixture: %v", err)
	}

	smallBox, err := analyzers.NewSandbox(box.Registry(), analyzers.SandboxConfig{
		ScratchBaseDir:  filepath.Join(t.TempDir(), "small-scratch"),
		MaxScratchBytes: quotaFix.ScratchLimitBytes, // 1024 bytes
		DefaultTimeout:  5 * time.Second,
		MaxTimeout:      10 * time.Second,
	})
	if err != nil {
		t.Fatalf("new small sandbox: %v", err)
	}

	smallSC, err := smallBox.AllocateScratch("quota-run")
	if err != nil {
		t.Fatalf("allocate quota scratch: %v", err)
	}
	defer smallSC.Cleanup()

	// Write within quota
	if err := smallSC.WriteFile("ok.dat", make([]byte, 512), 0600); err != nil {
		t.Fatalf("write within quota failed: %v", err)
	}
	if smallSC.BytesUsed() != 512 {
		t.Fatalf("expected 512 bytes used, got %d", smallSC.BytesUsed())
	}

	// Exceed quota via WriteFile using fixture attempted_write_bytes
	if err := smallSC.WriteFile("overflow.dat", make([]byte, quotaFix.AttemptedWriteBytes), 0600); !errors.Is(err, analyzers.ErrScratchLimitExceeded) {
		t.Fatalf("expected ErrScratchLimitExceeded for WriteFile overflow, got: %v", err)
	}

	// Exceed quota via streaming CreateFile
	w, err := smallSC.CreateFile("stream.dat")
	if err != nil {
		t.Fatalf("create streaming file: %v", err)
	}
	_, streamErr := w.Write(make([]byte, 800))
	_ = w.Close()
	if !errors.Is(streamErr, analyzers.ErrScratchLimitExceeded) {
		t.Fatalf("expected ErrScratchLimitExceeded for streaming write overflow, got: %v", streamErr)
	}

	// 5. CreateFile truncation reclaims previous file bytes and allows writing within quota
	recSC, err := smallBox.AllocateScratch("reclaim-run")
	if err != nil {
		t.Fatalf("allocate reclaim scratch: %v", err)
	}
	defer recSC.Cleanup()

	// Write 800 bytes to reusable.dat
	if err := recSC.WriteFile("reusable.dat", make([]byte, 800), 0600); err != nil {
		t.Fatalf("write initial file: %v", err)
	}
	if recSC.BytesUsed() != 800 {
		t.Fatalf("expected 800 bytes used, got %d", recSC.BytesUsed())
	}

	// Overwrite via CreateFile (truncates to 0) and write 400 bytes.
	// Since 800 was reclaimed, 400 <= 1024, so this MUST succeed without quota error.
	wRec, err := recSC.CreateFile("reusable.dat")
	if err != nil {
		t.Fatalf("CreateFile for truncate: %v", err)
	}
	n, writeErr := wRec.Write(make([]byte, 400))
	_ = wRec.Close()
	if writeErr != nil || n != 400 {
		t.Fatalf("expected write of 400 bytes to succeed after truncation, got err=%v, n=%d", writeErr, n)
	}
	if recSC.BytesUsed() != 400 {
		t.Fatalf("expected 400 bytes used after truncation, got %d", recSC.BytesUsed())
	}

	// 6. RemoveFile reclaims quota
	if err := recSC.RemoveFile("reusable.dat"); err != nil {
		t.Fatalf("RemoveFile failed: %v", err)
	}
	if recSC.BytesUsed() != 0 {
		t.Fatalf("expected 0 bytes used after RemoveFile, got %d", recSC.BytesUsed())
	}

	// 7. OpenFile strictly rejects write flags
	if _, err := recSC.OpenFile("read-only.txt", os.O_WRONLY|os.O_CREATE, 0600); !errors.Is(err, analyzers.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for OpenFile with write flags, got %v", err)
	}
	if _, err := recSC.OpenFile("read-only.txt", os.O_RDWR, 0600); !errors.Is(err, analyzers.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for OpenFile with O_RDWR, got %v", err)
	}

	// 8. ScratchController closed after Cleanup: post-cleanup writes fail closed
	cleanTestSC, err := smallBox.AllocateScratch("cleanup-guard-run")
	if err != nil {
		t.Fatalf("allocate scratch: %v", err)
	}
	_ = cleanTestSC.WriteFile("first.txt", []byte("initial"), 0600)
	if err := cleanTestSC.Cleanup(); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if err := cleanTestSC.WriteFile("second.txt", []byte("leaked"), 0600); !errors.Is(err, analyzers.ErrSandboxEscaped) {
		t.Fatalf("expected ErrSandboxEscaped for WriteFile after Cleanup, got %v", err)
	}
	if _, err := cleanTestSC.CreateFile("second.txt"); !errors.Is(err, analyzers.ErrSandboxEscaped) {
		t.Fatalf("expected ErrSandboxEscaped for CreateFile after Cleanup, got %v", err)
	}
	if _, err := cleanTestSC.OpenFile("first.txt", os.O_RDONLY, 0); !errors.Is(err, analyzers.ErrSandboxEscaped) {
		t.Fatalf("expected ErrSandboxEscaped for OpenFile after Cleanup, got %v", err)
	}
	if _, err := cleanTestSC.ReadFile("first.txt"); !errors.Is(err, analyzers.ErrSandboxEscaped) {
		t.Fatalf("expected ErrSandboxEscaped for ReadFile after Cleanup, got %v", err)
	}
	if err := cleanTestSC.RemoveFile("first.txt"); !errors.Is(err, analyzers.ErrSandboxEscaped) {
		t.Fatalf("expected ErrSandboxEscaped for RemoveFile after Cleanup, got %v", err)
	}

	// 9. Cleanup lifecycle: CleanScratchOnExit vs KeepScratch
	keepBox, err := analyzers.NewSandbox(box.Registry(), analyzers.SandboxConfig{
		ScratchBaseDir:     filepath.Join(t.TempDir(), "keep-scratch"),
		MaxScratchBytes:    1024 * 1024,
		DefaultTimeout:     5 * time.Second,
		MaxTimeout:         10 * time.Second,
		CleanScratchOnExit: true,
	})
	if err != nil {
		t.Fatalf("new keep sandbox: %v", err)
	}

	// KeepScratch = true: scratch dir persists
	resKeep, err := keepBox.RunIsolatedFunc(context.Background(), analyzers.IsolatedRunRequest{
		RunID:       "run-keep",
		KeepScratch: true,
	}, func(ctx context.Context, sc *analyzers.ScratchController, netGuard *analyzers.NetworkGuard) error {
		return sc.WriteFile("keep.txt", []byte("kept data"), 0600)
	})
	if err != nil {
		t.Fatalf("run with KeepScratch failed: %v", err)
	}
	if _, err := os.Stat(resKeep.ScratchDir); err != nil {
		t.Fatalf("expected scratch dir %s to exist when KeepScratch=true", resKeep.ScratchDir)
	}
	_ = os.RemoveAll(resKeep.ScratchDir)

	// KeepScratch = false: scratch dir is purged automatically
	resClean, err := keepBox.RunIsolatedFunc(context.Background(), analyzers.IsolatedRunRequest{
		RunID:       "run-clean",
		KeepScratch: false,
	}, func(ctx context.Context, sc *analyzers.ScratchController, netGuard *analyzers.NetworkGuard) error {
		return sc.WriteFile("clean.txt", []byte("temp data"), 0600)
	})
	if err != nil {
		t.Fatalf("run with CleanScratch failed: %v", err)
	}
	if _, err := os.Stat(resClean.ScratchDir); !os.IsNotExist(err) {
		t.Fatalf("expected scratch dir %s to be removed automatically on exit", resClean.ScratchDir)
	}
}

// TestC15NetworkIsolation verifies outbound network dialing is intercepted fail-closed.
func TestC15NetworkIsolation(t *testing.T) {
	sealStore, _, box, _, _ := setupC15Environment(t)
	defer sealStore.Close()

	fixturesDir := getC15FixturesDir(t)
	netRaw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "network-dial-rejected.json"))
	if err != nil {
		t.Fatalf("read network-dial-rejected fixture: %v", err)
	}
	var netFix c15NetFixture
	if err := json.Unmarshal(netRaw, &netFix); err != nil {
		t.Fatalf("unmarshal network-dial-rejected fixture: %v", err)
	}

	// 1. NetworkGuard CheckBlocked
	if err := box.NetworkGuard().CheckBlocked(); !errors.Is(err, analyzers.ErrNetworkForbidden) {
		t.Fatalf("expected ErrNetworkForbidden from CheckBlocked, got %v", err)
	}

	// 2. Direct DialContext & Dial interception using fixture target_network and target_address
	conn, err := box.DialContext(context.Background(), netFix.TargetNetwork, netFix.TargetAddress)
	if conn != nil {
		_ = conn.Close()
		t.Fatalf("expected nil conn on blocked dial")
	}
	if !errors.Is(err, analyzers.ErrNetworkForbidden) {
		t.Fatalf("expected ErrNetworkForbidden for DialContext, got %v", err)
	}

	conn, err = box.NetworkGuard().Dial("udp", "198.51.100.1:53")
	if conn != nil {
		_ = conn.Close()
		t.Fatalf("expected nil conn on blocked dial")
	}
	if !errors.Is(err, analyzers.ErrNetworkForbidden) {
		t.Fatalf("expected ErrNetworkForbidden for Dial, got %v", err)
	}

	// 3. HTTP client blocked
	client := box.NewBlockedHTTPClient()
	_, httpErr := client.Get(fmt.Sprintf("http://%s/data", netFix.TargetAddress))
	if httpErr == nil || !strings.Contains(httpErr.Error(), analyzers.ErrNetworkForbidden.Error()) {
		t.Fatalf("expected ErrNetworkForbidden in HTTP client error, got %v", httpErr)
	}

	// 4. Isolated execution attempting network dial fails closed
	_, err = box.RunIsolatedFunc(context.Background(), analyzers.IsolatedRunRequest{
		RunID: netFix.RunID,
	}, func(ctx context.Context, sc *analyzers.ScratchController, netGuard *analyzers.NetworkGuard) error {
		_, dialErr := netGuard.DialContext(ctx, netFix.TargetNetwork, netFix.TargetAddress)
		return dialErr
	})
	if !errors.Is(err, analyzers.ErrNetworkForbidden) {
		t.Fatalf("expected ErrNetworkForbidden inside isolated execution, got %v", err)
	}
}

// TestC15DeadlineEnforcement verifies execution timeout, goroutine abort, and scratch release.
func TestC15DeadlineEnforcement(t *testing.T) {
	sealStore, reg, _, _, _ := setupC15Environment(t)
	defer sealStore.Close()

	fixturesDir := getC15FixturesDir(t)
	timeRaw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "deadline-timeout.json"))
	if err != nil {
		t.Fatalf("read deadline-timeout fixture: %v", err)
	}
	var timeFix c15TimeoutFixture
	if err := json.Unmarshal(timeRaw, &timeFix); err != nil {
		t.Fatalf("unmarshal deadline-timeout fixture: %v", err)
	}

	scratchBase := filepath.Join(t.TempDir(), "timeout-scratch")
	cfg := analyzers.DefaultSandboxConfig(scratchBase)
	cfg.MaxScratchBytes = 1024 * 1024
	cfg.DefaultTimeout = 50 * time.Millisecond
	cfg.MaxTimeout = 200 * time.Millisecond
	timeoutBox, err := analyzers.NewSandbox(reg, cfg)
	if err != nil {
		t.Fatalf("new timeout sandbox: %v", err)
	}

	// 1. Hanging execution aborted upon deadline expiry using fixture timeout
	runTimeout := time.Duration(timeFix.TimeoutMs) * time.Millisecond
	simulatedHang := time.Duration(timeFix.SimulatedHangMs) * time.Millisecond

	_, err = timeoutBox.RunIsolatedFunc(context.Background(), analyzers.IsolatedRunRequest{
		RunID:   timeFix.RunID,
		Timeout: runTimeout,
	}, func(ctx context.Context, sc *analyzers.ScratchController, netGuard *analyzers.NetworkGuard) error {
		_ = sc.WriteFile("temp.txt", []byte("working..."), 0600)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(simulatedHang):
			return nil
		}
	})

	if !errors.Is(err, analyzers.ErrDeadlineExceeded) {
		t.Fatalf("expected ErrDeadlineExceeded, got %v", err)
	}

	// Verify scratch directory was cleanly purged despite the timeout
	expectedScratch := filepath.Join(scratchBase, "run-"+timeFix.RunID)
	if _, err := os.Stat(expectedScratch); !os.IsNotExist(err) {
		t.Fatalf("expected scratch dir %s to be released on timeout abort", expectedScratch)
	}

	// 2. Request timeout exceeding MaxTimeout rejected
	_, err = timeoutBox.RunIsolated(context.Background(), analyzers.IsolatedRunRequest{
		RunID:   "run-exceed-max-timeout",
		Timeout: 500 * time.Millisecond, // MaxTimeout is 200ms
	})
	if !errors.Is(err, analyzers.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for timeout > MaxTimeout, got %v", err)
	}

	// 3. Request negative timeout rejected
	_, err = timeoutBox.RunIsolated(context.Background(), analyzers.IsolatedRunRequest{
		RunID:   "run-neg-timeout",
		Timeout: -10 * time.Millisecond,
	})
	if !errors.Is(err, analyzers.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for negative timeout, got %v", err)
	}

	// 4. Pre-canceled context returns context cancellation immediately
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = timeoutBox.RunIsolated(canceledCtx, analyzers.IsolatedRunRequest{
		RunID: "run-precanceled",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestC15OrphanScratchRecovery verifies abandoned scratch recovery without affecting active runs.
func TestC15OrphanScratchRecovery(t *testing.T) {
	sealStore, reg, _, _, _ := setupC15Environment(t)
	defer sealStore.Close()

	fixturesDir := getC15FixturesDir(t)
	orphanRaw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "orphaned-scratch-interrupt.json"))
	if err != nil {
		t.Fatalf("read orphaned-scratch-interrupt fixture: %v", err)
	}
	var orphanFix c15OrphanFixture
	if err := json.Unmarshal(orphanRaw, &orphanFix); err != nil {
		t.Fatalf("unmarshal orphaned-scratch-interrupt fixture: %v", err)
	}

	scratchBase := filepath.Join(t.TempDir(), "orphan-scratch")
	box, err := analyzers.NewSandbox(reg, analyzers.DefaultSandboxConfig(scratchBase))
	if err != nil {
		t.Fatalf("new sandbox: %v", err)
	}

	// 1. Simulate abandoned scratch directories from fixture
	for _, dirName := range orphanFix.SimulatedAbandonedDirs {
		p := filepath.Join(scratchBase, dirName)
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatalf("create simulated abandoned dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(p, "leftover.dat"), []byte("residual data"), 0600); err != nil {
			t.Fatalf("write leftover file: %v", err)
		}
	}

	// Also allocate an active run
	activeSC, err := box.AllocateScratch("active-session")
	if err != nil {
		t.Fatalf("allocate active scratch: %v", err)
	}
	if err := activeSC.WriteFile("active.dat", []byte("active run data"), 0600); err != nil {
		t.Fatalf("write active file: %v", err)
	}

	// 2. CleanOrphans rejects negative maxAge
	if _, err := box.CleanOrphans(context.Background(), -1*time.Minute); !errors.Is(err, analyzers.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for negative maxAge, got %v", err)
	}

	// 3. CleanOrphans sweeps abandoned directories
	cleaned, err := box.CleanOrphans(context.Background(), 0)
	if err != nil {
		t.Fatalf("CleanOrphans failed: %v", err)
	}
	if cleaned != len(orphanFix.SimulatedAbandonedDirs) {
		t.Fatalf("expected %d cleaned directories, got %d", len(orphanFix.SimulatedAbandonedDirs), cleaned)
	}

	// Verify abandoned dirs are gone
	for _, dirName := range orphanFix.SimulatedAbandonedDirs {
		p := filepath.Join(scratchBase, dirName)
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("expected abandoned dir %s to be removed", p)
		}
	}

	// Verify active run scratch was NOT touched
	if _, err := os.Stat(activeSC.Dir()); err != nil {
		t.Fatalf("expected active scratch dir %s to be preserved: %v", activeSC.Dir(), err)
	}
	activeBytes, err := activeSC.ReadFile("active.dat")
	if err != nil || string(activeBytes) != "active run data" {
		t.Fatalf("active data corrupted: %v", err)
	}

	// Release active run
	if err := box.ReleaseScratch("active-session"); err != nil {
		t.Fatalf("release scratch: %v", err)
	}
	if _, err := os.Stat(activeSC.Dir()); !os.IsNotExist(err) {
		t.Fatalf("expected active scratch dir to be removed after release")
	}
}

// TestC15PrerequisiteValidation verifies inputs are rejected before scratch allocation or execution.
func TestC15PrerequisiteValidation(t *testing.T) {
	sealStore, _, box, _, _ := setupC15Environment(t)
	defer sealStore.Close()

	// 1. Missing case_id or evidence_id
	_, err := box.RunIsolated(context.Background(), analyzers.IsolatedRunRequest{
		RunID:      "run-missing-case",
		CaseID:     "",
		EvidenceID: "EVID-001",
		AnalyzerID: "csv",
	})
	if !errors.Is(err, analyzers.ErrMissingPrerequisite) {
		t.Fatalf("expected ErrMissingPrerequisite for empty case_id, got %v", err)
	}

	// 2. Unallowlisted analyzer ID
	_, err = box.RunIsolated(context.Background(), analyzers.IsolatedRunRequest{
		RunID:      "run-unallowlisted",
		CaseID:     "CASE-001",
		EvidenceID: "EVID-001",
		AnalyzerID: "python-exec",
	})
	if !errors.Is(err, analyzers.ErrAnalyzerNotAllowlisted) {
		t.Fatalf("expected ErrAnalyzerNotAllowlisted, got %v", err)
	}

	// 3. Unsupported provider
	_, err = box.RunIsolated(context.Background(), analyzers.IsolatedRunRequest{
		RunID:      "run-bad-provider",
		CaseID:     "CASE-001",
		EvidenceID: "EVID-001",
		AnalyzerID: "csv",
		Provider:   "remote-aws",
	})
	if !errors.Is(err, analyzers.ErrUnavailableProvider) {
		t.Fatalf("expected ErrUnavailableProvider, got %v", err)
	}

	// 4. Path traversal in run_id
	_, err = box.RunIsolated(context.Background(), analyzers.IsolatedRunRequest{
		RunID:      "../../escape",
		CaseID:     "CASE-001",
		EvidenceID: "EVID-001",
		AnalyzerID: "csv",
	})
	if !errors.Is(err, analyzers.ErrPathTraversal) {
		t.Fatalf("expected ErrPathTraversal, got %v", err)
	}
}

// TestC15ConcurrentIsolationAndRace verifies concurrent isolated runs under -race on shared sealed evidence,
// and concurrent scratch operations with orphan cleanup.
func TestC15ConcurrentIsolationAndRace(t *testing.T) {
	sealStore, _, box, sealDir, quarantineDir := setupC15Environment(t)
	defer sealStore.Close()

	csvPayload := "timestamp,host,action\n2026-11-11T12:00:00Z,srv-1,start\n2026-11-11T12:05:00Z,srv-1,stop\n"
	jsonPayload := "[{\"timestamp\":\"2026-11-11T12:00:00Z\",\"msg\":\"init\"},{\"timestamp\":\"2026-11-11T12:01:00Z\",\"msg\":\"ready\"}]\n"

	csvBlob, csvHash := sealPayloadForC15(t, quarantineDir, sealStore, sealDir, "CASE-RACE", "EVID-CSV", "text/csv", csvPayload)
	jsonBlob, jsonHash := sealPayloadForC15(t, quarantineDir, sealStore, sealDir, "CASE-RACE", "EVID-JSON", "application/json", jsonPayload)

	const concurrency = 12
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency*2)

	for i := 0; i < concurrency; i++ {
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			analyzerID := "csv"
			evidenceID := "EVID-CSV"
			if idx%2 == 1 {
				analyzerID = "json"
				evidenceID = "EVID-JSON"
			}

			runID := fmt.Sprintf("race-run-%d", idx)
			res, err := box.RunIsolated(context.Background(), analyzers.IsolatedRunRequest{
				RunID:      runID,
				CaseID:     "CASE-RACE",
				EvidenceID: evidenceID,
				AnalyzerID: analyzerID,
			})
			if err != nil {
				errCh <- fmt.Errorf("run %d failed: %w", idx, err)
				return
			}
			if !res.ReadOnlyVerified || !res.NetworkBlocked {
				errCh <- fmt.Errorf("run %d failed isolation verification", idx)
				return
			}
			if res.Analysis == nil || res.Analysis.RecordCount != 2 {
				errCh <- fmt.Errorf("run %d unexpected record count: %v", idx, res.Analysis)
				return
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	// Verify neither shared blob was mutated
	cBytes, _ := os.ReadFile(csvBlob)
	if sha256.Sum256(cBytes) != csvHash {
		t.Fatalf("shared CSV evidence was mutated under concurrency")
	}
	jBytes, _ := os.ReadFile(jsonBlob)
	if sha256.Sum256(jBytes) != jsonHash {
		t.Fatalf("shared JSON evidence was mutated under concurrency")
	}

	// Test concurrent scratch allocation and orphan cleanup under race detector
	var wgOrphan sync.WaitGroup
	orphanErrCh := make(chan error, 10)

	for i := 0; i < 5; i++ {
		idx := i
		wgOrphan.Add(2)

		go func() {
			defer wgOrphan.Done()
			runID := fmt.Sprintf("concurrent-alloc-%d", idx)
			sc, err := box.AllocateScratch(runID)
			if err != nil {
				orphanErrCh <- fmt.Errorf("alloc %d failed: %w", idx, err)
				return
			}
			_ = sc.WriteFile("data.txt", []byte("concurrent payload"), 0600)
			time.Sleep(5 * time.Millisecond)
			if err := box.ReleaseScratch(runID); err != nil {
				orphanErrCh <- fmt.Errorf("release %d failed: %w", idx, err)
				return
			}
		}()

		go func() {
			defer wgOrphan.Done()
			time.Sleep(2 * time.Millisecond)
			_, err := box.CleanOrphans(context.Background(), 0)
			if err != nil {
				orphanErrCh <- fmt.Errorf("clean %d failed: %w", idx, err)
				return
			}
		}()
	}

	wgOrphan.Wait()
	close(orphanErrCh)

	for err := range orphanErrCh {
		t.Fatal(err)
	}
}

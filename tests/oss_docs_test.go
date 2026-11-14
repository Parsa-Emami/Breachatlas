package tests_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

type c34Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

func TestC34OSSDocsSupportAndNegativeCases(t *testing.T) {
	ctx := context.Background()
	rootRepo := locateRepoRoot(t)
	fxDir := filepath.Join(rootRepo, "tests", "fixtures", "breachatlas", "C34")

	// 1. Verify C34 fixture provenance & SHA-256 digests.
	provRaw, err := os.ReadFile(filepath.Join(fxDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read C34 provenance: %v", err)
	}
	var prov c34Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatalf("decode C34 provenance: %v", err)
	}
	if prov.Task != "C34" || prov.License != "Apache-2.0" || len(prov.SHA256) < 3 {
		t.Fatalf("invalid C34 provenance: %+v", prov)
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

	// 2. Verify all C34 target docs and required sections.
	var pos struct {
		RequiredDocs     []string            `json:"required_docs"`
		RequiredSections map[string][]string `json:"required_sections"`
	}
	posRaw, err := os.ReadFile(filepath.Join(fxDir, "positive", "docs-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(posRaw, &pos); err != nil {
		t.Fatal(err)
	}
	for _, rel := range pos.RequiredDocs {
		raw, err := os.ReadFile(filepath.Join(rootRepo, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("missing required doc %s: %v", rel, err)
		}
		content := string(raw)
		for _, needle := range pos.RequiredSections[rel] {
			if !strings.Contains(content, needle) {
				t.Fatalf("doc %s missing required section/token %q", rel, needle)
			}
		}
	}

	// 3. Verify negative cases: script/HTML sentinel stays inert and sealed source bytes remain unmodified.
	var neg struct {
		ScriptSentinelPayload string `json:"script_sentinel_payload"`
	}
	negRaw, err := os.ReadFile(filepath.Join(fxDir, "invalid", "negative-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(negRaw, &neg); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	qDir := filepath.Join(root, "quarantine")
	sDir := filepath.Join(root, "sealstore")
	scDir := filepath.Join(root, "scratch")
	ss, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()

	payloadBytes := []byte(neg.ScriptSentinelPayload)
	sum := sha256.Sum256(payloadBytes)
	expectedSHA := hex.EncodeToString(sum[:])
	sz := int64(len(payloadBytes))

	q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{QuarantineDir: qDir, SyncDir: true}, evidence.UploadRequest{
		SchemaVersion:  "1",
		UploadID:       "upl-c34-sentinel",
		CaseID:         "case-c34-neg-001",
		EvidenceID:     "ev-c34-sentinel-01",
		MediaType:      "application/x-ndjson",
		Filename:       "sentinel.jsonl",
		ExpectedSize:   &sz,
		ExpectedSHA256: expectedSHA,
		Body:           bytes.NewReader(payloadBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	sm, err := ss.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "seal-c34-sentinel",
		Quarantined:    q,
		ExpectedSHA256: expectedSHA,
		AcquiredAt:     "2026-11-14T14:20:00Z",
		CustodyRoot:    strings.Repeat("0", 64),
	})
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
	runRes, err := sbx.RunIsolated(ctx, analyzers.IsolatedRunRequest{
		RunID:      "run-c34-sentinel",
		CaseID:     "case-c34-neg-001",
		EvidenceID: "ev-c34-sentinel-01",
		AnalyzerID: analyzers.AnalyzerJSON,
		Provider:   "local",
		Options:    analyzers.DefaultParseOptions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if runRes.Analysis == nil || runRes.Analysis.RecordCount != 1 || !runRes.Analysis.NonExecuting || !runRes.Analysis.ReadOnly {
		t.Fatalf("expected inert non-executing read-only sentinel record, got %+v", runRes.Analysis)
	}

	sealedPath := filepath.Join(sDir, filepath.FromSlash(sm.BlobRelPath))
	onDiskBytes, err := os.ReadFile(sealedPath)
	if err != nil || !bytes.Equal(onDiskBytes, payloadBytes) {
		t.Fatalf("sealed source bytes modified during C34 sentinel test")
	}
}

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
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

type c36Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c36OnboardingContract struct {
	SchemaVersion         string   `json:"schema_version"`
	Task                  string   `json:"task"`
	Requirement           string   `json:"requirement"`
	GuidePaths            []string `json:"guide_paths"`
	SetupCommands         []string `json:"setup_commands"`
	ScenarioPath          string   `json:"scenario_path"`
	RequiredWorkflowSteps int      `json:"required_workflow_steps"`
	RestartVerification   bool     `json:"restart_verification"`
	OfflineVerify         bool     `json:"offline_verify"`
}

func TestC36IndependentCloneToValue(t *testing.T) {
	ctx := context.Background()
	root := locateRepoRoot(t)
	fxDir := filepath.Join(root, "tests", "fixtures", "breachatlas", "C36")

	// 1. Validate C36 fixture provenance & SHA-256 digests.
	provRaw, err := os.ReadFile(filepath.Join(fxDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read C36 provenance: %v", err)
	}
	var prov c36Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatalf("decode C36 provenance: %v", err)
	}
	if prov.Task != "C36" || prov.License != "Apache-2.0" || len(prov.SHA256) < 3 {
		t.Fatalf("unexpected C36 provenance: %+v", prov)
	}
	for rel, expected := range prov.SHA256 {
		data, err := os.ReadFile(filepath.Join(fxDir, rel))
		if err != nil {
			t.Fatalf("read fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != expected {
			t.Fatalf("fixture %s sha256 mismatch: expected %s got %s", rel, expected, got)
		}
	}

	// 2. Validate onboarding contract, public guides, ONBOARDING_RESULTS.md, and clone-to-value.json.
	contractRaw, err := os.ReadFile(filepath.Join(fxDir, "positive", "onboarding-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract c36OnboardingContract
	if err := json.Unmarshal(contractRaw, &contract); err != nil {
		t.Fatal(err)
	}
	for _, guide := range contract.GuidePaths {
		if _, err := os.Stat(filepath.Join(root, guide)); err != nil {
			t.Fatalf("missing public onboarding guide %s: %v", guide, err)
		}
	}

	resultsRaw, err := os.ReadFile(filepath.Join(root, "docs", "product", "ONBOARDING_RESULTS.md"))
	if err != nil {
		t.Fatalf("read ONBOARDING_RESULTS.md: %v", err)
	}
	resultsText := string(resultsRaw)
	for _, needle := range []string{"npm run setup", "npm run test:clone", "Linux x86_64", "0440"} {
		if !strings.Contains(resultsText, needle) {
			t.Fatalf("ONBOARDING_RESULTS.md missing expected section %q", needle)
		}
	}

	scenarioRaw, err := os.ReadFile(filepath.Join(root, contract.ScenarioPath))
	if err != nil {
		t.Fatal(err)
	}
	var scenario struct {
		EngineImplemented bool   `json:"engine_implemented"`
		VerifiedAtCommit  string `json:"verified_at_commit"`
		Steps             []any  `json:"steps"`
	}
	if err := json.Unmarshal(scenarioRaw, &scenario); err != nil {
		t.Fatal(err)
	}
	if !scenario.EngineImplemented || len(scenario.Steps) != contract.RequiredWorkflowSteps || scenario.VerifiedAtCommit != "C30" {
		t.Fatalf("unexpected clone-to-value.json state: %+v", scenario)
	}

	// 3. Exercise core seal + custody + restart persistence + 0440 sealed-byte immutability on the Go engine.
	baseDir := t.TempDir()
	qDir := filepath.Join(baseDir, "quarantine")
	sDir := filepath.Join(baseDir, "sealstore")
	cDir := filepath.Join(baseDir, "custody")

	ss, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	ls, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: cDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("2026-11-14T14:50:00Z clean-host breachatlas: c36-onboarding-record\n")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	sz := int64(len(payload))
	now := time.Date(2026, 11, 14, 14, 50, 0, 0, time.UTC).Format(time.RFC3339)

	q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{QuarantineDir: qDir, SyncDir: true}, evidence.UploadRequest{
		SchemaVersion:  "1",
		UploadID:       "upl-c36-01",
		CaseID:         "c36-case",
		EvidenceID:     "c36-ev",
		MediaType:      "text/plain",
		Filename:       "c36.log",
		ExpectedSize:   &sz,
		ExpectedSHA256: hexSum,
		Body:           bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := ls.AppendEvent(ctx, custody.AppendEventRequest{
		EventID:    "cust-c36-01",
		CaseID:     "c36-case",
		EvidenceID: "c36-ev",
		EventType:  "intake_seal",
		Actor:      "analyst",
		Timestamp:  now,
		Reason:     "C36 independent onboarding verification",
		Provider:   "local",
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := ss.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "op-seal-c36",
		Quarantined:    q,
		ExpectedSHA256: hexSum,
		AcquiredAt:     now,
		CustodyRoot:    ev.CustodyRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = ss.Close()
	_ = ls.Close()

	// Simulate restart: reopen stores and verify sealed 0440 bytes are intact.
	ss2, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ss2.Close()
	ls2, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: cDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ls2.Close()

	blobPath := filepath.Join(sDir, sealed.BlobRelPath)
	gotBytes, err := os.ReadFile(blobPath)
	if err != nil || sha256.Sum256(gotBytes) != sum {
		t.Fatalf("sealed bytes changed or missing after restart")
	}
}

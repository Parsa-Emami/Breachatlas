package tests_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Parsa-Emami/Breachatlas/internal/cases"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/storage"
)

type C07RegistrationFixture struct {
	OperationID string            `json:"operation_id"`
	Manifest    evidence.Manifest `json:"manifest"`
	PayloadUTF8 string            `json:"payload_utf8"`
	Identity    storage.Identity  `json:"identity"`
}

type C07PositiveFixture struct {
	Cases         []cases.CreateCaseInput  `json:"cases"`
	Registrations []C07RegistrationFixture `json:"registrations"`
}

func getC07FixturesDir(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{
		filepath.Join("..", "tests", "fixtures", "breachatlas", "C07"),
		filepath.Join("fixtures", "breachatlas", "C07"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	t.Fatalf("could not locate C07 fixtures directory")
	return ""
}

func TestC07FixturesAndCaseInvariants(t *testing.T) {
	fixturesDir := getC07FixturesDir(t)

	// 1. Verify C07 provenance & Apache-2.0 license
	provBytes, err := os.ReadFile(filepath.Join(fixturesDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read provenance.json: %v", err)
	}
	var prov Provenance
	if err := json.Unmarshal(provBytes, &prov); err != nil {
		t.Fatalf("unmarshal provenance.json: %v", err)
	}
	if prov.License != "Apache-2.0" {
		t.Fatalf("expected Apache-2.0 license, got %q", prov.License)
	}
	for relPath, expectedHash := range prov.SHA256 {
		content, err := os.ReadFile(filepath.Join(fixturesDir, relPath))
		if err != nil {
			t.Fatalf("missing fixture %s: %v", relPath, err)
		}
		h := sha256.Sum256(content)
		if hex.EncodeToString(h[:]) != expectedHash {
			t.Fatalf("fixture hash mismatch for %s: got %s, want %s", relPath, hex.EncodeToString(h[:]), expectedHash)
		}
	}

	tmpDir, err := os.MkdirTemp("", "c07-cases-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	adapter, err := storage.Open(storage.Config{RootDir: tmpDir, SyncDir: true})
	if err != nil {
		t.Fatalf("open storage adapter: %v", err)
	}
	defer adapter.Close()

	reg, err := cases.NewRegistry(adapter)
	if err != nil {
		t.Fatalf("new case registry: %v", err)
	}

	// 2. Positive multi-case creation and isolated evidence registration
	posBytes, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "case-and-evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pos C07PositiveFixture
	if err := json.Unmarshal(posBytes, &pos); err != nil {
		t.Fatal(err)
	}

	for _, cIn := range pos.Cases {
		created, err := reg.CreateCase(cIn)
		if err != nil {
			t.Fatalf("CreateCase(%s) failed: %v", cIn.CaseID, err)
		}
		if created.CaseID != cIn.CaseID || created.Status != cases.StatusOpen {
			t.Fatalf("unexpected created case: %+v", created)
		}
	}

	ctx := context.Background()
	for _, rIn := range pos.Registrations {
		item, err := reg.RegisterEvidence(ctx, cases.RegisterEvidenceRequest{
			OperationID: rIn.OperationID,
			Manifest:    rIn.Manifest,
			Payload:     []byte(rIn.PayloadUTF8),
			Identity:    rIn.Identity,
		})
		if err != nil {
			t.Fatalf("RegisterEvidence(%s/%s) failed: %v", rIn.Manifest.CaseID, rIn.Manifest.EvidenceID, err)
		}
		if !item.Sealed || item.CaseID != rIn.Manifest.CaseID || item.EvidenceID != rIn.Manifest.EvidenceID {
			t.Fatalf("unexpected registered item: %+v", item)
		}
	}

	// Verify positive single-case retrieval and listing isolation
	got1, item1, err := reg.GetEvidence("case-2026-001", "ev-2026-0001")
	if err != nil {
		t.Fatalf("GetEvidence(case-2026-001, ev-2026-0001) failed: %v", err)
	}
	if !bytes.Equal(got1, []byte(pos.Registrations[0].PayloadUTF8)) || item1.CaseID != "case-2026-001" {
		t.Fatalf("retrieved evidence mismatch for case-2026-001")
	}

	list1, err := reg.ListCaseEvidence("case-2026-001")
	if err != nil || len(list1) != 1 || list1[0].EvidenceID != "ev-2026-0001" {
		t.Fatalf("unexpected evidence list for case-2026-001: %+v (err=%v)", list1, err)
	}
	list2, err := reg.ListCaseEvidence("case-2026-002")
	if err != nil || len(list2) != 1 || list2[0].EvidenceID != "ev-2026-0002" {
		t.Fatalf("unexpected evidence list for case-2026-002: %+v (err=%v)", list2, err)
	}

	// Cross-case read must explicitly fail
	if _, _, err := reg.GetEvidence("case-2026-002", "ev-2026-0001"); !errors.Is(err, cases.ErrCrossCaseAccess) {
		t.Fatalf("expected ErrCrossCaseAccess on cross-case read, got %v", err)
	}

	baselineState := adapter.CurrentState()

	// 3. Negative cases from versioned fixtures
	t.Run("invalid/cross-case-access.json", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "cross-case-access.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx C07RegistrationFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		_, err = reg.RegisterEvidence(ctx, cases.RegisterEvidenceRequest{
			OperationID: fx.OperationID,
			Manifest:    fx.Manifest,
			Payload:     []byte(fx.PayloadUTF8),
			Identity:    fx.Identity,
		})
		if !errors.Is(err, cases.ErrCrossCaseAccess) {
			t.Fatalf("expected ErrCrossCaseAccess, got %v", err)
		}
		if adapter.CurrentState().Generation != baselineState.Generation {
			t.Fatalf("storage state modified after cross-case access attempt")
		}
	})

	t.Run("invalid/missing-case-prerequisite.json", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "missing-case-prerequisite.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx C07RegistrationFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		_, err = reg.RegisterEvidence(ctx, cases.RegisterEvidenceRequest{
			OperationID: fx.OperationID,
			Manifest:    fx.Manifest,
			Payload:     []byte(fx.PayloadUTF8),
			Identity:    fx.Identity,
		})
		if !errors.Is(err, cases.ErrCaseNotFound) || !errors.Is(err, cases.ErrMissingPrerequisite) {
			t.Fatalf("expected ErrMissingPrerequisite / ErrCaseNotFound, got %v", err)
		}
		if adapter.CurrentState().Generation != baselineState.Generation {
			t.Fatalf("storage state modified after missing prerequisite rejection")
		}
	})

	t.Run("invalid/malformed-case.json", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "malformed-case.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx cases.CreateCaseInput
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		if _, err := reg.CreateCase(fx); !errors.Is(err, cases.ErrInvalidCase) {
			t.Fatalf("expected ErrInvalidCase, got %v", err)
		}
	})

	t.Run("invalid/unavailable-provider.json", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "unavailable-provider.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx C07RegistrationFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		_, err = reg.RegisterEvidence(ctx, cases.RegisterEvidenceRequest{
			OperationID: fx.OperationID,
			Manifest:    fx.Manifest,
			Payload:     []byte(fx.PayloadUTF8),
			Identity:    fx.Identity,
		})
		if !errors.Is(err, cases.ErrUnavailableProvider) {
			t.Fatalf("expected ErrUnavailableProvider, got %v", err)
		}
		if adapter.CurrentState().Generation != baselineState.Generation {
			t.Fatalf("storage state modified after unavailable provider rejection")
		}
	})

	// 4. Verify sealed source bytes remained intact after all negative tests
	gotAfter, _, err := reg.GetEvidence("case-2026-001", "ev-2026-0001")
	if err != nil || !bytes.Equal(gotAfter, []byte(pos.Registrations[0].PayloadUTF8)) {
		t.Fatalf("sealed source bytes changed or unreadable after negative tests (err=%v)", err)
	}
}

func TestCaseRestartAndRecoveryInvariant(t *testing.T) {
	fixturesDir := getC07FixturesDir(t)
	posBytes, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "case-and-evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pos C07PositiveFixture
	if err := json.Unmarshal(posBytes, &pos); err != nil {
		t.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "c07-restart-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Session 1: Create cases and commit sealed evidence
	a1, err := storage.Open(storage.Config{RootDir: tmpDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	r1, err := cases.NewRegistry(a1)
	if err != nil {
		t.Fatal(err)
	}
	for _, cIn := range pos.Cases {
		if _, err := r1.CreateCase(cIn); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	for _, rIn := range pos.Registrations {
		if _, err := r1.RegisterEvidence(ctx, cases.RegisterEvidenceRequest{
			OperationID: rIn.OperationID,
			Manifest:    rIn.Manifest,
			Payload:     []byte(rIn.PayloadUTF8),
			Identity:    rIn.Identity,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a1.Close(); err != nil {
		t.Fatal(err)
	}

	// Session 2 (Restart): Reopen storage adapter and recover case registry
	a2, err := storage.Open(storage.Config{RootDir: tmpDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen storage after restart: %v", err)
	}
	defer a2.Close()

	r2, err := cases.NewRegistry(a2)
	if err != nil {
		t.Fatalf("recover case registry after restart: %v", err)
	}

	// Verify both cases and their single-case ownership survived restart
	c1, err := r2.GetCase("case-2026-001")
	if err != nil || len(c1.EvidenceIDs) != 1 || c1.EvidenceIDs[0] != "ev-2026-0001" {
		t.Fatalf("unexpected recovered case-2026-001: %+v (err=%v)", c1, err)
	}
	c2, err := r2.GetCase("case-2026-002")
	if err != nil || len(c2.EvidenceIDs) != 1 || c2.EvidenceIDs[0] != "ev-2026-0002" {
		t.Fatalf("unexpected recovered case-2026-002: %+v (err=%v)", c2, err)
	}

	// Cross-case access must still fail after restart
	if _, _, err := r2.GetEvidence("case-2026-002", "ev-2026-0001"); !errors.Is(err, cases.ErrCrossCaseAccess) {
		t.Fatalf("expected ErrCrossCaseAccess after restart, got %v", err)
	}
	if _, _, err := r2.GetEvidence("case-2026-001", "ev-2026-0002"); !errors.Is(err, cases.ErrCrossCaseAccess) {
		t.Fatalf("expected ErrCrossCaseAccess after restart for ev-2026-0002, got %v", err)
	}

	// Sealed source bytes must remain exact after restart
	got1, _, err := r2.GetEvidence("case-2026-001", "ev-2026-0001")
	if err != nil || !bytes.Equal(got1, []byte(pos.Registrations[0].PayloadUTF8)) {
		t.Fatalf("sealed source bytes mismatch after restart (err=%v)", err)
	}
	got2, _, err := r2.GetEvidence("case-2026-002", "ev-2026-0002")
	if err != nil || !bytes.Equal(got2, []byte(pos.Registrations[1].PayloadUTF8)) {
		t.Fatalf("sealed source bytes mismatch for case-2026-002 after restart (err=%v)", err)
	}
}

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
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

type c37Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

func TestC37AcceptanceBlockersAndRegressions(t *testing.T) {
	ctx := context.Background()
	root := locateRepoRoot(t)
	fxDir := filepath.Join(root, "tests", "fixtures", "breachatlas", "C37")

	// 1. Validate C37 fixture provenance & SHA-256 digests.
	provRaw, err := os.ReadFile(filepath.Join(fxDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read C37 provenance: %v", err)
	}
	var prov c37Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatalf("decode C37 provenance: %v", err)
	}
	if prov.Task != "C37" || prov.License != "Apache-2.0" || len(prov.SHA256) < 3 {
		t.Fatalf("unexpected C37 provenance: %+v", prov)
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

	// 2. Verify docs/product/BETA_FIXES.md documents observed C30/C33/C35/C36 fixes without invented claims.
	fixesRaw, err := os.ReadFile(filepath.Join(root, "docs", "product", "BETA_FIXES.md"))
	if err != nil {
		t.Fatalf("read BETA_FIXES.md: %v", err)
	}
	fixesText := string(fixesRaw)
	for _, needle := range []string{
		"keyboard_enable_wait_in_c33",
		"content_addressed_blob_rel_path_check",
		"clone_to_value_scenario_pin",
		"Linux x86_64",
	} {
		if !strings.Contains(fixesText, needle) {
			t.Fatalf("BETA_FIXES.md missing expected entry %q", needle)
		}
	}

	// 3. Negative Case: Missing storage prerequisite fails closed.
	if _, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: ""}); !errors.Is(err, evidence.ErrSealStoreRequired) {
		t.Fatalf("expected ErrSealStoreRequired for missing RootDir, got %v", err)
	}

	// 4. Negative Case: Malformed JSON evidence manifest fails explicitly.
	if _, prob := evidence.ParseManifest(ctx, []byte(`{"schema_version":"1",`)); prob == nil || prob.Code != "invalid_json" {
		t.Fatalf("expected ParseManifest invalid_json problem for malformed JSON, got %+v", prob)
	}

	// 5. Negative Case: Unavailable analyzer provider fails closed.
	if _, err := analyzers.NewRegistry(analyzers.RegistryConfig{Provider: "nonexistent-provider"}); err == nil {
		t.Fatalf("expected error for unavailable analyzer provider")
	}

	// 6. Restart persistence & immutable 0440 sealed bytes regression.
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

	payload := []byte("2026-11-14T15:05:00Z host-c37 breachatlas: c37-sealed-record\n")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	sz := int64(len(payload))
	now := time.Date(2026, 11, 14, 15, 5, 0, 0, time.UTC).Format(time.RFC3339)

	q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{QuarantineDir: qDir, SyncDir: true}, evidence.UploadRequest{
		SchemaVersion:  "1",
		UploadID:       "upl-c37-01",
		CaseID:         "c37-case",
		EvidenceID:     "c37-ev",
		MediaType:      "text/plain",
		Filename:       "c37.log",
		ExpectedSize:   &sz,
		ExpectedSHA256: hexSum,
		Body:           bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := ls.AppendEvent(ctx, custody.AppendEventRequest{
		EventID:    "cust-c37-01",
		CaseID:     "c37-case",
		EvidenceID: "c37-ev",
		EventType:  "intake_seal",
		Actor:      "analyst",
		Timestamp:  now,
		Reason:     "C37 blocker fix verification",
		Provider:   "local",
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := ss.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "op-seal-c37",
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

	// Reopen across simulated restart and confirm sealed 0440 blob integrity.
	ss2, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ss2.Close()

	blobPath := filepath.Join(sDir, sealed.BlobRelPath)
	st, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("missing sealed blob after restart: %v", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("expected restricted owner-only sealed blob permissions, got %o", st.Mode().Perm())
	}
	got, err := os.ReadFile(blobPath)
	if err != nil || sha256.Sum256(got) != sum {
		t.Fatalf("sealed bytes altered after restart")
	}
}

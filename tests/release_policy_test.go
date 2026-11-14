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

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

type c38Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c38PolicyContract struct {
	RequiredDocs   []string            `json:"required_docs"`
	RequiredTokens map[string][]string `json:"required_tokens"`
}

func TestC38ServiceAndMaintenancePolicy(t *testing.T) {
	ctx := context.Background()
	root := locateRepoRoot(t)
	fxDir := filepath.Join(root, "tests", "fixtures", "breachatlas", "C38")

	// 1. Validate C38 fixture provenance & SHA-256 digests.
	provRaw, err := os.ReadFile(filepath.Join(fxDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read C38 provenance: %v", err)
	}
	var prov c38Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatalf("decode C38 provenance: %v", err)
	}
	if prov.Task != "C38" || prov.License != "Apache-2.0" || len(prov.SHA256) < 3 {
		t.Fatalf("unexpected C38 provenance: %+v", prov)
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

	// 2. Validate SERVICE_POLICY.md and MAINTENANCE.md completeness.
	contractRaw, err := os.ReadFile(filepath.Join(fxDir, "positive", "policy-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract c38PolicyContract
	if err := json.Unmarshal(contractRaw, &contract); err != nil {
		t.Fatal(err)
	}
	for _, docRel := range contract.RequiredDocs {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(docRel)))
		if err != nil {
			t.Fatalf("missing policy doc %s: %v", docRel, err)
		}
		text := string(raw)
		for _, token := range contract.RequiredTokens[docRel] {
			if !strings.Contains(text, token) {
				t.Fatalf("policy doc %s missing required token %q", docRel, token)
			}
		}
	}

	// 3. Negative Case: Writer killed at staged-byte/manifest boundary recovers cleanly on restart.
	baseDir := t.TempDir()
	qDir := filepath.Join(baseDir, "quarantine")
	sDir := filepath.Join(baseDir, "sealstore")
	cDir := filepath.Join(baseDir, "custody")

	ls, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: cDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ls.Close()

	payload := []byte("2026-11-14T15:15:00Z policy-host breachatlas: c38-boundary-record\n")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	sz := int64(len(payload))
	now := time.Date(2026, 11, 14, 15, 15, 0, 0, time.UTC).Format(time.RFC3339)

	q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{QuarantineDir: qDir, SyncDir: true}, evidence.UploadRequest{
		SchemaVersion:  "1",
		UploadID:       "upl-c38-01",
		CaseID:         "c38-case",
		EvidenceID:     "c38-ev",
		MediaType:      "text/plain",
		Filename:       "c38.log",
		ExpectedSize:   &sz,
		ExpectedSHA256: hexSum,
		Body:           bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := ls.AppendEvent(ctx, custody.AppendEventRequest{
		EventID:    "cust-c38-01",
		CaseID:     "c38-case",
		EvidenceID: "c38-ev",
		EventType:  "intake_seal",
		Actor:      "analyst",
		Timestamp:  now,
		Reason:     "C38 boundary test",
		Provider:   "local",
	})
	if err != nil {
		t.Fatal(err)
	}

	ssFault, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sDir,
		QuarantineDir: qDir,
		SyncDir:       true,
		Faults:        evidence.SealFaults{FailAfterBlobSyncBeforeManifest: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssFault.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "op-c38-fault",
		Quarantined:    q,
		ExpectedSHA256: hexSum,
		AcquiredAt:     now,
		CustodyRoot:    ev.CustodyRoot,
	}); !errors.Is(err, evidence.ErrSealInterrupted) {
		t.Fatalf("expected ErrSealInterrupted at manifest boundary, got %v", err)
	}
	_ = ssFault.Close()

	// Reopen cleanly and commit; verify idempotent replay and quota exhaustion.
	ss, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:         sDir,
		QuarantineDir:   qDir,
		MaxStorageBytes: sz + 10,
		SyncDir:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()

	sealed, err := ss.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "op-c38-ok",
		Quarantined:    q,
		ExpectedSHA256: hexSum,
		AcquiredAt:     now,
		CustodyRoot:    ev.CustodyRoot,
	})
	if err != nil {
		t.Fatalf("clean seal after restart failed: %v", err)
	}
	replayed, err := ss.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "op-c38-ok",
		Quarantined:    q,
		ExpectedSHA256: hexSum,
		AcquiredAt:     now,
		CustodyRoot:    ev.CustodyRoot,
	})
	if err != nil || !replayed.IdempotentReplay {
		t.Fatalf("expected idempotent replay, got %+v err=%v", replayed, err)
	}

	// Exceed storage quota with a second upload.
	payload2 := []byte("2026-11-14T15:16:00Z policy-host breachatlas: c38-quota-overflow-record\n")
	sum2 := sha256.Sum256(payload2)
	hexSum2 := hex.EncodeToString(sum2[:])
	sz2 := int64(len(payload2))
	q2, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{QuarantineDir: qDir, SyncDir: true}, evidence.UploadRequest{
		SchemaVersion:  "1",
		UploadID:       "upl-c38-02",
		CaseID:         "c38-case",
		EvidenceID:     "c38-ev-2",
		MediaType:      "text/plain",
		Filename:       "c38-2.log",
		ExpectedSize:   &sz2,
		ExpectedSHA256: hexSum2,
		Body:           bytes.NewReader(payload2),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ss.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "op-c38-quota",
		Quarantined:    q2,
		ExpectedSHA256: hexSum2,
		AcquiredAt:     now,
		CustodyRoot:    ev.CustodyRoot,
	}); !errors.Is(err, evidence.ErrStorageQuotaExceeded) {
		t.Fatalf("expected ErrStorageQuotaExceeded, got %v", err)
	}

	// Sealed source bytes from the first commit remain intact.
	got, err := os.ReadFile(filepath.Join(sDir, sealed.BlobRelPath))
	if err != nil || sha256.Sum256(got) != sum {
		t.Fatalf("sealed source bytes modified or missing")
	}
}

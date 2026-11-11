package tests_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

type c11PositiveFixture struct {
	SchemaVersion string `json:"schema_version"`
	CaseID        string `json:"case_id"`
	EvidenceID    string `json:"evidence_id"`
	Events        []struct {
		EventID       string `json:"event_id"`
		EventType     string `json:"event_type"`
		Actor         string `json:"actor"`
		Timestamp     string `json:"timestamp"`
		Reason        string `json:"reason"`
		FromCustodian string `json:"from_custodian"`
		ToCustodian   string `json:"to_custodian"`
	} `json:"events"`
}

type c11InvalidFixture struct {
	SchemaVersion   string `json:"schema_version"`
	CaseID          string `json:"case_id"`
	EvidenceID      string `json:"evidence_id"`
	EventID         string `json:"event_id"`
	EventType       string `json:"event_type"`
	Actor           string `json:"actor"`
	Timestamp       string `json:"timestamp"`
	Reason          string `json:"reason"`
	Provider        string `json:"provider,omitempty"`
	ExpectedFailure string `json:"expected_failure"`
}

type c11TamperFixture struct {
	SchemaVersion string `json:"schema_version"`
	CaseID        string `json:"case_id"`
	EvidenceID    string `json:"evidence_id"`
	Events        []struct {
		EventID       string `json:"event_id"`
		EventType     string `json:"event_type"`
		Actor         string `json:"actor"`
		Timestamp     string `json:"timestamp"`
		Reason        string `json:"reason"`
		FromCustodian string `json:"from_custodian"`
		ToCustodian   string `json:"to_custodian"`
	} `json:"events"`
	TamperedSequence int    `json:"tampered_event_sequence"`
	TamperedField    string `json:"tampered_field"`
	TamperedValue    string `json:"tampered_value"`
	ExpectedFailure  string `json:"expected_failure"`
}

func getC11FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "fixtures", "breachatlas", "C11")
	if filepath.Base(wd) != "tests" {
		dir = filepath.Join(wd, "tests", "fixtures", "breachatlas", "C11")
	}
	return dir
}

func TestC11FixturesAndCustodyInvariants(t *testing.T) {
	fixturesDir := getC11FixturesDir(t)

	// 1. Verify C11 provenance & Apache-2.0 hashes
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

	rootTmp := t.TempDir()
	quarantineDir := filepath.Join(rootTmp, "quarantine")
	sealDir := filepath.Join(rootTmp, "sealstore")
	custodyDir := filepath.Join(rootTmp, "custody_ledger")

	qCfg := evidence.UploadConfig{QuarantineDir: quarantineDir, BufferSize: 32, SyncDir: true}
	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("open seal store: %v", err)
	}
	defer sealStore.Close()

	ledgerStore, err := custody.OpenLedgerStore(custody.LedgerConfig{
		RootDir: custodyDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("open custody ledger: %v", err)
	}
	defer ledgerStore.Close()

	// 2. Integration with upstream C08 -> C09 -> C10 -> C11
	payload := "2026-11-11T11:00:00Z system=srv-core-01 event=disk_acquisition status=success\n"
	payloadHash := sha256.Sum256([]byte(payload))
	payloadHex := hex.EncodeToString(payloadHash[:])
	payloadSize := int64(len(payload))

	var pos c11PositiveFixture
	posRaw, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "valid-custody-chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(posRaw, &pos); err != nil {
		t.Fatal(err)
	}

	quarantined, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-c11-0001",
		CaseID:        pos.CaseID,
		EvidenceID:    pos.EvidenceID,
		MediaType:     "text/plain",
		Filename:      "disk-acq.log",
		ExpectedSize:  &payloadSize,
		Body:          strings.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("quarantine upload: %v", err)
	}

	initialCustodyRoot := custody.GenesisPrevHash
	sealedManifest, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
		OperationID:    "op-seal-c11-0001",
		Quarantined:    quarantined,
		ExpectedSHA256: payloadHex,
		AcquiredAt:     pos.Events[0].Timestamp,
		CustodyRoot:    initialCustodyRoot,
	})
	if err != nil {
		t.Fatalf("seal quarantined: %v", err)
	}

	// Verify evidence bytes are intact (C10)
	verifyRes, err := evidence.VerifyStoreEvidence(context.Background(), sealStore, pos.CaseID, pos.EvidenceID, evidence.VerifyOptions{})
	if err != nil || !verifyRes.Verified {
		t.Fatalf("verify sealed evidence: err=%v, res=%+v", err, verifyRes)
	}

	// Append custody transfer events from fixture (C11)
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var lastRoot string
	for i, evReq := range pos.Events {
		ev, err := ledgerStore.AppendEvent(context.Background(), custody.AppendEventRequest{
			EventID:       evReq.EventID,
			CaseID:        pos.CaseID,
			EvidenceID:    pos.EvidenceID,
			EventType:     evReq.EventType,
			Actor:         evReq.Actor,
			Timestamp:     evReq.Timestamp,
			Reason:        evReq.Reason,
			FromCustodian: evReq.FromCustodian,
			ToCustodian:   evReq.ToCustodian,
			PrivateKey:    privKey,
		})
		if err != nil {
			t.Fatalf("append custody event #%d: %v", i+1, err)
		}
		if ev.Sequence != uint64(i+1) {
			t.Fatalf("event #%d sequence got %d, want %d", i+1, ev.Sequence, i+1)
		}
		if ev.Actor != evReq.Actor || ev.Reason != evReq.Reason || ev.Timestamp != evReq.Timestamp {
			t.Fatalf("event #%d field mismatch", i+1)
		}
		if ev.PrevHash == "" || ev.EventDigest == "" || ev.CustodyRoot == "" {
			t.Fatalf("event #%d missing hashes", i+1)
		}
		lastRoot = ev.CustodyRoot
	}

	// Verify complete chain
	chainOk, err := ledgerStore.VerifyChain(pos.CaseID, pos.EvidenceID)
	if err != nil || !chainOk {
		t.Fatalf("custody chain verification failed: %v", err)
	}

	currentRoot, err := ledgerStore.CurrentRoot(pos.CaseID, pos.EvidenceID)
	if err != nil || currentRoot != lastRoot {
		t.Fatalf("current root mismatch: got %q, want %q", currentRoot, lastRoot)
	}

	events, err := ledgerStore.ListEvents(pos.CaseID, pos.EvidenceID)
	if err != nil || len(events) != len(pos.Events) {
		t.Fatalf("list events mismatch: got %d, want %d", len(events), len(pos.Events))
	}

	// 3. Negative cases from fixtures
	t.Run("MissingActorRejected", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "missing-actor.json"))
		if err != nil {
			t.Fatal(err)
		}
		var inv c11InvalidFixture
		if err := json.Unmarshal(raw, &inv); err != nil {
			t.Fatal(err)
		}
		_, err = ledgerStore.AppendEvent(context.Background(), custody.AppendEventRequest{
			EventID:    inv.EventID,
			CaseID:     inv.CaseID,
			EvidenceID: inv.EvidenceID,
			EventType:  inv.EventType,
			Actor:      inv.Actor,
			Timestamp:  inv.Timestamp,
			Reason:     inv.Reason,
		})
		if !errors.Is(err, custody.ErrMissingActor) {
			t.Fatalf("expected ErrMissingActor, got %v", err)
		}
	})

	t.Run("MissingReasonRejected", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "missing-reason.json"))
		if err != nil {
			t.Fatal(err)
		}
		var inv c11InvalidFixture
		if err := json.Unmarshal(raw, &inv); err != nil {
			t.Fatal(err)
		}
		_, err = ledgerStore.AppendEvent(context.Background(), custody.AppendEventRequest{
			EventID:    inv.EventID,
			CaseID:     inv.CaseID,
			EvidenceID: inv.EvidenceID,
			EventType:  inv.EventType,
			Actor:      inv.Actor,
			Timestamp:  inv.Timestamp,
			Reason:     inv.Reason,
		})
		if !errors.Is(err, custody.ErrMissingReason) {
			t.Fatalf("expected ErrMissingReason, got %v", err)
		}
	})

	t.Run("UnavailableProviderRejected", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "unavailable-provider.json"))
		if err != nil {
			t.Fatal(err)
		}
		var inv c11InvalidFixture
		if err := json.Unmarshal(raw, &inv); err != nil {
			t.Fatal(err)
		}
		_, err = ledgerStore.AppendEvent(context.Background(), custody.AppendEventRequest{
			EventID:    inv.EventID,
			CaseID:     inv.CaseID,
			EvidenceID: inv.EvidenceID,
			EventType:  inv.EventType,
			Actor:      inv.Actor,
			Timestamp:  inv.Timestamp,
			Reason:     inv.Reason,
			Provider:   inv.Provider,
		})
		if !errors.Is(err, custody.ErrUnavailableProvider) {
			t.Fatalf("expected ErrUnavailableProvider, got %v", err)
		}
	})

	// 4. Verify sealed source bytes were never modified
	blobDiskBytes, err := os.ReadFile(filepath.Join(sealDir, sealedManifest.BlobRelPath))
	if err != nil || !bytes.Equal(blobDiskBytes, []byte(payload)) {
		t.Fatalf("sealed source bytes modified during custody operations: %v", err)
	}
}

func TestCustodyLedgerAntiRewriteAndRestart(t *testing.T) {
	fixturesDir := getC11FixturesDir(t)
	rootTmp := t.TempDir()
	custodyDir := filepath.Join(rootTmp, "custody_ledger")

	store, err := custody.OpenLedgerStore(custody.LedgerConfig{
		RootDir: custodyDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	caseID := "case-2026-011"
	evidenceID := "ev-c11-0004"

	// 1. Append 2 events from tamper fixture
	raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "tampered-ledger-rewrite.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tamperFix c11TamperFixture
	if err := json.Unmarshal(raw, &tamperFix); err != nil {
		t.Fatal(err)
	}

	for _, e := range tamperFix.Events {
		_, err := store.AppendEvent(context.Background(), custody.AppendEventRequest{
			EventID:       e.EventID,
			CaseID:        caseID,
			EvidenceID:    evidenceID,
			EventType:     e.EventType,
			Actor:         e.Actor,
			Timestamp:     e.Timestamp,
			Reason:        e.Reason,
			FromCustodian: e.FromCustodian,
			ToCustodian:   e.ToCustodian,
		})
		if err != nil {
			t.Fatalf("append initial event: %v", err)
		}
	}

	// Verify chain is valid before tamper
	valid, err := store.VerifyChain(caseID, evidenceID)
	if err != nil || !valid {
		t.Fatalf("chain should be valid before tamper: %v", err)
	}

	// 2. Tamper with historical event (rewrite on disk)
	filePath := filepath.Join(custodyDir, "custody", caseID, evidenceID+".jsonl")
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(fileBytes)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d", len(lines))
	}

	var ev1 custody.CustodyEvent
	if err := json.Unmarshal([]byte(lines[0]), &ev1); err != nil {
		t.Fatal(err)
	}
	// Tamper actor
	ev1.Actor = tamperFix.TamperedValue
	tamperedEv1Bytes, _ := json.Marshal(ev1)
	lines[0] = string(tamperedEv1Bytes)

	tamperedContent := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filePath, []byte(tamperedContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Close and reopen store: recovery must fail on tampered ledger file!
	_ = store.Close()

	_, err = custody.OpenLedgerStore(custody.LedgerConfig{
		RootDir: custodyDir,
		SyncDir: true,
	})
	if err == nil {
		t.Fatalf("expected OpenLedgerStore to fail on tampered history, but succeeded")
	}
	if !errors.Is(err, custody.ErrChainCorrupted) && !errors.Is(err, custody.ErrHashMismatch) {
		t.Fatalf("expected ErrChainCorrupted or ErrHashMismatch on tampered history, got %v", err)
	}

	// 3. Restart and recovery test with clean store
	cleanCustodyDir := filepath.Join(rootTmp, "clean_custody")
	cleanStore1, err := custody.OpenLedgerStore(custody.LedgerConfig{
		RootDir: cleanCustodyDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	evA, err := cleanStore1.AppendEvent(context.Background(), custody.AppendEventRequest{
		CaseID:     "case-restart-01",
		EvidenceID: "ev-restart-01",
		Actor:      "analyst-1",
		Timestamp:  "2026-11-11T12:00:00Z",
		Reason:     "Initial check-in",
	})
	if err != nil {
		t.Fatal(err)
	}

	evB, err := cleanStore1.AppendEvent(context.Background(), custody.AppendEventRequest{
		CaseID:     "case-restart-01",
		EvidenceID: "ev-restart-01",
		Actor:      "analyst-2",
		Timestamp:  "2026-11-11T12:30:00Z",
		Reason:     "Transfer to analyst-2",
	})
	if err != nil {
		t.Fatal(err)
	}

	rootBeforeRestart, err := cleanStore1.CurrentRoot("case-restart-01", "ev-restart-01")
	if err != nil || rootBeforeRestart != evB.CustodyRoot {
		t.Fatalf("root mismatch before restart: %q vs %q", rootBeforeRestart, evB.CustodyRoot)
	}

	_ = cleanStore1.Close()

	// Reopen after restart
	cleanStore2, err := custody.OpenLedgerStore(custody.LedgerConfig{
		RootDir: cleanCustodyDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("reopen after restart failed: %v", err)
	}
	defer cleanStore2.Close()

	reopenedEvents, err := cleanStore2.ListEvents("case-restart-01", "ev-restart-01")
	if err != nil || len(reopenedEvents) != 2 {
		t.Fatalf("expected 2 recovered events, got %d (err=%v)", len(reopenedEvents), err)
	}
	if reopenedEvents[0].EventDigest != evA.EventDigest || reopenedEvents[1].EventDigest != evB.EventDigest {
		t.Fatalf("event digests mismatch after restart recovery")
	}

	rootAfterRestart, err := cleanStore2.CurrentRoot("case-restart-01", "ev-restart-01")
	if err != nil || rootAfterRestart != rootBeforeRestart {
		t.Fatalf("root mismatch after restart: got %q, want %q", rootAfterRestart, rootBeforeRestart)
	}

	// Continue appending after restart
	evC, err := cleanStore2.AppendEvent(context.Background(), custody.AppendEventRequest{
		CaseID:     "case-restart-01",
		EvidenceID: "ev-restart-01",
		Actor:      "analyst-3",
		Timestamp:  "2026-11-11T13:00:00Z",
		Reason:     "Final return",
	})
	if err != nil {
		t.Fatalf("append after restart: %v", err)
	}
	if evC.Sequence != 3 || evC.PrevHash != evB.EventDigest {
		t.Fatalf("event after restart broken sequence/prev_hash: %+v", evC)
	}

	validAfterAppend, err := cleanStore2.VerifyChain("case-restart-01", "ev-restart-01")
	if err != nil || !validAfterAppend {
		t.Fatalf("chain invalid after post-restart append: %v", err)
	}
}

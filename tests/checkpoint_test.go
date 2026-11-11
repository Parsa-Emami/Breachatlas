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
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

func getC12FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "fixtures", "breachatlas", "C12")
	if filepath.Base(wd) != "tests" {
		dir = filepath.Join(wd, "tests", "fixtures", "breachatlas", "C12")
	}
	return dir
}

// TestC12ProvenanceAndApache2 verifies synthetic fixture provenance, license, and SHA-256 integrity.
func TestC12ProvenanceAndApache2(t *testing.T) {
	fixturesDir := getC12FixturesDir(t)
	provPath := filepath.Join(fixturesDir, "provenance.json")
	provBytes, err := os.ReadFile(provPath)
	if err != nil {
		t.Fatalf("failed to read C12 provenance: %v", err)
	}

	var prov Provenance
	if err := json.Unmarshal(provBytes, &prov); err != nil {
		t.Fatalf("failed to unmarshal C12 provenance: %v", err)
	}

	if prov.License != "Apache-2.0" {
		t.Fatalf("expected Apache-2.0 license, got %q", prov.License)
	}
	if len(prov.SHA256) < 7 {
		t.Fatalf("expected at least 7 fixture hashes, got %d", len(prov.SHA256))
	}

	for relPath, expectedSHA := range prov.SHA256 {
		filePath := filepath.Join(fixturesDir, relPath)
		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("missing fixture file %s: %v", relPath, err)
		}
		h := sha256.Sum256(content)
		gotSHA := hex.EncodeToString(h[:])
		if gotSHA != expectedSHA {
			t.Fatalf("fixture %s sha256 mismatch: got %s, want %s", relPath, gotSHA, expectedSHA)
		}
	}

	// Verify outcomes.json parseable and non-empty
	outcomesRaw, err := os.ReadFile(filepath.Join(fixturesDir, "expected-output", "outcomes.json"))
	if err != nil {
		t.Fatalf("read outcomes.json: %v", err)
	}
	var outcomes map[string]map[string]any
	if err := json.Unmarshal(outcomesRaw, &outcomes); err != nil {
		t.Fatalf("unmarshal outcomes.json: %v", err)
	}
	if len(outcomes) < 6 {
		t.Fatalf("expected at least 6 outcomes, got %d", len(outcomes))
	}
}

// TestC12EndToEndCheckpointLifecycle verifies upload -> quarantine -> seal -> custody events -> checkpoint creation -> external store -> verification.
func TestC12EndToEndCheckpointLifecycle(t *testing.T) {
	rootTmp := t.TempDir()
	quarantineDir := filepath.Join(rootTmp, "quarantine")
	sealDir := filepath.Join(rootTmp, "sealstore")
	custodyDir := filepath.Join(rootTmp, "custody_ledger")
	checkpointDir := filepath.Join(rootTmp, "checkpoints_external")

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

	chkStore, err := custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{
		RootDir: checkpointDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("open checkpoint store: %v", err)
	}
	defer chkStore.Close()

	// 1. Evidence upload and sealing (C08 -> C09 -> C10)
	caseID := "case-c12-e2e"
	evidenceID := "ev-c12-e2e-001"
	payload := "2026-11-11T11:00:00Z system=core-fw event=traffic_anomaly src=10.0.0.5 dst=198.51.100.2\n"
	payloadHash := sha256.Sum256([]byte(payload))
	payloadHex := hex.EncodeToString(payloadHash[:])
	payloadSize := int64(len(payload))

	quarantined, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-c12-0001",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		MediaType:     "text/plain",
		Filename:      "firewall-anomaly.log",
		ExpectedSize:  &payloadSize,
		Body:          strings.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("quarantine upload: %v", err)
	}

	sealedManifest, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
		OperationID:    "op-seal-c12-0001",
		Quarantined:    quarantined,
		ExpectedSHA256: payloadHex,
		AcquiredAt:     "2026-11-11T11:05:00Z",
		CustodyRoot:    custody.GenesisPrevHash,
	})
	if err != nil {
		t.Fatalf("seal quarantined evidence: %v", err)
	}

	// Capture sealed evidence blob bytes to verify immutability
	blobFullPath := filepath.Join(sealDir, filepath.FromSlash(sealedManifest.BlobRelPath))
	initialBlobBytes, err := os.ReadFile(blobFullPath)
	if err != nil {
		t.Fatalf("read sealed blob: %v", err)
	}
	initialBlobSHA := sha256.Sum256(initialBlobBytes)

	// 2. Append custody events (C11)
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustedPubHex := hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	keyID := "key-c12-trusted-signer"

	ev1, err := ledgerStore.AppendEvent(context.Background(), custody.AppendEventRequest{
		EventID:       "cust-ev-001",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		EventType:     "acquisition",
		Actor:         "officer-alice",
		Timestamp:     "2026-11-11T11:10:00Z",
		Reason:        "Captured anomaly log during perimeter sweep",
		FromCustodian: "network-team",
		ToCustodian:   "evidence-vault",
		PrivateKey:    privKey,
	})
	if err != nil {
		t.Fatalf("append event 1: %v", err)
	}

	ev2, err := ledgerStore.AppendEvent(context.Background(), custody.AppendEventRequest{
		EventID:       "cust-ev-002",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		EventType:     "transfer",
		Actor:         "analyst-bob",
		Timestamp:     "2026-11-11T11:20:00Z",
		Reason:        "Checked out evidence for deep inspection",
		FromCustodian: "evidence-vault",
		ToCustodian:   "forensics-lab",
		PrivateKey:    privKey,
	})
	if err != nil {
		t.Fatalf("append event 2: %v", err)
	}
	_ = ev1

	// 3. Create independent signed checkpoint (C12)
	now := time.Now().UTC()
	chk, err := custody.CreateCheckpoint(context.Background(), ledgerStore, custody.CreateCheckpointRequest{
		CheckpointID: "chk-c12-e2e-001",
		CaseID:       caseID,
		EvidenceID:   evidenceID,
		Sequence:     ev2.Sequence,
		KeyID:        keyID,
		Revision:     1,
		IssuedAt:     now.Format(time.RFC3339Nano),
		ExpiresAt:    now.Add(24 * time.Hour).Format(time.RFC3339Nano),
		Metadata: map[string]string{
			"witness": "security-officer-99",
		},
		PrivateKey: privKey,
	})
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}

	if chk.CustodyRoot != ev2.CustodyRoot {
		t.Fatalf("checkpoint custody root mismatch: got %s, want %s", chk.CustodyRoot, ev2.CustodyRoot)
	}
	if chk.PublicKey != trustedPubHex {
		t.Fatalf("checkpoint public key mismatch")
	}

	// 4. Save and retrieve checkpoint in FileCheckpointStore
	if err := chkStore.SaveCheckpoint(context.Background(), *chk); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}

	retrieved, err := chkStore.GetCheckpoint(context.Background(), caseID, evidenceID, chk.CheckpointID)
	if err != nil {
		t.Fatalf("get checkpoint: %v", err)
	}
	if retrieved.CheckpointID != chk.CheckpointID || retrieved.CustodyRoot != chk.CustodyRoot {
		t.Fatalf("retrieved checkpoint mismatch: got %+v, want %+v", retrieved, chk)
	}

	list, err := chkStore.ListCheckpoints(context.Background(), caseID, evidenceID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list checkpoints failed: err=%v, count=%d", err, len(list))
	}

	latest, err := chkStore.GetLatestCheckpoint(context.Background(), caseID, evidenceID)
	if err != nil || latest.CheckpointID != chk.CheckpointID {
		t.Fatalf("get latest checkpoint failed: err=%v, latest=%+v", err, latest)
	}

	// 5. Verify checkpoint with outside trust
	trustedKeys := map[string]string{
		keyID: trustedPubHex,
	}
	tracker := custody.NewCheckpointTracker()

	verifyRes, err := custody.VerifyCheckpoint(context.Background(), ledgerStore, *chk, custody.VerifyCheckpointOptions{
		TrustedPublicKeys: trustedKeys,
		Tracker:           tracker,
		Now:               now,
		StrictReplay:      false,
	})
	if err != nil || !verifyRes.Verified {
		t.Fatalf("verify checkpoint failed: err=%v, res=%+v", err, verifyRes)
	}
	if verifyRes.Status != custody.CheckpointCodeVerified {
		t.Fatalf("expected status %s, got %s", custody.CheckpointCodeVerified, verifyRes.Status)
	}
	if verifyRes.LedgerRoot != ev2.CustodyRoot {
		t.Fatalf("verify result ledger root mismatch: got %s, want %s", verifyRes.LedgerRoot, ev2.CustodyRoot)
	}

	// Verify tracker recorded accepted state
	accepted, ok := tracker.GetAccepted(caseID, evidenceID)
	if !ok || accepted.CheckpointID != chk.CheckpointID || accepted.Revision != 1 {
		t.Fatalf("tracker accepted state mismatch: ok=%v, accepted=%+v", ok, accepted)
	}

	// 6. Immutability check: sealed source bytes must remain bit-for-bit identical
	finalBlobBytes, err := os.ReadFile(blobFullPath)
	if err != nil {
		t.Fatalf("read final sealed blob: %v", err)
	}
	finalBlobSHA := sha256.Sum256(finalBlobBytes)
	if !bytes.Equal(initialBlobSHA[:], finalBlobSHA[:]) {
		t.Fatalf("sealed source bytes modified! initial SHA: %x, final SHA: %x", initialBlobSHA, finalBlobSHA)
	}
}

// TestC12IndependentCheckpointDetectsLedgerRewrite verifies requirement F06:
// "Independent checkpoint detects ledger rewrite; signer trust must be supplied outside bundle."
func TestC12IndependentCheckpointDetectsLedgerRewrite(t *testing.T) {
	rootTmp := t.TempDir()
	custodyDir := filepath.Join(rootTmp, "custody_ledger")

	ledgerStore, err := custody.OpenLedgerStore(custody.LedgerConfig{
		RootDir: custodyDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("open custody ledger: %v", err)
	}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustedPubHex := hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	keyID := "key-c12-auditor-root"

	caseID := "case-c12-rewrite"
	evidenceID := "ev-c12-rewrite-001"

	// Create legitimate events
	ev1, err := ledgerStore.AppendEvent(context.Background(), custody.AppendEventRequest{
		EventID:       "ev-rew-01",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		EventType:     "acquisition",
		Actor:         "analyst-carol",
		Timestamp:     "2026-11-11T10:00:00Z",
		Reason:        "Initial disk image ingestion",
		FromCustodian: "field-team",
		ToCustodian:   "evidence-locker-01",
		PrivateKey:    privKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	ev2, err := ledgerStore.AppendEvent(context.Background(), custody.AppendEventRequest{
		EventID:       "ev-rew-02",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		EventType:     "transfer",
		Actor:         "officer-dave",
		Timestamp:     "2026-11-11T10:30:00Z",
		Reason:        "Transfer to lab workstation",
		FromCustodian: "evidence-locker-01",
		ToCustodian:   "forensics-workstation-02",
		PrivateKey:    privKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	ev3, err := ledgerStore.AppendEvent(context.Background(), custody.AppendEventRequest{
		EventID:       "ev-rew-03",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		EventType:     "analysis",
		Actor:         "examiner-eve",
		Timestamp:     "2026-11-11T11:00:00Z",
		Reason:        "Memory dump carving",
		FromCustodian: "forensics-workstation-02",
		ToCustodian:   "secure-vault-01",
		PrivateKey:    privKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = ev1
	_ = ev2

	// Create an independent checkpoint certifying the legitimate sequence 3 custody root
	legitCheckpoint, err := custody.CreateCheckpoint(context.Background(), ledgerStore, custody.CreateCheckpointRequest{
		CheckpointID: "chk-c12-legit-001",
		CaseID:       caseID,
		EvidenceID:   evidenceID,
		Sequence:     ev3.Sequence,
		KeyID:        keyID,
		Revision:     1,
		IssuedAt:     "2026-11-11T12:00:00Z",
		ExpiresAt:    "2027-11-11T12:00:00Z",
		PrivateKey:   privKey,
	})
	if err != nil {
		t.Fatalf("create legitimate checkpoint: %v", err)
	}

	trustedKeys := map[string]string{
		keyID: trustedPubHex,
	}

	// Step 1: Legitimate verification succeeds
	res, err := custody.VerifyCheckpoint(context.Background(), ledgerStore, *legitCheckpoint, custody.VerifyCheckpointOptions{
		TrustedPublicKeys: trustedKeys,
	})
	if err != nil || !res.Verified {
		t.Fatalf("expected legitimate verification to succeed: err=%v, res=%+v", err, res)
	}

	// Step 2: Now simulate an adversary rewriting the ledger on disk.
	// Scenario A: Adversary rewrote event 2 to disguise who handled the evidence,
	// and recomputed the hash chain so it is internally consistent, BUT the resulting sequence 3 root is altered!
	ledgerStore.Close()

	ledgerFile := filepath.Join(custodyDir, "custody", caseID, evidenceID+".jsonl")
	tamperedEv2 := custody.CustodyEvent{
		SchemaVersion: "1",
		EventID:       "ev-rew-02",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		Sequence:      2,
		EventType:     "transfer",
		Actor:         "attacker-mallory", // Rewritten actor!
		Timestamp:     "2026-11-11T10:30:00Z",
		Reason:        "Transfer to lab workstation",
		FromCustodian: "evidence-locker-01",
		ToCustodian:   "forensics-workstation-02",
		PrevHash:      ev1.EventDigest,
	}
	tamperedEv2.EventDigest = custody.ComputeEventDigest(tamperedEv2)
	tamperedEv2.CustodyRoot = custody.ComputeCustodyRoot(ev1.CustodyRoot, tamperedEv2.EventDigest)

	tamperedEv3 := custody.CustodyEvent{
		SchemaVersion: "1",
		EventID:       "ev-rew-03",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		Sequence:      3,
		EventType:     "analysis",
		Actor:         "examiner-eve",
		Timestamp:     "2026-11-11T11:00:00Z",
		Reason:        "Memory dump carving",
		FromCustodian: "forensics-workstation-02",
		ToCustodian:   "secure-vault-01",
		PrevHash:      tamperedEv2.EventDigest,
	}
	tamperedEv3.EventDigest = custody.ComputeEventDigest(tamperedEv3)
	tamperedEv3.CustodyRoot = custody.ComputeCustodyRoot(tamperedEv2.CustodyRoot, tamperedEv3.EventDigest)

	// Write rewritten ledger to disk
	rewrittenContent := bytes.Buffer{}
	d1, _ := json.Marshal(ev1)
	rewrittenContent.Write(d1)
	rewrittenContent.WriteByte('\n')
	d2, _ := json.Marshal(tamperedEv2)
	rewrittenContent.Write(d2)
	rewrittenContent.WriteByte('\n')
	d3, _ := json.Marshal(tamperedEv3)
	rewrittenContent.Write(d3)
	rewrittenContent.WriteByte('\n')

	if err := os.WriteFile(ledgerFile, rewrittenContent.Bytes(), 0o600); err != nil {
		t.Fatalf("write rewritten ledger: %v", err)
	}

	// Reopen the ledger store with the rewritten ledger
	reopenedLedger, err := custody.OpenLedgerStore(custody.LedgerConfig{
		RootDir: custodyDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("reopen rewritten ledger store: %v", err)
	}
	defer reopenedLedger.Close()

	// Verify the rewritten ledger has a different sequence 3 root
	rewrittenEv3, err := reopenedLedger.GetEvent(caseID, evidenceID, 3)
	if err != nil {
		t.Fatalf("get rewritten event 3: %v", err)
	}
	if rewrittenEv3.CustodyRoot == legitCheckpoint.CustodyRoot {
		t.Fatalf("rewritten root unexpectedly matches legitimate checkpoint root!")
	}

	// Step 3: Verify that the independent checkpoint DETECTS the ledger rewrite!
	failRes, err := custody.VerifyCheckpoint(context.Background(), reopenedLedger, *legitCheckpoint, custody.VerifyCheckpointOptions{
		TrustedPublicKeys: trustedKeys,
	})
	if err == nil {
		t.Fatalf("expected ledger rewrite to fail verification, but got err=nil")
	}
	if !errors.Is(err, custody.ErrCheckpointRootMismatch) {
		t.Fatalf("expected ErrCheckpointRootMismatch, got %v", err)
	}
	if failRes.Verified {
		t.Fatalf("failRes.Verified must be false for rewritten ledger")
	}
	if failRes.Status != custody.CheckpointCodeRootMismatch {
		t.Fatalf("expected status %s, got %s", custody.CheckpointCodeRootMismatch, failRes.Status)
	}
}

// TestC12NegativeCasesFromFixtures validates the repository fixtures under tests/fixtures/breachatlas/C12/.
func TestC12NegativeCasesFromFixtures(t *testing.T) {
	fixturesDir := getC12FixturesDir(t)

	// Setup a reference ledger that matches the fixture parameters
	rootTmp := t.TempDir()
	ledgerDir := filepath.Join(rootTmp, "ledger")
	ledgerStore, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: ledgerDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ledgerStore.Close()

	caseID := "case-c12-001"
	evidenceID := "ev-c12-0001"

	// Append 3 events matching fixture events
	_, err = ledgerStore.AppendEvent(context.Background(), custody.AppendEventRequest{
		EventID:       "cust-ev-c12-0001",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		EventType:     "acquisition",
		Actor:         "analyst-carol",
		Timestamp:     "2026-11-11T10:00:00Z",
		Reason:        "Initial disk image ingestion and custody capture",
		FromCustodian: "field-team",
		ToCustodian:   "evidence-locker-01",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = ledgerStore.AppendEvent(context.Background(), custody.AppendEventRequest{
		EventID:       "cust-ev-c12-0002",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		EventType:     "transfer",
		Actor:         "officer-dave",
		Timestamp:     "2026-11-11T10:30:00Z",
		Reason:        "Transfer to digital forensics lab for examination",
		FromCustodian: "evidence-locker-01",
		ToCustodian:   "forensics-workstation-02",
	})
	if err != nil {
		t.Fatal(err)
	}

	ev3, err := ledgerStore.AppendEvent(context.Background(), custody.AppendEventRequest{
		EventID:       "cust-ev-c12-0003",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		EventType:     "analysis",
		Actor:         "examiner-eve",
		Timestamp:     "2026-11-11T11:00:00Z",
		Reason:        "Volatile artifact carving and timeline extraction",
		FromCustodian: "forensics-workstation-02",
		ToCustodian:   "secure-vault-01",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Read positive valid checkpoint to get trusted key
	posRaw, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "valid-checkpoint.json"))
	if err != nil {
		t.Fatal(err)
	}
	var validChk custody.Checkpoint
	if err := json.Unmarshal(posRaw, &validChk); err != nil {
		t.Fatal(err)
	}

	trustedKeys := map[string]string{
		validChk.KeyID: validChk.PublicKey,
	}
	evalTime, _ := time.Parse(time.RFC3339Nano, "2026-11-11T12:30:00Z")

	t.Run("PositiveFixtureVerified", func(t *testing.T) {
		res, err := custody.VerifyCheckpoint(context.Background(), ledgerStore, validChk, custody.VerifyCheckpointOptions{
			TrustedPublicKeys: trustedKeys,
			Now:               evalTime,
		})
		if err != nil || !res.Verified {
			t.Fatalf("expected valid checkpoint to verify: err=%v, res=%+v", err, res)
		}
		if res.Status != custody.CheckpointCodeVerified {
			t.Fatalf("expected status %s, got %s", custody.CheckpointCodeVerified, res.Status)
		}
		if res.LedgerRoot != ev3.CustodyRoot {
			t.Fatalf("root mismatch: %s != %s", res.LedgerRoot, ev3.CustodyRoot)
		}
	})

	t.Run("UntrustedSignerRejected", func(t *testing.T) {
		untrustedRaw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "untrusted-signer.json"))
		if err != nil {
			t.Fatal(err)
		}
		var untrustedChk custody.Checkpoint
		if err := json.Unmarshal(untrustedRaw, &untrustedChk); err != nil {
			t.Fatal(err)
		}

		// Outside trust map does NOT trust key-c12-untrusted-99
		res, err := custody.VerifyCheckpoint(context.Background(), ledgerStore, untrustedChk, custody.VerifyCheckpointOptions{
			TrustedPublicKeys: trustedKeys,
			Now:               evalTime,
		})
		if !errors.Is(err, custody.ErrCheckpointUntrustedSigner) {
			t.Fatalf("expected ErrCheckpointUntrustedSigner, got %v", err)
		}
		if res.Verified {
			t.Fatalf("res.Verified must be false for untrusted signer")
		}
		if res.Status != custody.CheckpointCodeUntrustedSigner {
			t.Fatalf("expected status %s, got %s", custody.CheckpointCodeUntrustedSigner, res.Status)
		}

		// Also check when TrustedPublicKeys is nil
		_, errNil := custody.VerifyCheckpoint(context.Background(), ledgerStore, validChk, custody.VerifyCheckpointOptions{
			TrustedPublicKeys: nil,
			Now:               evalTime,
		})
		if !errors.Is(errNil, custody.ErrCheckpointUntrustedSigner) {
			t.Fatalf("expected ErrCheckpointUntrustedSigner when map is nil, got %v", errNil)
		}

		// Also check when public key in checkpoint is spoofed / doesn't match allowlisted key
		spoofedChk := validChk
		spoofedChk.PublicKey = untrustedChk.PublicKey // Spoofed public key
		_, errSpoof := custody.VerifyCheckpoint(context.Background(), ledgerStore, spoofedChk, custody.VerifyCheckpointOptions{
			TrustedPublicKeys: trustedKeys,
			Now:               evalTime,
		})
		if !errors.Is(errSpoof, custody.ErrCheckpointUntrustedSigner) {
			t.Fatalf("expected ErrCheckpointUntrustedSigner for spoofed public key, got %v", errSpoof)
		}
	})

	t.Run("TamperedCheckpointBytesRejected", func(t *testing.T) {
		tamperedRaw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "tampered-checkpoint-bytes.json"))
		if err != nil {
			t.Fatal(err)
		}
		var tamperedChk custody.Checkpoint
		if err := json.Unmarshal(tamperedRaw, &tamperedChk); err != nil {
			t.Fatal(err)
		}

		res, err := custody.VerifyCheckpoint(context.Background(), ledgerStore, tamperedChk, custody.VerifyCheckpointOptions{
			TrustedPublicKeys: trustedKeys,
			Now:               evalTime,
		})
		if !errors.Is(err, custody.ErrCheckpointInvalidSignature) {
			t.Fatalf("expected ErrCheckpointInvalidSignature, got %v", err)
		}
		if res.Verified {
			t.Fatalf("res.Verified must be false for tampered signature")
		}
		if res.Status != custody.CheckpointCodeInvalidSignature {
			t.Fatalf("expected status %s, got %s", custody.CheckpointCodeInvalidSignature, res.Status)
		}
	})

	t.Run("ExpiredCheckpointRejected", func(t *testing.T) {
		expiredRaw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "expired-checkpoint.json"))
		if err != nil {
			t.Fatal(err)
		}
		var expiredChk custody.Checkpoint
		if err := json.Unmarshal(expiredRaw, &expiredChk); err != nil {
			t.Fatal(err)
		}

		res, err := custody.VerifyCheckpoint(context.Background(), ledgerStore, expiredChk, custody.VerifyCheckpointOptions{
			TrustedPublicKeys: trustedKeys,
			Now:               evalTime, // 2026-11-11, checkpoint expired in 2024
		})
		if !errors.Is(err, custody.ErrCheckpointExpired) {
			t.Fatalf("expected ErrCheckpointExpired, got %v", err)
		}
		if res.Verified {
			t.Fatalf("res.Verified must be false for expired checkpoint")
		}
		if res.Status != custody.CheckpointCodeExpired {
			t.Fatalf("expected status %s, got %s", custody.CheckpointCodeExpired, res.Status)
		}
	})

	t.Run("StaleReplayedRevisionRejected", func(t *testing.T) {
		staleRaw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "stale-replayed-revision.json"))
		if err != nil {
			t.Fatal(err)
		}
		var staleChk custody.Checkpoint
		if err := json.Unmarshal(staleRaw, &staleChk); err != nil {
			t.Fatal(err)
		}

		// Pre-populate tracker with a higher revision (Revision 2)
		tracker := custody.NewCheckpointTracker()
		tracker.Record(custody.Checkpoint{
			CheckpointID: "chk-c12-accepted-rev2",
			CaseID:       staleChk.CaseID,
			EvidenceID:   staleChk.EvidenceID,
			Sequence:     staleChk.Sequence,
			Revision:     2,
			CustodyRoot:  staleChk.CustodyRoot,
		})

		res, err := custody.VerifyCheckpoint(context.Background(), ledgerStore, staleChk, custody.VerifyCheckpointOptions{
			TrustedPublicKeys: trustedKeys,
			Tracker:           tracker,
			Now:               evalTime,
		})
		if !errors.Is(err, custody.ErrCheckpointStaleRevision) {
			t.Fatalf("expected ErrCheckpointStaleRevision, got %v", err)
		}
		if res.Verified {
			t.Fatalf("res.Verified must be false for stale revision")
		}
		if res.Status != custody.CheckpointCodeStaleRevision {
			t.Fatalf("expected status %s, got %s", custody.CheckpointCodeStaleRevision, res.Status)
		}

		// Invariant: prior accepted authority is never overwritten
		accepted, ok := tracker.GetAccepted(staleChk.CaseID, staleChk.EvidenceID)
		if !ok || accepted.Revision != 2 {
			t.Fatalf("accepted authority degraded or lost! accepted: %+v", accepted)
		}
	})

	t.Run("LedgerRewrittenRootMismatchRejected", func(t *testing.T) {
		rewriteRaw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "ledger-rewritten-root-mismatch.json"))
		if err != nil {
			t.Fatal(err)
		}
		var rewriteChk custody.Checkpoint
		if err := json.Unmarshal(rewriteRaw, &rewriteChk); err != nil {
			t.Fatal(err)
		}

		res, err := custody.VerifyCheckpoint(context.Background(), ledgerStore, rewriteChk, custody.VerifyCheckpointOptions{
			TrustedPublicKeys: trustedKeys,
			Now:               evalTime,
		})
		if !errors.Is(err, custody.ErrCheckpointRootMismatch) {
			t.Fatalf("expected ErrCheckpointRootMismatch, got %v", err)
		}
		if res.Verified {
			t.Fatalf("res.Verified must be false for root mismatch")
		}
		if res.Status != custody.CheckpointCodeRootMismatch {
			t.Fatalf("expected status %s, got %s", custody.CheckpointCodeRootMismatch, res.Status)
		}
	})
}

// TestC12AntiRollbackTrackerInvariants verifies monotonic progression and strict replay protection.
func TestC12AntiRollbackTrackerInvariants(t *testing.T) {
	tracker := custody.NewCheckpointTracker()
	caseID := "case-anti-rollback"
	evidenceID := "ev-anti-rollback"

	chk1 := custody.Checkpoint{
		CheckpointID: "chk-001",
		CaseID:       caseID,
		EvidenceID:   evidenceID,
		Sequence:     3,
		Revision:     1,
	}

	// 1. Initial check on empty tracker succeeds
	if err := tracker.Check(chk1, false); err != nil {
		t.Fatalf("initial check should succeed, got: %v", err)
	}
	tracker.Record(chk1)

	// 2. Sequence rollback attempt (sequence 2 < sequence 3)
	seqRollback := chk1
	seqRollback.CheckpointID = "chk-002"
	seqRollback.Sequence = 2
	seqRollback.Revision = 2
	if err := tracker.Check(seqRollback, false); !errors.Is(err, custody.ErrCheckpointStaleRevision) {
		t.Fatalf("expected ErrCheckpointStaleRevision for sequence rollback, got: %v", err)
	}

	// 3. Revision rollback attempt (revision 0 < revision 1)
	revRollback := chk1
	revRollback.CheckpointID = "chk-003"
	revRollback.Sequence = 4
	revRollback.Revision = 0
	if err := tracker.Check(revRollback, false); !errors.Is(err, custody.ErrCheckpointStaleRevision) {
		t.Fatalf("expected ErrCheckpointStaleRevision for revision rollback, got: %v", err)
	}

	// 4. Same revision with different CheckpointID (conflicting checkpoint)
	conflictChk := chk1
	conflictChk.CheckpointID = "chk-conflicting"
	conflictChk.Revision = 1
	if err := tracker.Check(conflictChk, false); !errors.Is(err, custody.ErrCheckpointStaleRevision) {
		t.Fatalf("expected ErrCheckpointStaleRevision for conflicting checkpoint at same revision, got: %v", err)
	}

	// 5. Strict replay rejection on same checkpoint
	if err := tracker.Check(chk1, true); !errors.Is(err, custody.ErrCheckpointStaleRevision) {
		t.Fatalf("expected ErrCheckpointStaleRevision in strict replay mode, got: %v", err)
	}

	// 6. Monotonic advance succeeds
	chk2 := custody.Checkpoint{
		CheckpointID: "chk-002-legit",
		CaseID:       caseID,
		EvidenceID:   evidenceID,
		Sequence:     4,
		Revision:     2,
	}
	if err := tracker.Check(chk2, true); err != nil {
		t.Fatalf("monotonic advance should succeed, got: %v", err)
	}
	tracker.Record(chk2)

	accepted, ok := tracker.GetAccepted(caseID, evidenceID)
	if !ok || accepted.Revision != 2 {
		t.Fatalf("expected accepted revision 2, got %+v", accepted)
	}
}

// TestC12MissingEvidenceAndBoundaryErrors verifies missing sequences, missing chains, and nil ledger handling.
func TestC12MissingEvidenceAndBoundaryErrors(t *testing.T) {
	rootTmp := t.TempDir()
	ledgerStore, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: rootTmp, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ledgerStore.Close()

	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubHex := hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	keyID := "key-c12-bounds"

	trustedKeys := map[string]string{keyID: pubHex}

	// 1. Missing evidence / sequence in ledger
	chk := custody.Checkpoint{
		SchemaVersion: "1",
		CheckpointID:  "chk-missing-01",
		CaseID:        "case-nonexistent",
		EvidenceID:    "ev-nonexistent",
		Sequence:      99,
		CustodyRoot:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		KeyID:         keyID,
		PublicKey:     pubHex,
		IssuedAt:      "2026-11-11T12:00:00Z",
		Revision:      1,
	}
	sig := ed25519.Sign(privKey, custody.CanonicalCheckpointBytes(chk))
	chk.Signature = hex.EncodeToString(sig)

	res, err := custody.VerifyCheckpoint(context.Background(), ledgerStore, chk, custody.VerifyCheckpointOptions{
		TrustedPublicKeys: trustedKeys,
	})
	if !errors.Is(err, custody.ErrCheckpointMissingEvidence) {
		t.Fatalf("expected ErrCheckpointMissingEvidence, got %v", err)
	}
	if res.Status != custody.CheckpointCodeMissingEvidence {
		t.Fatalf("expected status %s, got %s", custody.CheckpointCodeMissingEvidence, res.Status)
	}

	// 2. Nil ledger store
	_, errNilLedger := custody.VerifyCheckpoint(context.Background(), nil, chk, custody.VerifyCheckpointOptions{
		TrustedPublicKeys: trustedKeys,
	})
	if !errors.Is(errNilLedger, custody.ErrCheckpointMissingEvidence) {
		t.Fatalf("expected ErrCheckpointMissingEvidence for nil ledger, got %v", errNilLedger)
	}

	// 3. Invalid checkpoint identifiers
	invalidChk := chk
	invalidChk.CaseID = "../evil/traversal"
	_, errTraversal := custody.VerifyCheckpoint(context.Background(), ledgerStore, invalidChk, custody.VerifyCheckpointOptions{
		TrustedPublicKeys: trustedKeys,
	})
	if !errors.Is(errTraversal, custody.ErrInvalidCheckpoint) {
		t.Fatalf("expected ErrInvalidCheckpoint for path traversal in caseID, got %v", errTraversal)
	}
}

// TestC12FileCheckpointStoreContainment verifies path traversal, symlink, and store closed protections.
func TestC12FileCheckpointStoreContainment(t *testing.T) {
	rootTmp := t.TempDir()
	store, err := custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{RootDir: rootTmp, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}

	chk := custody.Checkpoint{
		SchemaVersion: "1",
		CheckpointID:  "chk-safe-01",
		CaseID:        "case-safe",
		EvidenceID:    "ev-safe",
		Sequence:      1,
		CustodyRoot:   "1111111111111111111111111111111111111111111111111111111111111111",
		KeyID:         "key-safe",
		IssuedAt:      "2026-11-11T12:00:00Z",
		Revision:      1,
	}

	if err := store.SaveCheckpoint(context.Background(), chk); err != nil {
		t.Fatalf("save safe checkpoint: %v", err)
	}

	// 1. Path traversal rejected in SaveCheckpoint
	badChk := chk
	badChk.CaseID = "../escape"
	if err := store.SaveCheckpoint(context.Background(), badChk); !errors.Is(err, custody.ErrInvalidCheckpoint) && !errors.Is(err, custody.ErrPathTraversal) {
		t.Fatalf("expected path traversal / invalid identifier rejection, got: %v", err)
	}

	// 2. Path traversal rejected in GetCheckpoint
	if _, err := store.GetCheckpoint(context.Background(), "../escape", "ev-safe", "chk-safe-01"); !errors.Is(err, custody.ErrInvalidCheckpoint) && !errors.Is(err, custody.ErrPathTraversal) {
		t.Fatalf("expected GetCheckpoint traversal rejection, got: %v", err)
	}

	// 3. Closed store fails closed
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCheckpoint(context.Background(), chk); !errors.Is(err, custody.ErrCheckpointStoreClosed) {
		t.Fatalf("expected ErrCheckpointStoreClosed, got: %v", err)
	}
	if _, err := store.GetCheckpoint(context.Background(), "case-safe", "ev-safe", "chk-safe-01"); !errors.Is(err, custody.ErrCheckpointStoreClosed) {
		t.Fatalf("expected ErrCheckpointStoreClosed on get, got: %v", err)
	}
	if _, err := store.ListCheckpoints(context.Background(), "case-safe", "ev-safe"); !errors.Is(err, custody.ErrCheckpointStoreClosed) {
		t.Fatalf("expected ErrCheckpointStoreClosed on list, got: %v", err)
	}
}

// TestC12CheckpointTrackerRollbackAndConflictPrevention verifies tracker Record monotonicity, conflict detection, and count.
func TestC12CheckpointTrackerRollbackAndConflictPrevention(t *testing.T) {
	tracker := custody.NewCheckpointTracker()
	caseID := "case-tracker-mono"
	evidenceID := "ev-tracker-mono"

	chkRev2 := custody.Checkpoint{
		CheckpointID: "chk-rev-2",
		CaseID:       caseID,
		EvidenceID:   evidenceID,
		Sequence:     5,
		Revision:     2,
		CustodyRoot:  "2222222222222222222222222222222222222222222222222222222222222222",
	}

	if err := tracker.Record(chkRev2); err != nil {
		t.Fatalf("initial record failed: %v", err)
	}
	if tracker.Count() != 1 {
		t.Fatalf("expected tracker count 1, got %d", tracker.Count())
	}

	// 1. Attempt to record stale revision 1 must be rejected
	chkRev1 := chkRev2
	chkRev1.CheckpointID = "chk-rev-1"
	chkRev1.Revision = 1
	if err := tracker.Record(chkRev1); !errors.Is(err, custody.ErrCheckpointStaleRevision) {
		t.Fatalf("expected ErrCheckpointStaleRevision when recording revision 1 after 2, got: %v", err)
	}

	// 2. Attempt to record sequence rollback (seq 4 < 5) must be rejected
	chkSeqRollback := chkRev2
	chkSeqRollback.CheckpointID = "chk-seq-rollback"
	chkSeqRollback.Sequence = 4
	chkSeqRollback.Revision = 3
	if err := tracker.Record(chkSeqRollback); !errors.Is(err, custody.ErrCheckpointStaleRevision) {
		t.Fatalf("expected ErrCheckpointStaleRevision when recording sequence 4 after 5, got: %v", err)
	}

	// 3. Attempt to record conflicting checkpoint at same revision must be rejected
	chkConflict := chkRev2
	chkConflict.CheckpointID = "chk-conflict"
	if err := tracker.Record(chkConflict); !errors.Is(err, custody.ErrCheckpointStaleRevision) {
		t.Fatalf("expected ErrCheckpointStaleRevision for conflicting checkpoint ID at same revision, got: %v", err)
	}

	// 4. Same CheckpointID at same revision but different custody root must be rejected in Check and Record
	chkForgedRoot := chkRev2
	chkForgedRoot.CustodyRoot = "3333333333333333333333333333333333333333333333333333333333333333"
	if err := tracker.Check(chkForgedRoot, false); !errors.Is(err, custody.ErrCheckpointStaleRevision) {
		t.Fatalf("expected ErrCheckpointStaleRevision in Check for conflicting root at same ID/revision, got: %v", err)
	}
	if err := tracker.Record(chkForgedRoot); !errors.Is(err, custody.ErrCheckpointStaleRevision) {
		t.Fatalf("expected ErrCheckpointStaleRevision in Record for conflicting root at same ID/revision, got: %v", err)
	}

	// 5. Accepted authority remains rev2
	accepted, ok := tracker.GetAccepted(caseID, evidenceID)
	if !ok || accepted.CheckpointID != chkRev2.CheckpointID || accepted.Revision != 2 {
		t.Fatalf("accepted authority corrupted or overwritten! accepted: %+v", accepted)
	}
}

// TestC12FileCheckpointStoreImmutabilityAndOversized verifies idempotency, conflict rejection, and size boundaries.
func TestC12FileCheckpointStoreImmutabilityAndOversized(t *testing.T) {
	rootTmp := t.TempDir()
	store, err := custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{RootDir: rootTmp, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	caseID := "case-store-immut"
	evidenceID := "ev-store-immut"
	chk := custody.Checkpoint{
		SchemaVersion: "1",
		CheckpointID:  "chk-immut-01",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		Sequence:      1,
		CustodyRoot:   "4444444444444444444444444444444444444444444444444444444444444444",
		KeyID:         "key-trusted",
		IssuedAt:      "2026-11-11T12:00:00Z",
		Revision:      1,
	}

	// 1. Initial save succeeds
	if err := store.SaveCheckpoint(context.Background(), chk); err != nil {
		t.Fatalf("initial save failed: %v", err)
	}

	// 2. Idempotent save with exact same bytes succeeds
	if err := store.SaveCheckpoint(context.Background(), chk); err != nil {
		t.Fatalf("idempotent save should succeed, got: %v", err)
	}

	// 3. Conflicting save with same ID but different custody root must fail
	conflictingChk := chk
	conflictingChk.CustodyRoot = "5555555555555555555555555555555555555555555555555555555555555555"
	if err := store.SaveCheckpoint(context.Background(), conflictingChk); !errors.Is(err, custody.ErrImmutableHistory) {
		t.Fatalf("expected ErrImmutableHistory when overwriting existing checkpoint, got: %v", err)
	}

	// 4. Oversized checkpoint write rejected
	oversizedChk := chk
	oversizedChk.CheckpointID = "chk-oversized-01"
	oversizedChk.Metadata = map[string]string{
		"huge": strings.Repeat("A", custody.MaxCheckpointBytes+100),
	}
	if err := store.SaveCheckpoint(context.Background(), oversizedChk); !errors.Is(err, custody.ErrInvalidCheckpoint) {
		t.Fatalf("expected ErrInvalidCheckpoint for oversized checkpoint write, got: %v", err)
	}

	// 5. Oversized checkpoint file on disk rejected during read
	oversizedFile := filepath.Join(rootTmp, "checkpoints", caseID, evidenceID, "chk-oversized-disk.json")
	hugeData := make([]byte, custody.MaxCheckpointBytes+500)
	for i := range hugeData {
		hugeData[i] = ' '
	}
	if err := os.WriteFile(oversizedFile, hugeData, 0o600); err != nil {
		t.Fatalf("write huge disk file: %v", err)
	}
	if _, err := store.GetCheckpoint(context.Background(), caseID, evidenceID, "chk-oversized-disk"); !errors.Is(err, custody.ErrInvalidCheckpoint) {
		t.Fatalf("expected ErrInvalidCheckpoint when reading oversized checkpoint from disk, got: %v", err)
	}
}

// TestC12CanonicalBytesMutationSensitivity verifies that modifying any single field changes canonical bytes and invalidates signature.
func TestC12CanonicalBytesMutationSensitivity(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubHex := hex.EncodeToString(privKey.Public().(ed25519.PublicKey))

	base := custody.Checkpoint{
		SchemaVersion: "1",
		CheckpointID:  "chk-canonical-base",
		CaseID:        "case-base",
		EvidenceID:    "ev-base",
		Sequence:      10,
		CustodyRoot:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		KeyID:         "key-canon",
		PublicKey:     pubHex,
		IssuedAt:      "2026-11-11T12:00:00Z",
		ExpiresAt:     "2027-11-11T12:00:00Z",
		Revision:      1,
	}

	baseBytes := custody.CanonicalCheckpointBytes(base)
	sig := ed25519.Sign(privKey, baseBytes)
	base.Signature = hex.EncodeToString(sig)

	// Verify base signature verifies
	pubBytes, _ := hex.DecodeString(pubHex)
	if !ed25519.Verify(pubBytes, baseBytes, sig) {
		t.Fatal("base signature must verify")
	}

	// Test field mutations: each mutation must produce different canonical bytes and fail verification
	mutations := []struct {
		name string
		mut  func(c custody.Checkpoint) custody.Checkpoint
	}{
		{"SchemaVersion", func(c custody.Checkpoint) custody.Checkpoint { c.SchemaVersion = "2"; return c }},
		{"CheckpointID", func(c custody.Checkpoint) custody.Checkpoint { c.CheckpointID = "chk-mutated"; return c }},
		{"CaseID", func(c custody.Checkpoint) custody.Checkpoint { c.CaseID = "case-mutated"; return c }},
		{"EvidenceID", func(c custody.Checkpoint) custody.Checkpoint { c.EvidenceID = "ev-mutated"; return c }},
		{"Sequence", func(c custody.Checkpoint) custody.Checkpoint { c.Sequence = 11; return c }},
		{"CustodyRoot", func(c custody.Checkpoint) custody.Checkpoint { c.CustodyRoot = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; return c }},
		{"KeyID", func(c custody.Checkpoint) custody.Checkpoint { c.KeyID = "key-mutated"; return c }},
		{"Revision", func(c custody.Checkpoint) custody.Checkpoint { c.Revision = 2; return c }},
		{"IssuedAt", func(c custody.Checkpoint) custody.Checkpoint { c.IssuedAt = "2026-11-11T12:00:01Z"; return c }},
		{"ExpiresAt", func(c custody.Checkpoint) custody.Checkpoint { c.ExpiresAt = "2027-11-11T12:00:01Z"; return c }},
	}

	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mut(base)
			mutatedBytes := custody.CanonicalCheckpointBytes(mutated)
			if bytes.Equal(baseBytes, mutatedBytes) {
				t.Fatalf("mutating %s did not change canonical bytes!", tc.name)
			}
			// Signature over baseBytes must fail verification over mutatedBytes
			if ed25519.Verify(pubBytes, mutatedBytes, sig) {
				t.Fatalf("signature for baseBytes unexpectedly verified against mutated %s bytes!", tc.name)
			}
		})
	}
}

// TestC12CreateCheckpointAutoGeneratedIDAndValidation verifies auto ID generation and timestamp validation.
func TestC12CreateCheckpointAutoGeneratedIDAndValidation(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubHex := hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	keyID := "key-c12-gen"

	// 1. Auto-generated ID when CheckpointID is empty
	chk, err := custody.CreateCheckpoint(context.Background(), nil, custody.CreateCheckpointRequest{
		CaseID:      "case-gen",
		EvidenceID:  "ev-gen-01",
		Sequence:    3,
		CustodyRoot: "6666666666666666666666666666666666666666666666666666666666666666",
		KeyID:       keyID,
		Revision:    2,
		PrivateKey:  privKey,
	})
	if err != nil {
		t.Fatalf("create checkpoint with auto ID failed: %v", err)
	}
	expectedID := "chk-ev-gen-01-3-2"
	if chk.CheckpointID != expectedID {
		t.Fatalf("expected auto checkpoint ID %q, got %q", expectedID, chk.CheckpointID)
	}

	// 2. Excessively long EvidenceID that exceeds identifier regex max length (128)
	longEvidenceID := strings.Repeat("x", 125)
	_, errLong := custody.CreateCheckpoint(context.Background(), nil, custody.CreateCheckpointRequest{
		CaseID:      "case-gen",
		EvidenceID:  longEvidenceID,
		Sequence:    1,
		CustodyRoot: "6666666666666666666666666666666666666666666666666666666666666666",
		KeyID:       keyID,
		Revision:    1,
		PrivateKey:  privKey,
	})
	if !errors.Is(errLong, custody.ErrInvalidCheckpoint) {
		t.Fatalf("expected ErrInvalidCheckpoint for overly long generated ID, got: %v", errLong)
	}

	// 3. ExpiresAt <= IssuedAt rejected in CreateCheckpoint
	_, errExpBeforeIss := custody.CreateCheckpoint(context.Background(), nil, custody.CreateCheckpointRequest{
		CaseID:      "case-gen",
		EvidenceID:  "ev-gen-02",
		Sequence:    1,
		CustodyRoot: "6666666666666666666666666666666666666666666666666666666666666666",
		KeyID:       keyID,
		Revision:    1,
		IssuedAt:    "2026-11-11T12:00:00Z",
		ExpiresAt:   "2026-11-11T11:59:59Z", // Before IssuedAt
		PrivateKey:  privKey,
	})
	if !errors.Is(errExpBeforeIss, custody.ErrInvalidCheckpoint) {
		t.Fatalf("expected ErrInvalidCheckpoint for expires_at before issued_at in CreateCheckpoint, got: %v", errExpBeforeIss)
	}

	// 4. ExpiresAt <= IssuedAt rejected in VerifyCheckpoint
	invalidExpChk := *chk
	invalidExpChk.IssuedAt = "2026-11-11T12:00:00Z"
	invalidExpChk.ExpiresAt = "2026-11-11T11:00:00Z"
	sig := ed25519.Sign(privKey, custody.CanonicalCheckpointBytes(invalidExpChk))
	invalidExpChk.Signature = hex.EncodeToString(sig)

	trustedKeys := map[string]string{keyID: pubHex}
	_, errVerifyExp := custody.VerifyCheckpoint(context.Background(), nil, invalidExpChk, custody.VerifyCheckpointOptions{
		TrustedPublicKeys: trustedKeys,
	})
	if !errors.Is(errVerifyExp, custody.ErrInvalidCheckpoint) {
		t.Fatalf("expected ErrInvalidCheckpoint for expires_at before issued_at in VerifyCheckpoint, got: %v", errVerifyExp)
	}
}


package tests_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/holds"
)

type c13Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c13ActionSpec struct {
	HoldID    string `json:"hold_id,omitempty"`
	Actor     string `json:"actor"`
	Timestamp string `json:"timestamp"`
	Reason    string `json:"reason"`
	Provider  string `json:"provider,omitempty"`
}

type c13PositiveFixture struct {
	SchemaVersion string        `json:"schema_version"`
	CaseID        string        `json:"case_id"`
	EvidenceID    string        `json:"evidence_id"`
	Hold          c13ActionSpec `json:"hold"`
	BlockedDelete c13ActionSpec `json:"blocked_delete"`
	BlockedExpire c13ActionSpec `json:"blocked_expire"`
	Release       c13ActionSpec `json:"release"`
	AllowedDelete c13ActionSpec `json:"allowed_delete"`
}

type c13InvalidFixture struct {
	SchemaVersion   string `json:"schema_version"`
	HoldID          string `json:"hold_id"`
	CaseID          string `json:"case_id"`
	EvidenceID      string `json:"evidence_id"`
	Actor           string `json:"actor"`
	Timestamp       string `json:"timestamp"`
	Reason          string `json:"reason"`
	Provider        string `json:"provider,omitempty"`
	ExpectedFailure string `json:"expected_failure"`
}

func getC13FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "fixtures", "breachatlas", "C13")
	if filepath.Base(wd) != "tests" {
		dir = filepath.Join(wd, "tests", "fixtures", "breachatlas", "C13")
	}
	return dir
}

func setupSealedArtifactForHoldTests(t *testing.T, rootTmp, caseID, evidenceID, payload string) (*evidence.SealStore, *custody.LedgerStore, string, [32]byte) {
	t.Helper()
	quarantineDir := filepath.Join(rootTmp, "quarantine")
	sealDir := filepath.Join(rootTmp, "sealstore")
	custodyDir := filepath.Join(rootTmp, "custody_ledger")

	qCfg := evidence.UploadConfig{QuarantineDir: quarantineDir, BufferSize: 64, SyncDir: true}
	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("open seal store: %v", err)
	}

	ledgerStore, err := custody.OpenLedgerStore(custody.LedgerConfig{
		RootDir: custodyDir,
		SyncDir: true,
	})
	if err != nil {
		_ = sealStore.Close()
		t.Fatalf("open custody ledger: %v", err)
	}

	payloadBytes := []byte(payload)
	payloadSum := sha256.Sum256(payloadBytes)
	payloadHex := hex.EncodeToString(payloadSum[:])
	payloadSize := int64(len(payloadBytes))

	quarantined, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-" + evidenceID,
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		MediaType:     "application/octet-stream",
		Filename:      evidenceID + ".bin",
		ExpectedSize:  &payloadSize,
		Body:          strings.NewReader(payload),
	})
	if err != nil {
		_ = ledgerStore.Close()
		_ = sealStore.Close()
		t.Fatalf("quarantine upload: %v", err)
	}

	sealedManifest, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
		OperationID:    "seal-op-" + evidenceID,
		Quarantined:    quarantined,
		ExpectedSHA256: payloadHex,
		AcquiredAt:     "2026-11-11T09:50:00Z",
		CustodyRoot:    custody.GenesisPrevHash,
	})
	if err != nil {
		_ = ledgerStore.Close()
		_ = sealStore.Close()
		t.Fatalf("seal quarantined: %v", err)
	}

	blobFullPath := filepath.Join(sealDir, filepath.FromSlash(sealedManifest.BlobRelPath))
	blobBytes, err := os.ReadFile(blobFullPath)
	if err != nil {
		_ = ledgerStore.Close()
		_ = sealStore.Close()
		t.Fatalf("read sealed blob: %v", err)
	}

	return sealStore, ledgerStore, blobFullPath, sha256.Sum256(blobBytes)
}

func assertBlobUnchanged(t *testing.T, blobPath string, expectedSHA [32]byte) {
	t.Helper()
	gotBytes, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("sealed blob missing or unreadable at %s: %v", blobPath, err)
	}
	gotSHA := sha256.Sum256(gotBytes)
	if gotSHA != expectedSHA {
		t.Fatalf("sealed source bytes modified! got sha256=%x, want=%x", gotSHA, expectedSHA)
	}
}

func TestC13FixturesProvenanceAndLifecycle(t *testing.T) {
	fixturesDir := getC13FixturesDir(t)

	// 1. Verify C13 provenance & Apache-2.0 hashes
	provRaw, err := os.ReadFile(filepath.Join(fixturesDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read provenance.json: %v", err)
	}
	var prov c13Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatalf("unmarshal provenance.json: %v", err)
	}
	if prov.License != "Apache-2.0" {
		t.Fatalf("expected Apache-2.0 license, got %q", prov.License)
	}
	if len(prov.SHA256) < 7 {
		t.Fatalf("expected at least 7 hashed fixtures, got %d", len(prov.SHA256))
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

	// Verify expected-output/outcomes.json parses cleanly
	outcomesRaw, err := os.ReadFile(filepath.Join(fixturesDir, "expected-output", "outcomes.json"))
	if err != nil {
		t.Fatalf("read expected-output/outcomes.json: %v", err)
	}
	var outcomes map[string]any
	if err := json.Unmarshal(outcomesRaw, &outcomes); err != nil {
		t.Fatalf("unmarshal outcomes.json: %v", err)
	}

	// 2. Execute positive lifecycle fixture
	posRaw, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "active-hold-lifecycle.json"))
	if err != nil {
		t.Fatalf("read positive fixture: %v", err)
	}
	var fix c13PositiveFixture
	if err := json.Unmarshal(posRaw, &fix); err != nil {
		t.Fatalf("unmarshal positive fixture: %v", err)
	}

	rootTmp := t.TempDir()
	sealStore, ledgerStore, blobPath, initialBlobSHA := setupSealedArtifactForHoldTests(
		t,
		rootTmp,
		fix.CaseID,
		fix.EvidenceID,
		"synthetic-forensic-disk-sector-payload-c13\n",
	)
	defer sealStore.Close()
	defer ledgerStore.Close()

	holdsRoot := filepath.Join(rootTmp, "holds_root")
	svc, err := holds.OpenService(holds.ServiceConfig{
		RootDir:   holdsRoot,
		SealStore: sealStore,
		Ledger:    ledgerStore,
		SyncDir:   true,
	})
	if err != nil {
		t.Fatalf("open holds service: %v", err)
	}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Place active legal hold
	held, err := svc.PlaceHold(ctx, holds.PlaceHoldRequest{
		HoldID:     fix.Hold.HoldID,
		CaseID:     fix.CaseID,
		EvidenceID: fix.EvidenceID,
		Actor:      fix.Hold.Actor,
		Timestamp:  fix.Hold.Timestamp,
		Reason:     fix.Hold.Reason,
		Provider:   fix.Hold.Provider,
		PrivateKey: privKey,
	})
	if err != nil {
		t.Fatalf("PlaceHold failed: %v", err)
	}
	if held.Status != holds.HoldStatusActive {
		t.Fatalf("expected active hold status, got %q", held.Status)
	}

	// Idempotent replay of exact same active hold must return the same record cleanly
	replayed, err := svc.PlaceHold(ctx, holds.PlaceHoldRequest{
		HoldID:     fix.Hold.HoldID,
		CaseID:     fix.CaseID,
		EvidenceID: fix.EvidenceID,
		Actor:      fix.Hold.Actor,
		Timestamp:  fix.Hold.Timestamp,
		Reason:     fix.Hold.Reason,
		Provider:   fix.Hold.Provider,
	})
	if err != nil {
		t.Fatalf("idempotent PlaceHold failed: %v", err)
	}
	if replayed.HoldID != held.HoldID || replayed.Status != holds.HoldStatusActive {
		t.Fatalf("unexpected idempotent replay hold: %+v", replayed)
	}

	// Attempt deletion while hold is active -> MUST fail with ErrHoldActive
	if _, err := svc.DeleteEvidence(ctx, holds.DisposalRequest{
		CaseID:     fix.CaseID,
		EvidenceID: fix.EvidenceID,
		Actor:      fix.BlockedDelete.Actor,
		Timestamp:  fix.BlockedDelete.Timestamp,
		Reason:     fix.BlockedDelete.Reason,
		Provider:   fix.BlockedDelete.Provider,
		PrivateKey: privKey,
	}); !errors.Is(err, holds.ErrHoldActive) {
		t.Fatalf("expected ErrHoldActive on DeleteEvidence, got %v", err)
	}

	// Attempt retention expiration while hold is active -> MUST fail with ErrHoldActive
	if _, err := svc.ExpireRetention(ctx, holds.DisposalRequest{
		CaseID:     fix.CaseID,
		EvidenceID: fix.EvidenceID,
		Actor:      fix.BlockedExpire.Actor,
		Timestamp:  fix.BlockedExpire.Timestamp,
		Reason:     fix.BlockedExpire.Reason,
		Provider:   fix.BlockedExpire.Provider,
		PrivateKey: privKey,
	}); !errors.Is(err, holds.ErrHoldActive) {
		t.Fatalf("expected ErrHoldActive on ExpireRetention, got %v", err)
	}

	assertBlobUnchanged(t, blobPath, initialBlobSHA)

	// Close and restart service -> active hold MUST still block deletion
	if err := svc.Close(); err != nil {
		t.Fatalf("close service: %v", err)
	}
	svcRestarted, err := holds.OpenService(holds.ServiceConfig{
		RootDir:   holdsRoot,
		SealStore: sealStore,
		Ledger:    ledgerStore,
		SyncDir:   true,
	})
	if err != nil {
		t.Fatalf("reopen holds service after restart: %v", err)
	}
	defer svcRestarted.Close()

	if _, err := svcRestarted.DeleteEvidence(ctx, holds.DisposalRequest{
		CaseID:     fix.CaseID,
		EvidenceID: fix.EvidenceID,
		Actor:      fix.BlockedDelete.Actor,
		Timestamp:  "2026-11-11T10:15:00Z",
		Reason:     "Retry delete after service restart",
		Provider:   fix.BlockedDelete.Provider,
	}); !errors.Is(err, holds.ErrHoldActive) {
		t.Fatalf("expected ErrHoldActive after restart, got %v", err)
	}

	status, err := svcRestarted.GetEvidenceStatus(fix.CaseID, fix.EvidenceID)
	if err != nil {
		t.Fatalf("GetEvidenceStatus failed: %v", err)
	}
	if status.ActiveHoldCount != 1 || status.Disposition != holds.DispositionRetained {
		t.Fatalf("unexpected status while held: %+v", status)
	}

	// Release hold -> now deletion after release is allowed
	released, err := svcRestarted.ReleaseHold(ctx, holds.ReleaseHoldRequest{
		HoldID:     fix.Release.HoldID,
		CaseID:     fix.CaseID,
		EvidenceID: fix.EvidenceID,
		Actor:      fix.Release.Actor,
		Timestamp:  fix.Release.Timestamp,
		Reason:     fix.Release.Reason,
		Provider:   fix.Release.Provider,
		PrivateKey: privKey,
	})
	if err != nil {
		t.Fatalf("ReleaseHold failed: %v", err)
	}
	if released.Status != holds.HoldStatusReleased {
		t.Fatalf("expected released hold status, got %q", released.Status)
	}

	res, err := svcRestarted.DeleteEvidence(ctx, holds.DisposalRequest{
		CaseID:     fix.CaseID,
		EvidenceID: fix.EvidenceID,
		Actor:      fix.AllowedDelete.Actor,
		Timestamp:  fix.AllowedDelete.Timestamp,
		Reason:     fix.AllowedDelete.Reason,
		Provider:   fix.AllowedDelete.Provider,
		PrivateKey: privKey,
	})
	if err != nil {
		t.Fatalf("DeleteEvidence after hold release failed: %v", err)
	}
	if res.Disposition != holds.DispositionDeleted {
		t.Fatalf("expected deleted disposition, got %q", res.Disposition)
	}

	// Sealed source bytes must NEVER be modified at any stage
	assertBlobUnchanged(t, blobPath, initialBlobSHA)

	// Audit trail must capture every operation and exact reason (including blocked deletes)
	trail, err := svcRestarted.AuditTrail(fix.CaseID, fix.EvidenceID)
	if err != nil {
		t.Fatalf("AuditTrail failed: %v", err)
	}
	if len(trail) != 6 {
		t.Fatalf("expected 6 audit entries, got %d: %+v", len(trail), trail)
	}
	if trail[1].Action != holds.ActionDeleteBlocked || trail[1].Outcome != holds.OutcomeBlocked || trail[1].Reason != fix.BlockedDelete.Reason {
		t.Fatalf("unexpected blocked delete audit entry: %+v", trail[1])
	}
	if trail[2].Action != holds.ActionExpirationBlocked || trail[2].Outcome != holds.OutcomeBlocked || trail[2].Reason != fix.BlockedExpire.Reason {
		t.Fatalf("unexpected blocked expiration audit entry: %+v", trail[2])
	}
	if trail[3].Reason != "Retry delete after service restart" || len(trail[3].BlockingHoldIDs) != 1 || trail[3].BlockingHoldIDs[0] != fix.Hold.HoldID {
		t.Fatalf("unexpected post-restart blocked audit entry: %+v", trail[3])
	}

	// Verify custody ledger mirrored all 6 attributable events with intact cryptographic chain
	ok, err := ledgerStore.VerifyChain(fix.CaseID, fix.EvidenceID)
	if err != nil || !ok {
		t.Fatalf("VerifyChain failed: ok=%v err=%v", ok, err)
	}
	chain, err := ledgerStore.ListEvents(fix.CaseID, fix.EvidenceID)
	if err != nil {
		t.Fatalf("ListEvents failed: %v", err)
	}
	if len(chain) != 6 {
		t.Fatalf("expected 6 custody events mirrored from holds service, got %d", len(chain))
	}
}

func TestC13InvalidFixturesAndMissingPrerequisites(t *testing.T) {
	fixturesDir := getC13FixturesDir(t)
	rootTmp := t.TempDir()
	caseID := "CASE-C13-001"
	evidenceID := "EVID-C13-001"

	sealStore, ledgerStore, _, _ := setupSealedArtifactForHoldTests(t, rootTmp, caseID, evidenceID, "sealed-bytes\n")
	defer sealStore.Close()
	defer ledgerStore.Close()

	// Missing prerequisite checks on OpenService
	if _, err := holds.OpenService(holds.ServiceConfig{RootDir: "", SealStore: sealStore}); !errors.Is(err, holds.ErrStoreDirRequired) {
		t.Fatalf("expected ErrStoreDirRequired, got %v", err)
	}
	if _, err := holds.OpenService(holds.ServiceConfig{RootDir: filepath.Join(rootTmp, "h1"), SealStore: nil}); !errors.Is(err, holds.ErrSealStoreRequired) {
		t.Fatalf("expected ErrSealStoreRequired, got %v", err)
	}

	svc, err := holds.OpenService(holds.ServiceConfig{
		RootDir:   filepath.Join(rootTmp, "holds"),
		SealStore: sealStore,
		Ledger:    ledgerStore,
		SyncDir:   true,
	})
	if err != nil {
		t.Fatalf("open holds service: %v", err)
	}
	defer svc.Close()

	invalidCases := []struct {
		file      string
		wantError error
	}{
		{"invalid/missing-reason.json", holds.ErrMissingReason},
		{"invalid/missing-actor.json", holds.ErrMissingActor},
		{"invalid/unsealed-evidence.json", holds.ErrMissingPrerequisite},
		{"invalid/unavailable-provider.json", holds.ErrUnavailableProvider},
		{"invalid/malformed-hold-fixture.json", holds.ErrInvalidTimestamp},
	}

	ctx := context.Background()
	for _, tc := range invalidCases {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, tc.file))
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		var fix c13InvalidFixture
		if err := json.Unmarshal(raw, &fix); err != nil {
			t.Fatalf("unmarshal %s: %v", tc.file, err)
		}
		_, gotErr := svc.PlaceHold(ctx, holds.PlaceHoldRequest{
			HoldID:     fix.HoldID,
			CaseID:     fix.CaseID,
			EvidenceID: fix.EvidenceID,
			Actor:      fix.Actor,
			Timestamp:  fix.Timestamp,
			Reason:     fix.Reason,
			Provider:   fix.Provider,
		})
		if gotErr == nil {
			t.Fatalf("%s: expected error %v, got nil", tc.file, tc.wantError)
		}
		if tc.file == "invalid/malformed-hold-fixture.json" {
			// HoldID contains ../escape so ErrInvalidHold may trigger before timestamp check
			if !errors.Is(gotErr, holds.ErrInvalidHold) && !errors.Is(gotErr, holds.ErrInvalidTimestamp) {
				t.Fatalf("%s: expected invalid hold/timestamp error, got %v", tc.file, gotErr)
			}
			continue
		}
		if !errors.Is(gotErr, tc.wantError) {
			t.Fatalf("%s: expected %v, got %v", tc.file, tc.wantError, gotErr)
		}
	}

	// Duplicate HoldID conflict check + ReleaseHold edge cases + post-disposal guards
	if _, err := svc.PlaceHold(ctx, holds.PlaceHoldRequest{
		HoldID:     "HOLD-CONFLICT-1",
		CaseID:     caseID,
		EvidenceID: evidenceID,
		Actor:      "counsel-c13",
		Timestamp:  "2026-11-11T10:00:00Z",
		Reason:     "Initial hold reason",
	}); err != nil {
		t.Fatalf("PlaceHold failed: %v", err)
	}
	if _, err := svc.PlaceHold(ctx, holds.PlaceHoldRequest{
		HoldID:     "HOLD-CONFLICT-1",
		CaseID:     caseID,
		EvidenceID: evidenceID,
		Actor:      "counsel-c13",
		Timestamp:  "2026-11-11T10:00:00Z",
		Reason:     "Different conflicting reason",
	}); !errors.Is(err, holds.ErrHoldConflict) {
		t.Fatalf("expected ErrHoldConflict, got %v", err)
	}

	if _, err := svc.ReleaseHold(ctx, holds.ReleaseHoldRequest{
		HoldID:     "HOLD-DOES-NOT-EXIST",
		CaseID:     caseID,
		EvidenceID: evidenceID,
		Actor:      "counsel-c13",
		Timestamp:  "2026-11-11T10:05:00Z",
		Reason:     "Release unknown hold",
	}); !errors.Is(err, holds.ErrHoldNotFound) {
		t.Fatalf("expected ErrHoldNotFound, got %v", err)
	}

	if _, err := svc.ReleaseHold(ctx, holds.ReleaseHoldRequest{
		HoldID:     "HOLD-CONFLICT-1",
		CaseID:     caseID,
		EvidenceID: evidenceID,
		Actor:      "counsel-c13",
		Timestamp:  "2026-11-11T10:06:00Z",
		Reason:     "Release hold",
	}); err != nil {
		t.Fatalf("ReleaseHold failed: %v", err)
	}
	if _, err := svc.ReleaseHold(ctx, holds.ReleaseHoldRequest{
		HoldID:     "HOLD-CONFLICT-1",
		CaseID:     caseID,
		EvidenceID: evidenceID,
		Actor:      "counsel-c13",
		Timestamp:  "2026-11-11T10:07:00Z",
		Reason:     "Duplicate release",
	}); !errors.Is(err, holds.ErrHoldAlreadyReleased) {
		t.Fatalf("expected ErrHoldAlreadyReleased, got %v", err)
	}

	// Allowed retention expiration now proceeds, then subsequent delete or hold placement fails
	if _, err := svc.ExpireRetention(ctx, holds.DisposalRequest{
		CaseID:     caseID,
		EvidenceID: evidenceID,
		Actor:      "retention-c13",
		Timestamp:  "2026-11-11T10:08:00Z",
		Reason:     "Retention expired cleanly",
	}); err != nil {
		t.Fatalf("ExpireRetention failed: %v", err)
	}
	if _, err := svc.DeleteEvidence(ctx, holds.DisposalRequest{
		CaseID:     caseID,
		EvidenceID: evidenceID,
		Actor:      "retention-c13",
		Timestamp:  "2026-11-11T10:09:00Z",
		Reason:     "Second disposal attempt",
	}); !errors.Is(err, holds.ErrEvidenceAlreadyDisposed) {
		t.Fatalf("expected ErrEvidenceAlreadyDisposed, got %v", err)
	}
	if _, err := svc.PlaceHold(ctx, holds.PlaceHoldRequest{
		CaseID:     caseID,
		EvidenceID: evidenceID,
		Actor:      "counsel-c13",
		Timestamp:  "2026-11-11T10:10:00Z",
		Reason:     "Late hold after disposal",
	}); !errors.Is(err, holds.ErrEvidenceAlreadyDisposed) {
		t.Fatalf("expected ErrEvidenceAlreadyDisposed on post-disposal hold, got %v", err)
	}
}

func TestC13ConcurrentHoldAndDeleteRace(t *testing.T) {
	rootTmp := t.TempDir()
	caseID := "CASE-C13-RACE"
	evidenceID := "EVID-C13-RACE"

	sealStore, ledgerStore, blobPath, initialBlobSHA := setupSealedArtifactForHoldTests(
		t,
		rootTmp,
		caseID,
		evidenceID,
		"concurrent-hold-protection-payload\n",
	)
	defer sealStore.Close()
	defer ledgerStore.Close()

	holdsRoot := filepath.Join(rootTmp, "holds_race")
	svc, err := holds.OpenService(holds.ServiceConfig{
		RootDir:   holdsRoot,
		SealStore: sealStore,
		Ledger:    ledgerStore,
		SyncDir:   true,
	})
	if err != nil {
		t.Fatalf("open holds service: %v", err)
	}
	defer svc.Close()

	ctx := context.Background()
	// Place baseline active hold, then run concurrent holds + deletes + retention expirations.
	if _, err := svc.PlaceHold(ctx, holds.PlaceHoldRequest{
		HoldID:     "HOLD-BASELINE-01",
		CaseID:     caseID,
		EvidenceID: evidenceID,
		Actor:      "legal-ops",
		Timestamp:  "2026-11-11T12:00:00Z",
		Reason:     "Active baseline litigation hold",
	}); err != nil {
		t.Fatalf("baseline PlaceHold failed: %v", err)
	}

	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers*3)

	for i := 0; i < workers; i++ {
		i := i
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, err := svc.PlaceHold(ctx, holds.PlaceHoldRequest{
				HoldID:     fmt.Sprintf("HOLD-CONC-%02d", i),
				CaseID:     caseID,
				EvidenceID: evidenceID,
				Actor:      fmt.Sprintf("counsel-%02d", i),
				Timestamp:  fmt.Sprintf("2026-11-11T12:01:%02dZ", i%60),
				Reason:     fmt.Sprintf("Concurrent legal hold #%02d", i),
			})
			if err != nil {
				errs <- fmt.Errorf("PlaceHold %d failed: %w", i, err)
			}
		}()

		go func() {
			defer wg.Done()
			_, err := svc.DeleteEvidence(ctx, holds.DisposalRequest{
				CaseID:     caseID,
				EvidenceID: evidenceID,
				Actor:      fmt.Sprintf("deleter-%02d", i),
				Timestamp:  fmt.Sprintf("2026-11-11T12:01:%02dZ", i%60),
				Reason:     fmt.Sprintf("Concurrent delete request #%02d", i),
			})
			if !errors.Is(err, holds.ErrHoldActive) {
				errs <- fmt.Errorf("DeleteEvidence %d expected ErrHoldActive, got: %v", i, err)
			}
		}()

		go func() {
			defer wg.Done()
			_, err := svc.ExpireRetention(ctx, holds.DisposalRequest{
				CaseID:     caseID,
				EvidenceID: evidenceID,
				Actor:      fmt.Sprintf("scheduler-%02d", i),
				Timestamp:  fmt.Sprintf("2026-11-11T12:01:%02dZ", i%60),
				Reason:     fmt.Sprintf("Concurrent retention expiration #%02d", i),
			})
			if !errors.Is(err, holds.ErrHoldActive) {
				errs <- fmt.Errorf("ExpireRetention %d expected ErrHoldActive, got: %v", i, err)
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	status, err := svc.GetEvidenceStatus(caseID, evidenceID)
	if err != nil {
		t.Fatalf("GetEvidenceStatus failed: %v", err)
	}
	if status.ActiveHoldCount != workers+1 || status.Disposition != holds.DispositionRetained {
		t.Fatalf("unexpected concurrent hold status: %+v", status)
	}

	trail, err := svc.AuditTrail(caseID, evidenceID)
	if err != nil {
		t.Fatalf("AuditTrail failed: %v", err)
	}
	expectedAuditTotal := 1 + workers*3
	if len(trail) != expectedAuditTotal {
		t.Fatalf("expected %d durable audit entries, got %d", expectedAuditTotal, len(trail))
	}

	blockedCount := 0
	for _, entry := range trail {
		if entry.Outcome == holds.OutcomeBlocked {
			blockedCount++
			if len(entry.BlockingHoldIDs) == 0 || strings.TrimSpace(entry.Reason) == "" {
				t.Fatalf("blocked entry missing reason or blocking hold IDs: %+v", entry)
			}
		}
	}
	if blockedCount != workers*2 {
		t.Fatalf("expected %d audited blocked disposal attempts, got %d", workers*2, blockedCount)
	}

	ok, err := ledgerStore.VerifyChain(caseID, evidenceID)
	if err != nil || !ok {
		t.Fatalf("VerifyChain failed: ok=%v err=%v", ok, err)
	}
	chain, err := ledgerStore.ListEvents(caseID, evidenceID)
	if err != nil {
		t.Fatalf("ListEvents failed: %v", err)
	}
	if len(chain) != expectedAuditTotal {
		t.Fatalf("expected %d custody events matching holds audit, got %d", expectedAuditTotal, len(chain))
	}

	assertBlobUnchanged(t, blobPath, initialBlobSHA)
}

func TestC13ExclusiveLockRestartAndCorruptionRejection(t *testing.T) {
	rootTmp := t.TempDir()
	caseID := "CASE-C13-RECOVERY"
	evidenceID := "EVID-C13-RECOVERY"

	sealStore, _, _, _ := setupSealedArtifactForHoldTests(t, rootTmp, caseID, evidenceID, "recovery-payload\n")
	defer sealStore.Close()

	holdsRoot := filepath.Join(rootTmp, "holds_recovery")
	svc, err := holds.OpenService(holds.ServiceConfig{
		RootDir:   holdsRoot,
		SealStore: sealStore,
		SyncDir:   true,
	})
	if err != nil {
		t.Fatalf("open holds service: %v", err)
	}

	// Second concurrent OpenService on same RootDir must reject with ErrLockBusy
	if _, err := holds.OpenService(holds.ServiceConfig{
		RootDir:   holdsRoot,
		SealStore: sealStore,
	}); !errors.Is(err, holds.ErrLockBusy) {
		_ = svc.Close()
		t.Fatalf("expected ErrLockBusy on duplicate OpenService, got %v", err)
	}

	if _, err := svc.PlaceHold(context.Background(), holds.PlaceHoldRequest{
		HoldID:     "HOLD-PERSIST-01",
		CaseID:     caseID,
		EvidenceID: evidenceID,
		Actor:      "counsel-c13",
		Timestamp:  "2026-11-11T12:00:00Z",
		Reason:     "Persisted hold across restart",
	}); err != nil {
		_ = svc.Close()
		t.Fatalf("PlaceHold failed: %v", err)
	}
	if err := svc.Close(); err != nil {
		t.Fatalf("close holds service: %v", err)
	}

	// Corrupt holds-state.json -> OpenService MUST fail closed with ErrCorruptedHoldState
	statePath := filepath.Join(holdsRoot, holds.DefaultHoldsDir, "holds-state.json")
	validStateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read valid state: %v", err)
	}
	if err := os.WriteFile(statePath, []byte("{corrupted-json"), 0o600); err != nil {
		t.Fatalf("write corrupted state: %v", err)
	}
	if _, err := holds.OpenService(holds.ServiceConfig{
		RootDir:   holdsRoot,
		SealStore: sealStore,
	}); !errors.Is(err, holds.ErrCorruptedHoldState) {
		t.Fatalf("expected ErrCorruptedHoldState on corrupted holds-state.json, got %v", err)
	}

	// Restore valid state and corrupt audit log -> OpenService MUST also fail closed
	if err := os.WriteFile(statePath, validStateBytes, 0o600); err != nil {
		t.Fatalf("restore valid state: %v", err)
	}
	auditPath := filepath.Join(holdsRoot, holds.DefaultHoldsDir, "audit", caseID, evidenceID+".jsonl")
	if err := os.WriteFile(auditPath, []byte("{\"broken\":true}\n"), 0o600); err != nil {
		t.Fatalf("corrupt audit log: %v", err)
	}
	if _, err := holds.OpenService(holds.ServiceConfig{
		RootDir:   holdsRoot,
		SealStore: sealStore,
	}); !errors.Is(err, holds.ErrCorruptedHoldState) {
		t.Fatalf("expected ErrCorruptedHoldState on corrupted audit log, got %v", err)
	}
}

func TestC13ConcurrentHoldVsDeleteMutualExclusion(t *testing.T) {
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		rootTmp := t.TempDir()
		caseID := "CASE-C13-MUTEX"
		evidenceID := fmt.Sprintf("EVID-C13-MUTEX-%02d", round)

		sealStore, ledgerStore, blobPath, initialBlobSHA := setupSealedArtifactForHoldTests(
			t,
			rootTmp,
			caseID,
			evidenceID,
			fmt.Sprintf("mutex-round-%02d\n", round),
		)

		svc, err := holds.OpenService(holds.ServiceConfig{
			RootDir:   filepath.Join(rootTmp, "holds"),
			SealStore: sealStore,
			Ledger:    ledgerStore,
			SyncDir:   true,
		})
		if err != nil {
			_ = ledgerStore.Close()
			_ = sealStore.Close()
			t.Fatalf("open service: %v", err)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		var holdErr, delErr error

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, holdErr = svc.PlaceHold(ctx, holds.PlaceHoldRequest{
				HoldID:     "HOLD-RACE-01",
				CaseID:     caseID,
				EvidenceID: evidenceID,
				Actor:      "counsel-c13",
				Timestamp:  "2026-11-11T12:10:00Z",
				Reason:     "Simultaneous litigation hold",
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			_, delErr = svc.DeleteEvidence(ctx, holds.DisposalRequest{
				CaseID:     caseID,
				EvidenceID: evidenceID,
				Actor:      "retention-c13",
				Timestamp:  "2026-11-11T12:10:01Z",
				Reason:     "Simultaneous retention delete",
			})
		}()

		close(start)
		wg.Wait()

		status, stErr := svc.GetEvidenceStatus(caseID, evidenceID)
		if stErr != nil {
			_ = svc.Close()
			_ = ledgerStore.Close()
			_ = sealStore.Close()
			t.Fatalf("GetEvidenceStatus round %d: %v", round, stErr)
		}

		// Invariant: hold active + deleted disposition can NEVER both happen.
		if holdErr == nil {
			if !errors.Is(delErr, holds.ErrHoldActive) {
				t.Fatalf("round %d: hold succeeded, so delete MUST fail with ErrHoldActive, got %v", round, delErr)
			}
			if status.ActiveHoldCount != 1 || status.Disposition != holds.DispositionRetained {
				t.Fatalf("round %d: unexpected status when hold won: %+v", round, status)
			}
		} else {
			if !errors.Is(holdErr, holds.ErrEvidenceAlreadyDisposed) || delErr != nil {
				t.Fatalf("round %d: unexpected outcome when delete ran first: holdErr=%v, delErr=%v", round, holdErr, delErr)
			}
			if status.ActiveHoldCount != 0 || status.Disposition != holds.DispositionDeleted {
				t.Fatalf("round %d: unexpected status when unheld delete ran first: %+v", round, status)
			}
		}

		assertBlobUnchanged(t, blobPath, initialBlobSHA)
		_ = svc.Close()
		_ = ledgerStore.Close()
		_ = sealStore.Close()
	}
}


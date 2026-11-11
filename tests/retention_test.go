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
	"github.com/Parsa-Emami/Breachatlas/internal/retention"
)

type c25Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c25PositiveFixture struct {
	SchemaVersion string `json:"schema_version"`
	CaseID        string `json:"case_id"`
	EvidenceID    string `json:"evidence_id"`
	HoldID        string `json:"hold_id"`
	PolicyID      string `json:"policy_id"`
	TombstoneID   string `json:"tombstone_id"`
	OperationID   string `json:"operation_id"`
	KeyID         string `json:"key_id"`
	Provider      string `json:"provider"`
	Payload       string `json:"payload"`
	Hold          struct {
		Actor     string `json:"actor"`
		Timestamp string `json:"timestamp"`
		Reason    string `json:"reason"`
	} `json:"hold"`
	Release struct {
		Actor     string `json:"actor"`
		Timestamp string `json:"timestamp"`
		Reason    string `json:"reason"`
	} `json:"release"`
	BlockedDestroy struct {
		OperationID string `json:"operation_id"`
		TombstoneID string `json:"tombstone_id"`
		Operator    string `json:"operator"`
		Timestamp   string `json:"timestamp"`
		Reason      string `json:"reason"`
	} `json:"blocked_destroy"`
	AllowedDestroy struct {
		OperationID string `json:"operation_id"`
		TombstoneID string `json:"tombstone_id"`
		Operator    string `json:"operator"`
		Timestamp   string `json:"timestamp"`
		Reason      string `json:"reason"`
	} `json:"allowed_destroy"`
}

type c25NegativeCasesFixture struct {
	SchemaVersion string `json:"schema_version"`
	Cases         []struct {
		Name                   string `json:"name"`
		PolicyID               string `json:"policy_id,omitempty"`
		AutoDeleteRawEvidence  bool   `json:"auto_delete_raw_evidence,omitempty"`
		RawTTLSeconds          int64  `json:"raw_ttl_seconds,omitempty"`
		OperationID            string `json:"operation_id,omitempty"`
		AutomaticTTL           bool   `json:"automatic_ttl,omitempty"`
		ExplicitApproval       bool   `json:"explicit_approval,omitempty"`
		EvidenceID             string `json:"evidence_id,omitempty"`
		Provider               string `json:"provider,omitempty"`
		Operator               string `json:"operator,omitempty"`
		Reason                 string `json:"reason,omitempty"`
		ExpectedError          string `json:"expected_error"`
	} `json:"cases"`
}

type c25ExpectedOutcomesFixture struct {
	SchemaVersion        string `json:"schema_version"`
	AutoRawTTLPermitted  bool   `json:"auto_raw_ttl_permitted"`
	BlockedUnderHold     struct {
		Error             string `json:"error"`
		TombstoneCreated  bool   `json:"tombstone_created"`
		SealedBytesIntact bool   `json:"sealed_bytes_intact"`
		AuditAction       string `json:"audit_action"`
		AuditOutcome      string `json:"audit_outcome"`
	} `json:"blocked_under_hold"`
	ExplicitOperatorDestroyed struct {
		State             string `json:"state"`
		TombstoneCreated  bool   `json:"tombstone_created"`
		SealedBytesIntact bool   `json:"sealed_bytes_intact"`
		AuditAction       string `json:"audit_action"`
		AuditOutcome      string `json:"audit_outcome"`
	} `json:"explicit_operator_destroyed"`
}

type c25Env struct {
	qDir        string
	sDir        string
	custDir     string
	holdsDir    string
	retDir      string
	sealStore   *evidence.SealStore
	ledgerStore *custody.LedgerStore
	holdService *holds.Service
	retStore    *retention.RetentionStore
}

func getC25FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		cand := filepath.Join(dir, "tests", "fixtures", "breachatlas", "C25")
		if info, err := os.Stat(cand); err == nil && info.IsDir() {
			return cand
		}
	}
	t.Fatalf("could not locate tests/fixtures/breachatlas/C25 from %s", wd)
	return ""
}

func loadC25JSON[T any](t *testing.T, rel string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(getC25FixturesDir(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("load C25 fixture %s: %v", rel, err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal C25 fixture %s: %v", rel, err)
	}
	return out
}

func setupC25Env(t *testing.T) *c25Env {
	t.Helper()
	root := t.TempDir()
	qDir := filepath.Join(root, "quarantine")
	sDir := filepath.Join(root, "sealed")
	custDir := filepath.Join(root, "custody")
	holdsDir := filepath.Join(root, "holds")
	retDir := filepath.Join(root, "retention")

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sealStore.Close() })

	ledgerStore, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: custDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledgerStore.Close() })

	holdService, err := holds.OpenService(holds.ServiceConfig{
		RootDir:   holdsDir,
		SealStore: sealStore,
		Ledger:    ledgerStore,
		SyncDir:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holdService.Close() })

	retStore, err := retention.OpenRetentionStore(retention.RetentionConfig{
		RootDir:     retDir,
		SealStore:   sealStore,
		HoldService: holdService,
		LedgerStore: ledgerStore,
		SyncDir:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = retStore.Close() })

	return &c25Env{
		qDir:        qDir,
		sDir:        sDir,
		custDir:     custDir,
		holdsDir:    holdsDir,
		retDir:      retDir,
		sealStore:   sealStore,
		ledgerStore: ledgerStore,
		holdService: holdService,
		retStore:    retStore,
	}
}

func seedSealedEvidenceForC25(t *testing.T, env *c25Env, caseID, evidenceID, payload string) (string, string) {
	t.Helper()
	ctx := context.Background()
	raw := []byte(payload)
	sum := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(sum[:])
	sz := int64(len(raw))

	q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{
		QuarantineDir: env.qDir,
		BufferSize:    64,
		SyncDir:       true,
	}, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-" + caseID + "-" + evidenceID,
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		MediaType:     "application/json",
		Filename:      evidenceID + ".jsonl",
		ExpectedSize:  &sz,
		Body:          strings.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("quarantine %s: %v", evidenceID, err)
	}

	ev, err := env.ledgerStore.AppendEvent(ctx, custody.AppendEventRequest{
		EventID:    "cust-" + evidenceID + "-01",
		CaseID:     caseID,
		EvidenceID: evidenceID,
		EventType:  "intake_seal",
		Actor:      "analyst-mina",
		Timestamp:  "2026-10-16T08:30:00Z",
		Reason:     "Initial intake and seal",
	})
	if err != nil {
		t.Fatalf("append custody %s: %v", evidenceID, err)
	}

	sm, err := env.sealStore.SealQuarantined(ctx, evidence.SealRequest{
		OperationID: "seal-" + caseID + "-" + evidenceID,
		Quarantined: q,
		AcquiredAt:  "2026-10-16T08:30:00Z",
		CustodyRoot: ev.CustodyRoot,
	})
	if err != nil {
		t.Fatalf("seal %s: %v", evidenceID, err)
	}
	return filepath.Join(env.sDir, filepath.FromSlash(sm.BlobRelPath)), shaHex
}

func assertBlobSHAC25(t *testing.T, blobPath, wantHex string) {
	t.Helper()
	raw, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read sealed blob %s: %v", blobPath, err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != wantHex {
		t.Fatalf("sealed source bytes modified at %s: got %s want %s", blobPath, got, wantHex)
	}
}

func TestC25FixturesAndProvenance(t *testing.T) {
	prov := loadC25JSON[c25Provenance](t, "provenance.json")
	if prov.Task != "C25" || prov.License != "Apache-2.0" {
		t.Fatalf("unexpected C25 provenance: %+v", prov)
	}
	if len(prov.SHA256) != 3 {
		t.Fatalf("expected 3 hashed C25 fixture files, got %d", len(prov.SHA256))
	}
	dir := getC25FixturesDir(t)
	for rel, want := range prov.SHA256 {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("missing C25 fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("fixture %s sha mismatch: got %s want %s", rel, got, want)
		}
	}
}

func TestRetentionNoAutomaticRawTTL(t *testing.T) {
	fx := loadC25JSON[c25PositiveFixture](t, "positive/explicit-destruction.json")
	expected := loadC25JSON[c25ExpectedOutcomesFixture](t, "expected-output/retention-outcomes.json")
	if expected.AutoRawTTLPermitted {
		t.Fatalf("expected auto_raw_ttl_permitted to be false")
	}

	env := setupC25Env(t)
	blobPath, initialSHA := seedSealedEvidenceForC25(t, env, fx.CaseID, fx.EvidenceID, fx.Payload)
	ctx := context.Background()

	// 1. Policy attempting automatic deletion or non-zero raw TTL must fail with ErrAutoRawTTLForbidden
	if _, err := env.retStore.SetPolicy(ctx, retention.RetentionPolicy{
		PolicyID:              "pol-auto-del",
		CaseID:                fx.CaseID,
		AutoDeleteRawEvidence: true,
		Actor:                 fx.AllowedDestroy.Operator,
		UpdatedAt:             fx.AllowedDestroy.Timestamp,
		Reason:                "Forbidden automatic deletion",
	}); !errors.Is(err, retention.ErrAutoRawTTLForbidden) {
		t.Fatalf("expected ErrAutoRawTTLForbidden on AutoDeleteRawEvidence=true, got %v", err)
	}

	if _, err := env.retStore.SetPolicy(ctx, retention.RetentionPolicy{
		PolicyID:     "pol-ttl",
		CaseID:       fx.CaseID,
		RawTTLSeconds: 3600,
		Actor:        fx.AllowedDestroy.Operator,
		UpdatedAt:    fx.AllowedDestroy.Timestamp,
		Reason:       "Forbidden raw TTL",
	}); !errors.Is(err, retention.ErrAutoRawTTLForbidden) {
		t.Fatalf("expected ErrAutoRawTTLForbidden on RawTTLSeconds>0, got %v", err)
	}

	// 2. Valid manual-approval policy succeeds
	pol, err := env.retStore.SetPolicy(ctx, retention.RetentionPolicy{
		PolicyID:                fx.PolicyID,
		CaseID:                  fx.CaseID,
		AutoDeleteRawEvidence:   false,
		RawTTLSeconds:           0,
		RequireExplicitApproval: true,
		Actor:                   fx.AllowedDestroy.Operator,
		UpdatedAt:               fx.AllowedDestroy.Timestamp,
		Reason:                  "Preserve raw evidence; no automatic TTL",
		Provider:                fx.Provider,
	})
	if err != nil {
		t.Fatalf("valid SetPolicy failed: %v", err)
	}
	if pol.AutoDeleteRawEvidence || pol.RawTTLSeconds != 0 {
		t.Fatalf("unexpected auto TTL fields: %+v", pol)
	}

	// 3. EvaluateAutomaticRetention guarantees RawDeletedCount == 0
	sweep, err := env.retStore.EvaluateAutomaticRetention(ctx, fx.CaseID)
	if err != nil {
		t.Fatalf("EvaluateAutomaticRetention failed: %v", err)
	}
	if sweep.RawDeletedCount != 0 || sweep.EvaluatedCount != 1 || len(sweep.EligibleCandidateIDs) != 1 {
		t.Fatalf("unexpected sweep report: %+v", sweep)
	}

	// 4. DestroyEvidence invoked with AutomaticTTL=true must fail with ErrAutoRawTTLForbidden
	if _, err := env.retStore.DestroyEvidence(ctx, retention.DestroyRequest{
		OperationID:      "op-auto-ttl-attempt",
		TombstoneID:      "tomb-auto",
		CaseID:           fx.CaseID,
		EvidenceID:       fx.EvidenceID,
		Operator:         fx.AllowedDestroy.Operator,
		Timestamp:        fx.AllowedDestroy.Timestamp,
		Reason:           "Automated sweep attempt",
		ExplicitApproval: false,
		AutomaticTTL:     true,
	}); !errors.Is(err, retention.ErrAutoRawTTLForbidden) {
		t.Fatalf("expected ErrAutoRawTTLForbidden on AutomaticTTL=true, got %v", err)
	}

	assertBlobSHAC25(t, blobPath, initialSHA)
}

func TestRetentionExplicitDestructionRespectsHoldAndRestart(t *testing.T) {
	fx := loadC25JSON[c25PositiveFixture](t, "positive/explicit-destruction.json")
	expected := loadC25JSON[c25ExpectedOutcomesFixture](t, "expected-output/retention-outcomes.json")
	env := setupC25Env(t)
	blobPath, initialSHA := seedSealedEvidenceForC25(t, env, fx.CaseID, fx.EvidenceID, fx.Payload)
	ctx := context.Background()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pubKey)

	// 1. Place active legal hold
	_, err = env.holdService.PlaceHold(ctx, holds.PlaceHoldRequest{
		HoldID:     fx.HoldID,
		CaseID:     fx.CaseID,
		EvidenceID: fx.EvidenceID,
		Actor:      fx.Hold.Actor,
		Timestamp:  fx.Hold.Timestamp,
		Reason:     fx.Hold.Reason,
		Provider:   fx.Provider,
		PrivateKey: privKey,
	})
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}

	// 2. Attempt explicit operator destruction while hold is active -> MUST FAIL with ErrHoldActive
	_, err = env.retStore.DestroyEvidence(ctx, retention.DestroyRequest{
		SchemaVersion:    "1",
		OperationID:      fx.BlockedDestroy.OperationID,
		TombstoneID:      fx.BlockedDestroy.TombstoneID,
		CaseID:           fx.CaseID,
		EvidenceID:       fx.EvidenceID,
		Operator:         fx.BlockedDestroy.Operator,
		Timestamp:        fx.BlockedDestroy.Timestamp,
		Reason:           fx.BlockedDestroy.Reason,
		Provider:         fx.Provider,
		ExplicitApproval: true,
		KeyID:            fx.KeyID,
		PrivateKey:       privKey,
	})
	if !errors.Is(err, retention.ErrHoldActive) || !errors.Is(err, holds.ErrHoldActive) {
		t.Fatalf("expected ErrHoldActive while hold is active, got %v", err)
	}

	// No tombstone must exist
	if _, err := env.retStore.GetTombstone(fx.CaseID, fx.EvidenceID); !errors.Is(err, retention.ErrTombstoneNotFound) {
		t.Fatalf("expected ErrTombstoneNotFound while held, got %v", err)
	}
	assertBlobSHAC25(t, blobPath, initialSHA)

	// 3. Restart RetentionStore and HoldService -> hold must STILL block destruction
	if err := env.retStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := env.holdService.Close(); err != nil {
		t.Fatal(err)
	}

	holdSvc2, err := holds.OpenService(holds.ServiceConfig{
		RootDir:   env.holdsDir,
		SealStore: env.sealStore,
		Ledger:    env.ledgerStore,
		SyncDir:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.holdService = holdSvc2

	retStore2, err := retention.OpenRetentionStore(retention.RetentionConfig{
		RootDir:     env.retDir,
		SealStore:   env.sealStore,
		HoldService: holdSvc2,
		LedgerStore: env.ledgerStore,
		SyncDir:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.retStore = retStore2

	_, err = env.retStore.DestroyEvidence(ctx, retention.DestroyRequest{
		SchemaVersion:    "1",
		OperationID:      fx.BlockedDestroy.OperationID + "-post-restart",
		TombstoneID:      fx.BlockedDestroy.TombstoneID,
		CaseID:           fx.CaseID,
		EvidenceID:       fx.EvidenceID,
		Operator:         fx.BlockedDestroy.Operator,
		Timestamp:        fx.BlockedDestroy.Timestamp,
		Reason:           fx.BlockedDestroy.Reason,
		Provider:         fx.Provider,
		ExplicitApproval: true,
	})
	if !errors.Is(err, retention.ErrHoldActive) {
		t.Fatalf("expected ErrHoldActive after restart, got %v", err)
	}
	assertBlobSHAC25(t, blobPath, initialSHA)

	// 4. Release hold and execute explicit operator destruction -> creates verifiable tombstone
	if _, err := env.holdService.ReleaseHold(ctx, holds.ReleaseHoldRequest{
		HoldID:     fx.HoldID,
		CaseID:     fx.CaseID,
		EvidenceID: fx.EvidenceID,
		Actor:      fx.Release.Actor,
		Timestamp:  fx.Release.Timestamp,
		Reason:     fx.Release.Reason,
		Provider:   fx.Provider,
		PrivateKey: privKey,
	}); err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}

	out, err := env.retStore.DestroyEvidence(ctx, retention.DestroyRequest{
		SchemaVersion:    "1",
		OperationID:      fx.AllowedDestroy.OperationID,
		TombstoneID:      fx.AllowedDestroy.TombstoneID,
		CaseID:           fx.CaseID,
		EvidenceID:       fx.EvidenceID,
		Operator:         fx.AllowedDestroy.Operator,
		Timestamp:        fx.AllowedDestroy.Timestamp,
		Reason:           fx.AllowedDestroy.Reason,
		Provider:         fx.Provider,
		ExplicitApproval: true,
		KeyID:            fx.KeyID,
		PrivateKey:       privKey,
	})
	if err != nil {
		t.Fatalf("DestroyEvidence after release failed: %v", err)
	}
	if out.Tombstone.State != expected.ExplicitOperatorDestroyed.State {
		t.Fatalf("tombstone state: got %q want %q", out.Tombstone.State, expected.ExplicitOperatorDestroyed.State)
	}
	if out.Tombstone.OriginalSHA256 != initialSHA || !out.Tombstone.Signed || !out.Tombstone.SealedBytesIntact {
		t.Fatalf("unexpected tombstone metadata: %+v", out.Tombstone)
	}

	if err := retention.VerifyTombstone(out.Tombstone, map[string]string{fx.KeyID: pubHex}); err != nil {
		t.Fatalf("VerifyTombstone failed: %v", err)
	}
	// Wrong signer check
	if err := retention.VerifyTombstone(out.Tombstone, map[string]string{fx.KeyID: strings.Repeat("0", 64)}); err == nil {
		t.Fatalf("expected VerifyTombstone to reject untrusted signer key")
	}

	// Sealed bytes must remain intact
	assertBlobSHAC25(t, blobPath, initialSHA)

	// Idempotent replay with same OperationID works across restarts
	if err := env.retStore.Close(); err != nil {
		t.Fatal(err)
	}
	retStore3, err := retention.OpenRetentionStore(retention.RetentionConfig{
		RootDir:     env.retDir,
		SealStore:   env.sealStore,
		HoldService: env.holdService,
		LedgerStore: env.ledgerStore,
		SyncDir:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.retStore = retStore3

	if rep := env.retStore.RecoveryReport(); rep.RecoveredTombstones != 1 {
		t.Fatalf("expected 1 recovered tombstone on restart, got %+v", rep)
	}

	replay, err := env.retStore.DestroyEvidence(ctx, retention.DestroyRequest{
		SchemaVersion:    "1",
		OperationID:      fx.AllowedDestroy.OperationID,
		TombstoneID:      fx.AllowedDestroy.TombstoneID,
		CaseID:           fx.CaseID,
		EvidenceID:       fx.EvidenceID,
		Operator:         fx.AllowedDestroy.Operator,
		Timestamp:        fx.AllowedDestroy.Timestamp,
		Reason:           fx.AllowedDestroy.Reason,
		Provider:         fx.Provider,
		ExplicitApproval: true,
		KeyID:            fx.KeyID,
	})
	if err != nil || !replay.IdempotentReplay || replay.Tombstone.TombstoneDigest != out.Tombstone.TombstoneDigest {
		t.Fatalf("idempotent replay failed: err=%v replay=%+v", err, replay)
	}

	// Verify complete audit trail survives restart
	trail, err := env.retStore.AuditTrail(fx.CaseID, fx.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(trail) != 3 {
		t.Fatalf("expected 3 audit entries (2 blocked + 1 destroyed), got %d: %+v", len(trail), trail)
	}
	if trail[0].Action != expected.BlockedUnderHold.AuditAction || trail[0].Outcome != expected.BlockedUnderHold.AuditOutcome {
		t.Fatalf("unexpected blocked audit[0]: %+v", trail[0])
	}
	if trail[2].Action != expected.ExplicitOperatorDestroyed.AuditAction || trail[2].Outcome != expected.ExplicitOperatorDestroyed.AuditOutcome || trail[2].TombstoneID != fx.AllowedDestroy.TombstoneID {
		t.Fatalf("unexpected allowed audit[2]: %+v", trail[2])
	}
}

func TestRetentionNegativeAndFaultRecoveryCases(t *testing.T) {
	fx := loadC25JSON[c25PositiveFixture](t, "positive/explicit-destruction.json")
	neg := loadC25JSON[c25NegativeCasesFixture](t, "invalid/rejected-destruction-cases.json")
	env := setupC25Env(t)
	blobPath, initialSHA := seedSealedEvidenceForC25(t, env, fx.CaseID, fx.EvidenceID, fx.Payload)
	ctx := context.Background()

	// Drive fixture negative cases
	for _, c := range neg.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.PolicyID != "" {
				_, err := env.retStore.SetPolicy(ctx, retention.RetentionPolicy{
					PolicyID:              c.PolicyID,
					CaseID:                fx.CaseID,
					AutoDeleteRawEvidence: c.AutoDeleteRawEvidence,
					RawTTLSeconds:         c.RawTTLSeconds,
					Actor:                 fx.AllowedDestroy.Operator,
					UpdatedAt:             fx.AllowedDestroy.Timestamp,
					Reason:                "Negative policy test",
				})
				if !errors.Is(err, retention.ErrAutoRawTTLForbidden) {
					t.Fatalf("expected ErrAutoRawTTLForbidden, got %v", err)
				}
				return
			}

			evID := fx.EvidenceID
			if c.EvidenceID != "" {
				evID = c.EvidenceID
			}
			op := fx.AllowedDestroy.Operator
			if c.Name == "missing_operator_attribution" {
				op = c.Operator
			}
			explicit := c.ExplicitApproval
			if c.ExpectedError != "ErrExplicitApprovalRequired" && c.ExpectedError != "ErrAutoRawTTLForbidden" {
				explicit = true
			}

			_, err := env.retStore.DestroyEvidence(ctx, retention.DestroyRequest{
				SchemaVersion:    "1",
				OperationID:      c.OperationID,
				TombstoneID:      "tomb-neg",
				CaseID:           fx.CaseID,
				EvidenceID:       evID,
				Operator:         op,
				Timestamp:        fx.AllowedDestroy.Timestamp,
				Reason:           fx.AllowedDestroy.Reason,
				Provider:         c.Provider,
				ExplicitApproval: explicit,
				AutomaticTTL:     c.AutomaticTTL,
			})
			if err == nil {
				t.Fatalf("case %s unexpectedly succeeded", c.Name)
			}
			switch c.ExpectedError {
			case "ErrAutoRawTTLForbidden":
				if !errors.Is(err, retention.ErrAutoRawTTLForbidden) {
					t.Fatalf("got %v, want ErrAutoRawTTLForbidden", err)
				}
			case "ErrExplicitApprovalRequired":
				if !errors.Is(err, retention.ErrExplicitApprovalRequired) {
					t.Fatalf("got %v, want ErrExplicitApprovalRequired", err)
				}
			case "ErrMissingPrerequisite":
				if !errors.Is(err, retention.ErrMissingPrerequisite) {
					t.Fatalf("got %v, want ErrMissingPrerequisite", err)
				}
			case "ErrUnavailableProvider":
				if !errors.Is(err, retention.ErrUnavailableProvider) {
					t.Fatalf("got %v, want ErrUnavailableProvider", err)
				}
			case "ErrInvalidRetention":
				if !errors.Is(err, retention.ErrInvalidRetention) {
					t.Fatalf("got %v, want ErrInvalidRetention", err)
				}
			}
		})
	}

	// Lock busy contention check
	if _, err := retention.OpenRetentionStore(retention.RetentionConfig{
		RootDir:     env.retDir,
		SealStore:   env.sealStore,
		HoldService: env.holdService,
	}); !errors.Is(err, retention.ErrLockBusy) {
		t.Fatalf("expected ErrLockBusy for concurrent store open, got %v", err)
	}

	// Fault injection: FailAfterStageBeforeCommit -> creates staged file, aborts, then recovers cleanly on restart
	faultDir := filepath.Join(t.TempDir(), "ret-fault")
	faultStore, err := retention.OpenRetentionStore(retention.RetentionConfig{
		RootDir:     faultDir,
		SealStore:   env.sealStore,
		HoldService: env.holdService,
		SyncDir:     true,
		Faults:      retention.RetentionFaults{FailAfterStageBeforeCommit: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = faultStore.DestroyEvidence(ctx, retention.DestroyRequest{
		OperationID:      "op-fault-stage",
		TombstoneID:      "tomb-fault-stage",
		CaseID:           fx.CaseID,
		EvidenceID:       fx.EvidenceID,
		Operator:         fx.AllowedDestroy.Operator,
		Timestamp:        fx.AllowedDestroy.Timestamp,
		Reason:           "Simulated crash before commit",
		ExplicitApproval: true,
	})
	if !errors.Is(err, retention.ErrInterrupted) {
		t.Fatalf("expected ErrInterrupted, got %v", err)
	}
	_ = faultStore.Close()

	recoveredStore, err := retention.OpenRetentionStore(retention.RetentionConfig{
		RootDir:     faultDir,
		SealStore:   env.sealStore,
		HoldService: env.holdService,
		SyncDir:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer recoveredStore.Close()

	if rep := recoveredStore.RecoveryReport(); len(rep.CleanedStagingFiles) != 1 {
		t.Fatalf("expected 1 cleaned staging file after interrupted commit, got %+v", rep)
	}
	if _, err := recoveredStore.GetTombstone(fx.CaseID, fx.EvidenceID); !errors.Is(err, retention.ErrTombstoneNotFound) {
		t.Fatalf("interrupted attempt must not leave tombstone, got %v", err)
	}

	// Complete validly on recovered store, then test conflict and duplicate destruction errors
	if _, err := recoveredStore.DestroyEvidence(ctx, retention.DestroyRequest{
		OperationID:      "op-fault-stage",
		TombstoneID:      "tomb-fault-stage",
		CaseID:           fx.CaseID,
		EvidenceID:       fx.EvidenceID,
		Operator:         fx.AllowedDestroy.Operator,
		Timestamp:        fx.AllowedDestroy.Timestamp,
		Reason:           "Completed after crash recovery",
		ExplicitApproval: true,
	}); err != nil {
		t.Fatalf("DestroyEvidence after recovery failed: %v", err)
	}

	// Conflicting OperationID reuse fails
	if _, err := recoveredStore.DestroyEvidence(ctx, retention.DestroyRequest{
		OperationID:      "op-fault-stage",
		TombstoneID:      "tomb-different",
		CaseID:           fx.CaseID,
		EvidenceID:       fx.EvidenceID,
		Operator:         fx.AllowedDestroy.Operator,
		Timestamp:        fx.AllowedDestroy.Timestamp,
		Reason:           "Conflicting reason",
		ExplicitApproval: true,
	}); !errors.Is(err, retention.ErrRetentionConflict) {
		t.Fatalf("expected ErrRetentionConflict on conflicting replay, got %v", err)
	}

	// New OperationID targeting already tombstoned evidence fails
	if _, err := recoveredStore.DestroyEvidence(ctx, retention.DestroyRequest{
		OperationID:      "op-second-attempt",
		TombstoneID:      "tomb-second",
		CaseID:           fx.CaseID,
		EvidenceID:       fx.EvidenceID,
		Operator:         fx.AllowedDestroy.Operator,
		Timestamp:        fx.AllowedDestroy.Timestamp,
		Reason:           "Duplicate destroy",
		ExplicitApproval: true,
	}); !errors.Is(err, retention.ErrAlreadyDestroyed) {
		t.Fatalf("expected ErrAlreadyDestroyed on duplicate destruction, got %v", err)
	}

	assertBlobSHAC25(t, blobPath, initialSHA)
}

func TestRetentionConcurrentSafety(t *testing.T) {
	fx := loadC25JSON[c25PositiveFixture](t, "positive/explicit-destruction.json")
	env := setupC25Env(t)
	ctx := context.Background()

	// Seed unheld item for concurrent destruction race
	unheldEv := fx.EvidenceID + "-unheld"
	blobUnheld, shaUnheld := seedSealedEvidenceForC25(t, env, fx.CaseID, unheldEv, fx.Payload)

	var wg sync.WaitGroup
	successes := 0
	var mu sync.Mutex

	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := env.retStore.DestroyEvidence(ctx, retention.DestroyRequest{
				OperationID:      fmt.Sprintf("op-race-%02d", idx),
				TombstoneID:      fmt.Sprintf("tomb-race-%02d", idx),
				CaseID:           fx.CaseID,
				EvidenceID:       unheldEv,
				Operator:         fx.AllowedDestroy.Operator,
				Timestamp:        fx.AllowedDestroy.Timestamp,
				Reason:           "Concurrent destruction race test",
				ExplicitApproval: true,
			})
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("expected exactly 1 concurrent destruction to succeed, got %d", successes)
	}
	if _, err := env.retStore.GetTombstone(fx.CaseID, unheldEv); err != nil {
		t.Fatalf("expected tombstone after race: %v", err)
	}
	assertBlobSHAC25(t, blobUnheld, shaUnheld)
}

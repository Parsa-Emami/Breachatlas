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

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/artifacts"
	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/findings"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

type c20Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c20PositiveFixture struct {
	SchemaVersion  string `json:"schema_version"`
	CaseID         string `json:"case_id"`
	EvidenceID     string `json:"evidence_id"`
	ObservedEvents []struct {
		Timestamp string `json:"timestamp"`
		EventType string `json:"event_type"`
		Summary   string `json:"summary"`
	} `json:"observed_events"`
	Hypotheses []struct {
		HypothesisID string   `json:"hypothesis_id"`
		OperationID  string   `json:"operation_id"`
		Author       string   `json:"author"`
		Rationale    string   `json:"rationale"`
		Statement    string   `json:"statement"`
		Status       string   `json:"status"`
		Confidence   *float64 `json:"confidence"`
		UILabel      string   `json:"ui_label"`
	} `json:"hypotheses"`
}

type c20InvalidFieldsFixture struct {
	SchemaVersion string `json:"schema_version"`
	CaseID        string `json:"case_id"`
	Cases         []struct {
		Name          string   `json:"name"`
		HypothesisID  string   `json:"hypothesis_id"`
		Author        string   `json:"author"`
		Rationale     string   `json:"rationale"`
		Statement     string   `json:"statement"`
		Confidence    *float64 `json:"confidence,omitempty"`
		ExpectedError string   `json:"expected_error"`
	} `json:"cases"`
}

type c20PromotionFixture struct {
	SchemaVersion string `json:"schema_version"`
	CaseID        string `json:"case_id"`
	Attempts      []struct {
		Name                string `json:"name"`
		HypothesisID        string `json:"hypothesis_id"`
		Author              string `json:"author"`
		Rationale           string `json:"rationale"`
		Statement           string `json:"statement"`
		UILabel             string `json:"ui_label"`
		ClaimRecordKind     string `json:"claim_record_kind"`
		ClaimSourceEvidence bool   `json:"claim_source_evidence"`
		ExpectedError       string `json:"expected_error"`
	} `json:"attempts"`
}

type c20PrereqProviderFixture struct {
	SchemaVersion string `json:"schema_version"`
	Cases         []struct {
		Name                 string `json:"name"`
		Provider             string `json:"provider,omitempty"`
		SchemaVersion        string `json:"schema_version,omitempty"`
		MissingSealStore     bool   `json:"missing_seal_store,omitempty"`
		SupportingEvidenceID string `json:"supporting_evidence_id,omitempty"`
		SupportingEventID    string `json:"supporting_event_id,omitempty"`
		ExpectedError        string `json:"expected_error"`
	} `json:"cases"`
}

type c20Env struct {
	root          string
	qDir          string
	sDir          string
	scDir         string
	aDir          string
	idxDir        string
	findDir       string
	sealStore     *evidence.SealStore
	registry      *analyzers.Registry
	sandbox       *analyzers.Sandbox
	artifactStore *artifacts.ArtifactStore
	indexStore    *timeline.EventIndexStore
	findingStore  *findings.FindingStore
}

func getC20FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "fixtures", "breachatlas", "C20")
	if filepath.Base(wd) != "tests" {
		dir = filepath.Join(wd, "tests", "fixtures", "breachatlas", "C20")
	}
	return dir
}

func loadC20JSON[T any](t *testing.T, rel string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(getC20FixturesDir(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read C20 fixture %s: %v", rel, err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal C20 fixture %s: %v", rel, err)
	}
	return out
}

func setupC20Env(t *testing.T) *c20Env {
	t.Helper()
	root := t.TempDir()
	qDir := filepath.Join(root, "quarantine")
	sDir := filepath.Join(root, "sealstore")
	scDir := filepath.Join(root, "scratch")
	aDir := filepath.Join(root, "artifacts")
	idxDir := filepath.Join(root, "timeline-index")
	findDir := filepath.Join(root, "findings")

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sealStore.Close() })

	reg, err := analyzers.NewRegistry(analyzers.RegistryConfig{SealStore: sealStore, SealRootDir: sDir, Provider: "local"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := analyzers.NewSandbox(reg, analyzers.DefaultSandboxConfig(scDir))
	if err != nil {
		t.Fatal(err)
	}
	aStore, err := artifacts.OpenArtifactStore(artifacts.StoreConfig{RootDir: aDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aStore.Close() })

	idxStore, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: idxDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = idxStore.Close() })

	fStore, err := findings.OpenFindingStore(findings.FindingStoreConfig{RootDir: findDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fStore.Close() })

	return &c20Env{
		root:          root,
		qDir:          qDir,
		sDir:          sDir,
		scDir:         scDir,
		aDir:          aDir,
		idxDir:        idxDir,
		findDir:       findDir,
		sealStore:     sealStore,
		registry:      reg,
		sandbox:       sb,
		artifactStore: aStore,
		indexStore:    idxStore,
		findingStore:  fStore,
	}
}

func seedSealedObservedFactsC20(t *testing.T, env *c20Env, fx c20PositiveFixture) (string, string, int64, []string) {
	t.Helper()
	var lines []string
	for _, ev := range fx.ObservedEvents {
		raw, err := json.Marshal(map[string]any{
			"timestamp":  ev.Timestamp,
			"event_type": ev.EventType,
			"summary":    ev.Summary,
		})
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(raw))
	}
	jsonl := strings.Join(lines, "\n") + "\n"
	sum := sha256.Sum256([]byte(jsonl))
	shaHex := hex.EncodeToString(sum[:])
	sz := int64(len(jsonl))

	q, err := evidence.StreamIntoQuarantine(context.Background(), evidence.UploadConfig{
		QuarantineDir: env.qDir,
		BufferSize:    64,
		SyncDir:       true,
	}, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-" + fx.CaseID + "-" + fx.EvidenceID,
		CaseID:        fx.CaseID,
		EvidenceID:    fx.EvidenceID,
		MediaType:     "application/json",
		Filename:      fx.EvidenceID + ".jsonl",
		ExpectedSize:  &sz,
		Body:          strings.NewReader(jsonl),
	})
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	sm, err := env.sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
		OperationID:    "seal-" + fx.CaseID + "-" + fx.EvidenceID,
		Quarantined:    q,
		ExpectedSHA256: shaHex,
		AcquiredAt:     "2026-09-01T08:20:00Z",
		CustodyRoot:    custody.GenesisPrevHash,
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	blobPath := filepath.Join(env.sDir, filepath.FromSlash(sm.BlobRelPath))

	runRes, err := env.sandbox.RunIsolated(context.Background(), analyzers.IsolatedRunRequest{
		RunID:      "run-" + fx.CaseID,
		CaseID:     fx.CaseID,
		EvidenceID: fx.EvidenceID,
		AnalyzerID: analyzers.AnalyzerJSON,
		Provider:   "local",
		Options:    analyzers.DefaultParseOptions(),
	})
	if err != nil {
		t.Fatalf("sandbox run: %v", err)
	}
	_, err = env.artifactStore.DeriveFromIsolatedRun(context.Background(), env.sealStore, env.sDir, runRes, artifacts.DeriveRequest{
		OperationID: "drv-" + fx.CaseID,
		CaseID:      fx.CaseID,
		ArtifactID:  "art-" + fx.CaseID,
		Provider:    "local",
	})
	if err != nil {
		t.Fatalf("derive artifact: %v", err)
	}
	idxOut, err := env.indexStore.IndexDerivedArtifact(context.Background(), env.sealStore, env.sDir, env.artifactStore, env.aDir, timeline.IndexDerivedRequest{
		SchemaVersion: "1",
		OperationID:   "idx-" + fx.CaseID,
		CaseID:        fx.CaseID,
		ArtifactID:    "art-" + fx.CaseID,
		Provider:      "local",
	})
	if err != nil {
		t.Fatalf("index artifact: %v", err)
	}
	return blobPath, shaHex, sz, idxOut.EntryIdentities
}

func assertSealedBlobUnchangedC20(t *testing.T, blobPath, expectedSHA string, expectedSize int64) {
	t.Helper()
	raw, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read sealed blob %s: %v", blobPath, err)
	}
	sum := sha256.Sum256(raw)
	if gotSHA := hex.EncodeToString(sum[:]); int64(len(raw)) != expectedSize || gotSHA != expectedSHA {
		t.Fatalf("sealed source bytes modified! got size=%d sha=%s want size=%d sha=%s", len(raw), gotSHA, expectedSize, expectedSHA)
	}
}

func TestC20FixturesAndProvenance(t *testing.T) {
	prov := loadC20JSON[c20Provenance](t, "provenance.json")
	if prov.Task != "C20" || prov.License != "Apache-2.0" {
		t.Fatalf("unexpected C20 provenance: %+v", prov)
	}
	if len(prov.SHA256) != 5 {
		t.Fatalf("expected 5 hashed C20 fixture files, got %d", len(prov.SHA256))
	}
	dir := getC20FixturesDir(t)
	for rel, want := range prov.SHA256 {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("missing C20 fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("fixture %s sha mismatch: got %s want %s", rel, got, want)
		}
	}
}

func TestC20HypothesisAuthorRationaleAndSeparation(t *testing.T) {
	fx := loadC20JSON[c20PositiveFixture](t, "positive/analyst-hypotheses-and-facts.json")
	env := setupC20Env(t)

	blobPath, sealedSHA, sealedSize, eventIDs := seedSealedObservedFactsC20(t, env, fx)
	if len(eventIDs) != len(fx.ObservedEvents) {
		t.Fatalf("expected %d observed event identities, got %d", len(fx.ObservedEvents), len(eventIDs))
	}

	for _, h := range fx.Hypotheses {
		out, err := env.findingStore.RecordHypothesis(context.Background(), env.sealStore, env.sDir, env.indexStore, findings.RecordHypothesisRequest{
			SchemaVersion:         fx.SchemaVersion,
			OperationID:           h.OperationID,
			CaseID:                fx.CaseID,
			HypothesisID:          h.HypothesisID,
			Provider:              "local",
			Author:                h.Author,
			Rationale:             h.Rationale,
			Statement:             h.Statement,
			Status:                h.Status,
			Confidence:            h.Confidence,
			UILabel:               h.UILabel,
			SupportingEvidenceIDs: []string{fx.EvidenceID},
			SupportingEventIDs:    eventIDs[:1],
		})
		if err != nil {
			t.Fatalf("record hypothesis %s: %v", h.HypothesisID, err)
		}
		if out.Hypothesis.RecordKind != findings.RecordKindAnalystHypothesis || out.Hypothesis.IsSourceEvidence {
			t.Fatalf("hypothesis %s violated non-promotion invariant: %+v", h.HypothesisID, out.Hypothesis)
		}
		if out.Hypothesis.Author == "" || out.Hypothesis.Rationale == "" {
			t.Fatalf("hypothesis %s lost author/rationale: %+v", h.HypothesisID, out.Hypothesis)
		}
	}

	// Build strict epistemic ledger and prove spoofed UI label "source_evidence" never moves hypothesis to ObservedFacts.
	ledger, err := env.findingStore.BuildEpistemicLedger(context.Background(), env.sealStore, env.sDir, env.indexStore, fx.CaseID)
	if err != nil {
		t.Fatalf("BuildEpistemicLedger: %v", err)
	}
	if len(ledger.ObservedFacts) != len(fx.ObservedEvents) {
		t.Fatalf("expected %d observed facts, got %d", len(fx.ObservedEvents), len(ledger.ObservedFacts))
	}
	for _, fact := range ledger.ObservedFacts {
		if fact.RecordKind != findings.RecordKindObservedFact || fact.SealedSHA256 != sealedSHA {
			t.Fatalf("unexpected observed fact projection: %+v", fact)
		}
	}
	if len(ledger.Hypotheses) != len(fx.Hypotheses) {
		t.Fatalf("expected %d hypotheses, got %d", len(fx.Hypotheses), len(ledger.Hypotheses))
	}
	foundSpoofedBadge := false
	for _, hyp := range ledger.Hypotheses {
		if hyp.RecordKind != findings.RecordKindAnalystHypothesis || hyp.IsSourceEvidence {
			t.Fatalf("ledger hypothesis became source evidence: %+v", hyp)
		}
		if hyp.UILabel == "source_evidence" {
			foundSpoofedBadge = true
		}
	}
	if !foundSpoofedBadge {
		t.Fatalf("expected fixture hypothesis carrying source_evidence UI label to remain in Hypotheses")
	}

	// Explicit promotion API must fail closed.
	err = env.findingStore.PromoteHypothesisToEvidence(fx.CaseID, "hyp-c20-02-spoofed-ui", "source_evidence")
	if !errors.Is(err, findings.ErrPromotionForbidden) {
		t.Fatalf("expected ErrPromotionForbidden, got %v", err)
	}

	assertSealedBlobUnchangedC20(t, blobPath, sealedSHA, sealedSize)
}

func TestC20NegativePrerequisitesMalformedAndProviders(t *testing.T) {
	posFx := loadC20JSON[c20PositiveFixture](t, "positive/analyst-hypotheses-and-facts.json")
	fieldsFx := loadC20JSON[c20InvalidFieldsFixture](t, "invalid/missing-author-rationale.json")
	promoFx := loadC20JSON[c20PromotionFixture](t, "invalid/ui-label-promotion-spoof.json")
	prereqFx := loadC20JSON[c20PrereqProviderFixture](t, "invalid/missing-prerequisite-and-provider.json")

	env := setupC20Env(t)
	blobPath, sealedSHA, sealedSize, _ := seedSealedObservedFactsC20(t, env, posFx)

	// 1. Missing/invalid Author, Rationale, Statement, or Confidence.
	for _, tc := range fieldsFx.Cases {
		t.Run("field_"+tc.Name, func(t *testing.T) {
			_, err := env.findingStore.RecordHypothesis(context.Background(), env.sealStore, env.sDir, env.indexStore, findings.RecordHypothesisRequest{
				SchemaVersion: "1",
				CaseID:        posFx.CaseID,
				HypothesisID:  tc.HypothesisID,
				Author:        tc.Author,
				Rationale:     tc.Rationale,
				Statement:     tc.Statement,
				Confidence:    tc.Confidence,
			})
			switch tc.ExpectedError {
			case "ErrMissingAuthor":
				if !errors.Is(err, findings.ErrMissingAuthor) {
					t.Fatalf("expected ErrMissingAuthor, got %v", err)
				}
			case "ErrMissingRationale":
				if !errors.Is(err, findings.ErrMissingRationale) {
					t.Fatalf("expected ErrMissingRationale, got %v", err)
				}
			case "ErrInvalidHypothesis":
				if !errors.Is(err, findings.ErrInvalidHypothesis) {
					t.Fatalf("expected ErrInvalidHypothesis, got %v", err)
				}
			default:
				t.Fatalf("unexpected expected_error %q", tc.ExpectedError)
			}
		})
	}

	// 2. Spoofed source-evidence promotion attempts.
	for _, att := range promoFx.Attempts {
		t.Run("promotion_"+att.Name, func(t *testing.T) {
			var err error
			if att.Name == "promote_method_with_ui_label" {
				err = env.findingStore.PromoteHypothesisToEvidence(posFx.CaseID, att.HypothesisID, att.UILabel)
			} else {
				_, err = env.findingStore.RecordHypothesis(context.Background(), env.sealStore, env.sDir, env.indexStore, findings.RecordHypothesisRequest{
					SchemaVersion:       "1",
					CaseID:              posFx.CaseID,
					HypothesisID:        att.HypothesisID,
					Author:              att.Author,
					Rationale:           att.Rationale,
					Statement:           att.Statement,
					ClaimRecordKind:     att.ClaimRecordKind,
					ClaimSourceEvidence: att.ClaimSourceEvidence,
				})
			}
			if !errors.Is(err, findings.ErrPromotionForbidden) {
				t.Fatalf("expected ErrPromotionForbidden, got %v", err)
			}
		})
	}

	// 3. Unavailable providers, unsupported version, missing prerequisites.
	for _, tc := range prereqFx.Cases {
		t.Run("prereq_"+tc.Name, func(t *testing.T) {
			sv := tc.SchemaVersion
			if sv == "" {
				sv = "1"
			}
			sealRef := env.sealStore
			sealRoot := env.sDir
			if tc.MissingSealStore {
				sealRef = nil
				sealRoot = ""
			}
			var supEv []string
			if tc.SupportingEvidenceID != "" {
				supEv = []string{tc.SupportingEvidenceID}
			}
			var supEvents []string
			if tc.SupportingEventID != "" {
				supEvents = []string{tc.SupportingEventID}
			}
			_, err := env.findingStore.RecordHypothesis(context.Background(), sealRef, sealRoot, env.indexStore, findings.RecordHypothesisRequest{
				SchemaVersion:         sv,
				CaseID:                posFx.CaseID,
				HypothesisID:          "hyp-prereq-" + tc.Name,
				Provider:              tc.Provider,
				Author:                "analyst.mina@ir.local",
				Rationale:             "Negative check prerequisite verification.",
				Statement:             "Negative test hypothesis statement.",
				SupportingEvidenceIDs: supEv,
				SupportingEventIDs:    supEvents,
			})
			switch tc.ExpectedError {
			case "ErrUnavailableProvider":
				if !errors.Is(err, findings.ErrUnavailableProvider) {
					t.Fatalf("expected ErrUnavailableProvider, got %v", err)
				}
			case "ErrUnsupportedVersion":
				if !errors.Is(err, findings.ErrUnsupportedVersion) {
					t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
				}
			case "ErrMissingPrerequisite":
				if !errors.Is(err, findings.ErrMissingPrerequisite) {
					t.Fatalf("expected ErrMissingPrerequisite, got %v", err)
				}
			default:
				t.Fatalf("unexpected expected_error %q", tc.ExpectedError)
			}
		})
	}

	// 4. Path traversal / bad identifiers and lock contention.
	if _, err := env.findingStore.RecordHypothesis(context.Background(), env.sealStore, env.sDir, env.indexStore, findings.RecordHypothesisRequest{
		SchemaVersion: "1",
		CaseID:        "../escape",
		HypothesisID:  "hyp-bad",
		Author:        "a",
		Rationale:     "b",
		Statement:     "c",
	}); !errors.Is(err, findings.ErrPathTraversal) {
		t.Fatalf("expected ErrPathTraversal for invalid case_id, got %v", err)
	}
	if _, err := findings.OpenFindingStore(findings.FindingStoreConfig{RootDir: env.findDir}); !errors.Is(err, findings.ErrFindingLockBusy) {
		t.Fatalf("expected ErrFindingLockBusy when second writer opens active store, got %v", err)
	}

	assertSealedBlobUnchangedC20(t, blobPath, sealedSHA, sealedSize)
}

func TestC20RestartRecoveryAndTamperDefense(t *testing.T) {
	fx := loadC20JSON[c20PositiveFixture](t, "positive/analyst-hypotheses-and-facts.json")
	env := setupC20Env(t)
	blobPath, sealedSHA, sealedSize, eventIDs := seedSealedObservedFactsC20(t, env, fx)

	// Close normal store, open with crash-before-commit fault injection.
	_ = env.findingStore.Close()
	faultStore, err := findings.OpenFindingStore(findings.FindingStoreConfig{
		RootDir: env.findDir,
		SyncDir: true,
		Faults:  findings.FindingFaults{FailAfterStageBeforeCommit: true},
	})
	if err != nil {
		t.Fatalf("open fault finding store: %v", err)
	}
	h0 := fx.Hypotheses[0]
	_, err = faultStore.RecordHypothesis(context.Background(), env.sealStore, env.sDir, env.indexStore, findings.RecordHypothesisRequest{
		SchemaVersion:         "1",
		OperationID:           h0.OperationID,
		CaseID:                fx.CaseID,
		HypothesisID:          h0.HypothesisID,
		Author:                h0.Author,
		Rationale:             h0.Rationale,
		Statement:             h0.Statement,
		UILabel:               "source_evidence",
		SupportingEvidenceIDs: []string{fx.EvidenceID},
		SupportingEventIDs:    eventIDs[:1],
	})
	if !errors.Is(err, findings.ErrInterrupted) {
		t.Fatalf("expected ErrInterrupted during staged fault, got %v", err)
	}
	_ = faultStore.Close()

	// Reopen cleanly: orphan staging cleaned, zero committed hypotheses.
	reopened, err := findings.OpenFindingStore(findings.FindingStoreConfig{RootDir: env.findDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen after crash: %v", err)
	}
	if rep := reopened.LastRecoveryReport(); len(rep.CleanedStagingFiles) == 0 || rep.RecoveredHypotheses != 0 {
		t.Fatalf("unexpected recovery report after interrupted commit: %+v", rep)
	}

	// Now commit all hypotheses cleanly.
	for _, h := range fx.Hypotheses {
		if _, err := reopened.RecordHypothesis(context.Background(), env.sealStore, env.sDir, env.indexStore, findings.RecordHypothesisRequest{
			SchemaVersion:         "1",
			OperationID:           h.OperationID,
			CaseID:                fx.CaseID,
			HypothesisID:          h.HypothesisID,
			Author:                h.Author,
			Rationale:             h.Rationale,
			Statement:             h.Statement,
			UILabel:               h.UILabel,
			SupportingEvidenceIDs: []string{fx.EvidenceID},
		}); err != nil {
			t.Fatalf("commit %s after recovery: %v", h.HypothesisID, err)
		}
	}
	_ = reopened.Close()

	// Second restart: verify recovered counts, idempotent replay, conflict rejection, and ledger invariant.
	restarted, err := findings.OpenFindingStore(findings.FindingStoreConfig{RootDir: env.findDir, SyncDir: true})
	if err != nil {
		t.Fatalf("reopen persisted findings: %v", err)
	}
	if rep := restarted.LastRecoveryReport(); rep.RecoveredCases != 1 || rep.RecoveredHypotheses != len(fx.Hypotheses) {
		t.Fatalf("expected 1 recovered case and %d hypotheses, got %+v", len(fx.Hypotheses), rep)
	}

	replay, err := restarted.RecordHypothesis(context.Background(), env.sealStore, env.sDir, env.indexStore, findings.RecordHypothesisRequest{
		SchemaVersion:         "1",
		OperationID:           h0.OperationID,
		CaseID:                fx.CaseID,
		HypothesisID:          h0.HypothesisID,
		Author:                h0.Author,
		Rationale:             h0.Rationale,
		Statement:             h0.Statement,
		UILabel:               h0.UILabel,
		SupportingEvidenceIDs: []string{fx.EvidenceID},
	})
	if err != nil || !replay.IdempotentReplay {
		t.Fatalf("expected idempotent replay after restart, got replay=%v err=%v", replay, err)
	}
	if _, err := restarted.RecordHypothesis(context.Background(), env.sealStore, env.sDir, env.indexStore, findings.RecordHypothesisRequest{
		SchemaVersion: "1",
		OperationID:   h0.OperationID,
		CaseID:        fx.CaseID,
		HypothesisID:  h0.HypothesisID,
		Author:        h0.Author,
		Rationale:     h0.Rationale,
		Statement:     "Conflicting altered claim",
	}); !errors.Is(err, findings.ErrFindingConflict) {
		t.Fatalf("expected ErrFindingConflict on conflicting operation_id reuse, got %v", err)
	}

	ledger, err := restarted.BuildEpistemicLedger(context.Background(), env.sealStore, env.sDir, env.indexStore, fx.CaseID)
	if err != nil {
		t.Fatalf("BuildEpistemicLedger after restart: %v", err)
	}
	if len(ledger.ObservedFacts) != len(fx.ObservedEvents) || len(ledger.Hypotheses) != len(fx.Hypotheses) {
		t.Fatalf("unexpected ledger counts after restart: facts=%d hyps=%d", len(ledger.ObservedFacts), len(ledger.Hypotheses))
	}
	_ = restarted.Close()

	// Simulate hostile on-disk edit attempting to flip is_source_evidence / record_kind.
	caseFile := filepath.Join(env.findDir, "cases", fx.CaseID+".hypotheses.json")
	rawCase, err := os.ReadFile(caseFile)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(rawCase), `"is_source_evidence": false`, `"is_source_evidence": true`, 1)
	if err := os.WriteFile(caseFile, []byte(tampered), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.OpenFindingStore(findings.FindingStoreConfig{RootDir: env.findDir}); err == nil {
		t.Fatalf("expected tamper failure on reopen after on-disk edit to is_source_evidence")
	}

	assertSealedBlobUnchangedC20(t, blobPath, sealedSHA, sealedSize)
}

func TestC20ConcurrentFindingsAndLedgerRace(t *testing.T) {
	fx := loadC20JSON[c20PositiveFixture](t, "positive/analyst-hypotheses-and-facts.json")
	env := setupC20Env(t)
	blobPath, sealedSHA, sealedSize, eventIDs := seedSealedObservedFactsC20(t, env, fx)

	var wg sync.WaitGroup
	errs := make(chan error, 32)

	for i := 0; i < 6; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				hid := fmt.Sprintf("hyp-race-%d-%d", i, j)
				if _, err := env.findingStore.RecordHypothesis(context.Background(), env.sealStore, env.sDir, env.indexStore, findings.RecordHypothesisRequest{
					SchemaVersion:         "1",
					OperationID:           "op-" + hid,
					CaseID:                fx.CaseID,
					HypothesisID:          hid,
					Author:                fmt.Sprintf("analyst-%d@ir.local", i),
					Rationale:             "Concurrent reasoning validation.",
					Statement:             "Observed correlation hypothesis " + hid,
					UILabel:               "source_evidence",
					SupportingEvidenceIDs: []string{fx.EvidenceID},
					SupportingEventIDs:    eventIDs[:1],
				}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}

	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				ledger, err := env.findingStore.BuildEpistemicLedger(context.Background(), env.sealStore, env.sDir, env.indexStore, fx.CaseID)
				if err != nil {
					errs <- err
					return
				}
				if len(ledger.ObservedFacts) != len(fx.ObservedEvents) {
					errs <- fmt.Errorf("observed facts altered under concurrent hypotheses: got %d", len(ledger.ObservedFacts))
					return
				}
				for _, h := range ledger.Hypotheses {
					if h.IsSourceEvidence || h.RecordKind != findings.RecordKindAnalystHypothesis {
						errs <- fmt.Errorf("promotion invariant violated under concurrency: %+v", h)
						return
					}
				}
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent C20 error: %v", err)
		}
	}

	assertSealedBlobUnchangedC20(t, blobPath, sealedSHA, sealedSize)
}

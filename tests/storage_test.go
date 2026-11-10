package tests_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/storage"
)

type FixtureData struct {
	OperationID string            `json:"operation_id"`
	Manifest    evidence.Manifest `json:"manifest"`
	PayloadUTF8 string            `json:"payload_utf8"`
	Identity    storage.Identity  `json:"identity"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type OutcomeExpected struct {
	Status      string `json:"status"`
	Code        string `json:"code,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
	CaseID      string `json:"case_id,omitempty"`
	EvidenceID  string `json:"evidence_id,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
}

type Provenance struct {
	License string            `json:"license"`
	Origin  string            `json:"origin"`
	SHA256  map[string]string `json:"sha256"`
}

func getFixturesDir(t *testing.T) string {
	dir := filepath.Join("..", "tests", "fixtures", "breachatlas", "C05")
	if _, err := os.Stat(dir); err == nil {
		return dir
	}
	dir = filepath.Join("fixtures", "breachatlas", "C05")
	if _, err := os.Stat(dir); err == nil {
		return dir
	}
	t.Fatalf("could not locate C05 fixtures directory")
	return ""
}

func TestC05FixturesAndNegativeCases(t *testing.T) {
	fixturesDir := getFixturesDir(t)

	// 1. Verify provenance integrity & Apache-2.0 license
	provBytes, err := os.ReadFile(filepath.Join(fixturesDir, "provenance.json"))
	if err != nil {
		t.Fatalf("failed to read provenance.json: %v", err)
	}
	var prov Provenance
	if err := json.Unmarshal(provBytes, &prov); err != nil {
		t.Fatalf("malformed provenance.json: %v", err)
	}
	if prov.License != "Apache-2.0" {
		t.Fatalf("expected Apache-2.0 license in provenance, got %q", prov.License)
	}
	for relPath, expectedHash := range prov.SHA256 {
		content, err := os.ReadFile(filepath.Join(fixturesDir, relPath))
		if err != nil {
			t.Fatalf("missing fixture file referenced in provenance: %s", relPath)
		}
		h := sha256.Sum256(content)
		if hex.EncodeToString(h[:]) != expectedHash {
			t.Fatalf("fixture hash mismatch for %s: got %s, want %s", relPath, hex.EncodeToString(h[:]), expectedHash)
		}
	}

	// 2. Read expected outcomes
	outcomesBytes, err := os.ReadFile(filepath.Join(fixturesDir, "expected-output", "outcomes.json"))
	if err != nil {
		t.Fatalf("failed to read outcomes.json: %v", err)
	}
	var outcomes map[string]OutcomeExpected
	if err := json.Unmarshal(outcomesBytes, &outcomes); err != nil {
		t.Fatalf("malformed outcomes.json: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "c05-fixtures-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	adapter, err := storage.Open(storage.Config{
		RootDir: tmpDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("failed to open adapter: %v", err)
	}
	defer adapter.Close()

	ctx := context.Background()

	// 3. Test Positive Authoritative Write
	posRel := "positive/authoritative-write.json"
	posExpected := outcomes[posRel]
	posBytes, err := os.ReadFile(filepath.Join(fixturesDir, posRel))
	if err != nil {
		t.Fatal(err)
	}
	var posData FixtureData
	if err := json.Unmarshal(posBytes, &posData); err != nil {
		t.Fatal(err)
	}

	res, err := adapter.CommitWrite(ctx, storage.WriteRequest{
		OperationID: posData.OperationID,
		Manifest:    posData.Manifest,
		Payload:     []byte(posData.PayloadUTF8),
		Identity:    posData.Identity,
		Headers:     posData.Headers,
	})
	if err != nil {
		t.Fatalf("positive write failed: %v", err)
	}
	if res.Status != posExpected.Status || res.OperationID != posExpected.OperationID || res.SHA256 != posExpected.SHA256 || res.SizeBytes != posExpected.SizeBytes {
		t.Fatalf("unexpected positive write result: %+v, want %+v", res, posExpected)
	}

	// Verify durable blob on disk
	retrieved, rec, err := adapter.GetEvidence(posData.Manifest.CaseID, posData.Manifest.EvidenceID)
	if err != nil {
		t.Fatalf("failed to get committed evidence: %v", err)
	}
	if string(retrieved) != posData.PayloadUTF8 {
		t.Fatalf("retrieved bytes do not match committed payload")
	}
	if rec.SHA256 != posExpected.SHA256 {
		t.Fatalf("record sha256 mismatch")
	}

	// 4. Test Invalid / Negative Cases
	expectedErrors := map[string][]error{
		"invalid/missing-identity.json":      {storage.ErrMissingIdentity},
		"invalid/expired-identity.json":      {storage.ErrExpiredIdentity},
		"invalid/replayed-identity.json":     {storage.ErrReplayedIdentity, storage.ErrInvalidSignature},
		"invalid/scope-mismatch.json":        {storage.ErrScopeMismatch},
		"invalid/forged-signature.json":      {storage.ErrInvalidSignature},
		"invalid/unauthorized-role.json":     {storage.ErrUnauthorized},
		"invalid/widened-path.json":          {storage.ErrWidenedPath},
		"invalid/unavailable-provider.json":  {storage.ErrUnavailableProvider},
		"invalid/forged-header.json":         {storage.ErrForgedHeader},
		"invalid/corrupted-payload.json":     {storage.ErrDigestMismatch},
		"invalid/oversized-payload.json":     {storage.ErrPayloadTooLarge},
		"invalid/tampered-sealed-bytes.json": {storage.ErrSealedBytesImmutable},
	}

	initialState := adapter.CurrentState()

	for relPath, targetErrs := range expectedErrors {
		t.Run(relPath, func(t *testing.T) {
			fixBytes, err := os.ReadFile(filepath.Join(fixturesDir, relPath))
			if err != nil {
				t.Fatalf("failed to read fixture %s: %v", relPath, err)
			}
			var fixData FixtureData
			if err := json.Unmarshal(fixBytes, &fixData); err != nil {
				t.Fatalf("failed to unmarshal fixture %s: %v", relPath, err)
			}

			_, writeErr := adapter.CommitWrite(ctx, storage.WriteRequest{
				OperationID: fixData.OperationID,
				Manifest:    fixData.Manifest,
				Payload:     []byte(fixData.PayloadUTF8),
				Identity:    fixData.Identity,
				Headers:     fixData.Headers,
			})
			if writeErr == nil {
				t.Fatalf("expected error %v for %s, got nil", targetErrs, relPath)
			}
			matched := false
			for _, targetErr := range targetErrs {
				if errors.Is(writeErr, targetErr) {
					matched = true
					break
				}
			}
			if !matched {
				t.Fatalf("expected one of errors %v for %s, got %v", targetErrs, relPath, writeErr)
			}

			// Ensure state was NOT modified by failed sensitive action
			cur := adapter.CurrentState()
			if cur.Generation != initialState.Generation || cur.TotalBytes != initialState.TotalBytes {
				t.Fatalf("state was modified during rejected operation %s", relPath)
			}
		})
	}
}

func TestSingleWriterExclusivity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "c05-single-writer-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	w1, err := storage.Open(storage.Config{RootDir: tmpDir})
	if err != nil {
		t.Fatalf("failed to open writer 1: %v", err)
	}

	// Writer 2 attempt must fail with ErrLockBusy
	_, err = storage.Open(storage.Config{RootDir: tmpDir})
	if !errors.Is(err, storage.ErrLockBusy) {
		t.Fatalf("expected ErrLockBusy for writer 2, got: %v", err)
	}

	// Close writer 1, now writer 2 must succeed
	if err := w1.Close(); err != nil {
		t.Fatalf("failed to close writer 1: %v", err)
	}

	w2, err := storage.Open(storage.Config{RootDir: tmpDir})
	if err != nil {
		t.Fatalf("writer 2 failed to open after writer 1 closed: %v", err)
	}
	defer w2.Close()
}

func TestStableOperationIDsAndIdempotency(t *testing.T) {
	fixturesDir := getFixturesDir(t)
	posBytes, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "authoritative-write.json"))
	if err != nil {
		t.Fatal(err)
	}
	var posData FixtureData
	if err := json.Unmarshal(posBytes, &posData); err != nil {
		t.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "c05-idempotency-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	adapter, err := storage.Open(storage.Config{RootDir: tmpDir})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()

	ctx := context.Background()
	req := storage.WriteRequest{
		OperationID: posData.OperationID,
		Manifest:    posData.Manifest,
		Payload:     []byte(posData.PayloadUTF8),
		Identity:    posData.Identity,
	}

	// First commit
	firstRes, err := adapter.CommitWrite(ctx, req)
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if firstRes.IsReplay || firstRes.Status != "committed" {
		t.Fatalf("expected first write to be committed, got %+v", firstRes)
	}

	genAfterFirst := adapter.CurrentState().Generation

	// Replay write with same OperationID and same credentials
	replayRes, err := adapter.CommitWrite(ctx, req)
	if err != nil {
		t.Fatalf("replay write failed: %v", err)
	}
	if !replayRes.IsReplay || replayRes.Status != "replayed" {
		t.Fatalf("expected replay write to be marked is_replay=true, got %+v", replayRes)
	}
	if replayRes.SHA256 != firstRes.SHA256 || replayRes.CommittedAt != firstRes.CommittedAt {
		t.Fatalf("replay result did not preserve original commit metadata: %+v vs %+v", replayRes, firstRes)
	}

	// State generation must remain identical (no side effects)
	if adapter.CurrentState().Generation != genAfterFirst {
		t.Fatalf("manifest generation changed on replay: got %d, want %d", adapter.CurrentState().Generation, genAfterFirst)
	}

	// Replay attempt with missing identity must fail authentication (no information disclosure)
	unauthReq := req
	unauthReq.Identity = storage.Identity{}
	_, err = adapter.CommitWrite(ctx, unauthReq)
	if !errors.Is(err, storage.ErrMissingIdentity) {
		t.Fatalf("expected ErrMissingIdentity for unauthenticated replay attempt, got %v", err)
	}

	// Replay attempt with conflicting manifest parameters must be rejected
	conflictReq := req
	conflictReq.Manifest.EvidenceID = "ev-conflict-0002"
	_, err = adapter.CommitWrite(ctx, conflictReq)
	if err == nil {
		t.Fatalf("expected error for conflicting replay parameters, got nil")
	}
}

func TestInterruptedWriteAndOrphanRecovery(t *testing.T) {
	fixturesDir := getFixturesDir(t)
	posBytes, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "authoritative-write.json"))
	if err != nil {
		t.Fatal(err)
	}
	var posData FixtureData
	if err := json.Unmarshal(posBytes, &posData); err != nil {
		t.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "c05-interrupted-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Simulate interruption before manifest publication
	faultyAdapter, err := storage.Open(storage.Config{
		RootDir: tmpDir,
		Faults: storage.FaultInjection{
			FailBeforeManifestCommit: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	_, err = faultyAdapter.CommitWrite(ctx, storage.WriteRequest{
		OperationID: posData.OperationID,
		Manifest:    posData.Manifest,
		Payload:     []byte(posData.PayloadUTF8),
		Identity:    posData.Identity,
	})
	if !errors.Is(err, storage.ErrInterrupted) {
		t.Fatalf("expected ErrInterrupted, got: %v", err)
	}
	_ = faultyAdapter.Close()

	// Verify orphan staging file exists on disk
	stagingFiles, err := os.ReadDir(filepath.Join(tmpDir, storage.StagingDirName))
	if err != nil || len(stagingFiles) == 0 {
		t.Fatalf("expected orphan staging file before recovery, found none")
	}

	// 2. Open new adapter (recovers and cleans orphan staging)
	recoveredAdapter, err := storage.Open(storage.Config{RootDir: tmpDir})
	if err != nil {
		t.Fatalf("failed to open recovered adapter: %v", err)
	}
	defer recoveredAdapter.Close()

	// Verify orphan staging file was cleaned up
	remainingStaging, err := os.ReadDir(filepath.Join(tmpDir, storage.StagingDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(remainingStaging) != 0 {
		t.Fatalf("expected 0 staging files after recovery, got %d", len(remainingStaging))
	}

	// Verify uncommitted evidence is not in state
	if len(recoveredAdapter.CurrentState().Evidence) != 0 {
		t.Fatalf("uncommitted evidence was visible in recovered state")
	}
}

func TestDiskFullRecovery(t *testing.T) {
	fixturesDir := getFixturesDir(t)
	posBytes, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "authoritative-write.json"))
	if err != nil {
		t.Fatal(err)
	}
	var posData FixtureData
	if err := json.Unmarshal(posBytes, &posData); err != nil {
		t.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "c05-disk-full-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Simulate disk full
	adapter, err := storage.Open(storage.Config{
		RootDir: tmpDir,
		Faults: storage.FaultInjection{
			SimulateDiskFull: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	_, err = adapter.CommitWrite(ctx, storage.WriteRequest{
		OperationID: posData.OperationID,
		Manifest:    posData.Manifest,
		Payload:     []byte(posData.PayloadUTF8),
		Identity:    posData.Identity,
	})
	if !errors.Is(err, storage.ErrDiskFull) {
		t.Fatalf("expected ErrDiskFull, got: %v", err)
	}
	_ = adapter.Close()

	// Normal adapter works and state is clean
	normalAdapter, err := storage.Open(storage.Config{RootDir: tmpDir})
	if err != nil {
		t.Fatalf("failed to open normal adapter: %v", err)
	}
	defer normalAdapter.Close()

	if normalAdapter.CurrentState().Generation != 0 {
		t.Fatalf("state modified after failed disk full write")
	}
}

func TestMissingAndCorruptedReferenceDetection(t *testing.T) {
	fixturesDir := getFixturesDir(t)
	posBytes, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "authoritative-write.json"))
	if err != nil {
		t.Fatal(err)
	}
	var posData FixtureData
	if err := json.Unmarshal(posBytes, &posData); err != nil {
		t.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "c05-ref-integrity-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	adapter, err := storage.Open(storage.Config{RootDir: tmpDir})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	_, err = adapter.CommitWrite(ctx, storage.WriteRequest{
		OperationID: posData.OperationID,
		Manifest:    posData.Manifest,
		Payload:     []byte(posData.PayloadUTF8),
		Identity:    posData.Identity,
	})
	if err != nil {
		t.Fatal(err)
	}

	blobPath := filepath.Join(tmpDir, storage.BlobsDirName, posData.Manifest.SHA256)
	_ = adapter.Close()

	// Case 1: Corrupt blob content
	if err := os.WriteFile(blobPath, []byte("tampered data"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err = storage.Open(storage.Config{RootDir: tmpDir})
	if !errors.Is(err, storage.ErrCorruptedReference) {
		t.Fatalf("expected ErrCorruptedReference on startup, got %v", err)
	}

	// Case 2: Missing blob file
	if err := os.Remove(blobPath); err != nil {
		t.Fatal(err)
	}
	_, err = storage.Open(storage.Config{RootDir: tmpDir})
	if !errors.Is(err, storage.ErrMissingReference) {
		t.Fatalf("expected ErrMissingReference on startup, got %v", err)
	}
}

func TestCorruptedManifestDetection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "c05-manifest-corrupt-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Case 1: Corrupted JSON in manifest
	manifestPath := filepath.Join(tmpDir, storage.ManifestFileName)
	if err := os.WriteFile(manifestPath, []byte("NOT_VALID_JSON{"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err = storage.Open(storage.Config{RootDir: tmpDir})
	if !errors.Is(err, storage.ErrCorruptedManifest) {
		t.Fatalf("expected ErrCorruptedManifest for malformed JSON, got %v", err)
	}

	// Case 2: Unsupported schema version
	unsupportedVer := `{"schema_version":"99","generation":1,"committed_at":"2026-10-15T00:00:00Z","total_bytes":0,"operations":{},"evidence":{}}`
	if err := os.WriteFile(manifestPath, []byte(unsupportedVer), 0644); err != nil {
		t.Fatal(err)
	}
	_, err = storage.Open(storage.Config{RootDir: tmpDir})
	if !errors.Is(err, storage.ErrCorruptedManifest) {
		t.Fatalf("expected ErrCorruptedManifest for unsupported schema version, got %v", err)
	}
}

func TestWidenedPathTraversalRejection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "c05-widened-path-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	adapter, err := storage.Open(storage.Config{RootDir: tmpDir})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()

	ctx := context.Background()

	// OperationID path escape attempt
	_, err = adapter.CommitWrite(ctx, storage.WriteRequest{
		OperationID: "../../escape-op",
	})
	if !errors.Is(err, storage.ErrWidenedPath) {
		t.Fatalf("expected ErrWidenedPath for escaping OperationID, got %v", err)
	}

	// CaseID path escape attempt
	_, _, err = adapter.GetEvidence("../escape-case", "ev-001")
	if !errors.Is(err, storage.ErrWidenedPath) {
		t.Fatalf("expected ErrWidenedPath for escaping CaseID in GetEvidence, got %v", err)
	}
}

func TestBoundedStorageLimits(t *testing.T) {
	fixturesDir := getFixturesDir(t)
	posBytes, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "authoritative-write.json"))
	if err != nil {
		t.Fatal(err)
	}
	var posData FixtureData
	if err := json.Unmarshal(posBytes, &posData); err != nil {
		t.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "c05-bounded-storage-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// MaxStorageBytes is set lower than payload size (417 bytes)
	adapter, err := storage.Open(storage.Config{
		RootDir:         tmpDir,
		MaxStorageBytes: 100, // lower than 417
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()

	ctx := context.Background()
	_, err = adapter.CommitWrite(ctx, storage.WriteRequest{
		OperationID: posData.OperationID,
		Manifest:    posData.Manifest,
		Payload:     []byte(posData.PayloadUTF8),
		Identity:    posData.Identity,
	})
	if !errors.Is(err, storage.ErrStorageQuotaExceeded) {
		t.Fatalf("expected ErrStorageQuotaExceeded, got: %v", err)
	}
}

func TestProjectionRebuild(t *testing.T) {
	fixturesDir := getFixturesDir(t)
	posBytes, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "authoritative-write.json"))
	if err != nil {
		t.Fatal(err)
	}
	var posData FixtureData
	if err := json.Unmarshal(posBytes, &posData); err != nil {
		t.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "c05-projection-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	adapter, err := storage.Open(storage.Config{RootDir: tmpDir})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()

	ctx := context.Background()
	_, err = adapter.CommitWrite(ctx, storage.WriteRequest{
		OperationID: posData.OperationID,
		Manifest:    posData.Manifest,
		Payload:     []byte(posData.PayloadUTF8),
		Identity:    posData.Identity,
	})
	if err != nil {
		t.Fatal(err)
	}

	proj, err := adapter.RebuildProjection()
	if err != nil {
		t.Fatalf("failed to rebuild projection: %v", err)
	}
	if proj.TotalCases != 1 || proj.TotalEvidence != 1 || proj.TotalBytes != posData.Manifest.SizeBytes {
		t.Fatalf("unexpected projection state: %+v", proj)
	}
	caseProj, ok := proj.Cases[posData.Manifest.CaseID]
	if !ok || caseProj.EvidenceCount != 1 || len(caseProj.EvidenceIDs) != 1 || caseProj.EvidenceIDs[0] != posData.Manifest.EvidenceID {
		t.Fatalf("unexpected case projection: %+v", caseProj)
	}
}

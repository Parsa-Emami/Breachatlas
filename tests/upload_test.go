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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/cases"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/storage"
)

type C08PositiveFixture struct {
	SchemaVersion  string `json:"schema_version"`
	UploadID       string `json:"upload_id"`
	CaseID         string `json:"case_id"`
	EvidenceID     string `json:"evidence_id"`
	MediaType      string `json:"media_type"`
	Filename       string `json:"filename"`
	PayloadUTF8    string `json:"payload_utf8"`
	ExpectedSize   int64  `json:"expected_size"`
	ExpectedSHA256 string `json:"expected_sha256"`
	ExpectedStatus string `json:"expected_status"`
	ExpectedSealed bool   `json:"expected_sealed"`
}

type C08SimpleNegativeFixture struct {
	SchemaVersion string `json:"schema_version"`
	UploadID      string `json:"upload_id"`
	CaseID        string `json:"case_id"`
	EvidenceID    string `json:"evidence_id"`
	MediaType     string `json:"media_type"`
	Filename      string `json:"filename"`
	PayloadUTF8   string `json:"payload_utf8"`
	MaxBytes      int64  `json:"max_bytes"`
	StreamBytes   int64  `json:"stream_bytes"`
	ExpectedError string `json:"expected_error"`
}

type C08InterruptedFixture struct {
	SchemaVersion     string `json:"schema_version"`
	PriorValidUpload  struct {
		SchemaVersion string `json:"schema_version"`
		UploadID      string `json:"upload_id"`
		CaseID        string `json:"case_id"`
		EvidenceID    string `json:"evidence_id"`
		MediaType     string `json:"media_type"`
		Filename      string `json:"filename"`
		PayloadUTF8   string `json:"payload_utf8"`
	} `json:"prior_valid_upload"`
	InterruptedUpload struct {
		SchemaVersion       string `json:"schema_version"`
		UploadID            string `json:"upload_id"`
		CaseID              string `json:"case_id"`
		EvidenceID          string `json:"evidence_id"`
		MediaType           string `json:"media_type"`
		Filename            string `json:"filename"`
		PayloadUTF8         string `json:"payload_utf8"`
		InterruptAfterBytes int    `json:"interrupt_after_bytes"`
	} `json:"interrupted_upload"`
}

type failingAfterNReader struct {
	data      []byte
	offset    int
	failAfter int
	err       error
}

func (r *failingAfterNReader) Read(p []byte) (int, error) {
	if r.offset >= r.failAfter {
		return 0, r.err
	}
	remainingAllowed := r.failAfter - r.offset
	limit := len(p)
	if limit > remainingAllowed {
		limit = remainingAllowed
	}
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p[:limit], r.data[r.offset:])
	r.offset += n
	if r.offset >= r.failAfter {
		return n, r.err
	}
	return n, nil
}

type countingZeroReader struct {
	totalBytes int64
	bytesRead  int64
}

func (r *countingZeroReader) Read(p []byte) (int, error) {
	if r.bytesRead >= r.totalBytes {
		return 0, io.EOF
	}
	rem := r.totalBytes - r.bytesRead
	n := len(p)
	if int64(n) > rem {
		n = int(rem)
	}
	for i := 0; i < n; i++ {
		p[i] = 'A'
	}
	r.bytesRead += int64(n)
	return n, nil
}

func getC08FixturesDir(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{
		filepath.Join("..", "tests", "fixtures", "breachatlas", "C08"),
		filepath.Join("fixtures", "breachatlas", "C08"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	t.Fatalf("could not locate C08 fixtures directory")
	return ""
}

func makeUploadTestIdentity(t *testing.T, opID, caseID, evidenceID, shaHex string) storage.Identity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339)
	msg := storage.CanonicalSigningBytes(opID, caseID, evidenceID, shaHex, exp)
	sig := ed25519.Sign(priv, msg)
	return storage.Identity{
		Principal: "analyst-c08",
		Role:      "analyst",
		CaseScope: caseID,
		PublicKey: hex.EncodeToString(pub),
		ExpiresAt: exp,
		Signature: hex.EncodeToString(sig),
		Provider:  "local",
	}
}

func TestC08FixturesAndUploadInvariants(t *testing.T) {
	fixturesDir := getC08FixturesDir(t)

	// 1. Verify provenance & Apache-2.0 checksums
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
	storeDir := filepath.Join(rootTmp, "storage")

	adapter, err := storage.Open(storage.Config{RootDir: storeDir, SyncDir: true})
	if err != nil {
		t.Fatalf("open storage adapter: %v", err)
	}
	defer adapter.Close()

	reg, err := cases.NewRegistry(adapter)
	if err != nil {
		t.Fatalf("new case registry: %v", err)
	}
	if _, err := reg.CreateCase(cases.CreateCaseInput{
		CaseID:         "case-2026-001",
		Title:          "C08 Quarantine Streaming Case",
		Classification: "confidential",
		Owner:          "analyst-c08",
		Provider:       "local",
	}); err != nil {
		t.Fatalf("create case: %v", err)
	}

	isSealed := func(caseID, evidenceID string) (bool, error) {
		state := adapter.CurrentState()
		_, exists := state.Evidence[caseID+"/"+evidenceID]
		return exists, nil
	}

	// 2. Positive streaming upload into quarantine (never sealed by upload alone)
	posRaw, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "streaming-upload.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pos C08PositiveFixture
	if err := json.Unmarshal(posRaw, &pos); err != nil {
		t.Fatal(err)
	}

	cfg := evidence.UploadConfig{
		QuarantineDir: quarantineDir,
		BufferSize:    16, // force multi-chunk streaming
		SyncDir:       true,
		IsSealed:      isSealed,
	}

	qItem, err := evidence.StreamIntoQuarantine(context.Background(), cfg, evidence.UploadRequest{
		SchemaVersion: pos.SchemaVersion,
		UploadID:      pos.UploadID,
		CaseID:        pos.CaseID,
		EvidenceID:    pos.EvidenceID,
		MediaType:     pos.MediaType,
		Filename:      pos.Filename,
		ExpectedSize:  &pos.ExpectedSize,
		Body:          strings.NewReader(pos.PayloadUTF8),
	})
	if err != nil {
		t.Fatalf("positive streaming upload failed: %v", err)
	}
	if qItem.Sealed != pos.ExpectedSealed || qItem.Sealed {
		t.Fatalf("quarantined upload must never appear sealed, got Sealed=%v", qItem.Sealed)
	}
	if string(qItem.Status) != pos.ExpectedStatus {
		t.Fatalf("unexpected status: got %q, want %q", qItem.Status, pos.ExpectedStatus)
	}
	if qItem.SizeBytes != pos.ExpectedSize || qItem.SHA256 != pos.ExpectedSHA256 {
		t.Fatalf("digest/size mismatch: got (%d, %s), want (%d, %s)", qItem.SizeBytes, qItem.SHA256, pos.ExpectedSize, pos.ExpectedSHA256)
	}

	// Verify quarantined file bytes on disk
	qBytes, err := os.ReadFile(filepath.Join(quarantineDir, qItem.QuarantinePath))
	if err != nil || !bytes.Equal(qBytes, []byte(pos.PayloadUTF8)) {
		t.Fatalf("quarantined payload mismatch (err=%v)", err)
	}

	// Verify quarantined upload is NOT yet sealed in cases.Registry / storage.Adapter
	if _, _, err := reg.GetEvidence(pos.CaseID, pos.EvidenceID); !errors.Is(err, cases.ErrEvidenceNotFound) {
		t.Fatalf("quarantined evidence must not be sealed in registry yet, got err=%v", err)
	}

	// 3. Negative case: Malformed upload
	t.Run("MalformedUploadRejected", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "malformed-upload.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx C08SimpleNegativeFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		_, err = evidence.StreamIntoQuarantine(context.Background(), cfg, evidence.UploadRequest{
			SchemaVersion: fx.SchemaVersion,
			UploadID:      fx.UploadID,
			CaseID:        fx.CaseID,
			EvidenceID:    fx.EvidenceID,
			MediaType:     fx.MediaType,
			Filename:      fx.Filename,
			Body:          strings.NewReader(fx.PayloadUTF8),
		})
		if !errors.Is(err, evidence.ErrMalformedUpload) {
			t.Fatalf("expected ErrMalformedUpload, got %v", err)
		}
	})

	// 4. Negative case: Unsupported schema version
	t.Run("UnsupportedVersionRejected", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "unsupported-version.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx C08SimpleNegativeFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		_, err = evidence.StreamIntoQuarantine(context.Background(), cfg, evidence.UploadRequest{
			SchemaVersion: fx.SchemaVersion,
			UploadID:      fx.UploadID,
			CaseID:        fx.CaseID,
			EvidenceID:    fx.EvidenceID,
			MediaType:     fx.MediaType,
			Filename:      fx.Filename,
			Body:          strings.NewReader(fx.PayloadUTF8),
		})
		if !errors.Is(err, evidence.ErrUnsupportedVersion) {
			t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
		}
	})

	// 5. Negative case: Oversized upload aborts mid-stream and never appears sealed
	t.Run("OversizedStreamRejectedBeforeCompletion", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "oversized-upload.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx C08SimpleNegativeFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		boundedCfg := cfg
		boundedCfg.MaxBytes = fx.MaxBytes
		reader := &countingZeroReader{totalBytes: fx.StreamBytes}

		item, err := evidence.StreamIntoQuarantine(context.Background(), boundedCfg, evidence.UploadRequest{
			SchemaVersion: fx.SchemaVersion,
			UploadID:      fx.UploadID,
			CaseID:        fx.CaseID,
			EvidenceID:    fx.EvidenceID,
			MediaType:     fx.MediaType,
			Filename:      fx.Filename,
			Body:          reader,
		})
		if !errors.Is(err, evidence.ErrUploadTooLarge) {
			t.Fatalf("expected ErrUploadTooLarge, got %v", err)
		}
		if item != nil {
			t.Fatalf("expected nil result on oversized upload")
		}
		if reader.bytesRead >= fx.StreamBytes {
			t.Fatalf("expected streaming abort before draining full %d bytes, read %d", fx.StreamBytes, reader.bytesRead)
		}
		// Ensure no quarantine files or sealed evidence exist for the rejected UploadID
		completed, incomplete, err := evidence.InspectQuarantine(quarantineDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(incomplete) != 0 {
			t.Fatalf("expected no leftover incomplete artifacts after clean rejection, got %v", incomplete)
		}
		for _, c := range completed {
			if c.UploadID == fx.UploadID || c.Sealed {
				t.Fatalf("rejected oversized upload appeared in quarantine/sealed state: %+v", c)
			}
		}
	})

	// 6. Negative case: Traversal and symlink rejection
	t.Run("TraversalAndSymlinkRejected", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "traversal-symlink.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx C08SimpleNegativeFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		_, err = evidence.StreamIntoQuarantine(context.Background(), cfg, evidence.UploadRequest{
			SchemaVersion: fx.SchemaVersion,
			UploadID:      fx.UploadID,
			CaseID:        fx.CaseID,
			EvidenceID:    fx.EvidenceID,
			MediaType:     fx.MediaType,
			Filename:      fx.Filename,
			Body:          strings.NewReader(fx.PayloadUTF8),
		})
		if !errors.Is(err, evidence.ErrPathTraversal) {
			t.Fatalf("expected ErrPathTraversal for traversal evidence_id, got %v", err)
		}

		// Also verify Filename traversal alone is rejected
		_, err = evidence.StreamIntoQuarantine(context.Background(), cfg, evidence.UploadRequest{
			SchemaVersion: "1",
			UploadID:      fx.UploadID,
			CaseID:        fx.CaseID,
			EvidenceID:    "ev-2026-0096",
			MediaType:     fx.MediaType,
			Filename:      fx.Filename,
			Body:          strings.NewReader(fx.PayloadUTF8),
		})
		if !errors.Is(err, evidence.ErrPathTraversal) {
			t.Fatalf("expected ErrPathTraversal for traversal filename, got %v", err)
		}

		// Symlink quarantine directory must be rejected
		symRoot := t.TempDir()
		realTarget := filepath.Join(symRoot, "real-target")
		if err := os.MkdirAll(realTarget, 0750); err != nil {
			t.Fatal(err)
		}
		symQuarantine := filepath.Join(symRoot, "sym-quarantine")
		if err := os.Symlink(realTarget, symQuarantine); err != nil {
			t.Fatal(err)
		}
		_, err = evidence.StreamIntoQuarantine(context.Background(), evidence.UploadConfig{
			QuarantineDir: symQuarantine,
		}, evidence.UploadRequest{
			SchemaVersion: "1",
			UploadID:      "upl-sym-dir",
			CaseID:        "case-2026-001",
			EvidenceID:    "ev-2026-0095",
			MediaType:     "text/plain",
			Body:          strings.NewReader("symlink quarantine test"),
		})
		if !errors.Is(err, evidence.ErrSymlinkRejected) {
			t.Fatalf("expected ErrSymlinkRejected for symlink quarantine dir, got %v", err)
		}

		// Symlink source file in StreamFileIntoQuarantine must be rejected
		realSrc := filepath.Join(symRoot, "source.log")
		if err := os.WriteFile(realSrc, []byte("secret bytes"), 0600); err != nil {
			t.Fatal(err)
		}
		symSrc := filepath.Join(symRoot, "source-link.log")
		if err := os.Symlink(realSrc, symSrc); err != nil {
			t.Fatal(err)
		}
		_, err = evidence.StreamFileIntoQuarantine(context.Background(), cfg, evidence.UploadRequest{
			SchemaVersion: "1",
			UploadID:      "upl-sym-src",
			CaseID:        "case-2026-001",
			EvidenceID:    "ev-2026-0094",
			MediaType:     "text/plain",
		}, symSrc)
		if !errors.Is(err, evidence.ErrSymlinkRejected) {
			t.Fatalf("expected ErrSymlinkRejected for symlink source file, got %v", err)
		}
	})

	// 7. Negative case: Interrupt and repeat; prior valid data preserved & orphan incomplete never looks sealed
	t.Run("InterruptedUploadAndRepeatPreservesPriorValid", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "interrupted-upload.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx C08InterruptedFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}

		intQuarantine := filepath.Join(t.TempDir(), "quarantine")
		intCfg := evidence.UploadConfig{
			QuarantineDir: intQuarantine,
			BufferSize:    8,
			SyncDir:       true,
			IsSealed:      isSealed,
		}

		prior := fx.PriorValidUpload
		priorRes, err := evidence.StreamIntoQuarantine(context.Background(), intCfg, evidence.UploadRequest{
			SchemaVersion: prior.SchemaVersion,
			UploadID:      prior.UploadID,
			CaseID:        prior.CaseID,
			EvidenceID:    prior.EvidenceID,
			MediaType:     prior.MediaType,
			Filename:      prior.Filename,
			Body:          strings.NewReader(prior.PayloadUTF8),
		})
		if err != nil {
			t.Fatalf("prior valid upload failed: %v", err)
		}

		// Simulate mid-stream I/O interruption
		inter := fx.InterruptedUpload
		failReader := &failingAfterNReader{
			data:      []byte(inter.PayloadUTF8),
			failAfter: inter.InterruptAfterBytes,
			err:       errors.New("connection reset mid-stream"),
		}
		if _, err := evidence.StreamIntoQuarantine(context.Background(), intCfg, evidence.UploadRequest{
			SchemaVersion: inter.SchemaVersion,
			UploadID:      inter.UploadID,
			CaseID:        inter.CaseID,
			EvidenceID:    inter.EvidenceID,
			MediaType:     inter.MediaType,
			Filename:      inter.Filename,
			Body:          failReader,
		}); !errors.Is(err, evidence.ErrUploadInterrupted) {
			t.Fatalf("expected ErrUploadInterrupted on I/O failure, got %v", err)
		}

		// Also verify cancelled context aborts cleanly
		cancelCtx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := evidence.StreamIntoQuarantine(cancelCtx, intCfg, evidence.UploadRequest{
			SchemaVersion: inter.SchemaVersion,
			UploadID:      inter.UploadID,
			CaseID:        inter.CaseID,
			EvidenceID:    inter.EvidenceID,
			MediaType:     inter.MediaType,
			Filename:      inter.Filename,
			Body:          strings.NewReader(inter.PayloadUTF8),
		}); !errors.Is(err, evidence.ErrUploadInterrupted) {
			t.Fatalf("expected ErrUploadInterrupted on cancelled ctx, got %v", err)
		}

		// Simulate abrupt crash leaving an orphan .part file on disk
		orphanPart := filepath.Join(intQuarantine, inter.CaseID, inter.UploadID+".part")
		if err := os.WriteFile(orphanPart, []byte(inter.PayloadUTF8[:inter.InterruptAfterBytes]), 0600); err != nil {
			t.Fatal(err)
		}

		completed, incomplete, err := evidence.InspectQuarantine(intQuarantine)
		if err != nil {
			t.Fatal(err)
		}
		if len(completed) != 1 || completed[0].UploadID != prior.UploadID || completed[0].Sealed {
			t.Fatalf("expected only prior valid unsealed upload in completed, got %+v", completed)
		}
		if len(incomplete) != 1 || !strings.HasSuffix(incomplete[0], ".part") {
			t.Fatalf("expected orphan .part in incomplete list, got %v", incomplete)
		}

		// Repeat the interrupted import cleanly; stale .part is replaced and prior valid data remains intact
		retried, err := evidence.StreamIntoQuarantine(context.Background(), intCfg, evidence.UploadRequest{
			SchemaVersion: inter.SchemaVersion,
			UploadID:      inter.UploadID,
			CaseID:        inter.CaseID,
			EvidenceID:    inter.EvidenceID,
			MediaType:     inter.MediaType,
			Filename:      inter.Filename,
			Body:          strings.NewReader(inter.PayloadUTF8),
		})
		if err != nil {
			t.Fatalf("retry upload after interruption failed: %v", err)
		}
		if retried.Sealed || retried.Status != evidence.StatusQuarantined {
			t.Fatalf("retried upload must be quarantined and unsealed, got %+v", retried)
		}

		completedAfter, incompleteAfter, err := evidence.InspectQuarantine(intQuarantine)
		if err != nil {
			t.Fatal(err)
		}
		if len(completedAfter) != 2 || len(incompleteAfter) != 0 {
			t.Fatalf("expected 2 completed and 0 incomplete after retry, got completed=%d incomplete=%v", len(completedAfter), incompleteAfter)
		}
		priorDiskBytes, err := os.ReadFile(filepath.Join(intQuarantine, priorRes.QuarantinePath))
		if err != nil || string(priorDiskBytes) != prior.PayloadUTF8 {
			t.Fatalf("prior valid upload bytes modified after interrupted retry (err=%v)", err)
		}
	})

	// 8. Negative case: Sealed source bytes never modified
	t.Run("SealedSourceBytesNeverModified", func(t *testing.T) {
		sealedBytes := []byte("immutable-sealed-source-payload-v1\n")
		h := sha256.Sum256(sealedBytes)
		sealedSHA := hex.EncodeToString(h[:])
		opID := "op-seal-c08-001"
		manifest := evidence.Manifest{
			SchemaVersion: "1",
			CaseID:        "case-2026-001",
			EvidenceID:    "ev-sealed-c08",
			SHA256:        sealedSHA,
			SizeBytes:     int64(len(sealedBytes)),
			MediaType:     "text/plain",
			AcquiredAt:    "2026-11-11T08:10:00Z",
			CustodyRoot:   sealedSHA,
		}
		if _, err := reg.RegisterEvidence(context.Background(), cases.RegisterEvidenceRequest{
			OperationID: opID,
			Manifest:    manifest,
			Payload:     sealedBytes,
			Identity:    makeUploadTestIdentity(t, opID, manifest.CaseID, manifest.EvidenceID, sealedSHA),
		}); err != nil {
			t.Fatalf("seal initial evidence: %v", err)
		}

		// Attempting to stream new bytes for already-sealed EvidenceID must fail closed
		_, err := evidence.StreamIntoQuarantine(context.Background(), cfg, evidence.UploadRequest{
			SchemaVersion: "1",
			UploadID:      "upl-overwrite-sealed",
			CaseID:        "case-2026-001",
			EvidenceID:    "ev-sealed-c08",
			MediaType:     "text/plain",
			Body:          strings.NewReader("tampered-payload"),
		})
		if !errors.Is(err, evidence.ErrSealedBytesImmutable) {
			t.Fatalf("expected ErrSealedBytesImmutable, got %v", err)
		}

		gotSealed, item, err := reg.GetEvidence("case-2026-001", "ev-sealed-c08")
		if err != nil || !item.Sealed || !bytes.Equal(gotSealed, sealedBytes) {
			t.Fatalf("sealed source bytes were altered or unreadable (err=%v, item=%+v)", err, item)
		}
	})
}

func TestUploadDigestSizeMismatchAndCleanup(t *testing.T) {
	qDir := filepath.Join(t.TempDir(), "quarantine")
	cfg := evidence.UploadConfig{QuarantineDir: qDir, BufferSize: 8}

	wrongSize := int64(999)
	if _, err := evidence.StreamIntoQuarantine(context.Background(), cfg, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-size-mismatch",
		CaseID:        "case-2026-001",
		EvidenceID:    "ev-size-mismatch",
		MediaType:     "text/plain",
		ExpectedSize:  &wrongSize,
		Body:          strings.NewReader("short payload"),
	}); !errors.Is(err, evidence.ErrSizeMismatch) {
		t.Fatalf("expected ErrSizeMismatch, got %v", err)
	}

	if _, err := evidence.StreamIntoQuarantine(context.Background(), cfg, evidence.UploadRequest{
		SchemaVersion:  "1",
		UploadID:       "upl-digest-mismatch",
		CaseID:         "case-2026-001",
		EvidenceID:     "ev-digest-mismatch",
		MediaType:      "text/plain",
		ExpectedSHA256: strings.Repeat("0", 64),
		Body:           strings.NewReader("actual bytes"),
	}); !errors.Is(err, evidence.ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch, got %v", err)
	}

	// Verify orphan cleanup removes .part / .meta.tmp cleanly
	orphanDir := filepath.Join(qDir, "case-2026-001")
	if err := os.MkdirAll(orphanDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphanDir, "stale.part"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	removed, err := evidence.CleanupIncomplete(qDir)
	if err != nil || removed != 1 {
		t.Fatalf("expected CleanupIncomplete to remove 1 file, got removed=%d err=%v", removed, err)
	}
}

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

	"github.com/Parsa-Emami/Breachatlas/internal/cases"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/storage"
)

type C09PositiveFixture struct {
	SchemaVersion       string `json:"schema_version"`
	OperationID         string `json:"operation_id"`
	UploadID            string `json:"upload_id"`
	CaseID              string `json:"case_id"`
	EvidenceID          string `json:"evidence_id"`
	MediaType           string `json:"media_type"`
	Filename            string `json:"filename"`
	AcquiredAt          string `json:"acquired_at"`
	CustodyRoot         string `json:"custody_root"`
	PayloadUTF8         string `json:"payload_utf8"`
	ExpectedSize        int64  `json:"expected_size"`
	ExpectedSHA256      string `json:"expected_sha256"`
	ExpectedBlobRelPath string `json:"expected_blob_rel_path"`
}

type C09MismatchFixture struct {
	OperationID               string `json:"operation_id"`
	UploadID                  string `json:"upload_id"`
	CaseID                    string `json:"case_id"`
	EvidenceID                string `json:"evidence_id"`
	MediaType                 string `json:"media_type"`
	Filename                  string `json:"filename"`
	AcquiredAt                string `json:"acquired_at"`
	CustodyRoot               string `json:"custody_root"`
	PayloadUTF8               string `json:"payload_utf8"`
	CorruptQuarantineByteIdx  int    `json:"corrupt_quarantine_byte_index"`
}

type C09BoundaryFixture struct {
	OperationID    string `json:"operation_id"`
	UploadID       string `json:"upload_id"`
	CaseID         string `json:"case_id"`
	EvidenceID     string `json:"evidence_id"`
	MediaType      string `json:"media_type"`
	Filename       string `json:"filename"`
	AcquiredAt     string `json:"acquired_at"`
	CustodyRoot    string `json:"custody_root"`
	PayloadUTF8    string `json:"payload_utf8"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

type C09ReplayQuotaFixture struct {
	OperationID        string `json:"operation_id"`
	ConflictOpID       string `json:"conflict_operation_id"`
	QuotaOpID          string `json:"quota_operation_id"`
	DiskFullOpID       string `json:"disk_full_operation_id"`
	CaseID             string `json:"case_id"`
	ConflictEvidenceID string `json:"conflict_evidence_id"`
	QuotaEvidenceID    string `json:"quota_evidence_id"`
	DiskFullEvidenceID string `json:"disk_full_evidence_id"`
	MaxStorageBytes    int64  `json:"max_storage_bytes"`
	MaxRetries         int    `json:"max_retries"`
	ExcessiveAttempt   int    `json:"excessive_attempt"`
}

type C09ImmutableFixture struct {
	OperationID string `json:"operation_id"`
	UploadID    string `json:"upload_id"`
	CaseID      string `json:"case_id"`
	EvidenceID  string `json:"evidence_id"`
	MediaType   string `json:"media_type"`
	Filename    string `json:"filename"`
	AcquiredAt  string `json:"acquired_at"`
	CustodyRoot string `json:"custody_root"`
	PayloadUTF8 string `json:"payload_utf8"`
}

func getC09FixturesDir(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{
		filepath.Join("..", "tests", "fixtures", "breachatlas", "C09"),
		filepath.Join("fixtures", "breachatlas", "C09"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	t.Fatalf("could not locate C09 fixtures directory")
	return ""
}

func TestC09FixturesAndSealingInvariants(t *testing.T) {
	fixturesDir := getC09FixturesDir(t)

	// 1. Verify C09 provenance & Apache-2.0 hashes
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
	storageDir := filepath.Join(rootTmp, "storage")

	qCfg := evidence.UploadConfig{QuarantineDir: quarantineDir, BufferSize: 16, SyncDir: true}
	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		MaxRetries:    2,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("open seal store: %v", err)
	}

	// 2. Positive flow: quarantine -> durable content-addressed blob -> atomic manifest seal + cases integration
	posRaw, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "content-addressed-seal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pos C09PositiveFixture
	if err := json.Unmarshal(posRaw, &pos); err != nil {
		t.Fatal(err)
	}

	quarantined, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
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
		t.Fatalf("quarantine upload: %v", err)
	}
	if quarantined.Sealed {
		t.Fatalf("quarantined upload should not be sealed prior to SealQuarantined")
	}

	sealedManifest, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
		OperationID:    pos.OperationID,
		Quarantined:    quarantined,
		ExpectedSHA256: pos.ExpectedSHA256,
		AcquiredAt:     pos.AcquiredAt,
		CustodyRoot:    pos.CustodyRoot,
	})
	if err != nil {
		t.Fatalf("SealQuarantined failed: %v", err)
	}
	if !sealedManifest.Sealed || sealedManifest.Generation != 1 || sealedManifest.SHA256 != pos.ExpectedSHA256 {
		t.Fatalf("unexpected sealed manifest: %+v", sealedManifest)
	}
	if sealedManifest.BlobRelPath != pos.ExpectedBlobRelPath {
		t.Fatalf("blob_rel_path mismatch: got %q, want %q", sealedManifest.BlobRelPath, pos.ExpectedBlobRelPath)
	}
	blobDiskBytes, err := os.ReadFile(filepath.Join(sealDir, sealedManifest.BlobRelPath))
	if err != nil || !bytes.Equal(blobDiskBytes, []byte(pos.PayloadUTF8)) {
		t.Fatalf("sealed blob bytes mismatch on disk (err=%v)", err)
	}

	// Also confirm integration with storage.Adapter & cases.Registry
	adapter, err := storage.Open(storage.Config{RootDir: storageDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	reg, err := cases.NewRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.CreateCase(cases.CreateCaseInput{
		CaseID:         pos.CaseID,
		Title:          "C09 Domain Controller Seal Case",
		Classification: "confidential",
		Owner:          "analyst-c08",
		Provider:       "local",
	}); err != nil {
		t.Fatal(err)
	}
	manifest := quarantined.ToManifest(pos.AcquiredAt, pos.CustodyRoot)
	if _, err := reg.RegisterEvidence(context.Background(), cases.RegisterEvidenceRequest{
		OperationID: pos.OperationID,
		Manifest:    manifest,
		Payload:     blobDiskBytes,
		Identity:    makeUploadTestIdentity(t, pos.OperationID, pos.CaseID, pos.EvidenceID, pos.ExpectedSHA256),
	}); err != nil {
		t.Fatalf("register sealed evidence into case registry: %v", err)
	}

	// 3. Negative case: hash mismatch aborts cleanly without creating blob or manifest
	t.Run("HashMismatchAbortsBeforeSeal", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "hash-mismatch.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx C09MismatchFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		qTampered, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
			SchemaVersion: "1",
			UploadID:      fx.UploadID,
			CaseID:        fx.CaseID,
			EvidenceID:    fx.EvidenceID,
			MediaType:     fx.MediaType,
			Filename:      fx.Filename,
			Body:          strings.NewReader(fx.PayloadUTF8),
		})
		if err != nil {
			t.Fatal(err)
		}
		tamperPath := filepath.Join(quarantineDir, qTampered.QuarantinePath)
		content, err := os.ReadFile(tamperPath)
		if err != nil {
			t.Fatal(err)
		}
		content[fx.CorruptQuarantineByteIdx] ^= 0xFF
		if err := os.WriteFile(tamperPath, content, 0600); err != nil {
			t.Fatal(err)
		}

		if _, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
			OperationID: fx.OperationID,
			Quarantined: qTampered,
			AcquiredAt:  fx.AcquiredAt,
			CustodyRoot: fx.CustodyRoot,
		}); !errors.Is(err, evidence.ErrDigestMismatch) {
			t.Fatalf("expected ErrDigestMismatch, got %v", err)
		}
		if _, err := sealStore.GetSealedManifest(fx.CaseID, fx.EvidenceID); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("mismatched manifest must not be committed, got err=%v", err)
		}
		corruptSum := sha256.Sum256(content)
		if _, err := os.Stat(filepath.Join(sealDir, "blobs", "sha256", hex.EncodeToString(corruptSum[:]))); !os.IsNotExist(err) {
			t.Fatalf("mismatched bytes must not exist in blobs/sha256")
		}
	})

	// 4. Negative case: kill writer at staged-byte/manifest boundary, restart exposes only prior state, orphan recovery cleans up
	t.Run("BoundaryCrashOrphanRecoveryAndRestart", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "boundary-crash-orphan.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx C09BoundaryFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}

		qCrash, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
			SchemaVersion: "1",
			UploadID:      fx.UploadID,
			CaseID:        fx.CaseID,
			EvidenceID:    fx.EvidenceID,
			MediaType:     fx.MediaType,
			Filename:      fx.Filename,
			Body:          strings.NewReader(fx.PayloadUTF8),
		})
		if err != nil {
			t.Fatal(err)
		}

		// Reopen sealStore with boundary fault enabled
		if err := sealStore.Close(); err != nil {
			t.Fatal(err)
		}
		faultStore, err := evidence.OpenSealStore(evidence.SealConfig{
			RootDir:       sealDir,
			QuarantineDir: quarantineDir,
			MaxRetries:    2,
			SyncDir:       true,
			Faults:        evidence.SealFaults{FailAfterBlobSyncBeforeManifest: true},
		})
		if err != nil {
			t.Fatal(err)
		}

		if _, err := faultStore.SealQuarantined(context.Background(), evidence.SealRequest{
			OperationID:    fx.OperationID,
			Quarantined:    qCrash,
			ExpectedSHA256: fx.ExpectedSHA256,
			AcquiredAt:     fx.AcquiredAt,
			CustodyRoot:    fx.CustodyRoot,
		}); !errors.Is(err, evidence.ErrSealInterrupted) {
			t.Fatalf("expected ErrSealInterrupted at boundary, got %v", err)
		}
		if err := faultStore.Close(); err != nil {
			t.Fatal(err)
		}

		// Blob IS durable on disk before manifest commit
		orphanBlobPath := filepath.Join(sealDir, "blobs", "sha256", fx.ExpectedSHA256)
		if _, err := os.Stat(orphanBlobPath); err != nil {
			t.Fatalf("expected durable blob at boundary before manifest seal: %v", err)
		}

		// Restart cleanly: only prior authoritative manifest (ev-c09-0001) is exposed!
		restarted, err := evidence.OpenSealStore(evidence.SealConfig{
			RootDir:       sealDir,
			QuarantineDir: quarantineDir,
			MaxRetries:    2,
			SyncDir:       true,
		})
		if err != nil {
			t.Fatalf("restart seal store: %v", err)
		}
		sealStore = restarted

		if _, err := sealStore.GetSealedManifest(pos.CaseID, pos.EvidenceID); err != nil {
			t.Fatalf("prior committed manifest lost across crash/restart: %v", err)
		}
		if _, err := sealStore.GetSealedManifest(fx.CaseID, fx.EvidenceID); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("crashed uncommitted manifest should not appear sealed after restart, got err=%v", err)
		}

		// Orphan recovery detects uncommitted blob and reclaims it without harming prior committed blob
		reportInspect, err := sealStore.RecoverOrphans(false)
		if err != nil {
			t.Fatal(err)
		}
		if len(reportInspect.OrphanBlobs) != 1 || reportInspect.OrphanBlobs[0] != fx.ExpectedSHA256 {
			t.Fatalf("expected orphan blob %s reported, got %+v", fx.ExpectedSHA256, reportInspect)
		}
		reportReclaim, err := sealStore.RecoverOrphans(true)
		if err != nil {
			t.Fatal(err)
		}
		if len(reportReclaim.ReclaimedOrphanBlobs) != 1 || reportReclaim.ReclaimedOrphanBlobs[0] != fx.ExpectedSHA256 {
			t.Fatalf("expected reclaimed orphan blob %s, got %+v", fx.ExpectedSHA256, reportReclaim)
		}
		if _, err := os.Stat(filepath.Join(sealDir, pos.ExpectedBlobRelPath)); err != nil {
			t.Fatalf("prior committed blob should remain intact after orphan reclaim: %v", err)
		}

		// Retry after restart and orphan reclaim succeeds cleanly
		committedAfterCrash, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
			OperationID:    fx.OperationID,
			Quarantined:    qCrash,
			ExpectedSHA256: fx.ExpectedSHA256,
			AcquiredAt:     fx.AcquiredAt,
			CustodyRoot:    fx.CustodyRoot,
			Attempt:        1,
		})
		if err != nil || !committedAfterCrash.Sealed || committedAfterCrash.Generation != 2 {
			t.Fatalf("expected clean commit after restart, got %+v (err=%v)", committedAfterCrash, err)
		}
	})

	// 5. Negative case: replay / lost ACK, conflict, bounded retry, quota & disk full
	t.Run("ReplayLostACKConflictRetryAndQuota", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "replay-lost-ack-quota.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx C09ReplayQuotaFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}

		genBefore := sealStore.Generation()
		bytesBefore := sealStore.TotalBytes()

		// Lost ACK replay of op-seal-c09-0001 returns identical manifest with IdempotentReplay=true
		replayed, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
			OperationID: fx.OperationID,
			Quarantined: quarantined,
			AcquiredAt:  pos.AcquiredAt,
			CustodyRoot: pos.CustodyRoot,
			Attempt:     1,
		})
		if err != nil {
			t.Fatalf("idempotent replay failed: %v", err)
		}
		if !replayed.IdempotentReplay || replayed.ManifestDigest != sealedManifest.ManifestDigest || replayed.Generation != sealedManifest.Generation {
			t.Fatalf("invalid idempotent replay result: %+v", replayed)
		}
		if sealStore.Generation() != genBefore || sealStore.TotalBytes() != bytesBefore {
			t.Fatalf("idempotent replay must not produce duplicate side effects")
		}

		// Conflicting parameters for already-committed OperationID rejected
		qOther, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
			SchemaVersion: "1",
			UploadID:      "upl-c09-conflict",
			CaseID:        fx.CaseID,
			EvidenceID:    fx.ConflictEvidenceID,
			MediaType:     "text/plain",
			Body:          strings.NewReader("conflicting-payload-bytes\n"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
			OperationID: fx.ConflictOpID,
			Quarantined: qOther,
			AcquiredAt:  pos.AcquiredAt,
			CustodyRoot: pos.CustodyRoot,
		}); !errors.Is(err, evidence.ErrOperationConflict) {
			t.Fatalf("expected ErrOperationConflict, got %v", err)
		}

		// Excessive retry attempt rejected (no unlimited retry)
		if _, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
			OperationID: fx.QuotaOpID,
			Quarantined: qOther,
			AcquiredAt:  pos.AcquiredAt,
			CustodyRoot: pos.CustodyRoot,
			Attempt:     fx.ExcessiveAttempt,
		}); !errors.Is(err, evidence.ErrRetryLimitExceeded) {
			t.Fatalf("expected ErrRetryLimitExceeded, got %v", err)
		}

		// Quota exhaustion & disk full on isolated tight store
		quotaRoot := filepath.Join(t.TempDir(), "quota-seal")
		quotaStore, err := evidence.OpenSealStore(evidence.SealConfig{
			RootDir:         quotaRoot,
			QuarantineDir:   quarantineDir,
			MaxStorageBytes: fx.MaxStorageBytes, // 100 bytes; pos payload is 76 bytes
			SyncDir:         true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer quotaStore.Close()

		if _, err := quotaStore.SealQuarantined(context.Background(), evidence.SealRequest{
			OperationID: "op-quota-1",
			Quarantined: quarantined,
			AcquiredAt:  pos.AcquiredAt,
			CustodyRoot: pos.CustodyRoot,
		}); err != nil {
			t.Fatalf("first seal within quota failed: %v", err)
		}
		qSecond, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
			SchemaVersion: "1",
			UploadID:      "upl-quota-2",
			CaseID:        fx.CaseID,
			EvidenceID:    fx.QuotaEvidenceID,
			MediaType:     "text/plain",
			Body:          strings.NewReader(strings.Repeat("Q", 40)), // 76 + 40 = 116 > 100
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := quotaStore.SealQuarantined(context.Background(), evidence.SealRequest{
			OperationID: fx.QuotaOpID,
			Quarantined: qSecond,
			AcquiredAt:  pos.AcquiredAt,
			CustodyRoot: pos.CustodyRoot,
		}); !errors.Is(err, evidence.ErrStorageQuotaExceeded) {
			t.Fatalf("expected ErrStorageQuotaExceeded, got %v", err)
		}
		if quotaStore.Generation() != 1 {
			t.Fatalf("quota overflow must leave generation=1, got %d", quotaStore.Generation())
		}

		// Disk full fault simulation
		diskFullStore, err := evidence.OpenSealStore(evidence.SealConfig{
			RootDir:       filepath.Join(t.TempDir(), "diskfull-seal"),
			QuarantineDir: quarantineDir,
			Faults:        evidence.SealFaults{SimulateDiskFull: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer diskFullStore.Close()
		if _, err := diskFullStore.SealQuarantined(context.Background(), evidence.SealRequest{
			OperationID: fx.DiskFullOpID,
			Quarantined: qSecond,
			AcquiredAt:  pos.AcquiredAt,
			CustodyRoot: pos.CustodyRoot,
		}); !errors.Is(err, evidence.ErrSealDiskFull) {
			t.Fatalf("expected ErrSealDiskFull, got %v", err)
		}
	})

	// 6. Negative case: sealed source bytes never modified
	t.Run("SealedSourceBytesNeverModified", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "sealed-immutable.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fx C09ImmutableFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		qOverwrite, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
			SchemaVersion: "1",
			UploadID:      fx.UploadID,
			CaseID:        fx.CaseID,
			EvidenceID:    fx.EvidenceID, // already sealed ev-c09-0001
			MediaType:     fx.MediaType,
			Filename:      fx.Filename,
			Body:          strings.NewReader(fx.PayloadUTF8),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
			OperationID: fx.OperationID,
			Quarantined: qOverwrite,
			AcquiredAt:  fx.AcquiredAt,
			CustodyRoot: fx.CustodyRoot,
		}); !errors.Is(err, evidence.ErrSealedBytesImmutable) {
			t.Fatalf("expected ErrSealedBytesImmutable, got %v", err)
		}

		afterDiskBytes, err := os.ReadFile(filepath.Join(sealDir, pos.ExpectedBlobRelPath))
		if err != nil || !bytes.Equal(afterDiskBytes, []byte(pos.PayloadUTF8)) {
			t.Fatalf("sealed source bytes changed after rejected overwrite (err=%v)", err)
		}
		mAfter, err := sealStore.GetSealedManifest(pos.CaseID, pos.EvidenceID)
		if err != nil || mAfter.ManifestDigest != sealedManifest.ManifestDigest {
			t.Fatalf("sealed manifest changed after rejected overwrite (err=%v)", err)
		}
	})

	_ = sealStore.Close()
}

func TestSealStoreLockExclusivityAndCorruptBlobDetection(t *testing.T) {
	rootTmp := t.TempDir()
	qDir := filepath.Join(rootTmp, "quarantine")
	sDir := filepath.Join(rootTmp, "sealstore")

	qItem, err := evidence.StreamIntoQuarantine(context.Background(), evidence.UploadConfig{
		QuarantineDir: qDir,
	}, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-lock-test",
		CaseID:        "case-lock-001",
		EvidenceID:    "ev-lock-001",
		MediaType:     "text/plain",
		Body:          strings.NewReader("lock-exclusivity-payload\n"),
	})
	if err != nil {
		t.Fatal(err)
	}

	s1, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir}); !errors.Is(err, evidence.ErrSealLockBusy) {
		_ = s1.Close()
		t.Fatalf("expected ErrSealLockBusy when opening concurrent writer, got %v", err)
	}

	m, err := s1.SealQuarantined(context.Background(), evidence.SealRequest{
		OperationID: "op-lock-1",
		Quarantined: qItem,
		AcquiredAt:  "2026-11-11T09:30:00Z",
		CustodyRoot: qItem.SHA256,
	})
	if err != nil {
		_ = s1.Close()
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	// Corrupt committed blob on disk and verify OpenSealStore fails closed on restart recovery
	blobPath := filepath.Join(sDir, m.BlobRelPath)
	b, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xFF
	if err := os.WriteFile(blobPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir}); !errors.Is(err, evidence.ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch on restart with corrupted committed blob, got %v", err)
	}
}

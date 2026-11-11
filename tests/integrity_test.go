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

	"github.com/Parsa-Emami/Breachatlas/internal/cases"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/storage"
)

type c10BaseFixture struct {
	SchemaVersion string `json:"schema_version"`
	OperationID   string `json:"operation_id"`
	UploadID      string `json:"upload_id"`
	CaseID        string `json:"case_id"`
	EvidenceID    string `json:"evidence_id"`
	MediaType     string `json:"media_type"`
	Filename      string `json:"filename"`
	AcquiredAt    string `json:"acquired_at"`
	CustodyRoot   string `json:"custody_root"`
	PayloadUTF8   string `json:"payload_utf8"`
	ExpectedSize  int64  `json:"expected_size"`
	ExpectedSHA   string `json:"expected_sha256"`
	SignerKeyID   string `json:"signer_key_id"`
	Revision      uint64 `json:"revision"`
	FlipOffset    int    `json:"flip_byte_offset"`
	TruncateBytes int    `json:"truncate_bytes"`
	TrustedKeyID  string `json:"trusted_key_id"`
	UntrustedID   string `json:"untrusted_key_id"`
	AcceptedRev   uint64 `json:"accepted_revision"`
	StaleRev      uint64 `json:"stale_revision"`
}

func getC10FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "fixtures", "breachatlas", "C10")
	if filepath.Base(wd) != "tests" {
		dir = filepath.Join(wd, "tests", "fixtures", "breachatlas", "C10")
	}
	return dir
}

func quarantineAndSealForC10(t *testing.T, qCfg evidence.UploadConfig, store *evidence.SealStore, fix c10BaseFixture) *evidence.SealedManifest {
	t.Helper()
	q, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
		SchemaVersion: fix.SchemaVersion,
		UploadID:      fix.UploadID,
		CaseID:        fix.CaseID,
		EvidenceID:    fix.EvidenceID,
		MediaType:     fix.MediaType,
		Filename:      fix.Filename,
		Body:          strings.NewReader(fix.PayloadUTF8),
	})
	if err != nil {
		t.Fatalf("quarantine %s: %v", fix.EvidenceID, err)
	}
	sm, err := store.SealQuarantined(context.Background(), evidence.SealRequest{
		OperationID: fix.OperationID,
		Quarantined: q,
		AcquiredAt:  fix.AcquiredAt,
		CustodyRoot: fix.CustodyRoot,
	})
	if err != nil {
		t.Fatalf("seal %s: %v", fix.EvidenceID, err)
	}
	return sm
}

func TestC10FixturesAndIntegrityVerification(t *testing.T) {
	fixturesDir := getC10FixturesDir(t)

	// 1. Validate Apache-2.0 provenance and fixture hashes.
	provRaw, err := os.ReadFile(filepath.Join(fixturesDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read C10 provenance.json: %v", err)
	}
	var prov Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatalf("unmarshal C10 provenance.json: %v", err)
	}
	if prov.License != "Apache-2.0" {
		t.Fatalf("expected Apache-2.0 license, got %q", prov.License)
	}
	for relPath, wantHash := range prov.SHA256 {
		content, err := os.ReadFile(filepath.Join(fixturesDir, relPath))
		if err != nil {
			t.Fatalf("read fixture %s: %v", relPath, err)
		}
		sum := sha256.Sum256(content)
		if got := hex.EncodeToString(sum[:]); got != wantHash {
			t.Fatalf("fixture hash mismatch for %s: got %s, want %s", relPath, got, wantHash)
		}
	}

	outcomesRaw, err := os.ReadFile(filepath.Join(fixturesDir, "expected-output", "outcomes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var outcomes map[string]map[string]any
	if err := json.Unmarshal(outcomesRaw, &outcomes); err != nil {
		t.Fatal(err)
	}

	rootTmp := t.TempDir()
	quarantineDir := filepath.Join(rootTmp, "quarantine")
	sealDir := filepath.Join(rootTmp, "sealstore")
	storageDir := filepath.Join(rootTmp, "storage")

	qCfg := evidence.UploadConfig{QuarantineDir: quarantineDir, BufferSize: 32, SyncDir: true}
	store, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("OpenSealStore: %v", err)
	}
	defer store.Close()

	// Trusted Ed25519 signer and rogue untrusted Ed25519 signer.
	trustedPub, trustedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roguePub, roguePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = roguePub

	now := time.Date(2026, 11, 11, 10, 30, 0, 0, time.UTC)

	// 2. Positive case: quarantine -> seal -> storage commit -> cases register -> Ed25519 signed verify
	var pos c10BaseFixture
	posRaw, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "valid-sealed-signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(posRaw, &pos); err != nil {
		t.Fatal(err)
	}

	sealedPos := quarantineAndSealForC10(t, qCfg, store, pos)
	if sealedPos.SHA256 != pos.ExpectedSHA || sealedPos.SizeBytes != pos.ExpectedSize {
		t.Fatalf("sealed metadata mismatch: %+v", sealedPos)
	}

	trustedKeys := map[string]string{
		pos.SignerKeyID: hex.EncodeToString(trustedPub),
	}
	tracker := evidence.NewAuthorityTracker()
	attPos, err := evidence.SignSealedManifest(*sealedPos, pos.SignerKeyID, trustedPriv, pos.Revision, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignSealedManifest positive: %v", err)
	}

	// Integrate with storage.Adapter & cases.Registry to mirror full product vertical slice.
	adapter, err := storage.Open(storage.Config{RootDir: storageDir, SyncDir: true})
	if err != nil {
		t.Fatalf("open storage adapter: %v", err)
	}
	defer adapter.Close()

	payloadBytes, err := os.ReadFile(filepath.Join(sealDir, sealedPos.BlobRelPath))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := cases.NewRegistry(adapter)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if _, err := registry.CreateCase(cases.CreateCaseInput{
		CaseID:         pos.CaseID,
		Title:          "SSH Auth Verification",
		Classification: "internal",
		Owner:          "ir-lead",
	}); err != nil {
		t.Fatalf("CreateCase: %v", err)
	}
	if _, err := registry.RegisterEvidence(context.Background(), cases.RegisterEvidenceRequest{
		OperationID: "op-store-c10-0001",
		Manifest: evidence.Manifest{
			SchemaVersion: pos.SchemaVersion,
			CaseID:        pos.CaseID,
			EvidenceID:    pos.EvidenceID,
			SHA256:        sealedPos.SHA256,
			SizeBytes:     sealedPos.SizeBytes,
			MediaType:     sealedPos.MediaType,
			AcquiredAt:    sealedPos.AcquiredAt,
			CustodyRoot:   sealedPos.CustodyRoot,
		},
		Payload:  payloadBytes,
		Identity: makeUploadTestIdentity(t, "op-store-c10-0001", pos.CaseID, pos.EvidenceID, sealedPos.SHA256),
	}); err != nil {
		t.Fatalf("RegisterEvidence: %v", err)
	}

	verifyRes, err := evidence.VerifyStoreEvidence(context.Background(), store, pos.CaseID, pos.EvidenceID, evidence.VerifyOptions{
		RequireAuthority:  true,
		Authority:         attPos,
		TrustedPublicKeys: trustedKeys,
		Tracker:           tracker,
		Now:               now,
	})
	if err != nil {
		t.Fatalf("VerifyStoreEvidence positive failed: %v", err)
	}
	posOutcome := outcomes["positive/valid-sealed-signed.json"]
	if !verifyRes.Verified || verifyRes.Code != posOutcome["code"] || verifyRes.ActualSHA256 != pos.ExpectedSHA || verifyRes.ActualSize != pos.ExpectedSize {
		t.Fatalf("unexpected positive verification result: %+v", verifyRes)
	}
	if fileRes, err := evidence.VerifySealedFile(filepath.Join(sealDir, sealedPos.BlobRelPath), pos.ExpectedSHA, pos.ExpectedSize); err != nil || !fileRes.Verified {
		t.Fatalf("VerifySealedFile positive failed: err=%v res=%+v", err, fileRes)
	}

	// Verify sealed source bytes were never modified after positive verification.
	afterPosBytes, err := os.ReadFile(filepath.Join(sealDir, sealedPos.BlobRelPath))
	if err != nil || !bytes.Equal(afterPosBytes, []byte(pos.PayloadUTF8)) {
		t.Fatalf("sealed source bytes changed during verification (err=%v)", err)
	}

	// 3. Negative case A: 1-byte modification (distinct digest_mismatch; NOT size_mismatch or missing_file)
	t.Run("OneByteModificationDistinctFromSizeAndMissing", func(t *testing.T) {
		var fix c10BaseFixture
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "one-byte-modified.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &fix); err != nil {
			t.Fatal(err)
		}

		// Use isolated seal store so content-addressed blob path isn't shared across tests.
		subSealDir := filepath.Join(rootTmp, "seal-one-byte")
		subStore, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: subSealDir, QuarantineDir: quarantineDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		defer subStore.Close()

		sm := quarantineAndSealForC10(t, qCfg, subStore, fix)
		blobPath := filepath.Join(subSealDir, sm.BlobRelPath)
		orig, err := os.ReadFile(blobPath)
		if err != nil {
			t.Fatal(err)
		}
		mutated := append([]byte(nil), orig...)
		mutated[fix.FlipOffset] ^= 0x01 // flip exactly one bit in one byte; same length
		if err := os.WriteFile(blobPath, mutated, 0o600); err != nil {
			t.Fatal(err)
		}

		res, err := evidence.VerifyStoreEvidence(context.Background(), subStore, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{Now: now})
		if err == nil || res.Verified {
			t.Fatalf("expected verification failure on 1-byte modification, got success: %+v", res)
		}
		if !errors.Is(err, evidence.ErrDigestMismatch) {
			t.Fatalf("expected ErrDigestMismatch, got %v", err)
		}
		if errors.Is(err, evidence.ErrSizeMismatch) || errors.Is(err, evidence.ErrEvidenceMissing) {
			t.Fatalf("1-byte modification must be distinct from size/missing errors, got %v", err)
		}
		if res.Code != evidence.VerifyCodeDigestMismatch || res.ActualSize != sm.SizeBytes || res.ActualSHA256 == sm.SHA256 {
			t.Fatalf("unexpected 1-byte failure details: %+v", res)
		}
	})

	// 4. Negative case B: Size mismatch (distinct from digest_mismatch & missing_file)
	t.Run("SizeMismatchDistinctFromDigestAndMissing", func(t *testing.T) {
		var fix c10BaseFixture
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "size-mismatch.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &fix); err != nil {
			t.Fatal(err)
		}

		subSealDir := filepath.Join(rootTmp, "seal-size-mismatch")
		subStore, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: subSealDir, QuarantineDir: quarantineDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		defer subStore.Close()

		sm := quarantineAndSealForC10(t, qCfg, subStore, fix)
		blobPath := filepath.Join(subSealDir, sm.BlobRelPath)
		if err := os.Truncate(blobPath, int64(fix.TruncateBytes)); err != nil {
			t.Fatal(err)
		}

		res, err := evidence.VerifyStoreEvidence(context.Background(), subStore, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{Now: now})
		if err == nil || res.Verified {
			t.Fatalf("expected failure on truncated blob, got %+v", res)
		}
		if !errors.Is(err, evidence.ErrSizeMismatch) {
			t.Fatalf("expected ErrSizeMismatch, got %v", err)
		}
		if errors.Is(err, evidence.ErrDigestMismatch) || errors.Is(err, evidence.ErrEvidenceMissing) {
			t.Fatalf("size mismatch must be distinct from digest/missing errors, got %v", err)
		}
		if res.Code != evidence.VerifyCodeSizeMismatch || res.ActualSize != int64(fix.TruncateBytes) {
			t.Fatalf("unexpected size mismatch result: %+v", res)
		}

		// Also verify extended size (> expected) classifies distinctly as size_mismatch.
		if err := os.WriteFile(blobPath, append([]byte(fix.PayloadUTF8), []byte("EXTRA")...), 0o600); err != nil {
			t.Fatal(err)
		}
		resExt, errExt := evidence.VerifyStoreEvidence(context.Background(), subStore, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{Now: now})
		if !errors.Is(errExt, evidence.ErrSizeMismatch) || resExt.Code != evidence.VerifyCodeSizeMismatch {
			t.Fatalf("expected ErrSizeMismatch on extended blob, got err=%v code=%q", errExt, resExt.Code)
		}
	})

	// 5. Negative case C: Missing evidence file / missing manifest / unknown evidence ID
	t.Run("MissingEvidenceDistinctFromSizeAndDigest", func(t *testing.T) {
		var fix c10BaseFixture
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "missing-evidence.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &fix); err != nil {
			t.Fatal(err)
		}

		subSealDir := filepath.Join(rootTmp, "seal-missing")
		subStore, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: subSealDir, QuarantineDir: quarantineDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		defer subStore.Close()

		sm := quarantineAndSealForC10(t, qCfg, subStore, fix)
		blobPath := filepath.Join(subSealDir, sm.BlobRelPath)
		if err := os.Remove(blobPath); err != nil {
			t.Fatal(err)
		}

		res, err := evidence.VerifyStoreEvidence(context.Background(), subStore, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{Now: now})
		if err == nil || res.Verified {
			t.Fatalf("expected failure when blob is missing, got %+v", res)
		}
		if !errors.Is(err, evidence.ErrEvidenceMissing) {
			t.Fatalf("expected ErrEvidenceMissing, got %v", err)
		}
		if errors.Is(err, evidence.ErrSizeMismatch) || errors.Is(err, evidence.ErrDigestMismatch) {
			t.Fatalf("missing file must be distinct from size/digest errors, got %v", err)
		}
		if res.Code != evidence.VerifyCodeMissingFile {
			t.Fatalf("expected missing_file code, got %q", res.Code)
		}

		// Also verify missing manifest file & nonexistent evidence entry classify as missing_file.
		if resMissingID, errMissingID := evidence.VerifyStoreEvidence(context.Background(), subStore, fix.CaseID, "ev-does-not-exist", evidence.VerifyOptions{Now: now}); !errors.Is(errMissingID, evidence.ErrEvidenceMissing) || resMissingID.Code != evidence.VerifyCodeMissingFile {
			t.Fatalf("expected missing_file for nonexistent item, got err=%v code=%q", errMissingID, resMissingID.Code)
		}
	})

	// 6. Negative case D: Wrong / untrusted / forged Ed25519 signer must never produce trusted success
	t.Run("UntrustedOrForgedSignerRejected", func(t *testing.T) {
		var fix c10BaseFixture
		raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "untrusted-signer.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &fix); err != nil {
			t.Fatal(err)
		}

		subSealDir := filepath.Join(rootTmp, "seal-untrusted")
		subStore, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: subSealDir, QuarantineDir: quarantineDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		defer subStore.Close()

		sm := quarantineAndSealForC10(t, qCfg, subStore, fix)

		// Case 1: Signed by rogue private key claiming an untrusted key ID.
		rogueAtt, err := evidence.SignSealedManifest(*sm, fix.UntrustedID, roguePriv, 1, now.Add(-time.Minute), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		resRogue, errRogue := evidence.VerifyStoreEvidence(context.Background(), subStore, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{
			RequireAuthority:  true,
			Authority:         rogueAtt,
			TrustedPublicKeys: trustedKeys,
			Now:               now,
		})
		if errRogue == nil || resRogue.Verified || !errors.Is(errRogue, evidence.ErrAuthorityUntrusted) || resRogue.Code != evidence.VerifyCodeUntrustedSigner {
			t.Fatalf("expected untrusted_signer error for rogue key, got err=%v res=%+v", errRogue, resRogue)
		}

		// Case 2: Signed by rogue private key claiming the trusted key ID (key spoofing).
		spoofAtt, err := evidence.SignSealedManifest(*sm, fix.TrustedKeyID, roguePriv, 1, now.Add(-time.Minute), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		resSpoof, errSpoof := evidence.VerifyStoreEvidence(context.Background(), subStore, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{
			RequireAuthority:  true,
			Authority:         spoofAtt,
			TrustedPublicKeys: trustedKeys,
			Now:               now,
		})
		if errSpoof == nil || resSpoof.Verified || !errors.Is(errSpoof, evidence.ErrAuthorityUntrusted) || resSpoof.Code != evidence.VerifyCodeUntrustedSigner {
			t.Fatalf("expected untrusted_signer error for spoofed key_id, got err=%v res=%+v", errSpoof, resSpoof)
		}

		// Case 3: Missing authority when RequireAuthority=true.
		resMissingAuth, errMissingAuth := evidence.VerifyStoreEvidence(context.Background(), subStore, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{
			RequireAuthority:  true,
			TrustedPublicKeys: trustedKeys,
			Now:               now,
		})
		if errMissingAuth == nil || resMissingAuth.Verified || !errors.Is(errMissingAuth, evidence.ErrAuthorityUntrusted) {
			t.Fatalf("expected ErrAuthorityUntrusted when required authority omitted, got err=%v res=%+v", errMissingAuth, resMissingAuth)
		}
	})
}

func TestC10AuthorityAntiRollbackAndByteImmutability(t *testing.T) {
	fixturesDir := getC10FixturesDir(t)
	raw, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "expired-stale-replayed.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fix c10BaseFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatal(err)
	}

	rootTmp := t.TempDir()
	quarantineDir := filepath.Join(rootTmp, "quarantine")
	sealDir := filepath.Join(rootTmp, "sealstore")
	qCfg := evidence.UploadConfig{QuarantineDir: quarantineDir, BufferSize: 32, SyncDir: true}

	store, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatal(err)
	}

	sm := quarantineAndSealForC10(t, qCfg, store, fix)
	blobFull := filepath.Join(sealDir, sm.BlobRelPath)
	preStat, err := os.Stat(blobFull)
	if err != nil {
		t.Fatal(err)
	}

	trustedPub, trustedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roguePub, roguePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = roguePub

	keyID := "trust-key-01"
	trustedKeys := map[string]string{keyID: hex.EncodeToString(trustedPub)}
	tracker := evidence.NewAuthorityTracker()
	now := time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC)

	// Sign Revision 1 (older), then Revision 2 (current accepted authority).
	attRev1, err := evidence.SignSealedManifest(*sm, keyID, trustedPriv, fix.StaleRev, now.Add(-20*time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	attRev2, err := evidence.SignSealedManifest(*sm, keyID, trustedPriv, fix.AcceptedRev, now.Add(-5*time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	if res, err := evidence.VerifyStoreEvidence(context.Background(), store, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{
		RequireAuthority:  true,
		Authority:         attRev2,
		TrustedPublicKeys: trustedKeys,
		Tracker:           tracker,
		Now:               now,
	}); err != nil || !res.Verified {
		t.Fatalf("expected revision 2 acceptance, got err=%v res=%+v", err, res)
	}

	// Attempt 1: Expired higher revision (Revision 3) must fail and NOT replace Revision 2.
	attExpiredRev3, err := evidence.SignSealedManifest(*sm, keyID, trustedPriv, fix.AcceptedRev+1, now.Add(-2*time.Hour), now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if res, err := evidence.VerifyStoreEvidence(context.Background(), store, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{
		RequireAuthority:  true,
		Authority:         attExpiredRev3,
		TrustedPublicKeys: trustedKeys,
		Tracker:           tracker,
		Now:               now,
	}); !errors.Is(err, evidence.ErrAuthorityExpired) || res.Code != evidence.VerifyCodeExpiredAuthority {
		t.Fatalf("expected expired_authority rejection, got err=%v res=%+v", err, res)
	}

	// Attempt 2: Stale lower revision (Revision 1) must fail and NOT replace Revision 2.
	if res, err := evidence.VerifyStoreEvidence(context.Background(), store, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{
		RequireAuthority:  true,
		Authority:         attRev1,
		TrustedPublicKeys: trustedKeys,
		Tracker:           tracker,
		Now:               now,
	}); !errors.Is(err, evidence.ErrAuthorityStaleRevision) || res.Code != evidence.VerifyCodeStaleRevision {
		t.Fatalf("expected stale_revision for revision 1, got err=%v res=%+v", err, res)
	}

	// Attempt 3: Replayed current revision (StrictReplay: true) must be rejected without mutating accepted authority.
	if res, err := evidence.VerifyStoreEvidence(context.Background(), store, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{
		RequireAuthority:  true,
		Authority:         attRev2,
		TrustedPublicKeys: trustedKeys,
		Tracker:           tracker,
		StrictReplay:      true,
		Now:               now,
	}); !errors.Is(err, evidence.ErrAuthorityStaleRevision) || res.Code != evidence.VerifyCodeStaleRevision {
		t.Fatalf("expected stale_revision on strict replay of revision 2, got err=%v res=%+v", err, res)
	}

	// Attempt 4: Untrusted key on higher revision (Revision 4) must not replace accepted authority.
	attUntrustedRev4, err := evidence.SignSealedManifest(*sm, keyID, roguePriv, fix.AcceptedRev+2, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res, err := evidence.VerifyStoreEvidence(context.Background(), store, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{
		RequireAuthority:  true,
		Authority:         attUntrustedRev4,
		TrustedPublicKeys: trustedKeys,
		Tracker:           tracker,
		Now:               now,
	}); !errors.Is(err, evidence.ErrAuthorityUntrusted) || res.Code != evidence.VerifyCodeUntrustedSigner {
		t.Fatalf("expected untrusted_signer on revision 4, got err=%v res=%+v", err, res)
	}

	// Confirm the last valid accepted authority remained Revision 2 with original trusted signature.
	accepted, ok := tracker.LastAccepted(fix.CaseID, fix.EvidenceID)
	if !ok || accepted.Revision != fix.AcceptedRev || accepted.Signature != attRev2.Signature || accepted.KeyID != keyID {
		t.Fatalf("last valid accepted authority was altered or lost: ok=%v accepted=%+v", ok, accepted)
	}

	// Symlink and path traversal rejections during verification.
	linkRoot := filepath.Join(rootTmp, "symlink-root")
	if err := os.Symlink(sealDir, linkRoot); err == nil {
		if _, err := evidence.VerifySealedManifest(linkRoot, *sm, evidence.VerifyOptions{Now: now}); !errors.Is(err, evidence.ErrSymlinkRejected) {
			t.Fatalf("expected ErrSymlinkRejected on symlink root, got %v", err)
		}
	}
	if _, err := evidence.VerifySealedManifest(sealDir+"/../escape", *sm, evidence.VerifyOptions{Now: now}); !errors.Is(err, evidence.ErrPathTraversal) {
		t.Fatalf("expected ErrPathTraversal on traversal root, got %v", err)
	}
	traversalManifest := *sm
	traversalManifest.BlobRelPath = "../../etc/passwd"
	if _, err := evidence.VerifySealedManifest(sealDir, traversalManifest, evidence.VerifyOptions{Now: now}); !errors.Is(err, evidence.ErrPathTraversal) {
		t.Fatalf("expected ErrPathTraversal on traversal blob_rel_path, got %v", err)
	}

	// Restart SealStore cleanly and re-verify sealed evidence bytes and immutability.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sealDir,
		QuarantineDir: quarantineDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("reopen seal store: %v", err)
	}
	defer reopened.Close()

	resReopened, err := evidence.VerifyStoreEvidence(context.Background(), reopened, fix.CaseID, fix.EvidenceID, evidence.VerifyOptions{
		RequireAuthority:  true,
		Authority:         attRev2,
		TrustedPublicKeys: trustedKeys,
		Tracker:           tracker,
		Now:               now,
	})
	if err != nil || !resReopened.Verified {
		t.Fatalf("post-restart verification failed: err=%v res=%+v", err, resReopened)
	}

	postStat, err := os.Stat(blobFull)
	if err != nil {
		t.Fatal(err)
	}
	if postStat.Size() != preStat.Size() || !postStat.ModTime().Equal(preStat.ModTime()) || postStat.Mode() != preStat.Mode() {
		t.Fatalf("sealed source blob metadata changed during verification: pre=%v post=%v", preStat, postStat)
	}
	diskBytes, err := os.ReadFile(blobFull)
	if err != nil || !bytes.Equal(diskBytes, []byte(fix.PayloadUTF8)) {
		t.Fatalf("sealed source bytes changed after restart verification (err=%v)", err)
	}
}

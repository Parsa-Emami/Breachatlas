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
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/export"
	"github.com/Parsa-Emami/Breachatlas/internal/release"
)

type c35Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c35TrustedPolicyFixture struct {
	SchemaVersion      string   `json:"schema_version"`
	Task               string   `json:"task"`
	Requirement        string   `json:"requirement"`
	Scope              string   `json:"scope"`
	TrustedKeyID       string   `json:"trusted_key_id"`
	SupportedHosts     []string `json:"supported_hosts"`
	RequiredDeliverables []string `json:"required_deliverables"`
	UpgradeSequence    []struct {
		ReleaseVersion string `json:"release_version"`
		Revision       uint64 `json:"revision"`
		IssuedAt       string `json:"issued_at"`
		ExpiresAt      string `json:"expires_at"`
	} `json:"upgrade_sequence"`
}

func copyTreeForTest(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode()&0o755)
	})
	if err != nil {
		t.Fatalf("copyTreeForTest(%s -> %s): %v", src, dst, err)
	}
}

func TestC35SignedArtifactsAndDataSafeUpgrades(t *testing.T) {
	ctx := context.Background()
	root := locateRepoRoot(t)
	fxDir := filepath.Join(root, "tests", "fixtures", "breachatlas", "C35")

	// 1. Validate C35 fixture provenance & SHA-256 digests.
	provRaw, err := os.ReadFile(filepath.Join(fxDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read C35 provenance: %v", err)
	}
	var prov c35Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatalf("decode C35 provenance: %v", err)
	}
	if prov.Task != "C35" || prov.License != "Apache-2.0" || len(prov.SHA256) < 3 {
		t.Fatalf("unexpected C35 provenance: %+v", prov)
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

	var fxPolicy c35TrustedPolicyFixture
	policyRaw, err := os.ReadFile(filepath.Join(fxDir, "positive", "trusted-release-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(policyRaw, &fxPolicy); err != nil {
		t.Fatal(err)
	}
	if len(fxPolicy.UpgradeSequence) < 2 {
		t.Fatalf("expected >= 2 upgrade sequence versions in fixture")
	}

	// Ensure a complete base release package exists under dist/release.
	baseReleaseDir := filepath.Join(root, "dist", "release")
	if _, err := os.Stat(filepath.Join(baseReleaseDir, "release.json")); err != nil {
		pkgCmd := exec.CommandContext(ctx, "bash", filepath.Join(root, "scripts", "package.sh"))
		pkgCmd.Dir = root
		if out, err := pkgCmd.CombinedOutput(); err != nil {
			t.Fatalf("scripts/package.sh failed: %v\n%s", err, string(out))
		}
	}

	// 2. Prepare independently trusted and rogue Ed25519 signing keys + two signed release revisions (v0.1.0 rev 1, v0.1.1 rev 2).
	trustedPub, trustedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roguePub, roguePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = roguePub

	relV1 := filepath.Join(t.TempDir(), "rel-v1")
	relV2 := filepath.Join(t.TempDir(), "rel-v2")
	copyTreeForTest(t, baseReleaseDir, relV1)
	copyTreeForTest(t, baseReleaseDir, relV2)

	v1Spec := fxPolicy.UpgradeSequence[0]
	v2Spec := fxPolicy.UpgradeSequence[1]
	v1Issued, _ := time.Parse(time.RFC3339, v1Spec.IssuedAt)
	v1Expires, _ := time.Parse(time.RFC3339, v1Spec.ExpiresAt)
	v2Issued, _ := time.Parse(time.RFC3339, v2Spec.IssuedAt)
	v2Expires, _ := time.Parse(time.RFC3339, v2Spec.ExpiresAt)
	verifyNow := time.Date(2026, 11, 14, 14, 0, 0, 0, time.UTC)

	if _, err := release.SignReleaseDirectory(relV1, trustedPriv, fxPolicy.TrustedKeyID, v1Spec.ReleaseVersion, v1Spec.Revision, v1Issued, v1Expires); err != nil {
		t.Fatalf("SignReleaseDirectory v1 failed: %v", err)
	}
	if _, err := release.SignReleaseDirectory(relV2, trustedPriv, fxPolicy.TrustedKeyID, v2Spec.ReleaseVersion, v2Spec.Revision, v2Issued, v2Expires); err != nil {
		t.Fatalf("SignReleaseDirectory v2 failed: %v", err)
	}

	// Cross-verify Go-signed release directory with Node CLI scripts/verify-release.mjs.
	nodeVerifyCmd := exec.CommandContext(ctx, "node", filepath.Join(root, "scripts", "verify-release.mjs"),
		"--dir", relV2,
		"--trusted-key", hex.EncodeToString(trustedPub),
		"--key-id", fxPolicy.TrustedKeyID,
		"--min-revision", "2",
		"--now", verifyNow.Format(time.RFC3339),
	)
	nodeVerifyCmd.Dir = root
	if out, err := nodeVerifyCmd.CombinedOutput(); err != nil {
		t.Fatalf("scripts/verify-release.mjs failed on Go-signed release: %v\n%s", err, string(out))
	}

	policy := release.TrustedReleasePolicy{
		TrustedKeys:                   map[string]ed25519.PublicKey{fxPolicy.TrustedKeyID: trustedPub},
		MinRevision:                   1,
		VerifyTime:                    verifyNow,
		RequireSourceBuildAlternative: true,
	}

	// 3. Install v0.1.0 onto host, create real sealed evidence + custody ledger + export bundle in DataDir.
	hostRoot := filepath.Join(t.TempDir(), "host-install")
	dataDir := filepath.Join(t.TempDir(), "host-data")

	instOut, err := release.InstallOrUpgradeRelease(ctx, release.UpgradeConfig{
		InstallRoot:         hostRoot,
		DataDir:             dataDir,
		CandidateReleaseDir: relV1,
		Policy:              policy,
		Now:                 verifyNow,
	})
	if err != nil {
		t.Fatalf("fresh install v0.1.0 failed: %v", err)
	}
	if instOut.Authority.CurrentVersion != "0.1.0" || instOut.Authority.HighestAcceptedRevision != 1 || !instOut.Verification.SourceBuildRecipeReady {
		t.Fatalf("unexpected fresh install outcome: %+v", instOut)
	}

	// Create real sealed case-v1 inside host dataDir.
	qDir := filepath.Join(dataDir, "quarantine")
	sDir := filepath.Join(dataDir, "sealstore")
	cDir := filepath.Join(dataDir, "custody")
	kDir := filepath.Join(dataDir, "checkpoints")
	eDir := filepath.Join(dataDir, "exports")

	ss, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	ls, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: cDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	cs, err := custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{RootDir: kDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	es, err := export.OpenExportStore(export.ExportStoreConfig{RootDir: eDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = es.Close() })

	sealCase := func(caseID, evID, opID, payloadLine string) ([]byte, string) {
		payload := []byte(payloadLine)
		sum := sha256.Sum256(payload)
		hexSum := hex.EncodeToString(sum[:])
		sz := int64(len(payload))
		q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{QuarantineDir: qDir, SyncDir: true}, evidence.UploadRequest{
			SchemaVersion:  "1",
			UploadID:       "upl-" + opID,
			CaseID:         caseID,
			EvidenceID:     evID,
			MediaType:      "text/plain",
			Filename:       evID + ".log",
			ExpectedSize:   &sz,
			ExpectedSHA256: hexSum,
			Body:           bytes.NewReader(payload),
		})
		if err != nil {
			t.Fatal(err)
		}
		ev, err := ls.AppendEvent(ctx, custody.AppendEventRequest{
			EventID:    "cust-" + opID,
			CaseID:     caseID,
			EvidenceID: evID,
			EventType:  "intake_seal",
			Actor:      "analyst",
			Timestamp:  verifyNow.Format(time.RFC3339),
			Reason:     "C35 upgrade safety check",
			Provider:   "local",
		})
		if err != nil {
			t.Fatal(err)
		}
		sealedManifest, err := ss.SealQuarantined(ctx, evidence.SealRequest{
			OperationID:    opID,
			Quarantined:    q,
			ExpectedSHA256: hexSum,
			AcquiredAt:     verifyNow.Format(time.RFC3339),
			CustodyRoot:    ev.CustodyRoot,
		})
		if err != nil {
			t.Fatal(err)
		}
		return payload, filepath.Join(sDir, sealedManifest.BlobRelPath)
	}

	v1Payload, v1SealedPath := sealCase("c35-case-v1", "ev-v1", "op-v1", "2026-11-14T10:30:00Z node1 breachatlas: v1-accepted-record\n")
	v1SealedSum := sha256.Sum256(v1Payload)

	// 4. Upgrade host to signed v0.1.1 (revision 2) and confirm case-v1 sealed data is untouched.
	upgOut, err := release.InstallOrUpgradeRelease(ctx, release.UpgradeConfig{
		InstallRoot:         hostRoot,
		DataDir:             dataDir,
		CandidateReleaseDir: relV2,
		Policy:              policy,
		Now:                 verifyNow,
	})
	if err != nil {
		t.Fatalf("upgrade to v0.1.1 failed: %v", err)
	}
	if upgOut.Authority.CurrentVersion != "0.1.1" || upgOut.Authority.HighestAcceptedRevision != 2 || upgOut.PreservedDataFile < 1 {
		t.Fatalf("unexpected upgrade outcome: %+v", upgOut)
	}
	if got, err := os.ReadFile(v1SealedPath); err != nil || sha256.Sum256(got) != v1SealedSum {
		t.Fatalf("case-v1 sealed bytes damaged after upgrade")
	}

	// 5. Accept newer evidence under v0.1.1.
	v2Payload, v2SealedPath := sealCase("c35-case-v2-newer", "ev-v2", "op-v2", "2026-11-14T12:45:00Z node1 breachatlas: v2-newer-accepted-record\n")
	v2SealedSum := sha256.Sum256(v2Payload)

	// Negative: Rollback attempting to overwrite newer accepted data with an old backup MUST fail.
	if _, err := release.RollbackRelease(ctx, release.RollbackConfig{
		InstallRoot:                hostRoot,
		DataDir:                    dataDir,
		Policy:                     policy,
		OverwriteDataWithOldBackup: true,
		Now:                        verifyNow,
	}); !errors.Is(err, release.ErrNewerDataOverwriteForbidden) {
		t.Fatalf("expected ErrNewerDataOverwriteForbidden, got %v", err)
	}

	// 6. Data-safe binary rollback from v0.1.1 -> v0.1.0; newer accepted data and authority watermark MUST be preserved.
	rbOut, err := release.RollbackRelease(ctx, release.RollbackConfig{
		InstallRoot: hostRoot,
		DataDir:     dataDir,
		Policy:      policy,
		Now:         verifyNow,
	})
	if err != nil {
		t.Fatalf("data-safe rollback failed: %v", err)
	}
	if rbOut.Authority.CurrentVersion != "0.1.0" || rbOut.Authority.HighestAcceptedRevision != 2 {
		t.Fatalf("expected rolled back current_version=0.1.0 with highest_accepted_revision=2, got %+v", rbOut.Authority)
	}
	if got, err := os.ReadFile(v1SealedPath); err != nil || sha256.Sum256(got) != v1SealedSum {
		t.Fatalf("case-v1 sealed bytes lost after rollback")
	}
	if got, err := os.ReadFile(v2SealedPath); err != nil || sha256.Sum256(got) != v2SealedSum {
		t.Fatalf("newer case-v2 sealed bytes discarded after rollback")
	}

	// Verify packaged offline verifier binary inside rolled-back current/ still runs cleanly.
	if out, err := exec.CommandContext(ctx, filepath.Join(hostRoot, "current", "bin", "verify"), "--version").CombinedOutput(); err != nil {
		t.Fatalf("rolled-back current/bin/verify failed: %v\n%s", err, string(out))
	}

	// 7. Negative cases:
	// 7a. Stale/replayed revision (rev 1 <= authority 2) cannot be installed as an upgrade.
	if _, err := release.InstallOrUpgradeRelease(ctx, release.UpgradeConfig{
		InstallRoot:         hostRoot,
		DataDir:             dataDir,
		CandidateReleaseDir: relV1,
		Policy:              policy,
		Now:                 verifyNow,
	}); !errors.Is(err, release.ErrStaleOrExpiredRevision) {
		t.Fatalf("expected ErrStaleOrExpiredRevision for stale replay, got %v", err)
	}

	// 7b. One modified byte rejected.
	tamperDir := filepath.Join(t.TempDir(), "tamper-byte")
	copyTreeForTest(t, relV2, tamperDir)
	noticePath := filepath.Join(tamperDir, "THIRD_PARTY_NOTICES.md")
	noticeBytes, err := os.ReadFile(noticePath)
	if err != nil {
		t.Fatal(err)
	}
	noticeBytes[0] ^= 0x01
	if err := os.WriteFile(noticePath, noticeBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyTrustedRelease(ctx, tamperDir, policy); !errors.Is(err, release.ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch for 1-byte tamper, got %v", err)
	}

	// 7c. Missing deliverable rejected.
	missingDir := filepath.Join(t.TempDir(), "missing-deliverable")
	copyTreeForTest(t, relV2, missingDir)
	if err := os.Remove(filepath.Join(missingDir, "bin", "verify")); err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyTrustedRelease(ctx, missingDir, policy); !errors.Is(err, release.ErrIncompleteWebOnlyArtifact) {
		t.Fatalf("expected ErrIncompleteWebOnlyArtifact for missing deliverable, got %v", err)
	}

	// 7d. Untrusted signer rejected.
	rogueDir := filepath.Join(t.TempDir(), "rogue-signer")
	copyTreeForTest(t, baseReleaseDir, rogueDir)
	if _, err := release.SignReleaseDirectory(rogueDir, roguePriv, "rogue-signer-key", "0.1.2", 3, v2Issued, v2Expires); err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyTrustedRelease(ctx, rogueDir, policy); !errors.Is(err, release.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for untrusted signer, got %v", err)
	}

	// 7e. Expired release revision rejected.
	expiredDir := filepath.Join(t.TempDir(), "expired")
	copyTreeForTest(t, baseReleaseDir, expiredDir)
	expIssued := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	expAt := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if _, err := release.SignReleaseDirectory(expiredDir, trustedPriv, fxPolicy.TrustedKeyID, "0.1.3", 3, expIssued, expAt); err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyTrustedRelease(ctx, expiredDir, policy); !errors.Is(err, release.ErrStaleOrExpiredRevision) {
		t.Fatalf("expected ErrStaleOrExpiredRevision for expired revision, got %v", err)
	}

	// 8. Run Node distribution upgrade-recovery runner & confirm docs/evidence/release-verification.json matches expected contract.
	nodeSuiteCmd := exec.CommandContext(ctx, "node", filepath.Join(root, "tests", "release", "upgrade-recovery.mjs"))
	nodeSuiteCmd.Dir = root
	if out, err := nodeSuiteCmd.CombinedOutput(); err != nil {
		t.Fatalf("tests/release/upgrade-recovery.mjs failed: %v\n%s", err, string(out))
	}

	reportRaw, err := os.ReadFile(filepath.Join(root, "docs", "evidence", "release-verification.json"))
	if err != nil {
		t.Fatalf("read docs/evidence/release-verification.json: %v", err)
	}
	var report struct {
		Task                         string `json:"task"`
		Passed                       bool   `json:"passed"`
		SourceBuildAlternativeReady  bool   `json:"source_build_alternative_verified"`
		NegativeCasesRejected        []string `json:"negative_cases_rejected"`
		LifecycleChecks              map[string]any `json:"lifecycle_checks"`
	}
	if err := json.Unmarshal(reportRaw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Task != "C35" || !report.Passed || !report.SourceBuildAlternativeReady || len(report.NegativeCasesRejected) < 6 {
		t.Fatalf("unexpected release-verification.json summary: %+v", report)
	}
}

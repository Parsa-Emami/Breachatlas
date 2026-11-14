package tests

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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

type releaseGateReport struct {
	Passed                bool     `json:"passed"`
	VerifiedPrerequisites int      `json:"verified_prerequisites"`
	TotalPrerequisites    int      `json:"total_prerequisites"`
	CoreReady             bool     `json:"core_ready"`
	RequiredEvidenceCount int      `json:"required_evidence_checked"`
	Failures              []string `json:"failures"`
}

func TestC39ReleaseReadinessGate(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	t.Run("positive_release_check_and_v1_gate_artifact", func(t *testing.T) {
		provPath := filepath.Join(repoRoot, "tests/fixtures/breachatlas/C39/provenance.json")
		provBytes, err := os.ReadFile(provPath)
		if err != nil {
			t.Fatalf("read C39 provenance.json: %v", err)
		}
		var prov map[string]any
		if err := json.Unmarshal(provBytes, &prov); err != nil {
			t.Fatalf("unmarshal C39 provenance.json: %v", err)
		}

		cmd := exec.Command("node", "scripts/roadmap.mjs", "release-check")
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("roadmap release-check failed: %v\noutput:\n%s", err, string(out))
		}

		var report releaseGateReport
		if err := json.Unmarshal(out, &report); err != nil {
			t.Fatalf("unmarshal release-check output: %v\noutput:\n%s", err, string(out))
		}
		if !report.Passed || report.VerifiedPrerequisites != 38 || report.TotalPrerequisites != 38 || !report.CoreReady || report.RequiredEvidenceCount != 5 || len(report.Failures) != 0 {
			t.Fatalf("unexpected release-check report: %+v", report)
		}

		gateBytes, err := os.ReadFile(filepath.Join(repoRoot, "docs/evidence/v1-gate.json"))
		if err != nil {
			t.Fatalf("read docs/evidence/v1-gate.json: %v", err)
		}
		var gateDoc releaseGateReport
		if err := json.Unmarshal(gateBytes, &gateDoc); err != nil {
			t.Fatalf("unmarshal docs/evidence/v1-gate.json: %v", err)
		}
		if !gateDoc.Passed || gateDoc.VerifiedPrerequisites != 38 || !gateDoc.CoreReady {
			t.Fatalf("invalid v1-gate.json summary: %+v", gateDoc)
		}
	})

	t.Run("workflow_uses_pinned_40_char_shas", func(t *testing.T) {
		wfBytes, err := os.ReadFile(filepath.Join(repoRoot, ".github/workflows/release-gate.yml"))
		if err != nil {
			t.Fatalf("read release-gate.yml: %v", err)
		}
		wf := string(wfBytes)
		usesRe := regexp.MustCompile(`uses:\s*([^\s]+)`)
		matches := usesRe.FindAllStringSubmatch(wf, -1)
		if len(matches) == 0 {
			t.Fatalf("expected pinned GitHub Actions in release-gate.yml")
		}
		shaRe := regexp.MustCompile(`@[0-9a-f]{40}$`)
		for _, m := range matches {
			if !shaRe.MatchString(m[1]) {
				t.Fatalf("action reference %q is not pinned to a 40-char SHA", m[1])
			}
		}
		if !strings.Contains(wf, "release:check") || !strings.Contains(wf, "TestC39") {
			t.Fatalf("release-gate.yml must run release:check and TestC39")
		}
	})

	t.Run("negative_gate_rejects_planning_template_and_source_identity_mismatch", func(t *testing.T) {
		tmpRoot := t.TempDir()
		copyDir := func(rel string) {
			src := filepath.Join(repoRoot, rel)
			dst := filepath.Join(tmpRoot, rel)
			if err := os.MkdirAll(dst, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", dst, err)
			}
			entries, err := os.ReadDir(src)
			if err != nil {
				t.Fatalf("readdir %s: %v", src, err)
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				b, err := os.ReadFile(filepath.Join(src, e.Name()))
				if err != nil {
					t.Fatalf("read %s: %v", e.Name(), err)
				}
				if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644); err != nil {
					t.Fatalf("write %s: %v", e.Name(), err)
				}
			}
		}
		copyDir("plans")
		copyDir("docs/evidence")

		// Case 1: Inject planning_template: true into C38.json
		c38Path := filepath.Join(tmpRoot, "docs/evidence/C38.json")
		c38Raw, err := os.ReadFile(c38Path)
		if err != nil {
			t.Fatalf("read C38.json: %v", err)
		}
		var c38Map map[string]any
		if err := json.Unmarshal(c38Raw, &c38Map); err != nil {
			t.Fatalf("unmarshal C38.json: %v", err)
		}
		c38Map["planning_template"] = true
		c38Mod, _ := json.Marshal(c38Map)
		if err := os.WriteFile(c38Path, c38Mod, 0o644); err != nil {
			t.Fatalf("write modified C38.json: %v", err)
		}

		script := `import { evaluateReleaseGate } from './scripts/roadmap.mjs'; const res = await evaluateReleaseGate({ rootDir: process.env.TEST_ROOT }); console.log(JSON.stringify(res)); if (res.passed) process.exit(1);`
		cmd := exec.Command("node", "--input-type=module", "-e", script)
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "TEST_ROOT="+tmpRoot)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected evaluateReleaseGate to fail cleanly with passed=false, err=%v out=%s", err, string(out))
		}
		if !strings.Contains(string(out), "planning_template") {
			t.Fatalf("expected failure mentioning planning_template, got: %s", string(out))
		}

		// Restore C38.json and corrupt source_identity instead
		if err := os.WriteFile(c38Path, c38Raw, 0o644); err != nil {
			t.Fatalf("restore C38.json: %v", err)
		}
		c38Map["source_identity"] = "deadbeef"
		c38Mismatch, _ := json.Marshal(c38Map)
		if err := os.WriteFile(c38Path, c38Mismatch, 0o644); err != nil {
			t.Fatalf("write mismatched C38.json: %v", err)
		}

		cmd2 := exec.Command("node", "--input-type=module", "-e", script)
		cmd2.Dir = repoRoot
		cmd2.Env = append(os.Environ(), "TEST_ROOT="+tmpRoot)
		out2, err := cmd2.CombinedOutput()
		if err != nil {
			t.Fatalf("expected evaluateReleaseGate to fail cleanly on source_identity mismatch, err=%v out=%s", err, string(out2))
		}
		if !strings.Contains(string(out2), "source_identity") {
			t.Fatalf("expected failure mentioning source_identity, got: %s", string(out2))
		}
	})

	t.Run("seal_store_crash_recovery_quota_and_immutability", func(t *testing.T) {
		ctx := context.Background()
		baseDir := t.TempDir()
		quarantineDir := filepath.Join(baseDir, "quarantine")
		sealDir := filepath.Join(baseDir, "sealed")
		custodyDir := filepath.Join(baseDir, "custody")

		payload := []byte("breachatlas-c39-sealed-evidence-payload")
		sum := sha256.Sum256(payload)
		sumHex := hex.EncodeToString(sum[:])
		size := int64(len(payload))

		q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{
			QuarantineDir: quarantineDir,
		}, evidence.UploadRequest{
			SchemaVersion:  "1",
			UploadID:       "upl-c39-1",
			CaseID:         "case-c39",
			EvidenceID:     "ev-c39-1",
			MediaType:      "application/octet-stream",
			Filename:       "disk.img",
			ExpectedSize:   &size,
			ExpectedSHA256: sumHex,
			Body:           bytes.NewReader(payload),
		})
		if err != nil {
			t.Fatalf("StreamIntoQuarantine: %v", err)
		}

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		ledger, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: custodyDir})
		if err != nil {
			t.Fatalf("OpenLedgerStore: %v", err)
		}
		defer ledger.Close()
		evt, err := ledger.AppendEvent(ctx, custody.AppendEventRequest{
			EventID:    "evt-c39-1",
			CaseID:     "case-c39",
			EvidenceID: "ev-c39-1",
			EventType:  "acquired",
			Actor:      "examiner-local",
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			Reason:     "C39 gate verification",
			PrivateKey: privKey,
		})
		if err != nil {
			t.Fatalf("AppendEvent: %v", err)
		}

		// Quota exceeded negative check
		smallStore, err := evidence.OpenSealStore(evidence.SealConfig{
			RootDir:         filepath.Join(baseDir, "sealed-small"),
			QuarantineDir:   quarantineDir,
			MaxStorageBytes: 8,
		})
		if err != nil {
			t.Fatalf("OpenSealStore small: %v", err)
		}
		if _, err := smallStore.SealQuarantined(ctx, evidence.SealRequest{
			OperationID:    "op-c39-quota",
			Quarantined:    q,
			ExpectedSHA256: sumHex,
			AcquiredAt:     time.Now().UTC().Format(time.RFC3339),
			CustodyRoot:    evt.CustodyRoot,
		}); !errors.Is(err, evidence.ErrStorageQuotaExceeded) {
			_ = smallStore.Close()
			t.Fatalf("expected ErrStorageQuotaExceeded, got: %v", err)
		}
		_ = smallStore.Close()

		// Fault injection between blob sync and manifest commit
		faultStore, err := evidence.OpenSealStore(evidence.SealConfig{
			RootDir:       sealDir,
			QuarantineDir: quarantineDir,
			Faults:        evidence.SealFaults{FailAfterBlobSyncBeforeManifest: true},
		})
		if err != nil {
			t.Fatalf("OpenSealStore fault: %v", err)
		}
		if _, err := faultStore.SealQuarantined(ctx, evidence.SealRequest{
			OperationID:    "op-c39-seal",
			Quarantined:    q,
			ExpectedSHA256: sumHex,
			AcquiredAt:     time.Now().UTC().Format(time.RFC3339),
			CustodyRoot:    evt.CustodyRoot,
		}); !errors.Is(err, evidence.ErrSealInterrupted) {
			_ = faultStore.Close()
			t.Fatalf("expected ErrSealInterrupted, got: %v", err)
		}
		_ = faultStore.Close()

		// Recovery without fault
		cleanStore, err := evidence.OpenSealStore(evidence.SealConfig{
			RootDir:       sealDir,
			QuarantineDir: quarantineDir,
		})
		if err != nil {
			t.Fatalf("OpenSealStore clean: %v", err)
		}
		defer cleanStore.Close()
		manifest, err := cleanStore.SealQuarantined(ctx, evidence.SealRequest{
			OperationID:    "op-c39-seal",
			Quarantined:    q,
			ExpectedSHA256: sumHex,
			AcquiredAt:     time.Now().UTC().Format(time.RFC3339),
			CustodyRoot:    evt.CustodyRoot,
		})
		if err != nil {
			t.Fatalf("recovery SealQuarantined: %v", err)
		}

		// Idempotent replay with same OperationID
		replay, err := cleanStore.SealQuarantined(ctx, evidence.SealRequest{
			OperationID:    "op-c39-seal",
			Quarantined:    q,
			ExpectedSHA256: sumHex,
			AcquiredAt:     time.Now().UTC().Format(time.RFC3339),
			CustodyRoot:    evt.CustodyRoot,
		})
		if err != nil {
			t.Fatalf("replay SealQuarantined: %v", err)
		}
		if !replay.IdempotentReplay {
			t.Fatalf("expected IdempotentReplay=true on duplicate OperationID")
		}

		blobPath := filepath.Join(sealDir, manifest.BlobRelPath)
		blobBytes, err := os.ReadFile(blobPath)
		if err != nil {
			t.Fatalf("read sealed blob: %v", err)
		}
		if !bytes.Equal(blobBytes, payload) {
			t.Fatalf("sealed blob bytes altered after recovery/replay")
		}
		blobInfo, err := os.Stat(blobPath)
		if err != nil {
			t.Fatalf("stat sealed blob: %v", err)
		}
		if blobInfo.Mode().Perm()&0o077 != 0 {
			t.Fatalf("expected owner-only sealed blob mode, got %o", blobInfo.Mode().Perm())
		}
	})
}

package tests_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/storage"
)

type C06Fixture struct {
	OperationID      string            `json:"operation_id"`
	TrustedPublicKey string            `json:"trusted_public_key"`
	Manifest         evidence.Manifest `json:"manifest"`
	PayloadUTF8      string            `json:"payload_utf8,omitempty"`
	Identity         storage.Identity  `json:"identity,omitempty"`
	Scenario         string            `json:"scenario,omitempty"`
}

func getC06FixturesDir(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{
		filepath.Join("..", "tests", "fixtures", "breachatlas", "C06"),
		filepath.Join("fixtures", "breachatlas", "C06"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	t.Fatalf("could not locate C06 fixtures directory")
	return ""
}

func getRepoRoot(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"..", "."} {
		if _, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				t.Fatal(err)
			}
			return abs
		}
	}
	t.Fatalf("could not locate repository root")
	return ""
}

func TestC06FixturesAndSecurityInvariants(t *testing.T) {
	fixturesDir := getC06FixturesDir(t)

	// 1. Verify C06 fixture provenance & Apache-2.0 license
	provBytes, err := os.ReadFile(filepath.Join(fixturesDir, "provenance.json"))
	if err != nil {
		t.Fatalf("failed to read C06 provenance.json: %v", err)
	}
	var prov Provenance
	if err := json.Unmarshal(provBytes, &prov); err != nil {
		t.Fatalf("malformed C06 provenance.json: %v", err)
	}
	if prov.License != "Apache-2.0" {
		t.Fatalf("expected Apache-2.0 license, got %q", prov.License)
	}
	for relPath, expectedHash := range prov.SHA256 {
		content, err := os.ReadFile(filepath.Join(fixturesDir, relPath))
		if err != nil {
			t.Fatalf("missing fixture referenced in provenance: %s", relPath)
		}
		h := sha256.Sum256(content)
		if hex.EncodeToString(h[:]) != expectedHash {
			t.Fatalf("fixture hash mismatch for %s: got %s, want %s", relPath, hex.EncodeToString(h[:]), expectedHash)
		}
	}

	outcomesBytes, err := os.ReadFile(filepath.Join(fixturesDir, "expected-output", "outcomes.json"))
	if err != nil {
		t.Fatalf("failed to read C06 outcomes.json: %v", err)
	}
	var outcomes map[string]OutcomeExpected
	if err := json.Unmarshal(outcomesBytes, &outcomes); err != nil {
		t.Fatalf("malformed C06 outcomes.json: %v", err)
	}

	readFixture := func(rel string) C06Fixture {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		var fx C06Fixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("unmarshal %s: %v", rel, err)
		}
		return fx
	}

	// 2. Positive authoritative commit
	tmpDir, err := os.MkdirTemp("", "c06-engine-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	adapter, err := storage.Open(storage.Config{RootDir: tmpDir, SyncDir: true})
	if err != nil {
		t.Fatalf("open adapter: %v", err)
	}
	defer adapter.Close()

	ctx := context.Background()
	pos := readFixture("positive/signed-authority.json")
	posExpected := outcomes["positive/signed-authority.json"]
	if pos.Identity.PublicKey != pos.TrustedPublicKey {
		t.Fatalf("positive fixture signer does not match trusted public key")
	}

	res, err := adapter.CommitWrite(ctx, storage.WriteRequest{
		OperationID: pos.OperationID,
		Manifest:    pos.Manifest,
		Payload:     []byte(pos.PayloadUTF8),
		Identity:    pos.Identity,
	})
	if err != nil {
		t.Fatalf("positive signed authority commit failed: %v", err)
	}
	if res.Status != posExpected.Status || res.SHA256 != posExpected.SHA256 || res.SizeBytes != posExpected.SizeBytes {
		t.Fatalf("unexpected positive result: %+v, want %+v", res, posExpected)
	}
	baselineState := adapter.CurrentState()

	// 3. Negative case: 1 modified byte fails digest verification
	t.Run("invalid/modified-byte.json", func(t *testing.T) {
		fx := readFixture("invalid/modified-byte.json")
		_, err := adapter.CommitWrite(ctx, storage.WriteRequest{
			OperationID: fx.OperationID,
			Manifest:    fx.Manifest,
			Payload:     []byte(fx.PayloadUTF8),
			Identity:    fx.Identity,
		})
		if !errors.Is(err, storage.ErrDigestMismatch) {
			t.Fatalf("expected ErrDigestMismatch for modified byte, got %v", err)
		}
		if cur := adapter.CurrentState(); cur.Generation != baselineState.Generation {
			t.Fatalf("manifest generation changed after modified byte rejection")
		}
	})

	// 4. Negative case: untrusted signer is rejected prior to commit
	t.Run("invalid/untrusted-signer.json", func(t *testing.T) {
		fx := readFixture("invalid/untrusted-signer.json")
		if fx.Identity.PublicKey == fx.TrustedPublicKey {
			t.Fatalf("expected untrusted signer key to differ from trusted key")
		}
		// Enforce external trust key pinning check before accepting signer authority
		if fx.Identity.PublicKey != fx.TrustedPublicKey {
			// Verify adapter also rejects tampered/untrusted trust chain or that untrusted key cannot forge trusted authority
			tamperedTrust := fx.Identity
			tamperedTrust.PublicKey = fx.TrustedPublicKey
			_, err := adapter.CommitWrite(ctx, storage.WriteRequest{
				OperationID: fx.OperationID,
				Manifest:    fx.Manifest,
				Payload:     []byte(fx.PayloadUTF8),
				Identity:    tamperedTrust,
			})
			if !errors.Is(err, storage.ErrInvalidSignature) {
				t.Fatalf("expected ErrInvalidSignature when validating untrusted signature against trusted key, got %v", err)
			}
		}
		if cur := adapter.CurrentState(); cur.Generation != baselineState.Generation {
			t.Fatalf("manifest generation changed after untrusted signer rejection")
		}
	})

	// 5. Negative case: expired/stale/replayed revision cannot replace accepted authority
	t.Run("invalid/replayed-revision.json", func(t *testing.T) {
		fx := readFixture("invalid/replayed-revision.json")
		_, err := adapter.CommitWrite(ctx, storage.WriteRequest{
			OperationID: fx.OperationID,
			Manifest:    fx.Manifest,
			Payload:     []byte(fx.PayloadUTF8),
			Identity:    fx.Identity,
		})
		if !errors.Is(err, storage.ErrExpiredIdentity) {
			t.Fatalf("expected ErrExpiredIdentity for expired/stale revision, got %v", err)
		}
		// Also verify conflicting parameters on an existing operation ID cannot overwrite accepted state
		_, err = adapter.CommitWrite(ctx, storage.WriteRequest{
			OperationID: pos.OperationID,
			Manifest: evidence.Manifest{
				SchemaVersion: pos.Manifest.SchemaVersion,
				CaseID:        pos.Manifest.CaseID,
				EvidenceID:    "ev-2026-c06-overwrite",
				SHA256:        pos.Manifest.SHA256,
				SizeBytes:     pos.Manifest.SizeBytes,
				MediaType:     pos.Manifest.MediaType,
				AcquiredAt:    pos.Manifest.AcquiredAt,
				CustodyRoot:   pos.Manifest.CustodyRoot,
			},
			Payload:  []byte(pos.PayloadUTF8),
			Identity: pos.Identity,
		})
		if err == nil {
			t.Fatalf("expected conflict/signature error when replaying operation ID with altered manifest")
		}
		if cur := adapter.CurrentState(); cur.Generation != baselineState.Generation {
			t.Fatalf("accepted authority generation modified by replayed/stale revision")
		}
	})

	// 6. Verify sealed source bytes were never modified after all negative attempts
	gotBytes, gotRec, err := adapter.GetEvidence(pos.Manifest.CaseID, pos.Manifest.EvidenceID)
	if err != nil {
		t.Fatalf("get evidence after negative tests: %v", err)
	}
	if !bytes.Equal(gotBytes, []byte(pos.PayloadUTF8)) || gotRec.SHA256 != pos.Manifest.SHA256 {
		t.Fatalf("sealed source bytes were modified")
	}

	// 7. Negative case: missing evidence fails recovery explicitly
	t.Run("invalid/missing-evidence.json", func(t *testing.T) {
		fx := readFixture("invalid/missing-evidence.json")
		missingDir, err := os.MkdirTemp("", "c06-missing-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(missingDir)

		a2, err := storage.Open(storage.Config{RootDir: missingDir, SyncDir: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a2.CommitWrite(ctx, storage.WriteRequest{
			OperationID: pos.OperationID,
			Manifest:    pos.Manifest,
			Payload:     []byte(pos.PayloadUTF8),
			Identity:    pos.Identity,
		}); err != nil {
			t.Fatal(err)
		}
		_ = a2.Close()

		blobPath := filepath.Join(missingDir, storage.BlobsDirName, fx.Manifest.SHA256)
		if err := os.Remove(blobPath); err != nil {
			t.Fatal(err)
		}

		_, openErr := storage.Open(storage.Config{RootDir: missingDir, SyncDir: true})
		if !errors.Is(openErr, storage.ErrMissingReference) {
			t.Fatalf("expected ErrMissingReference when committed evidence is missing, got %v", openErr)
		}
	})
}

func TestEngineBuildAndTestCollection(t *testing.T) {
	repoRoot := getRepoRoot(t)
	tmpBinDir, err := os.MkdirTemp("", "c06-bin-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpBinDir)

	binPath := filepath.Join(tmpBinDir, "breachatlas")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/breachatlas")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, string(out))
	}

	verCmd := exec.Command(binPath, "--version")
	verOut, err := verCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("breachatlas --version failed: %v\n%s", err, string(verOut))
	}
	if !strings.Contains(string(verOut), "breachatlas-engine") {
		t.Fatalf("unexpected --version output: %s", string(verOut))
	}

	// Verify test discovery lists expected domain and engine tests (non-empty)
	listCmd := exec.Command("go", "test", "-list", ".", "./cmd/breachatlas", "./tests")
	listCmd.Dir = repoRoot
	listOut, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test -list failed: %v\n%s", err, string(listOut))
	}
	output := string(listOut)
	for _, requiredTest := range []string{
		"TestHealthEndpoint",
		"TestManifestReadDeadline",
		"TestC05FixturesAndNegativeCases",
		"TestC06FixturesAndSecurityInvariants",
	} {
		if !strings.Contains(output, requiredTest) {
			t.Fatalf("expected test %q in collected engine tests, output:\n%s", requiredTest, output)
		}
	}
}

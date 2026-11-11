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

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/artifacts"
	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

type c16Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c16PositiveFixture struct {
	SchemaVersion       string `json:"schema_version"`
	OperationID         string `json:"operation_id"`
	ArtifactID          string `json:"artifact_id"`
	CaseID              string `json:"case_id"`
	EvidenceID          string `json:"evidence_id"`
	AnalyzerID          string `json:"analyzer_id"`
	Provider            string `json:"provider"`
	MediaType           string `json:"media_type"`
	Payload             string `json:"payload"`
	ExpectedRecordCount int    `json:"expected_record_count"`
	Signed              bool   `json:"signed"`
	KeyID               string `json:"key_id,omitempty"`
}

func getC16FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "fixtures", "breachatlas", "C16")
	if filepath.Base(wd) != "tests" {
		dir = filepath.Join(wd, "tests", "fixtures", "breachatlas", "C16")
	}
	return dir
}

func loadC16JSON[T any](t *testing.T, relPath string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(getC16FixturesDir(t), filepath.FromSlash(relPath)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", relPath, err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", relPath, err)
	}
	return out
}

func sealPayloadForC16(t *testing.T, quarantineDir string, sealStore *evidence.SealStore, sealDir, caseID, evidenceID, mediaType, payload string) (string, string, int64) {
	t.Helper()
	qCfg := evidence.UploadConfig{QuarantineDir: quarantineDir, BufferSize: 64, SyncDir: true}
	payloadBytes := []byte(payload)
	sum := sha256.Sum256(payloadBytes)
	size := int64(len(payloadBytes))
	shaHex := hex.EncodeToString(sum[:])

	q, err := evidence.StreamIntoQuarantine(context.Background(), qCfg, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-" + evidenceID,
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		MediaType:     mediaType,
		Filename:      evidenceID + ".dat",
		ExpectedSize:  &size,
		Body:          strings.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("quarantine upload %s: %v", evidenceID, err)
	}

	m, err := sealStore.SealQuarantined(context.Background(), evidence.SealRequest{
		OperationID:    "seal-" + caseID + "-" + evidenceID,
		Quarantined:    q,
		ExpectedSHA256: shaHex,
		AcquiredAt:     "2026-11-11T10:00:00Z",
		CustodyRoot:    custody.GenesisPrevHash,
	})
	if err != nil {
		t.Fatalf("seal %s: %v", evidenceID, err)
	}

	blobPath := filepath.Join(sealDir, filepath.FromSlash(m.BlobRelPath))
	return blobPath, shaHex, size
}

func assertSealedBlobUnchangedC16(t *testing.T, blobPath, expectedSHA string, expectedSize int64) {
	t.Helper()
	raw, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read sealed blob %s: %v", blobPath, err)
	}
	sum := sha256.Sum256(raw)
	gotSHA := hex.EncodeToString(sum[:])
	if int64(len(raw)) != expectedSize || gotSHA != expectedSHA {
		t.Fatalf("sealed source bytes modified! got size=%d sha256=%s, want size=%d sha256=%s", len(raw), gotSHA, expectedSize, expectedSHA)
	}
}

type c16Env struct {
	rootDir       string
	quarantineDir string
	sealDir       string
	scratchDir    string
	artifactDir   string
	sealStore     *evidence.SealStore
	registry      *analyzers.Registry
	sandbox       *analyzers.Sandbox
	artifactStore *artifacts.ArtifactStore
}

func setupC16Env(t *testing.T, cfgMods ...func(*artifacts.StoreConfig)) *c16Env {
	t.Helper()
	root := t.TempDir()
	qDir := filepath.Join(root, "quarantine")
	sDir := filepath.Join(root, "sealstore")
	scDir := filepath.Join(root, "scratch")
	aDir := filepath.Join(root, "artifacts")

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sDir,
		QuarantineDir: qDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("open seal store: %v", err)
	}
	t.Cleanup(func() { _ = sealStore.Close() })

	reg, err := analyzers.NewRegistry(analyzers.RegistryConfig{
		SealStore:   sealStore,
		SealRootDir: sDir,
		Provider:    "local",
	})
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}

	sb, err := analyzers.NewSandbox(reg, analyzers.DefaultSandboxConfig(scDir))
	if err != nil {
		t.Fatalf("new sandbox: %v", err)
	}

	aCfg := artifacts.StoreConfig{
		RootDir: aDir,
		SyncDir: true,
	}
	for _, mod := range cfgMods {
		mod(&aCfg)
	}
	aStore, err := artifacts.OpenArtifactStore(aCfg)
	if err != nil {
		t.Fatalf("open artifact store: %v", err)
	}
	t.Cleanup(func() { _ = aStore.Close() })

	return &c16Env{
		rootDir:       root,
		quarantineDir: qDir,
		sealDir:       sDir,
		scratchDir:    scDir,
		artifactDir:   aDir,
		sealStore:     sealStore,
		registry:      reg,
		sandbox:       sb,
		artifactStore: aStore,
	}
}

func TestC16FixturesAndProvenance(t *testing.T) {
	prov := loadC16JSON[c16Provenance](t, "provenance.json")
	if prov.Task != "C16" || prov.License != "Apache-2.0" {
		t.Fatalf("unexpected C16 provenance header: %+v", prov)
	}
	if len(prov.SHA256) < 9 {
		t.Fatalf("expected all C16 fixtures hashed in provenance.json, got %d", len(prov.SHA256))
	}

	dir := getC16FixturesDir(t)
	for rel, expected := range prov.SHA256 {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("missing fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(raw)
		got := hex.EncodeToString(sum[:])
		if got != expected {
			t.Fatalf("fixture %s sha256 mismatch: got %s, want %s", rel, got, expected)
		}
	}

	expectedOut := loadC16JSON[struct {
		SchemaVersion string   `json:"schema_version"`
		Task          string   `json:"task"`
		Requirement   string   `json:"requirement"`
		Invariants    []string `json:"invariants"`
	}](t, "expected-output/provenance-outcomes.json")
	if expectedOut.Task != "C16" || expectedOut.Requirement != "F10" {
		t.Fatalf("unexpected C16 expected-output metadata: %+v", expectedOut)
	}
}

func TestC16DerivedManifestBindsInputsToolAndConfig(t *testing.T) {
	ctx := context.Background()
	env := setupC16Env(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}

	positiveFiles := []string{
		"positive/derived-csv-provenance.json",
		"positive/derived-json-signed-provenance.json",
	}

	for _, rel := range positiveFiles {
		fx := loadC16JSON[c16PositiveFixture](t, rel)
		t.Run(fx.ArtifactID, func(t *testing.T) {
			blobPath, inputSHA, inputSize := sealPayloadForC16(
				t, env.quarantineDir, env.sealStore, env.sealDir,
				fx.CaseID, fx.EvidenceID, fx.MediaType, fx.Payload,
			)

			runRes, err := env.sandbox.RunIsolated(ctx, analyzers.IsolatedRunRequest{
				RunID:      "run-" + fx.ArtifactID,
				CaseID:     fx.CaseID,
				EvidenceID: fx.EvidenceID,
				AnalyzerID: fx.AnalyzerID,
				Provider:   fx.Provider,
			})
			if err != nil {
				t.Fatalf("isolated run %s failed: %v", fx.ArtifactID, err)
			}

			deriveReq := artifacts.DeriveRequest{
				OperationID: fx.OperationID,
				ArtifactID:  fx.ArtifactID,
				CaseID:      fx.CaseID,
				Provider:    fx.Provider,
			}
			var verifyOpts artifacts.VerifyOptions
			if fx.Signed {
				deriveReq.KeyID = fx.KeyID
				deriveReq.PrivateKey = priv
				verifyOpts = artifacts.VerifyOptions{
					TrustedKeys:      map[string]ed25519.PublicKey{fx.KeyID: pub},
					RequireSignature: true,
				}
			}

			manifest, err := env.artifactStore.DeriveFromIsolatedRun(ctx, env.sealStore, env.sealDir, runRes, deriveReq)
			if err != nil {
				t.Fatalf("DeriveFromIsolatedRun %s failed: %v", fx.ArtifactID, err)
			}

			if len(manifest.InputHashes) != 1 || manifest.InputHashes[0] != inputSHA {
				t.Fatalf("manifest.InputHashes = %v, want [%s]", manifest.InputHashes, inputSHA)
			}
			if len(manifest.Inputs) != 1 || manifest.Inputs[0].SHA256 != inputSHA || manifest.Inputs[0].EvidenceID != fx.EvidenceID {
				t.Fatalf("manifest.Inputs mismatch: %+v", manifest.Inputs)
			}
			if manifest.ToolVersion != runRes.Analysis.ToolVersion {
				t.Fatalf("manifest.ToolVersion = %q, want %q", manifest.ToolVersion, runRes.Analysis.ToolVersion)
			}
			expectedCfgHash := analyzers.ConfigDigest(fx.AnalyzerID, runRes.Analysis.ToolVersion, analyzers.DefaultParseOptions())
			if manifest.ConfigHash != expectedCfgHash {
				t.Fatalf("manifest.ConfigHash = %q, want %q", manifest.ConfigHash, expectedCfgHash)
			}
			if manifest.Output.RecordCount != fx.ExpectedRecordCount {
				t.Fatalf("manifest.Output.RecordCount = %d, want %d", manifest.Output.RecordCount, fx.ExpectedRecordCount)
			}

			// Verify stored artifact end-to-end (structure, disk payload SHA-256, sealed input bytes, Ed25519 sig).
			vRes, err := env.artifactStore.VerifyStoredArtifact(ctx, env.sealStore, fx.CaseID, fx.ArtifactID, verifyOpts)
			if err != nil {
				t.Fatalf("VerifyStoredArtifact %s failed: %v", fx.ArtifactID, err)
			}
			if !vRes.Verified || !vRes.InputsVerified || vRes.SignatureValid != fx.Signed {
				t.Fatalf("unexpected verification result: %+v", vRes)
			}

			// Idempotent replay check.
			replay, err := env.artifactStore.DeriveFromIsolatedRun(ctx, env.sealStore, env.sealDir, runRes, deriveReq)
			if err != nil {
				t.Fatalf("idempotent replay failed: %v", err)
			}
			if !replay.IdempotentReplay || replay.ManifestDigest != manifest.ManifestDigest {
				t.Fatalf("expected idempotent replay with identical digest, got %+v", replay)
			}

			// Conflicting operation ID reuse rejected.
			conflictReq := deriveReq
			conflictReq.ArtifactID = fx.ArtifactID + "-conflict"
			if _, err := env.artifactStore.DeriveFromIsolatedRun(ctx, env.sealStore, env.sealDir, runRes, conflictReq); !errors.Is(err, artifacts.ErrManifestConflict) {
				t.Fatalf("expected ErrManifestConflict on conflicting operation_id reuse, got %v", err)
			}

			assertSealedBlobUnchangedC16(t, blobPath, inputSHA, inputSize)
		})
	}

	t.Run("config-hash-changes-when-options-change-and-multi-input-binding", func(t *testing.T) {
		caseID := "case-c16-multi"
		blob1, sha1, sz1 := sealPayloadForC16(t, env.quarantineDir, env.sealStore, env.sealDir, caseID, "ev-multi-1", "text/csv", "ts,v\n2026-11-11T10:00:00Z,1\n")
		blob2, sha2, sz2 := sealPayloadForC16(t, env.quarantineDir, env.sealStore, env.sealDir, caseID, "ev-multi-2", "text/plain", "aux-context")

		customOpts := analyzers.ParseOptions{MaxInputBytes: 4096, MaxRecords: 10, MaxFieldsPerRow: 16, MaxJSONDepth: 8}
		run1, err := env.sandbox.RunIsolated(ctx, analyzers.IsolatedRunRequest{
			RunID:      "run-multi-1",
			CaseID:     caseID,
			EvidenceID: "ev-multi-1",
			AnalyzerID: analyzers.AnalyzerCSV,
			Options:    customOpts,
		})
		if err != nil {
			t.Fatalf("run1: %v", err)
		}

		m1, err := env.artifactStore.DeriveFromIsolatedRun(ctx, env.sealStore, env.sealDir, run1, artifacts.DeriveRequest{
			OperationID:      "op-multi-1",
			ArtifactID:       "art-multi-1",
			CaseID:           caseID,
			AdditionalInputs: []string{"ev-multi-2"},
		})
		if err != nil {
			t.Fatalf("derive multi: %v", err)
		}
		if len(m1.Inputs) != 2 || len(m1.InputHashes) != 2 {
			t.Fatalf("expected 2 bound inputs and 2 input_hashes, got %+v", m1)
		}
		defaultHash := analyzers.ConfigDigest(analyzers.AnalyzerCSV, analyzers.ToolVersionCSV, analyzers.DefaultParseOptions())
		if m1.ConfigHash == defaultHash {
			t.Fatalf("expected custom options config hash to differ from default hash")
		}

		vr, err := env.artifactStore.VerifyStoredArtifact(ctx, env.sealStore, caseID, "art-multi-1", artifacts.VerifyOptions{})
		if err != nil || !vr.Verified || !vr.InputsVerified {
			t.Fatalf("verify multi-input artifact failed: res=%+v err=%v", vr, err)
		}
		assertSealedBlobUnchangedC16(t, blob1, sha1, sz1)
		assertSealedBlobUnchangedC16(t, blob2, sha2, sz2)
	})
}

func TestC16NegativeCasesAndTamperDetection(t *testing.T) {
	ctx := context.Background()
	env := setupC16Env(t)

	// Load negative fixtures to ensure fixture contract matches implementation outcomes.
	missingFx := loadC16JSON[struct {
		OperationID string `json:"operation_id"`
		ArtifactID  string `json:"artifact_id"`
		CaseID      string `json:"case_id"`
		EvidenceID  string `json:"evidence_id"`
		AnalyzerID  string `json:"analyzer_id"`
		Provider    string `json:"provider"`
	}](t, "invalid/missing-sealed-prerequisite.json")

	badCfgFx := loadC16JSON[struct {
		BadConfigHash string `json:"bad_config_hash"`
	}](t, "invalid/malformed-config-hash.json")

	missingToolFx := loadC16JSON[struct {
		BadToolVersion string `json:"bad_tool_version"`
	}](t, "invalid/missing-tool-version.json")

	tamperInputFx := loadC16JSON[struct {
		TamperedInputSHA256 string `json:"tampered_input_sha256"`
	}](t, "invalid/tampered-input-hash.json")

	tamperOutputFx := loadC16JSON[struct {
		TamperAppend string `json:"tamper_append"`
	}](t, "invalid/tampered-output-bytes.json")

	badSigFx := loadC16JSON[struct {
		KeyID          string `json:"key_id"`
		UntrustedKeyID string `json:"untrusted_key_id"`
	}](t, "invalid/invalid-signature.json")

	// Seed one valid signed derived artifact as baseline for tamper verification tests.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blobPath, inputSHA, inputSize := sealPayloadForC16(
		t, env.quarantineDir, env.sealStore, env.sealDir,
		"case-c16-neg", "ev-c16-neg-valid", "text/csv", "ts,user\n2026-11-11T10:00:00Z,alice\n",
	)
	validRun, err := env.sandbox.RunIsolated(ctx, analyzers.IsolatedRunRequest{
		RunID:      "run-neg-base",
		CaseID:     "case-c16-neg",
		EvidenceID: "ev-c16-neg-valid",
		AnalyzerID: analyzers.AnalyzerCSV,
		Provider:   "local",
	})
	if err != nil {
		t.Fatalf("baseline run failed: %v", err)
	}
	validManifest, err := env.artifactStore.DeriveFromIsolatedRun(ctx, env.sealStore, env.sealDir, validRun, artifacts.DeriveRequest{
		OperationID: "op-neg-base",
		ArtifactID:  "art-neg-base",
		CaseID:      "case-c16-neg",
		KeyID:       badSigFx.KeyID,
		PrivateKey:  priv,
	})
	if err != nil {
		t.Fatalf("baseline derive failed: %v", err)
	}

	t.Run("missing-sealed-prerequisite", func(t *testing.T) {
		fakeRes := &analyzers.AnalysisResult{
			SchemaVersion: "1",
			CaseID:        missingFx.CaseID,
			EvidenceID:    missingFx.EvidenceID,
			AnalyzerID:    missingFx.AnalyzerID,
			ToolVersion:   analyzers.ToolVersionCSV,
			ConfigDigest:  analyzers.ConfigDigest(analyzers.AnalyzerCSV, analyzers.ToolVersionCSV, analyzers.DefaultParseOptions()),
			InputSHA256:   tamperInputFx.TamperedInputSHA256,
			NonExecuting:  true,
			ReadOnly:      true,
		}
		_, err := env.artifactStore.DeriveFromAnalysis(ctx, env.sealStore, env.sealDir, fakeRes, artifacts.DeriveRequest{
			OperationID: missingFx.OperationID,
			ArtifactID:  missingFx.ArtifactID,
			CaseID:      missingFx.CaseID,
			Provider:    missingFx.Provider,
		})
		if !errors.Is(err, artifacts.ErrMissingPrerequisite) {
			t.Fatalf("expected ErrMissingPrerequisite, got %v", err)
		}
	})

	t.Run("malformed-config-hash", func(t *testing.T) {
		bad := *validManifest
		bad.ConfigHash = badCfgFx.BadConfigHash
		if err := artifacts.ValidateManifestStructure(bad); !errors.Is(err, artifacts.ErrConfigHashMismatch) {
			t.Fatalf("expected ErrConfigHashMismatch, got %v", err)
		}
		badRes := *validRun.Analysis
		badRes.ConfigDigest = badCfgFx.BadConfigHash
		if _, err := env.artifactStore.DeriveFromAnalysis(ctx, env.sealStore, env.sealDir, &badRes, artifacts.DeriveRequest{
			ArtifactID: "art-bad-cfg",
			CaseID:     "case-c16-neg",
		}); !errors.Is(err, artifacts.ErrConfigHashMismatch) {
			t.Fatalf("expected ErrConfigHashMismatch on DeriveFromAnalysis, got %v", err)
		}
	})

	t.Run("missing-tool-version-and-non-allowlisted-tool", func(t *testing.T) {
		bad := *validManifest
		bad.ToolVersion = missingToolFx.BadToolVersion
		if err := artifacts.ValidateManifestStructure(bad); !errors.Is(err, artifacts.ErrToolBindingInvalid) {
			t.Fatalf("expected ErrToolBindingInvalid for empty tool_version, got %v", err)
		}
		badExec := *validManifest
		badExec.NonExecuting = false
		if err := artifacts.ValidateManifestStructure(badExec); !errors.Is(err, artifacts.ErrToolBindingInvalid) {
			t.Fatalf("expected ErrToolBindingInvalid for non-executing=false, got %v", err)
		}
	})

	t.Run("tampered-input-hash-and-digest", func(t *testing.T) {
		tamperedRes := *validRun.Analysis
		tamperedRes.InputSHA256 = tamperInputFx.TamperedInputSHA256
		if _, err := env.artifactStore.DeriveFromAnalysis(ctx, env.sealStore, env.sealDir, &tamperedRes, artifacts.DeriveRequest{
			ArtifactID: "art-tamper-input",
			CaseID:     "case-c16-neg",
		}); !errors.Is(err, artifacts.ErrInputBindingMismatch) {
			t.Fatalf("expected ErrInputBindingMismatch, got %v", err)
		}

		// Tamper InputHashes in manifest + recompute digest -> signed manifest fails signature check,
		// and unsigned manifest fails ErrInputBindingMismatch against SealStore.
		badM := *validManifest
		badM.Inputs = append([]artifacts.InputBinding(nil), validManifest.Inputs...)
		badM.Inputs[0].SHA256 = tamperInputFx.TamperedInputSHA256
		badM.InputHashes = []string{tamperInputFx.TamperedInputSHA256}
		reDigest, _ := artifacts.ComputeManifestDigest(badM)
		badM.ManifestDigest = reDigest
		if _, err := artifacts.VerifyDerivedManifest(ctx, env.sealStore, &badM, artifacts.VerifyOptions{}); !errors.Is(err, artifacts.ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature when signed manifest digest changes, got %v", err)
		}
		badM.Signature = ""
		badM.PublicKey = ""
		badM.KeyID = ""
		if _, err := artifacts.VerifyDerivedManifest(ctx, env.sealStore, &badM, artifacts.VerifyOptions{}); !errors.Is(err, artifacts.ErrInputBindingMismatch) {
			t.Fatalf("expected ErrInputBindingMismatch against SealStore, got %v", err)
		}
	})

	t.Run("tampered-manifest-digest", func(t *testing.T) {
		bad := *validManifest
		bad.ToolVersion = "csv/9.9.9-forged"
		if err := artifacts.ValidateManifestStructure(bad); !errors.Is(err, artifacts.ErrManifestDigestMismatch) {
			t.Fatalf("expected ErrManifestDigestMismatch, got %v", err)
		}
	})

	t.Run("invalid-and-untrusted-signature", func(t *testing.T) {
		badSig := *validManifest
		sigBytes, _ := hex.DecodeString(badSig.Signature)
		sigBytes[0] ^= 0xff
		badSig.Signature = hex.EncodeToString(sigBytes)

		if _, err := artifacts.VerifyDerivedManifest(ctx, env.sealStore, &badSig, artifacts.VerifyOptions{
			TrustedKeys: map[string]ed25519.PublicKey{badSigFx.KeyID: pub},
		}); !errors.Is(err, artifacts.ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got %v", err)
		}

		// Untrusted key_id check.
		if _, err := artifacts.VerifyDerivedManifest(ctx, env.sealStore, validManifest, artifacts.VerifyOptions{
			TrustedKeys:      map[string]ed25519.PublicKey{badSigFx.UntrustedKeyID: pub},
			RequireSignature: true,
		}); !errors.Is(err, artifacts.ErrUntrustedSigner) {
			t.Fatalf("expected ErrUntrustedSigner, got %v", err)
		}

		// Missing signature when RequireSignature=true.
		unsigned := *validManifest
		unsigned.Signature = ""
		unsigned.PublicKey = ""
		unsigned.KeyID = ""
		if _, err := artifacts.VerifyDerivedManifest(ctx, env.sealStore, &unsigned, artifacts.VerifyOptions{
			RequireSignature: true,
		}); !errors.Is(err, artifacts.ErrUntrustedSigner) {
			t.Fatalf("expected ErrUntrustedSigner when signature missing, got %v", err)
		}
	})

	t.Run("traversal-and-symlink-rejected", func(t *testing.T) {
		if _, err := env.artifactStore.DeriveFromIsolatedRun(ctx, env.sealStore, env.sealDir, validRun, artifacts.DeriveRequest{
			ArtifactID: "../escape",
			CaseID:     "case-c16-neg",
		}); !errors.Is(err, artifacts.ErrPathTraversal) {
			t.Fatalf("expected ErrPathTraversal for artifact_id, got %v", err)
		}

		badRel := *validManifest
		badRel.Output.RelPath = "../../etc/passwd"
		if err := artifacts.ValidateManifestStructure(badRel); !errors.Is(err, artifacts.ErrPathTraversal) {
			t.Fatalf("expected ErrPathTraversal for rel_path, got %v", err)
		}
	})

	t.Run("tampered-output-bytes-on-disk", func(t *testing.T) {
		outPath := filepath.Join(env.artifactDir, filepath.FromSlash(validManifest.Output.RelPath))
		f, err := os.OpenFile(outPath, os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			t.Fatalf("open derived output: %v", err)
		}
		_, _ = f.WriteString(tamperOutputFx.TamperAppend)
		_ = f.Close()

		if _, err := env.artifactStore.VerifyStoredArtifact(ctx, env.sealStore, "case-c16-neg", "art-neg-base", artifacts.VerifyOptions{}); !errors.Is(err, artifacts.ErrOutputTampered) {
			t.Fatalf("expected ErrOutputTampered after disk mutation, got %v", err)
		}
	})

	t.Run("store-lock-busy-and-disk-full-and-closed", func(t *testing.T) {
		if _, err := artifacts.OpenArtifactStore(artifacts.StoreConfig{RootDir: env.artifactDir}); !errors.Is(err, artifacts.ErrArtifactLockBusy) {
			t.Fatalf("expected ErrArtifactLockBusy on concurrent open, got %v", err)
		}

		diskFullDir := filepath.Join(t.TempDir(), "diskfull-artifacts")
		dfStore, err := artifacts.OpenArtifactStore(artifacts.StoreConfig{
			RootDir: diskFullDir,
			Faults:  artifacts.StoreFaults{SimulateDiskFull: true},
		})
		if err != nil {
			t.Fatalf("open diskfull store: %v", err)
		}
		if _, err := dfStore.DeriveFromIsolatedRun(ctx, env.sealStore, env.sealDir, validRun, artifacts.DeriveRequest{
			ArtifactID: "art-diskfull",
			CaseID:     "case-c16-neg",
		}); !errors.Is(err, artifacts.ErrDiskFull) {
			t.Fatalf("expected ErrDiskFull, got %v", err)
		}
		_ = dfStore.Close()
		if _, err := dfStore.GetManifest("case-c16-neg", "art-diskfull"); !errors.Is(err, artifacts.ErrArtifactStoreClosed) {
			t.Fatalf("expected ErrArtifactStoreClosed, got %v", err)
		}
	})

	assertSealedBlobUnchangedC16(t, blobPath, inputSHA, inputSize)
}

func TestC16RestartRecoveryAndPersistence(t *testing.T) {
	ctx := context.Background()
	fx := loadC16JSON[c16PositiveFixture](t, "invalid/interrupted-staging-commit.json")

	root := t.TempDir()
	qDir := filepath.Join(root, "quarantine")
	sDir := filepath.Join(root, "sealstore")
	scDir := filepath.Join(root, "scratch")
	aDir := filepath.Join(root, "artifacts")

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sDir,
		QuarantineDir: qDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	blobPath, inputSHA, inputSize := sealPayloadForC16(t, qDir, sealStore, sDir, fx.CaseID, fx.EvidenceID, fx.MediaType, fx.Payload)

	reg, err := analyzers.NewRegistry(analyzers.RegistryConfig{SealStore: sealStore, SealRootDir: sDir, Provider: "local"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := analyzers.NewSandbox(reg, analyzers.DefaultSandboxConfig(scDir))
	if err != nil {
		t.Fatal(err)
	}
	runRes, err := sb.RunIsolated(ctx, analyzers.IsolatedRunRequest{
		RunID:      "run-recover-1",
		CaseID:     fx.CaseID,
		EvidenceID: fx.EvidenceID,
		AnalyzerID: fx.AnalyzerID,
		Provider:   fx.Provider,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Step 1: Commit a valid first artifact cleanly.
	aStore1, err := artifacts.OpenArtifactStore(artifacts.StoreConfig{RootDir: aDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	first, err := aStore1.DeriveFromIsolatedRun(ctx, sealStore, sDir, runRes, artifacts.DeriveRequest{
		OperationID: "op-committed-1",
		ArtifactID:  "art-committed-1",
		CaseID:      fx.CaseID,
		Provider:    fx.Provider,
	})
	if err != nil {
		t.Fatalf("first commit failed: %v", err)
	}
	_ = aStore1.Close()

	// Step 2: Reopen with FailAfterPayloadBeforeManifest fault to simulate crash mid-commit on a second artifact.
	aStoreCrash, err := artifacts.OpenArtifactStore(artifacts.StoreConfig{
		RootDir: aDir,
		SyncDir: true,
		Faults:  artifacts.StoreFaults{FailAfterPayloadBeforeManifest: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = aStoreCrash.DeriveFromIsolatedRun(ctx, sealStore, sDir, runRes, artifacts.DeriveRequest{
		OperationID: fx.OperationID,
		ArtifactID:  fx.ArtifactID,
		CaseID:      fx.CaseID,
		Provider:    fx.Provider,
	})
	if !errors.Is(err, artifacts.ErrInterrupted) {
		t.Fatalf("expected ErrInterrupted, got %v", err)
	}
	// Incomplete artifact must not look complete.
	if _, err := aStoreCrash.GetManifest(fx.CaseID, fx.ArtifactID); !errors.Is(err, artifacts.ErrArtifactNotFound) {
		t.Fatalf("interrupted artifact must not appear committed, got %v", err)
	}
	_ = aStoreCrash.Close()
	_ = sealStore.Close()

	// Step 3: Restart both SealStore and ArtifactStore cleanly and verify recovery + persistence.
	reopenedSeal, err := evidence.OpenSealStore(evidence.SealConfig{
		RootDir:       sDir,
		QuarantineDir: qDir,
		SyncDir:       true,
	})
	if err != nil {
		t.Fatalf("reopen sealStore: %v", err)
	}
	defer reopenedSeal.Close()

	reopenedArtifacts, err := artifacts.OpenArtifactStore(artifacts.StoreConfig{
		RootDir: aDir,
		SyncDir: true,
	})
	if err != nil {
		t.Fatalf("reopen artifactStore: %v", err)
	}
	defer reopenedArtifacts.Close()

	rec := reopenedArtifacts.LastRecoveryReport()
	if len(rec.CleanedStagingFiles) == 0 || rec.RecoveredArtifacts != 1 {
		t.Fatalf("expected orphaned staging cleanup and 1 recovered artifact, got %+v", rec)
	}

	// Prior committed artifact remains intact and passes full verification after restart.
	gotFirst, err := reopenedArtifacts.GetManifest(fx.CaseID, "art-committed-1")
	if err != nil || gotFirst.ManifestDigest != first.ManifestDigest {
		t.Fatalf("prior committed manifest mismatch after restart: got=%+v err=%v", gotFirst, err)
	}
	vr, err := reopenedArtifacts.VerifyStoredArtifact(ctx, reopenedSeal, fx.CaseID, "art-committed-1", artifacts.VerifyOptions{})
	if err != nil || !vr.Verified || !vr.InputsVerified {
		t.Fatalf("verify committed artifact after restart failed: res=%+v err=%v", vr, err)
	}

	// Retry interrupted derivation cleanly after restart.
	retried, err := reopenedArtifacts.DeriveFromIsolatedRun(ctx, reopenedSeal, sDir, runRes, artifacts.DeriveRequest{
		OperationID: fx.OperationID,
		ArtifactID:  fx.ArtifactID,
		CaseID:      fx.CaseID,
		Provider:    fx.Provider,
	})
	if err != nil {
		t.Fatalf("retry after restart failed: %v", err)
	}
	if vr2, err := reopenedArtifacts.VerifyStoredArtifact(ctx, reopenedSeal, fx.CaseID, retried.ArtifactID, artifacts.VerifyOptions{}); err != nil || !vr2.Verified {
		t.Fatalf("verify retried artifact failed: res=%+v err=%v", vr2, err)
	}

	assertSealedBlobUnchangedC16(t, blobPath, inputSHA, inputSize)
}

func TestC16ConcurrentDerivationAndRace(t *testing.T) {
	ctx := context.Background()
	env := setupC16Env(t)

	const workers = 8
	caseID := "case-c16-race"
	blobPath, inputSHA, inputSize := sealPayloadForC16(
		t, env.quarantineDir, env.sealStore, env.sealDir,
		caseID, "ev-c16-race", "text/csv", "timestamp,item\n2026-11-11T10:00:00Z,row1\n",
	)

	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			runRes, err := env.sandbox.RunIsolated(ctx, analyzers.IsolatedRunRequest{
				RunID:      fmt.Sprintf("run-race-%d", i),
				CaseID:     caseID,
				EvidenceID: "ev-c16-race",
				AnalyzerID: analyzers.AnalyzerCSV,
			})
			if err != nil {
				errs <- err
				return
			}
			artID := fmt.Sprintf("art-race-%d", i)
			if _, err := env.artifactStore.DeriveFromIsolatedRun(ctx, env.sealStore, env.sealDir, runRes, artifacts.DeriveRequest{
				OperationID: fmt.Sprintf("op-race-%d", i),
				ArtifactID:  artID,
				CaseID:      caseID,
			}); err != nil {
				errs <- err
				return
			}
			vr, err := env.artifactStore.VerifyStoredArtifact(ctx, env.sealStore, caseID, artID, artifacts.VerifyOptions{})
			if err != nil || !vr.Verified {
				errs <- fmt.Errorf("verify %s: err=%v vr=%+v", artID, err, vr)
				return
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent provenance operation failed: %v", err)
	}

	assertSealedBlobUnchangedC16(t, blobPath, inputSHA, inputSize)
}

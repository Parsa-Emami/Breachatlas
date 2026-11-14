package tests_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/storage"
)

type c29Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c29PositiveFixture struct {
	SchemaVersion        string   `json:"schema_version"`
	FixtureID            string   `json:"fixture_id"`
	CaseID               string   `json:"case_id"`
	EvidenceID           string   `json:"evidence_id"`
	SealedPayload        string   `json:"sealed_payload"`
	RequiredProviders    []string `json:"required_providers"`
	MaxDiagnosticEntries int      `json:"max_diagnostic_entries"`
	MaxDiagnosticBytes   int      `json:"max_diagnostic_bytes"`
}

type c29InvalidFixture struct {
	SchemaVersion            string   `json:"schema_version"`
	MissingStoragePathSuffix string   `json:"missing_storage_path_suffix"`
	UnavailableProviders     []string `json:"unavailable_providers"`
}

func getC29FixturesDir(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{
		filepath.Join("..", "tests", "fixtures", "breachatlas", "C29"),
		filepath.Join("fixtures", "breachatlas", "C29"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	t.Fatalf("could not locate C29 fixtures directory")
	return ""
}

func reserveFreeLoopbackPortC29(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func buildEngineBinaryC29(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "breachatlas-c29-test")
	repoRoot := filepath.Join("..")
	if _, err := os.Stat(filepath.Join(repoRoot, "go.mod")); err != nil {
		repoRoot = "."
	}
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/breachatlas")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build engine binary failed: %v\n%s", err, string(out))
	}
	return binPath
}

func startEngineProcessC29(t *testing.T, binPath string, port int, args ...string) (*exec.Cmd, func()) {
	t.Helper()
	fullArgs := append([]string{"--host", "127.0.0.1", "--port", strconv.Itoa(port)}, args...)
	cmd := exec.Command(binPath, fullArgs...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}

	readyCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var line map[string]any
			if json.Unmarshal(scanner.Bytes(), &line) == nil {
				if line["status"] == "listening" {
					readyCh <- nil
					// Drain remaining stdout until process exits
					_, _ = io.Copy(io.Discard, stdout)
					return
				}
			}
		}
		readyCh <- fmt.Errorf("engine exited before listening; stderr=%s", stderrBuf.String())
	}()

	select {
	case err := <-readyCh:
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("timed out waiting for engine startup; stderr=%s", stderrBuf.String())
	}

	stop := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		}
	}
	return cmd, stop
}

func TestC29FixturesAndProvenance(t *testing.T) {
	fixturesDir := getC29FixturesDir(t)
	provBytes, err := os.ReadFile(filepath.Join(fixturesDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read provenance.json: %v", err)
	}
	var prov c29Provenance
	if err := json.Unmarshal(provBytes, &prov); err != nil {
		t.Fatalf("parse provenance.json: %v", err)
	}
	if prov.Task != "C29" || prov.License != "Apache-2.0" {
		t.Fatalf("unexpected provenance metadata: %+v", prov)
	}
	if len(prov.SHA256) != 3 {
		t.Fatalf("expected 3 fixture hashes, got %d", len(prov.SHA256))
	}
	for rel, expected := range prov.SHA256 {
		data, err := os.ReadFile(filepath.Join(fixturesDir, rel))
		if err != nil {
			t.Fatalf("read fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(data)
		actual := hex.EncodeToString(sum[:])
		if actual != expected {
			t.Fatalf("fixture %s hash mismatch: got %s want %s", rel, actual, expected)
		}
	}
}

func TestC29RestartRecoveryAndSealedByteImmutability(t *testing.T) {
	fixturesDir := getC29FixturesDir(t)
	posBytes, err := os.ReadFile(filepath.Join(fixturesDir, "positive", "readiness-and-diagnostics.json"))
	if err != nil {
		t.Fatal(err)
	}
	invBytes, err := os.ReadFile(filepath.Join(fixturesDir, "invalid", "degraded-and-secret-sentinels.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pos c29PositiveFixture
	var inv c29InvalidFixture
	if err := json.Unmarshal(posBytes, &pos); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(invBytes, &inv); err != nil {
		t.Fatal(err)
	}

	// Seed authoritative storage with real signed evidence so sealed blob immutability is proven across probes and restart.
	storageDir := filepath.Join(t.TempDir(), "authoritative-storage")
	adapter, err := storage.Open(storage.Config{RootDir: storageDir, SyncDir: true})
	if err != nil {
		t.Fatalf("open authoritative storage: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(pos.SealedPayload)
	sum := sha256.Sum256(payload)
	shaHex := hex.EncodeToString(sum[:])
	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	opID := "op-c29-seal-01"
	sig := ed25519.Sign(priv, storage.CanonicalSigningBytes(opID, pos.CaseID, pos.EvidenceID, shaHex, expiresAt))

	_, err = adapter.CommitWrite(context.Background(), storage.WriteRequest{
		OperationID: opID,
		Payload:     payload,
		Manifest: evidence.Manifest{
			SchemaVersion: "1",
			CaseID:        pos.CaseID,
			EvidenceID:    pos.EvidenceID,
			MediaType:     "text/plain",
			AcquiredAt:    "2026-11-14T08:00:00Z",
			CustodyRoot:   strings.Repeat("0", 64),
			SHA256:        shaHex,
			SizeBytes:     int64(len(payload)),
		},
		Identity: storage.Identity{
			Principal: "analyst-ops",
			Role:      "analyst",
			CaseScope: pos.CaseID,
			PublicKey: hex.EncodeToString(pub),
			ExpiresAt: expiresAt,
			Signature: hex.EncodeToString(sig),
			Provider:  "local",
		},
	})
	if err != nil {
		t.Fatalf("commit authoritative evidence: %v", err)
	}
	state := adapter.CurrentState()
	evRec, ok := state.Evidence[pos.CaseID+"/"+pos.EvidenceID]
	if !ok {
		t.Fatalf("expected sealed evidence record in state")
	}
	blobPath := filepath.Join(storageDir, filepath.FromSlash(evRec.BlobPath))
	preBlobBytes, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read sealed blob before probes: %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("close storage adapter before engine boot: %v", err)
	}

	binPath := buildEngineBinaryC29(t)

	// Phase 1: Start engine pointing to missing storage prerequisite -> /healthz 200, /readyz 503 storage_prerequisite_missing
	missingDir := filepath.Join(t.TempDir(), inv.MissingStoragePathSuffix)
	port1 := reserveFreeLoopbackPortC29(t)
	_, stop1 := startEngineProcessC29(t, binPath, port1,
		"--storage-dir", missingDir,
		"--required-providers", strings.Join(pos.RequiredProviders, ","),
	)
	base1 := fmt.Sprintf("http://127.0.0.1:%d", port1)

	hResp, err := http.Get(base1 + "/healthz")
	if err != nil {
		stop1()
		t.Fatalf("healthz request failed: %v", err)
	}
	_ = hResp.Body.Close()
	if hResp.StatusCode != http.StatusOK {
		stop1()
		t.Fatalf("expected /healthz 200 even when storage missing, got %d", hResp.StatusCode)
	}

	rResp, err := http.Get(base1 + "/readyz")
	if err != nil {
		stop1()
		t.Fatalf("readyz request failed: %v", err)
	}
	rBody, _ := io.ReadAll(rResp.Body)
	_ = rResp.Body.Close()
	if rResp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(rBody), "storage_prerequisite_missing") {
		stop1()
		t.Fatalf("expected 503 storage_prerequisite_missing, got %d (%s)", rResp.StatusCode, string(rBody))
	}
	stop1()

	// Phase 2: Start engine with unavailable required provider -> /healthz 200, /api/v1/diagnostics 503 provider_unavailable
	port2 := reserveFreeLoopbackPortC29(t)
	_, stop2 := startEngineProcessC29(t, binPath, port2,
		"--storage-dir", storageDir,
		"--required-providers", strings.Join(inv.UnavailableProviders, ","),
	)
	base2 := fmt.Sprintf("http://127.0.0.1:%d", port2)

	dResp, err := http.Get(base2 + "/api/v1/diagnostics")
	if err != nil {
		stop2()
		t.Fatalf("diagnostics request failed: %v", err)
	}
	dBody, _ := io.ReadAll(dResp.Body)
	_ = dResp.Body.Close()
	if dResp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(dBody), "provider_unavailable") {
		stop2()
		t.Fatalf("expected 503 provider_unavailable, got %d (%s)", dResp.StatusCode, string(dBody))
	}
	stop2()

	// Phase 3: Restart engine with valid authoritative storage and allowlisted providers -> 200 ready and intact operations/evidence count
	port3 := reserveFreeLoopbackPortC29(t)
	_, stop3 := startEngineProcessC29(t, binPath, port3,
		"--storage-dir", storageDir,
		"--required-providers", strings.Join(pos.RequiredProviders, ","),
	)
	defer stop3()
	base3 := fmt.Sprintf("http://127.0.0.1:%d", port3)

	okReady, err := http.Get(base3 + "/readyz")
	if err != nil {
		t.Fatalf("healthy readyz failed: %v", err)
	}
	okBody, _ := io.ReadAll(okReady.Body)
	_ = okReady.Body.Close()
	if okReady.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after restart recovery, got %d (%s)", okReady.StatusCode, string(okBody))
	}

	var parsed struct {
		Status         string `json:"status"`
		EngineReady    bool   `json:"engineReady"`
		StorageReady   bool   `json:"storageReady"`
		ProvidersReady bool   `json:"providersReady"`
		Storage        struct {
			OperationsCount int `json:"operations_count"`
			EvidenceCount   int `json:"evidence_count"`
		} `json:"storage"`
	}
	if err := json.Unmarshal(okBody, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Status != "ready" || !parsed.EngineReady || !parsed.StorageReady || !parsed.ProvidersReady {
		t.Fatalf("unexpected readiness recovery report: %+v", parsed)
	}
	if parsed.Storage.OperationsCount != 1 || parsed.Storage.EvidenceCount != 1 {
		t.Fatalf("expected 1 operation and 1 sealed evidence preserved after probes/restart, got %+v", parsed.Storage)
	}

	// Phase 4: Verify sealed source bytes never modified across readiness probes & restarts
	postBlobBytes, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read sealed blob after restart: %v", err)
	}
	if !bytes.Equal(preBlobBytes, postBlobBytes) {
		t.Fatalf("INVARIANT VIOLATION: sealed source bytes changed during readiness verification")
	}
}

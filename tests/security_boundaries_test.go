package tests_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/cases"
	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/findings"
	"github.com/Parsa-Emami/Breachatlas/internal/holds"
	"github.com/Parsa-Emami/Breachatlas/internal/retention"
	"github.com/Parsa-Emami/Breachatlas/internal/storage"
)

type c27Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

type c27PositiveFixture struct {
	SchemaVersion string            `json:"schema_version"`
	OperationID   string            `json:"operation_id"`
	Manifest      evidence.Manifest `json:"manifest"`
	PayloadUTF8   string            `json:"payload_utf8"`
	Identity      storage.Identity  `json:"identity"`
}

type c27StorageCase struct {
	Name          string            `json:"name"`
	OperationID   string            `json:"operation_id"`
	CaseID        string            `json:"case_id,omitempty"`
	Identity      storage.Identity  `json:"identity"`
	Headers       map[string]string `json:"headers,omitempty"`
	ExpectedError string            `json:"expected_error"`
	UntrustedPub  string            `json:"untrusted_pub,omitempty"`
}

type c27HTTPCase struct {
	Name         string            `json:"name"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Host         string            `json:"host,omitempty"`
	Origin       string            `json:"origin,omitempty"`
	SecFetchSite string            `json:"sec_fetch_site,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
	Body         json.RawMessage   `json:"body,omitempty"`
	WantStatus   int               `json:"want_status"`
	WantCode     string            `json:"want_code"`
}

type c27AbuseCasesFixture struct {
	SchemaVersion        string           `json:"schema_version"`
	StorageAndCaseCases  []c27StorageCase `json:"storage_and_case_cases"`
	HTTPAndUIAbuseCases  []c27HTTPCase    `json:"http_and_ui_abuse_cases"`
}

type c27ExpectedOutcomes struct {
	SchemaVersion            string            `json:"schema_version"`
	SealedBytesModified      bool              `json:"sealed_bytes_modified"`
	XSSExecuted              bool              `json:"xss_executed"`
	StorageAndCaseRejections map[string]string `json:"storage_and_case_rejections"`
	DomainRejections         map[string]string `json:"domain_rejections"`
}

func getC27FixturesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		cand := filepath.Join(dir, "tests", "fixtures", "breachatlas", "C27")
		if info, err := os.Stat(cand); err == nil && info.IsDir() {
			return cand
		}
	}
	t.Fatalf("could not locate tests/fixtures/breachatlas/C27 from %s", wd)
	return ""
}

func loadC27JSON[T any](t *testing.T, rel string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(getC27FixturesDir(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read C27 fixture %s: %v", rel, err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal C27 fixture %s: %v", rel, err)
	}
	return out
}

func TestC27FixturesAndProvenance(t *testing.T) {
	dir := getC27FixturesDir(t)
	prov := loadC27JSON[c27Provenance](t, "provenance.json")
	if prov.Task != "C27" || prov.License != "Apache-2.0" {
		t.Fatalf("unexpected C27 provenance metadata: %+v", prov)
	}
	if len(prov.SHA256) != 3 {
		t.Fatalf("expected 3 C27 fixture hashes in provenance.json, got %d", len(prov.SHA256))
	}
	for rel, wantHex := range prov.SHA256 {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("missing C27 fixture %s: %v", rel, err)
		}
		sum := sha256.Sum256(raw)
		gotHex := hex.EncodeToString(sum[:])
		if gotHex != wantHex {
			t.Fatalf("C27 fixture hash mismatch for %s: got %s, want %s", rel, gotHex, wantHex)
		}
	}
}

func TestC27StorageAndCaseAuthorizationBoundaries(t *testing.T) {
	pos := loadC27JSON[c27PositiveFixture](t, "positive/authorized-security-baseline.json")
	abuse := loadC27JSON[c27AbuseCasesFixture](t, "invalid/security-abuse-cases.json")
	outcomes := loadC27JSON[c27ExpectedOutcomes](t, "expected-output/security-outcomes.json")

	root := t.TempDir()
	adapter, err := storage.Open(storage.Config{RootDir: root, SyncDir: true})
	if err != nil {
		t.Fatalf("open storage adapter: %v", err)
	}
	defer adapter.Close()

	reg, err := cases.NewRegistry(adapter)
	if err != nil {
		t.Fatalf("new case registry: %v", err)
	}

	if _, err := reg.CreateCase(cases.CreateCaseInput{
		CaseID:         pos.Manifest.CaseID,
		Title:          "C27 Security Baseline Case",
		Classification: "confidential",
		Owner:          pos.Identity.Principal,
		Provider:       "local",
	}); err != nil {
		t.Fatalf("create baseline case: %v", err)
	}
	if _, err := reg.CreateCase(cases.CreateCaseInput{
		CaseID:         "case-other-999",
		Title:          "Unrelated Case",
		Classification: "restricted",
		Owner:          "other-lead",
		Provider:       "local",
	}); err != nil {
		t.Fatalf("create unrelated case: %v", err)
	}

	ctx := context.Background()
	item, err := reg.RegisterEvidence(ctx, cases.RegisterEvidenceRequest{
		OperationID: pos.OperationID,
		Manifest:    pos.Manifest,
		Payload:     []byte(pos.PayloadUTF8),
		Identity:    pos.Identity,
	})
	if err != nil {
		t.Fatalf("baseline authorized RegisterEvidence failed: %v", err)
	}
	if item.SHA256 != pos.Manifest.SHA256 || !item.Sealed {
		t.Fatalf("unexpected registered item: %+v", item)
	}

	baselineState := adapter.CurrentState()
	blobPath := filepath.Join(root, storage.BlobsDirName, pos.Manifest.SHA256)
	beforeBytes, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read committed blob: %v", err)
	}

	errLookup := map[string]error{
		"ErrMissingIdentity":     storage.ErrMissingIdentity,
		"ErrExpiredIdentity":     storage.ErrExpiredIdentity,
		"ErrReplayedIdentity":    storage.ErrReplayedIdentity,
		"ErrScopeMismatch":       storage.ErrScopeMismatch,
		"ErrInvalidSignature":    storage.ErrInvalidSignature,
		"ErrForgedHeader":        storage.ErrForgedHeader,
		"ErrWidenedPath":         storage.ErrWidenedPath,
		"ErrUnavailableProvider": storage.ErrUnavailableProvider,
		"ErrCrossCaseAccess":     cases.ErrCrossCaseAccess,
	}

	for _, tc := range abuse.StorageAndCaseCases {
		t.Run(tc.Name, func(t *testing.T) {
			wantName, ok := outcomes.StorageAndCaseRejections[tc.Name]
			if !ok {
				t.Fatalf("missing expected outcome for %s", tc.Name)
			}
			wantErr, ok := errLookup[wantName]
			if !ok {
				t.Fatalf("unknown expected error %q", wantName)
			}

			manifest := pos.Manifest
			if tc.CaseID != "" {
				manifest.CaseID = tc.CaseID
			}
			identity := tc.Identity
			if len(tc.Headers) > 0 && identity.Principal == "" {
				identity = pos.Identity
			}

			var gotErr error
			if tc.Name == "cross_case_access" {
				_, gotErr = reg.RegisterEvidence(ctx, cases.RegisterEvidenceRequest{
					OperationID: tc.OperationID,
					Manifest:    manifest,
					Payload:     []byte(pos.PayloadUTF8),
					Identity:    identity,
					Headers:     tc.Headers,
				})
			} else {
				_, gotErr = adapter.CommitWrite(ctx, storage.WriteRequest{
					OperationID: tc.OperationID,
					Manifest:    manifest,
					Payload:     []byte(pos.PayloadUTF8),
					Identity:    identity,
					Headers:     tc.Headers,
				})
			}

			if !errors.Is(gotErr, wantErr) {
				t.Fatalf("%s: expected error %v, got %v", tc.Name, wantErr, gotErr)
			}

			// Verify state generation, total bytes, and sealed blob bytes never changed
			cur := adapter.CurrentState()
			if cur.Generation != baselineState.Generation || cur.TotalBytes != baselineState.TotalBytes {
				t.Fatalf("%s: storage state mutated after rejection", tc.Name)
			}
			afterBytes, readErr := os.ReadFile(blobPath)
			if readErr != nil || !bytes.Equal(beforeBytes, afterBytes) {
				t.Fatalf("%s: sealed source bytes modified", tc.Name)
			}
		})
	}

	// Explicit cross-case read check
	if _, _, err := reg.GetEvidence("case-other-999", pos.Manifest.EvidenceID); !errors.Is(err, cases.ErrCrossCaseAccess) {
		t.Fatalf("expected ErrCrossCaseAccess reading evidence from unrelated case, got %v", err)
	}

	// Tampered manifest blob_path escaping blobs/ must fail closed with ErrWidenedPath
	escapedDir := t.TempDir()
	escapedAdapter, err := storage.Open(storage.Config{RootDir: escapedDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := escapedAdapter.CommitWrite(ctx, storage.WriteRequest{
		OperationID: pos.OperationID,
		Manifest:    pos.Manifest,
		Payload:     []byte(pos.PayloadUTF8),
		Identity:    pos.Identity,
	}); err != nil {
		t.Fatal(err)
	}
	stateManifestPath := filepath.Join(escapedDir, storage.ManifestFileName)
	st := escapedAdapter.CurrentState()
	_ = escapedAdapter.Close()
	recKey := pos.Manifest.CaseID + "/" + pos.Manifest.EvidenceID
	rec := st.Evidence[recKey]
	rec.BlobPath = "../../etc/passwd"
	st.Evidence[recKey] = rec
	tamperedBytes, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateManifestPath, tamperedBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Open(storage.Config{RootDir: escapedDir, SyncDir: true}); !errors.Is(err, storage.ErrWidenedPath) {
		t.Fatalf("expected ErrWidenedPath for escaping manifest blob_path, got %v", err)
	}

	// Symlinked blob in blobs/ must fail closed with ErrWidenedPath on recovery
	symDir := t.TempDir()
	symAdapter, err := storage.Open(storage.Config{RootDir: symDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := symAdapter.CommitWrite(ctx, storage.WriteRequest{
		OperationID: pos.OperationID,
		Manifest:    pos.Manifest,
		Payload:     []byte(pos.PayloadUTF8),
		Identity:    pos.Identity,
	}); err != nil {
		t.Fatal(err)
	}
	_ = symAdapter.Close()
	symTarget := filepath.Join(t.TempDir(), "outside.log")
	if err := os.WriteFile(symTarget, []byte(pos.PayloadUTF8), 0600); err != nil {
		t.Fatal(err)
	}
	symBlobPath := filepath.Join(symDir, storage.BlobsDirName, pos.Manifest.SHA256)
	if err := os.Remove(symBlobPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(symTarget, symBlobPath); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Open(storage.Config{RootDir: symDir, SyncDir: true}); !errors.Is(err, storage.ErrWidenedPath) {
		t.Fatalf("expected ErrWidenedPath for symlinked blob, got %v", err)
	}
}

func TestC27DomainSecurityBoundaries(t *testing.T) {
	pos := loadC27JSON[c27PositiveFixture](t, "positive/authorized-security-baseline.json")
	ctx := context.Background()
	root := t.TempDir()

	qDir := filepath.Join(root, "quarantine")
	sDir := filepath.Join(root, "sealed")
	custDir := filepath.Join(root, "custody")
	holdsDir := filepath.Join(root, "holds")
	retDir := filepath.Join(root, "retention")
	scratchDir := filepath.Join(root, "scratch")
	findDir := filepath.Join(root, "findings")

	sealStore, err := evidence.OpenSealStore(evidence.SealConfig{RootDir: sDir, QuarantineDir: qDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sealStore.Close()

	ledgerStore, err := custody.OpenLedgerStore(custody.LedgerConfig{RootDir: custDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ledgerStore.Close()

	holdService, err := holds.OpenService(holds.ServiceConfig{
		RootDir:   holdsDir,
		SealStore: sealStore,
		Ledger:    ledgerStore,
		SyncDir:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer holdService.Close()

	retStore, err := retention.OpenRetentionStore(retention.RetentionConfig{
		RootDir:     retDir,
		SealStore:   sealStore,
		HoldService: holdService,
		LedgerStore: ledgerStore,
		SyncDir:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer retStore.Close()

	// Seed sealed evidence via real quarantine upload + SealStore
	raw := []byte(pos.PayloadUTF8)
	sum := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(sum[:])
	sz := int64(len(raw))

	q, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{QuarantineDir: qDir, BufferSize: 64, SyncDir: true}, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "upl-c27-domain",
		CaseID:        pos.Manifest.CaseID,
		EvidenceID:    pos.Manifest.EvidenceID,
		MediaType:     "text/plain",
		Filename:      "auth.log",
		ExpectedSize:  &sz,
		Body:          bytes.NewReader(raw),
	})
	if err != nil {
		t.Fatalf("quarantine upload failed: %v", err)
	}

	sealedManifest, err := sealStore.SealQuarantined(ctx, evidence.SealRequest{
		OperationID:    "seal-c27-domain",
		Quarantined:    q,
		ExpectedSHA256: shaHex,
		AcquiredAt:     "2026-11-12T08:00:00Z",
		CustodyRoot:    custody.GenesisPrevHash,
	})
	if err != nil {
		t.Fatalf("seal quarantined failed: %v", err)
	}

	blobPath := filepath.Join(sDir, filepath.FromSlash(sealedManifest.BlobRelPath))
	blobInfo, err := os.Stat(blobPath)
	if err != nil {
		t.Fatal(err)
	}
	if blobInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 owner-only sealed blob permissions, got %o", blobInfo.Mode().Perm())
	}

	// 1. Legal hold blocks destruction (ErrHoldActive)
	if _, err := holdService.PlaceHold(ctx, holds.PlaceHoldRequest{
		HoldID:     "hold-c27-01",
		CaseID:     pos.Manifest.CaseID,
		EvidenceID: pos.Manifest.EvidenceID,
		Actor:      "legal-counsel",
		Timestamp:  "2026-11-12T08:10:00Z",
		Reason:     "Active litigation preservation",
	}); err != nil {
		t.Fatalf("place hold failed: %v", err)
	}

	_, err = retStore.DestroyEvidence(ctx, retention.DestroyRequest{
		SchemaVersion:    "1",
		OperationID:      "op-destroy-held",
		TombstoneID:      "tomb-c27-01",
		CaseID:           pos.Manifest.CaseID,
		EvidenceID:       pos.Manifest.EvidenceID,
		Operator:         "admin-c27",
		Timestamp:        "2026-11-12T08:15:00Z",
		Reason:           "Attempted destruction while hold active",
		ExplicitApproval: true,
	})
	if !errors.Is(err, retention.ErrHoldActive) {
		t.Fatalf("expected ErrHoldActive when destroying held evidence, got %v", err)
	}

	// 2. Automatic raw-evidence TTL forbidden (ErrAutoRawTTLForbidden)
	_, err = retStore.SetPolicy(ctx, retention.RetentionPolicy{
		SchemaVersion:           "1",
		PolicyID:                "pol-c27-auto",
		CaseID:                  pos.Manifest.CaseID,
		AutoDeleteRawEvidence:   true,
		RawTTLSeconds:           86400,
		RequireExplicitApproval: false,
		Actor:                   "admin-c27",
		Reason:                  "Invalid auto TTL",
		UpdatedAt:               "2026-11-12T08:16:00Z",
	})
	if !errors.Is(err, retention.ErrAutoRawTTLForbidden) {
		t.Fatalf("expected ErrAutoRawTTLForbidden, got %v", err)
	}

	// 3. Epistemic promotion forbidden in findings store (ErrPromotionForbidden, ErrMissingAuthor, ErrMissingRationale)
	fStore, err := findings.OpenFindingStore(findings.FindingStoreConfig{RootDir: findDir, SyncDir: true})
	if err != nil {
		t.Fatal(err)
	}
	defer fStore.Close()

	_, err = fStore.RecordHypothesis(ctx, sealStore, sDir, nil, findings.RecordHypothesisRequest{
		SchemaVersion:       "1",
		OperationID:         "op-hyp-promote",
		CaseID:              pos.Manifest.CaseID,
		HypothesisID:        "hyp-c27-promote",
		Author:              "analyst-c27",
		Rationale:           "Attempted promotion",
		Statement:           "Cannot become observed fact",
		ClaimSourceEvidence: true,
	})
	if !errors.Is(err, findings.ErrPromotionForbidden) {
		t.Fatalf("expected ErrPromotionForbidden, got %v", err)
	}
	_, err = fStore.RecordHypothesis(ctx, sealStore, sDir, nil, findings.RecordHypothesisRequest{
		SchemaVersion: "1",
		CaseID:        pos.Manifest.CaseID,
		HypothesisID:  "hyp-c27-no-author",
		Author:        "   ",
		Rationale:     "Valid rationale",
		Statement:     "Missing author must fail",
	})
	if !errors.Is(err, findings.ErrMissingAuthor) {
		t.Fatalf("expected ErrMissingAuthor, got %v", err)
	}

	// 4. Analyzer unallowlisted provider & outbound network block
	reg, err := analyzers.NewRegistry(analyzers.RegistryConfig{
		SealStore:   sealStore,
		SealRootDir: sDir,
		Provider:    "local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Resolve("csv-parser", "external-cloud"); !errors.Is(err, analyzers.ErrUnavailableProvider) {
		t.Fatalf("expected ErrUnavailableProvider for external analyzer provider, got %v", err)
	}
	sb, err := analyzers.NewSandbox(reg, analyzers.DefaultSandboxConfig(scratchDir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sb.DialContext(ctx, "tcp", "198.51.100.1:443"); !errors.Is(err, analyzers.ErrNetworkForbidden) {
		t.Fatalf("expected ErrNetworkForbidden from sandbox network guard, got %v", err)
	}
	client := sb.NewBlockedHTTPClient()
	if _, err := client.Get("http://127.0.0.1:1/exfil"); !errors.Is(err, analyzers.ErrNetworkForbidden) {
		t.Fatalf("expected ErrNetworkForbidden from sandbox HTTP client, got %v", err)
	}

	// 5. Symlink traversal rejected in quarantine/evidence path
	symlinkTarget := filepath.Join(root, "outside-secret.txt")
	if err := os.WriteFile(symlinkTarget, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	holdsLinkDir := filepath.Join(root, "holds-symlink")
	if err := os.Symlink(symlinkTarget, holdsLinkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := holds.OpenService(holds.ServiceConfig{RootDir: holdsLinkDir, SealStore: sealStore, Ledger: ledgerStore}); !errors.Is(err, holds.ErrSymlinkRejected) {
		t.Fatalf("expected ErrSymlinkRejected opening symlink holds root, got %v", err)
	}

	// Confirm sealed source bytes remain unmodified and 0600
	gotRaw, err := os.ReadFile(blobPath)
	if err != nil || !bytes.Equal(gotRaw, raw) {
		t.Fatalf("sealed source bytes were modified after domain negative cases")
	}
	afterInfo, err := os.Stat(blobPath)
	if err != nil || afterInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected sealed blob permissions to remain 0600, got %v (err=%v)", afterInfo.Mode().Perm(), err)
	}
}

func TestC27LiveEngineHTTPAbuseBoundaries(t *testing.T) {
	abuse := loadC27JSON[c27AbuseCasesFixture](t, "invalid/security-abuse-cases.json")
	repoRoot := getRepoRoot(t)

	binPath := filepath.Join(t.TempDir(), "breachatlas")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/breachatlas")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build breachatlas failed: %v\n%s", err, string(out))
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "--host", "127.0.0.1", "--port", strconv.Itoa(port))
	cmd.Dir = repoRoot
	if err := cmd.Start(); err != nil {
		t.Fatalf("start breachatlas binary: %v", err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	httpClient := &http.Client{Timeout: 3 * time.Second}

	// Wait for /healthz
	ready := false
	for i := 0; i < 40; i++ {
		resp, err := httpClient.Get(baseURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("breachatlas binary did not become healthy on %s", baseURL)
	}

	for _, tc := range abuse.HTTPAndUIAbuseCases {
		t.Run(tc.Name, func(t *testing.T) {
			var bodyReader io.Reader
			if len(tc.Body) > 0 {
				bodyReader = bytes.NewReader(tc.Body)
			} else if tc.Method == http.MethodPost {
				bodyReader = strings.NewReader(`{}`)
			}

			req, err := http.NewRequest(tc.Method, baseURL+tc.Path, bodyReader)
			if err != nil {
				t.Fatal(err)
			}
			if tc.Host != "" {
				req.Host = tc.Host
			}
			if tc.ContentType != "" {
				req.Header.Set("Content-Type", tc.ContentType)
			} else if tc.Method == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
			}
			if tc.Origin != "" {
				req.Header.Set("Origin", tc.Origin)
			}
			if tc.SecFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.SecFetchSite)
			}
			for k, v := range tc.Headers {
				req.Header.Set(k, v)
			}

			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatalf("HTTP request %s failed: %v", tc.Name, err)
			}
			rawBody, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode != tc.WantStatus {
				t.Fatalf("%s: expected HTTP %d, got %d (%s)", tc.Name, tc.WantStatus, resp.StatusCode, string(rawBody))
			}
			if !strings.Contains(string(rawBody), tc.WantCode) {
				t.Fatalf("%s: expected code %q in body %s", tc.Name, tc.WantCode, string(rawBody))
			}
			if resp.Header.Get("X-Content-Type-Options") != "nosniff" ||
				resp.Header.Get("X-Frame-Options") != "DENY" ||
				resp.Header.Get("Content-Security-Policy") != "default-src 'none'" {
				t.Fatalf("%s: missing expected security headers: %v", tc.Name, resp.Header)
			}
		})
	}

	// Duplicate Origin header smuggling must fail closed against the live engine binary
	smuggleReq, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/evidence-integrity/inspect", strings.NewReader(`{"schema_version":"1","case_id":"case-c27-sec","items":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	smuggleReq.Header.Set("Content-Type", "application/json")
	smuggleReq.Header.Add("Origin", baseURL)
	smuggleReq.Header.Add("Origin", "https://attacker.invalid")
	smuggleResp, err := httpClient.Do(smuggleReq)
	if err != nil {
		t.Fatalf("live duplicate Origin request failed: %v", err)
	}
	smuggleBody, _ := io.ReadAll(smuggleResp.Body)
	_ = smuggleResp.Body.Close()
	if smuggleResp.StatusCode != http.StatusForbidden || !strings.Contains(string(smuggleBody), "origin_not_allowed") {
		t.Fatalf("live duplicate Origin smuggling: expected 403 origin_not_allowed, got %d (%s)", smuggleResp.StatusCode, string(smuggleBody))
	}
}

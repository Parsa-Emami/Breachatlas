package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRedactDiagnosticTextSentinelsAndCredentials(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		forbidden string
		wantRed   bool
	}{
		{
			name:      "secret sentinel",
			raw:       "cache failed with SECRET_SENTINEL_C29_KEY_991 during boot",
			forbidden: "SECRET_SENTINEL_C29_KEY_991",
			wantRed:   true,
		},
		{
			name:      "credential sentinel",
			raw:       "auth error CREDENTIAL_SENTINEL_C29_PASS",
			forbidden: "CREDENTIAL_SENTINEL_C29_PASS",
			wantRed:   true,
		},
		{
			name:      "bearer token",
			raw:       "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.C29SentinelToken",
			forbidden: "eyJhbGciOiJIUzI1NiJ9.C29SentinelToken",
			wantRed:   true,
		},
		{
			name:      "url userinfo",
			raw:       "upstream failed https://ops:TOKEN_SENTINEL_992@127.0.0.1:8080/readyz",
			forbidden: "TOKEN_SENTINEL_992",
			wantRed:   true,
		},
		{
			name:      "pem private key",
			raw:       "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw-----END PRIVATE KEY-----",
			forbidden: "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw",
			wantRed:   true,
		},
		{
			name:      "api key kv",
			raw:       "provider config api_key=API_KEY_SENTINEL_C29_777 rejected",
			forbidden: "API_KEY_SENTINEL_C29_777",
			wantRed:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clean, redacted := RedactDiagnosticText(tc.raw)
			if redacted != tc.wantRed {
				t.Fatalf("expected redacted=%v, got %v (%q)", tc.wantRed, redacted, clean)
			}
			if strings.Contains(clean, tc.forbidden) {
				t.Fatalf("forbidden secret substring %q leaked in %q", tc.forbidden, clean)
			}
			if !strings.Contains(clean, "[REDACTED") {
				t.Fatalf("expected redaction marker in %q", clean)
			}
		})
	}
}

func TestDiagnosticLoggerBoundedEvictionAndConcurrency(t *testing.T) {
	logger := NewDiagnosticLogger(8, 1024)

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				logger.Record("error", "storage", "probe_fail",
					fmt.Sprintf("worker-%d failed loading SECRET_SENTINEL_%d_%d payload=%s", id, id, i, strings.Repeat("x", 120)))
			}
		}(g)
	}
	wg.Wait()

	snap := logger.Snapshot()
	if len(snap.Entries) > snap.MaxEntries {
		t.Fatalf("entries exceeded max: got %d > %d", len(snap.Entries), snap.MaxEntries)
	}
	if snap.TotalBytes > snap.MaxBytes {
		t.Fatalf("total_bytes exceeded max: got %d > %d", snap.TotalBytes, snap.MaxBytes)
	}
	if snap.EvictedCount == 0 {
		t.Fatalf("expected evictions under flood, got 0")
	}
	if snap.RedactedCount != 80 {
		t.Fatalf("expected 80 redacted records, got %d", snap.RedactedCount)
	}
	for _, entry := range snap.Entries {
		if strings.Contains(entry.Message, "SECRET_SENTINEL") {
			t.Fatalf("sentinel leaked in entry: %+v", entry)
		}
		if len(entry.Message) > MaxDiagnosticMessageBytes {
			t.Fatalf("message exceeded per-entry bound: %d", len(entry.Message))
		}
	}
}

func TestEngineReadinessSeparatesStorageAndProviderFailures(t *testing.T) {
	validStorage := t.TempDir()
	logger := NewDiagnosticLogger(32, 8192)

	// 1. Healthy storage and required providers -> /healthz 200, /readyz 200, /api/v1/diagnostics 200
	okMux := NewMuxWithOptions(EngineRuntimeOptions{
		StorageRoot:       validStorage,
		RequireStorageDir: true,
		RequiredProviders: []string{"local", "csv", "json"},
		Logger:            logger,
	})

	recReady := httptest.NewRecorder()
	reqReady := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	reqReady.Host = "127.0.0.1:8080"
	okMux.ServeHTTP(recReady, reqReady)
	if recReady.Code != http.StatusOK {
		t.Fatalf("expected 200 from healthy /readyz, got %d (%s)", recReady.Code, recReady.Body.String())
	}
	var report ReadinessReport
	if err := json.Unmarshal(recReady.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.EngineReady || !report.StorageReady || !report.ProvidersReady || len(report.Failures) != 0 {
		t.Fatalf("unexpected healthy readiness report: %+v", report)
	}

	// 2. Missing storage prerequisite -> /healthz stays 200, /readyz & /api/v1/diagnostics return 503 with explicit failure
	missingDir := filepath.Join(t.TempDir(), "missing-storage-prereq")
	missingMux := NewMuxWithOptions(EngineRuntimeOptions{
		StorageRoot:       missingDir,
		RequireStorageDir: true,
		RequiredProviders: []string{"local", "csv", "json"},
	})

	recHealth := httptest.NewRecorder()
	reqHealth := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	reqHealth.Host = "127.0.0.1:8080"
	missingMux.ServeHTTP(recHealth, reqHealth)
	if recHealth.Code != http.StatusOK {
		t.Fatalf("expected /healthz 200 when storage prerequisite is missing, got %d", recHealth.Code)
	}

	recFail := httptest.NewRecorder()
	reqFail := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	reqFail.Host = "127.0.0.1:8080"
	missingMux.ServeHTTP(recFail, reqFail)
	if recFail.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for missing storage prerequisite, got %d (%s)", recFail.Code, recFail.Body.String())
	}
	var failReport ReadinessReport
	if err := json.Unmarshal(recFail.Body.Bytes(), &failReport); err != nil {
		t.Fatal(err)
	}
	if failReport.StorageReady || failReport.Storage.ErrorCode != "storage_prerequisite_missing" {
		t.Fatalf("expected storage_prerequisite_missing, got %+v", failReport.Storage)
	}

	// 3. Symlinked storage root must be rejected
	realTarget := t.TempDir()
	symlinkRoot := filepath.Join(t.TempDir(), "symlink-storage")
	if err := os.Symlink(realTarget, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	symlinkMux := NewMuxWithOptions(EngineRuntimeOptions{
		StorageRoot:       symlinkRoot,
		RequireStorageDir: true,
	})
	recSym := httptest.NewRecorder()
	reqSym := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	reqSym.Host = "127.0.0.1:8080"
	symlinkMux.ServeHTTP(recSym, reqSym)
	if recSym.Code != http.StatusServiceUnavailable || !strings.Contains(recSym.Body.String(), "storage_invalid_root") {
		t.Fatalf("expected 503 storage_invalid_root for symlink root, got %d (%s)", recSym.Code, recSym.Body.String())
	}

	// 4. Unavailable required provider -> 503 provider_unavailable
	provMux := NewMuxWithOptions(EngineRuntimeOptions{
		StorageRoot:       validStorage,
		RequireStorageDir: true,
		RequiredProviders: []string{"local", "remote-kms"},
	})
	recProv := httptest.NewRecorder()
	reqProv := httptest.NewRequest(http.MethodGet, "/api/v1/diagnostics", nil)
	reqProv.Host = "127.0.0.1:8080"
	provMux.ServeHTTP(recProv, reqProv)
	if recProv.Code != http.StatusServiceUnavailable || !strings.Contains(recProv.Body.String(), "provider_unavailable") {
		t.Fatalf("expected 503 provider_unavailable, got %d (%s)", recProv.Code, recProv.Body.String())
	}
}

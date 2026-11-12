package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHealthEndpoint(t *testing.T) {
	handler := NewMux()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if resp.Status != "ok" || resp.Service != ServiceName || resp.Version != EngineVersion {
		t.Errorf("unexpected health payload: %+v", resp)
	}
}

func TestVersionEndpoint(t *testing.T) {
	handler := NewMux()
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	req.Host = "localhost:8080"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp VersionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if resp.Version != EngineVersion || resp.Service != ServiceName || resp.Commit != "C03" {
		t.Errorf("unexpected version payload: %+v", resp)
	}
}

func TestReadyzEndpoint(t *testing.T) {
	handler := NewMux()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestApiV1Health(t *testing.T) {
	handler := NewMux()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestHostHeaderSecurity(t *testing.T) {
	handler := NewMux()

	for _, badHost := range []string{"evil.com", "attacker.invalid:8080", "192.168.1.100:8080", "10.0.0.1"} {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Host = badHost
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 for host %q, got %d", badHost, rec.Code)
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	handler := NewMux()
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST /healthz, got %d", rec.Code)
	}
}

func TestParseFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// Default
	cfg, err := ParseFlags([]string{}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "127.0.0.1" || cfg.Port != 8080 {
		t.Errorf("unexpected defaults: %+v", cfg)
	}

	// Custom valid
	cfg, err = ParseFlags([]string{"--host", "::1", "--port", "9090"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "::1" || cfg.Port != 9090 {
		t.Errorf("unexpected parsed config: %+v", cfg)
	}

	// Rejection of non-loopback host
	_, err = ParseFlags([]string{"--host", "0.0.0.0"}, &stdout, &stderr)
	if err == nil {
		t.Error("expected error for 0.0.0.0 host, got nil")
	}

	// Rejection of invalid port
	_, err = ParseFlags([]string{"--port", "70000"}, &stdout, &stderr)
	if err == nil {
		t.Error("expected error for port 70000, got nil")
	}
}

func TestOccupiedPort(t *testing.T) {
	// Bind a port first
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind port: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	var stdout, stderr bytes.Buffer
	ready := make(chan struct{})
	code := Run([]string{"--host", "127.0.0.1", "--port", strconv.Itoa(port)}, &stdout, &stderr, ready)
	if code != 1 || !bytes.Contains(stderr.Bytes(), []byte("Failed to listen")) {
		t.Fatalf("expected bind failure, got exit %d and %q", code, stderr.String())
	}
}

func TestGracefulShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	var stdout, stderr bytes.Buffer
	ready := make(chan struct{})

	done := make(chan int, 1)
	go func() {
		portStr := bytes.NewBuffer(nil)
		_ = json.NewEncoder(portStr).Encode(port)
		// Run with args
		code := Run([]string{"--host", "127.0.0.1", "--port", portStr.String()[:len(portStr.String())-1]}, &stdout, &stderr, ready)
		done <- code
	}()

	select {
	case <-ready:
		// Server is listening, send signal
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	case <-time.After(3 * time.Second):
		t.Fatal("server failed to start within timeout")
	}

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("expected clean shutdown code 0, got %d. stderr: %s", code, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server failed to shutdown within timeout")
	}
}

func TestAPISecurityOriginAndCrossSite(t *testing.T) {
	handler := NewMux()

	for _, endpoint := range []string{
		"/api/v1/evidence-manifests/validate",
		"/api/v1/evidence-integrity/inspect",
		"/api/v1/timeline/inspect",
	} {
		// 1. Sec-Fetch-Site: cross-site (mixed case) must fail closed with 403 origin_not_allowed
		req := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{}`))
		req.Host = "127.0.0.1:8080"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "Cross-Site")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "origin_not_allowed") {
			t.Fatalf("%s cross-site: expected 403 origin_not_allowed, got %d (%s)", endpoint, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Content-Security-Policy") != "default-src 'none'" ||
			rec.Header().Get("X-Content-Type-Options") != "nosniff" ||
			rec.Header().Get("X-Frame-Options") != "DENY" ||
			rec.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("%s missing hardened security headers: %v", endpoint, rec.Header())
		}

		// 2. Foreign Origin or Origin: null or mismatched port must fail closed with 403 origin_not_allowed
		for _, badOrigin := range []string{"https://attacker.invalid", "http://127.0.0.1:4173", "null"} {
			oReq := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{}`))
			oReq.Host = "127.0.0.1:8080"
			oReq.Header.Set("Content-Type", "application/json")
			oReq.Header.Set("Origin", badOrigin)
			oRec := httptest.NewRecorder()
			handler.ServeHTTP(oRec, oReq)
			if oRec.Code != http.StatusForbidden || !strings.Contains(oRec.Body.String(), "origin_not_allowed") {
				t.Fatalf("%s origin %q: expected 403 origin_not_allowed, got %d (%s)", endpoint, badOrigin, oRec.Code, oRec.Body.String())
			}
		}
	}

	// Same-origin request passes middleware and reaches endpoint validation
	okReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence-integrity/inspect", strings.NewReader(`{"schema_version":"1","case_id":"case-ok","items":[]}`))
	okReq.Host = "127.0.0.1:8080"
	okReq.Header.Set("Content-Type", "application/json")
	okReq.Header.Set("Origin", "http://127.0.0.1:8080")
	okReq.Header.Set("Sec-Fetch-Site", "same-origin")
	okRec := httptest.NewRecorder()
	handler.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("expected same-origin inspect request to succeed, got %d (%s)", okRec.Code, okRec.Body.String())
	}
}

func TestAPIForgedIdentityHeadersRejected(t *testing.T) {
	handler := NewMux()

	forgedHeaders := []struct {
		name  string
		value string
	}{
		{"X-Identity-Override", "admin"},
		{"x-identity-override", "admin"},
		{"X-Forwarded-User", "root"},
		{"x-forwarded-user", "admin"},
		{"X-Forwarded-Host", "evil.invalid"},
		{"x-forwarded-host", "evil.invalid"},
		{"X-Forwarded-Role", "admin"},
		{"X-Role", "admin"},
		{"x-role", "admin"},
		{"X-Case-Scope", "case-other"},
		{"x-case-scope", "case-other"},
		{"X-Provider", "remote-kms"},
		{"x-provider", "local"},
		{"X-Auth-User", "admin"},
		{"x-user-override", "admin"},
	}

	for _, endpoint := range []string{
		"/api/v1/evidence-manifests/validate",
		"/api/v1/evidence-integrity/inspect",
		"/api/v1/timeline/inspect",
	} {
		for _, hdr := range forgedHeaders {
			req := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{}`))
			req.Host = "127.0.0.1:8080"
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(hdr.name, hdr.value)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "forged_header") {
				t.Fatalf("%s header %s=%q: expected 403 forged_header, got %d (%s)", endpoint, hdr.name, hdr.value, rec.Code, rec.Body.String())
			}
		}
	}

	// Documented nginx reverse-proxy transport headers remain allowed
	proxyReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence-integrity/inspect", strings.NewReader(`{"schema_version":"1","case_id":"case-proxy","items":[]}`))
	proxyReq.Host = "127.0.0.1:8080"
	proxyReq.Header.Set("Content-Type", "application/json")
	proxyReq.Header.Set("X-Forwarded-Proto", "https")
	proxyReq.Header.Set("X-Forwarded-For", "127.0.0.1")
	proxyRec := httptest.NewRecorder()
	handler.ServeHTTP(proxyRec, proxyReq)
	if proxyRec.Code != http.StatusOK {
		t.Fatalf("expected documented proxy transport headers to be allowed, got %d (%s)", proxyRec.Code, proxyRec.Body.String())
	}

	// Duplicate/smuggled Origin and Sec-Fetch-Site headers must fail closed with 403 origin_not_allowed
	dupOriginReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence-integrity/inspect", strings.NewReader(`{}`))
	dupOriginReq.Host = "127.0.0.1:8080"
	dupOriginReq.Header.Set("Content-Type", "application/json")
	dupOriginReq.Header.Add("Origin", "http://127.0.0.1:8080")
	dupOriginReq.Header.Add("Origin", "https://attacker.invalid")
	dupOriginRec := httptest.NewRecorder()
	handler.ServeHTTP(dupOriginRec, dupOriginReq)
	if dupOriginRec.Code != http.StatusForbidden || !strings.Contains(dupOriginRec.Body.String(), "origin_not_allowed") {
		t.Fatalf("duplicate Origin header smuggling: expected 403 origin_not_allowed, got %d (%s)", dupOriginRec.Code, dupOriginRec.Body.String())
	}

	dupSiteReq := httptest.NewRequest(http.MethodPost, "/api/v1/timeline/inspect", strings.NewReader(`{}`))
	dupSiteReq.Host = "127.0.0.1:8080"
	dupSiteReq.Header.Set("Content-Type", "application/json")
	dupSiteReq.Header.Add("Sec-Fetch-Site", "same-origin")
	dupSiteReq.Header.Add("Sec-Fetch-Site", "cross-site")
	dupSiteRec := httptest.NewRecorder()
	handler.ServeHTTP(dupSiteRec, dupSiteReq)
	if dupSiteRec.Code != http.StatusForbidden || !strings.Contains(dupSiteRec.Body.String(), "origin_not_allowed") {
		t.Fatalf("duplicate Sec-Fetch-Site header smuggling: expected 403 origin_not_allowed, got %d (%s)", dupSiteRec.Code, dupSiteRec.Body.String())
	}

	// Exact /api path also rejects forged headers
	exactApiReq := httptest.NewRequest(http.MethodGet, "/api", nil)
	exactApiReq.Host = "127.0.0.1:8080"
	exactApiReq.Header.Set("x-identity-override", "admin")
	exactApiRec := httptest.NewRecorder()
	handler.ServeHTTP(exactApiRec, exactApiReq)
	if exactApiRec.Code != http.StatusForbidden || !strings.Contains(exactApiRec.Body.String(), "forged_header") {
		t.Fatalf("exact /api forged header: expected 403 forged_header, got %d (%s)", exactApiRec.Code, exactApiRec.Body.String())
	}
}

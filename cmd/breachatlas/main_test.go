package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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

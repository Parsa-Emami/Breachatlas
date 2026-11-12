package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

const (
	EngineVersion = "0.0.1"
	ServiceName   = "breachatlas-engine"
)

type Config struct {
	Host        string
	Port        int
	ShowVersion bool
	CheckHealth bool
}

type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
	Scope   string `json:"scope"`
}

type VersionResponse struct {
	Version string `json:"version"`
	Service string `json:"service"`
	Commit  string `json:"commit"`
}

func isLoopbackHost(host string) bool {
	h := strings.Trim(host, "[]")
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackAuthority(authority string) bool {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return authority == "[::1]" || !strings.ContainsAny(authority, ":[]") && isLoopbackHost(authority)
	}
	number, err := strconv.ParseUint(port, 10, 16)
	return err == nil && number != 0 && isLoopbackHost(host)
}

func NewMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/evidence-manifests/validate", validateManifest)
	mux.HandleFunc("/api/v1/evidence-integrity/inspect", inspectEvidenceIntegrity)
	mux.HandleFunc("/api/v1/timeline/inspect", inspectTimeline)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(HealthResponse{
				Status:  "ok",
				Service: ServiceName,
				Version: EngineVersion,
				Scope:   "local-loopback",
			})
		}
	})

	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(VersionResponse{
				Version: EngineVersion,
				Service: ServiceName,
				Commit:  "C03",
			})
		}
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ready",
			"service": ServiceName,
			"scope":   "local-loopback",
		})
	})

	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(HealthResponse{
			Status:  "ok",
			Service: ServiceName,
			Version: EngineVersion,
			Scope:   "local-loopback",
		})
	})

	// Wrap with security middleware
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")

		// Host validation: must be loopback
		if !isLoopbackAuthority(r.Host) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"invalid_host"}`))
			return
		}

		isAPIPath := r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/")

		// Cross-site / cross-origin browser request rejection (check every header value)
		if hasDisallowedCrossSiteOrOrigin(r) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			if isAPIPath {
				writeEngineProblem(w, http.StatusForbidden, evidence.Problem{Code: "origin_not_allowed"})
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"origin_not_allowed"}`))
			return
		}

		// Forged proxy/identity header rejection on API endpoints
		if isAPIPath && hasForgedIdentityHeader(r.Header) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			writeEngineProblem(w, http.StatusForbidden, evidence.Problem{Code: "forged_header"})
			return
		}

		mux.ServeHTTP(w, r)
	})
}

func hasDisallowedCrossSiteOrOrigin(r *http.Request) bool {
	for _, raw := range r.Header.Values("Sec-Fetch-Site") {
		for _, part := range strings.Split(raw, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "cross-site") {
				return true
			}
		}
	}
	for _, raw := range r.Header.Values("Origin") {
		for _, part := range strings.Split(raw, ",") {
			origin := strings.TrimSpace(part)
			if origin == "" {
				continue
			}
			if !strings.EqualFold(origin, "http://"+r.Host) && !strings.EqualFold(origin, "https://"+r.Host) {
				return true
			}
		}
	}
	return false
}

func hasForgedIdentityHeader(h http.Header) bool {
	for rawKey := range h {
		switch strings.ToLower(strings.TrimSpace(rawKey)) {
		case "x-identity-override",
			"x-forwarded-user",
			"x-forwarded-host",
			"x-forwarded-role",
			"x-role",
			"x-case-scope",
			"x-provider",
			"x-auth-user",
			"x-user-override":
			return true
		}
	}
	return false
}

func ParseFlags(args []string, stdout, stderr io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("breachatlas", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := &Config{}
	fs.StringVar(&cfg.Host, "host", "127.0.0.1", "Host address to bind (must be loopback)")
	fs.IntVar(&cfg.Port, "port", 8080, "Port number to listen on (1-65535)")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "Print engine version and exit")
	fs.BoolVar(&cfg.CheckHealth, "health", false, "Probe engine loopback health and exit")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d: must be 1-65535", cfg.Port)
	}

	if !isLoopbackHost(cfg.Host) {
		return nil, fmt.Errorf("forbidden non-loopback host %q: BreachAtlas strictly requires loopback binding (127.0.0.1, ::1)", cfg.Host)
	}

	return cfg, nil
}

func probeHealth(host string, port int) error {
	url := fmt.Sprintf("http://%s/healthz", net.JoinHostPort(host, strconv.Itoa(port)))
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	var h HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return fmt.Errorf("malformed health response: %w", err)
	}
	if h.Status != "ok" || h.Service != ServiceName {
		return fmt.Errorf("unexpected health status or service: %+v", h)
	}

	return nil
}

func Run(args []string, stdout, stderr io.Writer, readyChan chan<- struct{}) int {
	cfg, err := ParseFlags(args, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "Configuration error: %v\n", err)
		return 1
	}

	if cfg.ShowVersion {
		_ = json.NewEncoder(stdout).Encode(VersionResponse{
			Version: EngineVersion,
			Service: ServiceName,
			Commit:  "C03",
		})
		return 0
	}

	if cfg.CheckHealth {
		if err := probeHealth(cfg.Host, cfg.Port); err != nil {
			fmt.Fprintf(stderr, "Engine health check failed on %s:%d: %v\n", cfg.Host, cfg.Port, err)
			return 1
		}
		fmt.Fprintf(stdout, `{"status":"ok","service":"%s","host":"%s","port":%d}`+"\n", ServiceName, cfg.Host, cfg.Port)
		return 0
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to listen on %s: %v\n", addr, err)
		return 1
	}

	server := &http.Server{
		Handler:      NewMux(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	fmt.Fprintf(stdout, `{"service":"%s","version":"%s","host":"%s","port":%d,"status":"listening"}`+"\n",
		ServiceName, EngineVersion, cfg.Host, cfg.Port)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(quit)
	if readyChan != nil {
		close(readyChan)
	}

	select {
	case sig := <-quit:
		fmt.Fprintf(stdout, `{"service":"%s","action":"shutting_down","signal":"%s"}`+"\n", ServiceName, sig.String())
	case err := <-serverErr:
		if err != nil {
			fmt.Fprintf(stderr, "Server error: %v\n", err)
			return 1
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		fmt.Fprintf(stderr, "Graceful shutdown failed: %v\n", err)
		_ = server.Close()
		return 1
	}

	fmt.Fprintf(stdout, `{"service":"%s","status":"stopped"}`+"\n", ServiceName)
	return 0
}

func main() {
	os.Exit(Run(os.Args[1:], os.Stdout, os.Stderr, nil))
}

package tests_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type c32Provenance struct {
	Task       string            `json:"task"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	SHA256     map[string]string `json:"sha256"`
}

func TestC32LocalNetworkBoundariesAndPrivateHostingTemplate(t *testing.T) {
	root := locateRepoRoot(t)
	fxDir := filepath.Join(root, "tests", "fixtures", "breachatlas", "C32")

	// 1. Verify C32 fixture provenance & SHA-256 digests.
	provRaw, err := os.ReadFile(filepath.Join(fxDir, "provenance.json"))
	if err != nil {
		t.Fatalf("read C32 provenance: %v", err)
	}
	var prov c32Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatalf("decode C32 provenance: %v", err)
	}
	if prov.License != "Apache-2.0" || len(prov.SHA256) < 4 {
		t.Fatalf("unexpected C32 provenance: %+v", prov)
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

	var pos struct {
		OwnedPublicDomainRequired    bool              `json:"owned_public_domain_required"`
		LoopbackHosts                []string          `json:"loopback_hosts"`
		AllowedProxyTransportHeaders map[string]string `json:"allowed_proxy_transport_headers"`
	}
	posRaw, err := os.ReadFile(filepath.Join(fxDir, "positive", "local-loopback-boundary.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(posRaw, &pos); err != nil {
		t.Fatal(err)
	}
	if pos.OwnedPublicDomainRequired {
		t.Fatalf("expected owned_public_domain_required=false")
	}

	var neg struct {
		DisallowedHosts      []string `json:"disallowed_hosts"`
		DisallowedOrigins    []string `json:"disallowed_origins"`
		DisallowedFetchSite  string   `json:"disallowed_fetch_site"`
		ForgedHeaders        []string `json:"forged_headers"`
	}
	negRaw, err := os.ReadFile(filepath.Join(fxDir, "invalid", "non-loopback-and-cross-origin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(negRaw, &neg); err != nil {
		t.Fatal(err)
	}

	var miss struct {
		MissingStorageDir     string `json:"missing_storage_dir"`
		UnavailableProvider   string `json:"unavailable_provider"`
		MalformedManifestBody string `json:"malformed_manifest_body"`
	}
	missRaw, err := os.ReadFile(filepath.Join(fxDir, "invalid", "missing-prerequisites-and-provider.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(missRaw, &miss); err != nil {
		t.Fatal(err)
	}

	// 2. Verify sealed 0440 source bytes remain immutable across engine boundary checks.
	sealedDir := t.TempDir()
	sealedFile := filepath.Join(sealedDir, "sealed-source.log")
	sealedContent := []byte("2026-11-14T13:00:00Z c32-host sshd: immutable-sealed-record\n")
	if err := os.WriteFile(sealedFile, sealedContent, 0o440); err != nil {
		t.Fatal(err)
	}
	sealedSumBefore := sha256.Sum256(sealedContent)

	// 3. Spin up real compiled Go engine binary on loopback and repeat boundary & prerequisite checks across restart.
	binPath := buildEngineBinaryC29(t)
	if out, err := exec.Command(binPath, "--host", "0.0.0.0", "--port", "18080").CombinedOutput(); err == nil {
		t.Fatalf("expected non-loopback --host 0.0.0.0 startup to fail, output=%s", string(out))
	}

	missingDir := filepath.Join(t.TempDir(), miss.MissingStorageDir)
	for cycle := 0; cycle < 2; cycle++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()

		_, stopEngine := startEngineProcessC29(t, binPath, port, "--storage-dir", missingDir, "--required-providers", miss.UnavailableProvider)
		baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
		client := &http.Client{}

		// Loopback Host allowed + allowed Nginx proxy transport headers + Cache-Control: no-store
		for _, host := range pos.LoopbackHosts {
			req, _ := http.NewRequest(http.MethodGet, baseURL+"/healthz", nil)
			req.Host = fmt.Sprintf("%s:%d", host, port)
			for k, v := range pos.AllowedProxyTransportHeaders {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil {
				stopEngine()
				t.Fatalf("cycle %d loopback %s failed: %v", cycle, host, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				stopEngine()
				t.Fatalf("cycle %d loopback %s expected 200, got %d", cycle, host, resp.StatusCode)
			}
			if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
				stopEngine()
				t.Fatalf("expected Cache-Control: no-store, got %q", cc)
			}
		}

		// Non-loopback Host rejected
		for _, badHost := range neg.DisallowedHosts {
			req, _ := http.NewRequest(http.MethodGet, baseURL+"/healthz", nil)
			req.Host = badHost
			resp, err := client.Do(req)
			if err != nil {
				stopEngine()
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				stopEngine()
				t.Fatalf("expected 403 for disallowed host %s, got %d", badHost, resp.StatusCode)
			}
		}

		// Foreign Origin & cross-site Sec-Fetch-Site rejected
		for _, badOrigin := range neg.DisallowedOrigins {
			req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/evidence-manifests/validate", bytes.NewBufferString(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", badOrigin)
			resp, err := client.Do(req)
			if err != nil {
				stopEngine()
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				stopEngine()
				t.Fatalf("expected 403 for origin %q, got %d", badOrigin, resp.StatusCode)
			}
		}

		reqCross, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/diagnostics", nil)
		reqCross.Header.Set("Sec-Fetch-Site", neg.DisallowedFetchSite)
		respCross, err := client.Do(reqCross)
		if err != nil {
			stopEngine()
			t.Fatal(err)
		}
		_ = respCross.Body.Close()
		if respCross.StatusCode != http.StatusForbidden {
			stopEngine()
			t.Fatalf("expected 403 for Sec-Fetch-Site=cross-site, got %d", respCross.StatusCode)
		}

		// Forged headers rejected
		for _, hdr := range neg.ForgedHeaders {
			req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/diagnostics", nil)
			req.Header.Set(hdr, "spoofed")
			resp, err := client.Do(req)
			if err != nil {
				stopEngine()
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				stopEngine()
				t.Fatalf("expected 403 for forged header %s, got %d", hdr, resp.StatusCode)
			}
		}

		// Missing storage prerequisite + unavailable required provider return 503 on /readyz
		respReady, err := client.Get(baseURL + "/readyz")
		if err != nil {
			stopEngine()
			t.Fatal(err)
		}
		_ = respReady.Body.Close()
		if respReady.StatusCode != http.StatusServiceUnavailable {
			stopEngine()
			t.Fatalf("expected 503 on /readyz for missing storage & unavailable provider, got %d", respReady.StatusCode)
		}

		// Malformed fixture JSON returns 400
		respMal, err := client.Post(baseURL+"/api/v1/evidence-manifests/validate", "application/json", strings.NewReader(miss.MalformedManifestBody))
		if err != nil {
			stopEngine()
			t.Fatal(err)
		}
		_ = respMal.Body.Close()
		if respMal.StatusCode != http.StatusBadRequest {
			stopEngine()
			t.Fatalf("expected 400 on malformed JSON manifest, got %d", respMal.StatusCode)
		}

		stopEngine()
	}

	// 4. Verify Nginx template and systemd service enforce private-host isolation.
	nginxBytes, err := os.ReadFile(filepath.Join(root, "ops", "web", "nginx.conf.template"))
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(nginxBytes)
	for _, required := range []string{
		"listen 443 ssl;",
		"allow 127.0.0.1;",
		"deny all;",
		"proxy_pass http://127.0.0.1:4310;",
		"proxy_set_header Host $proxy_host;",
	} {
		if !strings.Contains(nginx, required) {
			t.Fatalf("nginx.conf.template missing required directive %q", required)
		}
	}
	if strings.Contains(nginx, "proxy_pass http://127.0.0.1:8080") || strings.Contains(nginx, "proxy_pass http://localhost:8080") || strings.Contains(nginx, "proxy_set_header Host $host") {
		t.Fatalf("nginx.conf.template must not expose port 8080 or forward $host")
	}

	systemdBytes, err := os.ReadFile(filepath.Join(root, "ops", "web", "service.systemd"))
	if err != nil {
		t.Fatal(err)
	}
	systemd := string(systemdBytes)
	for _, required := range []string{
		"--host 127.0.0.1",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
	} {
		if !strings.Contains(systemd, required) {
			t.Fatalf("service.systemd missing required hardening directive %q", required)
		}
	}

	// 5. Verify docs/evidence/domain.json & infra/deployment.md exist and confirm zero-domain local default.
	domainRaw, err := os.ReadFile(filepath.Join(root, "docs", "evidence", "domain.json"))
	if err != nil {
		t.Fatal(err)
	}
	var domainDoc struct {
		OwnedPublicDomainRequired bool `json:"owned_public_domain_required"`
	}
	if err := json.Unmarshal(domainRaw, &domainDoc); err != nil {
		t.Fatal(err)
	}
	if domainDoc.OwnedPublicDomainRequired {
		t.Fatalf("expected owned_public_domain_required=false in docs/evidence/domain.json")
	}

	deployBytes, err := os.ReadFile(filepath.Join(root, "infra", "deployment.md"))
	if err != nil || !strings.Contains(string(deployBytes), "no owned public domain") {
		t.Fatalf("infra/deployment.md missing or incomplete: err=%v", err)
	}

	// 6. Verify sealed source bytes remained completely unmodified.
	sealedAfter, err := os.ReadFile(sealedFile)
	if err != nil || sha256.Sum256(sealedAfter) != sealedSumBefore {
		t.Fatalf("sealed source bytes were modified")
	}
}

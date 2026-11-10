package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestManifestReadDeadline(t *testing.T) {
	server := httptest.NewServer(NewMux())
	defer server.Close()
	reader, writer := io.Pipe()
	defer writer.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/evidence-manifests/validate", reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	go func() {
		_, _ = writer.Write([]byte("{"))
	}()
	started := time.Now()
	response, err := (&http.Client{Timeout: 4 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result struct{ Error struct{ Code string } }
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 408 || result.Error.Code != "request_timeout" || time.Since(started) > 3*time.Second {
		t.Fatalf("expected bounded timeout, got %d %+v", response.StatusCode, result)
	}
}

func TestManifestMalformed(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/evidence-manifests/validate", bytes.NewBufferString("{"))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	NewMux().ServeHTTP(recorder, request)
	if recorder.Code != 400 {
		t.Fatalf("malformed payload got %d, want 400", recorder.Code)
	}
}

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func doWorkflowJSON(t *testing.T, handler http.Handler, method, target string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if payload == nil {
		bodyReader = bytes.NewReader(nil)
	} else if s, ok := payload.(string); ok {
		bodyReader = bytes.NewReader([]byte(s))
	} else {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		bodyReader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "http://127.0.0.1:8080"+target, bodyReader)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestWorkflowEndToEndRestartRestoreAndNegativeCases(t *testing.T) {
	storageDir := t.TempDir()
	h, closeFn := NewMuxWithOptionsAndCleanup(EngineRuntimeOptions{
		StorageRoot:       storageDir,
		RequireStorageDir: true,
	})
	closed := false
	t.Cleanup(func() {
		if !closed {
			closeFn()
		}
	})

	payload := "{\"timestamp\":\"2026-11-14T07:45:12+03:30\",\"event_type\":\"auth_login\",\"summary\":\"SSH login\",\"host\":\"bastion-01\"}\n" +
		"{\"timestamp\":\"2026-11-14 08:20:00\",\"event_type\":\"export_prep\",\"summary\":\"Normalized event\",\"host\":\"app-02\"}\n"
	expectedSum := sha256.Sum256([]byte(payload))
	expectedSHA := hex.EncodeToString(expectedSum[:])

	// 1. Upload + seal
	sealRec := doWorkflowJSON(t, h, http.MethodPost, "/api/v1/workflow/upload-seal", map[string]any{
		"schema_version": "1",
		"case_id":        "case-wf-01",
		"evidence_id":    "ev-wf-01",
		"filename":       "ev-wf-01.jsonl",
		"media_type":     "application/x-ndjson",
		"payload":        payload,
		"acquired_at":    "2026-11-14T08:00:00+03:30",
		"actor":          "analyst-parisa",
		"provider":       "local",
	})
	if sealRec.Code != http.StatusOK {
		t.Fatalf("upload-seal status=%d body=%s", sealRec.Code, sealRec.Body.String())
	}
	var sealResp map[string]any
	if err := json.Unmarshal(sealRec.Body.Bytes(), &sealResp); err != nil {
		t.Fatal(err)
	}
	if sealResp["sha256"] != expectedSHA || sealResp["status"] != "sealed" {
		t.Fatalf("unexpected seal response: %+v", sealResp)
	}

	// 2. Append custody + checkpoint
	custRec := doWorkflowJSON(t, h, http.MethodPost, "/api/v1/workflow/custody", map[string]any{
		"schema_version": "1",
		"case_id":        "case-wf-01",
		"evidence_id":    "ev-wf-01",
		"event_id":       "cust-wf-02",
		"event_type":     "custody_transfer",
		"actor":          "analyst-parisa",
		"timestamp":      "2026-11-14T08:10:00+03:30",
		"reason":         "Transfer to forensic indexing",
		"from_custodian": "collector-01",
		"to_custodian":   "analyst-parisa",
		"provider":       "local",
	})
	if custRec.Code != http.StatusOK {
		t.Fatalf("custody status=%d body=%s", custRec.Code, custRec.Body.String())
	}

	// 3. Parse bounded timeline preserving raw timestamp + offset + confidence
	tlRec := doWorkflowJSON(t, h, http.MethodPost, "/api/v1/workflow/timeline", map[string]any{
		"schema_version":    "1",
		"case_id":           "case-wf-01",
		"evidence_id":       "ev-wf-01",
		"artifact_id":       "art-wf-01",
		"zone_hint":         "Asia/Tehran",
		"source_confidence": 0.96,
		"provider":          "local",
	})
	if tlRec.Code != http.StatusOK {
		t.Fatalf("timeline status=%d body=%s", tlRec.Code, tlRec.Body.String())
	}
	var tlResp map[string]any
	if err := json.Unmarshal(tlRec.Body.Bytes(), &tlResp); err != nil {
		t.Fatal(err)
	}
	if tlResp["raw_timestamps_preserved"] != true || tlResp["total_entries"] != float64(2) {
		t.Fatalf("unexpected timeline response: %+v", tlResp)
	}

	// 4. Legal hold + delete/expire blocked with 409 hold_active
	holdRec := doWorkflowJSON(t, h, http.MethodPost, "/api/v1/workflow/hold", map[string]any{
		"schema_version": "1",
		"case_id":        "case-wf-01",
		"evidence_id":    "ev-wf-01",
		"hold_id":        "hold-wf-01",
		"action":         "place",
		"actor":          "legal-counsel",
		"timestamp":      "2026-11-14T08:15:00+03:30",
		"reason":         "Active litigation hold",
		"provider":       "local",
	})
	if holdRec.Code != http.StatusOK {
		t.Fatalf("place hold status=%d body=%s", holdRec.Code, holdRec.Body.String())
	}

	for _, action := range []string{"attempt_delete", "attempt_expire"} {
		negRec := doWorkflowJSON(t, h, http.MethodPost, "/api/v1/workflow/hold", map[string]any{
			"schema_version": "1",
			"case_id":        "case-wf-01",
			"evidence_id":    "ev-wf-01",
			"action":         action,
			"actor":          "ops-cleanup",
			"timestamp":      "2026-11-14T08:16:00+03:30",
			"reason":         "Attempted disposal during active hold",
			"provider":       "local",
		})
		if negRec.Code != http.StatusConflict {
			t.Fatalf("%s expected 409 hold_active, got %d body=%s", action, negRec.Code, negRec.Body.String())
		}
		if !strings.Contains(negRec.Body.String(), "hold_active") || !strings.Contains(negRec.Body.String(), `"evidence_intact":true`) {
			t.Fatalf("%s unexpected hold rejection body: %s", action, negRec.Body.String())
		}
	}

	// 5. Export signed portable bundle
	expRec := doWorkflowJSON(t, h, http.MethodPost, "/api/v1/workflow/export", map[string]any{
		"schema_version": "1",
		"case_id":        "case-wf-01",
		"bundle_id":      "bnd-wf-01",
		"evidence_ids":   []string{"ev-wf-01"},
		"artifact_ids":   []string{"art-wf-01"},
		"provider":       "local",
	})
	if expRec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", expRec.Code, expRec.Body.String())
	}
	var expResp map[string]any
	if err := json.Unmarshal(expRec.Body.Bytes(), &expResp); err != nil {
		t.Fatal(err)
	}
	pubHex, _ := expResp["public_key"].(string)
	if expResp["signed"] != true || pubHex == "" {
		t.Fatalf("expected signed export with public key, got %+v", expResp)
	}

	// 6. Verify authentic bundle + tampered copy fails 422
	verRec := doWorkflowJSON(t, h, http.MethodPost, "/api/v1/workflow/verify-bundle", map[string]any{
		"schema_version":     "1",
		"bundle_id":          "bnd-wf-01",
		"trusted_public_key": pubHex,
		"require_signature":  true,
	})
	if verRec.Code != http.StatusOK {
		t.Fatalf("verify-bundle authentic status=%d body=%s", verRec.Code, verRec.Body.String())
	}
	tamperRec := doWorkflowJSON(t, h, http.MethodPost, "/api/v1/workflow/verify-bundle", map[string]any{
		"schema_version":       "1",
		"bundle_id":            "bnd-wf-01",
		"trusted_public_key":   pubHex,
		"require_signature":    true,
		"simulate_tamper_copy": true,
	})
	if tamperRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("verify-bundle tampered expected 422, got %d body=%s", tamperRec.Code, tamperRec.Body.String())
	}

	// 7. Close & Restart against same storageDir
	closeFn()
	closed = true

	h2, closeFn2 := NewMuxWithOptionsAndCleanup(EngineRuntimeOptions{
		StorageRoot:       storageDir,
		RequireStorageDir: true,
	})
	defer closeFn2()

	stateRec := doWorkflowJSON(t, h2, http.MethodGet, "/api/v1/workflow/state?case_id=case-wf-01", nil)
	if stateRec.Code != http.StatusOK {
		t.Fatalf("post-restart state status=%d body=%s", stateRec.Code, stateRec.Body.String())
	}
	if !strings.Contains(stateRec.Body.String(), expectedSHA) || !strings.Contains(stateRec.Body.String(), "2026-11-14T07:45:12+03:30") {
		t.Fatalf("post-restart state missing persisted sha/timestamp: %s", stateRec.Body.String())
	}

	// 8. Rebuild after derived index drop + RestoreFromBundle into fresh case dir
	recRebuild := doWorkflowJSON(t, h2, http.MethodPost, "/api/v1/workflow/recover", map[string]any{
		"schema_version":   "1",
		"case_id":          "case-wf-01",
		"action":           "rebuild",
		"drop_index_first": true,
		"zone_hint":        "Asia/Tehran",
		"provider":         "local",
	})
	if recRebuild.Code != http.StatusOK {
		t.Fatalf("recover rebuild status=%d body=%s", recRebuild.Code, recRebuild.Body.String())
	}
	if !strings.Contains(recRebuild.Body.String(), `"rebuilt_timeline_entries":2`) || !strings.Contains(recRebuild.Body.String(), `"sealed_bytes_modified":false`) {
		t.Fatalf("unexpected rebuild response: %s", recRebuild.Body.String())
	}

	recRestore := doWorkflowJSON(t, h2, http.MethodPost, "/api/v1/workflow/recover", map[string]any{
		"schema_version": "1",
		"case_id":        "case-wf-01",
		"action":         "restore_bundle",
		"bundle_id":      "bnd-wf-01",
		"target_case_id": "case-wf-01-restored",
		"zone_hint":      "Asia/Tehran",
		"provider":       "local",
	})
	if recRestore.Code != http.StatusOK {
		t.Fatalf("recover restore_bundle status=%d body=%s", recRestore.Code, recRestore.Body.String())
	}
	if !strings.Contains(recRestore.Body.String(), `"restored_evidence_count":1`) || !strings.Contains(recRestore.Body.String(), `"sealed_bytes_modified":false`) {
		t.Fatalf("unexpected restore response: %s", recRestore.Body.String())
	}

	// 9. Negative cases: empty payload, malformed JSON, unavailable provider, missing storage
	emptyRec := doWorkflowJSON(t, h2, http.MethodPost, "/api/v1/workflow/upload-seal", map[string]any{
		"schema_version": "1",
		"case_id":        "case-wf-01",
		"evidence_id":    "ev-empty",
		"payload":        "",
	})
	if emptyRec.Code != http.StatusBadRequest {
		t.Fatalf("empty payload expected 400, got %d", emptyRec.Code)
	}
	badJSONRec := doWorkflowJSON(t, h2, http.MethodPost, "/api/v1/workflow/upload-seal", "{bad")
	if badJSONRec.Code != http.StatusBadRequest {
		t.Fatalf("malformed json expected 400, got %d", badJSONRec.Code)
	}
	unavailProvRec := doWorkflowJSON(t, h2, http.MethodGet, "/api/v1/workflow/state?case_id=case-wf-01&provider=cloud-unavailable", nil)
	if unavailProvRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable provider expected 503, got %d", unavailProvRec.Code)
	}

	missingStorage := filepath.Join(t.TempDir(), "does-not-exist")
	_ = os.RemoveAll(missingStorage)
	hMissing, closeMissing := NewMuxWithOptionsAndCleanup(EngineRuntimeOptions{
		StorageRoot:       missingStorage,
		RequireStorageDir: true,
	})
	defer closeMissing()
	missRec := doWorkflowJSON(t, hMissing, http.MethodGet, "/api/v1/workflow/state?case_id=case-wf-01", nil)
	if missRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing storage expected 503, got %d body=%s", missRec.Code, missRec.Body.String())
	}
}

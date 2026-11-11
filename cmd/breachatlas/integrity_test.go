package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
)

func buildValidCustodyEvent(caseID, evidenceID string, seq uint64, actor, action, ts, reason, prev string) custody.CustodyEvent {
	ev := custody.CustodyEvent{
		SchemaVersion: custody.SchemaVersion,
		EventID:       "cust-c21-01",
		CaseID:        caseID,
		EvidenceID:    evidenceID,
		Sequence:      seq,
		EventType:     action,
		Actor:         actor,
		Timestamp:     ts,
		Reason:        reason,
		PrevHash:      prev,
	}
	ev.EventDigest = custody.ComputeEventDigest(ev)
	ev.CustodyRoot = custody.ComputeCustodyRoot(prev, ev.EventDigest)
	return ev
}

func TestInspectEvidenceIntegrityEndpoint(t *testing.T) {
	handler := NewMux()

	const caseID = "case-c21-ui"
	const shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const shaWrong = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	ev1 := buildValidCustodyEvent(
		caseID,
		"ev-verified-01",
		1,
		"analyst<script>window.__xssSentinel=true</script>",
		"seal_verified",
		"2026-10-01T10:00:00Z",
		`Custody verified <img src=x onerror="window.__xssSentinel=true">`,
		custody.GenesisPrevHash,
	)

	payload := EvidenceInspectRequest{
		SchemaVersion: "1",
		CaseID:        caseID,
		Provider:      "local",
		Items: []EvidenceInspectItemInput{
			{
				EvidenceID:     "ev-verified-01",
				Filename:       `auth-<script>window.__xssSentinel=true</script>.log`,
				MediaType:      "text/plain",
				ExpectedSHA256: shaA,
				ActualSHA256:   shaA,
				SizeBytes:      2048,
				AcquiredAt:     "2026-10-01T10:00:00Z",
				CustodyRoot:    ev1.CustodyRoot,
				Sealed:         true,
				HoldActive:     true,
				HoldReason:     "Litigation hold <b>active</b>",
				CustodyEvents:  []custody.CustodyEvent{ev1},
			},
			{
				EvidenceID:     "ev-incomplete-02",
				Filename:       "partial-upload.bin",
				MediaType:      "application/octet-stream",
				ExpectedSHA256: shaB,
				ActualSHA256:   "",
				SizeBytes:      512,
				AcquiredAt:     "2026-10-01T10:05:00Z",
				CustodyRoot:    "",
				Sealed:         false,
			},
			{
				EvidenceID:     "ev-failed-03",
				Filename:       "tampered.pcap",
				MediaType:      "application/vnd.tcpdump.pcap",
				ExpectedSHA256: shaB,
				ActualSHA256:   shaWrong,
				SizeBytes:      4096,
				AcquiredAt:     "2026-10-01T10:10:00Z",
				CustodyRoot:    shaA,
				Sealed:         true,
			},
		},
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence-integrity/inspect", bytes.NewReader(raw))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp EvidenceInspectResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OverallStatus != "verification_failed" || resp.VerifiedCount != 1 || resp.IncompleteCount != 1 || resp.FailedCount != 1 {
		t.Fatalf("unexpected counts/overall status: %+v", resp)
	}
	if resp.Items[0].CustodyStatus != "custody_verified" || !strings.Contains(resp.Items[0].Filename, "<script>") {
		t.Fatalf("unexpected item[0] verification/escaping passthrough: %+v", resp.Items[0])
	}
	if resp.Items[1].SealStatus != "incomplete_seal" {
		t.Fatalf("expected item[1] incomplete_seal, got %+v", resp.Items[1])
	}
	if resp.Items[2].VerificationStatus != "verification_failed" {
		t.Fatalf("expected item[2] verification_failed, got %+v", resp.Items[2])
	}
}

func TestInspectEvidenceIntegrityNegativeCases(t *testing.T) {
	handler := NewMux()

	cases := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "unavailable_provider",
			body:       `{"schema_version":"1","case_id":"case-c21","provider":"remote-vendor","items":[]}`,
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "unavailable_provider",
		},
		{
			name:       "unsupported_version",
			body:       `{"schema_version":"99","case_id":"case-c21","items":[]}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "unsupported_version",
		},
		{
			name:       "invalid_case_id",
			body:       `{"schema_version":"1","case_id":"../bad","items":[]}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "invalid_field",
		},
		{
			name:       "malformed_json",
			body:       `{"schema_version":"1",`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_json",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence-integrity/inspect", strings.NewReader(tc.body))
			req.Host = "127.0.0.1:8080"
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d (%s)", tc.wantStatus, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantCode) {
				t.Fatalf("expected error code %q in body %s", tc.wantCode, rec.Body.String())
			}
		})
	}
}

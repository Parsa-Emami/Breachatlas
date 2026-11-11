package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInspectTimelineEndpointPositiveAndNotes(t *testing.T) {
	handler := NewMux()
	srcConf := 0.91

	reqBody := TimelineInspectRequest{
		SchemaVersion: "1",
		CaseID:        "case-c22-ui",
		Provider:      "local",
		Events: []TimelineEventInput{
			{
				EvidenceID:       "ev-log-01",
				SourceLine:       1,
				RawTimestamp:     "2026-11-01 01:30:00",
				ZoneHint:         "America/New_York",
				SourceConfidence: &srcConf,
				EventType:        "dst_ambiguous_auth",
				Summary:          `DST fallback login <script>window.__xssSentinel=true</script>`,
			},
			{
				EvidenceID:   "ev-log-01",
				SourceLine:   2,
				RawTimestamp: "2026-11-01 03:00:00",
				EventType:    "zoneless_exec",
				Summary:      "Executed collector without explicit timezone",
			},
			{
				EvidenceID:   "ev-log-01",
				SourceLine:   3,
				RawTimestamp: "2026-11-01T04:00:00-05:00",
				EventType:    "resolved_export",
				Summary:      "Exported artifact digest",
			},
		},
		Notes: []TimelineNoteInput{
			{
				HypothesisID: "hyp-c22-01",
				Author:       `analyst.mina<img src=x onerror="window.__xssSentinel=true">`,
				Rationale:    "Ambiguous 01:30 local wall clock precedes zoneless exec.",
				Statement:    "Repeated SSH auth occurred across DST fold-back.",
				Status:       "proposed",
				UILabel:      "source_evidence",
			},
		},
	}

	raw, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/timeline/inspect", bytes.NewReader(raw))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp TimelineInspectResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OverallStatus != "unresolved_timezones" || resp.ResolvedCount != 1 || resp.UnresolvedCount != 2 {
		t.Fatalf("unexpected resolution counts: %+v", resp)
	}
	if resp.Events[0].Status != "explicit_offset" || resp.Events[0].NormalizedTimestamp != "2026-11-01T09:00:00Z" {
		t.Fatalf("expected explicit_offset event first with preserved UTC, got %+v", resp.Events[0])
	}
	if resp.Events[1].RawTimestamp != "2026-11-01 01:30:00" || resp.Events[1].Status != "dst_ambiguous" || len(resp.Events[1].CandidateUTCs) != 2 {
		t.Fatalf("expected DST ambiguous candidates preserved without UTC fabrication, got %+v", resp.Events[1])
	}
	if resp.Events[1].RawConfidence == nil || *resp.Events[1].RawConfidence != 0.91 {
		t.Fatalf("expected raw_confidence preserved, got %+v", resp.Events[1])
	}
	if len(resp.Notes) != 1 || resp.Notes[0].RecordKind != "analyst_hypothesis" || resp.Notes[0].IsSourceEvidence {
		t.Fatalf("expected separated non-evidence analyst note even with source_evidence UILabel, got %+v", resp.Notes)
	}
}

func TestInspectTimelineEndpointNegativeCases(t *testing.T) {
	handler := NewMux()
	cases := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "unavailable_provider",
			body:       `{"schema_version":"1","case_id":"case-c22","provider":"cloud-vendor","events":[]}`,
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "unavailable_provider",
		},
		{
			name:       "unsupported_version",
			body:       `{"schema_version":"99","case_id":"case-c22","events":[]}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "unsupported_version",
		},
		{
			name:       "note_promotion_forbidden",
			body:       `{"schema_version":"1","case_id":"case-c22","events":[],"notes":[{"hypothesis_id":"hyp-1","author":"a","rationale":"b","statement":"c","claim_source_evidence":true}]}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "promotion_forbidden",
		},
		{
			name:       "note_missing_author",
			body:       `{"schema_version":"1","case_id":"case-c22","events":[],"notes":[{"hypothesis_id":"hyp-1","author":"  ","rationale":"b","statement":"c"}]}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "missing_field",
		},
		{
			name:       "malformed_json",
			body:       `{"schema_version":`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_json",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/timeline/inspect", strings.NewReader(tc.body))
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

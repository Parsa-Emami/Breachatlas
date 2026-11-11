package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/findings"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

type TimelineEventInput struct {
	EvidenceID       string   `json:"evidence_id"`
	InputHash        string   `json:"input_hash,omitempty"`
	SourceLine       int      `json:"source_line"`
	RawTimestamp     string   `json:"raw_timestamp"`
	ZoneHint         string   `json:"zone_hint,omitempty"`
	SourceConfidence *float64 `json:"source_confidence,omitempty"`
	EventType        string   `json:"event_type"`
	Summary          string   `json:"summary"`
}

type TimelineNoteInput struct {
	HypothesisID        string   `json:"hypothesis_id"`
	Author              string   `json:"author"`
	Rationale           string   `json:"rationale"`
	Statement           string   `json:"statement"`
	Status              string   `json:"status,omitempty"`
	Confidence          *float64 `json:"confidence,omitempty"`
	UILabel             string   `json:"ui_label,omitempty"`
	ClaimSourceEvidence bool     `json:"claim_source_evidence,omitempty"`
	ClaimRecordKind     string   `json:"claim_record_kind,omitempty"`
	SupportingEventIDs  []string `json:"supporting_event_ids,omitempty"`
}

type TimelineInspectRequest struct {
	SchemaVersion string               `json:"schema_version"`
	CaseID        string               `json:"case_id"`
	Provider      string               `json:"provider,omitempty"`
	MaxResults    int                  `json:"max_results,omitempty"`
	Events        []TimelineEventInput `json:"events"`
	Notes         []TimelineNoteInput  `json:"notes,omitempty"`
}

type TimelineInspectEventResult struct {
	EventIdentity       string   `json:"event_identity"`
	RecordKind          string   `json:"record_kind"`
	IsSourceEvidence    bool     `json:"is_source_evidence"`
	EvidenceID          string   `json:"evidence_id"`
	SourceLine          int      `json:"source_line"`
	EventType           string   `json:"event_type"`
	Summary             string   `json:"summary"`
	RawTimestamp        string   `json:"raw_timestamp"`
	NormalizedTimestamp string   `json:"normalized_timestamp"`
	TimezoneOffset      string   `json:"timezone_offset"`
	ZoneHint            string   `json:"zone_hint,omitempty"`
	ZoneName            string   `json:"zone_name,omitempty"`
	Status              string   `json:"status"`
	CandidateUTCs       []string `json:"candidate_utcs,omitempty"`
	CandidateOffsets    []string `json:"candidate_offsets,omitempty"`
	Confidence          float64  `json:"confidence"`
	RawConfidence       *float64 `json:"raw_confidence,omitempty"`
}

type TimelineInspectNoteResult struct {
	HypothesisID       string   `json:"hypothesis_id"`
	RecordKind         string   `json:"record_kind"`
	IsSourceEvidence   bool     `json:"is_source_evidence"`
	Author             string   `json:"author"`
	Rationale          string   `json:"rationale"`
	Statement          string   `json:"statement"`
	Status             string   `json:"status"`
	Confidence         *float64 `json:"confidence,omitempty"`
	UILabel            string   `json:"ui_label,omitempty"`
	SupportingEventIDs []string `json:"supporting_event_ids,omitempty"`
}

type TimelineInspectResponse struct {
	SchemaVersion   string                       `json:"schema_version"`
	Status          string                       `json:"status"`
	CaseID          string                       `json:"case_id"`
	Provider        string                       `json:"provider"`
	OverallStatus   string                       `json:"overall_status"`
	TotalEvents     int                          `json:"total_events"`
	ResolvedCount   int                          `json:"resolved_count"`
	UnresolvedCount int                          `json:"unresolved_count"`
	Truncated       bool                         `json:"truncated"`
	TotalNotes      int                          `json:"total_notes"`
	Events          []TimelineInspectEventResult `json:"events"`
	Notes           []TimelineInspectNoteResult  `json:"notes"`
}

func inspectTimeline(w http.ResponseWriter, r *http.Request) {
	var req TimelineInspectRequest
	if !decodeEngineJSON(w, r, maxInspectBytes, &req) {
		return
	}

	if req.SchemaVersion != evidence.SchemaVersion {
		writeEngineProblem(w, http.StatusUnprocessableEntity, evidence.Problem{Code: "unsupported_version", Field: "schema_version"})
		return
	}
	if !inspectIdentRegex.MatchString(req.CaseID) {
		writeEngineProblem(w, http.StatusUnprocessableEntity, evidence.Problem{Code: "invalid_field", Field: "case_id"})
		return
	}
	if !allowedProviders[req.Provider] {
		writeEngineProblem(w, http.StatusServiceUnavailable, evidence.Problem{Code: "unavailable_provider", Field: "provider"})
		return
	}
	if req.Events == nil {
		writeEngineProblem(w, http.StatusUnprocessableEntity, evidence.Problem{Code: "missing_field", Field: "events"})
		return
	}
	if req.MaxResults < 0 || req.MaxResults > timeline.MaxSearchResultsCap {
		writeEngineProblem(w, http.StatusUnprocessableEntity, evidence.Problem{Code: "invalid_field", Field: "max_results"})
		return
	}

	maxResults := req.MaxResults
	if maxResults == 0 {
		maxResults = timeline.DefaultSearchMaxResults
	}

	provider := req.Provider
	if provider == "" {
		provider = "local"
	}

	eventsOut := make([]TimelineInspectEventResult, 0, len(req.Events))
	resolvedCount := 0
	unresolvedCount := 0

	for _, ev := range req.Events {
		if !inspectIdentRegex.MatchString(ev.EvidenceID) {
			writeEngineProblem(w, http.StatusUnprocessableEntity, evidence.Problem{Code: "invalid_field", Field: "evidence_id"})
			return
		}
		nt, err := timeline.NormalizeTimestamp(timeline.NormalizeRequest{
			RawTimestamp:     ev.RawTimestamp,
			ZoneHint:         ev.ZoneHint,
			SourceConfidence: ev.SourceConfidence,
		})
		if err != nil {
			writeEngineProblem(w, http.StatusUnprocessableEntity, evidence.Problem{Code: "invalid_field", Field: "raw_timestamp"})
			return
		}

		inHash := strings.TrimSpace(ev.InputHash)
		if !inspectDigestRegex.MatchString(inHash) {
			sum := sha256.Sum256([]byte("breachatlas:c22-evidence:" + req.CaseID + ":" + ev.EvidenceID))
			inHash = hex.EncodeToString(sum[:])
		}

		evIdentity, err := timeline.ComputeEventIdentity(timeline.EventIdentityInput{
			CaseID:       req.CaseID,
			InputHashes:  []string{inHash},
			SourceLine:   ev.SourceLine,
			RawTimestamp: nt.RawTimestamp,
			EventType:    ev.EventType,
			Summary:      ev.Summary,
		})
		if err != nil {
			writeEngineProblem(w, http.StatusUnprocessableEntity, evidence.Problem{Code: "invalid_field", Field: "events"})
			return
		}

		if nt.NormalizedTimestamp != "" {
			resolvedCount++
		} else {
			unresolvedCount++
		}

		eventsOut = append(eventsOut, TimelineInspectEventResult{
			EventIdentity:       evIdentity,
			RecordKind:          findings.RecordKindObservedFact,
			IsSourceEvidence:    true,
			EvidenceID:          ev.EvidenceID,
			SourceLine:          ev.SourceLine,
			EventType:           ev.EventType,
			Summary:             ev.Summary,
			RawTimestamp:        nt.RawTimestamp,
			NormalizedTimestamp: nt.NormalizedTimestamp,
			TimezoneOffset:      nt.TimezoneOffset,
			ZoneHint:            ev.ZoneHint,
			ZoneName:            nt.SourceZone,
			Status:              nt.TimezoneStatus,
			CandidateUTCs:       nt.CandidateUTCs,
			CandidateOffsets:    nt.CandidateOffsets,
			Confidence:          nt.Confidence,
			RawConfidence:       nt.RawConfidence,
		})
	}

	sort.Slice(eventsOut, func(i, j int) bool {
		ti, oki := parseTimelineUTC(eventsOut[i].NormalizedTimestamp)
		tj, okj := parseTimelineUTC(eventsOut[j].NormalizedTimestamp)
		if oki != okj {
			return oki
		}
		if oki && !ti.Equal(tj) {
			return ti.Before(tj)
		}
		if eventsOut[i].RawTimestamp != eventsOut[j].RawTimestamp {
			return eventsOut[i].RawTimestamp < eventsOut[j].RawTimestamp
		}
		if eventsOut[i].SourceLine != eventsOut[j].SourceLine {
			return eventsOut[i].SourceLine < eventsOut[j].SourceLine
		}
		return eventsOut[i].EventIdentity < eventsOut[j].EventIdentity
	})

	truncated := false
	if len(eventsOut) > maxResults {
		eventsOut = eventsOut[:maxResults]
		truncated = true
	}

	notesOut := make([]TimelineInspectNoteResult, 0, len(req.Notes))
	for _, note := range req.Notes {
		if !inspectIdentRegex.MatchString(note.HypothesisID) {
			writeEngineProblem(w, http.StatusUnprocessableEntity, evidence.Problem{Code: "invalid_field", Field: "hypothesis_id"})
			return
		}
		if note.ClaimSourceEvidence || (strings.TrimSpace(note.ClaimRecordKind) != "" && strings.TrimSpace(note.ClaimRecordKind) != findings.RecordKindAnalystHypothesis) {
			writeEngineProblem(w, http.StatusUnprocessableEntity, evidence.Problem{Code: "promotion_forbidden", Field: "claim_source_evidence"})
			return
		}
		if strings.TrimSpace(note.Author) == "" {
			writeEngineProblem(w, http.StatusUnprocessableEntity, evidence.Problem{Code: "missing_field", Field: "author"})
			return
		}
		if strings.TrimSpace(note.Rationale) == "" {
			writeEngineProblem(w, http.StatusUnprocessableEntity, evidence.Problem{Code: "missing_field", Field: "rationale"})
			return
		}
		if strings.TrimSpace(note.Statement) == "" {
			writeEngineProblem(w, http.StatusUnprocessableEntity, evidence.Problem{Code: "missing_field", Field: "statement"})
			return
		}
		status := strings.TrimSpace(note.Status)
		if status == "" {
			status = findings.HypothesisStatusProposed
		}
		notesOut = append(notesOut, TimelineInspectNoteResult{
			HypothesisID:       note.HypothesisID,
			RecordKind:         findings.RecordKindAnalystHypothesis,
			IsSourceEvidence:   false,
			Author:             strings.TrimSpace(note.Author),
			Rationale:          strings.TrimSpace(note.Rationale),
			Statement:          strings.TrimSpace(note.Statement),
			Status:             status,
			Confidence:         note.Confidence,
			UILabel:            strings.TrimSpace(note.UILabel),
			SupportingEventIDs: note.SupportingEventIDs,
		})
	}

	overall := "resolved"
	switch {
	case len(eventsOut) == 0 && len(notesOut) == 0:
		overall = "empty"
	case unresolvedCount > 0:
		overall = "unresolved_timezones"
	}

	_ = json.NewEncoder(w).Encode(TimelineInspectResponse{
		SchemaVersion:   evidence.SchemaVersion,
		Status:          "valid",
		CaseID:          req.CaseID,
		Provider:        provider,
		OverallStatus:   overall,
		TotalEvents:     len(eventsOut),
		ResolvedCount:   resolvedCount,
		UnresolvedCount: unresolvedCount,
		Truncated:       truncated,
		TotalNotes:      len(notesOut),
		Events:          eventsOut,
		Notes:           notesOut,
	})
}

func parseTimelineUTC(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

const maxInspectBytes = 256 * 1024

var (
	inspectIdentRegex  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	inspectDigestRegex = regexp.MustCompile(`^[a-f0-9]{64}$`)
	allowedProviders   = map[string]bool{
		"":            true,
		"local":       true,
		"breachatlas": true,
	}
)

type EvidenceInspectItemInput struct {
	EvidenceID     string                 `json:"evidence_id"`
	Filename       string                 `json:"filename"`
	MediaType      string                 `json:"media_type"`
	ExpectedSHA256 string                 `json:"expected_sha256"`
	ActualSHA256   string                 `json:"actual_sha256"`
	SizeBytes      int64                  `json:"size_bytes"`
	AcquiredAt     string                 `json:"acquired_at"`
	CustodyRoot    string                 `json:"custody_root"`
	Sealed         bool                   `json:"sealed"`
	HoldActive     bool                   `json:"hold_active,omitempty"`
	HoldReason     string                 `json:"hold_reason,omitempty"`
	CustodyEvents  []custody.CustodyEvent `json:"custody_events,omitempty"`
}

type EvidenceInspectRequest struct {
	SchemaVersion string                     `json:"schema_version"`
	CaseID        string                     `json:"case_id"`
	Provider      string                     `json:"provider,omitempty"`
	Items         []EvidenceInspectItemInput `json:"items"`
}

type EvidenceInspectItemResult struct {
	EvidenceID         string                 `json:"evidence_id"`
	Filename           string                 `json:"filename"`
	MediaType          string                 `json:"media_type"`
	SizeBytes          int64                  `json:"size_bytes"`
	SealStatus         string                 `json:"seal_status"`
	VerificationStatus string                 `json:"verification_status"`
	CustodyStatus      string                 `json:"custody_status"`
	StatusReason       string                 `json:"status_reason"`
	ExpectedSHA256     string                 `json:"expected_sha256"`
	ActualSHA256       string                 `json:"actual_sha256"`
	CustodyRoot        string                 `json:"custody_root"`
	ComputedRoot       string                 `json:"computed_root,omitempty"`
	HoldActive         bool                   `json:"hold_active"`
	HoldReason         string                 `json:"hold_reason,omitempty"`
	CustodyEvents      []custody.CustodyEvent `json:"custody_events,omitempty"`
}

type EvidenceInspectResponse struct {
	SchemaVersion   string                      `json:"schema_version"`
	Status          string                      `json:"status"`
	CaseID          string                      `json:"case_id"`
	Provider        string                      `json:"provider"`
	OverallStatus   string                      `json:"overall_status"`
	TotalItems      int                         `json:"total_items"`
	VerifiedCount   int                         `json:"verified_count"`
	IncompleteCount int                         `json:"incomplete_count"`
	FailedCount     int                         `json:"failed_count"`
	Items           []EvidenceInspectItemResult `json:"items"`
}

func writeEngineProblem(w http.ResponseWriter, status int, problem evidence.Problem) {
	if status == http.StatusRequestEntityTooLarge || status == http.StatusRequestTimeout || status == http.StatusUnsupportedMediaType {
		w.Header().Set("Connection", "close")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		SchemaVersion string           `json:"schema_version"`
		Status        string           `json:"status"`
		Error         evidence.Problem `json:"error"`
	}{evidence.SchemaVersion, "error", problem})
}

func decodeEngineJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) bool {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeEngineProblem(w, http.StatusMethodNotAllowed, evidence.Problem{Code: "method_not_allowed"})
		return false
	}

	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	charset := params["charset"]
	if err != nil || mediaType != "application/json" || (charset != "" && !strings.EqualFold(charset, "utf-8")) || r.Header.Get("Content-Encoding") != "" {
		writeEngineProblem(w, http.StatusUnsupportedMediaType, evidence.Problem{Code: "unsupported_media_type"})
		return false
	}
	if r.ContentLength > maxBytes {
		writeEngineProblem(w, http.StatusRequestEntityTooLarge, evidence.Problem{Code: "payload_too_large"})
		return false
	}

	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeEngineProblem(w, http.StatusServiceUnavailable, evidence.Problem{Code: "engine_unavailable"})
		return false
	}
	defer controller.SetReadDeadline(time.Time{})

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	var maxBytesError *http.MaxBytesError
	switch {
	case errors.As(err, &maxBytesError):
		writeEngineProblem(w, http.StatusRequestEntityTooLarge, evidence.Problem{Code: "payload_too_large"})
		return false
	case errors.Is(err, os.ErrDeadlineExceeded):
		writeEngineProblem(w, http.StatusRequestTimeout, evidence.Problem{Code: "request_timeout"})
		return false
	case r.Context().Err() != nil:
		return false
	case err != nil:
		writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_json"})
		return false
	}

	if !utf8.Valid(body) {
		writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_json"})
		return false
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_json"})
		return false
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_json"})
		return false
	}
	return true
}

func inspectEvidenceIntegrity(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, problem evidence.Problem) {
		writeEngineProblem(w, status, problem)
	}

	var req EvidenceInspectRequest
	if !decodeEngineJSON(w, r, maxInspectBytes, &req) {
		return
	}

	if req.SchemaVersion != evidence.SchemaVersion {
		fail(http.StatusUnprocessableEntity, evidence.Problem{Code: "unsupported_version", Field: "schema_version"})
		return
	}
	if !inspectIdentRegex.MatchString(req.CaseID) {
		fail(http.StatusUnprocessableEntity, evidence.Problem{Code: "invalid_field", Field: "case_id"})
		return
	}
	if !allowedProviders[req.Provider] {
		fail(http.StatusServiceUnavailable, evidence.Problem{Code: "unavailable_provider", Field: "provider"})
		return
	}
	if req.Items == nil {
		fail(http.StatusUnprocessableEntity, evidence.Problem{Code: "missing_field", Field: "items"})
		return
	}

	provider := req.Provider
	if provider == "" {
		provider = "local"
	}

	results := make([]EvidenceInspectItemResult, 0, len(req.Items))
	verifiedCount := 0
	incompleteCount := 0
	failedCount := 0

	for _, item := range req.Items {
		if !inspectIdentRegex.MatchString(item.EvidenceID) {
			fail(http.StatusUnprocessableEntity, evidence.Problem{Code: "invalid_field", Field: "evidence_id"})
			return
		}
		res := evaluateEvidenceItem(req.CaseID, item)
		results = append(results, res)
		switch {
		case res.VerificationStatus == "verification_failed":
			failedCount++
		case res.SealStatus == "incomplete_seal" || res.VerificationStatus != "verified":
			incompleteCount++
		default:
			verifiedCount++
		}
	}

	overall := "verified"
	switch {
	case len(results) == 0:
		overall = "empty"
	case failedCount > 0:
		overall = "verification_failed"
	case incompleteCount > 0:
		overall = "incomplete_seal"
	}

	_ = json.NewEncoder(w).Encode(EvidenceInspectResponse{
		SchemaVersion:   evidence.SchemaVersion,
		Status:          "valid",
		CaseID:          req.CaseID,
		Provider:        provider,
		OverallStatus:   overall,
		TotalItems:      len(results),
		VerifiedCount:   verifiedCount,
		IncompleteCount: incompleteCount,
		FailedCount:     failedCount,
		Items:           results,
	})
}

func evaluateEvidenceItem(caseID string, item EvidenceInspectItemInput) EvidenceInspectItemResult {
	res := EvidenceInspectItemResult{
		EvidenceID:     item.EvidenceID,
		Filename:       item.Filename,
		MediaType:      item.MediaType,
		SizeBytes:      item.SizeBytes,
		ExpectedSHA256: item.ExpectedSHA256,
		ActualSHA256:   item.ActualSHA256,
		CustodyRoot:    item.CustodyRoot,
		HoldActive:     item.HoldActive,
		HoldReason:     item.HoldReason,
		CustodyEvents:  append([]custody.CustodyEvent(nil), item.CustodyEvents...),
	}

	custodyStatus, computedRoot, custodyReason := verifyCustodySlice(caseID, item.EvidenceID, item.CustodyEvents)
	res.CustodyStatus = custodyStatus
	res.ComputedRoot = computedRoot

	hasValidExpected := inspectDigestRegex.MatchString(item.ExpectedSHA256)
	hasValidActual := inspectDigestRegex.MatchString(item.ActualSHA256)
	hasCustodyRoot := inspectDigestRegex.MatchString(item.CustodyRoot)
	sealComplete := item.Sealed && hasValidExpected && hasCustodyRoot && item.SizeBytes > 0 && strings.TrimSpace(item.AcquiredAt) != ""

	if sealComplete {
		res.SealStatus = "sealed"
	} else {
		res.SealStatus = "incomplete_seal"
	}

	// Verification failure takes highest precedence (tampered digest or broken custody hash chain).
	if custodyStatus == "custody_failed" {
		res.VerificationStatus = "verification_failed"
		res.StatusReason = custodyReason
		return res
	}
	if len(item.CustodyEvents) > 0 && hasCustodyRoot && computedRoot != "" && item.CustodyRoot != computedRoot {
		res.CustodyStatus = "custody_failed"
		res.VerificationStatus = "verification_failed"
		res.StatusReason = "Custody root digest does not match verified custody event chain."
		return res
	}
	if hasValidExpected && item.ActualSHA256 != "" && (!hasValidActual || item.ActualSHA256 != item.ExpectedSHA256) {
		res.VerificationStatus = "verification_failed"
		res.StatusReason = "Sealed SHA-256 verification failed: source bytes do not match expected manifest digest."
		return res
	}
	if !sealComplete {
		res.VerificationStatus = "pending_seal"
		res.StatusReason = "Seal incomplete: sealed evidence manifest or custody root has not been finalized."
		return res
	}
	if !hasValidActual {
		res.VerificationStatus = "verification_failed"
		res.StatusReason = "Sealed verification failed: missing or invalid verified source SHA-256 digest."
		return res
	}

	res.VerificationStatus = "verified"
	res.StatusReason = "Sealed digest and custody record verified."
	return res
}

func verifyCustodySlice(caseID, evidenceID string, events []custody.CustodyEvent) (string, string, string) {
	if len(events) == 0 {
		return "custody_missing", "", ""
	}
	expectedPrev := custody.GenesisPrevHash
	for i, ev := range events {
		if ev.SchemaVersion != custody.SchemaVersion || ev.CaseID != caseID || ev.EvidenceID != evidenceID {
			return "custody_failed", "", "Custody event binding mismatch on case or evidence identifier."
		}
		if ev.Sequence != uint64(i+1) {
			return "custody_failed", "", "Custody event sequence gap or out-of-order entry."
		}
		if ev.PrevHash != expectedPrev {
			return "custody_failed", "", "Custody chain break: prev_hash mismatch."
		}
		wantDigest := custody.ComputeEventDigest(ev)
		if ev.EventDigest != wantDigest {
			return "custody_failed", "", "Custody event digest mismatch."
		}
		wantRoot := custody.ComputeCustodyRoot(expectedPrev, wantDigest)
		if ev.CustodyRoot != wantRoot {
			return "custody_failed", "", "Custody event root mismatch."
		}
		expectedPrev = wantRoot
	}
	return "custody_verified", expectedPrev, ""
}

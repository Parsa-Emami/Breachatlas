package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

func validateManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	fail := func(status int, problem evidence.Problem) {
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
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(http.StatusMethodNotAllowed, evidence.Problem{Code: "method_not_allowed"})
		return
	}
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	charset := params["charset"]
	if err != nil || mediaType != "application/json" || charset != "" && !strings.EqualFold(charset, "utf-8") || r.Header.Get("Content-Encoding") != "" {
		fail(http.StatusUnsupportedMediaType, evidence.Problem{Code: "unsupported_media_type"})
		return
	}
	if r.ContentLength > evidence.MaxManifestBytes {
		fail(http.StatusRequestEntityTooLarge, evidence.Problem{Code: "payload_too_large"})
		return
	}
	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		fail(http.StatusServiceUnavailable, evidence.Problem{Code: "engine_unavailable"})
		return
	}
	defer controller.SetReadDeadline(time.Time{})
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, evidence.MaxManifestBytes))
	var maxBytesError *http.MaxBytesError
	switch {
	case errors.As(err, &maxBytesError):
		fail(http.StatusRequestEntityTooLarge, evidence.Problem{Code: "payload_too_large"})
		return
	case errors.Is(err, os.ErrDeadlineExceeded):
		fail(http.StatusRequestTimeout, evidence.Problem{Code: "request_timeout"})
		return
	case r.Context().Err() != nil:
		return
	case err != nil:
		fail(http.StatusBadRequest, evidence.Problem{Code: "invalid_json"})
		return
	}
	manifest, problem := evidence.ParseManifest(r.Context(), body)
	if problem != nil {
		if problem.Code == "request_cancelled" {
			return
		}
		status := http.StatusUnprocessableEntity
		if problem.Code == "invalid_json" {
			status = http.StatusBadRequest
		}
		fail(status, *problem)
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		SchemaVersion string `json:"schema_version"`
		Status        string `json:"status"`
		InputDigest   string `json:"input_digest"`
		EngineVersion string `json:"engine_version"`
		Result        struct {
			CaseID     string `json:"case_id"`
			EvidenceID string `json:"evidence_id"`
		} `json:"result"`
	}{
		SchemaVersion: evidence.SchemaVersion,
		Status:        "valid",
		InputDigest:   fmt.Sprintf("%x", sha256.Sum256(body)),
		EngineVersion: EngineVersion,
		Result: struct {
			CaseID     string `json:"case_id"`
			EvidenceID string `json:"evidence_id"`
		}{manifest.CaseID, manifest.EvidenceID},
	})
}

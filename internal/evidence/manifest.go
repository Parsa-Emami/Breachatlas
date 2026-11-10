package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion    = "1"
	MaxManifestBytes = 16 * 1024
	MaxEvidenceBytes = 100 * 1024 * 1024
)

type Manifest struct {
	SchemaVersion string `json:"schema_version"`
	CaseID        string `json:"case_id"`
	EvidenceID    string `json:"evidence_id"`
	SHA256        string `json:"sha256"`
	SizeBytes     int64  `json:"size_bytes"`
	MediaType     string `json:"media_type"`
	AcquiredAt    string `json:"acquired_at"`
	CustodyRoot   string `json:"custody_root"`
}

type Problem struct {
	Code  string `json:"code"`
	Field string `json:"field,omitempty"`
}

var (
	identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	digest     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	mediaType  = regexp.MustCompile(`^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$`)
	timestamp  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$`)
)

func ParseManifest(ctx context.Context, body []byte) (Manifest, *Problem) {
	switch {
	case ctx.Err() != nil:
		return Manifest{}, &Problem{Code: "request_cancelled"}
	case len(body) > MaxManifestBytes:
		return Manifest{}, &Problem{Code: "payload_too_large"}
	case !utf8.Valid(body) || !json.Valid(body):
		return Manifest{}, &Problem{Code: "invalid_json"}
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return Manifest{}, &Problem{Code: "invalid_manifest"}
	}

	var manifest Manifest
	fields := []struct {
		name  string
		value any
		valid func() bool
	}{
		{"schema_version", &manifest.SchemaVersion, func() bool { return manifest.SchemaVersion == SchemaVersion }},
		{"case_id", &manifest.CaseID, func() bool { return identifier.MatchString(manifest.CaseID) }},
		{"evidence_id", &manifest.EvidenceID, func() bool { return identifier.MatchString(manifest.EvidenceID) }},
		{"sha256", &manifest.SHA256, func() bool { return digest.MatchString(manifest.SHA256) }},
		{"size_bytes", &manifest.SizeBytes, func() bool { return manifest.SizeBytes >= 0 && manifest.SizeBytes <= MaxEvidenceBytes }},
		{"media_type", &manifest.MediaType, func() bool { return len(manifest.MediaType) <= 127 && mediaType.MatchString(manifest.MediaType) }},
		{"acquired_at", &manifest.AcquiredAt, func() bool {
			_, err := time.Parse(time.RFC3339Nano, manifest.AcquiredAt)
			return err == nil && timestamp.MatchString(manifest.AcquiredAt)
		}},
		{"custody_root", &manifest.CustodyRoot, func() bool { return digest.MatchString(manifest.CustodyRoot) }},
	}
	pending := make(map[string]any, len(fields))
	for _, field := range fields {
		pending[field.name] = field.value
	}

	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return Manifest{}, &Problem{Code: "invalid_json"}
		}
		name := token.(string)
		value, known := pending[name]
		if !known {
			return Manifest{}, &Problem{Code: "unexpected_or_duplicate_field"}
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return Manifest{}, &Problem{Code: "invalid_json"}
		}
		if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, value) != nil {
			return Manifest{}, &Problem{Code: "invalid_field", Field: name}
		}
		delete(pending, name)
	}

	for _, field := range fields {
		if _, missing := pending[field.name]; missing {
			return Manifest{}, &Problem{Code: "missing_field", Field: field.name}
		}
		if !field.valid() {
			code := "invalid_field"
			if field.name == "schema_version" {
				code = "unsupported_version"
			}
			return Manifest{}, &Problem{Code: code, Field: field.name}
		}
	}
	if ctx.Err() != nil {
		return Manifest{}, &Problem{Code: "request_cancelled"}
	}
	return manifest, nil
}

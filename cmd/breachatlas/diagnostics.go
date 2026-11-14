package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/storage"
)

const (
	DefaultMaxDiagnosticEntries = 64
	DefaultMaxDiagnosticBytes   = 16384
	MaxDiagnosticMessageBytes   = 256
)

var (
	reSentinelToken = regexp.MustCompile(`(?i)\b(?:SECRET|CREDENTIAL|TOKEN|PRIVATE_KEY|API_KEY|AUTH)_SENTINEL(?:_[A-Z0-9_-]+)?\b`)
	rePEMBlock      = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	rePEMHeader     = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^\r\n]*`)
	reBearerToken   = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`)
	reURLUserInfo   = regexp.MustCompile(`(?i)(https?://)[^/@\s]+:[^/@\s]+@`)
	reKeyValueSecret = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api_key|apikey|access_key|private_key|client_secret|authorization|cookie)\s*([=:])\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`)
)

// EngineRuntimeOptions configures readiness probes and bounded diagnostics for the Go engine.
type EngineRuntimeOptions struct {
	StorageRoot       string
	RequireStorageDir bool
	RequiredProviders []string
	MaxLogEntries     int
	MaxLogBytes       int
	Logger            *DiagnosticLogger
}

// DiagnosticEntry represents one bounded, secret-redacted diagnostic event.
type DiagnosticEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Component string `json:"component"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Redacted  bool   `json:"redacted"`
}

// DiagnosticSnapshot summarizes the bounded ring buffer state.
type DiagnosticSnapshot struct {
	MaxEntries    int               `json:"max_entries"`
	MaxBytes      int               `json:"max_bytes"`
	TotalBytes    int               `json:"total_bytes"`
	EvictedCount  int               `json:"evicted_count"`
	RedactedCount int               `json:"redacted_count"`
	Entries       []DiagnosticEntry `json:"entries"`
}

// ComponentFailure records an explicit non-placeholder failure for readiness visibility.
type ComponentFailure struct {
	Component string `json:"component"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

// ReadinessReport separates web, engine, authoritative storage, and required provider readiness.
type ReadinessReport struct {
	Status           string             `json:"status"`
	Service          string             `json:"service"`
	Version          string             `json:"version"`
	Scope            string             `json:"scope"`
	EngineReady      bool               `json:"engineReady"`
	StorageReady     bool               `json:"storageReady"`
	ProvidersReady   bool               `json:"providersReady"`
	Storage          StorageReadiness   `json:"storage"`
	Providers        ProviderReadiness  `json:"providers"`
	Failures         []ComponentFailure `json:"failures"`
	CheckedAt        string             `json:"checked_at"`
}

// StorageReadiness captures authoritative local store health and root fingerprint.
type StorageReadiness struct {
	Ready           bool   `json:"ready"`
	RootConfigured  bool   `json:"root_configured"`
	RootFingerprint string `json:"root_fingerprint,omitempty"`
	OperationsCount int    `json:"operations_count"`
	EvidenceCount   int    `json:"evidence_count"`
	ErrorCode       string `json:"error_code,omitempty"`
	Message         string `json:"message,omitempty"`
}

// ProviderReadiness captures required provider verification state.
type ProviderReadiness struct {
	Ready              bool     `json:"ready"`
	Required           []string `json:"required"`
	Available          []string `json:"available"`
	Missing            []string `json:"missing"`
	AllowlistedParsers []string `json:"allowlisted_parsers"`
	ErrorCode          string   `json:"error_code,omitempty"`
	Message            string   `json:"message,omitempty"`
}

// DiagnosticLogger maintains a thread-safe, bounded, secret-redacted diagnostic ring buffer.
type DiagnosticLogger struct {
	mu            sync.Mutex
	maxEntries    int
	maxBytes      int
	totalBytes    int
	evictedCount  int
	redactedCount int
	entries       []diagnosticStored
}

type diagnosticStored struct {
	entry DiagnosticEntry
	bytes int
}

// NewDiagnosticLogger constructs a bounded logger with explicit entry and byte ceilings.
func NewDiagnosticLogger(maxEntries, maxBytes int) *DiagnosticLogger {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxDiagnosticEntries
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxDiagnosticBytes
	}
	return &DiagnosticLogger{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		entries:    make([]diagnosticStored, 0, maxEntries),
	}
}

// RedactDiagnosticText strips synthetic sentinels, tokens, credentials, and PEM keys before storage or emission.
func RedactDiagnosticText(raw string) (string, bool) {
	redacted := raw
	changed := false

	apply := func(re *regexp.Regexp, repl string) {
		next := re.ReplaceAllString(redacted, repl)
		if next != redacted {
			redacted = next
			changed = true
		}
	}

	apply(rePEMBlock, "[REDACTED_PEM]")
	apply(rePEMHeader, "[REDACTED_PEM]")
	apply(reSentinelToken, "[REDACTED]")
	apply(reBearerToken, "$1 [REDACTED]")
	apply(reURLUserInfo, "${1}[REDACTED]@")
	apply(reKeyValueSecret, "${1}${2}[REDACTED]")

	return redacted, changed
}

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes <= 3 {
		return s[:maxBytes]
	}
	limit := maxBytes - 3
	for limit > 0 && !utf8.ValidString(s[:limit]) {
		limit--
	}
	return s[:limit] + "..."
}

// Record sanitizes, truncates, and stores a diagnostic entry within configured byte and entry bounds.
func (l *DiagnosticLogger) Record(level, component, code, message string) DiagnosticEntry {
	cleanComponent, cRedacted := RedactDiagnosticText(strings.TrimSpace(component))
	cleanCode, codeRedacted := RedactDiagnosticText(strings.TrimSpace(code))
	cleanMsg, msgRedacted := RedactDiagnosticText(strings.TrimSpace(message))
	wasRedacted := cRedacted || codeRedacted || msgRedacted

	entry := DiagnosticEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     strings.ToLower(strings.TrimSpace(level)),
		Component: truncateUTF8(cleanComponent, 64),
		Code:      truncateUTF8(cleanCode, 64),
		Message:   truncateUTF8(cleanMsg, MaxDiagnosticMessageBytes),
		Redacted:  wasRedacted,
	}
	if entry.Level == "" {
		entry.Level = "info"
	}

	encoded, _ := json.Marshal(entry)
	entryBytes := len(encoded)

	l.mu.Lock()
	defer l.mu.Unlock()

	if wasRedacted {
		l.redactedCount++
	}
	if entryBytes > l.maxBytes {
		entry.Message = "[TRUNCATED]"
		encoded, _ = json.Marshal(entry)
		entryBytes = len(encoded)
	}

	for len(l.entries) > 0 && (len(l.entries) >= l.maxEntries || l.totalBytes+entryBytes > l.maxBytes) {
		l.totalBytes -= l.entries[0].bytes
		l.entries = l.entries[1:]
		l.evictedCount++
	}

	l.entries = append(l.entries, diagnosticStored{entry: entry, bytes: entryBytes})
	l.totalBytes += entryBytes
	return entry
}

// Snapshot returns a copy of current bounded diagnostic entries and counters.
func (l *DiagnosticLogger) Snapshot() DiagnosticSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make([]DiagnosticEntry, len(l.entries))
	for i, item := range l.entries {
		out[i] = item.entry
	}
	return DiagnosticSnapshot{
		MaxEntries:    l.maxEntries,
		MaxBytes:      l.maxBytes,
		TotalBytes:    l.totalBytes,
		EvictedCount:  l.evictedCount,
		RedactedCount: l.redactedCount,
		Entries:       out,
	}
}

func defaultRequiredProviders(in []string) []string {
	if len(in) == 0 {
		return []string{"local", analyzers.AnalyzerCSV, analyzers.AnalyzerJSON}
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; !ok {
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return []string{"local"}
	}
	return out
}

func fingerprintPath(p string) string {
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:8])
}

func probeStorageReadiness(storageRoot string, requireExisting bool) StorageReadiness {
	trimmed := strings.TrimSpace(storageRoot)
	if trimmed == "" {
		return StorageReadiness{
			Ready:          false,
			RootConfigured: false,
			ErrorCode:      "storage_root_missing",
			Message:        "Authoritative storage root path is not configured.",
		}
	}
	if strings.ContainsRune(trimmed, '\x00') {
		return StorageReadiness{
			Ready:          false,
			RootConfigured: true,
			ErrorCode:      "storage_invalid_root",
			Message:        "Storage root path contains illegal null byte.",
		}
	}
	for _, seg := range strings.FieldsFunc(trimmed, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return StorageReadiness{
				Ready:          false,
				RootConfigured: true,
				ErrorCode:      "storage_invalid_root",
				Message:        "Storage root path contains disallowed traversal segment.",
			}
		}
	}

	absRoot, err := filepath.Abs(filepath.Clean(trimmed))
	if err != nil {
		cleanMsg, _ := RedactDiagnosticText(err.Error())
		return StorageReadiness{
			Ready:          false,
			RootConfigured: true,
			ErrorCode:      "storage_invalid_root",
			Message:        cleanMsg,
		}
	}

	info, err := os.Lstat(absRoot)
	if err != nil {
		if os.IsNotExist(err) && !requireExisting {
			if mkErr := os.MkdirAll(absRoot, 0750); mkErr != nil {
				cleanMsg, _ := RedactDiagnosticText(mkErr.Error())
				return StorageReadiness{
					Ready:           false,
					RootConfigured:  true,
					RootFingerprint: fingerprintPath(absRoot),
					ErrorCode:       "storage_unavailable",
					Message:         cleanMsg,
				}
			}
			info, err = os.Lstat(absRoot)
		}
		if err != nil {
			code := "storage_unavailable"
			if os.IsNotExist(err) {
				code = "storage_prerequisite_missing"
			}
			cleanMsg, _ := RedactDiagnosticText(err.Error())
			return StorageReadiness{
				Ready:           false,
				RootConfigured:  true,
				RootFingerprint: fingerprintPath(absRoot),
				ErrorCode:       code,
				Message:         cleanMsg,
			}
		}
	}

	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return StorageReadiness{
			Ready:           false,
			RootConfigured:  true,
			RootFingerprint: fingerprintPath(absRoot),
			ErrorCode:       "storage_invalid_root",
			Message:         "Storage root must be a real non-symlink directory.",
		}
	}

	adapter, err := storage.Open(storage.Config{RootDir: absRoot, SyncDir: false})
	if err != nil {
		cleanMsg, _ := RedactDiagnosticText(err.Error())
		return StorageReadiness{
			Ready:           false,
			RootConfigured:  true,
			RootFingerprint: fingerprintPath(absRoot),
			ErrorCode:       "storage_unavailable",
			Message:         cleanMsg,
		}
	}
	state := adapter.CurrentState()
	closeErr := adapter.Close()
	if closeErr != nil {
		cleanMsg, _ := RedactDiagnosticText(closeErr.Error())
		return StorageReadiness{
			Ready:           false,
			RootConfigured:  true,
			RootFingerprint: fingerprintPath(absRoot),
			ErrorCode:       "storage_unavailable",
			Message:         cleanMsg,
		}
	}

	return StorageReadiness{
		Ready:           true,
		RootConfigured:  true,
		RootFingerprint: fingerprintPath(absRoot),
		OperationsCount: len(state.Operations),
		EvidenceCount:   len(state.Evidence),
	}
}

func probeProviderReadiness(required []string, storageRoot string) ProviderReadiness {
	reqList := defaultRequiredProviders(required)

	reg, err := analyzers.NewRegistry(analyzers.RegistryConfig{
		Provider:    "local",
		SealRootDir: storageRoot,
	})
	if err != nil {
		cleanMsg, _ := RedactDiagnosticText(err.Error())
		return ProviderReadiness{
			Ready:              false,
			Required:           reqList,
			Available:          []string{},
			Missing:            reqList,
			AllowlistedParsers: []string{},
			ErrorCode:          "provider_unavailable",
			Message:            cleanMsg,
		}
	}

	allowlisted := reg.Allowlisted()
	parserIDs := make([]string, 0, len(allowlisted))
	for _, desc := range allowlisted {
		parserIDs = append(parserIDs, desc.ID)
	}

	available := make([]string, 0, len(reqList))
	missing := make([]string, 0)
	for _, p := range reqList {
		if p == "local" {
			available = append(available, p)
			continue
		}
		if _, resolveErr := reg.Resolve(p, "local"); resolveErr == nil {
			available = append(available, p)
			continue
		}
		missing = append(missing, p)
	}

	if len(missing) > 0 {
		return ProviderReadiness{
			Ready:              false,
			Required:           reqList,
			Available:          available,
			Missing:            missing,
			AllowlistedParsers: parserIDs,
			ErrorCode:          "provider_unavailable",
			Message:            fmt.Sprintf("Required provider(s) unavailable: %s", strings.Join(missing, ", ")),
		}
	}

	return ProviderReadiness{
		Ready:              true,
		Required:           reqList,
		Available:          available,
		Missing:            []string{},
		AllowlistedParsers: parserIDs,
	}
}

func evaluateReadiness(opts EngineRuntimeOptions, logger *DiagnosticLogger) ReadinessReport {
	storageRoot := strings.TrimSpace(opts.StorageRoot)
	storageProbe := probeStorageReadiness(storageRoot, opts.RequireStorageDir)
	providerRoot := ""
	if storageProbe.Ready {
		providerRoot = storageRoot
	}
	providerProbe := probeProviderReadiness(opts.RequiredProviders, providerRoot)

	failures := make([]ComponentFailure, 0, 2)
	if !storageProbe.Ready {
		failures = append(failures, ComponentFailure{
			Component: "storage",
			Code:      storageProbe.ErrorCode,
			Message:   storageProbe.Message,
		})
		logger.Record("error", "storage", storageProbe.ErrorCode, storageProbe.Message)
	}
	if !providerProbe.Ready {
		failures = append(failures, ComponentFailure{
			Component: "provider",
			Code:      providerProbe.ErrorCode,
			Message:   providerProbe.Message,
		})
		logger.Record("error", "provider", providerProbe.ErrorCode, providerProbe.Message)
	}

	allReady := storageProbe.Ready && providerProbe.Ready
	status := "ready"
	if !allReady {
		status = "not_ready"
	}

	return ReadinessReport{
		Status:         status,
		Service:        ServiceName,
		Version:        EngineVersion,
		Scope:          "local-loopback",
		EngineReady:    true,
		StorageReady:   storageProbe.Ready,
		ProvidersReady: providerProbe.Ready,
		Storage:        storageProbe,
		Providers:      providerProbe,
		Failures:       failures,
		CheckedAt:      time.Now().UTC().Format(time.RFC3339),
	}
}

func registerDiagnosticsRoutes(mux *http.ServeMux, opts EngineRuntimeOptions) {
	logger := opts.Logger
	if logger == nil {
		logger = NewDiagnosticLogger(opts.MaxLogEntries, opts.MaxLogBytes)
	}
	if strings.TrimSpace(opts.StorageRoot) == "" && !opts.RequireStorageDir {
		opts.StorageRoot = filepath.Join(os.TempDir(), fmt.Sprintf("breachatlas-engine-%d", os.Getpid()))
	}

	logger.Record("info", "engine", "startup", fmt.Sprintf("%s %s initialized bounded diagnostics", ServiceName, EngineVersion))

	var probeMu sync.Mutex

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		probeMu.Lock()
		report := evaluateReadiness(opts, logger)
		probeMu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if report.Status != "ready" {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(report)
		}
	})

	mux.HandleFunc("/api/v1/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		probeMu.Lock()
		report := evaluateReadiness(opts, logger)
		snap := logger.Snapshot()
		probeMu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if report.Status != "ready" {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schema_version": "1",
				"status":         report.Status,
				"engine_health": map[string]any{
					"status":  "ok",
					"service": ServiceName,
					"version": EngineVersion,
					"scope":   "local-loopback",
				},
				"readiness":   report,
				"diagnostics": snap,
			})
		}
	})
}

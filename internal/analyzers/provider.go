package analyzers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

const (
	SchemaVersion = "1"

	AnalyzerCSV = "csv"
	AnalyzerJSON = "json"

	ToolVersionCSV  = "breachatlas-csv/1.0.0"
	ToolVersionJSON = "breachatlas-json/1.0.0"

	DefaultMaxInputBytes   int64 = 16 * 1024 * 1024 // 16 MiB bounded parser input
	DefaultMaxRecords      int   = 100000
	DefaultMaxFieldsPerRow int   = 256
	DefaultMaxJSONDepth    int   = 32
)

var (
	ErrAnalyzerNotAllowlisted   = errors.New("analyzer is not in the shipped MVP allowlist")
	ErrExecutingParserForbidden = errors.New("executing or dynamic code parsers are forbidden in MVP")
	ErrUnavailableProvider      = errors.New("unavailable analyzer provider")
	ErrMissingPrerequisite      = errors.New("missing prerequisite")
	ErrMalformedInput           = errors.New("malformed analyzer input")
	ErrInputTooLarge            = errors.New("analyzer input exceeds configured bounds")
	ErrInputDigestMismatch      = errors.New("sealed evidence digest mismatch during analysis")
	ErrInvalidConfig            = errors.New("invalid analyzer configuration or request")
	ErrPathTraversal            = errors.New("path traversal or invalid identifier rejected")
	ErrSymlinkRejected          = errors.New("symlink rejected in analyzer evidence path")
)

var (
	identifierRegex  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	allowedProviders = map[string]bool{
		"":            true,
		"local":       true,
		"breachatlas": true,
	}
	shippedAllowlist = map[string]bool{
		AnalyzerCSV:  true,
		AnalyzerJSON: true,
	}
)

func isValidIdentifier(s string) bool {
	return identifierRegex.MatchString(s) && !strings.Contains(s, "..") && !strings.ContainsAny(s, "/\\")
}

func checkWithinDir(root, target string) error {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %s escapes root", ErrPathTraversal, target)
	}
	return nil
}

func ensureNoSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlinkRejected, path)
	}
	return nil
}

// ParseOptions constrains non-executing bounded parser resource consumption.
type ParseOptions struct {
	MaxInputBytes   int64 `json:"max_input_bytes"`
	MaxRecords      int   `json:"max_records"`
	MaxFieldsPerRow int   `json:"max_fields_per_row"`
	MaxJSONDepth    int   `json:"max_json_depth"`
}

// DefaultParseOptions returns bounded MVP defaults suitable for local evidence artifacts.
func DefaultParseOptions() ParseOptions {
	return ParseOptions{
		MaxInputBytes:   DefaultMaxInputBytes,
		MaxRecords:      DefaultMaxRecords,
		MaxFieldsPerRow: DefaultMaxFieldsPerRow,
		MaxJSONDepth:    DefaultMaxJSONDepth,
	}
}

func normalizeParseOptions(opts ParseOptions) (ParseOptions, error) {
	if opts.MaxInputBytes == 0 {
		opts.MaxInputBytes = DefaultMaxInputBytes
	}
	if opts.MaxRecords == 0 {
		opts.MaxRecords = DefaultMaxRecords
	}
	if opts.MaxFieldsPerRow == 0 {
		opts.MaxFieldsPerRow = DefaultMaxFieldsPerRow
	}
	if opts.MaxJSONDepth == 0 {
		opts.MaxJSONDepth = DefaultMaxJSONDepth
	}
	if opts.MaxInputBytes < 0 || opts.MaxInputBytes > evidence.MaxEvidenceBytes {
		return ParseOptions{}, fmt.Errorf("%w: max_input_bytes %d out of bounds [1..%d]", ErrInvalidConfig, opts.MaxInputBytes, evidence.MaxEvidenceBytes)
	}
	if opts.MaxRecords < 1 || opts.MaxFieldsPerRow < 1 || opts.MaxJSONDepth < 1 {
		return ParseOptions{}, fmt.Errorf("%w: max_records, max_fields_per_row, and max_json_depth must be positive", ErrInvalidConfig)
	}
	return opts, nil
}

// ConfigDigest calculates a deterministic SHA-256 hash of parser identity and bounds.
func ConfigDigest(analyzerID, toolVersion string, opts ParseOptions) string {
	canon := fmt.Sprintf(
		"breachatlas:analyzer:v1:%s:%s:max_bytes=%d:max_records=%d:max_fields=%d:max_depth=%d:non_executing=true",
		analyzerID, toolVersion, opts.MaxInputBytes, opts.MaxRecords, opts.MaxFieldsPerRow, opts.MaxJSONDepth,
	)
	sum := sha256.Sum256([]byte(canon))
	return hex.EncodeToString(sum[:])
}

// Descriptor describes an allowlisted non-executing analyzer implementation.
type Descriptor struct {
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	Format       string   `json:"format"`
	MediaTypes   []string `json:"media_types"`
	NonExecuting bool     `json:"non_executing"`
	Executing    bool     `json:"executing"`
	ReadOnly     bool     `json:"read_only"`
	Capabilities []string `json:"capabilities"`
	ConfigDigest string   `json:"config_digest"`
}

// ParsedRecord represents one deterministic structured record extracted from evidence.
type ParsedRecord struct {
	Index     int            `json:"index"`
	RowNumber int            `json:"row_number"`
	Timestamp string         `json:"timestamp,omitempty"`
	Fields    map[string]any `json:"fields"`
}

// ParseOutput holds deterministic parser output from a bounded non-executing pass.
type ParseOutput struct {
	SchemaVersion string         `json:"schema_version"`
	AnalyzerID    string         `json:"analyzer_id"`
	ToolVersion   string         `json:"tool_version"`
	ConfigDigest  string         `json:"config_digest"`
	BytesRead     int64          `json:"bytes_read"`
	InputSHA256   string         `json:"input_sha256"`
	RecordCount   int            `json:"record_count"`
	Records       []ParsedRecord `json:"records"`
}

// Analyzer defines the fixed contract implemented by shipped non-executing parsers.
type Analyzer interface {
	Descriptor() Descriptor
	Parse(ctx context.Context, r io.Reader, opts ParseOptions) (*ParseOutput, error)
}

// RegistryConfig binds a read-only SealStore prerequisite to the fixed analyzer registry.
type RegistryConfig struct {
	SealStore   *evidence.SealStore
	SealRootDir string
	Provider    string
	Defaults    ParseOptions
}

// RunRequest describes a read-only analysis invocation against sealed evidence.
type RunRequest struct {
	AnalyzerID string       `json:"analyzer_id"`
	CaseID     string       `json:"case_id"`
	EvidenceID string       `json:"evidence_id"`
	Provider   string       `json:"provider,omitempty"`
	Options    ParseOptions `json:"options,omitempty"`
}

// AnalysisResult binds extracted records to sealed input digest, tool version, and config hash.
type AnalysisResult struct {
	SchemaVersion string         `json:"schema_version"`
	CaseID        string         `json:"case_id"`
	EvidenceID    string         `json:"evidence_id"`
	AnalyzerID    string         `json:"analyzer_id"`
	ToolVersion   string         `json:"tool_version"`
	ConfigDigest  string         `json:"config_digest"`
	InputSHA256   string         `json:"input_sha256"`
	BytesRead     int64          `json:"bytes_read"`
	NonExecuting  bool           `json:"non_executing"`
	ReadOnly      bool           `json:"read_only"`
	AnalyzedAt    string         `json:"analyzed_at"`
	RecordCount   int            `json:"record_count"`
	Records       []ParsedRecord `json:"records"`
}

// Registry exposes the compile-time allowlist of shipped non-executing parsers.
type Registry struct {
	mu          sync.RWMutex
	sealStore   *evidence.SealStore
	sealRootDir string
	provider    string
	defaults    ParseOptions
	analyzers   map[string]Analyzer
}

// NewRegistry constructs a fixed MVP registry containing ONLY the shipped non-executing CSV and JSON parsers.
func NewRegistry(cfg RegistryConfig) (*Registry, error) {
	if !allowedProviders[cfg.Provider] {
		return nil, fmt.Errorf("%w: provider %q not supported", ErrUnavailableProvider, cfg.Provider)
	}
	defaults, err := normalizeParseOptions(cfg.Defaults)
	if err != nil {
		return nil, err
	}

	var resolvedRoot string
	if strings.TrimSpace(cfg.SealRootDir) != "" {
		if strings.ContainsRune(cfg.SealRootDir, '\x00') {
			return nil, fmt.Errorf("%w: null byte in seal root dir", ErrPathTraversal)
		}
		for _, seg := range strings.FieldsFunc(cfg.SealRootDir, func(r rune) bool { return r == '/' || r == '\\' }) {
			if seg == ".." {
				return nil, fmt.Errorf("%w: traversal segment in seal root dir", ErrPathTraversal)
			}
		}
		absRoot, err := filepath.Abs(filepath.Clean(cfg.SealRootDir))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPathTraversal, err)
		}
		if err := ensureNoSymlink(absRoot); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		resolvedRoot = absRoot
	}

	reg := &Registry{
		sealStore:   cfg.SealStore,
		sealRootDir: resolvedRoot,
		provider:    cfg.Provider,
		defaults:    defaults,
		analyzers:   make(map[string]Analyzer, 2),
	}

	// Register only the two shipped non-executing parsers.
	_ = reg.registerInternal(&csvAnalyzer{defaults: defaults})
	_ = reg.registerInternal(&jsonAnalyzer{defaults: defaults})
	return reg, nil
}

func (r *Registry) registerInternal(a Analyzer) error {
	if a == nil {
		return fmt.Errorf("%w: nil analyzer", ErrInvalidConfig)
	}
	desc := a.Descriptor()
	if desc.Executing || !desc.NonExecuting {
		return fmt.Errorf("%w: parser %q declares executing behavior", ErrExecutingParserForbidden, desc.ID)
	}
	if !shippedAllowlist[desc.ID] {
		return fmt.Errorf("%w: parser %q", ErrAnalyzerNotAllowlisted, desc.ID)
	}
	r.analyzers[desc.ID] = a
	return nil
}

// Register validates whether an analyzer obeys the MVP non-executing allowlist contract.
// Any executing parser or unallowlisted ID is rejected fail-closed.
func (r *Registry) Register(a Analyzer) error {
	if a == nil {
		return fmt.Errorf("%w: nil analyzer", ErrInvalidConfig)
	}
	desc := a.Descriptor()
	if desc.Executing || !desc.NonExecuting {
		return fmt.Errorf("%w: parser %q cannot execute code or external processes", ErrExecutingParserForbidden, desc.ID)
	}
	if !shippedAllowlist[desc.ID] {
		return fmt.Errorf("%w: %q is not an enabled MVP parser", ErrAnalyzerNotAllowlisted, desc.ID)
	}
	if !desc.ReadOnly {
		return fmt.Errorf("%w: parser %q must operate strictly read-only", ErrInvalidConfig, desc.ID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.analyzers[desc.ID] = a
	return nil
}

// Allowlisted returns deterministic descriptors for all enabled non-executing MVP analyzers.
func (r *Registry) Allowlisted() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.analyzers))
	for id := range r.analyzers {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]Descriptor, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.analyzers[id].Descriptor())
	}
	return out
}

// Resolve returns an allowlisted non-executing analyzer or fails closed on unlisted/executing/unavailable providers.
func (r *Registry) Resolve(analyzerID, provider string) (Analyzer, error) {
	effectiveProvider := provider
	if effectiveProvider == "" {
		effectiveProvider = r.provider
	}
	if !allowedProviders[effectiveProvider] {
		return nil, fmt.Errorf("%w: provider %q is not supported in local-first MVP", ErrUnavailableProvider, effectiveProvider)
	}

	normID := strings.TrimSpace(strings.ToLower(analyzerID))
	if normID == "" || !shippedAllowlist[normID] {
		return nil, fmt.Errorf("%w: %q (allowed: csv, json)", ErrAnalyzerNotAllowlisted, analyzerID)
	}

	r.mu.RLock()
	a, ok := r.analyzers[normID]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q not registered", ErrAnalyzerNotAllowlisted, analyzerID)
	}
	desc := a.Descriptor()
	if desc.Executing || !desc.NonExecuting {
		return nil, fmt.Errorf("%w: %q", ErrExecutingParserForbidden, analyzerID)
	}
	return a, nil
}

// ParseStream executes an allowlisted non-executing parser on a caller-supplied read-only stream.
func (r *Registry) ParseStream(ctx context.Context, analyzerID, provider string, stream io.Reader, opts ParseOptions) (*ParseOutput, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if stream == nil {
		return nil, fmt.Errorf("%w: input stream is required", ErrMissingPrerequisite)
	}
	a, err := r.Resolve(analyzerID, provider)
	if err != nil {
		return nil, err
	}
	normOpts, err := normalizeParseOptions(opts)
	if err != nil {
		return nil, err
	}
	return a.Parse(ctx, stream, normOpts)
}

// RunAnalysis verifies sealed evidence prerequisites on disk, opens the committed blob strictly read-only,
// verifies its SHA-256 digest, and runs the allowlisted non-executing parser without mutating source bytes.
func (r *Registry) RunAnalysis(ctx context.Context, req RunRequest) (*AnalysisResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if r.sealStore == nil || strings.TrimSpace(r.sealRootDir) == "" {
		return nil, fmt.Errorf("%w: sealed evidence store and root directory are required", ErrMissingPrerequisite)
	}
	if !isValidIdentifier(req.CaseID) {
		return nil, fmt.Errorf("%w: invalid case_id %q", ErrPathTraversal, req.CaseID)
	}
	if !isValidIdentifier(req.EvidenceID) {
		return nil, fmt.Errorf("%w: invalid evidence_id %q", ErrPathTraversal, req.EvidenceID)
	}

	a, err := r.Resolve(req.AnalyzerID, req.Provider)
	if err != nil {
		return nil, err
	}
	normOpts, err := normalizeParseOptions(req.Options)
	if err != nil {
		return nil, err
	}

	// Verify sealed evidence exists and passes cryptographic integrity checks read-only.
	verifyRes, verifyErr := evidence.VerifyStoreEvidence(ctx, r.sealStore, req.CaseID, req.EvidenceID, evidence.VerifyOptions{})
	if verifyErr != nil {
		return nil, fmt.Errorf("%w: sealed evidence %s/%s verification failed: %v", ErrMissingPrerequisite, req.CaseID, req.EvidenceID, verifyErr)
	}
	if verifyRes == nil || !verifyRes.Verified {
		return nil, fmt.Errorf("%w: evidence %s/%s is not verified sealed", ErrMissingPrerequisite, req.CaseID, req.EvidenceID)
	}

	manifest, err := r.sealStore.GetSealedManifest(req.CaseID, req.EvidenceID)
	if err != nil || manifest == nil || !manifest.Sealed {
		return nil, fmt.Errorf("%w: sealed manifest for %s/%s unavailable: %v", ErrMissingPrerequisite, req.CaseID, req.EvidenceID, err)
	}

	blobPath := filepath.Join(r.sealRootDir, filepath.FromSlash(manifest.BlobRelPath))
	if err := checkWithinDir(r.sealRootDir, blobPath); err != nil {
		return nil, err
	}
	if err := ensureNoSymlink(blobPath); err != nil {
		return nil, err
	}

	f, err := os.Open(blobPath) // strictly O_RDONLY
	if err != nil {
		return nil, fmt.Errorf("%w: open sealed blob read-only: %v", ErrMissingPrerequisite, err)
	}
	defer f.Close()

	parsed, err := a.Parse(ctx, f, normOpts)
	if err != nil {
		return nil, err
	}
	if parsed.InputSHA256 != manifest.SHA256 {
		return nil, fmt.Errorf("%w: parsed sha256 %s != sealed manifest sha256 %s", ErrInputDigestMismatch, parsed.InputSHA256, manifest.SHA256)
	}

	desc := a.Descriptor()
	return &AnalysisResult{
		SchemaVersion: SchemaVersion,
		CaseID:        req.CaseID,
		EvidenceID:    req.EvidenceID,
		AnalyzerID:    desc.ID,
		ToolVersion:   parsed.ToolVersion,
		ConfigDigest:  parsed.ConfigDigest,
		InputSHA256:   parsed.InputSHA256,
		BytesRead:     parsed.BytesRead,
		NonExecuting:  desc.NonExecuting,
		ReadOnly:      desc.ReadOnly,
		AnalyzedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		RecordCount:   parsed.RecordCount,
		Records:       parsed.Records,
	}, nil
}

func readBoundedStream(ctx context.Context, r io.Reader, maxBytes int64) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	limited := io.LimitReader(r, maxBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, "", fmt.Errorf("read analyzer input: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, "", fmt.Errorf("%w: input exceeds %d bytes", ErrInputTooLarge, maxBytes)
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

func extractTimestampFromFields(fields map[string]any) string {
	for _, key := range []string{"timestamp", "time", "ts", "Timestamp", "Time"} {
		if val, ok := fields[key]; ok {
			if s, isStr := val.(string); isStr {
				trimmed := strings.TrimSpace(s)
				if trimmed != "" {
					return trimmed
				}
			}
		}
	}
	return ""
}

// --- Fixed non-executing CSV parser ---

type csvAnalyzer struct {
	defaults ParseOptions
}

func (c *csvAnalyzer) Descriptor() Descriptor {
	return Descriptor{
		ID:           AnalyzerCSV,
		Version:      ToolVersionCSV,
		Format:       "csv",
		MediaTypes:   []string{"text/csv", "application/csv"},
		NonExecuting: true,
		Executing:    false,
		ReadOnly:     true,
		Capabilities: []string{"header-validated-rows", "timestamp-extraction", "bounded-stream"},
		ConfigDigest: ConfigDigest(AnalyzerCSV, ToolVersionCSV, c.defaults),
	}
}

func (c *csvAnalyzer) Parse(ctx context.Context, r io.Reader, opts ParseOptions) (*ParseOutput, error) {
	normOpts, err := normalizeParseOptions(opts)
	if err != nil {
		return nil, err
	}
	raw, inputSHA, err := readBoundedStream(ctx, r, normOpts.MaxInputBytes)
	if err != nil {
		return nil, err
	}

	// Strip optional UTF-8 BOM.
	trimmed := bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	if len(bytes.TrimSpace(trimmed)) == 0 {
		return nil, fmt.Errorf("%w: empty csv input", ErrMalformedInput)
	}

	reader := csv.NewReader(bytes.NewReader(trimmed))
	reader.FieldsPerRecord = 0
	reader.ReuseRecord = false

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("%w: read csv header: %v", ErrMalformedInput, err)
	}
	if len(header) == 0 {
		return nil, fmt.Errorf("%w: empty csv header", ErrMalformedInput)
	}
	if len(header) > normOpts.MaxFieldsPerRow {
		return nil, fmt.Errorf("%w: csv column count %d exceeds limit %d", ErrInputTooLarge, len(header), normOpts.MaxFieldsPerRow)
	}

	seenCols := make(map[string]bool, len(header))
	cleanHeaders := make([]string, len(header))
	for i, col := range header {
		name := strings.TrimSpace(col)
		if name == "" {
			return nil, fmt.Errorf("%w: empty csv header column at index %d", ErrMalformedInput, i)
		}
		if seenCols[name] {
			return nil, fmt.Errorf("%w: duplicate csv header column %q", ErrMalformedInput, name)
		}
		seenCols[name] = true
		cleanHeaders[i] = name
	}

	var records []ParsedRecord
	rowNum := 1
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: csv row %d: %v", ErrMalformedInput, rowNum+1, err)
		}
		rowNum++
		if len(records) >= normOpts.MaxRecords {
			return nil, fmt.Errorf("%w: csv record count exceeds limit %d", ErrInputTooLarge, normOpts.MaxRecords)
		}

		fields := make(map[string]any, len(cleanHeaders))
		for i, col := range cleanHeaders {
			fields[col] = row[i]
		}
		records = append(records, ParsedRecord{
			Index:     len(records) + 1,
			RowNumber: rowNum,
			Timestamp: extractTimestampFromFields(fields),
			Fields:    fields,
		})
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("%w: csv contains header without data rows", ErrMalformedInput)
	}

	return &ParseOutput{
		SchemaVersion: SchemaVersion,
		AnalyzerID:    AnalyzerCSV,
		ToolVersion:   ToolVersionCSV,
		ConfigDigest:  ConfigDigest(AnalyzerCSV, ToolVersionCSV, normOpts),
		BytesRead:     int64(len(raw)),
		InputSHA256:   inputSHA,
		RecordCount:   len(records),
		Records:       records,
	}, nil
}

// --- Fixed non-executing JSON/JSONL parser ---

type jsonAnalyzer struct {
	defaults ParseOptions
}

func (j *jsonAnalyzer) Descriptor() Descriptor {
	return Descriptor{
		ID:           AnalyzerJSON,
		Version:      ToolVersionJSON,
		Format:       "json",
		MediaTypes:   []string{"application/json", "application/x-ndjson"},
		NonExecuting: true,
		Executing:    false,
		ReadOnly:     true,
		Capabilities: []string{"json-object", "json-array", "ndjson-stream", "depth-bounded"},
		ConfigDigest: ConfigDigest(AnalyzerJSON, ToolVersionJSON, j.defaults),
	}
}

func checkJSONMaxDepth(data []byte, maxDepth int) error {
	depth := 0
	inString := false
	escaped := false

	for _, b := range data {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				return fmt.Errorf("%w: json nesting depth %d exceeds max %d", ErrMalformedInput, depth, maxDepth)
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return fmt.Errorf("%w: unbalanced json closing token", ErrMalformedInput)
			}
		}
	}
	if inString || depth != 0 {
		return fmt.Errorf("%w: unterminated json structure", ErrMalformedInput)
	}
	return nil
}

func (j *jsonAnalyzer) Parse(ctx context.Context, r io.Reader, opts ParseOptions) (*ParseOutput, error) {
	normOpts, err := normalizeParseOptions(opts)
	if err != nil {
		return nil, err
	}
	raw, inputSHA, err := readBoundedStream(ctx, r, normOpts.MaxInputBytes)
	if err != nil {
		return nil, err
	}

	trimmed := bytes.TrimSpace(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF}))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: empty json input", ErrMalformedInput)
	}
	if err := checkJSONMaxDepth(trimmed, normOpts.MaxJSONDepth); err != nil {
		return nil, err
	}

	var records []ParsedRecord
	first := trimmed[0]

	switch first {
	case '[':
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		var items []map[string]any
		if err := dec.Decode(&items); err != nil {
			return nil, fmt.Errorf("%w: invalid json object array: %v", ErrMalformedInput, err)
		}
		var trailing any
		if err := dec.Decode(&trailing); err != io.EOF {
			return nil, fmt.Errorf("%w: unexpected trailing json tokens", ErrMalformedInput)
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("%w: json array contains no records", ErrMalformedInput)
		}
		if len(items) > normOpts.MaxRecords {
			return nil, fmt.Errorf("%w: json record count %d exceeds limit %d", ErrInputTooLarge, len(items), normOpts.MaxRecords)
		}
		for i, item := range items {
			if item == nil {
				return nil, fmt.Errorf("%w: json record %d is null", ErrMalformedInput, i+1)
			}
			if len(item) > normOpts.MaxFieldsPerRow {
				return nil, fmt.Errorf("%w: json record %d exceeds field limit %d", ErrInputTooLarge, i+1, normOpts.MaxFieldsPerRow)
			}
			records = append(records, ParsedRecord{
				Index:     i + 1,
				RowNumber: i + 1,
				Timestamp: extractTimestampFromFields(item),
				Fields:    item,
			})
		}

	case '{':
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		row := 0
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			var item map[string]any
			err := dec.Decode(&item)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("%w: invalid json object at record %d: %v", ErrMalformedInput, row+1, err)
			}
			if item == nil {
				return nil, fmt.Errorf("%w: json record %d is null", ErrMalformedInput, row+1)
			}
			row++
			if row > normOpts.MaxRecords {
				return nil, fmt.Errorf("%w: json record count exceeds limit %d", ErrInputTooLarge, normOpts.MaxRecords)
			}
			if len(item) > normOpts.MaxFieldsPerRow {
				return nil, fmt.Errorf("%w: json record %d exceeds field limit %d", ErrInputTooLarge, row, normOpts.MaxFieldsPerRow)
			}
			records = append(records, ParsedRecord{
				Index:     row,
				RowNumber: row,
				Timestamp: extractTimestampFromFields(item),
				Fields:    item,
			})
		}
		if len(records) == 0 {
			return nil, fmt.Errorf("%w: no json object records parsed", ErrMalformedInput)
		}

	default:
		return nil, fmt.Errorf("%w: json input must be a JSON object, array of objects, or JSONL stream", ErrMalformedInput)
	}

	return &ParseOutput{
		SchemaVersion: SchemaVersion,
		AnalyzerID:    AnalyzerJSON,
		ToolVersion:   ToolVersionJSON,
		ConfigDigest:  ConfigDigest(AnalyzerJSON, ToolVersionJSON, normOpts),
		BytesRead:     int64(len(raw)),
		InputSHA256:   inputSHA,
		RecordCount:   len(records),
		Records:       records,
	}, nil
}

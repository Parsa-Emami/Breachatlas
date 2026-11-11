package analyzers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrNetworkForbidden       = errors.New("analyzer network access is forbidden by sandbox isolation policy")
	ErrDeadlineExceeded       = errors.New("analyzer execution exceeded configured deadline")
	ErrScratchLimitExceeded   = errors.New("analyzer scratch disk usage exceeded configured quota")
	ErrEvidenceModified       = errors.New("sealed evidence source bytes modified; isolation breach detected")
	ErrEvidenceWriteForbidden = errors.New("sealed evidence cannot be opened with write permissions")
	ErrSandboxEscaped         = errors.New("analyzer scratch path escapes private sandbox directory")
)

const (
	DefaultMaxScratchBytes int64         = 32 * 1024 * 1024 // 32 MiB bounded private scratch quota
	DefaultTimeoutDuration time.Duration = 5 * time.Second
	MaxTimeoutDuration     time.Duration = 60 * time.Second
)

// SandboxConfig defines resource bounds, timeout policy, and filesystem isolation constraints.
type SandboxConfig struct {
	ScratchBaseDir          string        `json:"scratch_base_dir"`
	MaxScratchBytes         int64         `json:"max_scratch_bytes"`
	DefaultTimeout          time.Duration `json:"default_timeout"`
	MaxTimeout              time.Duration `json:"max_timeout"`
	BlockNetwork            bool          `json:"block_network"`
	EnforceReadOnlyEvidence bool          `json:"enforce_read_only_evidence"`
	CleanScratchOnExit      bool          `json:"clean_scratch_on_exit"`
}

// DefaultSandboxConfig returns secure bounded sandbox defaults for local execution.
func DefaultSandboxConfig(scratchBaseDir string) SandboxConfig {
	return SandboxConfig{
		ScratchBaseDir:          scratchBaseDir,
		MaxScratchBytes:         DefaultMaxScratchBytes,
		DefaultTimeout:          DefaultTimeoutDuration,
		MaxTimeout:              MaxTimeoutDuration,
		BlockNetwork:            true,
		EnforceReadOnlyEvidence: true,
		CleanScratchOnExit:      true,
	}
}

// IsolatedRunRequest configures an isolated analyzer run against sealed evidence.
type IsolatedRunRequest struct {
	RunID       string        `json:"run_id"`
	CaseID      string        `json:"case_id"`
	EvidenceID  string        `json:"evidence_id"`
	AnalyzerID  string        `json:"analyzer_id"`
	Provider    string        `json:"provider,omitempty"`
	Options     ParseOptions  `json:"options,omitempty"`
	Timeout     time.Duration `json:"timeout,omitempty"`
	KeepScratch bool          `json:"keep_scratch,omitempty"`
}

// IsolatedRunResult certifies isolated analysis outcome and verified resource invariants.
type IsolatedRunResult struct {
	SchemaVersion     string          `json:"schema_version"`
	RunID             string          `json:"run_id"`
	ScratchDir        string          `json:"scratch_dir"`
	ScratchBytesUsed  int64           `json:"scratch_bytes_used"`
	Analysis          *AnalysisResult `json:"analysis,omitempty"`
	ExecutionDuration time.Duration   `json:"execution_duration_ns"`
	NetworkBlocked    bool            `json:"network_blocked"`
	ReadOnlyVerified  bool            `json:"read_only_verified"`
	CompletedAt       string          `json:"completed_at"`
}

// NetworkGuard blocks all outbound network dialing fail-closed when network isolation is active.
type NetworkGuard struct {
	blocked bool
}

// NewNetworkGuard returns a network guard with the requested blocking state.
func NewNetworkGuard(blocked bool) *NetworkGuard {
	return &NetworkGuard{blocked: blocked}
}

// DialContext intercepts network dialing and returns ErrNetworkForbidden if blocked.
func (g *NetworkGuard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if g.blocked {
		return nil, ErrNetworkForbidden
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// Dial intercepts network dialing without context and returns ErrNetworkForbidden if blocked.
func (g *NetworkGuard) Dial(network, address string) (net.Conn, error) {
	return g.DialContext(context.Background(), network, address)
}

// CheckBlocked returns ErrNetworkForbidden if network access is blocked.
func (g *NetworkGuard) CheckBlocked() error {
	if g.blocked {
		return ErrNetworkForbidden
	}
	return nil
}

// NewHTTPClient returns an http.Client whose Transport routes through DialContext.
func (g *NetworkGuard) NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: g.DialContext,
		},
	}
}

// ScratchController manages a dedicated private scratch directory under strict bounds.
type ScratchController struct {
	mu        sync.Mutex
	dir       string
	maxBytes  int64
	bytesUsed int64
	cleaned   bool
}

// Dir returns the private scratch directory path.
func (sc *ScratchController) Dir() string {
	return sc.dir
}

// BytesUsed returns the total bytes written to the private scratch directory.
func (sc *ScratchController) BytesUsed() int64 {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.bytesUsed
}

// MaxBytes returns the maximum scratch bytes quota.
func (sc *ScratchController) MaxBytes() int64 {
	return sc.maxBytes
}

// ResolvePath checks that a relative path stays strictly within the scratch directory.
func (sc *ScratchController) ResolvePath(relPath string) (string, error) {
	sc.mu.Lock()
	if sc.cleaned {
		sc.mu.Unlock()
		return "", fmt.Errorf("%w: scratch controller already cleaned", ErrSandboxEscaped)
	}
	sc.mu.Unlock()

	if strings.ContainsRune(relPath, '\x00') {
		return "", fmt.Errorf("%w: null byte in scratch path", ErrSandboxEscaped)
	}
	clean := filepath.Clean(relPath)
	if clean == "." || clean == "" {
		return "", fmt.Errorf("%w: path refers to scratch root directory", ErrSandboxEscaped)
	}
	if filepath.IsAbs(clean) {
		rel, err := filepath.Rel(sc.dir, clean)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == "." {
			return "", fmt.Errorf("%w: absolute path %s escapes scratch directory", ErrSandboxEscaped, relPath)
		}
		clean = rel
	}
	for _, seg := range strings.FieldsFunc(clean, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return "", fmt.Errorf("%w: path traversal segment %q escapes scratch directory", ErrSandboxEscaped, seg)
		}
	}
	target := filepath.Join(sc.dir, clean)
	if target == sc.dir {
		return "", fmt.Errorf("%w: path refers to scratch root directory", ErrSandboxEscaped)
	}
	if err := checkWithinDir(sc.dir, target); err != nil {
		return "", fmt.Errorf("%w: %v", ErrSandboxEscaped, err)
	}

	curr := target
	for {
		fi, err := os.Lstat(curr)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				eval, err := filepath.EvalSymlinks(curr)
				if err != nil {
					return "", fmt.Errorf("%w: invalid symlink: %v", ErrSandboxEscaped, err)
				}
				if err := checkWithinDir(sc.dir, eval); err != nil {
					return "", fmt.Errorf("%w: symlink target %s escapes scratch directory", ErrSandboxEscaped, eval)
				}
			}
		}
		if curr == sc.dir || curr == "/" || curr == "." {
			break
		}
		curr = filepath.Dir(curr)
	}
	return target, nil
}

// WriteFile writes data to a path inside private scratch, enforcing quota and traversal bounds.
func (sc *ScratchController) WriteFile(relPath string, data []byte, perm os.FileMode) error {
	target, err := sc.ResolvePath(relPath)
	if err != nil {
		return err
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.cleaned {
		return fmt.Errorf("%w: scratch controller already cleaned", ErrSandboxEscaped)
	}

	var existingSize int64
	if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
		existingSize = fi.Size()
	}
	newTotal := sc.bytesUsed - existingSize + int64(len(data))
	if newTotal > sc.maxBytes {
		return fmt.Errorf("%w: write %d bytes (total %d) exceeds quota %d", ErrScratchLimitExceeded, len(data), newTotal, sc.maxBytes)
	}

	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("create scratch parent dir: %w", err)
	}
	effectivePerm := perm & 0700
	if effectivePerm == 0 {
		effectivePerm = 0600
	}
	if err := os.WriteFile(target, data, effectivePerm); err != nil {
		return fmt.Errorf("write scratch file: %w", err)
	}
	sc.bytesUsed = newTotal
	return nil
}

type scratchFileWriter struct {
	file *os.File
	sc   *ScratchController
}

func (w *scratchFileWriter) Write(p []byte) (int, error) {
	w.sc.mu.Lock()
	defer w.sc.mu.Unlock()
	if w.sc.cleaned {
		return 0, fmt.Errorf("%w: scratch controller already cleaned", ErrSandboxEscaped)
	}

	writeLen := int64(len(p))
	if w.sc.bytesUsed+writeLen > w.sc.maxBytes {
		return 0, fmt.Errorf("%w: write exceeds scratch quota %d", ErrScratchLimitExceeded, w.sc.maxBytes)
	}
	n, err := w.file.Write(p)
	w.sc.bytesUsed += int64(n)
	return n, err
}

func (w *scratchFileWriter) Close() error {
	return w.file.Close()
}

// CreateFile opens a bounded writer in private scratch that enforces quota limits as bytes are streamed.
// If the target file already exists, it is truncated and previous byte usage is reclaimed.
func (sc *ScratchController) CreateFile(relPath string) (io.WriteCloser, error) {
	target, err := sc.ResolvePath(relPath)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, fmt.Errorf("create scratch parent dir: %w", err)
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.cleaned {
		return nil, fmt.Errorf("%w: scratch controller already cleaned", ErrSandboxEscaped)
	}

	var existingSize int64
	if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
		existingSize = fi.Size()
	}

	f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open scratch file for write: %w", err)
	}

	sc.bytesUsed -= existingSize
	if sc.bytesUsed < 0 {
		sc.bytesUsed = 0
	}
	return &scratchFileWriter{file: f, sc: sc}, nil
}

// OpenFile opens a file inside private scratch strictly read-only, guarding against path escapes.
// Direct writes via OpenFile are forbidden because raw *os.File writes bypass quota enforcement.
func (sc *ScratchController) OpenFile(relPath string, flag int, perm os.FileMode) (*os.File, error) {
	if flag != os.O_RDONLY && flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0 {
		return nil, fmt.Errorf("%w: OpenFile only supports O_RDONLY; use CreateFile or WriteFile to enforce quota", ErrInvalidConfig)
	}
	target, err := sc.ResolvePath(relPath)
	if err != nil {
		return nil, err
	}
	sc.mu.Lock()
	if sc.cleaned {
		sc.mu.Unlock()
		return nil, fmt.Errorf("%w: scratch controller already cleaned", ErrSandboxEscaped)
	}
	sc.mu.Unlock()
	return os.OpenFile(target, flag, perm)
}

// ReadFile reads the full contents of a file inside private scratch.
func (sc *ScratchController) ReadFile(relPath string) ([]byte, error) {
	target, err := sc.ResolvePath(relPath)
	if err != nil {
		return nil, err
	}
	sc.mu.Lock()
	if sc.cleaned {
		sc.mu.Unlock()
		return nil, fmt.Errorf("%w: scratch controller already cleaned", ErrSandboxEscaped)
	}
	sc.mu.Unlock()
	return os.ReadFile(target)
}

// RemoveFile removes a file within private scratch and reclaims its quota.
func (sc *ScratchController) RemoveFile(relPath string) error {
	target, err := sc.ResolvePath(relPath)
	if err != nil {
		return err
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.cleaned {
		return fmt.Errorf("%w: scratch controller already cleaned", ErrSandboxEscaped)
	}

	fi, err := os.Stat(target)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("%w: cannot remove directory with RemoveFile", ErrInvalidConfig)
	}
	size := fi.Size()
	if err := os.Remove(target); err != nil {
		return err
	}
	sc.bytesUsed -= size
	if sc.bytesUsed < 0 {
		sc.bytesUsed = 0
	}
	return nil
}

// Cleanup safely removes the private scratch directory and marks the controller closed.
func (sc *ScratchController) Cleanup() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.cleaned = true
	if sc.dir != "" {
		return os.RemoveAll(sc.dir)
	}
	return nil
}

// Sandbox manages isolated analyzer execution, network blocking, and scratch lifecycle.
type Sandbox struct {
	mu           sync.RWMutex
	registry     *Registry
	cfg          SandboxConfig
	networkGuard *NetworkGuard
	activeRuns   map[string]*ScratchController
}

// NewSandbox constructs an isolated execution manager binding the analyzer registry to sandbox policy.
func NewSandbox(registry *Registry, cfg SandboxConfig) (*Sandbox, error) {
	if registry == nil {
		return nil, fmt.Errorf("%w: registry is required for sandbox initialization", ErrMissingPrerequisite)
	}
	if strings.TrimSpace(cfg.ScratchBaseDir) == "" {
		return nil, fmt.Errorf("%w: scratch_base_dir is required", ErrInvalidConfig)
	}
	if strings.ContainsRune(cfg.ScratchBaseDir, '\x00') {
		return nil, fmt.Errorf("%w: null byte in scratch base dir", ErrPathTraversal)
	}
	for _, seg := range strings.FieldsFunc(cfg.ScratchBaseDir, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return nil, fmt.Errorf("%w: traversal segment in scratch base dir", ErrPathTraversal)
		}
	}
	absBase, err := filepath.Abs(filepath.Clean(cfg.ScratchBaseDir))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if err := os.MkdirAll(absBase, 0700); err != nil {
		return nil, fmt.Errorf("create scratch base directory: %w", err)
	}
	_ = os.Chmod(absBase, 0700)
	if err := ensureNoSymlink(absBase); err != nil {
		return nil, err
	}

	if cfg.MaxScratchBytes <= 0 {
		cfg.MaxScratchBytes = DefaultMaxScratchBytes
	}
	if cfg.DefaultTimeout <= 0 {
		cfg.DefaultTimeout = DefaultTimeoutDuration
	}
	if cfg.MaxTimeout <= 0 {
		cfg.MaxTimeout = MaxTimeoutDuration
	}
	if cfg.DefaultTimeout > cfg.MaxTimeout {
		return nil, fmt.Errorf("%w: default timeout exceeds max timeout", ErrInvalidConfig)
	}
	cfg.ScratchBaseDir = absBase

	return &Sandbox{
		registry:     registry,
		cfg:          cfg,
		networkGuard: NewNetworkGuard(cfg.BlockNetwork),
		activeRuns:   make(map[string]*ScratchController),
	}, nil
}

// Config returns the immutable configured sandbox settings.
func (s *Sandbox) Config() SandboxConfig {
	return s.cfg
}

// Registry returns the bound analyzer registry.
func (s *Sandbox) Registry() *Registry {
	return s.registry
}

// NetworkGuard returns the bound network dial guard.
func (s *Sandbox) NetworkGuard() *NetworkGuard {
	return s.networkGuard
}

// DialContext delegates to the network guard to verify outbound dial policy.
func (s *Sandbox) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return s.networkGuard.DialContext(ctx, network, address)
}

// NewBlockedHTTPClient returns an http.Client backed by the sandbox's network guard.
func (s *Sandbox) NewBlockedHTTPClient() *http.Client {
	return s.networkGuard.NewHTTPClient()
}

// OpenEvidence opens sealed evidence strictly in read-only mode (O_RDONLY).
// Any flag requesting write access or non-read-only behavior fails closed with ErrEvidenceWriteForbidden.
func (s *Sandbox) OpenEvidence(caseID, evidenceID string, flag int) (*os.File, error) {
	if flag != os.O_RDONLY {
		return nil, ErrEvidenceWriteForbidden
	}
	if s.registry == nil || s.registry.sealStore == nil || strings.TrimSpace(s.registry.sealRootDir) == "" {
		return nil, fmt.Errorf("%w: registry and seal store required", ErrMissingPrerequisite)
	}
	if !isValidIdentifier(caseID) {
		return nil, fmt.Errorf("%w: invalid case_id %q", ErrPathTraversal, caseID)
	}
	if !isValidIdentifier(evidenceID) {
		return nil, fmt.Errorf("%w: invalid evidence_id %q", ErrPathTraversal, evidenceID)
	}

	manifest, err := s.registry.sealStore.GetSealedManifest(caseID, evidenceID)
	if err != nil || manifest == nil || !manifest.Sealed {
		return nil, fmt.Errorf("%w: sealed manifest for %s/%s unavailable", ErrMissingPrerequisite, caseID, evidenceID)
	}

	blobPath := filepath.Join(s.registry.sealRootDir, filepath.FromSlash(manifest.BlobRelPath))
	if err := checkWithinDir(s.registry.sealRootDir, blobPath); err != nil {
		return nil, err
	}
	if err := ensureNoSymlink(blobPath); err != nil {
		return nil, err
	}

	return os.OpenFile(blobPath, os.O_RDONLY, 0)
}

// AllocateScratch allocates an isolated private scratch directory with 0700 permissions.
func (s *Sandbox) AllocateScratch(runID string) (*ScratchController, error) {
	if runID == "" {
		runID = fmt.Sprintf("run-%d", time.Now().UnixNano())
	} else if !isValidIdentifier(runID) {
		return nil, fmt.Errorf("%w: invalid run_id %q", ErrPathTraversal, runID)
	}
	scratchDirName := "run-" + runID
	scratchDir := filepath.Join(s.cfg.ScratchBaseDir, scratchDirName)
	if err := checkWithinDir(s.cfg.ScratchBaseDir, scratchDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(scratchDir, 0700); err != nil {
		return nil, fmt.Errorf("create private scratch directory: %w", err)
	}
	_ = os.Chmod(scratchDir, 0700)
	sc := &ScratchController{
		dir:      scratchDir,
		maxBytes: s.cfg.MaxScratchBytes,
	}
	s.mu.Lock()
	s.activeRuns[runID] = sc
	s.mu.Unlock()
	return sc, nil
}

// ReleaseScratch unregisters and removes an allocated scratch directory.
func (s *Sandbox) ReleaseScratch(runID string) error {
	s.mu.Lock()
	sc, ok := s.activeRuns[runID]
	delete(s.activeRuns, runID)
	s.mu.Unlock()
	if ok && sc != nil {
		return sc.Cleanup()
	}
	return nil
}

// CleanOrphans safely purges abandoned or interrupted scratch directories without affecting active executions.
func (s *Sandbox) CleanOrphans(ctx context.Context, maxAge time.Duration) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if maxAge < 0 {
		return 0, fmt.Errorf("%w: maxAge cannot be negative", ErrInvalidConfig)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	active := make(map[string]bool, len(s.activeRuns))
	for id := range s.activeRuns {
		active["run-"+id] = true
	}
	scratchBase := s.cfg.ScratchBaseDir

	entries, err := os.ReadDir(scratchBase)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read scratch base dir: %w", err)
	}

	now := time.Now()
	cleaned := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return cleaned, err
		}
		name := entry.Name()
		if !entry.IsDir() {
			continue
		}
		if !strings.HasPrefix(name, "run-") {
			continue
		}
		if active[name] {
			continue
		}
		fullPath := filepath.Join(scratchBase, name)
		if err := checkWithinDir(scratchBase, fullPath); err != nil {
			continue
		}
		fi, err := entry.Info()
		if err != nil {
			continue
		}
		if maxAge > 0 && now.Sub(fi.ModTime()) < maxAge {
			continue
		}
		if err := os.RemoveAll(fullPath); err == nil {
			cleaned++
		}
	}
	return cleaned, nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// RunIsolatedFunc executes analysis or an isolated worker function under the full sandbox boundary.
func (s *Sandbox) RunIsolatedFunc(
	ctx context.Context,
	req IsolatedRunRequest,
	fn func(ctx context.Context, sc *ScratchController, netGuard *NetworkGuard) error,
) (*IsolatedRunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.registry == nil {
		return nil, fmt.Errorf("%w: registry is nil", ErrMissingPrerequisite)
	}

	if req.RunID == "" {
		req.RunID = fmt.Sprintf("run-%d", time.Now().UnixNano())
	} else if !isValidIdentifier(req.RunID) {
		return nil, fmt.Errorf("%w: invalid run_id %q", ErrPathTraversal, req.RunID)
	}

	if req.Timeout < 0 {
		return nil, fmt.Errorf("%w: negative timeout %v not allowed", ErrInvalidConfig, req.Timeout)
	}
	timeout := req.Timeout
	if timeout == 0 {
		timeout = s.cfg.DefaultTimeout
	}
	if timeout > s.cfg.MaxTimeout {
		return nil, fmt.Errorf("%w: timeout %v exceeds maximum %v", ErrInvalidConfig, timeout, s.cfg.MaxTimeout)
	}

	// When fn == nil, this is a real analyzer execution: prerequisites are mandatory before allocating scratch.
	if fn == nil {
		if strings.TrimSpace(req.CaseID) == "" || strings.TrimSpace(req.EvidenceID) == "" {
			return nil, fmt.Errorf("%w: case_id and evidence_id are required for analyzer execution", ErrMissingPrerequisite)
		}
		if _, err := s.registry.Resolve(req.AnalyzerID, req.Provider); err != nil {
			return nil, err
		}
	}

	var blobPath string
	var preHash string
	var preSize int64

	// If case_id and evidence_id are provided, verify sealed evidence integrity before run.
	if strings.TrimSpace(req.CaseID) != "" || strings.TrimSpace(req.EvidenceID) != "" {
		if !isValidIdentifier(req.CaseID) {
			return nil, fmt.Errorf("%w: invalid case_id %q", ErrPathTraversal, req.CaseID)
		}
		if !isValidIdentifier(req.EvidenceID) {
			return nil, fmt.Errorf("%w: invalid evidence_id %q", ErrPathTraversal, req.EvidenceID)
		}
		if s.registry.sealStore == nil || strings.TrimSpace(s.registry.sealRootDir) == "" {
			return nil, fmt.Errorf("%w: sealed evidence store and root directory required", ErrMissingPrerequisite)
		}

		manifest, err := s.registry.sealStore.GetSealedManifest(req.CaseID, req.EvidenceID)
		if err != nil || manifest == nil || !manifest.Sealed {
			return nil, fmt.Errorf("%w: sealed manifest for %s/%s unavailable: %v", ErrMissingPrerequisite, req.CaseID, req.EvidenceID, err)
		}

		blobPath = filepath.Join(s.registry.sealRootDir, filepath.FromSlash(manifest.BlobRelPath))
		if err := checkWithinDir(s.registry.sealRootDir, blobPath); err != nil {
			return nil, err
		}
		if err := ensureNoSymlink(blobPath); err != nil {
			return nil, err
		}

		h, sz, err := hashFile(blobPath)
		if err != nil {
			return nil, fmt.Errorf("read sealed blob: %w", err)
		}
		if h != manifest.SHA256 || sz != manifest.SizeBytes {
			return nil, fmt.Errorf("%w: sealed digest/size mismatch before analysis", ErrInputDigestMismatch)
		}
		preHash = h
		preSize = sz
	}

	// Allocate dedicated private scratch directory.
	scratchDirName := "run-" + req.RunID
	scratchDir := filepath.Join(s.cfg.ScratchBaseDir, scratchDirName)
	if err := checkWithinDir(s.cfg.ScratchBaseDir, scratchDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(scratchDir, 0700); err != nil {
		return nil, fmt.Errorf("create private scratch directory: %w", err)
	}
	_ = os.Chmod(scratchDir, 0700)

	sc := &ScratchController{
		dir:      scratchDir,
		maxBytes: s.cfg.MaxScratchBytes,
	}

	s.mu.Lock()
	s.activeRuns[req.RunID] = sc
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.activeRuns, req.RunID)
		s.mu.Unlock()

		if s.cfg.CleanScratchOnExit && !req.KeepScratch {
			_ = sc.Cleanup()
		}
	}()

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type execOutcome struct {
		analysis *AnalysisResult
		err      error
	}

	ch := make(chan execOutcome, 1)
	start := time.Now()

	go func() {
		if fn != nil {
			err := fn(execCtx, sc, s.networkGuard)
			ch <- execOutcome{analysis: nil, err: err}
			return
		}

		res, err := s.registry.RunAnalysis(execCtx, RunRequest{
			AnalyzerID: req.AnalyzerID,
			CaseID:     req.CaseID,
			EvidenceID: req.EvidenceID,
			Provider:   req.Provider,
			Options:    req.Options,
		})
		ch <- execOutcome{analysis: res, err: err}
	}()

	var runErr error
	var outcome execOutcome
	select {
	case <-execCtx.Done():
		if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			runErr = ErrDeadlineExceeded
		} else {
			runErr = execCtx.Err()
		}
	case outcome = <-ch:
		if outcome.err != nil {
			if errors.Is(outcome.err, context.DeadlineExceeded) || errors.Is(execCtx.Err(), context.DeadlineExceeded) {
				runErr = ErrDeadlineExceeded
			} else {
				runErr = outcome.err
			}
		}
	}
	duration := time.Since(start)

	// Post-execution evidence byte verification MUST ALWAYS run unconditionally if evidence was bound.
	// If the evidence was modified, ErrEvidenceModified takes precedence over any execution error.
	if blobPath != "" {
		postHash, postSize, err := hashFile(blobPath)
		if err != nil {
			return nil, fmt.Errorf("%w: post-analysis evidence verification failed: %v", ErrEvidenceModified, err)
		}
		if postHash != preHash || postSize != preSize {
			return nil, ErrEvidenceModified
		}
	}

	if runErr != nil {
		return nil, runErr
	}

	return &IsolatedRunResult{
		SchemaVersion:     SchemaVersion,
		RunID:             req.RunID,
		ScratchDir:        scratchDir,
		ScratchBytesUsed:  sc.BytesUsed(),
		Analysis:          outcome.analysis,
		ExecutionDuration: duration,
		NetworkBlocked:    s.cfg.BlockNetwork,
		ReadOnlyVerified:  blobPath != "",
		CompletedAt:       time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

// RunIsolated executes an allowlisted non-executing parser within the bounded isolation sandbox.
func (s *Sandbox) RunIsolated(ctx context.Context, req IsolatedRunRequest) (*IsolatedRunResult, error) {
	return s.RunIsolatedFunc(ctx, req, nil)
}

package custody

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	SchemaVersion     = "1"
	GenesisPrevHash   = "0000000000000000000000000000000000000000000000000000000000000000"
	DefaultLedgerDir  = "custody"
	MaxEventBytes     = 64 * 1024 // 64 KiB
)

var (
	ErrMissingActor        = errors.New("actor is required for custody event")
	ErrMissingReason       = errors.New("reason is required for custody transfer/action")
	ErrMissingTimestamp    = errors.New("timestamp is required for custody event")
	ErrInvalidTimestamp    = errors.New("invalid custody event timestamp")
	ErrInvalidEvent        = errors.New("invalid custody event fields")
	ErrChainCorrupted      = errors.New("custody event chain integrity corrupted")
	ErrSequenceMismatch    = errors.New("custody sequence must be strictly monotonic")
	ErrHashMismatch        = errors.New("custody event hash mismatch")
	ErrUnavailableProvider = errors.New("unavailable identity provider")
	ErrStoreClosed         = errors.New("custody ledger store closed")
	ErrImmutableHistory    = errors.New("custody event history is immutable and append-only")
	ErrEventNotFound       = errors.New("custody event not found")
	ErrStoreDirRequired    = errors.New("custody ledger root directory is required")
	ErrPathTraversal       = errors.New("path traversal or invalid path component rejected")
	ErrSymlinkRejected     = errors.New("symlink rejected in custody ledger path")
)

var (
	identifierRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	digestRegex     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	timestampRegex  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$`)
	allowedProviders = map[string]bool{
		"":            true,
		"local":       true,
		"breachatlas": true,
	}
)

func isValidIdentifier(s string) bool {
	return identifierRegex.MatchString(s) && !strings.Contains(s, "..") && !strings.ContainsAny(s, "/\\")
}

func ensureNoSymlink(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return true, fmt.Errorf("%w: %s", ErrSymlinkRejected, path)
	}
	return false, nil
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

// CustodyEvent represents a single immutable, attributable event in an evidence custody chain.
type CustodyEvent struct {
	SchemaVersion string `json:"schema_version"`
	EventID       string `json:"event_id"`
	CaseID        string `json:"case_id"`
	EvidenceID    string `json:"evidence_id"`
	Sequence      uint64 `json:"sequence"`
	EventType     string `json:"event_type"`
	Actor         string `json:"actor"`
	Timestamp     string `json:"timestamp"`
	Reason        string `json:"reason"`
	FromCustodian string `json:"from_custodian,omitempty"`
	ToCustodian   string `json:"to_custodian,omitempty"`
	PrevHash      string `json:"prev_hash"`
	EventDigest   string `json:"event_digest"`
	CustodyRoot   string `json:"custody_root"`
	Provider      string `json:"provider,omitempty"`
	PublicKey     string `json:"public_key,omitempty"`
	Signature     string `json:"signature,omitempty"`
}

// CanonicalEventBytes produces deterministic bytes representing the custody event.
func CanonicalEventBytes(e CustodyEvent) []byte {
	return []byte(fmt.Sprintf(
		"breachatlas:custody:v1:%s:%s:%s:%d:%s:%s:%s:%s:%s:%s:%s",
		e.SchemaVersion,
		e.CaseID,
		e.EvidenceID,
		e.Sequence,
		e.EventType,
		e.Actor,
		e.Timestamp,
		e.Reason,
		e.FromCustodian,
		e.ToCustodian,
		e.PrevHash,
	))
}

// ComputeEventDigest calculates the hex SHA-256 digest of the canonical event bytes.
func ComputeEventDigest(e CustodyEvent) string {
	h := sha256.Sum256(CanonicalEventBytes(e))
	return hex.EncodeToString(h[:])
}

// ComputeCustodyRoot calculates the updated chain root from previous root and current event digest.
func ComputeCustodyRoot(prevRoot, eventDigest string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", prevRoot, eventDigest)))
	return hex.EncodeToString(h[:])
}

// AppendEventRequest contains parameters for recording a new custody event.
type AppendEventRequest struct {
	EventID       string             `json:"event_id"`
	CaseID        string             `json:"case_id"`
	EvidenceID    string             `json:"evidence_id"`
	EventType     string             `json:"event_type"`
	Actor         string             `json:"actor"`
	Timestamp     string             `json:"timestamp"`
	Reason        string             `json:"reason"`
	FromCustodian string             `json:"from_custodian,omitempty"`
	ToCustodian   string             `json:"to_custodian,omitempty"`
	Provider      string             `json:"provider,omitempty"`
	PrivateKey    ed25519.PrivateKey `json:"-"`
}

// LedgerConfig configures the durable custody ledger store.
type LedgerConfig struct {
	RootDir string
	SyncDir bool
}

// LedgerStore manages durable, append-only custody chains.
type LedgerStore struct {
	mu      sync.RWMutex
	rootDir string
	syncDir bool
	closed  bool
	chains  map[string][]CustodyEvent // key: caseID + "/" + evidenceID
}

// OpenLedgerStore opens or initializes the custody ledger at rootDir.
func OpenLedgerStore(cfg LedgerConfig) (*LedgerStore, error) {
	if strings.TrimSpace(cfg.RootDir) == "" {
		return nil, ErrStoreDirRequired
	}
	if strings.ContainsRune(cfg.RootDir, '\x00') {
		return nil, fmt.Errorf("%w: null byte in root dir", ErrPathTraversal)
	}
	absRoot, err := filepath.Abs(cfg.RootDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if _, err := ensureNoSymlink(absRoot); err != nil {
		return nil, err
	}

	custodyDir := filepath.Join(absRoot, DefaultLedgerDir)
	if err := os.MkdirAll(custodyDir, 0o750); err != nil {
		return nil, fmt.Errorf("create custody dir: %w", err)
	}

	store := &LedgerStore{
		rootDir: custodyDir,
		syncDir: cfg.SyncDir,
		chains:  make(map[string][]CustodyEvent),
	}

	if err := store.recoverChains(); err != nil {
		return nil, err
	}

	return store, nil
}

func (s *LedgerStore) recoverChains() error {
	entries, err := os.ReadDir(s.rootDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read custody root: %w", err)
	}

	for _, caseEntry := range entries {
		if !caseEntry.IsDir() {
			continue
		}
		caseID := caseEntry.Name()
		if !isValidIdentifier(caseID) {
			continue
		}
		caseDir := filepath.Join(s.rootDir, caseID)
		files, err := os.ReadDir(caseDir)
		if err != nil {
			return fmt.Errorf("read case custody dir %s: %w", caseID, err)
		}
		for _, fileEntry := range files {
			if fileEntry.IsDir() || !strings.HasSuffix(fileEntry.Name(), ".jsonl") {
				continue
			}
			evidenceID := strings.TrimSuffix(fileEntry.Name(), ".jsonl")
			if !isValidIdentifier(evidenceID) {
				continue
			}
			filePath := filepath.Join(caseDir, fileEntry.Name())
			events, err := loadAndVerifyFile(filePath, caseID, evidenceID)
			if err != nil {
				return fmt.Errorf("load custody chain %s/%s: %w", caseID, evidenceID, err)
			}
			s.chains[caseID+"/"+evidenceID] = events
		}
	}
	return nil
}

func loadAndVerifyFile(path, caseID, evidenceID string) ([]CustodyEvent, error) {
	if _, err := ensureNoSymlink(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []CustodyEvent
	scanner := bufio.NewScanner(f)
	expectedSeq := uint64(1)
	expectedPrevHash := GenesisPrevHash
	expectedPrevRoot := GenesisPrevHash

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev CustodyEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("%w: malformed event JSON: %v", ErrChainCorrupted, err)
		}
		if ev.CaseID != caseID || ev.EvidenceID != evidenceID {
			return nil, fmt.Errorf("%w: event case/evidence mismatch", ErrChainCorrupted)
		}
		if ev.Sequence != expectedSeq {
			return nil, fmt.Errorf("%w: sequence gap/disorder at %d (want %d)", ErrSequenceMismatch, ev.Sequence, expectedSeq)
		}
		if ev.PrevHash != expectedPrevHash {
			return nil, fmt.Errorf("%w: prev_hash mismatch at sequence %d", ErrChainCorrupted, ev.Sequence)
		}
		computedDigest := ComputeEventDigest(ev)
		if ev.EventDigest != computedDigest {
			return nil, fmt.Errorf("%w: event digest mismatch at sequence %d", ErrHashMismatch, ev.Sequence)
		}
		computedRoot := ComputeCustodyRoot(expectedPrevRoot, computedDigest)
		if ev.CustodyRoot != computedRoot {
			return nil, fmt.Errorf("%w: custody root mismatch at sequence %d", ErrChainCorrupted, ev.Sequence)
		}

		events = append(events, ev)
		expectedSeq++
		expectedPrevHash = ev.EventDigest
		expectedPrevRoot = ev.CustodyRoot
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan custody file: %w", err)
	}

	return events, nil
}

// AppendEvent validates and durably records a new custody event to the chain.
func (s *LedgerStore) AppendEvent(ctx context.Context, req AppendEventRequest) (*CustodyEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrStoreClosed
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if err := validateAppendRequest(req); err != nil {
		return nil, err
	}

	key := req.CaseID + "/" + req.EvidenceID
	chain := s.chains[key]

	nextSeq := uint64(len(chain) + 1)
	prevHash := GenesisPrevHash
	prevRoot := GenesisPrevHash
	if len(chain) > 0 {
		last := chain[len(chain)-1]
		prevHash = last.EventDigest
		prevRoot = last.CustodyRoot

		// Timestamp must be >= previous timestamp
		lastT, errLast := time.Parse(time.RFC3339Nano, last.Timestamp)
		currT, errCurr := time.Parse(time.RFC3339Nano, req.Timestamp)
		if errLast == nil && errCurr == nil && currT.Before(lastT) {
			return nil, fmt.Errorf("%w: timestamp %s before previous %s", ErrInvalidTimestamp, req.Timestamp, last.Timestamp)
		}
	}

	eventID := req.EventID
	if eventID == "" {
		eventID = fmt.Sprintf("cust-ev-%s-%04d", req.EvidenceID, nextSeq)
	} else if !isValidIdentifier(eventID) {
		return nil, fmt.Errorf("%w: invalid event_id %q", ErrInvalidEvent, eventID)
	}

	eventType := req.EventType
	if eventType == "" {
		eventType = "transfer"
	}

	ev := CustodyEvent{
		SchemaVersion: SchemaVersion,
		EventID:       eventID,
		CaseID:        req.CaseID,
		EvidenceID:    req.EvidenceID,
		Sequence:      nextSeq,
		EventType:     eventType,
		Actor:         req.Actor,
		Timestamp:     req.Timestamp,
		Reason:        req.Reason,
		FromCustodian: req.FromCustodian,
		ToCustodian:   req.ToCustodian,
		PrevHash:      prevHash,
		Provider:      req.Provider,
	}

	ev.EventDigest = ComputeEventDigest(ev)
	ev.CustodyRoot = ComputeCustodyRoot(prevRoot, ev.EventDigest)

	if len(req.PrivateKey) == ed25519.PrivateKeySize {
		pub := req.PrivateKey.Public().(ed25519.PublicKey)
		sig := ed25519.Sign(req.PrivateKey, CanonicalEventBytes(ev))
		ev.PublicKey = hex.EncodeToString(pub)
		ev.Signature = hex.EncodeToString(sig)
	}

	// Write durably to disk before updating in-memory state
	if err := s.writeEventToFile(ev); err != nil {
		return nil, err
	}

	s.chains[key] = append(chain, ev)
	return &ev, nil
}

func (s *LedgerStore) writeEventToFile(ev CustodyEvent) error {
	caseDir := filepath.Join(s.rootDir, ev.CaseID)
	if err := checkWithinDir(s.rootDir, caseDir); err != nil {
		return err
	}
	if err := os.MkdirAll(caseDir, 0o750); err != nil {
		return fmt.Errorf("create case custody dir: %w", err)
	}

	filePath := filepath.Join(caseDir, ev.EvidenceID+".jsonl")
	if err := checkWithinDir(caseDir, filePath); err != nil {
		return err
	}
	if _, err := ensureNoSymlink(filePath); err != nil {
		return err
	}

	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal custody event: %w", err)
	}
	data = append(data, '\n')

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open custody ledger file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write custody event: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync custody ledger file: %w", err)
	}

	if s.syncDir {
		if df, err := os.Open(caseDir); err == nil {
			_ = df.Sync()
			_ = df.Close()
		}
	}
	return nil
}

func validateAppendRequest(req AppendEventRequest) error {
	if !isValidIdentifier(req.CaseID) {
		return fmt.Errorf("%w: invalid case_id %q", ErrInvalidEvent, req.CaseID)
	}
	if !isValidIdentifier(req.EvidenceID) {
		return fmt.Errorf("%w: invalid evidence_id %q", ErrInvalidEvent, req.EvidenceID)
	}
	if strings.TrimSpace(req.Actor) == "" {
		return ErrMissingActor
	}
	if !isValidIdentifier(req.Actor) {
		return fmt.Errorf("%w: invalid actor identifier %q", ErrInvalidEvent, req.Actor)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return ErrMissingReason
	}
	if strings.TrimSpace(req.Timestamp) == "" {
		return ErrMissingTimestamp
	}
	if !timestampRegex.MatchString(req.Timestamp) {
		return fmt.Errorf("%w: %q", ErrInvalidTimestamp, req.Timestamp)
	}
	if _, err := time.Parse(time.RFC3339Nano, req.Timestamp); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTimestamp, err)
	}
	if !allowedProviders[req.Provider] {
		return fmt.Errorf("%w: %q", ErrUnavailableProvider, req.Provider)
	}
	return nil
}

// ListEvents returns a copy of all custody events for (caseID, evidenceID).
func (s *LedgerStore) ListEvents(caseID, evidenceID string) ([]CustodyEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}
	key := caseID + "/" + evidenceID
	chain, exists := s.chains[key]
	if !exists {
		return []CustodyEvent{}, nil
	}
	out := make([]CustodyEvent, len(chain))
	copy(out, chain)
	return out, nil
}

// GetEvent returns a single custody event by sequence number.
func (s *LedgerStore) GetEvent(caseID, evidenceID string, sequence uint64) (*CustodyEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}
	key := caseID + "/" + evidenceID
	chain, exists := s.chains[key]
	if !exists || sequence == 0 || sequence > uint64(len(chain)) {
		return nil, ErrEventNotFound
	}
	ev := chain[sequence-1]
	return &ev, nil
}

// CurrentRoot returns the latest custody root hash for an evidence chain.
func (s *LedgerStore) CurrentRoot(caseID, evidenceID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return "", ErrStoreClosed
	}
	key := caseID + "/" + evidenceID
	chain, exists := s.chains[key]
	if !exists || len(chain) == 0 {
		return GenesisPrevHash, nil
	}
	return chain[len(chain)-1].CustodyRoot, nil
}

// VerifyChain verifies the cryptographic hash chain and sequence continuity for an evidence chain.
func (s *LedgerStore) VerifyChain(caseID, evidenceID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return false, ErrStoreClosed
	}
	key := caseID + "/" + evidenceID
	chain, exists := s.chains[key]
	if !exists || len(chain) == 0 {
		return true, nil
	}

	expectedPrevHash := GenesisPrevHash
	expectedPrevRoot := GenesisPrevHash

	for i, ev := range chain {
		expectedSeq := uint64(i + 1)
		if ev.Sequence != expectedSeq {
			return false, fmt.Errorf("%w: sequence %d != expected %d", ErrSequenceMismatch, ev.Sequence, expectedSeq)
		}
		if ev.PrevHash != expectedPrevHash {
			return false, fmt.Errorf("%w: prev_hash mismatch at sequence %d", ErrChainCorrupted, ev.Sequence)
		}
		digest := ComputeEventDigest(ev)
		if ev.EventDigest != digest {
			return false, fmt.Errorf("%w: digest mismatch at sequence %d", ErrHashMismatch, ev.Sequence)
		}
		root := ComputeCustodyRoot(expectedPrevRoot, digest)
		if ev.CustodyRoot != root {
			return false, fmt.Errorf("%w: custody root mismatch at sequence %d", ErrChainCorrupted, ev.Sequence)
		}
		if ev.PublicKey != "" && ev.Signature != "" {
			pubBytes, err := hex.DecodeString(ev.PublicKey)
			if err != nil || len(pubBytes) != ed25519.PublicKeySize {
				return false, fmt.Errorf("%w: invalid public key at sequence %d", ErrInvalidEvent, ev.Sequence)
			}
			sigBytes, err := hex.DecodeString(ev.Signature)
			if err != nil || len(sigBytes) != ed25519.SignatureSize {
				return false, fmt.Errorf("%w: invalid signature at sequence %d", ErrInvalidEvent, ev.Sequence)
			}
			if !ed25519.Verify(pubBytes, CanonicalEventBytes(ev), sigBytes) {
				return false, fmt.Errorf("%w: signature verification failed at sequence %d", ErrChainCorrupted, ev.Sequence)
			}
		}

		expectedPrevHash = ev.EventDigest
		expectedPrevRoot = ev.CustodyRoot
	}

	return true, nil
}

// CustodyDir returns the resolved custody directory storing <caseID>/<evidenceID>.jsonl chains.
func (s *LedgerStore) CustodyDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rootDir
}

// VerifyChainFileOnDisk re-reads and verifies the persisted <caseID>/<evidenceID>.jsonl file
// against cryptographic chain invariants and the store's loaded in-memory chain.
func (s *LedgerStore) VerifyChainFileOnDisk(caseID, evidenceID string) error {
	if s == nil {
		return ErrStoreDirRequired
	}
	if !isValidIdentifier(caseID) {
		return fmt.Errorf("%w: invalid case_id %q", ErrInvalidEvent, caseID)
	}
	if !isValidIdentifier(evidenceID) {
		return fmt.Errorf("%w: invalid evidence_id %q", ErrInvalidEvent, evidenceID)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrStoreClosed
	}

	key := caseID + "/" + evidenceID
	caseDir := filepath.Join(s.rootDir, caseID)
	if err := checkWithinDir(s.rootDir, caseDir); err != nil {
		return err
	}
	filePath := filepath.Join(caseDir, evidenceID+".jsonl")
	if err := checkWithinDir(caseDir, filePath); err != nil {
		return err
	}
	if _, err := ensureNoSymlink(filePath); err != nil {
		return err
	}

	memChain := s.chains[key]
	diskEvents, err := loadAndVerifyFile(filePath, caseID, evidenceID)
	if err != nil {
		if os.IsNotExist(err) {
			if len(memChain) == 0 {
				return fmt.Errorf("%w: missing custody file for %s", ErrChainCorrupted, key)
			}
			return fmt.Errorf("%w: missing on-disk custody file for loaded chain %s", ErrChainCorrupted, key)
		}
		return err
	}
	if len(diskEvents) == 0 {
		return fmt.Errorf("%w: empty custody file for %s", ErrChainCorrupted, key)
	}
	if err := verifyCandidateChain(caseID, evidenceID, diskEvents); err != nil {
		return err
	}
	if !custodyChainsEqual(memChain, diskEvents) {
		return fmt.Errorf("%w: on-disk custody file %s diverges from in-memory ledger", ErrChainCorrupted, key)
	}
	return nil
}

// RestoreVerifiedChain atomically imports a verified custody chain when absent on disk/in memory.
// If a chain already exists for (caseID, evidenceID), it is never rewritten or truncated:
// an identical chain returns nil (idempotent), while any divergence returns ErrImmutableHistory.
func (s *LedgerStore) RestoreVerifiedChain(ctx context.Context, caseID, evidenceID string, events []CustodyEvent) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if !isValidIdentifier(caseID) {
		return fmt.Errorf("%w: invalid case_id %q", ErrInvalidEvent, caseID)
	}
	if !isValidIdentifier(evidenceID) {
		return fmt.Errorf("%w: invalid evidence_id %q", ErrInvalidEvent, evidenceID)
	}
	if len(events) == 0 {
		return fmt.Errorf("%w: cannot restore empty custody chain", ErrInvalidEvent)
	}

	if err := verifyCandidateChain(caseID, evidenceID, events); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	key := caseID + "/" + evidenceID
	caseDir := filepath.Join(s.rootDir, caseID)
	if err := checkWithinDir(s.rootDir, caseDir); err != nil {
		return err
	}
	filePath := filepath.Join(caseDir, evidenceID+".jsonl")
	if err := checkWithinDir(caseDir, filePath); err != nil {
		return err
	}
	if _, err := ensureNoSymlink(filePath); err != nil {
		return err
	}

	// Never overwrite, rewrite, or truncate an existing custody chain.
	if existing, ok := s.chains[key]; ok {
		if !custodyChainsEqual(existing, events) {
			return fmt.Errorf("%w: existing custody chain %s differs from restore candidate", ErrImmutableHistory, key)
		}
		diskEvents, loadErr := loadAndVerifyFile(filePath, caseID, evidenceID)
		if loadErr != nil || !custodyChainsEqual(diskEvents, existing) {
			return fmt.Errorf("%w: on-disk custody file %s missing or diverges from loaded chain (%v)", ErrImmutableHistory, key, loadErr)
		}
		return nil
	}
	if _, err := os.Lstat(filePath); err == nil {
		diskEvents, loadErr := loadAndVerifyFile(filePath, caseID, evidenceID)
		if loadErr != nil {
			return fmt.Errorf("%w: existing custody file %s invalid: %v", ErrImmutableHistory, key, loadErr)
		}
		if custodyChainsEqual(diskEvents, events) {
			s.chains[key] = diskEvents
			return nil
		}
		return fmt.Errorf("%w: existing custody file %s differs from restore candidate", ErrImmutableHistory, key)
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.MkdirAll(caseDir, 0o750); err != nil {
		return fmt.Errorf("create case custody dir: %w", err)
	}

	var buf strings.Builder
	for _, ev := range events {
		line, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("marshal custody event: %w", err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	tmpPath := filepath.Join(caseDir, fmt.Sprintf(".%s.%d.jsonl.tmp", evidenceID, time.Now().UnixNano()))
	if _, err := ensureNoSymlink(tmpPath); err != nil {
		return err
	}
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create staged custody file: %w", err)
	}
	if _, err := f.WriteString(buf.String()); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write staged custody file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sync staged custody file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close staged custody file: %w", err)
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("commit custody chain %s: %w", key, err)
	}
	if s.syncDir {
		if df, err := os.Open(caseDir); err == nil {
			_ = df.Sync()
			_ = df.Close()
		}
	}

	copied := make([]CustodyEvent, len(events))
	copy(copied, events)
	s.chains[key] = copied
	return nil
}

func verifyCandidateChain(caseID, evidenceID string, events []CustodyEvent) error {
	expectedPrevHash := GenesisPrevHash
	expectedPrevRoot := GenesisPrevHash
	var prevTime time.Time

	for i, ev := range events {
		expectedSeq := uint64(i + 1)
		if ev.SchemaVersion != SchemaVersion {
			return fmt.Errorf("%w: unsupported event schema_version %q at sequence %d", ErrInvalidEvent, ev.SchemaVersion, expectedSeq)
		}
		if ev.CaseID != caseID || ev.EvidenceID != evidenceID {
			return fmt.Errorf("%w: event case/evidence mismatch at sequence %d", ErrChainCorrupted, expectedSeq)
		}
		if !isValidIdentifier(ev.EventID) {
			return fmt.Errorf("%w: invalid event_id %q", ErrInvalidEvent, ev.EventID)
		}
		if strings.TrimSpace(ev.Actor) == "" || !isValidIdentifier(ev.Actor) {
			return fmt.Errorf("%w: invalid actor at sequence %d", ErrInvalidEvent, expectedSeq)
		}
		if strings.TrimSpace(ev.Reason) == "" {
			return ErrMissingReason
		}
		if !timestampRegex.MatchString(ev.Timestamp) {
			return fmt.Errorf("%w: %q", ErrInvalidTimestamp, ev.Timestamp)
		}
		currTime, err := time.Parse(time.RFC3339Nano, ev.Timestamp)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidTimestamp, err)
		}
		if i > 0 && currTime.Before(prevTime) {
			return fmt.Errorf("%w: non-monotonic timestamp at sequence %d", ErrInvalidTimestamp, expectedSeq)
		}
		prevTime = currTime
		if !allowedProviders[ev.Provider] {
			return fmt.Errorf("%w: %q", ErrUnavailableProvider, ev.Provider)
		}
		if ev.Sequence != expectedSeq {
			return fmt.Errorf("%w: sequence %d != expected %d", ErrSequenceMismatch, ev.Sequence, expectedSeq)
		}
		if ev.PrevHash != expectedPrevHash {
			return fmt.Errorf("%w: prev_hash mismatch at sequence %d", ErrChainCorrupted, ev.Sequence)
		}
		digest := ComputeEventDigest(ev)
		if ev.EventDigest != digest {
			return fmt.Errorf("%w: digest mismatch at sequence %d", ErrHashMismatch, ev.Sequence)
		}
		root := ComputeCustodyRoot(expectedPrevRoot, digest)
		if ev.CustodyRoot != root {
			return fmt.Errorf("%w: custody root mismatch at sequence %d", ErrChainCorrupted, ev.Sequence)
		}
		if ev.PublicKey != "" || ev.Signature != "" {
			pubBytes, err := hex.DecodeString(ev.PublicKey)
			if err != nil || len(pubBytes) != ed25519.PublicKeySize {
				return fmt.Errorf("%w: invalid public key at sequence %d", ErrInvalidEvent, ev.Sequence)
			}
			sigBytes, err := hex.DecodeString(ev.Signature)
			if err != nil || len(sigBytes) != ed25519.SignatureSize {
				return fmt.Errorf("%w: invalid signature at sequence %d", ErrInvalidEvent, ev.Sequence)
			}
			if !ed25519.Verify(pubBytes, CanonicalEventBytes(ev), sigBytes) {
				return fmt.Errorf("%w: signature verification failed at sequence %d", ErrChainCorrupted, ev.Sequence)
			}
		}
		expectedPrevHash = ev.EventDigest
		expectedPrevRoot = ev.CustodyRoot
	}
	return nil
}

func custodyChainsEqual(a, b []CustodyEvent) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Close closes the ledger store.
func (s *LedgerStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

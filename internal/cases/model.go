package cases

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/storage"
)

type CaseStatus string

const (
	StatusOpen     CaseStatus = "open"
	StatusClosed   CaseStatus = "closed"
	StatusArchived CaseStatus = "archived"
)

var (
	ErrInvalidCase         = errors.New("invalid case specification")
	ErrCaseNotFound        = errors.New("case not found")
	ErrDuplicateCase       = errors.New("case already exists")
	ErrInvalidEvidenceID   = errors.New("invalid evidence identifier")
	ErrEvidenceNotFound    = errors.New("evidence not found in case")
	ErrCrossCaseAccess     = errors.New("cross-case access forbidden: evidence belongs to a different case")
	ErrMissingPrerequisite = errors.New("missing prerequisite")
	ErrUnavailableProvider = errors.New("unavailable identity or case provider")
	ErrStorageRequired     = errors.New("storage adapter is required")
)

var (
	identifierRegex    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	allowedClass       = map[string]bool{"public": true, "internal": true, "confidential": true, "restricted": true}
	allowedProviders   = map[string]bool{"": true, "local": true, "breachatlas": true}
)

func isValidIdentifier(s string) bool {
	return identifierRegex.MatchString(s) && !strings.Contains(s, "..") && !strings.ContainsAny(s, "/\\")
}

// Case represents an isolated DFIR investigation aggregate root.
type Case struct {
	CaseID         string     `json:"case_id"`
	Title          string     `json:"title"`
	Classification string     `json:"classification"`
	Status         CaseStatus `json:"status"`
	Owner          string     `json:"owner"`
	Provider       string     `json:"provider,omitempty"`
	CreatedAt      string     `json:"created_at"`
	EvidenceIDs    []string   `json:"evidence_ids"`
}

// EvidenceItem represents a sealed evidence artifact bound to exactly one Case.
type EvidenceItem struct {
	CaseID      string `json:"case_id"`
	EvidenceID  string `json:"evidence_id"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	MediaType   string `json:"media_type"`
	AcquiredAt  string `json:"acquired_at"`
	CustodyRoot string `json:"custody_root"`
	Sealed      bool   `json:"sealed"`
	CommittedAt string `json:"committed_at"`
}

type CreateCaseInput struct {
	CaseID         string `json:"case_id"`
	Title          string `json:"title"`
	Classification string `json:"classification"`
	Owner          string `json:"owner"`
	Provider       string `json:"provider,omitempty"`
}

type RegisterEvidenceRequest struct {
	OperationID string            `json:"operation_id"`
	Manifest    evidence.Manifest `json:"manifest"`
	Payload     []byte            `json:"payload"`
	Identity    storage.Identity  `json:"identity"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// Registry manages case aggregates and enforces single-case evidence ownership
// backed by the authoritative local storage adapter.
type Registry struct {
	mu             sync.RWMutex
	store          *storage.Adapter
	cases          map[string]*Case
	evidenceItems  map[string]map[string]EvidenceItem // caseID -> evidenceID -> item
	evidenceOwners map[string]string                  // evidenceID -> owning caseID
}

// NewRegistry creates a case/evidence aggregate registry backed by a non-nil storage adapter.
func NewRegistry(store *storage.Adapter) (*Registry, error) {
	if store == nil {
		return nil, ErrStorageRequired
	}
	r := &Registry{
		store:          store,
		cases:          make(map[string]*Case),
		evidenceItems:  make(map[string]map[string]EvidenceItem),
		evidenceOwners: make(map[string]string),
	}
	if err := r.RecoverFromStorage(); err != nil {
		return nil, err
	}
	return r, nil
}

// RecoverFromStorage rebuilds case aggregates and evidence ownership mappings
// from the storage adapter's durable committed manifest.
func (r *Registry) RecoverFromStorage() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.store == nil {
		return ErrStorageRequired
	}
	if _, err := r.store.RebuildProjection(); err != nil {
		return err
	}

	state := r.store.CurrentState()
	recoveredCases := make(map[string]*Case)
	recoveredItems := make(map[string]map[string]EvidenceItem)
	recoveredOwners := make(map[string]string)

	// Sort keys for deterministic recovery ordering.
	keys := make([]string, 0, len(state.Evidence))
	for k := range state.Evidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		rec := state.Evidence[k]
		if !isValidIdentifier(rec.CaseID) || !isValidIdentifier(rec.EvidenceID) {
			return fmt.Errorf("%w: invalid stored case/evidence identifier %q/%q", ErrInvalidCase, rec.CaseID, rec.EvidenceID)
		}
		if existingOwner, bound := recoveredOwners[rec.EvidenceID]; bound && existingOwner != rec.CaseID {
			return fmt.Errorf("%w: evidence %s bound to both %s and %s", ErrCrossCaseAccess, rec.EvidenceID, existingOwner, rec.CaseID)
		}
		recoveredOwners[rec.EvidenceID] = rec.CaseID

		c, exists := recoveredCases[rec.CaseID]
		if !exists {
			// Preserve existing in-memory metadata if already registered in this session.
			if prev, ok := r.cases[rec.CaseID]; ok {
				copyCase := *prev
				copyCase.EvidenceIDs = nil
				c = &copyCase
			} else {
				c = &Case{
					CaseID:         rec.CaseID,
					Title:          rec.CaseID,
					Classification: "internal",
					Status:         StatusOpen,
					Owner:          "recovered",
					CreatedAt:      rec.CommittedAt,
				}
			}
			recoveredCases[rec.CaseID] = c
			recoveredItems[rec.CaseID] = make(map[string]EvidenceItem)
		}
		c.EvidenceIDs = append(c.EvidenceIDs, rec.EvidenceID)
		recoveredItems[rec.CaseID][rec.EvidenceID] = EvidenceItem{
			CaseID:      rec.CaseID,
			EvidenceID:  rec.EvidenceID,
			SHA256:      rec.SHA256,
			SizeBytes:   rec.SizeBytes,
			MediaType:   rec.MediaType,
			AcquiredAt:  rec.AcquiredAt,
			CustodyRoot: rec.CustodyRoot,
			Sealed:      true,
			CommittedAt: rec.CommittedAt,
		}
	}

	// Retain open empty cases that were created in memory during this session.
	for id, prev := range r.cases {
		if _, ok := recoveredCases[id]; !ok {
			copyCase := *prev
			copyCase.EvidenceIDs = []string{}
			recoveredCases[id] = &copyCase
			recoveredItems[id] = make(map[string]EvidenceItem)
		}
	}

	for _, c := range recoveredCases {
		sort.Strings(c.EvidenceIDs)
	}

	r.cases = recoveredCases
	r.evidenceItems = recoveredItems
	r.evidenceOwners = recoveredOwners
	return nil
}

// CreateCase validates and registers a new isolated case aggregate.
func (r *Registry) CreateCase(in CreateCaseInput) (*Case, error) {
	if !allowedProviders[in.Provider] {
		return nil, fmt.Errorf("%w: %q", ErrUnavailableProvider, in.Provider)
	}
	if !isValidIdentifier(in.CaseID) {
		return nil, fmt.Errorf("%w: invalid case_id %q", ErrInvalidCase, in.CaseID)
	}
	title := strings.TrimSpace(in.Title)
	if title == "" || len(title) > 4096 {
		return nil, fmt.Errorf("%w: title is required and must be <= 4096 chars", ErrInvalidCase)
	}
	class := strings.ToLower(strings.TrimSpace(in.Classification))
	if !allowedClass[class] {
		return nil, fmt.Errorf("%w: unsupported classification %q", ErrInvalidCase, in.Classification)
	}
	if !isValidIdentifier(in.Owner) {
		return nil, fmt.Errorf("%w: invalid owner %q", ErrInvalidCase, in.Owner)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.cases[in.CaseID]; exists {
		return nil, fmt.Errorf("%w: %s", ErrDuplicateCase, in.CaseID)
	}

	c := &Case{
		CaseID:         in.CaseID,
		Title:          title,
		Classification: class,
		Status:         StatusOpen,
		Owner:          in.Owner,
		Provider:       in.Provider,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		EvidenceIDs:    []string{},
	}
	r.cases[in.CaseID] = c
	r.evidenceItems[in.CaseID] = make(map[string]EvidenceItem)

	out := *c
	out.EvidenceIDs = []string{}
	return &out, nil
}

// GetCase returns a copy of the requested Case aggregate.
func (r *Registry) GetCase(caseID string) (*Case, error) {
	if !isValidIdentifier(caseID) {
		return nil, fmt.Errorf("%w: invalid case_id %q", ErrInvalidCase, caseID)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	c, exists := r.cases[caseID]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrCaseNotFound, caseID)
	}
	out := *c
	out.EvidenceIDs = append([]string(nil), c.EvidenceIDs...)
	return &out, nil
}

// RegisterEvidence seals and binds an evidence item to its owning case.
// Prerequisite: the target Case must exist, and EvidenceID must not belong to another case.
func (r *Registry) RegisterEvidence(ctx context.Context, req RegisterEvidenceRequest) (*EvidenceItem, error) {
	if r.store == nil {
		return nil, ErrStorageRequired
	}
	if !allowedProviders[req.Identity.Provider] {
		return nil, fmt.Errorf("%w: %q", ErrUnavailableProvider, req.Identity.Provider)
	}
	if !isValidIdentifier(req.Manifest.CaseID) {
		return nil, fmt.Errorf("%w: invalid case_id %q", ErrInvalidCase, req.Manifest.CaseID)
	}
	if !isValidIdentifier(req.Manifest.EvidenceID) {
		return nil, fmt.Errorf("%w: invalid evidence_id %q", ErrInvalidEvidenceID, req.Manifest.EvidenceID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	c, caseExists := r.cases[req.Manifest.CaseID]
	if !caseExists {
		return nil, fmt.Errorf("%w: %w: case %s does not exist", ErrMissingPrerequisite, ErrCaseNotFound, req.Manifest.CaseID)
	}
	if c.Status != StatusOpen {
		return nil, fmt.Errorf("%w: case %s is %s", ErrInvalidCase, c.CaseID, c.Status)
	}

	if ownerCase, bound := r.evidenceOwners[req.Manifest.EvidenceID]; bound && ownerCase != req.Manifest.CaseID {
		return nil, fmt.Errorf("%w: evidence %s belongs to case %s, cannot bind to %s",
			ErrCrossCaseAccess, req.Manifest.EvidenceID, ownerCase, req.Manifest.CaseID)
	}

	res, err := r.store.CommitWrite(ctx, storage.WriteRequest{
		OperationID: req.OperationID,
		Manifest:    req.Manifest,
		Payload:     req.Payload,
		Identity:    req.Identity,
		Headers:     req.Headers,
	})
	if err != nil {
		return nil, err
	}

	item := EvidenceItem{
		CaseID:      req.Manifest.CaseID,
		EvidenceID:  req.Manifest.EvidenceID,
		SHA256:      res.SHA256,
		SizeBytes:   res.SizeBytes,
		MediaType:   req.Manifest.MediaType,
		AcquiredAt:  req.Manifest.AcquiredAt,
		CustodyRoot: req.Manifest.CustodyRoot,
		Sealed:      true,
		CommittedAt: res.CommittedAt,
	}

	if _, exists := r.evidenceItems[c.CaseID][item.EvidenceID]; !exists {
		c.EvidenceIDs = append(c.EvidenceIDs, item.EvidenceID)
		sort.Strings(c.EvidenceIDs)
	}
	r.evidenceItems[c.CaseID][item.EvidenceID] = item
	r.evidenceOwners[item.EvidenceID] = c.CaseID

	return &item, nil
}

// GetEvidence enforces single-case ownership before returning verified sealed bytes.
// Any attempt to read an EvidenceID owned by a different CaseID fails with ErrCrossCaseAccess.
func (r *Registry) GetEvidence(caseID, evidenceID string) ([]byte, *EvidenceItem, error) {
	if !isValidIdentifier(caseID) {
		return nil, nil, fmt.Errorf("%w: invalid case_id %q", ErrInvalidCase, caseID)
	}
	if !isValidIdentifier(evidenceID) {
		return nil, nil, fmt.Errorf("%w: invalid evidence_id %q", ErrInvalidEvidenceID, evidenceID)
	}

	r.mu.RLock()
	if _, caseExists := r.cases[caseID]; !caseExists {
		r.mu.RUnlock()
		return nil, nil, fmt.Errorf("%w: %s", ErrCaseNotFound, caseID)
	}
	if ownerCase, bound := r.evidenceOwners[evidenceID]; bound && ownerCase != caseID {
		r.mu.RUnlock()
		return nil, nil, fmt.Errorf("%w: evidence %s belongs to case %s", ErrCrossCaseAccess, evidenceID, ownerCase)
	}
	item, exists := r.evidenceItems[caseID][evidenceID]
	r.mu.RUnlock()

	if !exists {
		return nil, nil, fmt.Errorf("%w: %s/%s", ErrEvidenceNotFound, caseID, evidenceID)
	}

	data, _, err := r.store.GetEvidence(caseID, evidenceID)
	if err != nil {
		return nil, nil, err
	}
	itemCopy := item
	return data, &itemCopy, nil
}

// ListCaseEvidence returns all sealed evidence items belonging strictly to caseID.
func (r *Registry) ListCaseEvidence(caseID string) ([]EvidenceItem, error) {
	if !isValidIdentifier(caseID) {
		return nil, fmt.Errorf("%w: invalid case_id %q", ErrInvalidCase, caseID)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	c, exists := r.cases[caseID]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrCaseNotFound, caseID)
	}

	out := make([]EvidenceItem, 0, len(c.EvidenceIDs))
	for _, evID := range c.EvidenceIDs {
		if item, ok := r.evidenceItems[caseID][evID]; ok {
			out = append(out, item)
		}
	}
	return out, nil
}

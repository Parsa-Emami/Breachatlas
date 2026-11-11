package timeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/artifacts"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

const (
	DefaultSearchMaxResults = 100
	MaxSearchResultsCap     = 1000
	DefaultMaxScanEvents    = 5000
	MaxScanEventsCap        = 50000
	DefaultMaxExpandDepth   = 0
	MaxExpandDepthCap       = 8
	DefaultMaxExpandDegree  = 32
	MaxExpandDegreeCap      = 256
	DefaultMaxVisitedNodes  = 500
	MaxVisitedNodesCap      = 5000
	DefaultMaxRebuildEvents = 250000

	SearchStatusComplete         = "complete"
	SearchStatusTruncated        = "truncated"
	SearchStatusDeadlineExceeded = "deadline_exceeded"
	SearchStatusCanceled         = "canceled"

	TruncationMaxResults      = "max_results"
	TruncationMaxScanEvents   = "max_scan_events"
	TruncationMaxDegree       = "max_degree"
	TruncationMaxVisitedNodes = "max_visited_nodes"
	TruncationCycleDetected   = "cycle_detected"
	TruncationDeadline        = "deadline_exceeded"
	TruncationCanceled        = "canceled"
)

var (
	ErrQueryLimitExceeded    = errors.New("timeline query bound exceeds allowed maximum cap")
	ErrQueryDeadlineExceeded = errors.New("timeline query deadline exceeded")
	ErrQueryCanceled         = errors.New("timeline query canceled")
)

// SearchRequest configures a deterministic, strictly bounded query against a case's EventIndexStore.
type SearchRequest struct {
	SchemaVersion         string        `json:"schema_version"`
	CaseID                string        `json:"case_id"`
	Provider              string        `json:"provider,omitempty"`
	TextQuery             string        `json:"text_query,omitempty"`
	EventTypes            []string      `json:"event_types,omitempty"`
	EvidenceIDs           []string      `json:"evidence_ids,omitempty"`
	StartTimeUTC          string        `json:"start_time_utc,omitempty"`
	EndTimeUTC            string        `json:"end_time_utc,omitempty"`
	IncludeUnresolvedTime bool          `json:"include_unresolved_time,omitempty"`
	MinConfidence         *float64      `json:"min_confidence,omitempty"`
	Offset                int           `json:"offset,omitempty"`
	MaxResults            int           `json:"max_results,omitempty"`
	MaxScanEvents         int           `json:"max_scan_events,omitempty"`
	ExpandDepth           int           `json:"expand_depth,omitempty"`
	MaxExpandDegree       int           `json:"max_expand_degree,omitempty"`
	MaxVisitedNodes       int           `json:"max_visited_nodes,omitempty"`
	Timeout               time.Duration `json:"-"`
}

// RelatedEventEdge records a bounded link traversed during SearchRequest graph expansion.
type RelatedEventEdge struct {
	FromIdentity string `json:"from_identity"`
	ToIdentity   string `json:"to_identity"`
	Relation     string `json:"relation"`
	Depth        int    `json:"depth"`
}

// SearchResult returns deterministically ordered entries, bounded graph links, and explicit termination status.
type SearchResult struct {
	SchemaVersion    string             `json:"schema_version"`
	CaseID           string             `json:"case_id"`
	Status           string             `json:"status"`
	Truncated        bool               `json:"truncated"`
	TruncationReason string             `json:"truncation_reason,omitempty"`
	CycleDetected    bool               `json:"cycle_detected,omitempty"`
	ScannedCount     int                `json:"scanned_count"`
	MatchedCount     int                `json:"matched_count"`
	VisitedCount     int                `json:"visited_count,omitempty"`
	ReturnedCount    int                `json:"returned_count"`
	HasMore          bool               `json:"has_more"`
	NextOffset       int                `json:"next_offset,omitempty"`
	Entries          []TimelineEntry    `json:"entries"`
	RelatedEntries   []TimelineEntry    `json:"related_entries,omitempty"`
	RelatedEdges     []RelatedEventEdge `json:"related_edges,omitempty"`
	ResultDigest     string             `json:"result_digest"`
}

// RebuildRequest re-derives and atomically replaces a case timeline index from verified derived artifacts.
type RebuildRequest struct {
	SchemaVersion    string                  `json:"schema_version"`
	CaseID           string                  `json:"case_id"`
	ArtifactIDs      []string                `json:"artifact_ids,omitempty"`
	Provider         string                  `json:"provider,omitempty"`
	ZoneHint         string                  `json:"zone_hint,omitempty"`
	SourceConfidence *float64                `json:"source_confidence,omitempty"`
	MaxRebuildEvents int                     `json:"max_rebuild_events,omitempty"`
	VerifyOptions    artifacts.VerifyOptions `json:"-"`
}

// RebuildOutcome reports verified artifacts processed and deterministic entry counts after rebuilding a case index.
type RebuildOutcome struct {
	SchemaVersion      string   `json:"schema_version"`
	CaseID             string   `json:"case_id"`
	ArtifactIDs        []string `json:"artifact_ids"`
	ArtifactsProcessed int      `json:"artifacts_processed"`
	TotalSubmitted     int      `json:"total_submitted"`
	RebuiltEntries     int      `json:"rebuilt_entries"`
	DeduplicatedCount  int      `json:"deduplicated_count"`
	Generation         uint64   `json:"generation"`
	CaseIndexSHA256    string   `json:"case_index_sha256"`
}

type searchBounds struct {
	maxResults      int
	maxScanEvents   int
	expandDepth     int
	maxExpandDegree int
	maxVisitedNodes int
	hasStart        bool
	startUTC        time.Time
	hasEnd          bool
	endUTC          time.Time
	typeSet         map[string]bool
	evidenceSet     map[string]bool
	textNeedle      string
}

type sealedBlobSnapshot struct {
	path string
	sha  string
	size int64
}

// Search executes a deterministic, bounded query over indexed timeline entries for CaseID.
// Over-limit, high-degree, or cyclic inputs terminate cleanly with Status == "truncated" and an
// explicit TruncationReason; context deadlines and cancellations return partial telemetry alongside
// ErrQueryDeadlineExceeded or ErrQueryCanceled.
func (s *EventIndexStore) Search(ctx context.Context, req SearchRequest) (*SearchResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil {
		return nil, ErrIndexStoreRequired
	}
	if req.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %q", ErrUnsupportedVersion, req.SchemaVersion)
	}
	if err := validateIdentifier("case_id", req.CaseID); err != nil {
		return nil, err
	}
	if !allowedProviders[req.Provider] {
		return nil, fmt.Errorf("%w: provider %q unsupported in local-first profile", ErrUnavailableProvider, req.Provider)
	}
	if req.Timeout < 0 {
		return nil, fmt.Errorf("%w: timeout cannot be negative", ErrInvalidInput)
	}
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	bounds, err := validateSearchBounds(req)
	if err != nil {
		return nil, err
	}

	// Snapshot sorted case entries under lock so concurrent writes/rebuilds cannot race or corrupt reads.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrIndexStoreClosed
	}
	caseMap, exists := s.entriesByCase[req.CaseID]
	var sorted []TimelineEntry
	if exists {
		sorted = sortTimelineEntries(caseMap)
	}
	s.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("%w: case %q not indexed", ErrEntryNotFound, req.CaseID)
	}

	res := &SearchResult{
		SchemaVersion: SchemaVersion,
		CaseID:        req.CaseID,
		Status:        SearchStatusComplete,
		Entries:       []TimelineEntry{},
	}

	if err := checkSearchContext(ctx, res); err != nil {
		finalizeSearchDigest(res)
		return res, err
	}

	for _, entry := range sorted {
		if err := checkSearchContext(ctx, res); err != nil {
			finalizeSearchDigest(res)
			return res, err
		}
		if res.ScannedCount >= bounds.maxScanEvents {
			markTruncated(res, TruncationMaxScanEvents)
			break
		}
		res.ScannedCount++

		if !entryMatchesSearch(entry, req, bounds) {
			continue
		}
		res.MatchedCount++

		if res.MatchedCount <= req.Offset {
			continue
		}
		if len(res.Entries) < bounds.maxResults {
			res.Entries = append(res.Entries, cloneEntry(entry))
			continue
		}

		res.HasMore = true
		res.NextOffset = req.Offset + len(res.Entries)
		markTruncated(res, TruncationMaxResults)
		break
	}

	res.ReturnedCount = len(res.Entries)

	if bounds.expandDepth > 0 && len(res.Entries) > 0 {
		if err := expandBoundedRelated(ctx, sorted, bounds, res); err != nil {
			finalizeSearchDigest(res)
			return res, err
		}
	}

	finalizeSearchDigest(res)
	return res, nil
}

// RebuildCaseIndex deterministically rebuilds the timeline index for CaseID from verified C16
// derived artifacts and read-only SealStore inputs, replacing stale or missing case index state
// atomically without altering sealed source bytes.
func (s *EventIndexStore) RebuildCaseIndex(
	ctx context.Context,
	sealStore *evidence.SealStore,
	sealRootDir string,
	artifactStore *artifacts.ArtifactStore,
	artifactRootDir string,
	req RebuildRequest,
) (*RebuildOutcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, classifyContextErr(err)
	}
	if s == nil {
		return nil, ErrIndexStoreRequired
	}
	if req.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %q", ErrUnsupportedVersion, req.SchemaVersion)
	}
	if err := validateIdentifier("case_id", req.CaseID); err != nil {
		return nil, err
	}
	if !allowedProviders[req.Provider] {
		return nil, fmt.Errorf("%w: provider %q unsupported in local-first profile", ErrUnavailableProvider, req.Provider)
	}
	if err := validateZoneHint(req.ZoneHint); err != nil {
		return nil, err
	}
	if req.SourceConfidence != nil && (*req.SourceConfidence < 0 || *req.SourceConfidence > 1) {
		return nil, fmt.Errorf("%w: source_confidence %.4f must be within [0, 1]", ErrInvalidInput, *req.SourceConfidence)
	}
	maxRebuild := req.MaxRebuildEvents
	if maxRebuild == 0 {
		maxRebuild = DefaultMaxRebuildEvents
	}
	if maxRebuild < 0 || maxRebuild > DefaultMaxRebuildEvents {
		return nil, fmt.Errorf("%w: max_rebuild_events %d out of bounds [1, %d]", ErrQueryLimitExceeded, req.MaxRebuildEvents, DefaultMaxRebuildEvents)
	}
	if sealStore == nil || strings.TrimSpace(sealRootDir) == "" || artifactStore == nil || strings.TrimSpace(artifactRootDir) == "" {
		return nil, fmt.Errorf("%w: sealStore, sealRootDir, artifactStore, and artifactRootDir are required", ErrMissingPrerequisite)
	}

	absSealRoot, err := filepath.Abs(filepath.Clean(sealRootDir))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if _, err := ensureNoSymlink(absSealRoot); err != nil {
		return nil, err
	}

	absArtifactRoot, err := filepath.Abs(filepath.Clean(artifactRootDir))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if _, err := ensureNoSymlink(absArtifactRoot); err != nil {
		return nil, err
	}

	artifactIDs, err := resolveCaseArtifactIDs(absArtifactRoot, req.CaseID, req.ArtifactIDs)
	if err != nil {
		return nil, err
	}
	if len(artifactIDs) == 0 {
		return nil, fmt.Errorf("%w: no verified derived artifacts available for case %s", ErrMissingPrerequisite, req.CaseID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrIndexStoreClosed
	}

	if s.cfg.Faults.SimulateDiskFull {
		return nil, ErrDiskFull
	}

	nextCaseMap := make(map[string]TimelineEntry)
	sealedSnapshots := make(map[string]sealedBlobSnapshot)
	totalSubmitted := 0
	deduplicated := 0

	for _, artifactID := range artifactIDs {
		if err := ctx.Err(); err != nil {
			return nil, classifyContextErr(err)
		}

		vr, err := artifactStore.VerifyStoredArtifact(ctx, sealStore, req.CaseID, artifactID, req.VerifyOptions)
		if err != nil || vr == nil || !vr.Verified {
			return nil, fmt.Errorf("%w: derived artifact %s/%s verification failed: %v", ErrMissingPrerequisite, req.CaseID, artifactID, err)
		}

		dm, err := artifactStore.GetManifest(req.CaseID, artifactID)
		if err != nil || dm == nil {
			return nil, fmt.Errorf("%w: derived manifest %s/%s unavailable: %v", ErrMissingPrerequisite, req.CaseID, artifactID, err)
		}

		payloadPath := filepath.Join(absArtifactRoot, filepath.FromSlash(dm.Output.RelPath))
		if err := checkWithinDir(absArtifactRoot, payloadPath); err != nil {
			return nil, err
		}
		gotSHA, gotSize, err := hashRegularFile(payloadPath)
		if err != nil {
			return nil, fmt.Errorf("%w: read derived payload: %v", ErrMalformedPayload, err)
		}
		if gotSHA != dm.Output.SHA256 || gotSize != dm.Output.SizeBytes {
			return nil, fmt.Errorf("%w: derived payload digest mismatch for %s/%s", ErrMalformedPayload, req.CaseID, artifactID)
		}
		rawPayload, err := os.ReadFile(payloadPath)
		if err != nil {
			return nil, err
		}
		var payload artifacts.DerivedPayload
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return nil, fmt.Errorf("%w: parse derived payload JSON: %v", ErrMalformedPayload, err)
		}
		if payload.CaseID != req.CaseID {
			return nil, fmt.Errorf("%w: derived payload case_id mismatch", ErrMalformedPayload)
		}
		if len(payload.Records) == 0 {
			return nil, fmt.Errorf("%w: derived payload %s/%s contains zero records", ErrMalformedPayload, req.CaseID, artifactID)
		}

		if err := snapshotSealedEvidence(ctx, sealStore, absSealRoot, req.CaseID, payload.EvidenceID, sealedSnapshots); err != nil {
			return nil, err
		}

		sortedHashes := normalizeUniqueStrings(dm.InputHashes)
		indexedAt := strings.TrimSpace(dm.CreatedAt)
		if indexedAt == "" {
			indexedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}

		for idx, rec := range payload.Records {
			if err := ctx.Err(); err != nil {
				return nil, classifyContextErr(err)
			}
			totalSubmitted++
			if totalSubmitted > maxRebuild {
				return nil, fmt.Errorf("%w: rebuild event count %d exceeds max_rebuild_events %d", ErrQueryLimitExceeded, totalSubmitted, maxRebuild)
			}

			rawTS := strings.TrimSpace(rec.Timestamp)
			if rawTS == "" && rec.Fields != nil {
				if tsVal, ok := rec.Fields["timestamp"].(string); ok {
					rawTS = tsVal
				}
			}
			evType, _ := rec.Fields["event_type"].(string)
			if evType == "" {
				evType, _ = rec.Fields["event"].(string)
			}
			summary, _ := rec.Fields["summary"].(string)

			nt, err := NormalizeTimestamp(NormalizeRequest{
				RawTimestamp:     rawTS,
				ZoneHint:         req.ZoneHint,
				SourceConfidence: req.SourceConfidence,
			})
			if err != nil {
				return nil, fmt.Errorf("artifact %s record[%d]: %w", artifactID, idx, err)
			}

			evID, err := ComputeEventIdentity(EventIdentityInput{
				CaseID:       req.CaseID,
				InputHashes:  sortedHashes,
				SourceLine:   rec.RowNumber,
				RawTimestamp: nt.RawTimestamp,
				EventType:    evType,
				Summary:      summary,
				Fields:       rec.Fields,
			})
			if err != nil {
				return nil, fmt.Errorf("artifact %s record[%d]: %w", artifactID, idx, err)
			}

			if prev, dup := nextCaseMap[evID]; dup {
				deduplicated++
				prev.ObservedArtifactIDs = normalizeUniqueStrings(append(prev.ObservedArtifactIDs, artifactID))
				nextCaseMap[evID] = prev
				continue
			}

			if len(nextCaseMap)+1 > s.maxEntries {
				return nil, fmt.Errorf("%w: rebuilt case %s exceeds max entries %d", ErrIndexQuotaExceeded, req.CaseID, s.maxEntries)
			}

			nextCaseMap[evID] = TimelineEntry{
				SchemaVersion:       SchemaVersion,
				EventIdentity:       evID,
				CaseID:              req.CaseID,
				EvidenceID:          payload.EvidenceID,
				InputHashes:         append([]string(nil), sortedHashes...),
				SourceLine:          rec.RowNumber,
				EventType:           evType,
				Summary:             summary,
				Time:                nt,
				Fields:              cloneMap(rec.Fields),
				ToolVersion:         dm.ToolVersion,
				ConfigHash:          dm.ConfigHash,
				ObservedArtifactIDs: []string{artifactID},
				FirstIndexedAt:      indexedAt,
			}
		}
	}

	sortedEntries := sortTimelineEntries(nextCaseMap)
	nextGen := s.manifest.Generation + 1
	caseDoc := caseIndexFile{
		SchemaVersion: SchemaVersion,
		CaseID:        req.CaseID,
		Generation:    nextGen,
		Entries:       sortedEntries,
	}
	caseBytes, err := json.MarshalIndent(caseDoc, "", "  ")
	if err != nil {
		return nil, err
	}
	caseBytes = append(caseBytes, '\n')
	if int64(len(caseBytes)) > s.maxStorage {
		return nil, fmt.Errorf("%w: rebuilt case index byte quota exceeded", ErrIndexQuotaExceeded)
	}

	tmpCasePath := filepath.Join(s.rootDir, stagingSubdir, fmt.Sprintf("rebuild-gen-%d-%s.case.tmp", nextGen, req.CaseID))
	if err := writeSyncFile(tmpCasePath, caseBytes, 0640); err != nil {
		return nil, err
	}
	if s.cfg.Faults.FailAfterStageBeforeCommit {
		return nil, ErrInterrupted
	}

	finalCasePath := filepath.Join(s.rootDir, casesIndexSubdir, req.CaseID+".index.json")
	if err := checkWithinDir(s.rootDir, finalCasePath); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpCasePath, finalCasePath); err != nil {
		return nil, fmt.Errorf("commit rebuilt case index %s: %w", req.CaseID, err)
	}
	if s.cfg.SyncDir {
		_ = syncDir(filepath.Dir(finalCasePath))
	}

	caseSum := sha256.Sum256(caseBytes)
	caseSHA := hex.EncodeToString(caseSum[:])

	nextManifest := s.manifest
	nextManifest.Generation = nextGen
	if nextManifest.Operations == nil {
		nextManifest.Operations = make(map[string]IndexOutcome)
	}
	nextCases := make(map[string]persistedCaseMeta, len(s.manifest.Cases)+1)
	for k, v := range s.manifest.Cases {
		nextCases[k] = v
	}
	nextCases[req.CaseID] = persistedCaseMeta{
		CaseID:     req.CaseID,
		FileSHA256: caseSHA,
		EntryCount: len(sortedEntries),
	}
	nextManifest.Cases = nextCases

	// Recompute total persisted case index bytes across active cases so rebuilds don't inflate quota usage.
	var totalCaseBytes int64
	for cid := range nextCases {
		p := filepath.Join(s.rootDir, casesIndexSubdir, cid+".index.json")
		if info, statErr := os.Stat(p); statErr == nil && info.Mode().IsRegular() {
			totalCaseBytes += info.Size()
		}
	}
	nextManifest.TotalBytes = totalCaseBytes

	if err := s.persistManifestUnlocked(nextManifest); err != nil {
		return nil, err
	}
	s.manifest = nextManifest
	s.entriesByCase[req.CaseID] = nextCaseMap

	for _, snap := range sealedSnapshots {
		postSHA, postSize, hErr := hashRegularFile(snap.path)
		if hErr != nil || postSHA != snap.sha || postSize != snap.size {
			return nil, ErrSealedBytesTampered
		}
	}

	return &RebuildOutcome{
		SchemaVersion:      SchemaVersion,
		CaseID:             req.CaseID,
		ArtifactIDs:        artifactIDs,
		ArtifactsProcessed: len(artifactIDs),
		TotalSubmitted:     totalSubmitted,
		RebuiltEntries:     len(sortedEntries),
		DeduplicatedCount:  deduplicated,
		Generation:         nextGen,
		CaseIndexSHA256:    caseSHA,
	}, nil
}

func validateSearchBounds(req SearchRequest) (searchBounds, error) {
	var b searchBounds
	if req.Offset < 0 {
		return b, fmt.Errorf("%w: offset %d cannot be negative", ErrInvalidInput, req.Offset)
	}
	b.maxResults = req.MaxResults
	if b.maxResults == 0 {
		b.maxResults = DefaultSearchMaxResults
	}
	if b.maxResults < 0 || b.maxResults > MaxSearchResultsCap {
		return b, fmt.Errorf("%w: max_results %d out of bounds [1, %d]", ErrQueryLimitExceeded, req.MaxResults, MaxSearchResultsCap)
	}
	b.maxScanEvents = req.MaxScanEvents
	if b.maxScanEvents == 0 {
		b.maxScanEvents = DefaultMaxScanEvents
	}
	if b.maxScanEvents < 0 || b.maxScanEvents > MaxScanEventsCap {
		return b, fmt.Errorf("%w: max_scan_events %d out of bounds [1, %d]", ErrQueryLimitExceeded, req.MaxScanEvents, MaxScanEventsCap)
	}
	if req.ExpandDepth < 0 || req.ExpandDepth > MaxExpandDepthCap {
		return b, fmt.Errorf("%w: expand_depth %d out of bounds [0, %d]", ErrQueryLimitExceeded, req.ExpandDepth, MaxExpandDepthCap)
	}
	b.expandDepth = req.ExpandDepth

	b.maxExpandDegree = req.MaxExpandDegree
	if b.maxExpandDegree == 0 {
		b.maxExpandDegree = DefaultMaxExpandDegree
	}
	if b.maxExpandDegree < 0 || b.maxExpandDegree > MaxExpandDegreeCap {
		return b, fmt.Errorf("%w: max_expand_degree %d out of bounds [1, %d]", ErrQueryLimitExceeded, req.MaxExpandDegree, MaxExpandDegreeCap)
	}

	b.maxVisitedNodes = req.MaxVisitedNodes
	if b.maxVisitedNodes == 0 {
		b.maxVisitedNodes = DefaultMaxVisitedNodes
	}
	if b.maxVisitedNodes < 0 || b.maxVisitedNodes > MaxVisitedNodesCap {
		return b, fmt.Errorf("%w: max_visited_nodes %d out of bounds [1, %d]", ErrQueryLimitExceeded, req.MaxVisitedNodes, MaxVisitedNodesCap)
	}

	if req.MinConfidence != nil && (*req.MinConfidence < 0 || *req.MinConfidence > 1) {
		return b, fmt.Errorf("%w: min_confidence %.4f must be within [0, 1]", ErrInvalidInput, *req.MinConfidence)
	}

	if strings.TrimSpace(req.StartTimeUTC) != "" {
		t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(req.StartTimeUTC))
		if err != nil {
			return b, fmt.Errorf("%w: invalid start_time_utc %q: %v", ErrInvalidInput, req.StartTimeUTC, err)
		}
		b.hasStart = true
		b.startUTC = t.UTC()
	}
	if strings.TrimSpace(req.EndTimeUTC) != "" {
		t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(req.EndTimeUTC))
		if err != nil {
			return b, fmt.Errorf("%w: invalid end_time_utc %q: %v", ErrInvalidInput, req.EndTimeUTC, err)
		}
		b.hasEnd = true
		b.endUTC = t.UTC()
	}
	if b.hasStart && b.hasEnd && b.startUTC.After(b.endUTC) {
		return b, fmt.Errorf("%w: start_time_utc %s is after end_time_utc %s", ErrInvalidInput, req.StartTimeUTC, req.EndTimeUTC)
	}

	if len(req.EventTypes) > 0 {
		b.typeSet = make(map[string]bool, len(req.EventTypes))
		for _, t := range req.EventTypes {
			b.typeSet[strings.TrimSpace(t)] = true
		}
	}
	if len(req.EvidenceIDs) > 0 {
		b.evidenceSet = make(map[string]bool, len(req.EvidenceIDs))
		for _, ev := range req.EvidenceIDs {
			b.evidenceSet[strings.TrimSpace(ev)] = true
		}
	}
	b.textNeedle = strings.ToLower(strings.TrimSpace(req.TextQuery))
	return b, nil
}

func entryMatchesSearch(entry TimelineEntry, req SearchRequest, b searchBounds) bool {
	if len(b.typeSet) > 0 && !b.typeSet[entry.EventType] {
		return false
	}
	if len(b.evidenceSet) > 0 && !b.evidenceSet[entry.EvidenceID] {
		return false
	}
	if req.MinConfidence != nil && entry.Time.Confidence < *req.MinConfidence {
		return false
	}
	if b.hasStart || b.hasEnd {
		t, ok := parseUTC(entry.Time.NormalizedTimestamp)
		if !ok {
			if !req.IncludeUnresolvedTime {
				return false
			}
		} else {
			if b.hasStart && t.Before(b.startUTC) {
				return false
			}
			if b.hasEnd && t.After(b.endUTC) {
				return false
			}
		}
	}
	if b.textNeedle != "" && !entryContainsText(entry, b.textNeedle) {
		return false
	}
	return true
}

func entryContainsText(entry TimelineEntry, needle string) bool {
	candidates := []string{
		entry.EventIdentity,
		entry.EvidenceID,
		entry.EventType,
		entry.Summary,
		entry.Time.RawTimestamp,
		entry.Time.NormalizedTimestamp,
	}
	for _, s := range candidates {
		if strings.Contains(strings.ToLower(s), needle) {
			return true
		}
	}
	return valueContainsText(entry.Fields, needle)
}

func valueContainsText(v any, needle string) bool {
	switch typed := v.(type) {
	case nil:
		return false
	case string:
		return strings.Contains(strings.ToLower(typed), needle)
	case bool:
		return strings.Contains(strconv.FormatBool(typed), needle)
	case float64:
		return strings.Contains(strconv.FormatFloat(typed, 'f', -1, 64), needle)
	case int:
		return strings.Contains(strconv.Itoa(typed), needle)
	case []string:
		for _, item := range typed {
			if strings.Contains(strings.ToLower(item), needle) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if valueContainsText(item, needle) {
				return true
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for k := range typed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.Contains(strings.ToLower(k), needle) || valueContainsText(typed[k], needle) {
				return true
			}
		}
	}
	return false
}

type expandQueueItem struct {
	identity string
	depth    int
}

type neighborRef struct {
	targetRef string
	relation  string
}

func expandBoundedRelated(ctx context.Context, sorted []TimelineEntry, b searchBounds, res *SearchResult) error {
	byID := make(map[string]TimelineEntry, len(sorted))
	byNodeID := make(map[string]TimelineEntry)
	for _, e := range sorted {
		byID[e.EventIdentity] = e
		if e.Fields != nil {
			if nid, ok := e.Fields["node_id"].(string); ok && strings.TrimSpace(nid) != "" {
				// Keep first deterministic entry if node_id collides across distinct entries.
				if _, exists := byNodeID[nid]; !exists {
					byNodeID[nid] = e
				}
			}
		}
	}

	visited := make(map[string]bool, len(res.Entries))
	relatedIncluded := make(map[string]bool, len(res.Entries))
	queue := make([]expandQueueItem, 0, len(res.Entries))
	for _, seed := range res.Entries {
		if len(visited) >= b.maxVisitedNodes {
			markTruncated(res, TruncationMaxVisitedNodes)
			break
		}
		if !visited[seed.EventIdentity] {
			visited[seed.EventIdentity] = true
			relatedIncluded[seed.EventIdentity] = true
			queue = append(queue, expandQueueItem{identity: seed.EventIdentity, depth: 0})
		}
	}

	for len(queue) > 0 {
		if err := checkSearchContext(ctx, res); err != nil {
			res.VisitedCount = len(visited)
			return err
		}
		curr := queue[0]
		queue = queue[1:]
		if curr.depth >= b.expandDepth {
			continue
		}

		entry, ok := byID[curr.identity]
		if !ok {
			continue
		}
		refs := extractNeighborRefs(entry.Fields)
		if len(refs) > b.maxExpandDegree {
			markTruncated(res, TruncationMaxDegree)
			refs = refs[:b.maxExpandDegree]
		}

		for _, ref := range refs {
			if err := checkSearchContext(ctx, res); err != nil {
				res.VisitedCount = len(visited)
				return err
			}
			target, resolved := byID[ref.targetRef]
			if !resolved {
				target, resolved = byNodeID[ref.targetRef]
			}
			if !resolved {
				continue
			}

			res.RelatedEdges = append(res.RelatedEdges, RelatedEventEdge{
				FromIdentity: curr.identity,
				ToIdentity:   target.EventIdentity,
				Relation:     ref.relation,
				Depth:        curr.depth + 1,
			})

			if visited[target.EventIdentity] {
				res.CycleDetected = true
				markTruncated(res, TruncationCycleDetected)
				continue
			}
			if len(visited) >= b.maxVisitedNodes {
				markTruncated(res, TruncationMaxVisitedNodes)
				res.VisitedCount = len(visited)
				return nil
			}
			visited[target.EventIdentity] = true
			if !relatedIncluded[target.EventIdentity] {
				relatedIncluded[target.EventIdentity] = true
				res.RelatedEntries = append(res.RelatedEntries, cloneEntry(target))
			}
			queue = append(queue, expandQueueItem{
				identity: target.EventIdentity,
				depth:    curr.depth + 1,
			})
		}
	}

	res.VisitedCount = len(visited)
	return nil
}

func extractNeighborRefs(fields map[string]any) []neighborRef {
	if fields == nil {
		return nil
	}
	var refs []neighborRef
	if parent, ok := fields["parent_event_id"].(string); ok && strings.TrimSpace(parent) != "" {
		refs = append(refs, neighborRef{targetRef: strings.TrimSpace(parent), relation: "parent"})
	}
	switch raw := fields["related_event_ids"].(type) {
	case []string:
		sorted := normalizeUniqueStrings(raw)
		for _, id := range sorted {
			if strings.TrimSpace(id) != "" {
				refs = append(refs, neighborRef{targetRef: strings.TrimSpace(id), relation: "related"})
			}
		}
	case []any:
		items := make([]string, 0, len(raw))
		for _, elem := range raw {
			if s, ok := elem.(string); ok && strings.TrimSpace(s) != "" {
				items = append(items, strings.TrimSpace(s))
			}
		}
		for _, id := range normalizeUniqueStrings(items) {
			refs = append(refs, neighborRef{targetRef: id, relation: "related"})
		}
	}
	return refs
}

func checkSearchContext(ctx context.Context, res *SearchResult) error {
	err := ctx.Err()
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		res.Status = SearchStatusDeadlineExceeded
		res.Truncated = true
		res.TruncationReason = TruncationDeadline
		return classifyContextErr(err)
	}
	res.Status = SearchStatusCanceled
	res.Truncated = true
	res.TruncationReason = TruncationCanceled
	return classifyContextErr(err)
}

func classifyContextErr(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrQueryDeadlineExceeded, err)
	}
	return fmt.Errorf("%w: %w", ErrQueryCanceled, err)
}

func markTruncated(res *SearchResult, reason string) {
	if res.Status == SearchStatusDeadlineExceeded || res.Status == SearchStatusCanceled {
		return
	}
	res.Status = SearchStatusTruncated
	res.Truncated = true
	if res.TruncationReason == "" {
		res.TruncationReason = reason
	}
}

type digestEntry struct {
	EventIdentity       string         `json:"event_identity"`
	CaseID              string         `json:"case_id"`
	EvidenceID          string         `json:"evidence_id"`
	InputHashes         []string       `json:"input_hashes"`
	SourceLine          int            `json:"source_line"`
	EventType           string         `json:"event_type,omitempty"`
	Summary             string         `json:"summary,omitempty"`
	Time                NormalizedTime `json:"time"`
	Fields              any            `json:"fields,omitempty"`
	ToolVersion         string         `json:"tool_version"`
	ConfigHash          string         `json:"config_hash"`
	ObservedArtifactIDs []string       `json:"observed_artifact_ids"`
}

func toDigestEntries(in []TimelineEntry) []digestEntry {
	out := make([]digestEntry, 0, len(in))
	for _, e := range in {
		out = append(out, digestEntry{
			EventIdentity:       e.EventIdentity,
			CaseID:              e.CaseID,
			EvidenceID:          e.EvidenceID,
			InputHashes:         normalizeUniqueStrings(e.InputHashes),
			SourceLine:          e.SourceLine,
			EventType:           e.EventType,
			Summary:             e.Summary,
			Time:                e.Time,
			Fields:              canonicalizeValue(e.Fields),
			ToolVersion:         e.ToolVersion,
			ConfigHash:          e.ConfigHash,
			ObservedArtifactIDs: normalizeUniqueStrings(e.ObservedArtifactIDs),
		})
	}
	return out
}

func finalizeSearchDigest(res *SearchResult) {
	payload := struct {
		SchemaVersion    string             `json:"schema_version"`
		CaseID           string             `json:"case_id"`
		Status           string             `json:"status"`
		Truncated        bool               `json:"truncated"`
		TruncationReason string             `json:"truncation_reason,omitempty"`
		CycleDetected    bool               `json:"cycle_detected,omitempty"`
		ScannedCount     int                `json:"scanned_count"`
		MatchedCount     int                `json:"matched_count"`
		VisitedCount     int                `json:"visited_count,omitempty"`
		ReturnedCount    int                `json:"returned_count"`
		HasMore          bool               `json:"has_more"`
		NextOffset       int                `json:"next_offset,omitempty"`
		Entries          []digestEntry      `json:"entries"`
		RelatedEntries   []digestEntry      `json:"related_entries,omitempty"`
		RelatedEdges     []RelatedEventEdge `json:"related_edges,omitempty"`
	}{
		SchemaVersion:    res.SchemaVersion,
		CaseID:           res.CaseID,
		Status:           res.Status,
		Truncated:        res.Truncated,
		TruncationReason: res.TruncationReason,
		CycleDetected:    res.CycleDetected,
		ScannedCount:     res.ScannedCount,
		MatchedCount:     res.MatchedCount,
		VisitedCount:     res.VisitedCount,
		ReturnedCount:    res.ReturnedCount,
		HasMore:          res.HasMore,
		NextOffset:       res.NextOffset,
		Entries:          toDigestEntries(res.Entries),
		RelatedEntries:   toDigestEntries(res.RelatedEntries),
		RelatedEdges:     res.RelatedEdges,
	}
	raw, _ := json.Marshal(payload)
	prefixed := append([]byte("breachatlas:search-result:v1:"), raw...)
	sum := sha256.Sum256(prefixed)
	res.ResultDigest = hex.EncodeToString(sum[:])
}

func resolveCaseArtifactIDs(absArtifactRoot, caseID string, explicit []string) ([]string, error) {
	if len(explicit) > 0 {
		cleaned := make([]string, 0, len(explicit))
		for _, id := range explicit {
			if err := validateIdentifier("artifact_id", id); err != nil {
				return nil, err
			}
			cleaned = append(cleaned, id)
		}
		return normalizeUniqueStrings(cleaned), nil
	}

	caseArtifactsDir := filepath.Join(absArtifactRoot, "artifacts", caseID)
	if err := checkWithinDir(absArtifactRoot, caseArtifactsDir); err != nil {
		return nil, err
	}
	if _, err := ensureNoSymlink(caseArtifactsDir); err != nil {
		return nil, err
	}
	dirEntries, err := os.ReadDir(caseArtifactsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: artifact directory for case %s not found", ErrMissingPrerequisite, caseID)
		}
		return nil, fmt.Errorf("list case artifacts for %s: %w", caseID, err)
	}
	var ids []string
	for _, de := range dirEntries {
		if !de.IsDir() {
			continue
		}
		if err := validateIdentifier("artifact_id", de.Name()); err != nil {
			continue
		}
		ids = append(ids, de.Name())
	}
	sort.Strings(ids)
	return ids, nil
}

func snapshotSealedEvidence(
	ctx context.Context,
	sealStore *evidence.SealStore,
	absSealRoot, caseID, evidenceID string,
	snaps map[string]sealedBlobSnapshot,
) error {
	key := caseID + "/" + evidenceID
	if _, already := snaps[key]; already {
		return nil
	}
	if err := validateIdentifier("evidence_id", evidenceID); err != nil {
		return err
	}
	vr, vErr := evidence.VerifyStoreEvidence(ctx, sealStore, caseID, evidenceID, evidence.VerifyOptions{})
	if vErr != nil || vr == nil || !vr.Verified {
		return fmt.Errorf("%w: sealed evidence %s failed verification: %v", ErrMissingPrerequisite, key, vErr)
	}
	sm, sErr := sealStore.GetSealedManifest(caseID, evidenceID)
	if sErr != nil || sm == nil || !sm.Sealed {
		return fmt.Errorf("%w: sealed manifest %s unavailable", ErrMissingPrerequisite, key)
	}
	blobPath := filepath.Join(absSealRoot, filepath.FromSlash(sm.BlobRelPath))
	if err := checkWithinDir(absSealRoot, blobPath); err != nil {
		return err
	}
	preSHA, preSize, err := hashRegularFile(blobPath)
	if err != nil || preSHA != sm.SHA256 || preSize != sm.SizeBytes {
		return ErrSealedBytesTampered
	}
	snaps[key] = sealedBlobSnapshot{
		path: blobPath,
		sha:  preSHA,
		size: preSize,
	}
	return nil
}

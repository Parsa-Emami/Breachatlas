package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/analyzers"
	"github.com/Parsa-Emami/Breachatlas/internal/artifacts"
	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
	"github.com/Parsa-Emami/Breachatlas/internal/export"
	"github.com/Parsa-Emami/Breachatlas/internal/findings"
	"github.com/Parsa-Emami/Breachatlas/internal/holds"
	"github.com/Parsa-Emami/Breachatlas/internal/recovery"
	"github.com/Parsa-Emami/Breachatlas/internal/retention"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

const (
	workflowKeyIDCheckpoint = "ed25519-local-chk-1"
	workflowKeyIDArtifact   = "ed25519-local-art-1"
	workflowKeyIDBundle     = "ed25519-local-bnd-1"
	maxWorkflowRequestBytes = 256 * 1024
)

var workflowAllowedProviders = map[string]bool{
	"":            true,
	"local":       true,
	"breachatlas": true,
	"csv":         true,
	"json":        true,
}

type persistedKeySet struct {
	SchemaVersion string `json:"schema_version"`
	CheckpointKey string `json:"checkpoint_priv_hex"`
	ArtifactKey   string `json:"artifact_priv_hex"`
	BundleKey     string `json:"bundle_priv_hex"`
}

type workflowKeys struct {
	chkPriv ed25519.PrivateKey
	chkPub  ed25519.PublicKey
	artPriv ed25519.PrivateKey
	artPub  ed25519.PublicKey
	bndPriv ed25519.PrivateKey
	bndPub  ed25519.PublicKey
}

type workflowWorkspace struct {
	root            string
	qDir            string
	sDir            string
	custDir         string
	chkDir          string
	scDir           string
	aDir            string
	idxDir          string
	findDir         string
	expDir          string
	holdsDir        string
	retDir          string
	recDir          string
	keys            workflowKeys
	sealStore       *evidence.SealStore
	ledgerStore     *custody.LedgerStore
	checkpointStore *custody.FileCheckpointStore
	registry        *analyzers.Registry
	sandbox         *analyzers.Sandbox
	artifactStore   *artifacts.ArtifactStore
	indexStore      *timeline.EventIndexStore
	findingStore    *findings.FindingStore
	exportStore     *export.ExportStore
	holdService     *holds.Service
	retStore        *retention.RetentionStore
	restoreStore    *recovery.RestoreStore
}

type workflowController struct {
	mu           sync.Mutex
	opts         EngineRuntimeOptions
	ephemeralDir string
	ws           *workflowWorkspace
	logger       *DiagnosticLogger
	closed       bool
}

func newWorkflowController(opts EngineRuntimeOptions, logger *DiagnosticLogger) *workflowController {
	return &workflowController{
		opts:   opts,
		logger: logger,
	}
}

func (c *workflowController) log(level, code, msg string) {
	if c.logger != nil {
		c.logger.Record(level, "workflow", code, msg)
	}
}

func (c *workflowController) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.ws != nil {
		c.ws.close()
		c.ws = nil
	}
}

func (c *workflowController) ensureWorkspaceLocked() (*workflowWorkspace, *evidence.Problem, int) {
	if c.closed {
		return nil, &evidence.Problem{Code: "engine_unavailable"}, http.StatusServiceUnavailable
	}
	if strings.TrimSpace(c.opts.StorageRoot) != "" {
		probe := probeStorageReadiness(c.opts.StorageRoot, c.opts.RequireStorageDir)
		if !probe.Ready {
			c.log("error", "storage_unavailable", "Authoritative local storage root failed readiness probe")
			return nil, &evidence.Problem{Code: "storage_unavailable"}, http.StatusServiceUnavailable
		}
	}
	if c.ws != nil {
		return c.ws, nil, http.StatusOK
	}

	var baseRoot string
	if strings.TrimSpace(c.opts.StorageRoot) != "" {
		baseRoot = filepath.Join(c.opts.StorageRoot, "workflow-data")
	} else {
		if c.ephemeralDir == "" {
			tmp, err := os.MkdirTemp("", "breachatlas-workflow-*")
			if err != nil {
				return nil, &evidence.Problem{Code: "storage_unavailable"}, http.StatusServiceUnavailable
			}
			c.ephemeralDir = tmp
		}
		baseRoot = c.ephemeralDir
	}

	ws, err := openWorkflowWorkspace(baseRoot)
	if err != nil {
		c.log("error", "workspace_open_failed", err.Error())
		return nil, &evidence.Problem{Code: "storage_unavailable"}, http.StatusServiceUnavailable
	}
	c.ws = ws
	return ws, nil, http.StatusOK
}

func loadOrCreateKeySet(keysDir string) (workflowKeys, error) {
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return workflowKeys{}, err
	}
	path := filepath.Join(keysDir, "local-keys.json")
	var persisted persistedKeySet
	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, &persisted); err != nil {
			return workflowKeys{}, err
		}
		return decodeKeySet(persisted)
	} else if !os.IsNotExist(err) {
		return workflowKeys{}, err
	}

	_, chkPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return workflowKeys{}, err
	}
	_, artPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return workflowKeys{}, err
	}
	_, bndPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return workflowKeys{}, err
	}
	persisted = persistedKeySet{
		SchemaVersion: "1",
		CheckpointKey: hex.EncodeToString(chkPriv),
		ArtifactKey:   hex.EncodeToString(artPriv),
		BundleKey:     hex.EncodeToString(bndPriv),
	}
	data, err := json.Marshal(persisted)
	if err != nil {
		return workflowKeys{}, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return workflowKeys{}, err
	}
	return decodeKeySet(persisted)
}

func decodeKeySet(p persistedKeySet) (workflowKeys, error) {
	dec := func(hexStr string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
		raw, err := hex.DecodeString(strings.TrimSpace(hexStr))
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, nil, errors.New("corrupted persisted key")
		}
		priv := ed25519.PrivateKey(raw)
		pub := priv.Public().(ed25519.PublicKey)
		return priv, pub, nil
	}
	chkPriv, chkPub, err := dec(p.CheckpointKey)
	if err != nil {
		return workflowKeys{}, err
	}
	artPriv, artPub, err := dec(p.ArtifactKey)
	if err != nil {
		return workflowKeys{}, err
	}
	bndPriv, bndPub, err := dec(p.BundleKey)
	if err != nil {
		return workflowKeys{}, err
	}
	return workflowKeys{
		chkPriv: chkPriv, chkPub: chkPub,
		artPriv: artPriv, artPub: artPub,
		bndPriv: bndPriv, bndPub: bndPub,
	}, nil
}

func openWorkflowWorkspace(root string) (*workflowWorkspace, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	keys, err := loadOrCreateKeySet(filepath.Join(root, "keys"))
	if err != nil {
		return nil, err
	}
	ws := &workflowWorkspace{
		root:     root,
		qDir:     filepath.Join(root, "quarantine"),
		sDir:     filepath.Join(root, "sealstore"),
		custDir:  filepath.Join(root, "custody"),
		chkDir:   filepath.Join(root, "checkpoints"),
		scDir:    filepath.Join(root, "scratch"),
		aDir:     filepath.Join(root, "artifacts"),
		idxDir:   filepath.Join(root, "timeline-index"),
		findDir:  filepath.Join(root, "findings"),
		expDir:   filepath.Join(root, "exports"),
		holdsDir: filepath.Join(root, "holds"),
		retDir:   filepath.Join(root, "retention"),
		recDir:   filepath.Join(root, "recovery"),
		keys:     keys,
	}

	cleanupOnErr := true
	defer func() {
		if cleanupOnErr {
			ws.close()
		}
	}()

	if ws.sealStore, err = evidence.OpenSealStore(evidence.SealConfig{RootDir: ws.sDir, QuarantineDir: ws.qDir, SyncDir: true}); err != nil {
		return nil, err
	}
	if ws.ledgerStore, err = custody.OpenLedgerStore(custody.LedgerConfig{RootDir: ws.custDir, SyncDir: true}); err != nil {
		return nil, err
	}
	if ws.checkpointStore, err = custody.OpenFileCheckpointStore(custody.FileCheckpointStoreConfig{RootDir: ws.chkDir, SyncDir: true}); err != nil {
		return nil, err
	}
	if ws.registry, err = analyzers.NewRegistry(analyzers.RegistryConfig{SealStore: ws.sealStore, SealRootDir: ws.sDir, Provider: "local"}); err != nil {
		return nil, err
	}
	if ws.sandbox, err = analyzers.NewSandbox(ws.registry, analyzers.DefaultSandboxConfig(ws.scDir)); err != nil {
		return nil, err
	}
	if ws.artifactStore, err = artifacts.OpenArtifactStore(artifacts.StoreConfig{RootDir: ws.aDir, SyncDir: true}); err != nil {
		return nil, err
	}
	if ws.indexStore, err = timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: ws.idxDir, SyncDir: true}); err != nil {
		return nil, err
	}
	if ws.findingStore, err = findings.OpenFindingStore(findings.FindingStoreConfig{RootDir: ws.findDir, SyncDir: true}); err != nil {
		return nil, err
	}
	if ws.exportStore, err = export.OpenExportStore(export.ExportStoreConfig{RootDir: ws.expDir, SyncDir: true}); err != nil {
		return nil, err
	}
	if ws.holdService, err = holds.OpenService(holds.ServiceConfig{
		RootDir:   ws.holdsDir,
		SealStore: ws.sealStore,
		Ledger:    ws.ledgerStore,
		SyncDir:   true,
	}); err != nil {
		return nil, err
	}
	if ws.retStore, err = retention.OpenRetentionStore(retention.RetentionConfig{
		RootDir:     ws.retDir,
		SealStore:   ws.sealStore,
		HoldService: ws.holdService,
		LedgerStore: ws.ledgerStore,
		SyncDir:     true,
	}); err != nil {
		return nil, err
	}
	if ws.restoreStore, err = recovery.OpenRestoreStore(recovery.RestoreConfig{RootDir: ws.recDir, SyncDir: true}); err != nil {
		return nil, err
	}

	cleanupOnErr = false
	return ws, nil
}

func (ws *workflowWorkspace) close() {
	if ws.restoreStore != nil {
		_ = ws.restoreStore.Close()
	}
	if ws.retStore != nil {
		_ = ws.retStore.Close()
	}
	if ws.holdService != nil {
		_ = ws.holdService.Close()
	}
	if ws.exportStore != nil {
		_ = ws.exportStore.Close()
	}
	if ws.findingStore != nil {
		_ = ws.findingStore.Close()
	}
	if ws.indexStore != nil {
		_ = ws.indexStore.Close()
	}
	if ws.artifactStore != nil {
		_ = ws.artifactStore.Close()
	}
	if ws.checkpointStore != nil {
		_ = ws.checkpointStore.Close()
	}
	if ws.ledgerStore != nil {
		_ = ws.ledgerStore.Close()
	}
	if ws.sealStore != nil {
		_ = ws.sealStore.Close()
	}
}

func (ws *workflowWorkspace) targetStores() recovery.TargetStores {
	return recovery.TargetStores{
		SealStore:       ws.sealStore,
		SealRootDir:     ws.sDir,
		QuarantineDir:   ws.qDir,
		LedgerStore:     ws.ledgerStore,
		LedgerRootDir:   ws.custDir,
		CheckpointStore: ws.checkpointStore,
		ArtifactStore:   ws.artifactStore,
		ArtifactRootDir: ws.aDir,
		IndexStore:      ws.indexStore,
		IndexRootDir:    ws.idxDir,
		HoldService:     ws.holdService,
		RetentionStore:  ws.retStore,
	}
}

func (ws *workflowWorkspace) saveLatestCheckpoint(ctx context.Context, caseID, evidenceID string) (*custody.Checkpoint, error) {
	events, err := ws.ledgerStore.ListEvents(caseID, evidenceID)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, errors.New("custody chain has no events")
	}
	last := events[len(events)-1]
	existing, _ := ws.checkpointStore.GetLatestCheckpoint(ctx, caseID, evidenceID)
	rev := uint64(1)
	if existing != nil {
		rev = existing.Revision + 1
	}
	chk, err := custody.CreateCheckpoint(ctx, ws.ledgerStore, custody.CreateCheckpointRequest{
		CheckpointID: fmt.Sprintf("chk-%s-%02d", evidenceID, rev),
		CaseID:       caseID,
		EvidenceID:   evidenceID,
		Sequence:     last.Sequence,
		CustodyRoot:  last.CustodyRoot,
		KeyID:        workflowKeyIDCheckpoint,
		Revision:     rev,
		IssuedAt:     time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		PrivateKey:   ws.keys.chkPriv,
	})
	if err != nil {
		return nil, err
	}
	if err := ws.checkpointStore.SaveCheckpoint(ctx, *chk); err != nil {
		return nil, err
	}
	return chk, nil
}

func validateWorkflowProvider(provider string) bool {
	return workflowAllowedProviders[strings.TrimSpace(provider)]
}

func writeWorkflowJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func registerWorkflowRoutes(mux *http.ServeMux, opts EngineRuntimeOptions, logger *DiagnosticLogger) func() {
	ctrl := newWorkflowController(opts, logger)

	mux.HandleFunc("/api/v1/workflow/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeEngineProblem(w, http.StatusMethodNotAllowed, evidence.Problem{Code: "method_not_allowed"})
			return
		}
		caseID := strings.TrimSpace(r.URL.Query().Get("case_id"))
		provider := strings.TrimSpace(r.URL.Query().Get("provider"))
		if !validateWorkflowProvider(provider) {
			writeEngineProblem(w, http.StatusServiceUnavailable, evidence.Problem{Code: "unavailable_provider", Field: "provider"})
			return
		}
		if !inspectIdentRegex.MatchString(caseID) {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field", Field: "case_id"})
			return
		}

		ctrl.mu.Lock()
		defer ctrl.mu.Unlock()
		ws, prob, code := ctrl.ensureWorkspaceLocked()
		if prob != nil {
			writeEngineProblem(w, code, *prob)
			return
		}
		writeWorkflowJSON(w, http.StatusOK, buildWorkflowStateSnapshot(r.Context(), ws, caseID))
	})

	mux.HandleFunc("/api/v1/workflow/upload-seal", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SchemaVersion string `json:"schema_version"`
			CaseID        string `json:"case_id"`
			EvidenceID    string `json:"evidence_id"`
			Filename      string `json:"filename"`
			MediaType     string `json:"media_type"`
			Payload       string `json:"payload"`
			AcquiredAt    string `json:"acquired_at"`
			Actor         string `json:"actor,omitempty"`
			Provider      string `json:"provider,omitempty"`
		}
		if !decodeEngineJSON(w, r, maxWorkflowRequestBytes, &req) {
			return
		}
		if req.SchemaVersion != evidence.SchemaVersion {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "unsupported_version", Field: "schema_version"})
			return
		}
		if !validateWorkflowProvider(req.Provider) {
			writeEngineProblem(w, http.StatusServiceUnavailable, evidence.Problem{Code: "unavailable_provider", Field: "provider"})
			return
		}
		if !inspectIdentRegex.MatchString(req.CaseID) {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field", Field: "case_id"})
			return
		}
		if !inspectIdentRegex.MatchString(req.EvidenceID) {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field", Field: "evidence_id"})
			return
		}
		if len(req.Payload) == 0 {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field", Field: "payload"})
			return
		}
		acquiredAt := strings.TrimSpace(req.AcquiredAt)
		if acquiredAt == "" {
			acquiredAt = time.Now().UTC().Format(time.RFC3339)
		}
		if _, err := time.Parse(time.RFC3339, acquiredAt); err != nil {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field", Field: "acquired_at"})
			return
		}
		actor := strings.TrimSpace(req.Actor)
		if actor == "" {
			actor = "analyst-local"
		}
		filename := strings.TrimSpace(req.Filename)
		if filename == "" {
			filename = req.EvidenceID + ".jsonl"
		}
		mediaType := strings.TrimSpace(req.MediaType)
		if mediaType == "" {
			mediaType = "application/x-ndjson"
		}

		ctrl.mu.Lock()
		defer ctrl.mu.Unlock()
		ws, prob, code := ctrl.ensureWorkspaceLocked()
		if prob != nil {
			writeEngineProblem(w, code, *prob)
			return
		}

		raw := []byte(req.Payload)
		sum := sha256.Sum256(raw)
		shaHex := hex.EncodeToString(sum[:])
		sz := int64(len(raw))

		// Idempotent return if already sealed with identical SHA-256
		if existing, err := ws.sealStore.GetSealedManifest(req.CaseID, req.EvidenceID); err == nil && existing != nil {
			if existing.SHA256 != shaHex {
				writeEngineProblem(w, http.StatusConflict, evidence.Problem{Code: "sealed_bytes_immutable"})
				return
			}
			writeWorkflowJSON(w, http.StatusOK, map[string]any{
				"schema_version":      "1",
				"status":              "sealed",
				"case_id":             existing.CaseID,
				"evidence_id":         existing.EvidenceID,
				"sha256":              existing.SHA256,
				"size_bytes":          existing.SizeBytes,
				"media_type":          existing.MediaType,
				"acquired_at":         existing.AcquiredAt,
				"custody_root":        existing.CustodyRoot,
				"verification_status": "verified",
				"idempotent_replay":   true,
			})
			return
		}

		q, err := evidence.StreamIntoQuarantine(r.Context(), evidence.UploadConfig{
			QuarantineDir: ws.qDir,
			BufferSize:    1024,
			SyncDir:       true,
		}, evidence.UploadRequest{
			SchemaVersion: "1",
			UploadID:      fmt.Sprintf("upl-%s-%s", req.CaseID, req.EvidenceID),
			CaseID:        req.CaseID,
			EvidenceID:    req.EvidenceID,
			MediaType:     mediaType,
			Filename:      filename,
			ExpectedSize:  &sz,
			ExpectedSHA256: shaHex,
			Body:          strings.NewReader(req.Payload),
		})
		if err != nil {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "upload_failed"})
			return
		}

		events, _ := ws.ledgerStore.ListEvents(req.CaseID, req.EvidenceID)
		if len(events) == 0 {
			if _, err := ws.ledgerStore.AppendEvent(r.Context(), custody.AppendEventRequest{
				EventID:    fmt.Sprintf("cust-intake-%s", req.EvidenceID),
				CaseID:     req.CaseID,
				EvidenceID: req.EvidenceID,
				EventType:  "intake_seal",
				Actor:      actor,
				Timestamp:  acquiredAt,
				Reason:     "Initial intake and quarantine SHA-256 verification",
				Provider:   "local",
			}); err != nil {
				writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "custody_error"})
				return
			}
		}
		curRoot, err := ws.ledgerStore.CurrentRoot(req.CaseID, req.EvidenceID)
		if err != nil {
			writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "custody_error"})
			return
		}

		sm, err := ws.sealStore.SealQuarantined(r.Context(), evidence.SealRequest{
			OperationID:    fmt.Sprintf("seal-%s-%s", req.CaseID, req.EvidenceID),
			Quarantined:    q,
			ExpectedSHA256: shaHex,
			AcquiredAt:     acquiredAt,
			CustodyRoot:    curRoot,
		})
		if err != nil {
			writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "seal_failed"})
			return
		}
		if _, err := ws.saveLatestCheckpoint(r.Context(), req.CaseID, req.EvidenceID); err != nil {
			writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "checkpoint_failed"})
			return
		}
		vRes, err := evidence.VerifyStoreEvidence(r.Context(), ws.sealStore, req.CaseID, req.EvidenceID, evidence.VerifyOptions{})
		if err != nil || !vRes.Verified {
			writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "verification_failed"})
			return
		}
		ctrl.log("info", "upload_sealed", fmt.Sprintf("Sealed %s/%s (%d bytes)", req.CaseID, req.EvidenceID, sm.SizeBytes))
		writeWorkflowJSON(w, http.StatusOK, map[string]any{
			"schema_version":      "1",
			"status":              "sealed",
			"case_id":             sm.CaseID,
			"evidence_id":         sm.EvidenceID,
			"sha256":              sm.SHA256,
			"size_bytes":          sm.SizeBytes,
			"media_type":          sm.MediaType,
			"acquired_at":         sm.AcquiredAt,
			"custody_root":        sm.CustodyRoot,
			"verification_status": "verified",
		})
	})

	mux.HandleFunc("/api/v1/workflow/custody", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SchemaVersion string `json:"schema_version"`
			CaseID        string `json:"case_id"`
			EvidenceID    string `json:"evidence_id"`
			EventID       string `json:"event_id"`
			EventType     string `json:"event_type"`
			Actor         string `json:"actor"`
			Timestamp     string `json:"timestamp"`
			Reason        string `json:"reason"`
			FromCustodian string `json:"from_custodian,omitempty"`
			ToCustodian   string `json:"to_custodian,omitempty"`
			Provider      string `json:"provider,omitempty"`
		}
		if !decodeEngineJSON(w, r, maxWorkflowRequestBytes, &req) {
			return
		}
		if req.SchemaVersion != evidence.SchemaVersion {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "unsupported_version", Field: "schema_version"})
			return
		}
		if !validateWorkflowProvider(req.Provider) {
			writeEngineProblem(w, http.StatusServiceUnavailable, evidence.Problem{Code: "unavailable_provider", Field: "provider"})
			return
		}
		if !inspectIdentRegex.MatchString(req.CaseID) || !inspectIdentRegex.MatchString(req.EvidenceID) {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field"})
			return
		}
		ctrl.mu.Lock()
		defer ctrl.mu.Unlock()
		ws, prob, code := ctrl.ensureWorkspaceLocked()
		if prob != nil {
			writeEngineProblem(w, code, *prob)
			return
		}
		if _, err := ws.sealStore.GetSealedManifest(req.CaseID, req.EvidenceID); err != nil {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "missing_evidence"})
			return
		}
		evID := strings.TrimSpace(req.EventID)
		if evID == "" {
			evID = fmt.Sprintf("cust-%d", time.Now().UnixNano())
		}
		evType := strings.TrimSpace(req.EventType)
		if evType == "" {
			evType = "custody_transfer"
		}
		ts := strings.TrimSpace(req.Timestamp)
		if ts == "" {
			ts = time.Now().UTC().Format(time.RFC3339)
		}
		ev, err := ws.ledgerStore.AppendEvent(r.Context(), custody.AppendEventRequest{
			EventID:       evID,
			CaseID:        req.CaseID,
			EvidenceID:    req.EvidenceID,
			EventType:     evType,
			Actor:         req.Actor,
			Timestamp:     ts,
			Reason:        req.Reason,
			FromCustodian: req.FromCustodian,
			ToCustodian:   req.ToCustodian,
			Provider:      "local",
		})
		if err != nil {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "custody_error"})
			return
		}
		chk, err := ws.saveLatestCheckpoint(r.Context(), req.CaseID, req.EvidenceID)
		if err != nil {
			writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "checkpoint_failed"})
			return
		}
		valid, err := ws.ledgerStore.VerifyChain(req.CaseID, req.EvidenceID)
		if err != nil || !valid {
			writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "custody_chain_invalid"})
			return
		}
		ctrl.log("info", "custody_updated", fmt.Sprintf("Appended custody seq %d for %s/%s", ev.Sequence, req.CaseID, req.EvidenceID))
		writeWorkflowJSON(w, http.StatusOK, map[string]any{
			"schema_version":        "1",
			"status":                "custody_updated",
			"event":                 ev,
			"custody_root":          ev.CustodyRoot,
			"sequence":              ev.Sequence,
			"chain_valid":           true,
			"checkpoint_id":         chk.CheckpointID,
			"checkpoint_key_id":     chk.KeyID,
			"checkpoint_public_key": hex.EncodeToString(ws.keys.chkPub),
		})
	})

	mux.HandleFunc("/api/v1/workflow/timeline", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SchemaVersion    string  `json:"schema_version"`
			CaseID           string  `json:"case_id"`
			EvidenceID       string  `json:"evidence_id"`
			ArtifactID       string  `json:"artifact_id"`
			ZoneHint         string  `json:"zone_hint,omitempty"`
			SourceConfidence float64 `json:"source_confidence,omitempty"`
			Provider         string  `json:"provider,omitempty"`
		}
		if !decodeEngineJSON(w, r, maxWorkflowRequestBytes, &req) {
			return
		}
		if req.SchemaVersion != evidence.SchemaVersion {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "unsupported_version", Field: "schema_version"})
			return
		}
		if !validateWorkflowProvider(req.Provider) {
			writeEngineProblem(w, http.StatusServiceUnavailable, evidence.Problem{Code: "unavailable_provider", Field: "provider"})
			return
		}
		if !inspectIdentRegex.MatchString(req.CaseID) || !inspectIdentRegex.MatchString(req.EvidenceID) || !inspectIdentRegex.MatchString(req.ArtifactID) {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field"})
			return
		}

		ctrl.mu.Lock()
		defer ctrl.mu.Unlock()
		ws, prob, code := ctrl.ensureWorkspaceLocked()
		if prob != nil {
			writeEngineProblem(w, code, *prob)
			return
		}
		runRes, err := ws.sandbox.RunIsolated(r.Context(), analyzers.IsolatedRunRequest{
			RunID:      "run-" + req.ArtifactID,
			CaseID:     req.CaseID,
			EvidenceID: req.EvidenceID,
			AnalyzerID: analyzers.AnalyzerJSON,
			Provider:   "local",
			Options:    analyzers.DefaultParseOptions(),
		})
		if err != nil {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "timeline_parse_failed"})
			return
		}
		if _, err := ws.artifactStore.DeriveFromIsolatedRun(r.Context(), ws.sealStore, ws.sDir, runRes, artifacts.DeriveRequest{
			OperationID: "drv-" + req.ArtifactID,
			CaseID:      req.CaseID,
			ArtifactID:  req.ArtifactID,
			Provider:    "local",
			KeyID:       workflowKeyIDArtifact,
			PrivateKey:  ws.keys.artPriv,
		}); err != nil {
			writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "artifact_derive_failed"})
			return
		}
		conf := req.SourceConfidence
		if conf <= 0 || conf > 1 {
			conf = 0.95
		}
		if _, err := ws.indexStore.IndexDerivedArtifact(r.Context(), ws.sealStore, ws.sDir, ws.artifactStore, ws.aDir, timeline.IndexDerivedRequest{
			SchemaVersion:    "1",
			OperationID:      "idx-" + req.ArtifactID,
			CaseID:           req.CaseID,
			ArtifactID:       req.ArtifactID,
			Provider:         "local",
			ZoneHint:         req.ZoneHint,
			SourceConfidence: &conf,
			VerifyOptions: artifacts.VerifyOptions{
				TrustedKeys:      map[string]ed25519.PublicKey{workflowKeyIDArtifact: ws.keys.artPub},
				RequireSignature: true,
			},
		}); err != nil {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "timeline_index_failed"})
			return
		}
		searchRes, err := ws.indexStore.Search(r.Context(), timeline.SearchRequest{
			SchemaVersion: "1",
			CaseID:        req.CaseID,
			Provider:      "local",
			MaxResults:    100,
		})
		if err != nil {
			writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "timeline_search_failed"})
			return
		}
		rawPreserved := len(searchRes.Entries) > 0
		for _, entry := range searchRes.Entries {
			if strings.TrimSpace(entry.Time.RawTimestamp) == "" || strings.TrimSpace(entry.Time.TimezoneOffset) == "" || entry.Time.Confidence <= 0 {
				rawPreserved = false
				break
			}
		}
		ctrl.log("info", "timeline_indexed", fmt.Sprintf("Indexed %d timeline entries for %s/%s", len(searchRes.Entries), req.CaseID, req.EvidenceID))
		writeWorkflowJSON(w, http.StatusOK, map[string]any{
			"schema_version":           "1",
			"status":                   "timeline_indexed",
			"artifact_id":              req.ArtifactID,
			"total_entries":            len(searchRes.Entries),
			"raw_timestamps_preserved": rawPreserved,
			"entries":                  searchRes.Entries,
		})
	})

	mux.HandleFunc("/api/v1/workflow/hold", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SchemaVersion string `json:"schema_version"`
			CaseID        string `json:"case_id"`
			EvidenceID    string `json:"evidence_id"`
			HoldID        string `json:"hold_id,omitempty"`
			Action        string `json:"action"`
			Actor         string `json:"actor"`
			Timestamp     string `json:"timestamp,omitempty"`
			Reason        string `json:"reason"`
			Provider      string `json:"provider,omitempty"`
		}
		if !decodeEngineJSON(w, r, maxWorkflowRequestBytes, &req) {
			return
		}
		if req.SchemaVersion != evidence.SchemaVersion {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "unsupported_version", Field: "schema_version"})
			return
		}
		if !validateWorkflowProvider(req.Provider) {
			writeEngineProblem(w, http.StatusServiceUnavailable, evidence.Problem{Code: "unavailable_provider", Field: "provider"})
			return
		}
		if !inspectIdentRegex.MatchString(req.CaseID) || !inspectIdentRegex.MatchString(req.EvidenceID) {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field"})
			return
		}
		ts := strings.TrimSpace(req.Timestamp)
		if ts == "" {
			ts = time.Now().UTC().Format(time.RFC3339)
		}
		ctrl.mu.Lock()
		defer ctrl.mu.Unlock()
		ws, prob, code := ctrl.ensureWorkspaceLocked()
		if prob != nil {
			writeEngineProblem(w, code, *prob)
			return
		}

		switch strings.TrimSpace(req.Action) {
		case "place":
			holdID := strings.TrimSpace(req.HoldID)
			if holdID == "" {
				holdID = "hold-" + req.EvidenceID
			}
			_, err := ws.holdService.PlaceHold(r.Context(), holds.PlaceHoldRequest{
				HoldID:     holdID,
				CaseID:     req.CaseID,
				EvidenceID: req.EvidenceID,
				Actor:      req.Actor,
				Timestamp:  ts,
				Reason:     req.Reason,
				Provider:   "local",
			})
			if err != nil {
				writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "hold_failed"})
				return
			}
			if _, err := ws.saveLatestCheckpoint(r.Context(), req.CaseID, req.EvidenceID); err != nil {
				writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "checkpoint_failed"})
				return
			}
			st, _ := ws.holdService.GetEvidenceStatus(req.CaseID, req.EvidenceID)
			ctrl.log("info", "hold_placed", fmt.Sprintf("Placed hold %s on %s/%s", holdID, req.CaseID, req.EvidenceID))
			writeWorkflowJSON(w, http.StatusOK, map[string]any{
				"schema_version": "1",
				"status":         "hold_placed",
				"hold_id":        holdID,
				"hold_status":    st,
			})
		case "attempt_delete", "attempt_expire":
			dispReq := holds.DisposalRequest{
				CaseID:     req.CaseID,
				EvidenceID: req.EvidenceID,
				Actor:      req.Actor,
				Timestamp:  ts,
				Reason:     req.Reason,
				Provider:   "local",
			}
			var err error
			if req.Action == "attempt_delete" {
				_, err = ws.holdService.DeleteEvidence(r.Context(), dispReq)
			} else {
				_, err = ws.holdService.ExpireRetention(r.Context(), dispReq)
			}
			// Keep custody checkpoint current after mirrored audit event
			_, _ = ws.saveLatestCheckpoint(r.Context(), req.CaseID, req.EvidenceID)
			vRes, vErr := evidence.VerifyStoreEvidence(r.Context(), ws.sealStore, req.CaseID, req.EvidenceID, evidence.VerifyOptions{})
			evidenceIntact := vErr == nil && vRes.Verified
			if errors.Is(err, holds.ErrHoldActive) {
				st, _ := ws.holdService.GetEvidenceStatus(req.CaseID, req.EvidenceID)
				ctrl.log("info", "disposal_blocked_by_hold", fmt.Sprintf("%s blocked for %s/%s", req.Action, req.CaseID, req.EvidenceID))
				writeWorkflowJSON(w, http.StatusConflict, map[string]any{
					"schema_version":  "1",
					"status":          "error",
					"error":           evidence.Problem{Code: "hold_active", Field: "action"},
					"evidence_intact": evidenceIntact,
					"hold_status":     st,
				})
				return
			}
			if err != nil {
				writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "disposal_error"})
				return
			}
			writeWorkflowJSON(w, http.StatusOK, map[string]any{
				"schema_version":  "1",
				"status":          "disposed",
				"evidence_intact": evidenceIntact,
			})
		default:
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field", Field: "action"})
		}
	})

	mux.HandleFunc("/api/v1/workflow/export", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SchemaVersion string   `json:"schema_version"`
			CaseID        string   `json:"case_id"`
			BundleID      string   `json:"bundle_id"`
			EvidenceIDs   []string `json:"evidence_ids"`
			ArtifactIDs   []string `json:"artifact_ids"`
			Provider      string   `json:"provider,omitempty"`
		}
		if !decodeEngineJSON(w, r, maxWorkflowRequestBytes, &req) {
			return
		}
		if req.SchemaVersion != evidence.SchemaVersion {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "unsupported_version", Field: "schema_version"})
			return
		}
		if !validateWorkflowProvider(req.Provider) {
			writeEngineProblem(w, http.StatusServiceUnavailable, evidence.Problem{Code: "unavailable_provider", Field: "provider"})
			return
		}
		if !inspectIdentRegex.MatchString(req.CaseID) || !inspectIdentRegex.MatchString(req.BundleID) || len(req.EvidenceIDs) == 0 {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field"})
			return
		}
		ctrl.mu.Lock()
		defer ctrl.mu.Unlock()
		ws, prob, code := ctrl.ensureWorkspaceLocked()
		if prob != nil {
			writeEngineProblem(w, code, *prob)
			return
		}
		chkPubHex := hex.EncodeToString(ws.keys.chkPub)
		for _, evID := range req.EvidenceIDs {
			if _, err := ws.saveLatestCheckpoint(r.Context(), req.CaseID, evID); err != nil {
				writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "checkpoint_failed"})
				return
			}
		}
		out, err := ws.exportStore.PackageCaseBundle(r.Context(), export.ExportDeps{
			SealStore:       ws.sealStore,
			SealRootDir:     ws.sDir,
			LedgerStore:     ws.ledgerStore,
			CheckpointStore: ws.checkpointStore,
			CheckpointOpts: custody.VerifyCheckpointOptions{
				TrustedPublicKeys: map[string]string{workflowKeyIDCheckpoint: chkPubHex},
			},
			ArtifactStore:   ws.artifactStore,
			ArtifactRootDir: ws.aDir,
			IndexStore:      ws.indexStore,
			FindingStore:    ws.findingStore,
		}, export.ExportRequest{
			SchemaVersion:   "1",
			OperationID:     "exp-" + req.BundleID,
			BundleID:        req.BundleID,
			CaseID:          req.CaseID,
			Provider:        "local",
			EvidenceIDs:     req.EvidenceIDs,
			ArtifactIDs:     req.ArtifactIDs,
			IncludeTimeline: true,
			IncludeNotes:    true,
			KeyID:           workflowKeyIDBundle,
			PrivateKey:      ws.keys.bndPriv,
		})
		if err != nil {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "export_failed"})
			return
		}
		ctrl.log("info", "bundle_exported", fmt.Sprintf("Exported bundle %s (%d evidence, %d timeline)", out.BundleID, len(out.Manifest.EvidenceItems), out.Manifest.TimelineCount))
		writeWorkflowJSON(w, http.StatusOK, map[string]any{
			"schema_version":  "1",
			"status":          "exported",
			"bundle_id":       out.BundleID,
			"case_id":         out.CaseID,
			"bundle_dir":      out.BundleDir,
			"bundle_digest":   out.BundleDigest,
			"signed":          out.Signed,
			"key_id":          workflowKeyIDBundle,
			"public_key":      hex.EncodeToString(ws.keys.bndPub),
			"evidence_count":  len(out.Manifest.EvidenceItems),
			"timeline_count":  out.Manifest.TimelineCount,
		})
	})

	mux.HandleFunc("/api/v1/workflow/verify-bundle", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SchemaVersion      string `json:"schema_version"`
			BundleID           string `json:"bundle_id"`
			TrustedPublicKey   string `json:"trusted_public_key,omitempty"`
			RequireSignature   bool   `json:"require_signature"`
			SimulateTamperCopy bool   `json:"simulate_tamper_copy,omitempty"`
		}
		if !decodeEngineJSON(w, r, maxWorkflowRequestBytes, &req) {
			return
		}
		if req.SchemaVersion != evidence.SchemaVersion {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "unsupported_version", Field: "schema_version"})
			return
		}
		if !inspectIdentRegex.MatchString(req.BundleID) {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field", Field: "bundle_id"})
			return
		}
		ctrl.mu.Lock()
		defer ctrl.mu.Unlock()
		ws, prob, code := ctrl.ensureWorkspaceLocked()
		if prob != nil {
			writeEngineProblem(w, code, *prob)
			return
		}
		if _, err := ws.exportStore.GetBundleManifest(req.BundleID); err != nil {
			writeEngineProblem(w, http.StatusNotFound, evidence.Problem{Code: "bundle_not_found"})
			return
		}
		bundleDir := filepath.Join(ws.expDir, "bundles", req.BundleID)
		pubHex := strings.TrimSpace(req.TrustedPublicKey)
		if pubHex == "" {
			pubHex = hex.EncodeToString(ws.keys.bndPub)
		}
		targetDir := bundleDir
		if req.SimulateTamperCopy {
			tmpCopy, err := os.MkdirTemp(ws.scDir, "tamper-verify-*")
			if err != nil {
				writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "tamper_sim_failed"})
				return
			}
			defer os.RemoveAll(tmpCopy)
			if err := copyDirTree(bundleDir, tmpCopy); err != nil {
				writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "tamper_sim_failed"})
				return
			}
			if err := tamperCopiedBlob(tmpCopy); err != nil {
				writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "tamper_sim_failed"})
				return
			}
			targetDir = tmpCopy
		}

		res, err := export.VerifyBundle(r.Context(), targetDir, export.VerifyBundleOptions{
			TrustedPublicKeys: map[string]string{workflowKeyIDBundle: pubHex, "*": pubHex},
			RequireSignature:  req.RequireSignature,
		})
		if err != nil || !res.Verified {
			writeWorkflowJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"schema_version": "1",
				"status":         "verification_failed",
				"verified":       false,
				"error":          evidence.Problem{Code: "verification_failed"},
				"result":         res,
			})
			return
		}
		writeWorkflowJSON(w, http.StatusOK, map[string]any{
			"schema_version": "1",
			"status":         "verified",
			"verified":       true,
			"result":         res,
		})
	})

	mux.HandleFunc("/api/v1/workflow/recover", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SchemaVersion  string `json:"schema_version"`
			CaseID         string `json:"case_id"`
			Action         string `json:"action,omitempty"`
			BundleID       string `json:"bundle_id,omitempty"`
			TargetCaseID   string `json:"target_case_id,omitempty"`
			DropIndexFirst bool   `json:"drop_index_first,omitempty"`
			ZoneHint       string `json:"zone_hint,omitempty"`
			Provider       string `json:"provider,omitempty"`
		}
		if !decodeEngineJSON(w, r, maxWorkflowRequestBytes, &req) {
			return
		}
		if req.SchemaVersion != evidence.SchemaVersion {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "unsupported_version", Field: "schema_version"})
			return
		}
		if !validateWorkflowProvider(req.Provider) {
			writeEngineProblem(w, http.StatusServiceUnavailable, evidence.Problem{Code: "unavailable_provider", Field: "provider"})
			return
		}
		if !inspectIdentRegex.MatchString(req.CaseID) {
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field", Field: "case_id"})
			return
		}
		ctrl.mu.Lock()
		defer ctrl.mu.Unlock()
		ws, prob, code := ctrl.ensureWorkspaceLocked()
		if prob != nil {
			writeEngineProblem(w, code, *prob)
			return
		}

		action := strings.TrimSpace(req.Action)
		if action == "" {
			action = "rebuild"
		}
		switch action {
		case "rebuild":
			if req.DropIndexFirst {
				_ = ws.indexStore.Close()
				_ = os.RemoveAll(filepath.Join(ws.idxDir, "cases", req.CaseID+".json"))
				reopened, err := timeline.OpenEventIndexStore(timeline.EventIndexConfig{RootDir: ws.idxDir, SyncDir: true})
				if err != nil {
					writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "recovery_failed"})
					return
				}
				ws.indexStore = reopened
			}
			chkPubHex := hex.EncodeToString(ws.keys.chkPub)
			out, err := ws.restoreStore.VerifyAndRebuildCase(r.Context(), ws.targetStores(), recovery.VerifyAndRebuildRequest{
				SchemaVersion:         "1",
				OperationID:           fmt.Sprintf("reb-%s-%d", req.CaseID, time.Now().UnixNano()),
				CaseID:                req.CaseID,
				Provider:              "local",
				ZoneHint:              req.ZoneHint,
				TrustedCheckpointKeys: map[string]string{workflowKeyIDCheckpoint: chkPubHex},
				RequireCheckpoints:    true,
				ArtifactVerifyOpts: artifacts.VerifyOptions{
					TrustedKeys:      map[string]ed25519.PublicKey{workflowKeyIDArtifact: ws.keys.artPub},
					RequireSignature: true,
				},
			})
			if err != nil {
				writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "recovery_failed"})
				return
			}
			ctrl.log("info", "consistency_rebuilt", fmt.Sprintf("Verified %d evidence items and rebuilt %d timeline entries for %s", out.VerifiedEvidenceCount, out.RebuiltTimelineEntries, req.CaseID))
			writeWorkflowJSON(w, http.StatusOK, map[string]any{
				"schema_version":           "1",
				"status":                   "consistency_rebuilt",
				"case_id":                  out.CaseID,
				"verified_evidence_count":  out.VerifiedEvidenceCount,
				"rebuilt_timeline_entries": out.RebuiltTimelineEntries,
				"timeline_rebuilt":         out.TimelineRebuilt,
				"sealed_bytes_modified":    out.SealedBytesModified,
				"custody_rewritten":        out.CustodyRewritten,
			})
		case "restore_bundle":
			if !inspectIdentRegex.MatchString(req.BundleID) {
				writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field", Field: "bundle_id"})
				return
			}
			bundleDir := filepath.Join(ws.expDir, "bundles", req.BundleID)
			targetID := strings.TrimSpace(req.TargetCaseID)
			if targetID == "" {
				targetID = req.CaseID
			}
			if !inspectIdentRegex.MatchString(targetID) {
				writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field", Field: "target_case_id"})
				return
			}
			restoredRoot := filepath.Join(ws.root, "restored", fmt.Sprintf("%s-%d", targetID, time.Now().UnixNano()))
			targetWS, err := openWorkflowWorkspace(restoredRoot)
			if err != nil {
				writeEngineProblem(w, http.StatusInternalServerError, evidence.Problem{Code: "restore_failed"})
				return
			}
			defer targetWS.close()
			bndPubHex := hex.EncodeToString(ws.keys.bndPub)
			chkPubHex := hex.EncodeToString(ws.keys.chkPub)
			out, err := targetWS.restoreStore.RestoreFromBundle(r.Context(), targetWS.targetStores(), recovery.RestoreBundleRequest{
				SchemaVersion:          "1",
				OperationID:            fmt.Sprintf("rst-%s-%d", req.BundleID, time.Now().UnixNano()),
				CaseID:                 req.CaseID,
				BundlePath:             bundleDir,
				Provider:               "local",
				ZoneHint:               req.ZoneHint,
				TrustedBundleKeys:      map[string]string{workflowKeyIDBundle: bndPubHex, "*": bndPubHex},
				RequireBundleSignature: true,
				TrustedCheckpointKeys:  map[string]string{workflowKeyIDCheckpoint: chkPubHex},
				RequireCheckpointTrust: true,
				ArtifactVerifyOpts: artifacts.VerifyOptions{
					TrustedKeys:      map[string]ed25519.PublicKey{workflowKeyIDArtifact: ws.keys.artPub},
					RequireSignature: true,
				},
			})
			if err != nil {
				writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "restore_failed"})
				return
			}
			entries, _ := targetWS.indexStore.ListEntries(req.CaseID)
			writeWorkflowJSON(w, http.StatusOK, map[string]any{
				"schema_version":           "1",
				"status":                   "restored",
				"case_id":                  out.CaseID,
				"bundle_id":                out.BundleID,
				"restored_evidence_count":  out.RestoredEvidenceCount,
				"rebuilt_timeline_entries": out.RebuiltTimelineEntries,
				"sealed_bytes_modified":    out.SealedBytesModified,
				"custody_rewritten":        out.CustodyRewritten,
				"restored_entries":         entries,
			})
		default:
			writeEngineProblem(w, http.StatusBadRequest, evidence.Problem{Code: "invalid_field", Field: "action"})
		}
	})

	return ctrl.Close
}

func buildWorkflowStateSnapshot(ctx context.Context, ws *workflowWorkspace, caseID string) map[string]any {
	manifests := ws.sealStore.ListSealedManifests()
	sort.Slice(manifests, func(i, j int) bool {
		return manifests[i].EvidenceID < manifests[j].EvidenceID
	})
	items := make([]map[string]any, 0)
	for _, m := range manifests {
		if m.CaseID != caseID {
			continue
		}
		vRes, vErr := evidence.VerifyStoreEvidence(ctx, ws.sealStore, m.CaseID, m.EvidenceID, evidence.VerifyOptions{})
		verified := vErr == nil && vRes.Verified
		events, _ := ws.ledgerStore.ListEvents(m.CaseID, m.EvidenceID)
		chainValid, _ := ws.ledgerStore.VerifyChain(m.CaseID, m.EvidenceID)
		curRoot, _ := ws.ledgerStore.CurrentRoot(m.CaseID, m.EvidenceID)
		holdSt, _ := ws.holdService.GetEvidenceStatus(m.CaseID, m.EvidenceID)
		items = append(items, map[string]any{
			"case_id":             m.CaseID,
			"evidence_id":         m.EvidenceID,
			"sha256":              m.SHA256,
			"size_bytes":          m.SizeBytes,
			"media_type":          m.MediaType,
			"acquired_at":         m.AcquiredAt,
			"custody_root":        curRoot,
			"manifest_digest":     m.ManifestDigest,
			"verified":            verified,
			"custody_chain_valid": chainValid,
			"custody_event_count": len(events),
			"custody_events":      events,
			"hold_status":         holdSt,
		})
	}
	entries, _ := ws.indexStore.ListEntries(caseID)
	return map[string]any{
		"schema_version":   "1",
		"status":           "ok",
		"case_id":          caseID,
		"bundle_public_key": hex.EncodeToString(ws.keys.bndPub),
		"bundle_key_id":     workflowKeyIDBundle,
		"evidence":         items,
		"timeline_count":   len(entries),
		"timeline_entries": entries,
	}
}

func copyDirTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o600)
	})
}

func tamperCopiedBlob(bundleDir string) error {
	var targetBlob string
	_ = filepath.WalkDir(bundleDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (d.Name() == "blob.dat" || strings.Contains(filepath.ToSlash(path), "/blobs/")) {
			targetBlob = path
			return filepath.SkipAll
		}
		return nil
	})
	if targetBlob == "" {
		return errors.New("no blob found in copied bundle")
	}
	raw, err := os.ReadFile(targetBlob)
	if err != nil || len(raw) == 0 {
		return errors.New("failed to read copied blob")
	}
	raw[0] ^= 0xff
	return os.WriteFile(targetBlob, raw, 0o600)
}

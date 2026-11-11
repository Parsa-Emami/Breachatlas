package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	DefaultStreamBufferSize = 32 * 1024
	MaxFilenameBytes        = 255
	partSuffix              = ".part"
	payloadSuffix           = ".bin"
	metadataSuffix          = ".meta.json"
	metadataTmpSuffix       = ".meta.tmp"
)

type QuarantineStatus string

const (
	StatusQuarantined QuarantineStatus = "quarantined"
	StatusIncomplete  QuarantineStatus = "incomplete"
)

var (
	ErrQuarantineRequired   = errors.New("quarantine directory is required")
	ErrMalformedUpload      = errors.New("malformed upload metadata")
	ErrUnsupportedVersion   = errors.New("unsupported upload schema version")
	ErrUploadTooLarge       = errors.New("upload exceeds maximum allowed bytes")
	ErrPathTraversal        = errors.New("path traversal or invalid path component rejected")
	ErrSymlinkRejected      = errors.New("symlink rejected in upload or quarantine path")
	ErrUploadInterrupted    = errors.New("upload interrupted before quarantine completion")
	ErrSizeMismatch         = errors.New("streamed size does not match declared size")
	ErrDigestMismatch       = errors.New("streamed sha256 does not match declared digest")
	ErrSealedBytesImmutable = errors.New("sealed source bytes never modified: evidence already sealed")
	ErrDuplicateUpload      = errors.New("upload already quarantined")
)

// SealedChecker reports whether a (caseID, evidenceID) pair has already been sealed
// in authoritative storage, allowing quarantine ingest to fail closed without import cycles.
type SealedChecker func(caseID, evidenceID string) (bool, error)

// UploadConfig configures bounded streaming quarantine storage.
type UploadConfig struct {
	QuarantineDir string
	MaxBytes      int64
	BufferSize    int
	SyncDir       bool
	IsSealed      SealedChecker
}

// UploadRequest describes an incoming evidence stream staged for quarantine hashing.
type UploadRequest struct {
	SchemaVersion  string    `json:"schema_version"`
	UploadID       string    `json:"upload_id"`
	CaseID         string    `json:"case_id"`
	EvidenceID     string    `json:"evidence_id"`
	MediaType      string    `json:"media_type"`
	Filename       string    `json:"filename,omitempty"`
	ExpectedSize   *int64    `json:"expected_size,omitempty"`
	ExpectedSHA256 string    `json:"expected_sha256,omitempty"`
	Body           io.Reader `json:"-"`
}

// QuarantinedUpload represents a hashed, unsealed evidence artifact residing in quarantine.
type QuarantinedUpload struct {
	SchemaVersion  string           `json:"schema_version"`
	UploadID       string           `json:"upload_id"`
	CaseID         string           `json:"case_id"`
	EvidenceID     string           `json:"evidence_id"`
	MediaType      string           `json:"media_type"`
	Filename       string           `json:"filename,omitempty"`
	SHA256         string           `json:"sha256"`
	SizeBytes      int64            `json:"size_bytes"`
	QuarantinePath string           `json:"quarantine_path"`
	MetadataPath   string           `json:"metadata_path"`
	Status         QuarantineStatus `json:"status"`
	Sealed         bool             `json:"sealed"`
	CreatedAt      string           `json:"created_at"`
}

// ToManifest converts a completed quarantined upload into a Manifest candidate for sealing.
func (q *QuarantinedUpload) ToManifest(acquiredAt, custodyRoot string) Manifest {
	return Manifest{
		SchemaVersion: q.SchemaVersion,
		CaseID:        q.CaseID,
		EvidenceID:    q.EvidenceID,
		SHA256:        q.SHA256,
		SizeBytes:     q.SizeBytes,
		MediaType:     q.MediaType,
		AcquiredAt:    acquiredAt,
		CustodyRoot:   custodyRoot,
	}
}

func hasTraversalOrSeparator(s string) bool {
	return strings.Contains(s, "..") || strings.ContainsAny(s, "/\\") || strings.ContainsRune(s, '\x00')
}

func validateID(field, val string) error {
	if hasTraversalOrSeparator(val) {
		return fmt.Errorf("%w: %s contains invalid path characters", ErrPathTraversal, field)
	}
	if !identifier.MatchString(val) {
		return fmt.Errorf("%w: invalid %s %q", ErrMalformedUpload, field, val)
	}
	return nil
}

func validateFilename(name string) error {
	if name == "" {
		return nil
	}
	if hasTraversalOrSeparator(name) || name == "." {
		return fmt.Errorf("%w: invalid filename %q", ErrPathTraversal, name)
	}
	if len(name) > MaxFilenameBytes {
		return fmt.Errorf("%w: filename exceeds %d bytes", ErrMalformedUpload, MaxFilenameBytes)
	}
	for _, r := range name {
		if r < 32 || r == 127 {
			return fmt.Errorf("%w: filename contains control character", ErrMalformedUpload)
		}
	}
	return nil
}

func ensureNoSymlink(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true, fmt.Errorf("%w: %s", ErrSymlinkRejected, path)
	}
	return true, nil
}

func resolveQuarantineRoot(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", ErrQuarantineRequired
	}
	if strings.ContainsRune(dir, '\x00') {
		return "", fmt.Errorf("%w: null byte in quarantine dir", ErrPathTraversal)
	}
	for _, seg := range strings.FieldsFunc(dir, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return "", fmt.Errorf("%w: traversal segment in quarantine dir", ErrPathTraversal)
		}
	}

	absDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}

	exists, err := ensureNoSymlink(absDir)
	if err != nil {
		return "", err
	}
	if !exists {
		if err := os.MkdirAll(absDir, 0750); err != nil {
			return "", fmt.Errorf("create quarantine dir: %w", err)
		}
		if _, err := ensureNoSymlink(absDir); err != nil {
			return "", err
		}
	} else {
		info, err := os.Stat(absDir)
		if err != nil {
			return "", err
		}
		if !info.IsDir() {
			return "", fmt.Errorf("%w: quarantine path is not a directory", ErrMalformedUpload)
		}
	}
	return absDir, nil
}

func checkWithinDir(root, target string) error {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("%w: %s escapes quarantine root", ErrPathTraversal, target)
	}
	return nil
}

func validateConfigAndRequest(cfg UploadConfig, req UploadRequest) (int64, int, error) {
	maxBytes := cfg.MaxBytes
	if maxBytes == 0 {
		maxBytes = MaxEvidenceBytes
	}
	if maxBytes < 0 || maxBytes > MaxEvidenceBytes {
		return 0, 0, fmt.Errorf("%w: max_bytes must be within [1, %d]", ErrMalformedUpload, MaxEvidenceBytes)
	}

	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = DefaultStreamBufferSize
	}

	if req.SchemaVersion != SchemaVersion {
		return 0, 0, fmt.Errorf("%w: got %q, want %q", ErrUnsupportedVersion, req.SchemaVersion, SchemaVersion)
	}
	if err := validateID("upload_id", req.UploadID); err != nil {
		return 0, 0, err
	}
	if err := validateID("case_id", req.CaseID); err != nil {
		return 0, 0, err
	}
	if err := validateID("evidence_id", req.EvidenceID); err != nil {
		return 0, 0, err
	}
	if len(req.MediaType) == 0 || len(req.MediaType) > 127 || !mediaType.MatchString(req.MediaType) {
		return 0, 0, fmt.Errorf("%w: invalid media_type %q", ErrMalformedUpload, req.MediaType)
	}
	if err := validateFilename(req.Filename); err != nil {
		return 0, 0, err
	}
	if req.ExpectedSize != nil {
		if *req.ExpectedSize < 0 {
			return 0, 0, fmt.Errorf("%w: negative expected_size", ErrMalformedUpload)
		}
		if *req.ExpectedSize > maxBytes {
			return 0, 0, fmt.Errorf("%w: expected_size %d exceeds limit %d", ErrUploadTooLarge, *req.ExpectedSize, maxBytes)
		}
	}
	if req.ExpectedSHA256 != "" && !digest.MatchString(req.ExpectedSHA256) {
		return 0, 0, fmt.Errorf("%w: invalid expected_sha256", ErrMalformedUpload)
	}
	if req.Body == nil {
		return 0, 0, fmt.Errorf("%w: upload body reader is required", ErrMalformedUpload)
	}

	return maxBytes, bufSize, nil
}

func syncPath(path string) {
	d, err := os.Open(path)
	if err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// StreamIntoQuarantine streams evidence bytes in bounded chunks to an isolated quarantine file,
// computing SHA-256 on the fly. Interrupted, oversized, malformed, traversal, or symlink inputs
// are rejected and cleaned up before completion, and quarantined artifacts always remain Sealed: false.
func StreamIntoQuarantine(ctx context.Context, cfg UploadConfig, req UploadRequest) (*QuarantinedUpload, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUploadInterrupted, err)
	}

	maxBytes, bufSize, err := validateConfigAndRequest(cfg, req)
	if err != nil {
		return nil, err
	}

	rootDir, err := resolveQuarantineRoot(cfg.QuarantineDir)
	if err != nil {
		return nil, err
	}

	if cfg.IsSealed != nil {
		sealed, err := cfg.IsSealed(req.CaseID, req.EvidenceID)
		if err != nil {
			return nil, fmt.Errorf("check sealed state: %w", err)
		}
		if sealed {
			return nil, fmt.Errorf("%w: %s/%s", ErrSealedBytesImmutable, req.CaseID, req.EvidenceID)
		}
	}

	caseDir := filepath.Join(rootDir, req.CaseID)
	if err := checkWithinDir(rootDir, caseDir); err != nil {
		return nil, err
	}
	caseExists, err := ensureNoSymlink(caseDir)
	if err != nil {
		return nil, err
	}
	if !caseExists {
		if err := os.Mkdir(caseDir, 0750); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("create case quarantine dir: %w", err)
		}
		if _, err := ensureNoSymlink(caseDir); err != nil {
			return nil, err
		}
	} else {
		info, err := os.Stat(caseDir)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%w: case quarantine path is not a directory", ErrMalformedUpload)
		}
	}

	partPath := filepath.Join(caseDir, req.UploadID+partSuffix)
	dataPath := filepath.Join(caseDir, req.UploadID+payloadSuffix)
	metaPath := filepath.Join(caseDir, req.UploadID+metadataSuffix)
	metaTmpPath := filepath.Join(caseDir, req.UploadID+metadataTmpSuffix)

	for _, p := range []string{partPath, dataPath, metaPath, metaTmpPath} {
		if err := checkWithinDir(caseDir, p); err != nil {
			return nil, err
		}
		if _, err := ensureNoSymlink(p); err != nil {
			return nil, err
		}
	}

	if _, err := os.Lstat(metaPath); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrDuplicateUpload, req.UploadID)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	// Remove any uncompleted orphan .part/.meta.tmp for this UploadID before starting a clean retry.
	_ = os.Remove(partPath)
	_ = os.Remove(metaTmpPath)

	partFile, err := os.OpenFile(partPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("open quarantine part file: %w", err)
	}

	cleanupPart := func() {
		_ = partFile.Close()
		_ = os.Remove(partPath)
	}

	hasher := sha256.New()
	buf := make([]byte, bufSize)
	var totalBytes int64

	for {
		if err := ctx.Err(); err != nil {
			cleanupPart()
			return nil, fmt.Errorf("%w: %v", ErrUploadInterrupted, err)
		}

		n, readErr := req.Body.Read(buf)
		if n > 0 {
			if totalBytes+int64(n) > maxBytes {
				cleanupPart()
				return nil, fmt.Errorf("%w: stream exceeded %d bytes", ErrUploadTooLarge, maxBytes)
			}
			chunk := buf[:n]
			if _, wErr := partFile.Write(chunk); wErr != nil {
				cleanupPart()
				return nil, fmt.Errorf("%w: write quarantine chunk: %v", ErrUploadInterrupted, wErr)
			}
			_, _ = hasher.Write(chunk)
			totalBytes += int64(n)
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			cleanupPart()
			return nil, fmt.Errorf("%w: read stream: %v", ErrUploadInterrupted, readErr)
		}
	}

	if ctx.Err() != nil {
		cleanupPart()
		return nil, fmt.Errorf("%w: %v", ErrUploadInterrupted, ctx.Err())
	}

	if req.ExpectedSize != nil && totalBytes != *req.ExpectedSize {
		cleanupPart()
		return nil, fmt.Errorf("%w: streamed %d bytes, expected %d", ErrSizeMismatch, totalBytes, *req.ExpectedSize)
	}

	computedSHA := hex.EncodeToString(hasher.Sum(nil))
	if req.ExpectedSHA256 != "" && computedSHA != req.ExpectedSHA256 {
		cleanupPart()
		return nil, fmt.Errorf("%w: got %s, expected %s", ErrDigestMismatch, computedSHA, req.ExpectedSHA256)
	}

	if err := partFile.Sync(); err != nil {
		cleanupPart()
		return nil, fmt.Errorf("sync quarantine file: %w", err)
	}
	if err := partFile.Close(); err != nil {
		_ = os.Remove(partPath)
		return nil, fmt.Errorf("close quarantine file: %w", err)
	}

	// Re-check sealed status before promoting .part -> .bin in case an authoritative seal occurred concurrently.
	if cfg.IsSealed != nil {
		sealed, err := cfg.IsSealed(req.CaseID, req.EvidenceID)
		if err != nil {
			_ = os.Remove(partPath)
			return nil, fmt.Errorf("recheck sealed state: %w", err)
		}
		if sealed {
			_ = os.Remove(partPath)
			return nil, fmt.Errorf("%w: %s/%s", ErrSealedBytesImmutable, req.CaseID, req.EvidenceID)
		}
	}

	if err := os.Rename(partPath, dataPath); err != nil {
		_ = os.Remove(partPath)
		return nil, fmt.Errorf("finalize quarantine payload: %w", err)
	}

	relDataPath := filepath.Join(req.CaseID, req.UploadID+payloadSuffix)
	relMetaPath := filepath.Join(req.CaseID, req.UploadID+metadataSuffix)
	record := QuarantinedUpload{
		SchemaVersion:  SchemaVersion,
		UploadID:       req.UploadID,
		CaseID:         req.CaseID,
		EvidenceID:     req.EvidenceID,
		MediaType:      req.MediaType,
		Filename:       req.Filename,
		SHA256:         computedSHA,
		SizeBytes:      totalBytes,
		QuarantinePath: relDataPath,
		MetadataPath:   relMetaPath,
		Status:         StatusQuarantined,
		Sealed:         false,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339Nano),
	}

	metaBytes, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		_ = os.Remove(dataPath)
		return nil, fmt.Errorf("marshal quarantine metadata: %w", err)
	}

	metaFile, err := os.OpenFile(metaTmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		_ = os.Remove(dataPath)
		return nil, fmt.Errorf("create quarantine metadata tmp: %w", err)
	}
	if _, err := metaFile.Write(metaBytes); err != nil {
		_ = metaFile.Close()
		_ = os.Remove(metaTmpPath)
		_ = os.Remove(dataPath)
		return nil, fmt.Errorf("write quarantine metadata: %w", err)
	}
	if err := metaFile.Sync(); err != nil {
		_ = metaFile.Close()
		_ = os.Remove(metaTmpPath)
		_ = os.Remove(dataPath)
		return nil, fmt.Errorf("sync quarantine metadata: %w", err)
	}
	if err := metaFile.Close(); err != nil {
		_ = os.Remove(metaTmpPath)
		_ = os.Remove(dataPath)
		return nil, fmt.Errorf("close quarantine metadata: %w", err)
	}

	if err := os.Rename(metaTmpPath, metaPath); err != nil {
		_ = os.Remove(metaTmpPath)
		_ = os.Remove(dataPath)
		return nil, fmt.Errorf("commit quarantine metadata: %w", err)
	}

	if cfg.SyncDir {
		syncPath(caseDir)
	}

	return &record, nil
}

// StreamFileIntoQuarantine safely opens a regular non-symlink local file and streams it into quarantine.
func StreamFileIntoQuarantine(ctx context.Context, cfg UploadConfig, req UploadRequest, sourcePath string) (*QuarantinedUpload, error) {
	if strings.TrimSpace(sourcePath) == "" {
		return nil, fmt.Errorf("%w: source_path is required", ErrMalformedUpload)
	}
	if strings.ContainsRune(sourcePath, '\x00') {
		return nil, fmt.Errorf("%w: invalid source_path", ErrPathTraversal)
	}
	for _, seg := range strings.FieldsFunc(sourcePath, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return nil, fmt.Errorf("%w: traversal segment in source_path", ErrPathTraversal)
		}
	}
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlinkRejected, sourcePath)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: source_path must be a regular file", ErrMalformedUpload)
	}

	f, err := os.Open(sourcePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	req.Body = f
	if req.Filename == "" {
		req.Filename = filepath.Base(sourcePath)
	}
	return StreamIntoQuarantine(ctx, cfg, req)
}

// InspectQuarantine scans quarantineDir and returns verified quarantined uploads (always Sealed: false)
// separately from any incomplete orphan .part / .meta.tmp / unmatched .bin entries.
func InspectQuarantine(quarantineDir string) ([]QuarantinedUpload, []string, error) {
	rootDir, err := resolveQuarantineRoot(quarantineDir)
	if err != nil {
		return nil, nil, err
	}

	var completed []QuarantinedUpload
	var incomplete []string
	referencedBins := make(map[string]bool)
	var candidateBins []string

	caseEntries, err := os.ReadDir(rootDir)
	if err != nil {
		return nil, nil, err
	}
	for _, ce := range caseEntries {
		if !ce.IsDir() {
			incomplete = append(incomplete, ce.Name())
			continue
		}
		casePath := filepath.Join(rootDir, ce.Name())
		if _, err := ensureNoSymlink(casePath); err != nil {
			return nil, nil, err
		}
		files, err := os.ReadDir(casePath)
		if err != nil {
			return nil, nil, err
		}
		for _, fe := range files {
			name := fe.Name()
			rel := filepath.Join(ce.Name(), name)
			full := filepath.Join(casePath, name)
			if _, err := ensureNoSymlink(full); err != nil {
				return nil, nil, err
			}
			switch {
			case strings.HasSuffix(name, partSuffix) || strings.HasSuffix(name, metadataTmpSuffix):
				incomplete = append(incomplete, rel)
			case strings.HasSuffix(name, payloadSuffix):
				candidateBins = append(candidateBins, rel)
			case strings.HasSuffix(name, metadataSuffix):
				raw, err := os.ReadFile(full)
				if err != nil {
					incomplete = append(incomplete, rel)
					continue
				}
				var rec QuarantinedUpload
				if err := json.Unmarshal(raw, &rec); err != nil || rec.Sealed || rec.Status != StatusQuarantined {
					incomplete = append(incomplete, rel)
					continue
				}
				binFull := filepath.Join(rootDir, rec.QuarantinePath)
				if err := checkWithinDir(rootDir, binFull); err != nil {
					incomplete = append(incomplete, rel)
					continue
				}
				binInfo, err := os.Lstat(binFull)
				if err != nil || binInfo.Mode()&os.ModeSymlink != 0 || binInfo.Size() != rec.SizeBytes {
					incomplete = append(incomplete, rel)
					continue
				}
				rec.Sealed = false
				completed = append(completed, rec)
				referencedBins[rec.QuarantinePath] = true
			default:
				incomplete = append(incomplete, rel)
			}
		}
	}

	for _, relBin := range candidateBins {
		if !referencedBins[relBin] {
			incomplete = append(incomplete, relBin)
		}
	}

	sort.Slice(completed, func(i, j int) bool {
		if completed[i].CaseID != completed[j].CaseID {
			return completed[i].CaseID < completed[j].CaseID
		}
		return completed[i].UploadID < completed[j].UploadID
	})
	sort.Strings(incomplete)

	return completed, incomplete, nil
}

// CleanupIncomplete removes incomplete .part and .meta.tmp files from quarantineDir
// without modifying any completed quarantined upload or any sealed evidence.
func CleanupIncomplete(quarantineDir string) (int, error) {
	rootDir, err := resolveQuarantineRoot(quarantineDir)
	if err != nil {
		return 0, err
	}

	removed := 0
	caseEntries, err := os.ReadDir(rootDir)
	if err != nil {
		return 0, err
	}
	for _, ce := range caseEntries {
		if !ce.IsDir() {
			continue
		}
		casePath := filepath.Join(rootDir, ce.Name())
		files, err := os.ReadDir(casePath)
		if err != nil {
			return removed, err
		}
		for _, fe := range files {
			name := fe.Name()
			if strings.HasSuffix(name, partSuffix) || strings.HasSuffix(name, metadataTmpSuffix) {
				full := filepath.Join(casePath, name)
				if err := os.Remove(full); err == nil {
					removed++
				}
			}
		}
	}
	return removed, nil
}

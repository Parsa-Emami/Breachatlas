package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	VerifyCodeVerified           = "verified"
	VerifyCodeMissingFile        = "missing_file"
	VerifyCodeSizeMismatch       = "size_mismatch"
	VerifyCodeDigestMismatch     = "digest_mismatch"
	VerifyCodeUntrustedSigner    = "untrusted_signer"
	VerifyCodeExpiredAuthority   = "expired_authority"
	VerifyCodeStaleRevision      = "stale_revision"
	VerifyCodeInvalidManifest    = "invalid_manifest"
	VerifyCodeSymlinkRejected    = "symlink_rejected"
	VerifyCodePathTraversal      = "path_traversal"
	VerifyCodeUnsupportedVersion = "unsupported_version"
)

var (
	ErrEvidenceMissing        = errors.New("sealed evidence file or manifest missing")
	ErrAuthorityUntrusted     = errors.New("untrusted, missing, or invalid manifest authority signer")
	ErrAuthorityExpired       = errors.New("expired manifest authority attestation")
	ErrAuthorityStaleRevision = errors.New("stale or replayed revision cannot replace accepted authority")
)

// AuthorityAttestation binds a sealed manifest to a monotonic authority revision signed by an Ed25519 key.
type AuthorityAttestation struct {
	SchemaVersion  string `json:"schema_version"`
	KeyID          string `json:"key_id"`
	PublicKey      string `json:"public_key"`
	Signature      string `json:"signature"`
	Revision       uint64 `json:"revision"`
	IssuedAt       string `json:"issued_at,omitempty"`
	ExpiresAt      string `json:"expires_at"`
	ManifestDigest string `json:"manifest_digest"`
}

// AcceptedAuthority records the last valid authority state accepted for an evidence item.
type AcceptedAuthority struct {
	CaseID         string `json:"case_id"`
	EvidenceID     string `json:"evidence_id"`
	KeyID          string `json:"key_id"`
	PublicKey      string `json:"public_key"`
	Signature      string `json:"signature"`
	Revision       uint64 `json:"revision"`
	ManifestDigest string `json:"manifest_digest"`
	ExpiresAt      string `json:"expires_at"`
	AcceptedAt     string `json:"accepted_at"`
}

// AuthorityTracker enforces monotonic authority revisions and preserves the last valid accepted authority.
type AuthorityTracker struct {
	mu       sync.RWMutex
	accepted map[string]AcceptedAuthority
}

// NewAuthorityTracker creates an anti-rollback authority tracker.
func NewAuthorityTracker() *AuthorityTracker {
	return &AuthorityTracker{
		accepted: make(map[string]AcceptedAuthority),
	}
}

// LastAccepted returns the last valid accepted authority recorded for (caseID, evidenceID).
func (t *AuthorityTracker) LastAccepted(caseID, evidenceID string) (AcceptedAuthority, bool) {
	if t == nil {
		return AcceptedAuthority{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	rec, ok := t.accepted[caseID+"/"+evidenceID]
	return rec, ok
}

// VerifyOptions configures sealed manifest, byte-level, and Ed25519 authority checks.
type VerifyOptions struct {
	RequireAuthority  bool
	Authority         *AuthorityAttestation
	TrustedPublicKeys map[string]string // optional map[keyID]hexEd25519PublicKey
	Tracker           *AuthorityTracker
	MinRevision       uint64
	StrictReplay      bool
	Now               time.Time
}

// VerificationResult summarizes the typed outcome of a sealed evidence verification pass.
type VerificationResult struct {
	Verified           bool   `json:"verified"`
	Code               string `json:"code"`
	FailureKind        string `json:"failure_kind,omitempty"`
	Message            string `json:"message,omitempty"`
	CaseID             string `json:"case_id"`
	EvidenceID         string `json:"evidence_id"`
	ExpectedSHA256     string `json:"expected_sha256"`
	ActualSHA256       string `json:"actual_sha256,omitempty"`
	ExpectedSize       int64  `json:"expected_size"`
	ActualSize         int64  `json:"actual_size"`
	ManifestDigest     string `json:"manifest_digest,omitempty"`
	AuthorityRevision  uint64 `json:"authority_revision,omitempty"`
	TrustedSignerKeyID string `json:"trusted_signer_key_id,omitempty"`
	VerifiedAt         string `json:"verified_at"`
}

// CanonicalAuthorityPayload returns deterministic signing bytes binding a sealed manifest and authority revision.
func CanonicalAuthorityPayload(m SealedManifest, keyID string, revision uint64, expiresAt string) []byte {
	return []byte(fmt.Sprintf(
		"breachatlas:authority:v1:%s:%s:%s:%s:%s:%d:%s:%d:%s:%d:%s",
		m.SchemaVersion,
		m.ManifestDigest,
		m.CaseID,
		m.EvidenceID,
		m.SHA256,
		m.SizeBytes,
		m.CustodyRoot,
		m.Generation,
		keyID,
		revision,
		expiresAt,
	))
}

// SignSealedManifest signs a sealed manifest with an Ed25519 private key for independent verification.
func SignSealedManifest(m SealedManifest, keyID string, priv ed25519.PrivateKey, revision uint64, issuedAt, expiresAt time.Time) (*AuthorityAttestation, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: invalid Ed25519 private key length", ErrAuthorityUntrusted)
	}
	if err := validateID("key_id", keyID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthorityUntrusted, err)
	}
	if revision == 0 {
		return nil, fmt.Errorf("%w: revision must be >= 1", ErrAuthorityStaleRevision)
	}
	if !m.Sealed {
		return nil, fmt.Errorf("%w: cannot sign unsealed manifest", ErrManifestInvalid)
	}
	if m.ManifestDigest == "" {
		m.ManifestDigest = computeManifestDigest(m)
	}

	expStr := expiresAt.UTC().Format(time.RFC3339Nano)
	payload := CanonicalAuthorityPayload(m, keyID, revision, expStr)
	sig := ed25519.Sign(priv, payload)
	pub := priv.Public().(ed25519.PublicKey)

	att := &AuthorityAttestation{
		SchemaVersion:  SchemaVersion,
		KeyID:          keyID,
		PublicKey:      hex.EncodeToString(pub),
		Signature:      hex.EncodeToString(sig),
		Revision:       revision,
		ExpiresAt:      expStr,
		ManifestDigest: m.ManifestDigest,
	}
	if !issuedAt.IsZero() {
		att.IssuedAt = issuedAt.UTC().Format(time.RFC3339Nano)
	}
	return att, nil
}

// VerifySealedFile checks a single file read-only against expected size and SHA-256 without mutating bytes.
func VerifySealedFile(path, expectedSHA256 string, expectedSize int64) (*VerificationResult, error) {
	now := time.Now().UTC()
	res := &VerificationResult{
		Verified:       false,
		ExpectedSHA256: expectedSHA256,
		ExpectedSize:   expectedSize,
		VerifiedAt:     now.Format(time.RFC3339Nano),
	}

	if expectedSize < 0 || !digest.MatchString(expectedSHA256) {
		res.Code = VerifyCodeInvalidManifest
		res.FailureKind = VerifyCodeInvalidManifest
		res.Message = "invalid expected size or sha256"
		return res, fmt.Errorf("%w: invalid expected size or sha256", ErrManifestInvalid)
	}

	if err := verifyFileBytes(path, expectedSHA256, expectedSize, res); err != nil {
		return res, err
	}

	res.Verified = true
	res.Code = VerifyCodeVerified
	res.FailureKind = ""
	res.Message = "sealed file bytes verified"
	return res, nil
}

// VerifySealedManifest verifies manifest structure, optional/required Ed25519 authority, and read-only blob bytes.
func VerifySealedManifest(rootDir string, manifest SealedManifest, opts VerifyOptions) (*VerificationResult, error) {
	now := opts.Now.UTC()
	if opts.Now.IsZero() {
		now = time.Now().UTC()
	}

	res := &VerificationResult{
		Verified:       false,
		CaseID:         manifest.CaseID,
		EvidenceID:     manifest.EvidenceID,
		ExpectedSHA256: manifest.SHA256,
		ExpectedSize:   manifest.SizeBytes,
		ManifestDigest: manifest.ManifestDigest,
		VerifiedAt:     now.Format(time.RFC3339Nano),
	}

	safeRoot, err := validateVerifyRootDir(rootDir)
	if err != nil {
		return failVerification(res, err)
	}

	if err := validateSealedManifestFields(manifest); err != nil {
		return failVerification(res, err)
	}

	expectedManifestDigest := computeManifestDigest(manifest)
	if manifest.ManifestDigest != expectedManifestDigest {
		return failVerification(res, fmt.Errorf("%w: manifest_digest %s != computed %s", ErrDigestMismatch, manifest.ManifestDigest, expectedManifestDigest))
	}

	var acceptedCandidate *AcceptedAuthority
	if opts.RequireAuthority || opts.Authority != nil {
		candidate, authErr := validateAuthority(manifest, opts, now)
		if authErr != nil {
			return failVerification(res, authErr)
		}
		acceptedCandidate = candidate
		res.AuthorityRevision = candidate.Revision
		res.TrustedSignerKeyID = candidate.KeyID
	}

	blobFull := filepath.Join(safeRoot, filepath.FromSlash(manifest.BlobRelPath))
	if err := checkWithinDir(safeRoot, blobFull); err != nil {
		return failVerification(res, err)
	}
	if err := verifyFileBytes(blobFull, manifest.SHA256, manifest.SizeBytes, res); err != nil {
		return failVerification(res, err)
	}

	if acceptedCandidate != nil && opts.Tracker != nil {
		opts.Tracker.commitAccepted(*acceptedCandidate)
	}

	res.Verified = true
	res.Code = VerifyCodeVerified
	res.FailureKind = ""
	res.Message = "sealed bytes and manifest integrity verified"
	return res, nil
}

// VerifyStoreEvidence verifies committed SealStore state against on-disk manifest and sealed blob bytes.
func VerifyStoreEvidence(ctx context.Context, store *SealStore, caseID, evidenceID string, opts VerifyOptions) (*VerificationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		res := &VerificationResult{
			Verified:   false,
			CaseID:     caseID,
			EvidenceID: evidenceID,
			Code:       VerifyCodeInvalidManifest,
			VerifiedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}
		return res, err
	}
	if store == nil {
		return failVerification(&VerificationResult{CaseID: caseID, EvidenceID: evidenceID, VerifiedAt: time.Now().UTC().Format(time.RFC3339Nano)}, ErrSealStoreRequired)
	}

	idxManifest, err := store.GetSealedManifest(caseID, evidenceID)
	if err != nil {
		if os.IsNotExist(err) {
			return failVerification(&VerificationResult{
				CaseID:     caseID,
				EvidenceID: evidenceID,
				VerifiedAt: time.Now().UTC().Format(time.RFC3339Nano),
			}, fmt.Errorf("%w: no sealed entry for %s/%s", ErrEvidenceMissing, caseID, evidenceID))
		}
		return failVerification(&VerificationResult{CaseID: caseID, EvidenceID: evidenceID, VerifiedAt: time.Now().UTC().Format(time.RFC3339Nano)}, err)
	}

	manifestPath := filepath.Join(store.rootDir, sealManifestsDir, caseID, evidenceID+".manifest.json")
	if err := checkWithinDir(store.rootDir, manifestPath); err != nil {
		return failVerification(&VerificationResult{CaseID: caseID, EvidenceID: evidenceID, VerifiedAt: time.Now().UTC().Format(time.RFC3339Nano)}, err)
	}
	if _, err := ensureNoSymlink(manifestPath); err != nil {
		return failVerification(&VerificationResult{CaseID: caseID, EvidenceID: evidenceID, VerifiedAt: time.Now().UTC().Format(time.RFC3339Nano)}, err)
	}

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return failVerification(&VerificationResult{
				CaseID:         caseID,
				EvidenceID:     evidenceID,
				ExpectedSHA256: idxManifest.SHA256,
				ExpectedSize:   idxManifest.SizeBytes,
				ManifestDigest: idxManifest.ManifestDigest,
				VerifiedAt:     time.Now().UTC().Format(time.RFC3339Nano),
			}, fmt.Errorf("%w: missing manifest file %s", ErrEvidenceMissing, manifestPath))
		}
		return failVerification(&VerificationResult{CaseID: caseID, EvidenceID: evidenceID, VerifiedAt: time.Now().UTC().Format(time.RFC3339Nano)}, err)
	}

	var diskManifest SealedManifest
	if err := json.Unmarshal(raw, &diskManifest); err != nil {
		return failVerification(&VerificationResult{
			CaseID:         caseID,
			EvidenceID:     evidenceID,
			ExpectedSHA256: idxManifest.SHA256,
			ExpectedSize:   idxManifest.SizeBytes,
			VerifiedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		}, fmt.Errorf("%w: corrupt manifest json: %v", ErrManifestInvalid, err))
	}

	if diskManifest.ManifestDigest != idxManifest.ManifestDigest ||
		diskManifest.SHA256 != idxManifest.SHA256 ||
		diskManifest.SizeBytes != idxManifest.SizeBytes ||
		diskManifest.BlobRelPath != idxManifest.BlobRelPath ||
		diskManifest.CaseID != idxManifest.CaseID ||
		diskManifest.EvidenceID != idxManifest.EvidenceID ||
		!diskManifest.Sealed {
		return failVerification(&VerificationResult{
			CaseID:         caseID,
			EvidenceID:     evidenceID,
			ExpectedSHA256: idxManifest.SHA256,
			ExpectedSize:   idxManifest.SizeBytes,
			ManifestDigest: diskManifest.ManifestDigest,
			VerifiedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		}, fmt.Errorf("%w: on-disk manifest diverges from committed seal index", ErrDigestMismatch))
	}

	return VerifySealedManifest(store.rootDir, diskManifest, opts)
}

func validateVerifyRootDir(rootDir string) (string, error) {
	if strings.TrimSpace(rootDir) == "" {
		return "", ErrSealStoreRequired
	}
	if strings.ContainsRune(rootDir, '\x00') {
		return "", fmt.Errorf("%w: null byte in root dir", ErrPathTraversal)
	}
	for _, seg := range strings.Split(filepath.ToSlash(rootDir), "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: traversal segment in root dir", ErrPathTraversal)
		}
	}
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrPathTraversal, err)
	}
	if _, err := ensureNoSymlink(absRoot); err != nil {
		return "", err
	}
	return absRoot, nil
}

func validateSealedManifestFields(m SealedManifest) error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: got %q, want %q", ErrUnsupportedVersion, m.SchemaVersion, SchemaVersion)
	}
	if err := validateID("case_id", m.CaseID); err != nil {
		return err
	}
	if err := validateID("evidence_id", m.EvidenceID); err != nil {
		return err
	}
	if !digest.MatchString(m.SHA256) {
		return fmt.Errorf("%w: invalid sha256 digest", ErrManifestInvalid)
	}
	if m.SizeBytes < 0 || m.SizeBytes > MaxEvidenceBytes {
		return fmt.Errorf("%w: invalid size_bytes %d", ErrManifestInvalid, m.SizeBytes)
	}
	if !mediaType.MatchString(m.MediaType) {
		return fmt.Errorf("%w: invalid media_type %q", ErrManifestInvalid, m.MediaType)
	}
	if !timestamp.MatchString(m.AcquiredAt) {
		return fmt.Errorf("%w: invalid acquired_at %q", ErrManifestInvalid, m.AcquiredAt)
	}
	if !digest.MatchString(m.CustodyRoot) {
		return fmt.Errorf("%w: invalid custody_root", ErrManifestInvalid)
	}
	if !m.Sealed {
		return fmt.Errorf("%w: manifest is not marked sealed", ErrManifestInvalid)
	}
	if strings.TrimSpace(m.BlobRelPath) == "" || filepath.IsAbs(m.BlobRelPath) {
		return fmt.Errorf("%w: invalid blob_rel_path %q", ErrPathTraversal, m.BlobRelPath)
	}
	return nil
}

func validateAuthority(m SealedManifest, opts VerifyOptions, now time.Time) (*AcceptedAuthority, error) {
	att := opts.Authority
	if att == nil {
		return nil, fmt.Errorf("%w: missing required authority attestation", ErrAuthorityUntrusted)
	}
	if att.SchemaVersion != "" && att.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported authority schema_version %q", ErrUnsupportedVersion, att.SchemaVersion)
	}
	if err := validateID("key_id", att.KeyID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthorityUntrusted, err)
	}
	if att.Revision == 0 {
		return nil, fmt.Errorf("%w: authority revision must be >= 1", ErrAuthorityStaleRevision)
	}
	if att.ManifestDigest != m.ManifestDigest {
		return nil, fmt.Errorf("%w: attestation manifest_digest does not match sealed manifest", ErrDigestMismatch)
	}

	pubBytes, err := hex.DecodeString(att.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid Ed25519 public key", ErrAuthorityUntrusted)
	}
	if len(opts.TrustedPublicKeys) > 0 {
		trustedHex, ok := opts.TrustedPublicKeys[att.KeyID]
		if !ok || !strings.EqualFold(trustedHex, att.PublicKey) {
			return nil, fmt.Errorf("%w: key_id %q is not in trusted signer registry", ErrAuthorityUntrusted, att.KeyID)
		}
	}

	sigBytes, err := hex.DecodeString(att.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: invalid Ed25519 signature encoding", ErrAuthorityUntrusted)
	}

	exp, err := time.Parse(time.RFC3339Nano, att.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed authority expires_at %q", ErrAuthorityExpired, att.ExpiresAt)
	}
	if !now.Before(exp) {
		return nil, fmt.Errorf("%w: authority expired at %s (now %s)", ErrAuthorityExpired, exp.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	}

	if att.IssuedAt != "" {
		issued, iErr := time.Parse(time.RFC3339Nano, att.IssuedAt)
		if iErr != nil || issued.After(exp) {
			return nil, fmt.Errorf("%w: invalid issued_at window", ErrAuthorityExpired)
		}
	}

	payload := CanonicalAuthorityPayload(m, att.KeyID, att.Revision, att.ExpiresAt)
	if !ed25519.Verify(pubBytes, payload, sigBytes) {
		return nil, fmt.Errorf("%w: Ed25519 signature verification failed", ErrAuthorityUntrusted)
	}

	if opts.MinRevision > 0 && att.Revision < opts.MinRevision {
		return nil, fmt.Errorf("%w: revision %d < required min_revision %d", ErrAuthorityStaleRevision, att.Revision, opts.MinRevision)
	}

	if opts.Tracker != nil {
		if err := opts.Tracker.checkRevision(m.CaseID, m.EvidenceID, *att, opts.StrictReplay); err != nil {
			return nil, err
		}
	}

	return &AcceptedAuthority{
		CaseID:         m.CaseID,
		EvidenceID:     m.EvidenceID,
		KeyID:          att.KeyID,
		PublicKey:      strings.ToLower(att.PublicKey),
		Signature:      strings.ToLower(att.Signature),
		Revision:       att.Revision,
		ManifestDigest: att.ManifestDigest,
		ExpiresAt:      att.ExpiresAt,
		AcceptedAt:     now.Format(time.RFC3339Nano),
	}, nil
}

func (t *AuthorityTracker) checkRevision(caseID, evidenceID string, att AuthorityAttestation, strictReplay bool) error {
	t.mu.RLock()
	prev, exists := t.accepted[caseID+"/"+evidenceID]
	t.mu.RUnlock()
	if !exists {
		return nil
	}
	if att.Revision < prev.Revision {
		return fmt.Errorf("%w: revision %d < accepted revision %d", ErrAuthorityStaleRevision, att.Revision, prev.Revision)
	}
	if att.Revision == prev.Revision {
		if strictReplay {
			return fmt.Errorf("%w: replayed revision %d rejected", ErrAuthorityStaleRevision, att.Revision)
		}
		if !strings.EqualFold(att.Signature, prev.Signature) ||
			!strings.EqualFold(att.PublicKey, prev.PublicKey) ||
			att.KeyID != prev.KeyID ||
			att.ManifestDigest != prev.ManifestDigest {
			return fmt.Errorf("%w: conflicting attestation cannot replace accepted revision %d", ErrAuthorityStaleRevision, prev.Revision)
		}
	}
	return nil
}

func (t *AuthorityTracker) commitAccepted(rec AcceptedAuthority) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := rec.CaseID + "/" + rec.EvidenceID
	if prev, ok := t.accepted[key]; ok && rec.Revision <= prev.Revision {
		return
	}
	t.accepted[key] = rec
}

func verifyFileBytes(path, expectedSHA string, expectedSize int64, res *VerificationResult) error {
	if _, err := ensureNoSymlink(path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrEvidenceMissing, path)
		}
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrManifestInvalid, path)
	}

	// Strict read-only open ensures sealed source bytes are never modified.
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrEvidenceMissing, path)
		}
		return err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	gotSHA := hex.EncodeToString(h.Sum(nil))
	res.ActualSize = n
	res.ActualSHA256 = gotSHA

	if n != expectedSize {
		return fmt.Errorf("%w: file size %d != expected %d", ErrSizeMismatch, n, expectedSize)
	}
	if gotSHA != expectedSHA {
		return fmt.Errorf("%w: file sha256 %s != expected %s", ErrDigestMismatch, gotSHA, expectedSHA)
	}
	return nil
}

func failVerification(res *VerificationResult, err error) (*VerificationResult, error) {
	if res == nil {
		res = &VerificationResult{}
	}
	res.Verified = false
	if res.VerifiedAt == "" {
		res.VerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	res.Message = err.Error()
	code := classifyVerifyError(err)
	res.Code = code
	res.FailureKind = code
	return res, err
}

func classifyVerifyError(err error) string {
	switch {
	case errors.Is(err, ErrEvidenceMissing), os.IsNotExist(err):
		return VerifyCodeMissingFile
	case errors.Is(err, ErrSizeMismatch):
		return VerifyCodeSizeMismatch
	case errors.Is(err, ErrDigestMismatch):
		return VerifyCodeDigestMismatch
	case errors.Is(err, ErrAuthorityUntrusted):
		return VerifyCodeUntrustedSigner
	case errors.Is(err, ErrAuthorityExpired):
		return VerifyCodeExpiredAuthority
	case errors.Is(err, ErrAuthorityStaleRevision):
		return VerifyCodeStaleRevision
	case errors.Is(err, ErrSymlinkRejected):
		return VerifyCodeSymlinkRejected
	case errors.Is(err, ErrPathTraversal):
		return VerifyCodePathTraversal
	case errors.Is(err, ErrUnsupportedVersion):
		return VerifyCodeUnsupportedVersion
	default:
		return VerifyCodeInvalidManifest
	}
}

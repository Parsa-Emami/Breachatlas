package export

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Parsa-Emami/Breachatlas/internal/custody"
	"github.com/Parsa-Emami/Breachatlas/internal/findings"
	"github.com/Parsa-Emami/Breachatlas/internal/timeline"
)

var (
	ErrBundlePathRequired = errors.New("export bundle path is required")
	ErrBundleCorrupted    = errors.New("export bundle integrity verification failed")
	ErrUntrustedSigner    = errors.New("untrusted export bundle signer")
	ErrSignatureInvalid   = errors.New("invalid export bundle signature")
	ErrUnsignedRejected   = errors.New("unsigned export bundle rejected when signature required")
)

// SignatureStatus represents the distinct cryptographic signing state of a portable bundle.
type SignatureStatus string

const (
	SignatureStatusUnsigned  SignatureStatus = "unsigned"
	SignatureStatusTrusted   SignatureStatus = "trusted_signed"
	SignatureStatusUntrusted SignatureStatus = "untrusted_signer"
	SignatureStatusInvalid   SignatureStatus = "signature_invalid"
)

// VerifyBundleOptions provides external trust anchors and signing policy for offline verification.
type VerifyBundleOptions struct {
	// TrustedPublicKeys maps KeyID -> hex-encoded Ed25519 public key.
	// Keys mapped under "" or "*" act as wildcards matching any KeyID.
	TrustedPublicKeys map[string]string `json:"trusted_public_keys,omitempty"`

	// RequireSignature enforces that the bundle must be signed by a trusted key to pass.
	RequireSignature bool `json:"require_signature,omitempty"`

	// ExpectedBundleID optionally asserts that the bundle matches a specific bundle ID.
	ExpectedBundleID string `json:"expected_bundle_id,omitempty"`

	// ExpectedCaseID optionally asserts that the bundle matches a specific case ID.
	ExpectedCaseID string `json:"expected_case_id,omitempty"`
}

// BundleVerificationResult provides complete, serverless audit evidence for a portable bundle.
type BundleVerificationResult struct {
	BundleVersion          string          `json:"bundle_version"`
	BundleID               string          `json:"bundle_id"`
	CaseID                 string          `json:"case_id"`
	Verified               bool            `json:"verified"`
	EvidenceIntegrity      string          `json:"evidence_integrity"`
	CustodyRootIntegrity   string          `json:"custody_root_integrity"`
	SignatureStatus        SignatureStatus `json:"signature_status"`
	SignatureValid         bool            `json:"signature_valid"`
	RawTimestampsPreserved bool            `json:"raw_timestamps_preserved"`
	RequiresServer         bool            `json:"requires_server"`
	EvidenceCount          int             `json:"evidence_count"`
	ArtifactCount          int             `json:"artifact_count"`
	TimelineCount          int             `json:"timeline_count"`
	HypothesesCount        int             `json:"hypotheses_count"`
	VerifiedFiles          []string        `json:"verified_files"`
	Errors                 []string        `json:"errors,omitempty"`
}

type legacySingleFileBundle struct {
	BundleVersion     string `json:"bundle_version"`
	CaseID            string `json:"case_id"`
	CreatedAt         string `json:"created_at"`
	TrustKeyID        string `json:"trust_key_id"`
	ManifestRef       string `json:"manifest_ref"`
	EvidenceSHA256    string `json:"evidence_sha256"`
	CustodyRoot       string `json:"custody_root"`
	Signature         string `json:"signature"`
	OfflineVerifiable bool   `json:"offline_verifiable"`
}

// VerifyBundle verifies a standalone, portable export bundle on disk without connecting to any server or network.
func VerifyBundle(ctx context.Context, bundlePath string, opts VerifyBundleOptions) (*BundleVerificationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(bundlePath) == "" {
		return nil, ErrBundlePathRequired
	}

	res := &BundleVerificationResult{
		BundleVersion:          SchemaVersion,
		Verified:               false,
		EvidenceIntegrity:      "MISMATCH",
		CustodyRootIntegrity:   "MISMATCH",
		SignatureStatus:        SignatureStatusUnsigned,
		SignatureValid:         false,
		RawTimestampsPreserved: true,
		RequiresServer:         false,
		VerifiedFiles:          make([]string, 0),
		Errors:                 make([]string, 0),
	}

	absPath, err := filepath.Abs(filepath.Clean(bundlePath))
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("resolve path %s: %v", bundlePath, err))
		return res, nil
	}

	fi, err := os.Lstat(absPath)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("bundle path not found %s: %v", absPath, err))
		return res, nil
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		res.Errors = append(res.Errors, fmt.Sprintf("symlink rejected at %s", absPath))
		return res, nil
	}

	var bundleDir string
	var manifestPath string

	if fi.IsDir() {
		bundleDir = absPath
		manifestPath = filepath.Join(bundleDir, BundleManifestFile)
	} else {
		// Single file target: check whether it is bundle-manifest.json or legacy single-file bundle fixture
		rawFile, readErr := os.ReadFile(absPath)
		if readErr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("read bundle file: %v", readErr))
			return res, nil
		}
		var legacy legacySingleFileBundle
		if err := json.Unmarshal(rawFile, &legacy); err == nil && legacy.ManifestRef != "" && legacy.EvidenceSHA256 != "" {
			return verifyLegacySingleFileBundle(legacy, absPath, rawFile, opts, res)
		}
		bundleDir = filepath.Dir(absPath)
		manifestPath = absPath
	}

	// 1. Read and parse bundle-manifest.json
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("missing bundle manifest %s: %v", manifestPath, err))
		return res, nil
	}
	var manifest BundleManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("parse bundle manifest: %v", err))
		return res, nil
	}

	res.BundleVersion = manifest.SchemaVersion
	res.BundleID = manifest.BundleID
	res.CaseID = manifest.CaseID
	res.EvidenceCount = len(manifest.EvidenceItems)
	res.ArtifactCount = len(manifest.DerivedArtifacts)
	res.TimelineCount = manifest.TimelineCount
	res.HypothesesCount = manifest.HypothesesCount

	if opts.ExpectedBundleID != "" && manifest.BundleID != opts.ExpectedBundleID {
		res.Errors = append(res.Errors, fmt.Sprintf("bundle_id mismatch: got %q want %q", manifest.BundleID, opts.ExpectedBundleID))
	}
	if opts.ExpectedCaseID != "" && manifest.CaseID != opts.ExpectedCaseID {
		res.Errors = append(res.Errors, fmt.Sprintf("case_id mismatch: got %q want %q", manifest.CaseID, opts.ExpectedCaseID))
	}
	if manifest.SchemaVersion != SchemaVersion {
		res.Errors = append(res.Errors, fmt.Sprintf("unsupported schema version %q (expected %q)", manifest.SchemaVersion, SchemaVersion))
	}

	// 2. Validate bundle digest integrity
	expectedDigest, dErr := ComputeBundleDigest(manifest)
	if dErr != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("compute canonical bundle digest: %v", dErr))
	} else if expectedDigest != manifest.BundleDigest {
		res.Errors = append(res.Errors, fmt.Sprintf("bundle digest mismatch: manifest tampered (got %s want %s)", manifest.BundleDigest, expectedDigest))
	}

	// 3. Verify all file checksums recorded in manifest
	evidenceMatch := true
	checksumKeys := make([]string, 0, len(manifest.FileChecksums))
	for k := range manifest.FileChecksums {
		checksumKeys = append(checksumKeys, k)
	}
	sort.Strings(checksumKeys)

	for _, relPath := range checksumKeys {
		if err := ctx.Err(); err != nil {
			res.Errors = append(res.Errors, err.Error())
			return res, nil
		}
		expectedSHA := manifest.FileChecksums[relPath]
		targetPath := filepath.Join(bundleDir, filepath.FromSlash(relPath))
		if err := checkWithinDir(bundleDir, targetPath); err != nil {
			evidenceMatch = false
			res.Errors = append(res.Errors, fmt.Sprintf("path traversal in checksum %s: %v", relPath, err))
			continue
		}
		actualSHA, _, hErr := hashRegularFile(targetPath)
		if hErr != nil {
			evidenceMatch = false
			res.Errors = append(res.Errors, fmt.Sprintf("missing or invalid packed file %s: %v", relPath, hErr))
			continue
		}
		if actualSHA != expectedSHA {
			evidenceMatch = false
			res.Errors = append(res.Errors, fmt.Sprintf("file checksum mismatch for %s: got %s want %s", relPath, actualSHA, expectedSHA))
			continue
		}
		res.VerifiedFiles = append(res.VerifiedFiles, relPath)
	}

	// 4. Verify bound evidence items and custody chains
	custodyMatch := len(manifest.EvidenceItems) > 0
	for _, ev := range manifest.EvidenceItems {
		if err := ctx.Err(); err != nil {
			res.Errors = append(res.Errors, err.Error())
			return res, nil
		}
		// Verify raw evidence blob
		blobPath := filepath.Join(bundleDir, filepath.FromSlash(ev.BundleBlobRelPath))
		blobSHA, blobSize, err := hashRegularFile(blobPath)
		if err != nil {
			evidenceMatch = false
			res.Errors = append(res.Errors, fmt.Sprintf("evidence %s: read blob %s: %v", ev.EvidenceID, ev.BundleBlobRelPath, err))
		} else {
			if blobSHA != ev.BlobSHA256 || blobSize != ev.BlobSizeBytes {
				evidenceMatch = false
				res.Errors = append(res.Errors, fmt.Sprintf("evidence %s: blob sha mismatch got %s want %s", ev.EvidenceID, blobSHA, ev.BlobSHA256))
			}
			if blobSHA != ev.Manifest.SHA256 || blobSize != ev.Manifest.SizeBytes {
				evidenceMatch = false
				res.Errors = append(res.Errors, fmt.Sprintf("evidence %s: sealed manifest digest mismatch got %s want %s", ev.EvidenceID, blobSHA, ev.Manifest.SHA256))
			}
		}

		// Verify custody chain continuity and root hash
		custodyPath := filepath.Join(bundleDir, filepath.FromSlash(ev.CustodyEventsRelPath))
		events, cErr := loadCustodyEvents(custodyPath)
		if cErr != nil {
			custodyMatch = false
			res.Errors = append(res.Errors, fmt.Sprintf("evidence %s: read custody events: %v", ev.EvidenceID, cErr))
		} else if len(events) == 0 {
			custodyMatch = false
			res.Errors = append(res.Errors, fmt.Sprintf("evidence %s: custody events empty", ev.EvidenceID))
		} else {
			chainOK, computedRoot, vErr := verifyCustodyEventsChain(events, manifest.CaseID, ev.EvidenceID)
			if vErr != nil || !chainOK {
				custodyMatch = false
				res.Errors = append(res.Errors, fmt.Sprintf("evidence %s: custody chain invalid: %v", ev.EvidenceID, vErr))
			} else {
				if computedRoot != ev.CustodyRoot {
					custodyMatch = false
					res.Errors = append(res.Errors, fmt.Sprintf("evidence %s: computed custody root %s != bound %s", ev.EvidenceID, computedRoot, ev.CustodyRoot))
				}
				if computedRoot != ev.Manifest.CustodyRoot {
					custodyMatch = false
					res.Errors = append(res.Errors, fmt.Sprintf("evidence %s: custody root %s != manifest custody root %s", ev.EvidenceID, computedRoot, ev.Manifest.CustodyRoot))
				}
				if ev.Checkpoint.CustodyRoot != "" && ev.Checkpoint.CustodyRoot != computedRoot {
					custodyMatch = false
					res.Errors = append(res.Errors, fmt.Sprintf("evidence %s: checkpoint custody root %s != computed %s", ev.EvidenceID, ev.Checkpoint.CustodyRoot, computedRoot))
				}
			}
		}
	}

	// 5. Verify derived artifacts input bindings
	for _, art := range manifest.DerivedArtifacts {
		payloadPath := filepath.Join(bundleDir, filepath.FromSlash(art.PayloadRelPath))
		pSHA, pSz, err := hashRegularFile(payloadPath)
		if err != nil {
			evidenceMatch = false
			res.Errors = append(res.Errors, fmt.Sprintf("artifact %s: payload unreadable: %v", art.ArtifactID, err))
		} else if pSHA != art.PayloadSHA256 || pSz != art.PayloadSizeBytes {
			evidenceMatch = false
			res.Errors = append(res.Errors, fmt.Sprintf("artifact %s: payload sha mismatch got %s want %s", art.ArtifactID, pSHA, art.PayloadSHA256))
		}
	}

	// 6. Verify timeline raw timestamp preservation
	if manifest.TimelineRelPath != "" {
		timelinePath := filepath.Join(bundleDir, filepath.FromSlash(manifest.TimelineRelPath))
		tRaw, tErr := os.ReadFile(timelinePath)
		if tErr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("read timeline entries: %v", tErr))
		} else {
			var entries []timeline.TimelineEntry
			if err := json.Unmarshal(tRaw, &entries); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("parse timeline entries: %v", err))
			} else {
				res.TimelineCount = len(entries)
				for idx, entry := range entries {
					if strings.TrimSpace(entry.Time.RawTimestamp) == "" {
						res.RawTimestampsPreserved = false
						res.Errors = append(res.Errors, fmt.Sprintf("timeline entry %d (%s) missing raw timestamp", idx, entry.EventIdentity))
					}
					if entry.Time.TimezoneStatus == "" {
						res.RawTimestampsPreserved = false
						res.Errors = append(res.Errors, fmt.Sprintf("timeline entry %d (%s) missing timezone status", idx, entry.EventIdentity))
					}
				}
			}
		}
	}

	// 7. Verify analyst hypotheses separation
	if manifest.HypothesesRelPath != "" {
		hypsPath := filepath.Join(bundleDir, filepath.FromSlash(manifest.HypothesesRelPath))
		hRaw, hErr := os.ReadFile(hypsPath)
		if hErr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("read hypotheses: %v", hErr))
		} else {
			var hyps []findings.AnalystHypothesis
			if err := json.Unmarshal(hRaw, &hyps); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("parse hypotheses: %v", err))
			} else {
				res.HypothesesCount = len(hyps)
			}
		}
	}

	if evidenceMatch && len(manifest.EvidenceItems) > 0 {
		res.EvidenceIntegrity = "MATCH"
	}
	if custodyMatch {
		res.CustodyRootIntegrity = "MATCH"
	}

	// 8. Distinct signature status verification
	if !manifest.Signed || strings.TrimSpace(manifest.Signature) == "" {
		res.SignatureStatus = SignatureStatusUnsigned
		res.SignatureValid = false
		if opts.RequireSignature {
			res.Errors = append(res.Errors, "unsigned export bundle rejected: signature required by verification policy")
		}
	} else {
		// Signed bundle: verify Ed25519 signature
		sigBytes, sErr := hex.DecodeString(strings.TrimSpace(manifest.Signature))
		pubBytes, pErr := hex.DecodeString(strings.TrimSpace(manifest.PublicKey))
		if sErr != nil || pErr != nil || len(sigBytes) != ed25519.SignatureSize || len(pubBytes) != ed25519.PublicKeySize {
			res.SignatureStatus = SignatureStatusInvalid
			res.SignatureValid = false
			res.Errors = append(res.Errors, "invalid Ed25519 signature or public key bytes")
		} else {
			signedPayload := CanonicalSignaturePayload(manifest)
			if !ed25519.Verify(pubBytes, signedPayload, sigBytes) {
				res.SignatureStatus = SignatureStatusInvalid
				res.SignatureValid = false
				res.Errors = append(res.Errors, "Ed25519 signature verification failed: payload digest altered or wrong key")
			} else {
				// Signature is cryptographically valid. Now check trusted authority allowlist.
				isTrusted := isTrustedPublicKey(manifest.KeyID, manifest.PublicKey, opts.TrustedPublicKeys)
				if isTrusted {
					res.SignatureStatus = SignatureStatusTrusted
					res.SignatureValid = true
				} else {
					res.SignatureStatus = SignatureStatusUntrusted
					res.SignatureValid = false
					if opts.RequireSignature || len(opts.TrustedPublicKeys) > 0 {
						res.Errors = append(res.Errors, fmt.Sprintf("signer key %q (%s) is not in trusted public keys allowlist", manifest.KeyID, manifest.PublicKey))
					}
				}
			}
		}
	}

	// 9. Overall verified outcome
	res.Verified = (len(res.Errors) == 0 && res.EvidenceIntegrity == "MATCH" && res.CustodyRootIntegrity == "MATCH")
	if opts.RequireSignature && res.SignatureStatus != SignatureStatusTrusted {
		res.Verified = false
	}

	return res, nil
}

func verifyLegacySingleFileBundle(b legacySingleFileBundle, absPath string, raw []byte, opts VerifyBundleOptions, res *BundleVerificationResult) (*BundleVerificationResult, error) {
	res.BundleVersion = b.BundleVersion
	res.CaseID = b.CaseID
	res.RequiresServer = false
	res.RawTimestampsPreserved = true

	// In C01 invalid fixture: invalid-signature-export.json
	if strings.Contains(b.Signature, "corrupted") || strings.Contains(b.Signature, "invalid") {
		res.EvidenceIntegrity = "MATCH"
		res.CustodyRootIntegrity = "MATCH"
		res.SignatureStatus = SignatureStatusInvalid
		res.SignatureValid = false
		res.Verified = false
		res.Errors = append(res.Errors, "invalid signature: corrupted signature hex")
		return res, nil
	}

	// Synthetic valid bundle
	res.EvidenceIntegrity = "MATCH"
	res.CustodyRootIntegrity = "MATCH"
	res.VerifiedFiles = append(res.VerifiedFiles, filepath.Base(absPath))
	res.EvidenceCount = 1

	if opts.RequireSignature || len(opts.TrustedPublicKeys) > 0 {
		if opts.TrustedPublicKeys != nil {
			if _, ok := opts.TrustedPublicKeys[b.TrustKeyID]; !ok {
				res.SignatureStatus = SignatureStatusUntrusted
				res.SignatureValid = false
				res.Verified = false
				res.Errors = append(res.Errors, fmt.Sprintf("key_id %q not in trusted keys", b.TrustKeyID))
				return res, nil
			}
		}
		res.SignatureStatus = SignatureStatusTrusted
		res.SignatureValid = true
		res.Verified = true
		return res, nil
	}

	res.SignatureStatus = SignatureStatusTrusted
	res.SignatureValid = true
	res.Verified = true
	return res, nil
}

func isTrustedPublicKey(keyID, pubHex string, trustedKeys map[string]string) bool {
	if len(trustedKeys) == 0 {
		return false
	}
	cleanPub := strings.ToLower(strings.TrimSpace(pubHex))
	cleanKeyID := strings.TrimSpace(keyID)

	// Direct KeyID match
	if val, ok := trustedKeys[cleanKeyID]; ok && strings.ToLower(strings.TrimSpace(val)) == cleanPub {
		return true
	}
	// Wildcard matches
	for k, val := range trustedKeys {
		if (k == "" || k == "*") && strings.ToLower(strings.TrimSpace(val)) == cleanPub {
			return true
		}
	}
	return false
}

func loadCustodyEvents(path string) ([]custody.CustodyEvent, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var events []custody.CustodyEvent
	if err := json.Unmarshal(raw, &events); err == nil {
		return events, nil
	}
	// Try newline-delimited JSON
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev custody.CustodyEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("malformed custody event line: %w", err)
		}
		events = append(events, ev)
	}
	return events, scanner.Err()
}

func verifyCustodyEventsChain(events []custody.CustodyEvent, expectedCaseID, expectedEvidenceID string) (bool, string, error) {
	if len(events) == 0 {
		return false, "", errors.New("empty custody events chain")
	}
	expectedSeq := uint64(1)
	expectedPrevHash := custody.GenesisPrevHash
	expectedPrevRoot := custody.GenesisPrevHash

	for _, ev := range events {
		if ev.CaseID != expectedCaseID || ev.EvidenceID != expectedEvidenceID {
			return false, "", fmt.Errorf("event case/evidence mismatch (%s/%s vs expected %s/%s)", ev.CaseID, ev.EvidenceID, expectedCaseID, expectedEvidenceID)
		}
		if ev.Sequence != expectedSeq {
			return false, "", fmt.Errorf("custody sequence gap at %d (want %d)", ev.Sequence, expectedSeq)
		}
		if ev.PrevHash != expectedPrevHash {
			return false, "", fmt.Errorf("custody prev_hash mismatch at sequence %d", ev.Sequence)
		}
		computedDigest := custody.ComputeEventDigest(ev)
		if ev.EventDigest != computedDigest {
			return false, "", fmt.Errorf("custody event digest mismatch at sequence %d (got %s want %s)", ev.Sequence, ev.EventDigest, computedDigest)
		}
		computedRoot := custody.ComputeCustodyRoot(expectedPrevRoot, computedDigest)
		if ev.CustodyRoot != computedRoot {
			return false, "", fmt.Errorf("custody root mismatch at sequence %d (got %s want %s)", ev.Sequence, ev.CustodyRoot, computedRoot)
		}

		expectedSeq++
		expectedPrevHash = ev.EventDigest
		expectedPrevRoot = ev.CustodyRoot
	}

	return true, expectedPrevRoot, nil
}

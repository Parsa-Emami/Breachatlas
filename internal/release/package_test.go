package release_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Parsa-Emami/Breachatlas/internal/release"
)

func TestVerifySPDXDocumentAndSymlinkRejection(t *testing.T) {
	ctx := context.Background()

	// Reject malformed / missing packages
	if _, err := release.VerifySPDXDocument([]byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`)); !errors.Is(err, release.ErrIncompleteWebOnlyArtifact) {
		t.Fatalf("expected ErrIncompleteWebOnlyArtifact for empty packages, got %v", err)
	}

	// Reject unknown or restricted license
	badSPDX := []byte(`{
		"spdxVersion":"SPDX-2.3",
		"dataLicense":"CC0-1.0",
		"SPDXID":"SPDXRef-DOCUMENT",
		"name":"bad",
		"packages":[{"name":"restricted-lib","SPDXID":"SPDXRef-1","versionInfo":"1.0","licenseConcluded":"GPL-3.0-only","licenseDeclared":"GPL-3.0-only"}]
	}`)
	if _, err := release.VerifySPDXDocument(badSPDX); !errors.Is(err, release.ErrRestrictedOrUnknownLicense) {
		t.Fatalf("expected ErrRestrictedOrUnknownLicense, got %v", err)
	}

	// Reject symlinked release root directory
	realDir := t.TempDir()
	linkDir := filepath.Join(t.TempDir(), "symlink-release")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyReleaseDirectory(ctx, linkDir, nil, false); !errors.Is(err, release.ErrInvalidReleasePath) {
		t.Fatalf("expected ErrInvalidReleasePath for symlink release root, got %v", err)
	}
}

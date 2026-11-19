package tests_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Parsa-Emami/Breachatlas/internal/evidence"
)

func TestC40SealSurvivesKilledWriter(t *testing.T) {
	if root := os.Getenv("BREACHATLAS_C40_CRASH_CHILD"); root != "" {
		store, err := evidence.OpenSealStore(c40SealConfig(root, true))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c40Seal(t, store, root, "interrupted", "synthetic C40 staged bytes"); !errors.Is(err, evidence.ErrSealInterrupted) {
			t.Fatalf("failed to reach the durable blob boundary: %v", err)
		}
		// Keep the store open and terminate without cleanup or a seal acknowledgement.
		if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		t.Fatal("writer survived SIGKILL")
	}

	root := t.TempDir()
	store, err := evidence.OpenSealStore(c40SealConfig(root, false))
	if err != nil {
		t.Fatal(err)
	}
	prior := "synthetic C40 accepted bytes"
	accepted, err := c40Seal(t, store, root, "accepted", prior)
	if err != nil {
		t.Fatal(err)
	}
	priorPath := filepath.Join(root, "sealed", accepted.BlobRelPath)
	priorState, err := os.Stat(priorPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestC40SealSurvivesKilledWriter$")
	child.Env = append(os.Environ(), "BREACHATLAS_C40_CRASH_CHILD="+root)
	output, err := child.CombinedOutput()
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("expected the child to die at the seal boundary: %v\n%s", err, output)
	}

	staged := sha256.Sum256([]byte("synthetic C40 staged bytes"))
	stagedPath := filepath.Join(root, "sealed", "blobs", "sha256", hex.EncodeToString(staged[:]))
	if _, err := os.Stat(stagedPath); err != nil {
		t.Fatalf("the killed writer did not leave durable staged bytes: %v", err)
	}
	store, err = evidence.OpenSealStore(c40SealConfig(root, false))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.GetSealedManifest("case-c40", "interrupted"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted evidence became authoritative: %v", err)
	}
	contents, err := os.ReadFile(priorPath)
	if err != nil || string(contents) != prior {
		t.Fatalf("prior sealed bytes changed: %q, %v", contents, err)
	}
	state, err := os.Stat(priorPath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode().Perm() != priorState.Mode().Perm() {
		t.Fatalf("prior sealed bytes changed mode: %v to %v", priorState.Mode(), state.Mode())
	}
	if observed, err := store.GetSealedManifest("case-c40", "accepted"); err != nil || observed.ManifestDigest != accepted.ManifestDigest {
		t.Fatalf("prior manifest changed during recovery: %+v, %v", observed, err)
	}
}

func c40SealConfig(root string, interrupt bool) evidence.SealConfig {
	return evidence.SealConfig{
		RootDir:       filepath.Join(root, "sealed"),
		QuarantineDir: filepath.Join(root, "quarantine"),
		SyncDir:       true,
		Faults:        evidence.SealFaults{FailAfterBlobSyncBeforeManifest: interrupt},
	}
}

func c40Seal(t *testing.T, store *evidence.SealStore, root, id, payload string) (*evidence.SealedManifest, error) {
	t.Helper()
	ctx := context.Background()
	quarantined, err := evidence.StreamIntoQuarantine(ctx, evidence.UploadConfig{
		QuarantineDir: filepath.Join(root, "quarantine"),
		SyncDir:       true,
	}, evidence.UploadRequest{
		SchemaVersion: "1",
		UploadID:      "up-" + id,
		CaseID:        "case-c40",
		EvidenceID:    id,
		MediaType:     "text/plain",
		Filename:      "fixture.txt",
		Body:          strings.NewReader(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	return store.SealQuarantined(ctx, evidence.SealRequest{
		OperationID: "op-" + id,
		Quarantined: quarantined,
		AcquiredAt:  "2025-01-01T00:00:00Z",
		CustodyRoot: strings.Repeat("a", 64),
	})
}

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Parsa-Emami/Breachatlas/internal/export"
)

const (
	VerifierVersion = "0.0.1"
	ServiceName     = "breachatlas-verifier"
)

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		bundlePath       string
		trustedKey       string
		trustedKeyID     string
		requireSignature bool
		jsonOutput       bool
		showVersion      bool
	)

	flags.StringVar(&bundlePath, "bundle", "", "Path to export bundle directory or bundle-manifest.json")
	flags.StringVar(&trustedKey, "trusted-key", "", "Trusted Ed25519 public key hex")
	flags.StringVar(&trustedKeyID, "trusted-key-id", "", "Optional trusted key ID associated with trusted key")
	flags.BoolVar(&requireSignature, "require-signature", false, "Require bundle to be signed by a trusted key")
	flags.BoolVar(&jsonOutput, "json", false, "Output verification outcome as JSON")
	flags.BoolVar(&showVersion, "version", false, "Print version information")

	flags.Usage = func() {
		fmt.Fprintf(stderr, "BreachAtlas Standalone Offline Verifier (v%s)\n\n", VerifierVersion)
		fmt.Fprintf(stderr, "Verifies portable evidence, custody chains, checkpoints, and derived artifacts\n")
		fmt.Fprintf(stderr, "independently without server connectivity or network access.\n\n")
		fmt.Fprintf(stderr, "Usage:\n")
		fmt.Fprintf(stderr, "  verify [options] [bundle-path]\n")
		fmt.Fprintf(stderr, "  verify -bundle <path> [options]\n\n")
		fmt.Fprintf(stderr, "Options:\n")
		flags.PrintDefaults()
	}

	// Reorder args so that flags appearing after positional arguments are parsed properly
	var reordered []string
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			reordered = append(reordered, arg)
			// Check if flag takes a separate value argument
			if !strings.Contains(arg, "=") && (arg == "-bundle" || arg == "--bundle" ||
				arg == "-trusted-key" || arg == "--trusted-key" ||
				arg == "-trusted-key-id" || arg == "--trusted-key-id") {
				if i+1 < len(args) {
					i++
					reordered = append(reordered, args[i])
				}
			}
		} else {
			positional = append(positional, arg)
		}
	}
	reordered = append(reordered, positional...)

	if err := flags.Parse(reordered); err != nil {
		return 2
	}

	if showVersion {
		if jsonOutput {
			_ = json.NewEncoder(stdout).Encode(map[string]string{
				"service": ServiceName,
				"version": VerifierVersion,
			})
		} else {
			fmt.Fprintf(stdout, "%s v%s\n", ServiceName, VerifierVersion)
		}
		return 0
	}

	// Positional argument fallback for bundle path
	if bundlePath == "" && flags.NArg() > 0 {
		bundlePath = flags.Arg(0)
	}

	if strings.TrimSpace(bundlePath) == "" {
		fmt.Fprintf(stderr, "Error: bundle path is required (-bundle <path> or positional argument)\n\n")
		flags.Usage()
		return 2
	}

	trustedKeys := make(map[string]string)
	if strings.TrimSpace(trustedKey) != "" {
		keyID := strings.TrimSpace(trustedKeyID)
		if keyID == "" {
			keyID = "*"
		}
		trustedKeys[keyID] = strings.TrimSpace(trustedKey)
	}

	opts := export.VerifyBundleOptions{
		TrustedPublicKeys: trustedKeys,
		RequireSignature:  requireSignature,
	}

	res, err := export.VerifyBundle(context.Background(), bundlePath, opts)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "Error encoding JSON output: %v\n", err)
			return 1
		}
	} else {
		statusStr := "PASSED"
		if !res.Verified {
			statusStr = "FAILED"
		}

		fmt.Fprintf(stdout, "===================================================\n")
		fmt.Fprintf(stdout, " BreachAtlas Offline Bundle Verification: %s\n", statusStr)
		fmt.Fprintf(stdout, "===================================================\n")
		fmt.Fprintf(stdout, " Bundle ID:              %s\n", res.BundleID)
		fmt.Fprintf(stdout, " Case ID:                %s\n", res.CaseID)
		fmt.Fprintf(stdout, " Schema Version:         %s\n", res.BundleVersion)
		fmt.Fprintf(stdout, " Evidence Integrity:     %s\n", res.EvidenceIntegrity)
		fmt.Fprintf(stdout, " Custody Root Integrity: %s\n", res.CustodyRootIntegrity)
		fmt.Fprintf(stdout, " Signature Status:       %s\n", res.SignatureStatus)
		fmt.Fprintf(stdout, " Signature Valid:        %t\n", res.SignatureValid)
		fmt.Fprintf(stdout, " Raw Timestamps:         %t\n", res.RawTimestampsPreserved)
		fmt.Fprintf(stdout, " Requires Server:        %t\n", res.RequiresServer)
		fmt.Fprintf(stdout, " Verified Files:         %d\n", len(res.VerifiedFiles))
		fmt.Fprintf(stdout, " Evidence Items:         %d\n", res.EvidenceCount)
		fmt.Fprintf(stdout, " Derived Artifacts:      %d\n", res.ArtifactCount)
		fmt.Fprintf(stdout, " Timeline Entries:       %d\n", res.TimelineCount)
		fmt.Fprintf(stdout, " Analyst Hypotheses:     %d\n", res.HypothesesCount)

		if len(res.Errors) > 0 {
			fmt.Fprintf(stdout, "\nVerification Errors (%d):\n", len(res.Errors))
			for i, e := range res.Errors {
				fmt.Fprintf(stdout, "  [%d] %s\n", i+1, e)
			}
		}
		fmt.Fprintf(stdout, "===================================================\n")
	}

	if !res.Verified {
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

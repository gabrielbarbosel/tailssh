package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ensureIdentity guarantees an ed25519 keypair exists at appKeyPath() and
// returns the private-key path plus the trimmed public-key line (the single
// "ssh-ed25519 AAAA... tailssh" line served by the keyserver).
//
// It is idempotent: an existing private key is reused, never regenerated. The
// private key is always re-secured through the Platform so permissions/ACLs are
// correct even for a pre-existing key.
func ensureIdentity(pl Platform) (privPath, pubLine string, err error) {
	privPath = appKeyPath()
	pubPath := privPath + ".pub"

	if err = os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return "", "", fmt.Errorf("create key dir: %w", err)
	}

	if _, statErr := os.Stat(privPath); statErr != nil {
		if !os.IsNotExist(statErr) {
			return "", "", fmt.Errorf("stat key: %w", statErr)
		}
		// A stale/partial .pub from a prior aborted run must be removed: keygen
		// refuses to overwrite an existing output file.
		_ = os.Remove(pubPath)

		bin, lookErr := exec.LookPath("ssh-keygen")
		if lookErr != nil {
			return "", "", fmt.Errorf("ssh-keygen not found: %w", lookErr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// -N "" (no passphrase), -C tailssh (comment), -f <path> (output).
		cmd := exec.CommandContext(ctx, bin,
			"-t", "ed25519", "-N", "", "-C", "tailssh", "-f", privPath)
		if out, runErr := cmd.CombinedOutput(); runErr != nil {
			return "", "", fmt.Errorf("ssh-keygen failed: %w: %s",
				runErr, strings.TrimSpace(string(out)))
		}
	}

	pubBytes, readErr := os.ReadFile(pubPath)
	if readErr != nil {
		if !os.IsNotExist(readErr) {
			return "", "", fmt.Errorf("read public key: %w", readErr)
		}
		// The private key exists but its .pub is missing (e.g. deleted out of
		// band). Derive the public line from the private key rather than failing.
		bin, lookErr := exec.LookPath("ssh-keygen")
		if lookErr != nil {
			return "", "", fmt.Errorf("ssh-keygen not found: %w", lookErr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// -y prints the public key derived from the private key to stdout.
		out, runErr := exec.CommandContext(ctx, bin, "-y", "-f", privPath).Output()
		if runErr != nil {
			return "", "", fmt.Errorf("derive public key: %w", runErr)
		}
		// -y omits the comment; re-append "tailssh" so the derived line matches a
		// freshly generated key, then persist it (best effort) for later runs.
		pubLine = strings.TrimSpace(string(out))
		if pubLine != "" {
			pubLine += " tailssh"
		}
		_ = os.WriteFile(pubPath, []byte(pubLine+"\n"), 0o644)
	} else {
		pubLine = strings.TrimSpace(string(pubBytes))
	}
	if pubLine == "" {
		return "", "", fmt.Errorf("public key %s is empty", pubPath)
	}

	if err = pl.SecureKeyFile(privPath); err != nil {
		return "", "", fmt.Errorf("secure key file: %w", err)
	}

	return privPath, pubLine, nil
}

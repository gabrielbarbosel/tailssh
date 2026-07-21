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

const (
	// identityKeyComment is the comment stamped on generated keys. It is also
	// re-appended to derived public lines, which ssh-keygen prints without one.
	identityKeyComment = "tailssh"

	identityKeygenTimeout = 30 * time.Second
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
		if err = identityGenerateKeypair(privPath, pubPath); err != nil {
			return "", "", err
		}
	}

	if pubLine, err = identityPublicLine(privPath, pubPath); err != nil {
		return "", "", err
	}
	if pubLine == "" {
		return "", "", fmt.Errorf("public key %s is empty", pubPath)
	}

	if err = pl.SecureKeyFile(privPath); err != nil {
		return "", "", fmt.Errorf("secure key file: %w", err)
	}

	return privPath, pubLine, nil
}

// identityGenerateKeypair writes a fresh passphrase-less ed25519 keypair at
// privPath. A stale/partial .pub left by an aborted run is removed first
// because ssh-keygen refuses to overwrite an existing output file.
func identityGenerateKeypair(privPath, pubPath string) error {
	_ = os.Remove(pubPath)

	bin, err := identityKeygenPath()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), identityKeygenTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"-t", "ed25519", "-N", "", "-C", identityKeyComment, "-f", privPath)
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		return fmt.Errorf("ssh-keygen failed: %w: %s",
			runErr, strings.TrimSpace(string(out)))
	}
	return nil
}

// identityPublicLine returns the trimmed public-key line, reading pubPath when
// present. A missing .pub (deleted out of band) is re-derived from the private
// key rather than treated as failure, then persisted best effort for later runs.
func identityPublicLine(privPath, pubPath string) (string, error) {
	pubBytes, readErr := os.ReadFile(pubPath)
	if readErr == nil {
		return strings.TrimSpace(string(pubBytes)), nil
	}
	if !os.IsNotExist(readErr) {
		return "", fmt.Errorf("read public key: %w", readErr)
	}

	pubLine, err := identityDerivePublicLine(privPath)
	if err != nil {
		return "", err
	}
	_ = os.WriteFile(pubPath, []byte(pubLine+"\n"), 0o644)
	return pubLine, nil
}

// identityDerivePublicLine recomputes the public-key line from the private key.
// ssh-keygen -y prints it without the comment, so identityKeyComment is
// re-appended to keep the line identical to a freshly generated one.
func identityDerivePublicLine(privPath string) (string, error) {
	bin, err := identityKeygenPath()
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), identityKeygenTimeout)
	defer cancel()
	out, runErr := exec.CommandContext(ctx, bin, "-y", "-f", privPath).Output()
	if runErr != nil {
		return "", fmt.Errorf("derive public key: %w", runErr)
	}

	pubLine := strings.TrimSpace(string(out))
	if pubLine == "" {
		return "", nil
	}
	return pubLine + " " + identityKeyComment, nil
}

// identityKeygenPath locates the ssh-keygen binary both key operations shell out to.
func identityKeygenPath() (string, error) {
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return "", fmt.Errorf("ssh-keygen not found: %w", err)
	}
	return bin, nil
}

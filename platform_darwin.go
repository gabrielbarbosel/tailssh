//go:build darwin

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// xmlEscaper escapes the five XML metacharacters so arbitrary strings can be
// embedded safely in plist element content.
var xmlEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&apos;",
)

// darwinPlatform implements Platform for macOS. sshd ("Remote Login") ships with
// the OS, so install is a no-op; enable goes through launchd. The daemon runs as
// a per-user LaunchAgent so it writes the user's own ~/.ssh with no root/TCC.
type darwinPlatform struct{}

// newPlatform returns the macOS Platform implementation.
func newPlatform() Platform { return darwinPlatform{} }

// OpenURL opens a URL in the default browser.
func (p darwinPlatform) OpenURL(url string) error {
	return exec.Command("open", url).Start()
}

// InstallTailscale auto-installs the cask via Homebrew when available; otherwise
// opens the official download page.
func (p darwinPlatform) InstallTailscale() error {
	if _, err := exec.LookPath("brew"); err == nil {
		return exec.Command("brew", "install", "--cask", "tailscale").Run()
	}
	return p.OpenURL("https://tailscale.com/download/mac")
}

const darwinDaemonLabel = "com.tailssh.daemon"

// run executes a command under a short timeout, prefixing sudo when not root.
func (darwinPlatform) run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if os.Geteuid() != 0 {
		args = append([]string{name}, args...)
		name = "sudo"
	}
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, out)
	}
	return nil
}

func (darwinPlatform) Name() string { return "darwin" }

// SSHState reports sshd as always installed (built into macOS) and probes running
// state by dialing the loopback SSH port — socket-activated launchd sshd has no
// idle process to grep for, so a successful dial is the reliable signal.
func (darwinPlatform) SSHState() (installed, running bool) {
	installed = true
	conn, err := net.DialTimeout("tcp", "127.0.0.1:22", time.Second)
	if err == nil {
		conn.Close()
		running = true
	}
	return installed, running
}

// InstallSSH is a no-op: OpenSSH server is part of the base system.
func (darwinPlatform) InstallSSH() error { return nil }

// EnableSSH turns on Remote Login. It first tries the launchd path (enable +
// bootstrap the system sshd job); if that fails it falls back to the classic
// systemsetup toggle. Both need root, so run acquires sudo when needed.
func (p darwinPlatform) EnableSSH() error {
	// Preferred: launchd. enable persists the job across reboots; bootstrap
	// starts it now. bootstrap may report "already bootstrapped" — harmless.
	if err := p.run("launchctl", "enable", "system/com.openssh.sshd"); err == nil {
		_ = p.run("launchctl", "bootstrap", "system",
			"/System/Library/LaunchDaemons/ssh.plist")
		if _, running := p.SSHState(); running {
			return nil
		}
	}
	// Fallback: the user-facing Remote Login switch (FDA-gated on newer macOS).
	if err := p.run("systemsetup", "-setremotelogin", "on"); err != nil {
		return fmt.Errorf("enable Remote Login: %w", err)
	}
	return nil
}

// SSHListenPort is the standard SSH port on macOS.
func (darwinPlatform) SSHListenPort() int { return 22 }

// AuthorizedKeysPath returns the current user's authorized_keys file.
func (darwinPlatform) AuthorizedKeysPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "authorized_keys"), nil
}

// SecureKeyFile applies StrictModes-compatible permissions: 0700 on the
// containing directory and 0600 on the file itself.
func (darwinPlatform) SecureKeyFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// SupportsIPNBus is true on desktop macOS: `tailscale debug watch-ipn` works.
func (darwinPlatform) SupportsIPNBus() bool { return true }

// diskEncryption reports FileVault state via fdesetup (best-effort).
func diskEncryption() (on bool, detail string) {
	out, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		return false, "unknown"
	}
	if strings.Contains(string(out), "FileVault is On") {
		return true, "FileVault on"
	}
	return false, "FileVault off"
}

// persistenceNote returns a reboot-persistence caveat; the LaunchAgent persists on
// its own, so there is nothing to warn about.
func persistenceNote() string { return "" }

// sshHostKeyPubPath is where macOS sshd keeps its ed25519 host public key.
func sshHostKeyPubPath() string {
	return "/etc/ssh/ssh_host_ed25519_key.pub"
}

// EnsurePrivilege is a no-op on macOS: the daemon runs as a per-user LaunchAgent
// and privileged steps escalate per command via sudo, so no re-launch is needed.
func (p darwinPlatform) EnsurePrivilege([]string) (bool, error) { return false, nil }

// InstallDaemon writes a per-user LaunchAgent plist and loads it. Running as the
// logged-in user keeps authorized_keys owned correctly and avoids root/TCC. The
// PATH is widened so the Tailscale.app CLI is discoverable from the agent.
func (p darwinPlatform) InstallDaemon(exePath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", darwinDaemonLabel+".plist")
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>daemon</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Background</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>/usr/local/bin:/opt/homebrew/bin:/Applications/Tailscale.app/Contents/MacOS:/usr/bin:/bin:/usr/sbin:/sbin</string>
	</dict>
</dict>
</plist>
`, darwinDaemonLabel, xmlEscaper.Replace(exePath))

	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return err
	}

	// Load into the per-user domain (user/<uid>), which is present without a GUI
	// (Aqua) login session — the gui/<uid> domain only exists for a logged-in
	// window-server session, so it would fail over SSH on a headless Mac.
	target := "user/" + strconv.Itoa(os.Getuid())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Idempotent: tear down any existing instance before bootstrapping, so a
	// reinstall doesn't fail with "service already bootstrapped". Best-effort.
	_ = exec.CommandContext(ctx, "launchctl", "bootout", target+"/"+darwinDaemonLabel).Run()
	// Prefer bootstrap; fall back to the legacy load verb on older launchctl.
	if err := exec.CommandContext(ctx, "launchctl", "bootstrap", target, plistPath).Run(); err != nil {
		if err := exec.CommandContext(ctx, "launchctl", "load", "-w", plistPath).Run(); err != nil {
			return fmt.Errorf("launchctl load %s: %w", plistPath, err)
		}
	}
	return nil
}

// RemoveDaemon unloads the LaunchAgent and deletes its plist.
func (p darwinPlatform) RemoveDaemon() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", darwinDaemonLabel+".plist")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	target := "user/" + strconv.Itoa(os.Getuid()) + "/" + darwinDaemonLabel
	// bootout is the modern unload; fall back to legacy unload. Both best-effort.
	if err := exec.CommandContext(ctx, "launchctl", "bootout", target).Run(); err != nil {
		_ = exec.CommandContext(ctx, "launchctl", "unload", "-w", plistPath).Run()
	}
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

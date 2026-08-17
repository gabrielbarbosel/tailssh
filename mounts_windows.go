//go:build windows

package main

// mounts_windows.go — the Windows mount client: rclone over SFTP + WinFsp, presented
// as a network drive letter in Explorer (the same rclone+WinFsp mechanism many
// setups already use). Each peer gets a per-peer rclone config (no shared file to
// merge), mounted read-write with the VFS cache OFF so nothing lands on disk. rclone
// mount is a foreground process, so it is launched detached+hidden and re-created by
// the next reconcile if it dies; unmount finds and stops the rclone serving that
// letter.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// windows CreateProcess flags for a detached, windowless child (stdlib values, to
// keep go.mod dependency-free).
const (
	winDetachedProcess = 0x00000008
	winCreateNoWindow  = 0x08000000
)

// MountSupport: Windows can both serve (its sshd) and mount (rclone+WinFsp).
func (windowsPlatform) MountSupport() (canExport, canMount bool) { return true, true }

// MountToolingPresent: mounting needs both rclone (the SFTP client) and WinFsp
// (the FUSE layer rclone mounts through).
func (windowsPlatform) MountToolingPresent() bool {
	return haveExecutable("rclone") && winfspPresent()
}

// EnsureMountTooling installs WinFsp + rclone via winget when missing (idempotent).
func (windowsPlatform) EnsureMountTooling() error {
	if _, err := exec.LookPath("winget"); err != nil {
		if !haveExecutable("rclone") || !winfspPresent() {
			return fmt.Errorf("winget not found; install WinFsp and rclone to enable mounts")
		}
		return nil
	}
	if !winfspPresent() {
		_ = exec.Command("winget", "install", "-e", "--id", "WinFsp.WinFsp",
			"--silent", "--accept-package-agreements", "--accept-source-agreements").Run()
	}
	if !haveExecutable("rclone") {
		_ = exec.Command("winget", "install", "-e", "--id", "Rclone.Rclone",
			"--silent", "--accept-package-agreements", "--accept-source-agreements").Run()
	}
	return nil
}

// winfspPresent reports whether WinFsp appears installed (its fixed install dir).
func winfspPresent() bool {
	for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
		if base == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(base, "WinFsp")); err == nil {
			return true
		}
	}
	return false
}

// MountPeer mounts spec's whole filesystem read-write as a network drive letter and
// returns it (e.g. "Z:"). Reuses prevAt when that drive is already live; otherwise
// allocates a free letter. Nothing is cached to disk (--vfs-cache-mode off).
func (windowsPlatform) MountPeer(spec mountSpec, prevAt string) (string, error) {
	if prevAt != "" && driveLive(prevAt) {
		return prevAt, nil // already mounted for this peer
	}
	at := freeDriveLetter()
	if at == "" {
		return "", fmt.Errorf("no free drive letter for %s", spec.Name)
	}
	conf, err := writeRclonePeerConfig(spec)
	if err != nil {
		return "", err
	}
	cmd := exec.Command("rclone", "mount", "--config", conf, spec.Name+":/", at,
		"--network-mode", "--volname", spec.Name, "--vfs-cache-mode", "off")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: winDetachedProcess | winCreateNoWindow}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("rclone mount %s: %w", spec.Name, err)
	}
	// rclone mount is async; wait briefly for the drive to appear so the next peer's
	// allocation sees this letter taken (prevents two peers grabbing the same letter).
	for i := 0; i < 25; i++ {
		if driveLive(at) {
			return at, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return at, nil // return the letter even if slow; next reconcile confirms/retries
}

// UnmountPeer stops the rclone process serving drive `at`, dropping the WinFsp mount.
func (p windowsPlatform) UnmountPeer(at string) error {
	if !driveLive(at) {
		return nil
	}
	// Stop the rclone whose command line mounts this letter.
	script := fmt.Sprintf(
		"Get-CimInstance Win32_Process -Filter \"Name='rclone.exe'\" | "+
			"Where-Object { $_.CommandLine -like '*mount*%s*' } | "+
			"ForEach-Object { Stop-Process -Id $_.ProcessId -Force }", at)
	if _, err := windowsPowershell(script); err != nil {
		return fmt.Errorf("unmount %s: %w", at, err)
	}
	return nil
}

// driveLive reports whether a drive letter like "Z:" is currently present.
func driveLive(letter string) bool {
	_, err := os.Stat(letter + `\`)
	return err == nil
}

// freeDriveLetter returns the first unused letter from Z downward (leaving the low
// letters to physical/removable drives), or "" if none is free.
func freeDriveLetter() string {
	for c := 'Z'; c >= 'D'; c-- {
		letter := string(c) + ":"
		if !driveLive(letter) {
			return letter
		}
	}
	return ""
}

// writeRclonePeerConfig writes a self-contained rclone config for one peer (an sftp
// remote named after the peer, keyed by the mesh identity) and returns its path.
// Written atomically under the tailssh config dir; no shared file to merge.
//
// It deliberately does NOT pin a known_hosts file: rclone verifies host keys
// strictly with no accept-new, so a stale managed entry would hard-fail the mount
// (whereas sshfs's accept-new tolerates it). The peer's identity is already
// authenticated by WireGuard — tailnet membership is the authorization boundary, the
// same reason the keyserver serves plain HTTP — so host-key pinning here adds nothing
// over the encrypted, authenticated tunnel the traffic already rides.
func writeRclonePeerConfig(spec mountSpec) (string, error) {
	path := filepath.Join(filepath.Dir(appKeyPath()), "rclone", "peer-"+spec.Name+".conf")
	var b strings.Builder
	fmt.Fprintf(&b, "[%s]\n", spec.Name)
	fmt.Fprintf(&b, "type = sftp\n")
	fmt.Fprintf(&b, "host = %s\n", spec.Host)
	fmt.Fprintf(&b, "user = %s\n", spec.User)
	fmt.Fprintf(&b, "port = %d\n", spec.Port)
	fmt.Fprintf(&b, "key_file = %s\n", spec.Identity)
	fmt.Fprintf(&b, "md5sum_command = none\n")
	fmt.Fprintf(&b, "sha1sum_command = none\n")
	out := []byte(b.String())
	if sameContent(path, out) {
		return path, nil
	}
	if err := atomicWrite(path, out, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

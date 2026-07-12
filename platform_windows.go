//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const windowsSvcName = "tailssh"

// windowsPlatform implements Platform for Windows using PowerShell (service +
// capability + firewall control) and icacls (ACL hardening).
type windowsPlatform struct {
	admin bool
}

func newPlatform() Platform {
	return &windowsPlatform{admin: windowsIsAdmin()}
}

func (p windowsPlatform) OpenURL(url string) error {
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// InstallTailscale auto-installs via winget when available; otherwise opens the
// official download page.
func (p windowsPlatform) InstallTailscale() error {
	if _, err := exec.LookPath("winget"); err == nil {
		return exec.Command("winget", "install", "-e", "--id", "Tailscale.Tailscale",
			"--silent", "--accept-package-agreements", "--accept-source-agreements").Run()
	}
	return p.OpenURL("https://tailscale.com/download/windows")
}

func (windowsPlatform) Name() string { return "windows" }

// windowsPowershell runs a PowerShell command and returns trimmed stdout.
func windowsPowershell(script string) (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command", script).Output()
	return strings.TrimSpace(string(out)), err
}

// windowsIsAdmin reports Administrators membership. A false result on error
// keeps behavior in the safe, unprivileged path.
func windowsIsAdmin() bool {
	out, err := windowsPowershell(
		"([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())" +
			".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
	if err != nil {
		return false
	}
	return strings.EqualFold(out, "True")
}

func (windowsPlatform) SSHState() (installed, running bool) {
	out, _ := windowsPowershell("(Get-Service sshd -ErrorAction SilentlyContinue).Status")
	s := strings.TrimSpace(out)
	return s != "", strings.EqualFold(s, "Running")
}

// InstallSSH installs the OpenSSH server capability and opens the firewall for
// inbound TCP 22. Both steps are idempotent. Host keys come from the capability,
// so no ssh-keygen is needed here.
func (windowsPlatform) InstallSSH() error {
	if _, err := windowsPowershell(
		"Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"); err != nil {
		return fmt.Errorf("add OpenSSH.Server capability: %w", err)
	}
	// RemoteAddress scopes the rule to the Tailscale CGNAT range (100.64.0.0/10)
	// so sshd is reachable only over the tailnet, never from public networks.
	_, _ = windowsPowershell(
		"if (-not (Get-NetFirewallRule -Name 'tailssh-sshd' -ErrorAction SilentlyContinue)) {" +
			" New-NetFirewallRule -Name 'tailssh-sshd' -DisplayName 'tailssh OpenSSH Server'" +
			" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22" +
			" -RemoteAddress 100.64.0.0/10 }")
	return nil
}

// EnableSSH sets sshd to start automatically and starts it now. Idempotent.
func (windowsPlatform) EnableSSH() error {
	if _, err := windowsPowershell(
		"$ErrorActionPreference='Stop'; Set-Service sshd -StartupType Automatic; Start-Service sshd"); err != nil {
		return fmt.Errorf("enable/start sshd: %w", err)
	}
	return nil
}

func (windowsPlatform) SSHListenPort() int { return 22 }

// windowsAdminKeysPath is the system-wide authorized_keys file sshd consults
// for members of the Administrators group.
func windowsAdminKeysPath() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "ssh", "administrators_authorized_keys")
}

// AuthorizedKeysPath returns the admin-wide file when elevated, else the
// per-user file. sshd on Windows requires admins to use the ProgramData file.
func (p windowsPlatform) AuthorizedKeysPath() (string, error) {
	if p.admin {
		return windowsAdminKeysPath(), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "authorized_keys"), nil
}

// SecureKeyFile applies the ACL sshd's StrictModes requires: inheritance
// disabled, and only SYSTEM plus the appropriate principal granted full
// control. Wrong or extra-writable ACLs make sshd silently ignore the file.
func (p windowsPlatform) SecureKeyFile(path string) error {
	if out, err := exec.Command("icacls", path, "/inheritance:r").CombinedOutput(); err != nil {
		return fmt.Errorf("icacls inheritance: %v: %s", err, strings.TrimSpace(string(out)))
	}
	grants := []string{"/grant", "SYSTEM:F"}
	if p.admin {
		// Administrators well-known SID S-1-5-32-544.
		grants = append(grants, "/grant", "*S-1-5-32-544:F")
	} else {
		// Qualify the account with its domain (USERDOMAIN\USERNAME) so icacls
		// resolves the right principal; a bare USERNAME can be ambiguous or fail
		// to resolve on domain-joined or multi-account machines.
		if u := os.Getenv("USERNAME"); u != "" {
			principal := u
			if dom := os.Getenv("USERDOMAIN"); dom != "" {
				principal = dom + `\` + u
			}
			grants = append(grants, "/grant", principal+":F")
		}
	}
	args := append([]string{path}, grants...)
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("icacls grant: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (windowsPlatform) SupportsIPNBus() bool { return true }

// diskEncryption reports the BitLocker protection state of the system drive
// (best-effort; returns unknown when the query fails, e.g. without privilege).
func diskEncryption() (on bool, detail string) {
	out, err := windowsPowershell(
		"(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus")
	if err != nil {
		return false, "unknown"
	}
	switch strings.TrimSpace(out) {
	case "On", "1":
		return true, "BitLocker on"
	case "Off", "0":
		return false, "BitLocker off"
	default:
		return false, "unknown"
	}
}

// persistenceNote returns a reboot-persistence caveat; the daemon's scheduled task
// (or Run-key fallback) already survives logon, so there is nothing to warn about.
func persistenceNote() string { return "" }

// sshHostKeyPubPath is where Windows OpenSSH keeps its ed25519 host public key.
func sshHostKeyPubPath() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "ssh", "ssh_host_ed25519_key.pub")
}

// InstallDaemon registers the tailssh daemon as a Scheduled Task that runs the
// exe's "daemon" subcommand at logon. tailssh is a plain console program, not a
// Win32 service — an sc.exe service would fail to answer the SCM and die with
// Error 1053. A scheduled task avoids the SCM protocol entirely and runs as the
// interactive user with highest privileges.
func (p windowsPlatform) InstallDaemon(exePath string) error {
	tr := fmt.Sprintf(`"%s" daemon`, exePath)
	// /F overwrites any existing task, making install idempotent. /RL HIGHEST needs
	// elevation, so this path is taken only when running as admin.
	out, err := exec.Command("schtasks", "/Create",
		"/TN", windowsSvcName,
		"/TR", tr,
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/F").CombinedOutput()
	if err != nil {
		// Not elevated: fall back to a per-user autostart (HKCU Run key), which needs
		// no admin and starts the daemon at each logon. Start it now too, detached.
		if rerr := installRunKey(exePath); rerr != nil {
			return fmt.Errorf("schtasks: %v: %s; run-key: %v",
				err, strings.TrimSpace(string(out)), rerr)
		}
		startDaemonNow(exePath)
		return nil
	}
	// Start now so the daemon runs without waiting for the next logon.
	_, _ = exec.Command("schtasks", "/Run", "/TN", windowsSvcName).CombinedOutput()
	return nil
}

// installRunKey registers the daemon under HKCU…\Run so it starts at logon without
// any elevation (the elevation-free counterpart to the scheduled task).
func installRunKey(exePath string) error {
	val := fmt.Sprintf(`"%s" daemon`, exePath)
	out, err := exec.Command("reg", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", windowsSvcName, "/t", "REG_SZ", "/d", val, "/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// startDaemonNow launches the daemon fully detached so it keeps running after this
// process (and its console) exits.
func startDaemonNow(exePath string) {
	_, _ = windowsPowershell(fmt.Sprintf(
		"Start-Process -FilePath '%s' -ArgumentList 'daemon' -WindowStyle Hidden",
		strings.ReplaceAll(exePath, "'", "''")))
}

// RemoveDaemon removes both persistence mechanisms (scheduled task and Run key) and
// stops any running instance. Every step is best-effort — whichever exists is gone.
func (windowsPlatform) RemoveDaemon() error {
	_, _ = exec.Command("schtasks", "/End", "/TN", windowsSvcName).CombinedOutput()
	_, _ = exec.Command("schtasks", "/Delete", "/TN", windowsSvcName, "/F").CombinedOutput()
	_, _ = exec.Command("reg", "delete",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", windowsSvcName, "/f").CombinedOutput()
	return nil
}

//go:build windows

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

const windowsSvcName = "tailssh"

// windowsAdministratorsSID is the locale-independent well-known SID of the local
// Administrators group.
const windowsAdministratorsSID = "S-1-5-32-544"

// windowsPlatform implements Platform for Windows using PowerShell (service +
// capability + firewall control) and icacls (ACL hardening).
//
// Two distinct facts are tracked because they answer different questions:
//   - adminGroup: is the login account a member of Administrators? This is what
//     sshd keys off — for a member it authorizes ONLY against the ProgramData
//     administrators_authorized_keys, never the per-user file. It decides the
//     target key file and its ACL principal.
//   - elevated: does this process hold an elevated token? This is a capability —
//     writing under ProgramData and creating a /RL HIGHEST task both need it.
//
// Conflating the two is a silent-failure trap: an unelevated admin writing peer
// keys to the per-user file (which sshd ignores) leaves inbound auth broken.
type windowsPlatform struct {
	adminGroup bool
	elevated   bool
}

func newPlatform() Platform {
	return &windowsPlatform{adminGroup: windowsInAdminGroup(), elevated: windowsIsElevated()}
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

// windowsIsElevated reports whether this process runs with an elevated token —
// the capability needed to write under ProgramData and to register a /RL HIGHEST
// scheduled task. A false result on error keeps behavior in the unprivileged path.
func windowsIsElevated() bool {
	out, err := windowsPowershell(
		"([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())" +
			".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
	if err != nil {
		return false
	}
	return strings.EqualFold(out, "True")
}

// windowsInAdminGroup reports whether the login account is a member of the local
// Administrators group, independent of the current process's elevation — the exact
// condition Windows OpenSSH uses to switch inbound auth to
// administrators_authorized_keys. Elevation is not a substitute: an unelevated
// admin's token carries the Administrators SID as deny-only, so IsInRole/token
// checks report false. Membership is resolved by the well-known SID S-1-5-32-544
// (locale-independent); on any query failure it falls back to the elevation check,
// which can only under-report, never authorize the wrong file.
func windowsInAdminGroup() bool {
	out, err := windowsPowershell(
		"$me=([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value;" +
			"try{((Get-LocalGroupMember -SID '" + windowsAdministratorsSID + "' -ErrorAction Stop|" +
			"Where-Object{$_.SID.Value -eq $me}|Measure-Object).Count -gt 0)}" +
			"catch{([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())" +
			".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}")
	if err != nil {
		return windowsIsElevated()
	}
	return strings.EqualFold(out, "True")
}

func (windowsPlatform) SSHState() (installed, running bool) {
	out, _ := windowsPowershell("(Get-Service sshd -ErrorAction SilentlyContinue).Status")
	s := strings.TrimSpace(out)
	return s != "", strings.EqualFold(s, "Running")
}

// windowsTailnetCGNATRange is the Tailscale CGNAT address range; scoping the sshd
// firewall rule to it keeps the server reachable only over the tailnet, never from
// public networks.
const windowsTailnetCGNATRange = "100.64.0.0/10"

// InstallSSH installs the OpenSSH server capability and opens the firewall for
// inbound TCP 22. Both steps are idempotent. Host keys come from the capability,
// so no ssh-keygen is needed here.
func (windowsPlatform) InstallSSH() error {
	if _, err := windowsPowershell(
		"Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"); err != nil {
		return fmt.Errorf("add OpenSSH.Server capability: %w", err)
	}
	windowsOpenTailnetFirewall()
	return nil
}

// windowsOpenTailnetFirewall adds an idempotent inbound rule allowing TCP 22 only
// from the tailnet CGNAT range, so sshd is never exposed to public networks.
func windowsOpenTailnetFirewall() {
	_, _ = windowsPowershell(
		"if (-not (Get-NetFirewallRule -Name 'tailssh-sshd' -ErrorAction SilentlyContinue)) {" +
			" New-NetFirewallRule -Name 'tailssh-sshd' -DisplayName 'tailssh OpenSSH Server'" +
			" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22" +
			" -RemoteAddress " + windowsTailnetCGNATRange + " }")
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

// windowsAdminKeysActive reports whether sshd_config actually routes
// Administrators members to administrators_authorized_keys — the stock
// "Match Group administrators" block with its AuthorizedKeysFile override.
// Real machines drift: with that block commented out, sshd reads the
// per-user file for every account, and keys written to the admin file are
// silently ignored. sshd_config is the source of truth, so the managed
// block must follow it. Unreadable config falls back to the stock default.
func windowsAdminKeysActive() bool {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	data, err := os.ReadFile(filepath.Join(pd, "ssh", "sshd_config"))
	if err != nil {
		return true
	}
	inAdminMatch := false
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "match ") {
			inAdminMatch = strings.Contains(l, "group administrators")
			continue
		}
		if inAdminMatch && strings.HasPrefix(l, "authorizedkeysfile") &&
			strings.Contains(l, "administrators_authorized_keys") {
			return true
		}
	}
	return false
}

// AuthorizedKeysPath returns the file sshd actually reads for this account:
// the admin-wide file for an Administrators member under a stock sshd_config,
// else the per-user file. Membership is decided by group, never elevation, so
// an unelevated admin daemon still targets the file sshd honors (writing it
// then requires elevation).
func (p windowsPlatform) AuthorizedKeysPath() (string, error) {
	if p.adminGroup && windowsAdminKeysActive() {
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
// control. The principal follows the file, not the account: only the
// admin-wide keys file belongs to Administrators; per-user files (and the
// private identity) get the tightest ACL — the owning user alone.
// Wrong or extra-writable ACLs make sshd silently ignore the file.
//
// Grants are applied BEFORE inheritance is stripped. The reverse order leaves the
// file with no ACE at all whenever the grant step fails, locking out every
// principal — including Administrators, for whom the only way back is taking
// ownership from an elevated shell.
func (p windowsPlatform) SecureKeyFile(path string) error {
	grants := []string{"/grant", "SYSTEM:F"}
	if path == windowsAdminKeysPath() {
		grants = append(grants, "/grant", "*"+windowsAdministratorsSID+":F")
	} else {
		grants = append(grants, windowsPerUserKeyGrant()...)
	}
	args := append([]string{path}, grants...)
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("icacls grant: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("icacls", path, "/inheritance:r").CombinedOutput(); err != nil {
		return fmt.Errorf("icacls inheritance: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return verifyReadable(path)
}

// windowsPerUserKeyGrant returns the icacls "/grant <principal>:F" pair for the
// current account. It grants by SID, never by name: name principals are
// locale-dependent and unmappable on workgroup machines, where USERDOMAIN is the
// workgroup rather than a security authority (icacls error 1332). os/user resolves
// the account SID directly; only when that fails does it fall back to the USERNAME
// principal, and to no grant at all when neither is available.
func windowsPerUserKeyGrant() []string {
	if u, err := user.Current(); err == nil && u.Uid != "" {
		return []string{"/grant", "*" + u.Uid + ":F"}
	}
	if name := os.Getenv("USERNAME"); name != "" {
		return []string{"/grant", name + ":F"}
	}
	return nil
}

// verifyReadable confirms the ACL just applied still lets this process open the
// file. icacls exits 0 on ACLs that are silently unusable, so an actual open is
// the only trustworthy check — the caveat DESIGN.md records as "verify the
// resulting ACL, don't assume icacls success".
func verifyReadable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("ACL verification failed — %s unreadable after securing: %w", path, err)
	}
	return f.Close()
}

// EnsurePrivilege re-launches tailssh elevated when the account is an
// Administrators member but the current process is not elevated — the exact case
// where provisioning would otherwise write peer keys into the per-user file sshd
// ignores. It escalates the same command through a single UAC prompt (Start-Process
// -Verb RunAs), waits for the elevated instance to finish, and returns handled=true
// so the unprivileged caller stops. Already-elevated or non-admin accounts need no
// escalation (handled=false): the daemon task runs elevated, and a standard account
// correctly manages its own per-user file.
func (p windowsPlatform) EnsurePrivilege(args []string) (bool, error) {
	if !p.adminGroup || p.elevated {
		return false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	if err := runElevatedAndWait(exe, args); err != nil {
		return false, err
	}
	return true, nil
}

// runElevatedAndWait re-runs exe with args elevated and blocks until it finishes.
//
// The elevated command is carried as a -EncodedCommand (UTF-16LE base64), which
// passes through Start-Process with no quoting hazard — the reason a plain
// -ArgumentList handoff is unreliable (a dropped flag silently downgrades, e.g.
// `up --yes` to a read-only `up` that provisions nothing). The elevated instance
// redirects all output to a log and records its real exit code in a sentinel file,
// because an unelevated parent cannot read an elevated child's exit code directly —
// so this is the only way to tell success from a mid-run failure or declined UAC.
func runElevatedAndWait(exe string, args []string) error {
	tmp := os.TempDir()
	logPath := filepath.Join(tmp, "tailssh-elevated.log")
	exitPath := filepath.Join(tmp, "tailssh-elevated.exit")
	_ = os.Remove(logPath)
	_ = os.Remove(exitPath)

	psSingle := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	inner := "& " + psSingle(exe)
	for _, a := range args {
		inner += " " + psSingle(a)
	}
	inner += " *> " + psSingle(logPath) +
		"; Set-Content -LiteralPath " + psSingle(exitPath) + " -Value $LASTEXITCODE"

	outer := fmt.Sprintf(
		"Start-Process powershell -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','%s' -Verb RunAs -Wait",
		base64.StdEncoding.EncodeToString(utf16LEBytes(inner)))
	if out, err := windowsPowershell(outer); err != nil {
		return fmt.Errorf("elevation failed or was declined: %v: %s", err, out)
	}

	code, err := os.ReadFile(exitPath)
	if err != nil {
		return fmt.Errorf("elevated run left no exit status (UAC declined or launch failed)")
	}
	if c := strings.TrimSpace(string(code)); c != "" && c != "0" {
		out, _ := os.ReadFile(logPath)
		return fmt.Errorf("elevated tailssh exited %s: %s", c, strings.TrimSpace(string(out)))
	}
	return nil
}

// utf16LEBytes encodes s as UTF-16LE, the wire format PowerShell -EncodedCommand
// expects after base64-decoding.
func utf16LEBytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		b[2*i] = byte(r)
		b[2*i+1] = byte(r >> 8)
	}
	return b
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
// Error 1053. A scheduled task avoids the SCM protocol entirely.
//
// The principal uses S4U, not Interactive: an Interactive principal runs the
// daemon inside the desktop session, which attaches a visible console window and
// tears the daemon down at logoff — leaving the keyserver unreachable until the
// next logon. S4U runs it detached, with no console and no stored password, while
// still loading the user profile the daemon needs to write ~/.ssh.
//
// The task is registered via Register-ScheduledTask, not schtasks.exe: schtasks
// defaults are lethal to a laptop daemon (start blocked on battery power — the
// task and any /Run just sit "Queued" — and a 72h ExecutionTimeLimit that kills
// a long-running daemon) and it has no flags to change either. The settings set
// below allows battery start/continue, removes the time limit, and auto-restarts
// the daemon if it crashes.
func (p windowsPlatform) InstallDaemon(exePath string) error {
	out, err := windowsPowershell(windowsDaemonTaskScript(exePath))
	if err == nil {
		return nil
	}
	return p.installDaemonFallback(exePath, err, out)
}

// windowsDaemonTaskScript builds the PowerShell that idempotently registers (via
// -Force, which overwrites any existing task) and starts the tailssh daemon
// scheduled task. RunLevel Highest requires elevation, so running the script
// succeeds only from an elevated process.
func windowsDaemonTaskScript(exePath string) string {
	psq := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	return "$ErrorActionPreference='Stop';" +
		"$a=New-ScheduledTaskAction -Execute '" + psq(exePath) + "' -Argument 'daemon';" +
		"$t=New-ScheduledTaskTrigger -AtLogOn;" +
		"$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries" +
		" -ExecutionTimeLimit ([TimeSpan]::Zero)" +
		" -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1);" +
		"$p=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name)" +
		" -LogonType S4U -RunLevel Highest;" +
		"Register-ScheduledTask -TaskName '" + windowsSvcName + "' -Action $a -Trigger $t" +
		" -Settings $s -Principal $p -Force | Out-Null;" +
		"Start-ScheduledTask -TaskName '" + windowsSvcName + "'"
}

// installDaemonFallback handles a failed scheduled-task registration (the elevated
// task couldn't be created because this process isn't elevated).
//
// On an Administrators account the daemon MUST run elevated — only then can it write
// and ACL administrators_authorized_keys, the sole file sshd reads for admins. The
// unprivileged run-key fallback would run the daemon unelevated and authorize peers
// into the per-user file sshd ignores, silently breaking inbound key auth, so this
// fails fast with a pointer to re-run elevated instead of installing that trap. A
// standard (non-admin) account is the opposite case: its unprivileged run-key daemon
// correctly manages the per-user authorized_keys that sshd actually reads there.
func (p windowsPlatform) installDaemonFallback(exePath string, taskErr error, taskOut string) error {
	if p.adminGroup {
		return fmt.Errorf("daemon must run elevated on an Administrators account so it can "+
			"manage %s (the only keys file sshd reads for admins) — re-run install from an "+
			"elevated shell: register task: %v: %s",
			windowsAdminKeysPath(), taskErr, strings.TrimSpace(taskOut))
	}
	if rerr := installRunKey(exePath); rerr != nil {
		return fmt.Errorf("register task: %v: %s; run-key: %v",
			taskErr, strings.TrimSpace(taskOut), rerr)
	}
	startDaemonNow(exePath)
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

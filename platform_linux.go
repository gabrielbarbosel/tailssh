//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

// linuxDaemonUnit is the systemd service name for the tailssh daemon.
const linuxDaemonUnit = "tailssh-daemon.service"

// linuxPlatform implements Platform for desktop/server Linux and, when running
// inside Termux (Android), for the Termux userland too. The two variants share
// most logic; the `termux` flag switches package manager, ports, enable path,
// and privilege model (Termux is always unprivileged, never uses sudo).
type linuxPlatform struct {
	termux bool
}

// newPlatform returns the Linux Platform implementation, detecting Termux at
// runtime via the $PREFIX Termux sets ("…/com.termux/…").
func newPlatform() Platform {
	return &linuxPlatform{termux: strings.Contains(os.Getenv("PREFIX"), "com.termux")}
}

// OpenURL opens a URL in the default browser (xdg-open) or, on Termux, via the
// Android activity manager / termux-open-url.
func (p *linuxPlatform) OpenURL(url string) error {
	if p.termux {
		if have("termux-open-url") {
			return exec.Command("termux-open-url", url).Run()
		}
		return exec.Command("am", "start", "-a", "android.intent.action.VIEW", "-d", url).Run()
	}
	return exec.Command("xdg-open", url).Start()
}

// InstallTailscale auto-installs on Linux via the official script. On Termux the
// tailnet is the Android app: if it is already installed, launch it directly (via
// `monkey`, which resolves the launcher activity without hardcoding it) so the user
// can just toggle it on; only fall back to the Play Store when it isn't installed.
func (p *linuxPlatform) InstallTailscale() error {
	if p.termux {
		// The launcher activity is exported, so `am start -n` works from Termux's
		// unprivileged uid; the name has changed across app versions, so try the
		// known ones, then monkey (auto-resolves), then the store as last resort.
		for _, comp := range []string{
			"com.tailscale.ipn/.MainActivity",
			"com.tailscale.ipn/.IPNActivity",
		} {
			if exec.Command("am", "start", "-n", comp).Run() == nil {
				return nil
			}
		}
		if exec.Command("monkey", "-p", "com.tailscale.ipn",
			"-c", "android.intent.category.LAUNCHER", "1").Run() == nil {
			return nil
		}
		return p.OpenURL("https://play.google.com/store/apps/details?id=com.tailscale.ipn")
	}
	return p.run("sh", "-c", "curl -fsSL https://tailscale.com/install.sh | sh")
}

// Name is the short OS label.
func (p *linuxPlatform) Name() string {
	if p.termux {
		return "termux"
	}
	return "linux"
}

// needSudo reports whether a mutating command must be wrapped in sudo: only on
// real Linux when not already root. Termux has no root and never uses sudo.
func (p *linuxPlatform) needSudo() bool {
	return !p.termux && os.Geteuid() != 0
}

// run executes a mutating command under a timeout, prefixing sudo when needed,
// and returns any error with combined output for context.
func (p *linuxPlatform) run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if p.needSudo() {
		args = append([]string{name}, args...)
		name = "sudo"
	}
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// have reports whether a binary is resolvable on PATH.
func have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// diskEncryption reports this device's at-rest encryption posture (best-effort).
// Android uses mandatory file-based encryption; on Linux we look for a dm-crypt
// (LUKS) layer under the root filesystem.
func diskEncryption() (on bool, detail string) {
	if strings.Contains(os.Getenv("PREFIX"), "com.termux") {
		return true, "Android file-based encryption (mandatory)"
	}
	if have("lsblk") {
		out, err := exec.Command("lsblk", "-no", "TYPE").Output()
		if err == nil {
			if strings.Contains(string(out), "crypt") {
				return true, "LUKS/dm-crypt"
			}
			return false, "no dm-crypt layer found"
		}
	}
	return false, "unknown"
}

// sshHostKeyPubPath is where sshd keeps its ed25519 host public key, used to
// pre-populate peers' known_hosts. Termux keeps it under $PREFIX/etc.
func sshHostKeyPubPath() string {
	if prefix := os.Getenv("PREFIX"); strings.Contains(prefix, "com.termux") {
		return filepath.Join(prefix, "etc", "ssh", "ssh_host_ed25519_key.pub")
	}
	return "/etc/ssh/ssh_host_ed25519_key.pub"
}

// hasSystemd / hasOpenRC detect the init system by filesystem probe rather than
// by the mere presence of systemctl/rc-service on PATH (which lies in chroots).
func hasSystemd() bool {
	fi, err := os.Stat("/run/systemd/system")
	return err == nil && fi.IsDir()
}

func hasOpenRC() bool {
	_, err := os.Stat("/run/openrc")
	return err == nil
}

// sshdInstalled probes for an sshd binary in PATH and the usual sbin locations.
func sshdInstalled() bool {
	for _, c := range []string{"sshd", "/usr/sbin/sshd", "/usr/bin/sshd"} {
		if _, err := exec.LookPath(c); err == nil {
			return true
		}
		if _, err := os.Stat(c); err == nil {
			return true
		}
	}
	return false
}

// sshdRunning reports whether an sshd is live. It prefers pgrep and, when pgrep
// is not installed, falls back to probing the listening socket on the given
// port (via ss, then /proc/net/tcp) rather than reporting not-running.
func sshdRunning(port int) bool {
	if have("pgrep") {
		return exec.Command("pgrep", "-x", "sshd").Run() == nil
	}
	return listeningOn(port)
}

// listeningOn reports whether any local socket is in LISTEN on the given TCP
// port, using ss when available and otherwise parsing /proc/net/tcp{,6}.
func listeningOn(port int) bool {
	if have("ss") {
		if out, err := exec.Command("ss", "-Hltn").Output(); err == nil {
			want := fmt.Sprintf(":%d", port)
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					addr := fields[3]
					if i := strings.LastIndex(addr, ":"); i >= 0 && addr[i:] == want {
						return true
					}
				}
			}
			return false
		}
	}
	return procNetListening(port)
}

// procNetListening scans /proc/net/tcp and tcp6 for a LISTEN socket (state 0A)
// bound to the given port. Addresses there are "HEXIP:HEXPORT".
func procNetListening(port int) bool {
	target := fmt.Sprintf("%04X", port)
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			local := fields[1]
			if i := strings.LastIndex(local, ":"); i >= 0 &&
				strings.EqualFold(local[i+1:], target) {
				return true
			}
		}
	}
	return false
}

// SSHState reports install + running state using init-aware probes.
func (p *linuxPlatform) SSHState() (installed, running bool) {
	installed = sshdInstalled()
	switch {
	case p.termux:
		// No service manager under Termux: a live sshd is the signal.
		running = sshdRunning(p.SSHListenPort())
	case hasSystemd():
		// Either the classic "ssh" or "sshd" unit, or an active ssh.socket.
		for _, u := range []string{"ssh", "sshd", "ssh.socket"} {
			out, _ := exec.Command("systemctl", "is-active", u).Output()
			if strings.TrimSpace(string(out)) == "active" {
				running = true
				break
			}
		}
	case hasOpenRC():
		running = exec.Command("rc-service", "sshd", "status").Run() == nil
	default:
		running = sshdRunning(p.SSHListenPort())
	}
	return installed, running
}

// InstallSSH installs the OpenSSH server via the detected package manager and
// generates any missing host keys. Idempotent (package managers no-op when the
// package is present; ssh-keygen -A only creates absent host keys).
func (p *linuxPlatform) InstallSSH() error {
	if p.termux {
		if err := p.run("pkg", "install", "-y", "openssh"); err != nil {
			return err
		}
		_ = p.run("ssh-keygen", "-A") // best-effort host keys under $PREFIX/etc/ssh
		return nil
	}

	switch {
	case have("apt-get"):
		_ = p.run("apt-get", "update") // best-effort refresh
		// env DEBIAN_FRONTEND=noninteractive survives the sudo boundary.
		if err := p.run("env", "DEBIAN_FRONTEND=noninteractive",
			"apt-get", "install", "-y", "openssh-server"); err != nil {
			return err
		}
	case have("dnf"):
		if err := p.run("dnf", "install", "-y", "openssh-server"); err != nil {
			return err
		}
	case have("yum"):
		if err := p.run("yum", "install", "-y", "openssh-server"); err != nil {
			return err
		}
	case have("pacman"):
		if err := p.run("pacman", "-Sy", "--noconfirm", "openssh"); err != nil {
			return err
		}
	case have("apk"):
		if err := p.run("apk", "add", "openssh", "openssh-keygen"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("no supported package manager (apt/dnf/yum/pacman/apk) found")
	}

	_ = p.run("ssh-keygen", "-A") // best-effort: create any missing host keys
	p.openFirewall()              // best-effort: allow SSH through a live firewall
	return nil
}

// openFirewall best-effort opens SSH through a running host firewall. If ufw is
// active it allows the tailscale0 interface and the OpenSSH profile; otherwise,
// if firewalld is running it permanently adds the ssh service and reloads. It is
// a no-op when neither is active. Not used under Termux (unprivileged).
func (p *linuxPlatform) openFirewall() {
	if have("ufw") {
		if out, err := exec.Command("ufw", "status").Output(); err == nil &&
			strings.Contains(string(out), "Status: active") {
			_ = p.run("ufw", "allow", "in", "on", "tailscale0")
			_ = p.run("ufw", "allow", "OpenSSH")
			return
		}
	}
	if have("firewall-cmd") {
		if out, err := exec.Command("firewall-cmd", "--state").Output(); err == nil &&
			strings.TrimSpace(string(out)) == "running" {
			_ = p.run("firewall-cmd", "--permanent", "--add-service=ssh")
			_ = p.run("firewall-cmd", "--reload")
		}
	}
}

// daemonUser is the non-root user the systemd daemon should run as: the human
// behind sudo when `up` was run through it, otherwise the current user.
func daemonUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// persistenceNote returns a caveat about reboot persistence, or "" when there is
// nothing to warn about. On Termux the boot script is inert without the Termux:Boot
// app; elsewhere the systemd unit persists on its own.
func persistenceNote() string {
	if strings.Contains(os.Getenv("PREFIX"), "com.termux") {
		if in, known := termuxBootInstalled(); known && !in {
			return "Termux:Boot app not installed — daemon won't auto-start after reboot"
		}
	}
	return ""
}

// termuxBootInstalled reports whether the Termux:Boot app is installed (it runs the
// boot script at device startup). The second return is false when the package
// manager can't be queried, so callers don't nag on an inconclusive check.
func termuxBootInstalled() (installed, known bool) {
	out, err := exec.Command("pm", "list", "packages", "com.termux.boot").Output()
	if err != nil {
		return false, false
	}
	return strings.Contains(string(out), "com.termux.boot"), true
}

// ensureTermuxBoot makes reboot persistence real. The boot script only fires if the
// separate Termux:Boot app is installed, so when it isn't this opens the app's
// F-Droid page and waits, bounded, for the user to install it — detecting completion
// on return. Best-effort: persistence is a nicety, so it never fails the install and
// never waits long enough to matter for the battery.
func (p *linuxPlatform) ensureTermuxBoot() {
	installed, known := termuxBootInstalled()
	if installed {
		return
	}
	if !known {
		fmt.Println("  boot        : install the Termux:Boot app for auto-start after a reboot.")
		return
	}
	fmt.Println("  boot        : Termux:Boot app missing — needed to auto-start after a reboot.")
	fmt.Println("                opening its F-Droid page; install it and return here...")
	_ = p.OpenURL("https://f-droid.org/packages/com.termux.boot/")
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		if in, _ := termuxBootInstalled(); in {
			fmt.Println("  boot        : Termux:Boot detected — reboot persistence enabled.")
			return
		}
	}
	fmt.Println("  boot        : skipped — the daemon runs now; install Termux:Boot later")
	fmt.Println("                (or re-run) to survive a reboot.")
}

// termuxBootDir returns Termux:Boot's script directory (~/.termux/boot).
func termuxBootDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".termux", "boot"), nil
}

// termuxShebang returns the interpreter line for Termux boot scripts, using the
// live $PREFIX so it points at Termux's own sh.
func termuxShebang() string {
	prefix := os.Getenv("PREFIX")
	if prefix == "" {
		prefix = "/data/data/com.termux/files/usr"
	}
	return "#!" + prefix + "/bin/sh\n"
}

// EnableSSH makes sshd start on boot and starts it now.
func (p *linuxPlatform) EnableSSH() error {
	if p.termux {
		// Termux:Boot runs every executable in ~/.termux/boot at device boot.
		dir, err := termuxBootDir()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		script := termuxShebang() + "sshd\n"
		path := filepath.Join(dir, "start-sshd")
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
			return err
		}
		// Start it now too so the current session is reachable immediately.
		_ = exec.Command("sshd").Run()
		return nil
	}

	switch {
	case hasSystemd():
		// The unit is named "ssh" on Debian/Ubuntu and "sshd" on RHEL/Arch.
		if err := p.run("systemctl", "enable", "--now", "ssh"); err != nil {
			if err2 := p.run("systemctl", "enable", "--now", "sshd"); err2 != nil {
				return fmt.Errorf("enable ssh(d): %v / %v", err, err2)
			}
		}
	case hasOpenRC():
		if err := p.run("rc-update", "add", "sshd", "default"); err != nil {
			return err
		}
		if err := p.run("rc-service", "sshd", "start"); err != nil {
			return err
		}
	default:
		// No recognized init: best-effort direct start (no reboot persistence).
		if err := p.run("sshd"); err != nil {
			return fmt.Errorf("no init system detected and direct sshd start failed: %w", err)
		}
	}
	return nil
}

// SSHListenPort is 22 on Linux; Termux's sshd cannot bind privileged ports and
// listens on 8022.
func (p *linuxPlatform) SSHListenPort() int {
	if p.termux {
		return 8022
	}
	return 22
}

// AuthorizedKeysPath returns the current user's authorized_keys file.
func (p *linuxPlatform) AuthorizedKeysPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "authorized_keys"), nil
}

// SecureKeyFile applies StrictModes-compatible permissions (0700 dir, 0600
// file) and, on SELinux-enforcing Linux, restores the file's security label so
// sshd is allowed to read it.
func (p *linuxPlatform) SecureKeyFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	if !p.termux {
		if out, err := exec.Command("getenforce").Output(); err == nil &&
			strings.TrimSpace(string(out)) == "Enforcing" {
			// Relabel both the ~/.ssh directory and the key file so sshd's
			// SELinux policy permits reading them.
			_ = exec.Command("restorecon", dir).Run()
			_ = exec.Command("restorecon", path).Run()
		}
	}
	return nil
}

// SupportsIPNBus is true on desktop/server Linux (`tailscale debug watch-ipn`
// works) and false under Termux, where there is no local Tailscale CLI/bus.
func (p *linuxPlatform) SupportsIPNBus() bool { return !p.termux }

// EnsurePrivilege is a no-op on Linux: privileged provisioning steps escalate per
// command via sudo where needed, so the process itself is never re-launched.
func (p *linuxPlatform) EnsurePrivilege([]string) (bool, error) { return false, nil }

// InstallDaemon installs the tailssh daemon as a persistent service: a systemd
// unit on Linux, or a Termux:Boot script under Termux.
func (p *linuxPlatform) InstallDaemon(exePath string) error {
	if p.termux {
		dir, err := termuxBootDir()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		// Supervise the daemon: restart it whenever it exits, so a crash or an
		// Android kill self-heals. The wake lock is held by THIS script (the loop),
		// not the daemon: it is app-global, so it keeps the whole Termux process —
		// supervisor and daemon alike — alive through Doze. Holding it only in the
		// daemon would let Android reap the wake-lock-less loop, leaving the daemon
		// unsupervised. Export PREFIX so the daemon detects Termux (port + behavior)
		// regardless of how the script is launched.
		prefix := os.Getenv("PREFIX")
		if prefix == "" {
			prefix = "/data/data/com.termux/files/usr"
		}
		wakelock := "termux-wake-lock\n"
		if os.Getenv("TAILSSH_BATTERY") == "saver" {
			wakelock = "" // saver: no wake lock — reachable only while the device is awake
		}
		script := termuxShebang() +
			fmt.Sprintf("export PREFIX=%s\n", prefix) +
			wakelock +
			"while true; do\n" +
			fmt.Sprintf("\t%q daemon\n", exePath) +
			"\tsleep 5\n" +
			"done\n"
		path := filepath.Join(dir, "start-tailssh")
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
			return err
		}
		// The boot script is inert without the Termux:Boot app; assist installing it.
		p.ensureTermuxBoot()
		return nil
	}

	// Run the daemon as the human user (not root) so it manages that user's
	// ~/.ssh and, crucially, advertises the right SSH login name in /meta. A
	// root daemon would report "root", which cloud VMs (and any host with
	// PermitRootLogin no) refuse — breaking `ssh <name>` for that peer.
	userLine := ""
	if u := daemonUser(); u != "" && u != "root" {
		userLine = "User=" + u + "\n"
	}
	unit := fmt.Sprintf(`[Unit]
Description=tailssh daemon
After=tailscaled.service network-online.target
Wants=network-online.target

[Service]
Type=simple
%sExecStart=%s daemon
Restart=always
RestartSec=5
MemoryMax=64M
Nice=10

[Install]
WantedBy=multi-user.target
`, userLine, exePath)

	// Stage the unit in a user-writable temp file, then place it as root.
	tmp, err := os.CreateTemp("", "tailssh-unit-*.service")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.WriteString(unit); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	dest := filepath.Join("/etc/systemd/system", linuxDaemonUnit)
	if err := p.run("cp", tmpPath, dest); err != nil {
		return err
	}
	if err := p.run("chmod", "0644", dest); err != nil {
		return err
	}
	if err := p.run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := p.run("systemctl", "enable", linuxDaemonUnit); err != nil {
		return err
	}
	// restart, not just start: on a reinstall the service may already be active,
	// and `enable --now` would not pick up unit changes (e.g. a new User=).
	return p.run("systemctl", "restart", linuxDaemonUnit)
}

// RemoveDaemon uninstalls the daemon service.
func (p *linuxPlatform) RemoveDaemon() error {
	if p.termux {
		dir, err := termuxBootDir()
		if err != nil {
			return err
		}
		script := filepath.Join(dir, "start-tailssh")
		// Kill the supervisor loop first so it can't respawn, then the daemon itself,
		// then release the wake lock the supervisor was holding.
		_ = exec.Command("pkill", "-f", script).Run()
		if exe, err := os.Executable(); err == nil {
			_ = exec.Command("pkill", "-f", exe+" daemon").Run()
		}
		_ = exec.Command("termux-wake-unlock").Run()
		if err := os.Remove(script); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	_ = p.run("systemctl", "disable", "--now", linuxDaemonUnit) // best-effort
	dest := filepath.Join("/etc/systemd/system", linuxDaemonUnit)
	if err := p.run("rm", "-f", dest); err != nil {
		return err
	}
	return p.run("systemctl", "daemon-reload")
}

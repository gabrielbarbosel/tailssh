//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// linuxDaemonUnit is the systemd service name for the tailssh daemon.
const linuxDaemonUnit = "tailssh-daemon.service"

// linuxTailscaleLink is the kernel network interface Tailscale creates on Linux,
// whose MTU tailssh reads from sysfs and sets with `ip link`.
const linuxTailscaleLink = "tailscale0"

// termuxDefaultPrefix is Termux's install prefix, used when $PREFIX is unset.
const termuxDefaultPrefix = "/data/data/com.termux/files/usr"

// linuxPlatform implements Platform for desktop/server Linux and, when running
// inside Termux (Android), for the Termux userland too. The two variants share
// most logic; the `termux` flag switches package manager, ports, enable path,
// and privilege model (Termux is always unprivileged, never uses sudo).
type linuxPlatform struct {
	termux bool
}

// newPlatform returns the Linux Platform implementation, detecting Termux at
// runtime.
func newPlatform() Platform {
	return &linuxPlatform{termux: runningUnderTermux()}
}

// runningUnderTermux reports whether the process runs inside Termux, detected via
// the $PREFIX Termux sets ("…/com.termux/…").
func runningUnderTermux() bool {
	return strings.Contains(os.Getenv("PREFIX"), "com.termux")
}

// termuxPrefix returns Termux's install prefix from $PREFIX, falling back to the
// default location when it is unset.
func termuxPrefix() string {
	if prefix := os.Getenv("PREFIX"); prefix != "" {
		return prefix
	}
	return termuxDefaultPrefix
}

// OpenURL opens a URL in the default browser (xdg-open) or, on Termux, via the
// Android activity manager / termux-open-url.
func (p *linuxPlatform) OpenURL(url string) error {
	if p.termux {
		if have("termux-open-url") {
			return command("termux-open-url", url).Run()
		}
		return command("am", "start", "-a", "android.intent.action.VIEW", "-d", url).Run()
	}
	return command("xdg-open", url).Start()
}

// InstallTailscale auto-installs on Linux via the official script. On Termux the
// tailnet is the Android app: if it is already installed, launch it directly so the
// user can just toggle it on; only fall back to the Play Store when it isn't.
func (p *linuxPlatform) InstallTailscale() error {
	if p.termux {
		if launchTermuxTailscaleApp() {
			return nil
		}
		return p.OpenURL("https://play.google.com/store/apps/details?id=com.tailscale.ipn")
	}
	return p.run("sh", "-c", "curl -fsSL https://tailscale.com/install.sh | sh")
}

// termuxTailscaleActivities are the launcher activity names the Tailscale Android
// app has used across versions; `am start -n` works from Termux's unprivileged uid
// because the activity is exported. The name has changed, so callers try each.
var termuxTailscaleActivities = []string{
	"com.tailscale.ipn/.MainActivity",
	"com.tailscale.ipn/.IPNActivity",
}

// launchTermuxTailscaleApp opens the already-installed Tailscale Android app from
// Termux, trying each known launcher activity and then `monkey`, which resolves the
// launcher without a hardcoded activity name. It reports whether the app launched.
func launchTermuxTailscaleApp() bool {
	for _, comp := range termuxTailscaleActivities {
		if command("am", "start", "-n", comp).Run() == nil {
			return true
		}
	}
	return command("monkey", "-p", "com.tailscale.ipn",
		"-c", "android.intent.category.LAUNCHER", "1").Run() == nil
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
	out, err := commandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// have reports whether a binary is resolvable on PATH.
func have(name string) bool {
	return haveExecutable(name)
}

// diskEncryption reports this device's at-rest encryption posture (best-effort).
// Android uses mandatory file-based encryption; on Linux we look for a dm-crypt
// (LUKS) layer under the root filesystem.
func diskEncryption() (on bool, detail string) {
	if runningUnderTermux() {
		return true, "Android file-based encryption (mandatory)"
	}
	if have("lsblk") {
		out, err := command("lsblk", "-no", "TYPE").Output()
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
	if runningUnderTermux() {
		return filepath.Join(os.Getenv("PREFIX"), "etc", "ssh", "ssh_host_ed25519_key.pub")
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
		if haveExecutable(c) {
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
		return command("pgrep", "-x", "sshd").Run() == nil
	}
	return listeningOn(port)
}

// listeningOn reports whether any local socket is in LISTEN on the given TCP
// port, using ss when available and otherwise parsing /proc/net/tcp{,6}.
func listeningOn(port int) bool {
	if have("ss") {
		if out, err := command("ss", "-Hltn").Output(); err == nil {
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

// SSHState reports install + running state using init-aware probes. Termux and
// hosts with no recognized init have no service manager, so a live sshd (or a
// listening port) is the running signal.
func (p *linuxPlatform) SSHState() (installed, running bool) {
	installed = sshdInstalled()
	switch {
	case p.termux:
		running = sshdRunning(p.SSHListenPort())
	case hasSystemd():
		running = systemdSSHActive()
	case hasOpenRC():
		running = command("rc-service", "sshd", "status").Run() == nil
	default:
		running = sshdRunning(p.SSHListenPort())
	}
	return installed, running
}

// sshSystemdUnits are the unit names an active SSH server may run under: the
// classic "ssh"/"sshd" service, or a socket-activated ssh.socket.
var sshSystemdUnits = []string{"ssh", "sshd", "ssh.socket"}

// systemdSSHActive reports whether systemd considers any SSH unit active, covering
// the classic ssh/sshd service and socket-activated ssh.socket.
func systemdSSHActive() bool {
	for _, u := range sshSystemdUnits {
		out, _ := command("systemctl", "is-active", u).Output()
		if strings.TrimSpace(string(out)) == "active" {
			return true
		}
	}
	return false
}

// InstallSSH installs the OpenSSH server via the detected package manager and
// generates any missing host keys. Idempotent (package managers no-op when the
// package is present; ssh-keygen -A only creates absent host keys).
func (p *linuxPlatform) InstallSSH() error {
	if p.termux {
		if err := p.run("pkg", "install", "-y", "openssh"); err != nil {
			return err
		}
		_ = p.run("ssh-keygen", "-A")
		return nil
	}

	if err := p.installOpenSSHServerPackage(); err != nil {
		return err
	}
	_ = p.run("ssh-keygen", "-A")
	p.openFirewall()
	return nil
}

// installOpenSSHServerPackage installs the OpenSSH server through the first
// available system package manager. DEBIAN_FRONTEND=noninteractive is passed via
// `env` so it survives the sudo boundary that p.run may insert.
func (p *linuxPlatform) installOpenSSHServerPackage() error {
	switch {
	case have("apt-get"):
		_ = p.run("apt-get", "update")
		return p.run("env", "DEBIAN_FRONTEND=noninteractive",
			"apt-get", "install", "-y", "openssh-server")
	case have("dnf"):
		return p.run("dnf", "install", "-y", "openssh-server")
	case have("yum"):
		return p.run("yum", "install", "-y", "openssh-server")
	case have("pacman"):
		return p.run("pacman", "-Sy", "--noconfirm", "openssh")
	case have("apk"):
		return p.run("apk", "add", "openssh", "openssh-keygen")
	default:
		return fmt.Errorf("no supported package manager (apt/dnf/yum/pacman/apk) found")
	}
}

// openFirewall best-effort opens SSH through a running host firewall. If ufw is
// active it allows the tailscale0 interface and the OpenSSH profile; otherwise,
// if firewalld is running it permanently adds the ssh service and reloads. It is
// a no-op when neither is active. Not used under Termux (unprivileged).
func (p *linuxPlatform) openFirewall() {
	if have("ufw") {
		if out, err := command("ufw", "status").Output(); err == nil &&
			strings.Contains(string(out), "Status: active") {
			_ = p.run("ufw", "allow", "in", "on", "tailscale0")
			_ = p.run("ufw", "allow", "OpenSSH")
			return
		}
	}
	if have("firewall-cmd") {
		if out, err := command("firewall-cmd", "--state").Output(); err == nil &&
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
	if runningUnderTermux() {
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
	out, err := command("pm", "list", "packages", "com.termux.boot").Output()
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
	return "#!" + termuxPrefix() + "/bin/sh\n"
}

// EnableSSH makes sshd start on boot and starts it now. With no recognized init
// system it falls back to a direct sshd start, which has no reboot persistence.
func (p *linuxPlatform) EnableSSH() error {
	switch {
	case p.termux:
		return p.enableTermuxSSHOnBoot()
	case hasSystemd():
		return p.enableSystemdSSH()
	case hasOpenRC():
		if err := p.run("rc-update", "add", "sshd", "default"); err != nil {
			return err
		}
		return p.run("rc-service", "sshd", "start")
	default:
		if err := p.run("sshd"); err != nil {
			return fmt.Errorf("no init system detected and direct sshd start failed: %w", err)
		}
		return nil
	}
}

// enableTermuxSSHOnBoot installs a Termux:Boot script that starts sshd at device
// boot (Termux:Boot runs every executable in ~/.termux/boot) and starts sshd now
// so the current session is reachable immediately.
func (p *linuxPlatform) enableTermuxSSHOnBoot() error {
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
	_ = command("sshd").Run()
	return nil
}

// enableSystemdSSH enables and starts the SSH server now, trying both unit names
// because Debian/Ubuntu ship "ssh" while RHEL/Arch ship "sshd".
func (p *linuxPlatform) enableSystemdSSH() error {
	if err := p.run("systemctl", "enable", "--now", "ssh"); err != nil {
		if err2 := p.run("systemctl", "enable", "--now", "sshd"); err2 != nil {
			return fmt.Errorf("enable ssh(d): %v / %v", err, err2)
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
		restoreSSHKeyLabels(dir, path)
	}
	return nil
}

// selinuxEnforcing reports whether SELinux is in enforcing mode (getenforce).
func selinuxEnforcing() bool {
	out, err := command("getenforce").Output()
	return err == nil && strings.TrimSpace(string(out)) == "Enforcing"
}

// restoreSSHKeyLabels relabels the ~/.ssh directory and key file (restorecon) so
// sshd's SELinux policy is permitted to read them. No-op unless SELinux enforces.
func restoreSSHKeyLabels(dir, path string) {
	if !selinuxEnforcing() {
		return
	}
	_ = command("restorecon", dir).Run()
	_ = command("restorecon", path).Run()
}

// EnsureTailnetMTU lowers the tailscale0 link MTU to tailnetSafeMTU when it is
// higher. It is a no-op under Termux (the tun belongs to the Tailscale Android app,
// which an unprivileged uid cannot reconfigure) and when this process is not root,
// since lowering a link MTU needs CAP_NET_ADMIN — a non-root daemon defers to a
// privileged run rather than shelling out to a sudo that would only prompt.
func (p *linuxPlatform) EnsureTailnetMTU() error {
	if p.termux {
		return nil
	}
	cur, ok := tailnetMTU()
	if !ok || cur <= tailnetSafeMTU {
		return nil
	}
	if os.Geteuid() != 0 {
		return nil
	}
	return p.run("ip", "link", "set", linuxTailscaleLink, "mtu", strconv.Itoa(tailnetSafeMTU))
}

// tailnetMTU reads the tailscale0 link MTU from sysfs — the same value
// EnsureTailnetMTU sets — needing no privilege. False when the interface is absent
// (Tailscale down, or the app-managed tun under Termux, which has no sysfs entry).
func tailnetMTU() (int, bool) {
	b, err := os.ReadFile(filepath.Join("/sys/class/net", linuxTailscaleLink, "mtu"))
	if err != nil {
		return 0, false
	}
	mtu, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, false
	}
	return mtu, true
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
		return p.installTermuxDaemon(exePath)
	}
	return p.installSystemdDaemon(exePath)
}

// installTermuxDaemon writes the Termux:Boot supervisor script and assists
// installing the Termux:Boot app that the boot script is inert without.
func (p *linuxPlatform) installTermuxDaemon(exePath string) error {
	dir, err := termuxBootDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	script := termuxDaemonSupervisorScript(exePath)
	path := filepath.Join(dir, "start-tailssh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		return err
	}
	p.ensureTermuxBoot()
	assistTermuxBattery()
	return nil
}

// termuxBatteryTargets are the apps whose battery optimisation must be relaxed so
// Android's Doze can't freeze them: Termux (hosts the tailssh daemon and sshd) and
// the Tailscale app (the transport — if it is frozen the phone is unreachable even
// though it shows online). Tailscale is opened last so it lands in the foreground.
var termuxBatteryTargets = []struct{ pkg, label string }{
	{"com.termux", "Termux"},
	{"com.tailscale.ipn", "Tailscale"},
}

// assistTermuxBattery opens each app's details screen so the user is one tap from
// setting it battery-"Unrestricted", which keeps the daemon and the tailnet alive
// through Doze. Android forbids exempting an app without user consent, so this can
// only open the right screen — it can't flip the toggle — and it is best-effort:
// printing the path matters more than the screen opening, and the daemon's wake lock
// already softens Doze while held.
func assistTermuxBattery() {
	fmt.Println("  battery     : set BOTH to \"Unrestricted\" so Doze can't freeze the mesh")
	fmt.Println("                (App info -> Battery -> Unrestricted; opening the screens):")
	for _, t := range termuxBatteryTargets {
		fmt.Printf("                - %s\n", t.label)
		_ = command("am", "start", "-a", "android.settings.APPLICATION_DETAILS_SETTINGS",
			"-d", "package:"+t.pkg).Run()
	}
}

// termuxDaemonSupervisorScript builds the Termux:Boot script that supervises the
// daemon: it restarts the daemon whenever it exits, so a crash or an Android kill
// self-heals. The wake lock is held by THIS loop, not the daemon, because it is
// app-global — it keeps the whole Termux process (supervisor and daemon alike)
// alive through Doze; held only in the daemon, Android could reap the
// wake-lock-less loop and leave the daemon unsupervised. Under battery-saver mode
// the wake lock is dropped, so the host is reachable only while the device is
// awake. PREFIX is exported so the daemon detects Termux (port + behavior)
// however the script is launched.
func termuxDaemonSupervisorScript(exePath string) string {
	wakelock := "termux-wake-lock\n"
	if os.Getenv("TAILSSH_BATTERY") == "saver" {
		wakelock = ""
	}
	return termuxShebang() +
		fmt.Sprintf("export PREFIX=%s\n", termuxPrefix()) +
		wakelock +
		"while true; do\n" +
		fmt.Sprintf("\t%q daemon\n", exePath) +
		"\tsleep 5\n" +
		"done\n"
}

// installSystemdDaemon renders the daemon's systemd unit, stages it in a
// user-writable temp file, and installs it as root (the unit directory is
// root-only). It restarts rather than merely starts the service so a reinstall
// picks up unit changes such as a new User=, which `enable --now` would not apply
// to an already-active service.
func (p *linuxPlatform) installSystemdDaemon(exePath string) error {
	unit := systemdDaemonUnit(exePath)

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
	return p.run("systemctl", "restart", linuxDaemonUnit)
}

// systemdDaemonUnit renders the systemd unit for the tailssh daemon. It runs as
// the human user (not root) so the daemon manages that user's ~/.ssh and, in
// /meta, advertises the right SSH login name: a root daemon would report "root",
// which cloud VMs and any host with PermitRootLogin=no refuse, breaking
// `ssh <name>` for that peer.
func systemdDaemonUnit(exePath string) string {
	userLine := ""
	if u := daemonUser(); u != "" && u != "root" {
		userLine = "User=" + u + "\n"
	}
	return fmt.Sprintf(`[Unit]
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
}

// RemoveDaemon uninstalls the daemon service.
func (p *linuxPlatform) RemoveDaemon() error {
	if p.termux {
		return p.removeTermuxDaemon()
	}

	_ = p.run("systemctl", "disable", "--now", linuxDaemonUnit)
	dest := filepath.Join("/etc/systemd/system", linuxDaemonUnit)
	if err := p.run("rm", "-f", dest); err != nil {
		return err
	}
	return p.run("systemctl", "daemon-reload")
}

// removeTermuxDaemon stops and uninstalls the Termux daemon. It kills the
// supervisor loop first so it can't respawn the daemon, then the daemon process,
// then releases the wake lock the supervisor was holding, and finally deletes the
// boot script.
func (p *linuxPlatform) removeTermuxDaemon() error {
	dir, err := termuxBootDir()
	if err != nil {
		return err
	}
	script := filepath.Join(dir, "start-tailssh")
	_ = command("pkill", "-f", script).Run()
	if exe, err := os.Executable(); err == nil {
		_ = command("pkill", "-f", exe+" daemon").Run()
	}
	_ = command("termux-wake-unlock").Run()
	if err := os.Remove(script); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

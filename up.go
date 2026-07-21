package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// backendState returns the tailscaled BackendState from `tailscale status --json`
// (e.g. "Running", "NeedsLogin", "Stopped"), or "" if it can't be read. A daemon
// that is up but logged out still makes `tailscale status` exit 0, so this is the
// only reliable signal that the node is actually authenticated.
func backendState() string {
	bin, err := tailscaleBin()
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "status", "--json").Output()
	if err != nil {
		return ""
	}
	var st struct {
		BackendState string `json:"BackendState"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return ""
	}
	return st.BackendState
}

// tailscaleReady reports whether the node is logged in (BackendState=="Running")
// and its tailnet is discoverable. discover() alone is insufficient because
// status exits 0 even when the daemon is running but logged out.
func tailscaleReady() bool {
	if backendState() != "Running" {
		return false
	}
	_, err := discover()
	return err == nil
}

// waitFor polls ok() until it is true or the timeout elapses. Used after an
// assisted (interactive) install so the bootstrap continues on its own instead
// of asking the user to re-run.
func waitFor(ok func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(3 * time.Second)
	}
	return true
}

// ensureTailscale brings up the network primitive: install (auto on desktop, or
// open the store on Android), then login, waiting for each to complete so the
// bootstrap flows straight through. Returns false only if it truly gives up.
func ensureTailscale(pl Platform) bool {
	if pl.Name() == "termux" {
		return ensureTailscaleTermux(pl)
	}

	if _, err := tailscaleBin(); err != nil {
		fmt.Println("Tailscale not installed — installing / opening the installer...")
		if e := pl.InstallTailscale(); e != nil {
			fmt.Printf("  tailscale   : %v\n", e)
		}
		if !waitFor(func() bool { _, e := tailscaleBin(); return e == nil }, 5*time.Minute) {
			fmt.Println("  tailscale   : not detected yet — install it, then re-run: tailssh up --yes")
			return false
		}
	}
	if tailscaleReady() {
		fmt.Println("  tailscale   : ready")
		return true
	}
	if ensureTailscaleAuthKeyJoin() {
		return true
	}
	return ensureTailscaleInteractiveLogin()
}

// ensureTailscaleTermux brings the network up on Android/Termux, which has no
// tailscale CLI: the primitive is the Android app and readiness is a tailnet IP
// present on an interface. Opens the app directly (not the Play Store) when it
// isn't connected and waits for the user to toggle it on. Reports whether the
// node is connected.
func ensureTailscaleTermux(pl Platform) bool {
	if selfTailnetIP() != "" {
		fmt.Println("  tailscale   : ready (app connected)")
		return true
	}
	fmt.Println("Tailscale app is not connected — opening it; toggle the switch ON...")
	_ = pl.InstallTailscale()
	if !waitFor(func() bool { return selfTailnetIP() != "" }, 5*time.Minute) {
		fmt.Println("  tailscale   : not connected — open the Tailscale app, connect, then re-run: tailssh up --yes")
		return false
	}
	fmt.Println("  tailscale   : ready (app connected)")
	return true
}

// ensureTailscaleAuthKeyJoin attempts a non-interactive `tailscale up --authkey`
// join when TS_AUTHKEY is supplied, removing the manual browser login on
// unattended/first-run setups. The key is read at use and never written to disk.
// Reports whether the node came up; callers fall back to interactive login.
func ensureTailscaleAuthKeyJoin() bool {
	key := os.Getenv("TS_AUTHKEY")
	if key == "" {
		return false
	}
	bin, err := tailscaleBin()
	if err != nil {
		return false
	}
	fmt.Println("Tailscale not logged in — joining with TS_AUTHKEY...")
	if exec.Command(bin, "up", "--authkey", key).Run() != nil {
		_ = exec.Command("sudo", bin, "up", "--authkey", key).Run()
	}
	if tailscaleReady() {
		fmt.Println("  tailscale   : ready")
		return true
	}
	return false
}

// ensureTailscaleInteractiveLogin starts `tailscale up`, which prints/opens the
// login URL, and polls readiness rather than blocking on it. The child is reaped
// afterward so it doesn't linger as a zombie. Reports whether login completed.
func ensureTailscaleInteractiveLogin() bool {
	fmt.Println("Tailscale not logged in — opening login...")
	var up *exec.Cmd
	if bin, e := tailscaleBin(); e == nil {
		up = exec.Command(bin, "up")
		up.Stdout, up.Stderr = os.Stdout, os.Stderr
		up.Start()
	}
	ok := waitFor(tailscaleReady, 5*time.Minute)
	if up != nil && up.Process != nil {
		go up.Wait()
	}
	if !ok {
		fmt.Println("  tailscale   : login not completed — finish it, then re-run: tailssh up --yes")
		return false
	}
	fmt.Println("  tailscale   : ready")
	return true
}

// enableTailscaleSSH makes this node reachable keyless via Tailscale SSH, retrying
// under sudo where setting the pref needs privilege. Only Linux/macOS can be a
// Tailscale SSH target; Windows/Termux fall back to the tailssh key mesh, so this
// is a no-op there.
func enableTailscaleSSH(pl Platform) {
	if pl.Name() != "linux" && pl.Name() != "darwin" {
		return
	}
	bin, err := tailscaleBin()
	if err != nil {
		return
	}
	if exec.Command(bin, "set", "--ssh").Run() != nil {
		_ = exec.Command("sudo", bin, "set", "--ssh").Run()
	}
	fmt.Println("  tailscale ssh: enabled (keyless inbound)")
}

// ensureSSH brings up the OpenSSH primitive (server + client + ssh-keygen), which
// every later stage depends on: auto-install, then enable. If it still isn't
// present (no package manager / assisted case), it stops with a clear pointer.
func ensureSSH(pl Platform) bool {
	installed, running := pl.SSHState()
	if !installed {
		fmt.Println("installing OpenSSH...")
		if err := pl.InstallSSH(); err != nil {
			fmt.Printf("  ssh server  : %v\n", err)
		}
		installed, running = pl.SSHState()
	}
	if !installed {
		fmt.Println("  ssh server  : could not auto-install — install OpenSSH, then re-run: tailssh up --yes")
		return false
	}
	if !running {
		fmt.Println("enabling sshd...")
		if err := pl.EnableSSH(); err != nil {
			fmt.Printf("  enable ssh  : %v\n", err)
		}
	}
	fmt.Println("  ssh server  : ready")
	return true
}

// upReadiness is the outcome of auditing the local device for tailssh: tailnet
// discovery, sshd state, and the app identity key. It seeds both the read-only
// plan and the provisioning flow, which refreshes it as stages bring pieces up.
type upReadiness struct {
	devices   []device
	self      device
	haveSelf  bool
	discErr   error
	installed bool
	running   bool
	keyPath   string
	keyOK     bool
}

// runUp audits the local device, prints a readiness report, and — only under
// --yes — provisions this node as a reachable SSH server. It provisions the
// *server*; sync owns all authorized_keys/config writes. Every mutating step is
// idempotent and optional-step failures never abort the run (log + continue).
func runUp(pl Platform, yes bool) error {
	fmt.Printf("tailssh readiness — %s/%s (%s)\n\n", runtime.GOOS, runtime.GOARCH, pl.Name())

	readiness := upAuditDevice(pl)
	if !yes {
		upPrintPlan(readiness)
		return nil
	}
	return upProvision(pl, readiness)
}

// upAuditDevice inspects tailnet reachability, the OpenSSH server state, and the
// presence of the tailssh identity key, printing one status line per primitive.
func upAuditDevice(pl Platform) upReadiness {
	var r upReadiness

	r.devices, r.discErr = discover()
	if r.discErr != nil {
		fmt.Printf("  tailscale   : MISSING (%v)\n", r.discErr)
	} else {
		r.self, r.haveSelf = selfDevice(r.devices)
		if r.haveSelf {
			fmt.Printf("  tailscale   : ok  (%s · %s)\n", r.self.name, r.self.ip)
		} else {
			fmt.Printf("  tailscale   : ok  (self not found in status)\n")
		}
	}

	r.installed, r.running = pl.SSHState()
	switch {
	case r.running:
		fmt.Printf("  ssh server  : ok  (running)\n")
	case r.installed:
		fmt.Printf("  ssh server  : installed but not running\n")
	default:
		fmt.Printf("  ssh server  : MISSING\n")
	}

	r.keyPath = appKeyPath()
	if _, err := os.Stat(r.keyPath); err == nil {
		r.keyOK = true
	}
	fmt.Printf("  app key     : %s  (%s)\n", mark(r.keyOK), r.keyPath)
	return r
}

// upPrintPlan reports what `tailssh up --yes` would change, or confirms the node
// is already provisioned. Read-only: it never mutates the device.
func upPrintPlan(r upReadiness) {
	fmt.Println()
	if r.discErr == nil && r.running && r.keyOK {
		fmt.Println("all set — run `tailssh sync` to refresh the mesh.")
		return
	}
	fmt.Println("tailssh up would:")
	if r.discErr != nil {
		fmt.Println("  - install Tailscale and run `tailscale up` (required prerequisite)")
	}
	if !r.installed {
		fmt.Println("  - install + enable the OpenSSH server for this OS")
	} else if !r.running {
		fmt.Println("  - start/enable the sshd service")
	}
	if !r.keyOK {
		fmt.Println("  - generate the tailssh SSH identity")
	}
	fmt.Println("  - sync the trusted-peer key block")
	fmt.Println("\nrun `tailssh up --yes` to apply")
}

// upProvision runs the ordered, primitives-first bootstrap under --yes: elevate
// if required, bring up the network, install + enable sshd, ensure the identity,
// join the mesh, and install the self-healing daemon. Each stage assumes the prior
// one may not have existed and builds it up; load-bearing stages that can't be
// satisfied stop with a clear pointer instead of failing downstream, while
// optional-step failures are logged and the run continues.
func upProvision(pl Platform, r upReadiness) error {
	if handled, err := upElevateIfNeeded(pl); err != nil {
		return err
	} else if handled {
		fmt.Println("\nprovisioned in an elevated instance — done.")
		return nil
	}

	if !upEnsureNetwork(pl, &r) {
		return nil
	}

	fmt.Println()

	if !ensureSSH(pl) {
		return nil
	}
	enableTailscaleSSH(pl)
	upEnsureSSHAcceptRule()
	upEnsureIdentity(pl)
	upJoinMesh(pl)
	upInstallDaemon(pl)

	fmt.Println()
	upPrintReachability(r.self, r.haveSelf)
	fmt.Println("tailssh up complete — peers can now reach this device.")
	return nil
}

// upElevateIfNeeded re-launches tailssh elevated on a Windows Administrators
// account (one UAC prompt) and hands provisioning to the elevated instance;
// without it, peer keys would land in the per-user authorized_keys file that sshd
// ignores for admins. A no-op where per-command sudo suffices (Linux/macOS).
// Reports whether the elevated instance took over the run.
func upElevateIfNeeded(pl Platform) (handled bool, err error) {
	handled, err = pl.EnsurePrivilege(os.Args[1:])
	if err != nil {
		return false, fmt.Errorf("elevation: %w", err)
	}
	return handled, nil
}

// upEnsureNetwork brings Tailscale up when the audit couldn't reach the tailnet,
// then re-runs discovery. Peer discovery is allowed to stay empty: a fresh
// CLI-less node has no roster yet and is handed one by a CLI peer once its daemon
// starts, so provisioning proceeds regardless. Reports whether to continue.
func upEnsureNetwork(pl Platform, r *upReadiness) bool {
	if r.discErr == nil {
		return true
	}
	if !ensureTailscale(pl) {
		return false
	}
	if r.devices, r.discErr = discover(); r.discErr == nil {
		r.self, r.haveSelf = selfDevice(r.devices)
	}
	return true
}

// upEnsureSSHAcceptRule ensures the tailnet's `ssh accept` policy rule when a
// Tailscale API token is present (TS_API_KEY), making Tailscale SSH seamless with
// no browser check. One-time and tailnet-wide; silently skipped without a token.
func upEnsureSSHAcceptRule() {
	if os.Getenv("TS_API_KEY") == "" {
		return
	}
	if err := applyACL(true, true); err != nil {
		fmt.Printf("  acl         : %v\n", err)
		return
	}
	fmt.Println("  acl         : ssh accept ensured")
}

// upEnsureIdentity generates the tailssh ed25519 identity now that ssh-keygen is
// present from the OpenSSH stage. Failure is non-fatal and the run continues.
func upEnsureIdentity(pl Platform) {
	if _, _, err := ensureIdentity(pl); err != nil {
		fmt.Printf("  app key     : FAILED (%v) — continuing\n", err)
		return
	}
	fmt.Println("  app key     : ok")
}

// upJoinMesh runs one sync to join the mesh; sync owns all authorized_keys and
// ssh_config writes. Failure is non-fatal and the run continues.
func upJoinMesh(pl Platform) {
	if err := runSync(pl); err != nil {
		fmt.Printf("  sync        : FAILED (%v) — continuing\n", err)
		return
	}
	fmt.Println("  sync        : ok")
}

// upInstallDaemon installs and starts the daemon so this node keeps serving its
// key and re-syncs on tailnet changes — the mechanism that makes the mesh
// self-heal. Failure is non-fatal and the run continues.
func upInstallDaemon(pl Platform) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if err := pl.InstallDaemon(exe); err != nil {
		fmt.Printf("  daemon      : FAILED (%v) — continuing\n", err)
		return
	}
	fmt.Println("  daemon      : installed")
}

// upPrintReachability prints the ssh command peers can use to reach this node,
// including a non-default port when one is set. No-op when self isn't in status.
func upPrintReachability(self device, haveSelf bool) {
	if !haveSelf {
		return
	}
	name := self.name
	if name == "" {
		name = self.host
	}
	if self.sshPort != 0 && self.sshPort != 22 {
		fmt.Printf("this node is reachable as:  ssh -p %d %s\n", self.sshPort, name)
		return
	}
	fmt.Printf("this node is reachable as:  ssh %s\n", name)
}

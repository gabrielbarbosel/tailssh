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
	// Termux has no tailscale CLI — the network primitive is the Android app, and
	// readiness is a tailnet IP present on an interface. Open the app directly (not
	// the Play Store) when it isn't connected, and wait for the user to toggle it on.
	if pl.Name() == "termux" {
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
	// Non-interactive join when an auth key is supplied via env (TS_AUTHKEY is read
	// at use and never written to disk): removes the manual browser login on
	// unattended/first-run setups. Falls through to interactive login if it fails.
	if key := os.Getenv("TS_AUTHKEY"); key != "" {
		if bin, e := tailscaleBin(); e == nil {
			fmt.Println("Tailscale not logged in — joining with TS_AUTHKEY...")
			if exec.Command(bin, "up", "--authkey", key).Run() != nil {
				_ = exec.Command("sudo", bin, "up", "--authkey", key).Run()
			}
			if tailscaleReady() {
				fmt.Println("  tailscale   : ready")
				return true
			}
		}
	}
	fmt.Println("Tailscale not logged in — opening login...")
	var up *exec.Cmd
	if bin, e := tailscaleBin(); e == nil {
		up = exec.Command(bin, "up")
		up.Stdout, up.Stderr = os.Stdout, os.Stderr
		up.Start() // prints/opens the login URL; we poll rather than block on it
	}
	ok := waitFor(tailscaleReady, 5*time.Minute)
	// Reap the `tailscale up` child so it doesn't linger as a zombie.
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

// enableTailscaleSSH makes this node reachable keyless via Tailscale SSH. Only
// Linux/macOS can be a Tailscale SSH target; Windows/Termux fall back to the
// tailssh key mesh, so this is a no-op there.
func enableTailscaleSSH(pl Platform) {
	if pl.Name() != "linux" && pl.Name() != "darwin" {
		return
	}
	bin, err := tailscaleBin()
	if err != nil {
		return
	}
	if exec.Command(bin, "set", "--ssh").Run() != nil {
		// Setting the pref may need privilege on some hosts.
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

// runUp audits the local device, prints a readiness report, and — only under
// --yes — provisions this node as a reachable SSH server: install + enable sshd,
// ensure the tailssh identity, and run one sync to join the mesh. It provisions
// the *server*; sync owns all authorized_keys/config writes. Every mutating step
// is idempotent and optional-step failures never abort the run (log + continue).
func runUp(pl Platform, yes bool) error {
	fmt.Printf("tailssh readiness — %s/%s (%s)\n\n", runtime.GOOS, runtime.GOARCH, pl.Name())

	devices, derr := discover()
	var self device
	haveSelf := false
	if derr != nil {
		fmt.Printf("  tailscale   : MISSING (%v)\n", derr)
	} else {
		self, haveSelf = selfDevice(devices)
		if haveSelf {
			fmt.Printf("  tailscale   : ok  (%s · %s)\n", self.name, self.ip)
		} else {
			fmt.Printf("  tailscale   : ok  (self not found in status)\n")
		}
	}

	installed, running := pl.SSHState()
	switch {
	case running:
		fmt.Printf("  ssh server  : ok  (running)\n")
	case installed:
		fmt.Printf("  ssh server  : installed but not running\n")
	default:
		fmt.Printf("  ssh server  : MISSING\n")
	}

	keyPath := appKeyPath()
	keyOK := false
	if _, err := os.Stat(keyPath); err == nil {
		keyOK = true
	}
	fmt.Printf("  app key     : %s  (%s)\n", mark(keyOK), keyPath)

	// Read-only audit mode: report the plan and stop without mutating.
	if !yes {
		fmt.Println()
		if derr == nil && running && keyOK {
			fmt.Println("all set — run `tailssh sync` to refresh the mesh.")
			return nil
		}
		fmt.Println("tailssh up would:")
		if derr != nil {
			fmt.Println("  - install Tailscale and run `tailscale up` (required prerequisite)")
		}
		if !installed {
			fmt.Println("  - install + enable the OpenSSH server for this OS")
		} else if !running {
			fmt.Println("  - start/enable the sshd service")
		}
		if !keyOK {
			fmt.Println("  - generate the tailssh SSH identity")
		}
		fmt.Println("  - sync the trusted-peer key block")
		fmt.Println("\nrun `tailssh up --yes` to apply")
		return nil
	}

	// Apply mode — an ordered, primitives-first bootstrap. Each stage assumes the
	// prior one may not have existed and builds it up; load-bearing stages that
	// can't be satisfied stop with a clear pointer instead of failing downstream.

	// STAGE 1 — network. Ensure Tailscale is up (CLI logged in, or the Android app
	// connected on Termux). We do NOT require peer discovery to succeed: a fresh
	// CLI-less node has no roster yet and will be handed one by a CLI peer after its
	// daemon starts, so we proceed to provision the local server either way.
	if derr != nil {
		if !ensureTailscale(pl) {
			return nil
		}
		if devices, derr = discover(); derr == nil {
			self, haveSelf = selfDevice(devices)
		}
	}

	fmt.Println()

	// STAGE 2 — OpenSSH (server + client + ssh-keygen), which STAGE 3+ depend on.
	if !ensureSSH(pl) {
		return nil
	}

	// STAGE 2.5 — on Linux/macOS, turn on Tailscale SSH so peers reach us keyless
	// (the hybrid: Tailscale SSH here, tailssh key mesh on Windows/Android).
	enableTailscaleSSH(pl)

	// Opportunistic: if a Tailscale API token is present, ensure the tailnet's
	// `ssh accept` rule so Tailscale SSH is seamless (no browser check). One-time,
	// tailnet-wide; silently skipped without a token. Set TS_API_KEY once.
	if os.Getenv("TS_API_KEY") != "" {
		if err := applyACL(true, true); err != nil {
			fmt.Printf("  acl         : %v\n", err)
		} else {
			fmt.Println("  acl         : ssh accept ensured")
		}
	}

	// STAGE 3 — the tailssh ed25519 identity (ssh-keygen now exists from STAGE 2).
	if _, _, err := ensureIdentity(pl); err != nil {
		fmt.Printf("  app key     : FAILED (%v) — continuing\n", err)
	} else {
		fmt.Println("  app key     : ok")
	}

	// Join the mesh: sync owns all authorized_keys / ssh_config writes.
	if err := runSync(pl); err != nil {
		fmt.Printf("  sync        : FAILED (%v) — continuing\n", err)
	} else {
		fmt.Println("  sync        : ok")
	}

	// Install + start the daemon so this node keeps serving its key and re-syncs
	// on tailnet changes — this is what makes the mesh self-heal.
	if exe, err := os.Executable(); err == nil {
		if err := pl.InstallDaemon(exe); err != nil {
			fmt.Printf("  daemon      : FAILED (%v) — continuing\n", err)
		} else {
			fmt.Println("  daemon      : installed")
		}
	}

	fmt.Println()
	if haveSelf {
		name := self.name
		if name == "" {
			name = self.host
		}
		if self.sshPort != 0 && self.sshPort != 22 {
			fmt.Printf("this node is reachable as:  ssh -p %d %s\n", self.sshPort, name)
		} else {
			fmt.Printf("this node is reachable as:  ssh %s\n", name)
		}
	}
	fmt.Println("tailssh up complete — peers can now reach this device.")
	return nil
}

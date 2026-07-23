// tailssh — federated cross-platform SSH mesh over a Tailscale tailnet.
//
// It is a thin layer over Tailscale: discovery, identity and transport come from
// the tailnet; tailssh adds a uniform SSH server per OS, federated key exchange,
// and a device directory. Nothing is hardcoded — every value is read at runtime.
//
// Phase 1: discovery + directory (`tailssh list`).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// node mirrors the fields tailssh needs from a `tailscale status --json` node.
type node struct {
	StableID     string   `json:"ID"` // stable trust + cache key
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	OS           string   `json:"OS"`
	Online       bool     `json:"Online"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	UserID       int64    `json:"UserID"`
}

type status struct {
	MagicDNSSuffix string                 `json:"MagicDNSSuffix"`
	Self           *node                  `json:"Self"`
	Peer           map[string]*node       `json:"Peer"`
	User           map[string]userProfile `json:"User"`
}

type userProfile struct {
	LoginName string `json:"LoginName"`
}

// device is a normalized tailnet member.
type device struct {
	name, host, os, ip, owner string
	online, self              bool
	sshPort                   int // Termux sshd can't bind 22
}

var cachedBin string

// tailscaleBin locates the tailscale CLI across platforms (resolved once).
func tailscaleBin() (string, error) {
	if cachedBin != "" {
		return cachedBin, nil
	}
	for _, c := range []string{
		"tailscale",
		`C:\Program Files\Tailscale\tailscale.exe`,
		"/usr/bin/tailscale",
		"/usr/local/bin/tailscale",
		"/Applications/Tailscale.app/Contents/MacOS/Tailscale",
	} {
		if p, err := exec.LookPath(c); err == nil {
			cachedBin = p
			return p, nil
		}
		if isExplicitPath(c) {
			if _, err := os.Stat(c); err == nil {
				cachedBin = c
				return c, nil
			}
		}
	}
	return "", fmt.Errorf("tailscale CLI not found (is Tailscale installed and running?)")
}

// isExplicitPath reports whether a candidate names a filesystem location rather
// than a bare command. Only explicit paths may be stat'd: os.Stat of a bare name
// like "tailscale" would match a file in the cwd and shadow the real absolute
// install locations, so bare names are resolved through PATH (LookPath) alone.
func isExplicitPath(candidate string) bool {
	return strings.ContainsRune(candidate, filepath.Separator) || strings.ContainsRune(candidate, '/')
}

// discover returns the tailnet members. On hosts with the tailscale CLI it reads
// `tailscale status` (authoritative); on CLI-less hosts (Android/Termux, where the
// app hides the CLI) it uses the roster a CLI peer pushed to us (no seed needed).
func discover() ([]device, error) {
	if _, err := tailscaleBin(); err == nil {
		return discoverCLI()
	}
	return discoverCLIless()
}

// discoverCLI reads the tailnet directly from the local `tailscale status --json`.
func discoverCLI() ([]device, error) {
	bin, err := tailscaleBin()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "status", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("tailscale status failed: %w", err)
	}
	var st status
	if err := json.Unmarshal(out, &st); err != nil {
		return nil, err
	}

	toDevice := func(n *node, self bool) device {
		host := strings.TrimSuffix(n.DNSName, ".")
		name := host
		if suf := "." + st.MagicDNSSuffix; st.MagicDNSSuffix != "" && strings.HasSuffix(host, suf) {
			name = strings.TrimSuffix(host, suf)
		}
		ip := ""
		if len(n.TailscaleIPs) > 0 {
			ip = n.TailscaleIPs[0]
		}
		port := 22
		if n.OS == "android" {
			port = 8022
		}
		return device{
			name: name, host: host, os: n.OS, ip: ip,
			owner:  st.User[fmt.Sprint(n.UserID)].LoginName,
			online: self || n.Online, self: self, sshPort: port,
		}
	}

	var devices []device
	if st.Self != nil {
		devices = append(devices, toDevice(st.Self, true))
	}
	for _, p := range st.Peer {
		devices = append(devices, toDevice(p, false))
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].self != devices[j].self {
			return devices[i].self
		}
		return devices[i].name < devices[j].name
	})
	return devices, nil
}

// renderList prints the devices as an aligned directory table.
func renderList(devices []device) {
	head := []string{"DEVICE", "OS", "OWNER", "STATE", "CONNECT"}
	rows := [][]string{}
	online := 0
	for _, d := range devices {
		name := d.name
		if d.self {
			name += " (this)"
		}
		state := "offline"
		if d.online {
			state, online = "online", online+1
		}
		connect := "ssh " + d.name
		if d.sshPort != 22 {
			connect = fmt.Sprintf("ssh %s  (:%d)", d.name, d.sshPort)
		}
		rows = append(rows, []string{name, d.os, d.owner, state, connect})
	}

	w := make([]int, len(head))
	for i, h := range head {
		w[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if len(c) > w[i] {
				w[i] = len(c)
			}
		}
	}
	printRow := func(r []string) {
		parts := make([]string, len(r))
		for i, c := range r {
			parts[i] = c + strings.Repeat(" ", w[i]-len(c))
		}
		fmt.Println(strings.TrimRight(strings.Join(parts, "  "), " "))
	}
	printRow(head)
	sep := make([]string, len(head))
	for i := range head {
		sep[i] = strings.Repeat("-", w[i])
	}
	fmt.Println(strings.Join(sep, "  "))
	for _, r := range rows {
		printRow(r)
	}
	fmt.Printf("\n%d devices, %d online\n", len(rows), online)
}

// appKeyPath is where tailssh keeps its own SSH identity (kept out of ~/.ssh
// so it stays invisible to the user).
func appKeyPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "tailssh", "id_ed25519")
}

// mark renders a boolean readiness flag (used by the `up` audit).
func mark(ok bool) string {
	if ok {
		return "ok"
	}
	return "MISSING"
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// runSyncCommand runs a manual sync. Because it writes the same system-wide files
// provisioning does, it self-elevates on a Windows admin account before syncing —
// the daemon's own syncs already run elevated via its scheduled task. When the
// call was handled by re-launching elevated, it returns without syncing here.
// EnsurePrivilege is a no-op on the other platforms.
func runSyncCommand(pl Platform) error {
	if handled, err := pl.EnsurePrivilege(os.Args[1:]); err != nil {
		return err
	} else if handled {
		return nil
	}
	return runSync(pl)
}

func main() {
	cmd := "list"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "list":
		devices, err := discover()
		if err != nil {
			fail(err)
		}
		renderList(devices)
	case "up":
		yes := false
		for _, a := range os.Args[2:] {
			if a == "--yes" || a == "-y" {
				yes = true
			}
		}
		if err := runUp(selectPlatform(), yes); err != nil {
			fail(err)
		}
	case "status":
		if err := runStatus(selectPlatform()); err != nil {
			fail(err)
		}
	case "sync":
		if err := runSyncCommand(selectPlatform()); err != nil {
			fail(err)
		}
	case "daemon":
		if err := runDaemon(selectPlatform()); err != nil {
			fail(err)
		}
	case "acl":
		apply := false
		for _, a := range os.Args[2:] {
			if a == "--apply" {
				apply = true
			}
		}
		if err := runACL(apply); err != nil {
			fail(err)
		}
	case "off":
		if err := runOff(selectPlatform()); err != nil {
			fail(err)
		}
	case "uninstall":
		if err := runUninstall(selectPlatform()); err != nil {
			fail(err)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: tailssh (list | status | up [--yes] | sync | daemon | acl [--apply] | off | uninstall)")
		os.Exit(1)
	}
}

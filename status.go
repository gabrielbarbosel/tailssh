package main

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"
)

// installCmdUnix and installCmdWindows are the one-command network bootstraps a fresh
// device runs to join the mesh: it fetches the binary from the repo and runs
// `tailssh up`. Onboarding is a fetch-from-network run once ON the new device — not a
// device-to-device push — so it depends on nothing but the release and works
// identically on every device.
const (
	installCmdUnix    = "curl -fsSL https://raw.githubusercontent.com/gabrielbarbosel/tailssh/main/install.sh | sh"
	installCmdWindows = "irm https://raw.githubusercontent.com/gabrielbarbosel/tailssh/main/install.ps1 | iex"
)

// runStatus prints a read-only health view of the mesh from this node: the local
// SSH server and security posture, then every same-owner peer's reachability
// (online, how we reach it, and whether it is currently serving its key). It only
// reads — no authorized_keys/config/identity is touched — so it is safe to run any
// time to see why `ssh <name>` does or doesn't work.
func runStatus(pl Platform) error {
	fmt.Printf("tailssh status — %s/%s (%s)\n\n", runtime.GOOS, runtime.GOARCH, pl.Name())

	devs, err := discover()
	if err != nil {
		fmt.Printf("  tailnet     : UNREACHABLE (%v)\n", err)
		return nil
	}
	self, haveSelf := selfDevice(devs)

	statusPrintLocalNode(pl, self, haveSelf)
	statusPrintPeers(statusOwnedPeers(devs, self), loadPeers())
	return nil
}

// statusPrintLocalNode prints this node's identity, SSH server state, keyserver
// reachability, disk-encryption posture, and any persistence caveat.
func statusPrintLocalNode(pl Platform, self device, haveSelf bool) {
	if haveSelf {
		fmt.Printf("  this node   : %s  (%s)\n", nameOr(self), self.ip)
	}
	installed, running := pl.SSHState()
	fmt.Printf("  ssh server  : %s\n", sshStateLabel(installed, running))
	fmt.Printf("  keyserver   : %s\n", upDown(haveSelf && keyserverUp(self.ip)))
	if mtu, ok := tailnetMTU(); ok {
		fmt.Printf("  tailnet mtu : %s\n", mtuLabel(mtu))
	}
	if on, detail := diskEncryption(); on {
		fmt.Printf("  disk crypto : on — %s\n", detail)
	} else {
		fmt.Printf("  disk crypto : %s\n", detail)
	}
	if note := persistenceNote(); note != "" {
		fmt.Printf("  persistence : %s\n", note)
	}
}

// statusOwnedPeers returns the addressable, same-owner peers of self sorted by
// name — the nodes `ssh <name>` could plausibly reach. Peers owned by someone
// else are excluded only when self's owner is known.
func statusOwnedPeers(devs []device, self device) []device {
	var peers []device
	for _, d := range devs {
		if d.self || d.ip == "" || (self.owner != "" && d.owner != self.owner) {
			continue
		}
		peers = append(peers, d)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].name < peers[j].name })
	return peers
}

// statusPrintPeers prints one reachability row per peer: online state, how we
// reach it, and whether it is currently serving its key. It then points out any
// online same-owner device that isn't reachable yet because it doesn't run tailssh,
// with the one-command bootstrap to bring it in.
func statusPrintPeers(peers []device, cache map[string]cachedPeer) {
	fmt.Printf("\n  peers (%d):\n", len(peers))
	var needBootstrap []device
	for _, p := range peers {
		_, keyed := cache[p.name]
		reach := statusPeerReach(p, keyed)
		fmt.Printf("    %-18s %-8s %-14s %-8s ssh %s\n",
			nameOr(p), statusPeerState(p), reach, servingLabel(p.online && inMesh(p.ip)), nameOr(p))
		if p.online && reach == statusReachUnreachable {
			needBootstrap = append(needBootstrap, p)
		}
	}
	statusPrintBootstrapHint(needBootstrap)
}

// statusPrintBootstrapHint lists any online device that can't be reached until it
// joins the mesh and gives the network bootstrap to run on it. Nothing is pushed to
// the device — Android forbids executing a delivered binary — so joining is always a
// single fetch-and-run on that device, the same command everywhere.
func statusPrintBootstrapHint(peers []device) {
	if len(peers) == 0 {
		return
	}
	names := make([]string, 0, len(peers))
	for _, p := range peers {
		names = append(names, nameOr(p))
	}
	fmt.Printf("\n  not in mesh : %s\n", strings.Join(names, ", "))
	fmt.Printf("  bootstrap   : run on that device —\n")
	fmt.Printf("                Linux/macOS/Termux : %s\n", installCmdUnix)
	fmt.Printf("                Windows (elevated) : %s\n", installCmdWindows)
}

func statusPeerState(p device) string {
	if p.online {
		return "online"
	}
	return "offline"
}

// statusReachUnreachable is the reach label for an online peer that runs neither
// tailssh (no cached key) nor a Tailscale-SSH-capable OS — it can't be reached until
// it joins the mesh, which is what triggers the bootstrap hint.
const statusReachUnreachable = "unreachable"

// statusPeerReach names the transport `ssh <name>` would use: the key mesh once a
// peer's key is cached, tailscale-ssh for Linux/macOS peers we haven't keyed, and
// unreachable otherwise (e.g. Windows without a cached key).
func statusPeerReach(p device, keyed bool) string {
	switch {
	case keyed:
		return "key mesh"
	case p.os == "linux" || p.os == "macOS":
		return "tailscale-ssh"
	}
	return statusReachUnreachable
}

// servingLabel renders the key-serving column: "serving" when the peer answers its
// keyserver right now, blank otherwise.
func servingLabel(serving bool) string {
	if serving {
		return "serving"
	}
	return ""
}

// inMesh reports whether a peer already runs tailssh (i.e. serves /pubkey).
func inMesh(ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := getBounded(ctx, fmt.Sprintf("http://%s:%d/pubkey", hostForURL(ip), keyPort), 4096)
	return err == nil
}

// keyserverUp reports whether this node's own keyserver answers on its tailnet IP.
func keyserverUp(ip string) bool {
	if ip == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := getBounded(ctx, fmt.Sprintf("http://%s:%d/pubkey", hostForURL(ip), keyPort), 4096)
	return err == nil
}

func nameOr(d device) string {
	if d.name != "" {
		return d.name
	}
	return d.host
}

func upDown(b bool) string {
	if b {
		return "up"
	}
	return "down"
}

// mtuLabel describes the tailnet interface MTU: at/below the safe value it is fine,
// above it a direct path with a broken PMTU (typically to a phone) can blackhole
// large packets, which the daemon's next MTU pass — or `tailssh up` — will clamp.
func mtuLabel(mtu int) string {
	if mtu <= tailnetSafeMTU {
		return fmt.Sprintf("%d (ok)", mtu)
	}
	return fmt.Sprintf("%d (high — large packets may stall on direct paths to phones; clamps to %d)", mtu, tailnetSafeMTU)
}

func sshStateLabel(installed, running bool) string {
	switch {
	case running:
		return "running"
	case installed:
		return "installed (not running)"
	default:
		return "missing"
	}
}

package main

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"time"
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
// reach it, and whether it is currently serving its key.
func statusPrintPeers(peers []device, cache map[string]cachedPeer) {
	fmt.Printf("\n  peers (%d):\n", len(peers))
	for _, p := range peers {
		_, keyed := cache[p.name]
		fmt.Printf("    %-18s %-8s %-14s %-8s ssh %s\n",
			nameOr(p), statusPeerState(p), statusPeerReach(p, keyed), statusPeerServing(p), nameOr(p))
	}
}

func statusPeerState(p device) string {
	if p.online {
		return "online"
	}
	return "offline"
}

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
	return "unreachable"
}

func statusPeerServing(p device) string {
	if p.online && inMesh(p.ip) {
		return "serving"
	}
	return ""
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

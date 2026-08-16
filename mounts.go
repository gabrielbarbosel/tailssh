package main

// mounts.go — the file mesh (OS-agnostic core).
//
// Every tailssh node already serves its whole filesystem over SFTP (its sshd), so
// "serving" needs no code here. This mounts every same-owner, ONLINE peer's whole
// filesystem read-write as a local network unit — a drive letter on Windows, a
// folder on Unix — and tears it down when the peer goes offline or leaves. It rides
// the exact name@host:port + identity that `sync` already wrote into ~/.ssh/config:
// no new channel, no new listener, no data at rest (the client runs with caching
// off / in-memory only). Access is tailnet membership; off the tailnet the peer is
// unreachable, so a mount holds nothing — the cutoff is by construction.
//
// reconcileMounts is the 5th idempotent step of runSync, so it inherits the daemon's
// netmap-triggered, debounced, serialized loop for free: the mount appears when a
// peer comes online and vanishes when it drops — the file twin of the managed
// authorized_keys block. A node that cannot mount (Termux: no root FUSE) is a clean
// no-op; it still serves its own files to the mesh.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// mountSpec is everything needed to mount one peer's whole filesystem over the SSH
// mesh — the same reach info sync already resolved, plus this node's identity and
// the tailssh-managed known_hosts for non-interactive trust.
type mountSpec struct {
	Name       string // peer name — the mount label / directory name
	User       string // remote login (from the peer's /meta, cached in peers.json)
	Host       string // reach address: peer name (MagicDNS), else tailnet IP
	Port       int    // remote sshd port
	Identity   string // this node's tailssh private key (appKeyPath)
	KnownHosts string // tailssh-managed known_hosts
}

// mountsStatePath is the fully-owned record of peer→mountpoint (like known_hosts,
// replaced wholesale). It lets reconcile reuse a peer's mountpoint across passes and
// unmount exactly what it mounted, surviving a restart.
func mountsStatePath() string {
	return filepath.Join(filepath.Dir(appKeyPath()), "mounts.json")
}

// loadMounts reads the peer→mountpoint record; a missing/broken file is an empty map.
func loadMounts() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(mountsStatePath())
	if err != nil {
		return m
	}
	_ = json.Unmarshal(b, &m)
	return m
}

// saveMounts persists the record atomically, skipping a no-op write.
func saveMounts(m map[string]string) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	if sameContent(mountsStatePath(), b) {
		return
	}
	_ = atomicWrite(mountsStatePath(), b, 0o600)
}

// reconcileMounts brings this node's peer mounts in line with the tailnet: mount
// every online same-owner peer whose remote login we know, and unmount anything that
// went offline or left. Prune-safe: it only ever acts on a set derived from a
// successful discover (its caller returns before this on a failed/degraded read).
func reconcileMounts(pl Platform, owned []device, keyed map[string]cachedPeer) error {
	if _, canMount := pl.MountSupport(); !canMount {
		return nil // e.g. Termux: no root FUSE — serve-only node
	}
	kh, _ := knownHostsPath()
	id := appKeyPath()

	want := map[string]mountSpec{}
	for _, d := range owned {
		if !d.online || d.name == "" {
			continue // don't mount an offline peer; it would just hang
		}
		c, ok := keyed[d.name]
		if !ok || c.User == "" {
			continue // no /meta login yet — can't build a reachable target
		}
		host := d.name
		if host == "" {
			host = d.ip
		}
		want[d.name] = mountSpec{
			Name: d.name, User: c.User, Host: host,
			Port: sshPortFor(d.os, c.Port), Identity: id, KnownHosts: kh,
		}
	}

	var firstErr error
	note := func(e error) {
		if e != nil {
			fmt.Fprintln(os.Stderr, "mounts:", e)
			if firstErr == nil {
				firstErr = e
			}
		}
	}

	state := loadMounts()
	next := map[string]string{}
	// Mount/refresh in a stable order so per-OS mountpoint allocation is deterministic.
	for _, name := range sortedSpecNames(want) {
		at, err := pl.MountPeer(want[name], state[name])
		if err != nil {
			note(err)
			if state[name] != "" {
				next[name] = state[name] // keep the record; retry next pass
			}
			continue
		}
		next[name] = at
	}
	// Unmount peers no longer wanted (offline or left the tailnet) — the cutoff.
	for name, at := range state {
		if _, keep := want[name]; keep {
			continue
		}
		note(pl.UnmountPeer(at))
	}

	saveMounts(next)
	return firstErr
}

// unmountAll tears down every recorded mount and clears the record — used by
// `uninstall`/`off` so no network unit is left dangling. Best-effort.
func unmountAll(pl Platform) {
	if _, canMount := pl.MountSupport(); !canMount {
		return
	}
	for _, at := range loadMounts() {
		_ = pl.UnmountPeer(at)
	}
	_ = os.Remove(mountsStatePath())
}

// sortedSpecNames returns the map keys sorted, for deterministic iteration.
func sortedSpecNames(m map[string]mountSpec) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

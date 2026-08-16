//go:build unix

package main

// mounts_unix.go — the sshfs client shared by Linux and macOS. The mount command is
// identical on both (sshfs over the mesh identity, no on-disk cache); only the
// unmount verb and the tooling install differ, so those stay in the platform files.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// unixMountpoint is where a peer's filesystem mounts on a Unix node —
// <config>/tailssh/mnt/<peer>, the same directory family as every other tailssh
// artifact. No hardcoded path.
func unixMountpoint(name string) string {
	return filepath.Join(filepath.Dir(appKeyPath()), "mnt", name)
}

// pathIsMountpoint reports whether path is currently a mount: an entry in
// /proc/mounts on Linux, or a match in `mount` output on macOS (no /proc).
func pathIsMountpoint(path string) bool {
	if b, err := os.ReadFile("/proc/mounts"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[1] == path {
				return true
			}
		}
		return false
	}
	out, err := command("mount").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), " on "+path+" ")
}

// sshfsMount mounts spec's whole filesystem read-write at `at` via sshfs, reusing the
// same private key + known_hosts sync already wrote, with no on-disk cache
// (sshfs caches in memory only). Idempotent: a no-op when `at` is already a mount.
func sshfsMount(spec mountSpec, at string) error {
	if pathIsMountpoint(at) {
		return nil
	}
	if err := os.MkdirAll(at, 0o700); err != nil {
		return err
	}
	opts := fmt.Sprintf(
		"IdentityFile=%s,IdentitiesOnly=yes,UserKnownHostsFile=%s,StrictHostKeyChecking=accept-new,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,cache=no,follow_symlinks",
		spec.Identity, spec.KnownHosts)
	args := []string{
		fmt.Sprintf("%s@%s:/", spec.User, spec.Host), at,
		"-p", strconv.Itoa(spec.Port), "-o", opts,
	}
	if out, err := command("sshfs", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("sshfs %s: %v: %s", spec.Name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

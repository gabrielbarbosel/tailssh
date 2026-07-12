package main

// admin.go — the two teardown commands.
//   off       : turn the service OFF (stop the daemon) but keep identity + the
//               currently authorized peers, so the device stays reachable.
//   uninstall : remove tailssh from the machine — daemon, managed key/config
//               blocks (revoking peer access), identity/cache, and the binary.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// runOff stops and removes the daemon service. Nothing else is touched, so
// inbound SSH still works with the keys already authorized. `tailssh up` re-arms it.
func runOff(pl Platform) error {
	if err := pl.RemoveDaemon(); err != nil {
		fmt.Printf("  daemon    : %v\n", err)
	} else {
		fmt.Println("  daemon    : off (service stopped & removed)")
	}
	fmt.Println("tailssh is off — identity and authorized keys kept. `tailssh up` turns it back on.")
	return nil
}

// runUninstall removes tailssh from this machine entirely.
func runUninstall(pl Platform) error {
	if err := pl.RemoveDaemon(); err != nil {
		fmt.Printf("  daemon         : %v\n", err)
	} else {
		fmt.Println("  daemon         : removed")
	}

	// Revoke inbound access: clear the managed authorized_keys block.
	if path, err := pl.AuthorizedKeysPath(); err == nil {
		clearManagedBlock(path, pl)
		fmt.Printf("  authorized_keys: managed block cleared\n")
	}

	if home, err := os.UserHomeDir(); err == nil {
		clearManagedBlock(filepath.Join(home, ".ssh", "config"), nil)
		fmt.Printf("  ssh_config     : managed block cleared\n")
	}

	// dir holds the app identity + peer cache.
	dir := filepath.Dir(appKeyPath())
	if err := os.RemoveAll(dir); err != nil {
		fmt.Printf("  identity/cache : remove failed — %v\n", err)
	} else {
		fmt.Printf("  identity/cache : removed (%s)\n", dir)
	}

	// Best-effort binary removal (may be locked while running on Windows).
	if exe, err := os.Executable(); err == nil {
		if os.Remove(exe) != nil {
			fmt.Printf("  binary         : remove manually — %s\n", exe)
		} else {
			fmt.Printf("  binary         : removed (%s)\n", exe)
		}
	}

	fmt.Println("tailssh uninstalled.")
	return nil
}

// clearManagedBlock removes the tailssh-managed region from a file, keeping the
// user's own content, and re-secures it via pl when pl != nil.
func clearManagedBlock(path string, pl Platform) {
	existing, err := os.ReadFile(path)
	if err != nil {
		return
	}
	stripped := strings.TrimRight(stripManagedBlock(string(existing)), "\n") + "\n"
	if sameContent(path, []byte(stripped)) {
		return
	}
	if atomicWrite(path, []byte(stripped), 0o600) == nil && pl != nil {
		pl.SecureKeyFile(path)
	}
}

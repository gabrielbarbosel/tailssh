package main

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

// runUninstall removes tailssh from this machine entirely: daemon, managed
// key/config blocks (revoking peer access), identity/cache, and the binary.
// Every step is best-effort and reports its own outcome, so one failure still
// leaves the machine as clean as possible.
func runUninstall(pl Platform) error {
	if err := pl.RemoveDaemon(); err != nil {
		fmt.Printf("  daemon         : %v\n", err)
	} else {
		fmt.Println("  daemon         : removed")
	}

	adminRevokeInboundAccess(pl)
	adminClearSSHConfig()
	adminRemoveIdentityCache()
	adminRemoveBinary()

	fmt.Println("tailssh uninstalled.")
	return nil
}

// adminRevokeInboundAccess clears the managed authorized_keys block, which is
// what actually cuts peers off from this host. A platform that cannot report an
// authorized_keys path has nothing to revoke.
func adminRevokeInboundAccess(pl Platform) {
	path, err := pl.AuthorizedKeysPath()
	if err != nil {
		return
	}
	if err := clearManagedBlock(path, pl); err != nil {
		fmt.Printf("  authorized_keys: NOT cleared — %v\n", err)
		return
	}
	fmt.Printf("  authorized_keys: managed block cleared\n")
}

// adminClearSSHConfig drops the managed outbound host entries from ~/.ssh/config.
// The file belongs to the user, not to a privileged daemon, so it needs no
// platform re-securing.
func adminClearSSHConfig() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	if err := clearManagedBlock(filepath.Join(home, ".ssh", "config"), nil); err != nil {
		fmt.Printf("  ssh_config     : NOT cleared — %v\n", err)
		return
	}
	fmt.Printf("  ssh_config     : managed block cleared\n")
}

// adminRemoveIdentityCache deletes the directory holding the app identity and
// the peer cache.
func adminRemoveIdentityCache() {
	dir := filepath.Dir(appKeyPath())
	if err := os.RemoveAll(dir); err != nil {
		fmt.Printf("  identity/cache : remove failed — %v\n", err)
		return
	}
	fmt.Printf("  identity/cache : removed (%s)\n", dir)
}

// adminRemoveBinary deletes the running executable, falling back to a manual
// instruction because Windows keeps the image locked while it executes.
func adminRemoveBinary() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if os.Remove(exe) != nil {
		fmt.Printf("  binary         : remove manually — %s\n", exe)
		return
	}
	fmt.Printf("  binary         : removed (%s)\n", exe)
}

// clearManagedBlock removes the tailssh-managed region from a file, keeping the
// user's own content, and re-secures it via pl when pl != nil. An absent file is
// not an error — uninstall also runs where the block was never written — but any
// other read failure is, since it means the user's content cannot be preserved.
func clearManagedBlock(path string, pl Platform) error {
	existing, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	stripped := strings.TrimRight(stripManagedBlock(string(existing)), "\n") + "\n"
	if sameContent(path, []byte(stripped)) {
		return nil
	}
	if err := atomicWrite(path, []byte(stripped), 0o600); err != nil {
		return err
	}
	if pl != nil {
		return pl.SecureKeyFile(path)
	}
	return nil
}

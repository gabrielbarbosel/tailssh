//go:build unix

package main

// update_unix.go — the Unix half of self-update: replace the executable by an inode
// swap (allowed while the old image runs) and restart by re-execing into it.

import (
	"os"
	"path/filepath"
	"syscall"
)

// replaceExecutable swaps the running executable's file with data: written 0755 next
// to it, then renamed over — atomic on the same filesystem, and Unix keeps the old
// running image alive by inode. Shared by the Linux and macOS ReplaceSelf.
func replaceExecutable(data []byte) error {
	exe, err := selfExe()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".tailssh-update-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o755); err != nil {
		return err
	}
	return os.Rename(name, exe)
}

// restartSelf replaces the current process image with the on-disk executable (now the
// new binary), preserving the argument vector — the cleanest restart on Unix, with no
// dependency on the service manager. Never returns on success.
func restartSelf() error {
	exe, err := selfExe()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}

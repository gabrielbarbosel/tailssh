//go:build windows

package main

// update_windows.go — the Windows half of self-update. Windows locks a running .exe,
// so the old image is renamed aside and the new bytes take its path; restart starts
// the new binary detached and exits (no exec() on Windows).

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// ReplaceSelf swaps the running executable: rename it to <exe>.old (permitted while
// running) and write the new bytes to the original path, rolling back on failure.
// A stale .old that cannot be removed is not fatal: it is the mapped image of a
// still-running previous daemon (a mapped image can be neither deleted nor replaced),
// and failing here would wedge updates until that process dies. The rename falls back
// to a uniquely-named aside instead; cleanupUpdateLeftovers prunes every aside once
// nothing maps it.
func (windowsPlatform) ReplaceSelf(data []byte) error {
	exe, err := selfExe()
	if err != nil {
		return err
	}
	old := exe + ".old"
	if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
		old = fmt.Sprintf("%s.old.%d", exe, os.Getpid())
	}
	if err := os.Rename(exe, old); err != nil {
		return fmt.Errorf("rename running exe: %w", err)
	}
	if err := os.WriteFile(exe, data, 0o755); err != nil {
		_ = os.Rename(old, exe)
		return fmt.Errorf("write new exe: %w", err)
	}
	return nil
}

// restartSelf launches the (now updated) executable detached and exits — Windows has
// no exec() to replace the image in place.
func restartSelf() error {
	exe, err := selfExe()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: winDetachedProcess | winCreateNoWindow}
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}

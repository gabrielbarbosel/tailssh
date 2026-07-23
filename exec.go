package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// lookExecutable resolves a command name to a runnable path WITHOUT os/exec.LookPath's
// executable-access probe, which on Linux issues faccessat2 — a syscall some
// Android/Termux seccomp policies answer with SIGSYS, killing the process the instant
// it checks any command that exists. On Linux it scans $PATH with os.Stat (the
// permitted newfstatat) and returns the first regular file carrying an execute bit; a
// name that already contains a separator is returned unchanged. On other platforms it
// defers to exec.LookPath, preserving Windows PATHEXT/.exe resolution. When nothing
// resolves it returns name unchanged, so callers detect "not found" by the absence of a
// path separator, and a later exec still yields a normal not-found error (a bare,
// missing name never reaches the faccessat2 probe — findExecutable's os.Stat fails first).
func lookExecutable(name string) string {
	if runtime.GOOS != "linux" {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
		return name
	}
	if strings.ContainsRune(name, os.PathSeparator) {
		return name
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		if candidate := filepath.Join(dir, name); isExecutableFile(candidate) {
			return candidate
		}
	}
	return name
}

// isExecutableFile reports whether path is a regular file carrying an execute bit,
// via os.Stat alone (no faccessat2). Meaningful on Unix; used only on the Linux path.
func isExecutableFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// haveExecutable reports whether name resolves to a runnable executable, via
// lookExecutable, so it never triggers the faccessat2 seccomp crash on Android/Termux.
func haveExecutable(name string) bool {
	if strings.ContainsRune(name, os.PathSeparator) {
		return isExecutableFile(name)
	}
	return strings.ContainsRune(lookExecutable(name), os.PathSeparator)
}

// command builds an *exec.Cmd with name pre-resolved by lookExecutable, so a bare
// command name never reaches exec.Command's own LookPath (and its faccessat2 probe).
// A drop-in replacement for exec.Command.
func command(name string, args ...string) *exec.Cmd {
	return exec.Command(lookExecutable(name), args...)
}

// commandContext is command with a context — a drop-in replacement for
// exec.CommandContext.
func commandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, lookExecutable(name), args...)
}

package main

// sshenv.go — truecolor passthrough across the mesh.
//
// Terminal apps only emit 24-bit color when the session carries
// COLORTERM=truecolor; without it they quantize every color to the washed-out
// 256-color palette. sshd drops any client-sent variable it was not told to
// accept, so the mesh closes the gap symmetrically on every node: each
// generated ~/.ssh/config stanza asserts the variable (sshConfigHostEntry) and
// a managed sshd_config block accepts it (ensureSSHDAcceptEnv). Entirely
// node-local — no tailnet policy edit, no API credential. A peer reached over
// the Tailscale SSH fallback silently drops the variable and stays 256-color
// until it joins the mesh, which upgrades it with everything else.

import (
	"os"
	"strings"
)

// truecolorEnvVar/truecolorEnvValue are the one environment variable the mesh
// forwards end to end. Every terminal in scope renders 24-bit color, so the
// client side asserts the value outright instead of forwarding a local one
// (which most Windows terminals never set).
const (
	truecolorEnvVar   = "COLORTERM"
	truecolorEnvValue = "truecolor"
)

// sshdAcceptEnvBlock is the managed sshd_config body that lets clients deliver
// the truecolor variable.
const sshdAcceptEnvBlock = "AcceptEnv " + truecolorEnvVar

// sshdConfigWithAcceptEnv returns cfg with the managed AcceptEnv block ensured
// at the top of the file, and whether that changed anything. The block is
// prepended, never appended: stock configs can end in a Match block (Windows
// ships one), and a trailing AcceptEnv would be captured into that conditional
// scope instead of applying globally. AcceptEnv is cumulative in sshd, so any
// user-authored AcceptEnv keeps working alongside the managed one.
func sshdConfigWithAcceptEnv(cfg []byte) ([]byte, bool) {
	preserved := strings.TrimLeft(stripManagedBlock(string(cfg)), "\n")

	var b strings.Builder
	b.WriteString(managedBegin)
	b.WriteByte('\n')
	b.WriteString(sshdAcceptEnvBlock)
	b.WriteByte('\n')
	b.WriteString(managedEnd)
	b.WriteByte('\n')
	if strings.TrimSpace(preserved) != "" {
		b.WriteByte('\n')
		b.WriteString(preserved)
	}
	out := []byte(b.String())
	if string(out) == string(cfg) {
		return cfg, false
	}
	return out, true
}

// ensureSSHDAcceptEnv makes this node's sshd accept the truecolor variable,
// rewriting sshd_config through the platform's privilege-appropriate replace
// (which also makes sshd re-read it). Reports whether the file changed. An
// absent or unreadable config is an error: there is no sshd install to amend.
func ensureSSHDAcceptEnv(pl Platform) (changed bool, err error) {
	cfg, err := os.ReadFile(pl.SSHDConfigPath())
	if err != nil {
		return false, err
	}
	out, changed := sshdConfigWithAcceptEnv(cfg)
	if !changed {
		return false, nil
	}
	return true, pl.ReplaceSSHDConfig(out)
}

// clearSSHDAcceptEnv removes the managed sshd_config block on uninstall,
// preserving everything the user owns. An absent file means nothing to clear.
func clearSSHDAcceptEnv(pl Platform) (changed bool, err error) {
	cfg, err := os.ReadFile(pl.SSHDConfigPath())
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	stripped := strings.TrimLeft(stripManagedBlock(string(cfg)), "\n")
	if stripped == string(cfg) {
		return false, nil
	}
	return true, pl.ReplaceSSHDConfig([]byte(stripped))
}

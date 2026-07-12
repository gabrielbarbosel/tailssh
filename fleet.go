package main

// fleet.go — self-propagation using ONLY tailssh + native Tailscale features
// (no Tailscale SSH). A seed node (any host with the tailscale CLI) finds every
// same-owner peer not yet in the mesh and pushes the installer to it with Taildrop
// (`tailscale file cp`); the peer's Tailscale app raises a notification and the
// user taps to run it. That one tap is unavoidable — without Tailscale SSH there
// is no native way to EXECUTE on a remote device; Taildrop only DELIVERS.
// Once a device runs the installer it joins the mesh and syncs keys natively.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// download fetches url with a generous timeout (the shared httpClient's 5s cap is
// far too short for a multi-MB binary).
func download(url string, limit int64) ([]byte, error) {
	c := &http.Client{Timeout: 120 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

const releaseBase = "https://github.com/gabrielbarbosel/tailssh/releases/latest/download"

// onboardState rate-limits onboarding attempts so a peer is not spammed.
type onboardState struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func newOnboardState() *onboardState { return &onboardState{last: map[string]time.Time{}} }

// due reports whether name may be attempted again, recording the attempt if so.
func (s *onboardState) due(name string, every time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.last[name]; ok && time.Since(t) < every {
		return false
	}
	s.last[name] = time.Now()
	return true
}

// inMesh reports whether a peer already runs tailssh (i.e. serves /pubkey).
func inMesh(ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := getBounded(ctx, fmt.Sprintf("http://%s:%d/pubkey", hostForURL(ip), keyPort), 4096)
	return err == nil
}

// fleetSweep runs one onboarding pass. Only a node with the tailscale CLI can
// seed; CLI-less nodes (Android) return immediately.
func fleetSweep(state *onboardState) {
	bin, err := tailscaleBin()
	if err != nil {
		return
	}
	devs, err := discover()
	if err != nil {
		return
	}
	self, ok := selfDevice(devs)
	if !ok {
		return
	}
	var wg sync.WaitGroup
	for _, p := range devs {
		if p.self || !p.online || p.ip == "" || p.owner != self.owner {
			continue
		}
		if inMesh(p.ip) {
			continue
		}
		if !state.due(p.name, 15*time.Minute) {
			continue
		}
		p := p
		wg.Add(1)
		go func() { defer wg.Done(); onboardViaTaildrop(bin, p) }()
	}
	wg.Wait()
}

// onboardViaTaildrop downloads the installer for the peer's OS and pushes it with
// Taildrop; the peer's Tailscale app shows a notification to run it (one tap).
func onboardViaTaildrop(bin string, p device) {
	url, name := installerFor(p.os)
	body, err := download(url, 64<<20)
	if err != nil {
		fmt.Printf("fleet: download for %s failed: %v\n", p.name, err)
		return
	}
	tmp := filepath.Join(os.TempDir(), name)
	if os.WriteFile(tmp, body, 0o755) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, bin, "file", "cp", tmp, p.name+":").Run(); err != nil {
		fmt.Printf("fleet: taildrop to %s failed: %v\n", p.name, err)
		return
	}
	fmt.Printf("fleet: pushed installer to %s — tap the Tailscale notification to finish\n", p.name)
}

// installerFor picks the download URL + filename appropriate for a peer's OS.
func installerFor(peerOS string) (url, name string) {
	switch peerOS {
	case "android":
		return releaseBase + "/tailssh-linux-arm64", "tailssh"
	case "windows":
		return releaseBase + "/tailssh-windows-amd64.exe", "tailssh.exe"
	case "macOS":
		return releaseBase + "/tailssh-darwin-arm64", "tailssh"
	default:
		return releaseBase + "/tailssh-linux-amd64", "tailssh"
	}
}

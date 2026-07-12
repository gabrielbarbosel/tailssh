package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// httpClient is the single shared client for all peer fetches: tight timeouts,
// no keep-alives (short-lived one-shot calls), and bounded response headers.
var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 8 << 10,
		ResponseHeaderTimeout:  3 * time.Second,
	},
}

// getBounded GETs url with the shared client and reads at most limit bytes.
func getBounded(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, limit)) // drain to reuse conn
		resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// backoff returns capped exponential backoff with full jitter for attempt n (0-based):
// a random duration in [0, min(base<<n, max)].
func backoff(n int, base, max time.Duration) time.Duration {
	d := base << n
	if d <= 0 || d > max {
		d = max
	}
	return time.Duration(rand.Int63n(int64(d) + 1))
}

// atomicWrite writes data to path via a temp file + fsync + rename, then applies perm.
// The rename is atomic, so readers never see a partial file.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Best-effort cleanup of temp files left behind by an ungraceful kill. Only
	// remove ones old enough that they can't be a concurrent writer's in-flight
	// temp — two atomicWrites can target the same dir (e.g. peers.json written by
	// a sync while roster.json is written by an incoming push).
	if stale, err := filepath.Glob(filepath.Join(dir, ".tailssh-*")); err == nil {
		for _, f := range stale {
			if fi, statErr := os.Stat(f); statErr == nil && time.Since(fi.ModTime()) > 5*time.Minute {
				os.Remove(f)
			}
		}
	}
	tmp, err := os.CreateTemp(dir, ".tailssh-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
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
	if err := os.Chmod(name, perm); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// sameContent reports whether path already holds exactly data, to skip no-op writes.
func sameContent(path string, data []byte) bool {
	cur, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return sha256.Sum256(cur) == sha256.Sum256(data)
}

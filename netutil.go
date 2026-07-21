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

// drainAndCloseBody reads and discards up to limit bytes of body before closing
// it, so the underlying keep-alive connection can be reused instead of dropped.
func drainAndCloseBody(body io.ReadCloser, limit int64) {
	io.Copy(io.Discard, io.LimitReader(body, limit))
	body.Close()
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
	defer drainAndCloseBody(resp.Body, limit)
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

// atomicWriteTempPattern is the CreateTemp pattern for atomicWrite's in-flight temp
// files; the ".tailssh-" prefix also identifies stale temps to prune.
const atomicWriteTempPattern = ".tailssh-*"

// staleTempAge is how old an atomicWrite temp must be before pruneStaleTempFiles
// removes it. It must exceed the longest plausible in-flight write so a concurrent
// writer's temp is never mistaken for abandoned: two atomicWrites can target the
// same dir (e.g. peers.json written by a sync while roster.json is written by an
// incoming push).
const staleTempAge = 5 * time.Minute

// pruneStaleTempFiles best-effort removes atomicWrite temp files left behind by an
// ungraceful kill, skipping any young enough to still be a concurrent writer's
// in-flight temp.
func pruneStaleTempFiles(dir string) {
	stale, err := filepath.Glob(filepath.Join(dir, atomicWriteTempPattern))
	if err != nil {
		return
	}
	for _, f := range stale {
		if fi, statErr := os.Stat(f); statErr == nil && time.Since(fi.ModTime()) > staleTempAge {
			os.Remove(f)
		}
	}
}

// atomicWrite writes data to path via a temp file + fsync + rename, then applies perm.
// The rename is atomic, so readers never see a partial file.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	pruneStaleTempFiles(dir)
	tmp, err := os.CreateTemp(dir, atomicWriteTempPattern)
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

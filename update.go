package main

// update.go — self-update (OS-agnostic core).
//
// The daemon keeps every node on the latest published binary, so the mesh never
// drifts in version. It compares the SHA256 of the running executable against the
// release's SHA256SUMS (no version string to manage: the node converges to the
// released binary byte-for-byte), and only when they differ downloads the asset,
// re-verifies its checksum, and self-replaces via the Platform. Offline-first: any
// network error just logs and retries next cycle. Opt out with a sentinel file.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// releaseBase is GitHub's "latest release" asset directory; it redirects to the
// current release, so self-update needs no API call and no embedded version.
const releaseBase = "https://github.com/gabrielbarbosel/tailssh/releases/latest/download"

// updateCheckInterval is the slow cadence the daemon re-checks for a new release.
const updateCheckInterval = 8 * time.Hour

// releaseAsset is this build's binary name in a release — tailssh-<os>-<arch>[.exe],
// matching install.sh / install.ps1.
func releaseAsset() string {
	name := fmt.Sprintf("tailssh-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// autoUpdateDisabledPath is a sentinel whose mere presence opts a node out of the
// daemon's unattended update loop — a file, not an env toggle (the project keeps
// config out of env). It never gates `tailssh update`: an operator asking for an
// update by name has already overridden the opt-out by asking.
func autoUpdateDisabledPath() string {
	return filepath.Join(filepath.Dir(appKeyPath()), "autoupdate.off")
}

func autoUpdateEnabled() bool {
	_, err := os.Stat(autoUpdateDisabledPath())
	return os.IsNotExist(err)
}

// selfExe returns the running executable's path, symlinks resolved.
func selfExe() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved, nil
	}
	return p, nil
}

// fileSHA256 returns the lowercase hex sha256 of a file.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// releasedSHA256 fetches the release SHA256SUMS and returns the hash listed for asset.
// Lines are `<hash>  <name>` or `<hash> *<name>` (sha256sum text/binary form).
func releasedSHA256(ctx context.Context, asset string) (string, error) {
	body, err := getBounded(ctx, releaseBase+"/SHA256SUMS", 1<<20)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == asset {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("release SHA256SUMS has no entry for %s", asset)
}

// downloadRelease fetches a release asset with a generous timeout, independent of the
// short-lived httpClient used for peer metadata.
func downloadRelease(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 3 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer drainAndCloseBody(resp.Body, 128<<20)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: http %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 128<<20))
}

// checkForUpdate replaces the running binary with the latest release when they differ,
// verifying the download against SHA256SUMS before swapping. replaced=true means the
// on-disk binary was updated and the caller should restart into it. Offline-first:
// network errors are returned, never fatal.
//
// The autoupdate.off sentinel is NOT consulted here — it gates the daemon's unattended
// loop, not this function. Honouring it here made `tailssh update`, an explicit
// operator request, a silent no-op that still printed "tailssh is up to date." on a
// node that was demonstrably behind, hiding a stale binary behind a reassuring line.
func checkForUpdate(pl Platform) (replaced bool, err error) {
	asset := releaseAsset()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	want, err := releasedSHA256(ctx, asset)
	if err != nil {
		return false, err
	}
	exe, err := selfExe()
	if err != nil {
		return false, err
	}
	have, err := fileSHA256(exe)
	if err != nil {
		return false, err
	}
	if strings.EqualFold(have, want) {
		return false, nil // already the released binary
	}
	data, err := downloadRelease(releaseBase + "/" + asset)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
		return false, fmt.Errorf("downloaded %s failed checksum — refusing to install", asset)
	}
	if err := probeExecutable(data); err != nil {
		return false, fmt.Errorf("staged %s does not run on this host — keeping the current binary: %w", asset, err)
	}
	return true, pl.ReplaceSelf(data)
}

// probeExecutable verifies the downloaded binary actually STARTS on this host before
// it replaces the running one. A checksum proves integrity, not runnability: an
// application-control policy (e.g. Windows Smart App Control) can block an unknown
// unsigned binary outright, and swapping to one bricks the node — the daemon's next
// restart runs nothing, and so does every command that could have fixed it. The bytes
// are staged next to the current exe (same volume and policy scope; a temp dir can be
// noexec on Unix) and started with a throwaway argument the CLI answers with its usage
// text; only the process failing to START counts as blocked.
func probeExecutable(data []byte) error {
	exe, err := selfExe()
	if err != nil {
		return err
	}
	probe := filepath.Join(filepath.Dir(exe), "tailssh-probe"+filepath.Ext(exe))
	if err := os.WriteFile(probe, data, 0o755); err != nil {
		return err
	}
	defer os.Remove(probe)
	cmd := command(probe, "probe")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start staged binary: %w", err)
	}
	_ = cmd.Wait()
	return nil
}

// cleanupUpdateLeftovers removes update debris: the executables a Windows
// self-replace renames aside (<exe>.old, plus the uniquely-named asides ReplaceSelf
// falls back to when a stale .old is still a live process's mapped image) and any
// probe binary an interrupted update left staged. Best-effort: an aside still mapped
// by an exiting process simply survives until the next daemon start prunes it.
func cleanupUpdateLeftovers() {
	exe, err := selfExe()
	if err != nil {
		return
	}
	patterns := []string{exe + ".old*", filepath.Join(filepath.Dir(exe), "tailssh-probe*")}
	for _, pat := range patterns {
		matches, err := filepath.Glob(pat)
		if err != nil {
			continue
		}
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
}

// runUpdate is the `update` command: check once and apply, restarting into the new
// binary on success. Self-elevates first where a privileged install path needs it.
func runUpdate(pl Platform) error {
	if handled, err := pl.EnsurePrivilege(os.Args[1:]); err != nil {
		return err
	} else if handled {
		return nil
	}
	replaced, err := checkForUpdate(pl)
	if err != nil {
		return err
	}
	if !replaced {
		fmt.Println("tailssh is up to date.")
		return nil
	}
	fmt.Println("tailssh updated — restarting the daemon into the new binary.")
	if err := pl.RestartDaemon(); err != nil {
		fmt.Printf("daemon restart: %v — it keeps running the previous binary until its next restart\n", err)
	}
	return restartSelf()
}

// daemonAutoUpdateLoop checks for a new release on a slow cadence and, when it
// installs one, restarts the daemon into it. Runs on every device; the first check is
// delayed so startup spends no time on a round-trip, and a failure just logs and
// waits for the next tick.
func daemonAutoUpdateLoop(ctx context.Context, pl Platform) {
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if !autoUpdateEnabled() {
			timer.Reset(updateCheckInterval + backoff(0, 5*time.Minute, 5*time.Minute))
			continue
		}
		if replaced, err := checkForUpdate(pl); err != nil {
			log.Printf("daemon: update: %v", err)
		} else if replaced {
			log.Printf("daemon: installed the latest release — restarting")
			if err := restartSelf(); err != nil {
				log.Printf("daemon: restart after update failed: %v", err)
			}
			return
		}
		timer.Reset(updateCheckInterval + backoff(0, 5*time.Minute, 5*time.Minute))
	}
}

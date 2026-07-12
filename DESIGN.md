# tailssh — Hardened Unified Design

## 0. Grounding: what exists today

`main.go` (list + read-only `up`):
- `node`/`status` structs parse a subset of `tailscale status --json`; **missing** `StableID` (needed as the stable cache/trust key) and `HostName`.
- `tailscaleBin()` re-locates the CLI on every call (no caching).
- `discover()` runs `tailscale status --json` with **no context timeout**.
- `sshServerState()`: installed-check already probes `/usr/sbin/sshd` and `/usr/bin/sshd` via `os.Stat` (good), but running-check is `pgrep -x sshd` (wrong: false-positive on a per-connection child, false-negative on socket-activated/launchd sshd, wrong on Windows).
- `appKeyPath()` → `UserConfigDir/tailssh/id_ed25519` (correct on all OSes; out of `~/.ssh`).
- `cmdUp()` only audits and prints a to-do list; it never mutates.
- `main()` switch handles only `list` and `up`.

`install.sh` / `install.ps1` hold the mutation logic (install/enable sshd, write keys, firewall, default shell) that must be folded into Go's `up`/`sync`, hardened per the specs. The scripts stay as the curl-bootstrap that downloads the binary and runs `tailssh up && tailssh sync && tailssh daemon install`.

**Design stance:** put *all* resilience, resource, and security behavior in shared Go code; the only per-platform code is a thin `Platform` implementation of a common interface. Never a per-platform hack in the hot path.

---

## 1. Architecture

### 1.1 One static binary
`CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w"`. Dependencies limited to: stdlib, `golang.org/x/crypto/ssh` (in-process ed25519 marshaling + `ParseAuthorizedKey`), and `golang.org/x/sys/windows/svc(+mgr,+eventlog)` (Windows-only, statically linked). No third-party JSON, no ssh-keygen shell-out, no libc. One artifact per `GOOS/GOARCH`: linux/amd64, linux/arm64, darwin/amd64+arm64 (lipo → universal, ad-hoc `codesign -s -`), windows/amd64, windows/arm64, plus an in-Termux `pkg install golang` build for android/arm64.

### 1.2 Package/file layout (within `package main`, split into files)
- `discovery.go` — status parsing (`discover()`), `tailscaleBin()` with lifetime cache, context-bounded exec.
- `identity.go` — in-process ed25519 keygen, atomic write, perms/ACL, fingerprint, rotate.
- `keyserver.go` — plain-HTTP pubkey (+ roster on Android) server bound to the tailnet IP.
- `keysync.go` — the `sync` core: fetch peer keys, managed-block rendering, atomic writes, peer cache, ssh_config generation.
- `platform_*.go` — build-tagged `Platform` implementations (`platform_linux.go`, `platform_darwin.go`, `platform_windows.go`, `platform_android.go`/detected at runtime).
- `daemon.go` — event loop, debounce, poll fallback, service install/remove.
- `netutil.go` — shared http.Client, retry/backoff+jitter, metered detection, atomic file write, hash-compare.
- `main.go` — command switch: `list | up | sync | daemon [install|remove]`.

### 1.3 The `Platform` interface (the ONLY seam)
```
type Platform interface {
    SSHState() (installed, running, enabled bool)      // filesystem/init/service probe, never pgrep
    InstallSSH(ctx) error                              // package manager / capability / built-in
    EnableSSH(ctx) error                               // init/launchd/SCM + host keys + firewall
    AuthorizedKeysPath(user) (string, error)           // per-user vs admin_authorized_keys
    SecureKeyFile(path) error                          // chmod+verify / icacls+SID / restorecon
    SSHListenPort() int                                // 22 everywhere except android=8022
    InstallDaemon(binPath) error / RemoveDaemon()      // systemd/OpenRC/launchd/SCM/Termux:Boot
    SupportsIPNBus() bool                              // false on android/Termux
}
```
`selectPlatform()` chooses by `runtime.GOOS` + runtime probes (Termux via `$PREFIX` containing `com.termux`; Linux init via filesystem probe — see §4).

### 1.4 Config dir (`UserConfigDir/tailssh/`, 0700 / user-ACL)
- `id_ed25519` (0600 / SYSTEM+user ACL), `id_ed25519.pub` (0644).
- `peers.json` — cache keyed by **StableID**: `{name, ip, os, pubkey, fetchedAt}`.
- `config.json` — tunables (ports, intervals, metered override, tags opt-in, wakelock mode). Nothing hardcoded in behavior; these are defaults.

---

## 2. Command behavior (uniform across platforms)

### 2.1 `list` (already implemented — minor hardening)
Wrap the status exec in `context.WithTimeout(5s)`; on timeout fall back to `peers.json` cache and mark entries stale rather than erroring. Add `StableID`/`HostName` to the parse.

### 2.2 `up` (currently audit-only → make it mutate under `--yes`)
Steps, each **idempotent**, each reporting `ok/skipped/MISSING` like the current `cmdUp` summary, and **never aborting the whole run because one optional step failed**:
1. Verify Tailscale present + `status` works (prerequisite).
2. `SSHState()` — skip install if already installed.
3. `InstallSSH()` with capped-backoff retry (network-transient only).
4. Generate host keys if absent (`ssh-keygen -A` on Unix; capability handles Windows).
5. `EnableSSH()` via the correct init/service; prefer socket activation where present.
6. Open firewall **only if a firewall is active** and scope to the tailnet CGNAT range.
7. Generate/rotate the app identity if missing.
8. (Does **not** by itself write authorized_keys — that's `sync`, so `up` stays about "make me a reachable server"; `up --yes` then chains `sync`.)

Privilege: acquire transparently — direct if uid 0 / elevated, else `sudo` → `doas` (Unix) or fail-early with a clear "run elevated" message (Windows). Read-only audit (`up` with no `--yes`) works unprivileged.

### 2.3 `sync` (new — the federated key exchange core)
1. `tailscale status --json` (5s ctx). On failure, use `peers.json` (offline-first) — do **not** prune.
2. Build the trusted peer set: keep a peer **iff** its `UserID` resolves to the same `LoginName` as `Self` (same-owner scoping). Exclude other owners and, by default, tagged nodes (opt-in flag for tags).
3. For each new/changed peer (StableID new, or IP changed): fetch `http://<peer.TailscaleIPs[0]>:<keyport>/pubkey` via the shared http.Client (3s connect / 5s total), body capped at 8 KiB, validated by `ssh.ParseAuthorizedKey` and required `ssh-ed25519`. Retry capped-backoff+jitter (3 attempts; 1 on metered). Bounded worker pool (concurrency 8), overall 60s deadline. On per-peer failure reuse the cached key.
4. Render the **managed block** (delimited markers) of authorized_keys from the trusted set; write atomically (temp in same dir → fsync → rename) only if content changed; preserve all user lines outside the block. **Prune** a peer's key only when it is absent from a *successful* status call (left tailnet) or changed owner — never merely offline/unreachable.
5. `SecureKeyFile()` on the written file (perms/ACL/SELinux label).
6. Regenerate the managed block of `~/.ssh/config`: `Host <name>` / `HostName <name-or-100.x>` / no User / no Port, injecting `Port 8022` only for `os=="android"` peers. Atomic + hash-compare. Preserve user Host entries.
7. Persist `peers.json` atomically. `debug.FreeOSMemory()` after completion.

`sync` is runnable on demand (bypasses debounce) so a user can force propagation.

### 2.4 `daemon` (new — event-driven, near-zero idle)
- On start: run one `sync` (self-correct even with no events).
- **Event path (desktop: linux/darwin/windows):** spawn `tailscale debug watch-ipn` via `exec.CommandContext`, decode the stream with `json.NewDecoder(pipe).Decode(&notify)` in a loop (**never** `bufio.Scanner` — netmaps exceed 64 KB and may be pretty-printed). Decode into `{Version string; State *int; ErrMessage *string; NetMap json.RawMessage; Engine json.RawMessage}`; treat as a change **only** when `len(NetMap)>0 && NetMap != "null"`. Ignore Engine/stats frames.
- **Debounce:** one resettable `time.NewTimer(2–3s)`; arm on each NetMap event, `sync` once on fire. No timer armed while idle → zero wakeups.
- **Serialize:** if a sync is running when the timer fires, set a `dirty` flag and re-run once on completion; never two concurrent syncs. `recover()` per sync so one flaky peer/panic never kills the daemon.
- **Respawn:** on Decode EOF/err (tailscaled restart), reconnect with exponential backoff (1s→30s cap + jitter), reset on clean reconnect, and run one `sync` immediately post-reconnect to catch missed changes.
- **Capability probe:** if watch-ipn exits immediately/repeatedly or emits no NetMap within a probe window, or returns permission errors, fall back to poll mode (and surface a clear operator/root hint on permission errors rather than silently degrading forever).
- **Poll fallback (android/Termux always; desktop on bus-unavailable):** `tailscale status --json` every 60s desktop / **15 min mobile (Doze-aligned)**, ±20% jitter, hash a stable subset (peer StableID+IP+key+online), `sync` only on hash change. Longer interval / back off when metered or tailnet down.

---

## 3. Cross-cutting shared rules (baked into `netutil.go` + runtime setup)

### 3.1 Resource minimalism (all platforms)
- At startup: `runtime.GOMAXPROCS(1)`, `debug.SetMemoryLimit(64<<20)`, `debug.SetGCPercent(40)`; `debug.FreeOSMemory()` after each sync.
- Idle = blocked on pipe read (event) or sleeping between polls; no busy timers, no per-peer goroutines at idle.
- Cache `tailscaleBin()` and the sshd path for the daemon's lifetime (stop re-`LookPath`/`Stat` per sync).
- Bound `json` buffers; keep NetMap as `RawMessage` (never fully parse peers in the event path — sync re-reads status anyway).
- Targets (self-checkable): idle RSS < 12 MB (< 8 MB post-FreeOSMemory), idle CPU ~0%, stripped binary < 8 MB, self-wakeups ~0/min desktop-event, ≤1/min desktop-poll, ≤1/15min mobile.

### 3.2 Network resilience
- Every subprocess + HTTP call wrapped in `context.WithTimeout`; always `cmd.Wait()` + close pipes.
- Capped exponential backoff + **full jitter** everywhere; reset on sustained success.
- Offline-first: `peers.json` seeds authorized_keys when status/fetch fail; keys never expire on a timer.
- Atomic writes (temp+fsync+rename) + content hash-compare → redundant syncs are free, and a crash can't corrupt authorized_keys.
- Metered detection (`metered=auto|yes|no`): Linux `nmcli -t -f GENERAL.METERED dev show`; Windows WinRT `NetworkCostType`; Android best-effort/config. Metered ⇒ never auto-install (require `--yes`), stretch poll to 300s, raise revalidate TTL, cap fetch retries at 1. Metered affects **installs and cadence, never key correctness**.
- Fetch by `TailscaleIPs[0]` (never MagicDNS) so key exchange has no DNS dependency; try v6 tailnet IP as a fallback address family.

### 3.3 Security parity (identical invariants everywhere)
1. In-process ed25519 identity (`crypto/ed25519` + `x/crypto/ssh`), atomic write, out of `~/.ssh`, rotatable.
2. Marker-delimited **managed block** in authorized_keys; user keys never read/moved/clobbered; block fully regenerated each sync (this is the revocation mechanism).
3. Trust = same-owner tailnet membership only; tagged/other-owner nodes excluded by default.
4. Keyserver binds **exclusively** to the node's Tailscale IP (`Self.TailscaleIPs`); refuse to start if none — WireGuard = encryption+authenticated peer identity, tailnet membership = authorization, pubkey = non-secret ⇒ no TLS. Never `0.0.0.0`/`::`/localhost.
5. Peer keys validated (single valid `ssh-ed25519`, size-capped) before entering the block.
6. Revoke on confirmed departure/owner-change only; retain last-known key on offline/unreachable (no flapping).
7. Never log private key material; expose only fingerprints. Redact keyserver logs to peer-IP+result.

---

## 4. Per-platform matrix (identical functionality, platform-correct mechanism)

| Concern | Linux | macOS | Windows | Android/Termux |
|---|---|---|---|---|
| **sshd install** | apt→`openssh-server`(update+`DEBIAN_FRONTEND=noninteractive`) / dnf,yum→`openssh-server` / pacman→`openssh`(`-Sy`) / apk→`openssh-server openssh-keygen` / zypper→`openssh` | built-in `/usr/sbin/sshd` (stat only; never install) | `Get-WindowsCapability 'OpenSSH.Server*'`→`Add-WindowsCapability` (resolve exact name); offline `0x800f0954`→DISM `/Source` ISO→Win32-OpenSSH portable zip `install-sshd.ps1` | `pkg install -y openssh` |
| **host keys** | `ssh-keygen -A` if `/etc/ssh/ssh_host_*` absent | present | capability-provided | `ssh-keygen -A` ($PREFIX/etc/ssh) |
| **init/enable detection** | **filesystem probe**: systemd iff `-d /run/systemd/system`; OpenRC iff `/run/openrc` or `rc-status` — **never** `command -v systemctl` | launchd socket-activated | SCM `Get-Service sshd` | `pgrep` (no service mgr) |
| **enable+start** | systemd `enable --now ssh`→fallback `sshd`; prefer `ssh.socket` if present / OpenRC `rc-update add sshd default && rc-service sshd start` / runit / sysvinit | `launchctl enable system/com.openssh.sshd` + `bootstrap system …/ssh.plist` (no TCC); add user to `com.apple.access_ssh` if group exists; fallback `systemsetup -setremotelogin on` (FDA-gated, name the cause) | `Set-Service sshd -StartupType Automatic; Start-Service sshd` | `sshd` / `pkill sshd` |
| **running probe** | `systemctl is-active ssh\|\|sshd`, treat `ssh.socket` active as ready; OpenRC `rc-service sshd status`; no-init `ss -tln`/`pgrep` | **dial 127.0.0.1:22** / `lsof -iTCP:22 -sTCP:LISTEN` (socket-activated ⇒ no idle proc) | `Get-Service sshd` Status | `pgrep -x sshd` |
| **port / config** | 22, no Port line | 22, no Port line | read effective `Port` from `sshd_config` (default 22), use it for firewall+config | **8022**; peers inject `Port 8022` |
| **authorized_keys** | `~/.ssh/authorized_keys` 700/600, owner=user; **`restorecon`** when getenforce=Enforcing | `~/.ssh/authorized_keys` 700/600 (StrictModes) | admin→`%ProgramData%\ssh\administrators_authorized_keys` (icacls `/inheritance:r` SYSTEM+`*S-1-5-32-544`); user→`%UserProfile%\.ssh\authorized_keys` (SYSTEM+userSID) | `$HOME/.ssh/authorized_keys` 700/600 |
| **firewall** | firewalld `--add-service=ssh` / ufw `allow OpenSSH` — only if active | App Firewall: ad-hoc sign / `socketfilterfw --add --unblock` | `New-NetFirewallRule` scoped `RemoteAddress 100.64.0.0/10` for sshd+keyserve, idempotent | n/a (unprivileged) |
| **default shell** | n/a | n/a | `HKLM\SOFTWARE\OpenSSH\DefaultShell`→pwsh.exe else powershell.exe (opt-out) | n/a |
| **discovery** | `status --json` | `status --json` | `status --json` | **pushed roster**: no CLI/LocalAPI — a CLI peer discovers this node (it serves `/pubkey` on its own tailnet IP, derived from interface scan) and POSTs it the full `/roster`; no seed/bootstrap IP needed. `/roster` GET pull remains as a fallback |
| **daemon events** | `watch-ipn` (bus) | `watch-ipn` (bus) | `watch-ipn` (named-pipe bus) | **poll only** (no bus) |
| **daemon service** | systemd unit `tailssh-daemon.service` (Restart=always, After=tailscaled, MemoryMax, Nice/IO idle); OpenRC fallback | LaunchDaemon `/Library/LaunchDaemons/com.tailssh.daemon.plist` (RunAtLoad, KeepAlive, ProcessType=Background) or per-user LaunchAgent (writes own ~/.ssh, no root); inject Tailscale.app PATH | `svc.IsWindowsService()`→`svc.Run`; `sc create … start= delayed-auto`, `depend= Tailscale`, failure=restart; schtasks fallback | `~/.termux/boot/start-tailssh` (Termux:Boot); wakelock only when serving |
| **persistence honesty** | no-init container: exec `sshd` directly, report reboot-persistence not guaranteed | — | elevation required, fail early | requires Termux:Boot + OEM battery-optimization exemption |

**Android gossip specifics:** each node serves `/pubkey` and `/roster` (JSON `[{name,ip,os,pubkeyURL}]`) on the tailnet IP (default `:8021`); bootstrap peers configured as **raw 100.x IPs** (MagicDNS doesn't resolve in Termux); fetch each peer's key from its **own** `/pubkey` (never trust the aggregator) with optional TOFU pinning; 0.0.0.0 bind only as last-resort fallback **with a logged warning**. Offer opt-in `tailscaled --tun=userspace-networking` mode for no-Android-app users (heavier; second node; not default).

---

## 5. Conflict resolutions (where specs overlapped/differed)

- **Keyserver port:** unify on a single configurable pubkey port (default `8099` on Windows spec, `8021` on Android spec). **Resolved:** one config value `keyPort` default **8021**, overridable; Android additionally serves `/roster` on the same port.
- **macOS daemon as system LaunchDaemon vs per-user LaunchAgent:** the event-daemon spec says LaunchDaemon; the darwin spec says LaunchAgent (writes the user's own ~/.ssh, no TCC/root). **Resolved:** default **per-user LaunchAgent** (correct owner for authorized_keys, no root), with a documented system-LaunchDaemon option for multi-user hosts. Both inject Tailscale.app PATH.
- **watch-ipn transport:** CLI subprocess vs in-process `LocalClient.WatchIPNBus`. **Resolved:** ship the **CLI-subprocess** path (no heavy dep, keeps binary small, reuses `tailscaleBin()`); note the library API as a future version-stable option (nice-to-have).
- **`up` writing keys:** install.sh writes keys during install; sync spec owns key writing. **Resolved:** `up` provisions the *server*; **`sync` owns all authorized_keys/config writes**; `up --yes` chains `sync`.
- **Termux wakelock:** install.sh holds `termux-wake-lock` unconditionally in boot; resource spec forbids idle wakelock. **Resolved:** boot script holds a wakelock only in default "always-reachable" mode; provide an "on-demand" mode with no permanent wakelock (availability-vs-battery tradeoff, sync-on-connect).
- **pruning vs offline:** all key-management specs agree — prune only on confirmed tailnet departure/owner-change from a *successful* status call; the network-resilience "fail-open never expire" and security "prompt revocation" reconcile via the "membership from live status, material from cache" split.

---

## 6. Open risks carried into implementation
- `watch-ipn` is an unstable debug surface (masking/JSON shape/availability vary by version) → poll fallback is the guaranteed baseline, not a special case.
- Same-owner trust means a compromised owned node can serve a bogus key and pivot to all owned devices (inherent; mitigated by validation + prompt revocation, not eliminated).
- Windows ACL correctness is silent-fail-prone (extra writable SID / left inheritance ⇒ sshd ignores the file) → verify the resulting ACL, don't assume `icacls` success.
- No-init containers and OEM-battery-manager phones cannot guarantee reboot persistence → report honestly.
- Remote username mismatch across the mesh (keyless `ssh <name>` sends the local username) is out of scope of key sync but will surface on Windows.

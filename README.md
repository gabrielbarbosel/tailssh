# tailssh

A single static Go binary that turns **every device on your Tailscale tailnet into an
SSH-reachable node — uniformly, across every OS** (Linux, macOS, Windows, Android/Termux).
It layers on Tailscale (identity, discovery, encrypted transport, MagicDNS) and adds a
uniform SSH server per OS, a **federated key mesh**, and a device directory.

No hardcoded data, no runtime dependency (just the Tailscale you already run), and an
**event-driven** daemon (no polling) that keeps the mesh in sync as devices come and go.

## Install (one command per device)

Requires Tailscale installed and logged in.

**Linux / macOS / Termux**
```sh
curl -fsSL https://raw.githubusercontent.com/gabrielbarbosel/tailssh/main/install.sh | sh
```

**Windows** (elevated PowerShell)
```powershell
irm https://raw.githubusercontent.com/gabrielbarbosel/tailssh/main/install.ps1 | iex
```

That fetches the right static binary and runs `tailssh up --yes`, which installs/enables
the OpenSSH server, generates a per-device key, and joins the mesh. After it runs on two
or more devices, you can reach any of them by name:

```sh
ssh my-server
```

## Commands

| command | what it does |
|---|---|
| `tailssh list` | device directory (name, OS, owner, online, how to connect) |
| `tailssh status` | read-only health view: local server + posture (disk encryption, reboot persistence) and each peer's reachability — why `ssh <name>` does or doesn't work |
| `tailssh up [--yes]` | audit; with `--yes`, an ordered bootstrap: ensure Tailscale → OpenSSH → identity → sync → daemon, auto-installing or opening the installer/login and waiting so it flows straight through |
| `tailssh sync` | fetch trusted peers' keys → managed `authorized_keys` + `~/.ssh/config` + `known_hosts` |
| `tailssh daemon` | event-driven: watch the tailnet and re-sync on every change; also keeps the tailnet interface MTU clamped for broken-PMTU direct paths (e.g. to a phone) |
| `tailssh acl [--apply]` | ensure the tailnet's `ssh accept` rule (preserving the rest of the policy); needs `TS_API_KEY` |
| `tailssh off` | turn the service off (stop the daemon); keys stay, `up` re-arms it |
| `tailssh uninstall` | remove tailssh from this machine (daemon, managed blocks, identity, binary) |

## Configuration (all optional, read from the environment; secrets are never stored)

| env var | effect |
|---|---|
| `TS_AUTHKEY` | join Tailscale non-interactively during `up` (`tailscale up --authkey …`) — skips the manual browser login. Used once, never written to disk. |
| `TS_API_KEY` | lets `up`/`acl` ensure the tailnet `ssh accept` rule automatically. Used transiently, never stored. |
| `TAILSSH_BATTERY=saver` | on Termux, drop the always-on wake lock: reachable only while the device is awake, in exchange for zero idle battery draw. |
| `TAILSSH_SEED` | comma-separated peer tailnet IPs for a CLI-less node's very first discovery, before any peer has pushed it a roster (rarely needed). |

## How it works

- **Discovery & trust** come from `tailscale status --json`; only nodes owned by the same
  Tailscale account are trusted (revocation is automatic when a device leaves the tailnet).
- **Keys** are app-managed ed25519 identities kept out of `~/.ssh`. Each device serves its
  public key over plain HTTP bound to its **tailnet IP** — WireGuard already encrypts the
  link and tailnet membership already authenticates it, so no TLS/cert is needed.
- **`authorized_keys`** is edited only inside a delimited managed block; your own keys are
  never touched. `~/.ssh/config` is generated so `ssh <name>` needs no user or port
  (Termux's `8022` is injected automatically).
- **Transport is hybrid.** A peer running tailssh is reached over the key mesh (reliable,
  no tailnet ACL needed); a Linux/macOS peer *not* in the mesh falls back to keyless
  Tailscale SSH. Peers' sshd host keys are fetched and written to a managed `known_hosts`,
  so first connects verify silently instead of prompting.
- **The daemon is event-driven.** On Linux/macOS/Windows it subscribes to Tailscale's own
  control-plane push (`tailscale debug watch-ipn`) — no polling. Android/Termux (no local
  CLI) is woken by a relay push from an event-capable peer, plus sync-on-connect.

## Platform notes

- **Termux/Android**: sshd runs on `8022`. Install assists with the **Termux:Boot** app
  (opens its F-Droid page and waits) so the daemon auto-starts after a reboot; the daemon
  holds a wake lock so Android's Doze can't freeze it (see `TAILSSH_BATTERY`).
- **Windows/Termux** join via OpenSSH + key (Tailscale SSH itself only serves Linux/macOS);
  MagicDNS resolves the name identically, so `ssh <name>` works the same everywhere. On
  Windows the daemon persists via a scheduled task (elevated) or a per-user Run key.

See `DESIGN.md` for the full cross-platform design, resource budget, and threat model.

## License

MIT — see [LICENSE](LICENSE).

#!/bin/sh
# tailssh installer (Linux/macOS/Termux) — fetch the static binary and join the mesh.
# Requires Tailscale. One command, no runtime deps.
#
#   curl -fsSL https://raw.githubusercontent.com/gabrielbarbosel/tailssh/main/install.sh | sh
set -eu

REPO="gabrielbarbosel/tailssh"
BASE="https://github.com/${REPO}/releases/latest/download"

say() { printf '\033[36m[tailssh]\033[0m %s\n' "$1"; }
die() { printf '\033[31m[tailssh] error:\033[0m %s\n' "$1" >&2; exit 1; }

is_termux() { [ -n "${PREFIX:-}" ] && printf '%s' "$PREFIX" | grep -q com.termux; }

# Require Tailscale. On Termux the tailnet is the Android app — there is no CLI, and
# its VPN address can't be read from a shell on Android 11+ — so we skip the check
# here and let the tailssh binary detect the app (and open it if needed).
if ! command -v tailscale >/dev/null 2>&1 && ! is_termux; then
	die "Tailscale is required first: https://tailscale.com/download"
fi

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in linux|darwin) ;; *) die "unsupported OS: $os" ;; esac
arch=$(uname -m)
case "$arch" in
	x86_64|amd64) arch=amd64 ;;
	aarch64|arm64) arch=arm64 ;;
	*) die "unsupported arch: $arch" ;;
esac
bin="tailssh-${os}-${arch}"

# Termux installs into $PREFIX/bin; elsewhere /usr/local/bin (sudo/doas if needed).
if [ -n "${PREFIX:-}" ] && printf '%s' "$PREFIX" | grep -q com.termux; then
	dest="$PREFIX/bin/tailssh"; SUDO=""
else
	dest="/usr/local/bin/tailssh"
	if [ "$(id -u)" != 0 ]; then
		if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; elif command -v doas >/dev/null 2>&1; then SUDO="doas"; else SUDO=""; fi
	else SUDO=""
	fi
fi

tmp=$(mktemp)
say "downloading ${bin}..."
curl -fsSL "${BASE}/${bin}" -o "$tmp" || die "download failed (${BASE}/${bin})"
chmod +x "$tmp"
$SUDO mkdir -p "$(dirname "$dest")"
$SUDO mv "$tmp" "$dest"
say "installed -> $dest"

# On Termux there is no tailscale CLI, so this node can't enumerate the tailnet on
# its own. It doesn't need to: any device running the daemon that has the CLI
# discovers this phone and pushes it the full roster automatically (usually within
# a minute). Until that first push lands, `ssh <name>` from here has no map yet.
if is_termux && [ ! -f "${XDG_CONFIG_HOME:-$HOME/.config}/tailssh/roster.json" ]; then
	say "note: make sure a device with the tailscale CLI (a PC/server) has tailssh"
	say "      running — it will push this phone the device list within ~1 minute."
fi

say "setting up this device..."
"$dest" up --yes || true

# Keep a daemon running now (the persistent service may need privileges we lack,
# e.g. Termux/rootless). A second daemon just exits if the port is already bound.
say "starting the tailssh daemon..."
boot="$HOME/.termux/boot/start-tailssh"
if is_termux && [ -f "$boot" ]; then
	# The boot script supervises the daemon (restart-on-exit); run it now too so
	# self-healing applies to this session, not just after a reboot.
	nohup sh "$boot" >"${HOME:-/tmp}/.tailssh-daemon.log" 2>&1 &
else
	nohup "$dest" daemon >"${HOME:-/tmp}/.tailssh-daemon.log" 2>&1 &
fi
say "done — reach any device with:  ssh <name>"

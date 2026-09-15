package main

// selectPlatform returns the backend for the current OS. Build tags ensure
// exactly one platform_<os>.go compiles and provides newPlatform().
func selectPlatform() Platform { return newPlatform() }

// Platform is the per-OS backend. One build-tagged file implements it
// (platform_linux.go — which also handles Termux at runtime, platform_windows.go,
// platform_darwin.go), each exposing `func newPlatform() Platform`.
//
// Everything above the Platform boundary (identity, keyserver, keysync, daemon,
// up) is OS-agnostic and shares netutil.go + discover(). Nothing is hardcoded to
// a user or tailnet — all values come from `tailscale status` at runtime.
type Platform interface {
	// Name is a short OS label ("linux", "termux", "windows", "darwin").
	Name() string

	// SSHState reports whether an SSH server is installed and currently running,
	// using init-aware probes (not PATH/pgrep guesses).
	SSHState() (installed, running bool)

	// InstallSSH installs the OpenSSH server, generates host keys if missing,
	// and opens the firewall where one is active. Idempotent.
	InstallSSH() error

	// EnableSSH enables + starts sshd so it survives reboot (systemd/OpenRC/
	// launchd/Windows service/Termux:Boot as appropriate). Idempotent.
	EnableSSH() error

	// SSHListenPort is the port this device's sshd listens on (22 everywhere
	// except Termux, which uses 8022). Used to generate the client ssh config.
	SSHListenPort() int

	// AuthorizedKeysPath returns the file that must hold the managed key block
	// for inbound auth (e.g. administrators_authorized_keys for a Windows admin).
	AuthorizedKeysPath() (string, error)

	// SecureKeyFile applies the correct ownership/permissions/labels to a key or
	// authorized_keys file (Unix 600/700, SELinux restorecon, Windows ACL).
	SecureKeyFile(path string) error

	// EnsureTailnetMTU clamps this node's Tailscale interface MTU down to
	// tailnetSafeMTU so large packets survive direct paths with a broken PMTU (see
	// tailnetSafeMTU). It only ever lowers, never raises, and is idempotent: a no-op
	// when the MTU is already at or below the target. It is also a no-op where the
	// local Tailscale MTU cannot be set — Android/Termux (the tun belongs to the
	// app) — or where doing so needs a privilege this process lacks (an unelevated
	// Windows daemon, a non-root Linux/macOS daemon), leaving it to a privileged run.
	EnsureTailnetMTU() error

	// SupportsIPNBus reports whether `tailscale debug watch-ipn` is usable here.
	// False on Android/Termux (app has no local CLI) → relay/receive model.
	SupportsIPNBus() bool

	// OpenURL opens a URL in the default browser / Android handler (for logins
	// and store pages during assisted setup).
	OpenURL(url string) error

	// InstallTailscale provisions Tailscale at the best level the platform allows:
	// auto-install on desktop, or open the app store on Android/Termux.
	InstallTailscale() error

	// InstallDaemon installs the tailssh daemon as a persistent service.
	InstallDaemon(exePath string) error
	// RemoveDaemon uninstalls the daemon service.
	RemoveDaemon() error
	// RestartDaemon bounces the installed daemon service so it runs the binary
	// currently on disk. `update` calls it after a swap: without the bounce the old
	// daemon keeps running from its renamed-aside image — stale code serving the
	// mesh, and a mapped .old that wedges the next update.
	RestartDaemon() error
	// EnsureDaemonPersistence repairs this node's daemon registration so an exited
	// daemon is always revived — called by the daemon at startup, so the whole fleet
	// converges through auto-update with no manual reinstall. A no-op where the
	// service manager already guarantees revival (systemd Restart=always, launchd
	// KeepAlive, the Termux supervisor loop); on Windows it upgrades a legacy
	// scheduled task to the watchdog registration.
	EnsureDaemonPersistence() error

	// MountSupport reports whether this node can serve its files to the mesh
	// (canExport — true wherever sshd/SFTP runs) and mount peers' filesystems
	// locally (canMount — false where there is no usable FUSE, e.g. Termux).
	MountSupport() (canExport, canMount bool)

	// EnsureMountTooling installs the client needed to mount a peer (sshfs, or
	// rclone + WinFsp on Windows), the way InstallSSH provisions the server.
	// Idempotent and best-effort.
	EnsureMountTooling() error

	// MountToolingPresent reports whether that mount client is installed right now.
	// reconcileMounts silently skips mounting while it is false — a node provisioned
	// before the file mesh existed (or whose `up` install failed) must keep exchanging
	// keys, not fail every sync over a client only `up` installs.
	MountToolingPresent() bool

	// MountPeer mounts spec's whole filesystem read-write as a local network unit and
	// returns the mountpoint used — a drive letter like "Z:" on Windows, a directory
	// on Unix. prevAt is the mountpoint from the previous pass ("" if none), reused
	// when still valid so a peer keeps a stable location. Idempotent: a no-op
	// returning prevAt when that mount is already live. Nothing is cached to disk.
	MountPeer(spec mountSpec, prevAt string) (at string, err error)

	// UnmountPeer tears down the mount at `at` (drive letter or directory). Idempotent.
	UnmountPeer(at string) error

	// SSHDConfigPath is the config file this node's sshd reads, which carries
	// the managed AcceptEnv block (see sshenv.go).
	SSHDConfigPath() string

	// ReplaceSSHDConfig overwrites sshd_config with data using whatever
	// privilege path the OS requires, then makes sshd re-read it (a service
	// reload/restart, or nothing where sshd is spawned per connection and
	// re-reads on its own). Callers only invoke it with changed content.
	ReplaceSSHDConfig(data []byte) error

	// ReplaceSelf overwrites the running executable's on-disk file with data (a new
	// release binary), the OS-correct way: an inode swap on Unix, or rename-aside +
	// rewrite on Windows (which locks a running image). The caller restarts afterward.
	ReplaceSelf(data []byte) error

	// EnsurePrivilege guarantees the process can perform the privileged provisioning
	// steps (write the system-wide authorized_keys, register a boot service). When it
	// re-launches the current command elevated to obtain them, it reports handled=true
	// so the caller stops and lets the elevated instance finish the work. On platforms
	// that escalate per-command (sudo) or already run privileged, it is a no-op
	// returning handled=false. args is the argument vector to re-run (os.Args[1:]).
	EnsurePrivilege(args []string) (handled bool, err error)
}

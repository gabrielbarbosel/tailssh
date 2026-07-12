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
}

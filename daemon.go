package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// daemonRosterPushActiveInterval is the roster push cadence while at least one
	// CLI-less peer is online, favouring fast onboarding.
	daemonRosterPushActiveInterval = 60 * time.Second
	// daemonRosterPushIdleInterval is the relaxed cadence used when no CLI-less peer
	// answered, so a tailnet of only desktops does almost no idle work.
	daemonRosterPushIdleInterval = 5 * time.Minute
	// daemonReconcileInterval is Doze-aligned: real-time changes already arrive via
	// /resync and roster pushes, so this only backstops drift and revocations — rare
	// enough that a long interval keeps mobile wakeups (and battery) minimal.
	daemonReconcileInterval = 15 * time.Minute
	// daemonHealthyStreamDuration is how long a watch-ipn stream must survive before
	// the transport counts as healthy and the reconnect backoff resets.
	daemonHealthyStreamDuration = 30 * time.Second
	// daemonMTUInterval is how often the daemon re-asserts the tailnet interface MTU,
	// so a Tailscale self-update that resets the adapter's MTU is corrected within one
	// interval. Kept long because the revert is rare and the check is cheap.
	daemonMTUInterval = 15 * time.Minute
)

// localUsername is this device's login name, with any Windows DOMAIN\ prefix
// stripped. On Termux/Android user.Current() fails (the app uid has no passwd
// entry), so it falls back to $USER/$LOGNAME and finally `id -un`, which resolves
// the u0_aNNN login there — without it /meta would advertise an empty user and
// peers could not build a working `ssh <phone>` entry.
func localUsername() string {
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	if name == "" {
		for _, e := range []string{"USER", "LOGNAME"} {
			if v := os.Getenv(e); v != "" {
				name = v
				break
			}
		}
	}
	if name == "" {
		if out, err := command("id", "-un").Output(); err == nil {
			name = strings.TrimSpace(string(out))
		}
	}
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// runDaemon is the long-lived event loop. It keeps this device's authorized_keys
// and ssh_config in sync with the tailnet at near-zero idle cost: it blocks on the
// Tailscale IPN bus (desktops) or on the keyserver /resync receiver (Android), and
// only runs a sync when something actually changed — debounced and serialized.
//
// An initial sync and a presence announcement run before the event loop so the device
// self-corrects even if no event ever arrives. SIGINT/SIGTERM cancels ctx, which tears
// down the watch-ipn subprocess and unblocks the event loops.
func runDaemon(pl Platform) error {
	daemonTuneRuntimeFootprint()

	_, pubLine, err := ensureIdentity(pl)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	if daemonAlreadyRunning(pubLine) {
		log.Printf("daemon: another instance already serves this node's key — exiting so it stays the only one")
		return nil
	}

	engine := &syncEngine{pl: pl}

	ks, ksDebounce := daemonNewKeyserverSupervisor(pl, pubLine, engine)
	engine.beforeSync = ks.ensure
	ks.ensure()
	defer ks.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("daemon: %s up (ipn-bus=%v)", pl.Name(), pl.SupportsIPNBus())

	cleanupUpdateLeftovers()
	if err := pl.EnsureDaemonPersistence(); err != nil {
		log.Printf("daemon: persistence: %v", err)
	}
	engine.trigger(false)
	daemonAnnouncePresence()
	daemonStartSeedLoops(ctx, pl)
	go daemonAutoUpdateLoop(ctx, pl)

	if pl.SupportsIPNBus() {
		watchIPN(ctx, engine)
	} else {
		pollLoop(ctx, engine)
	}

	daemonStopSyncing(ksDebounce, engine)

	log.Printf("daemon: shutting down")
	return nil
}

// daemonAlreadyRunning reports whether another live daemon on this device is already
// serving this node's public key — the single-instance guard. The Windows watchdog
// trigger (or a logon firing both a task and a leftover Run key) can start a second
// daemon while a healthy one holds the keyserver port; the newcomer detects the
// incumbent by fetching /pubkey on the tailnet IP and comparing keys, then exits 0 so
// the service manager records a clean no-op instead of a failure. Comparing the key —
// not just port liveness — means a foreign process squatting on the port does NOT
// make the daemon bow out.
func daemonAlreadyRunning(pubLine string) bool {
	ip, err := daemonResolveSelfIP()
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	line, err := fetchPubkey(ctx, ip)
	return err == nil && line == keysyncFirstLine([]byte(pubLine))
}

// daemonTuneRuntimeFootprint keeps the resident footprint tiny — one OS thread, a hard
// memory ceiling and lazy GC — since the daemon idles on every device, phones included.
func daemonTuneRuntimeFootprint() {
	runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(64 << 20)
	debug.SetGCPercent(40)
}

// daemonResolveSelfIP returns this device's tailnet IP, which the keyserver binds to
// exclusively. It prefers the value from discover() and falls back to scanning
// interfaces for the 100.64/10 address, so a CLI-less node (Termux, no seed yet) still
// comes up and serves its key — enough for CLI-capable peers to discover and authorize
// it inbound.
func daemonResolveSelfIP() (string, error) {
	if devs, err := discover(); err == nil {
		if self, ok := selfDevice(devs); ok && self.ip != "" {
			return self.ip, nil
		}
	}
	if ip := selfTailnetIP(); ip != "" {
		return ip, nil
	}
	return "", fmt.Errorf("cannot determine this device's tailnet IP (is Tailscale connected?)")
}

// daemonNewKeyserverSupervisor prepares the key/meta/roster endpoints and returns the
// debounce that a /resync POST arms — the only change signal on Android, and a
// belt-and-suspenders one on desktops. A CLI peer's roster push replaces our cached map,
// which we adopt and re-sync so this node rebuilds ssh_config/authorized_keys against
// the new peers.
//
// Adopting a roster also announces our presence. A CLI-less node (a phone) starts with
// no roster, so its startup announce reaches no one and peers never learn it began
// serving its key — a mesh-join raises no netmap event to wake them, so without this
// they would not fetch its key until their next slow reconcile. Announcing the moment we
// learn our peers closes that gap: every device, including one that was offline and just
// came back, is picked up within the roster-push interval instead of up to a reconcile.
func daemonNewKeyserverSupervisor(pl Platform, pubLine string, engine *syncEngine) (*keyserverSupervisor, *debounce) {
	resyncDebounce := newDebounce(2*time.Second, 10*time.Second, func() { engine.trigger(false) })
	metaBytes, _ := json.Marshal(nodeMeta{User: localUsername(), OS: pl.Name(), Port: pl.SSHListenPort()})
	adoptRoster := func(raw []byte) {
		if changed, err := saveRosterCache(raw); err == nil && changed {
			engine.trigger(false)
			go daemonAnnouncePresence()
		}
	}
	hostKey := readHostKey(pl.SSHListenPort())
	open := func(ip string) (io.Closer, error) {
		return startKeyserver(ip, pubLine, string(metaBytes), hostKey, rosterJSON, resyncDebounce.arm, adoptRoster)
	}
	return &keyserverSupervisor{resolve: daemonResolveSelfIP, open: open}, resyncDebounce
}

// keyserverSupervisor keeps the keyserver listening on this device's CURRENT tailnet
// IP. startKeyserver deliberately binds one explicit IP (tailnet membership is the
// authorization boundary, so never 0.0.0.0), but that IP is only resolved once per
// bind — and it can change while the daemon runs (re-login, node re-added to the
// tailnet). A listener left on the old IP is silently unreachable: peers stop fetching
// this node's key and `ssh <name>` eventually fails with publickey errors while
// everything still looks up. ensure() heals both that drift and a bind that failed
// outright (Tailscale not connected yet at boot): it re-resolves the IP and rebinds
// only when the listener is missing or on the wrong address, so the steady-state call
// is a cheap compare.
type keyserverSupervisor struct {
	mu      sync.Mutex
	resolve func() (string, error)             // current tailnet IP (daemonResolveSelfIP)
	open    func(ip string) (io.Closer, error) // binds the keyserver to one IP
	bound   string
	ks      io.Closer
}

// ensure (re)binds the keyserver to the current tailnet IP if it isn't already there.
// Called at daemon startup and before every sync pass — netmap events, /resync nudges
// and the reconcile ticker all funnel through the sync engine, so an IP change is
// picked up by the very event that announces it. Failures are logged, never fatal:
// the next pass retries.
func (s *keyserverSupervisor) ensure() {
	ip, err := s.resolve()
	if err != nil {
		return // no tailnet view right now; keep whatever listener we have
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ks != nil && ip == s.bound {
		return
	}
	if s.ks != nil {
		log.Printf("daemon: keyserver: tailnet IP moved %s -> %s, rebinding", s.bound, ip)
		s.ks.Close()
		s.ks = nil
	}
	ks, err := s.open(ip)
	if err != nil {
		log.Printf("daemon: keyserver: %v (will retry on next sync)", err)
		return
	}
	s.ks, s.bound = ks, ip
	log.Printf("daemon: keyserver up on %s", ip)
}

func (s *keyserverSupervisor) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ks == nil {
		return nil
	}
	err := s.ks.Close()
	s.ks = nil
	return err
}

// daemonAnnouncePresence nudges peers already on the tailnet to re-sync and authorize us
// — joining the mesh doesn't change the netmap, so nothing else wakes them — and pushes
// our roster to any CLI-less peer so it can reach everyone without a seed.
func daemonAnnouncePresence() {
	devs, err := discover()
	if err != nil {
		return
	}
	announceAll(devs)
	pushRoster(devs)
}

// daemonStartSeedLoops starts the background loops only a node with the tailscale CLI
// can run, and is a no-op where the CLI is absent (Termux/Android). CLI presence also
// gates the MTU loop: the CLI-less node is the phone, whose app-managed tun MTU
// tailssh cannot set anyway, so skipping it there also spares the phone an idle wakeup.
func daemonStartSeedLoops(ctx context.Context, pl Platform) {
	if _, err := tailscaleBin(); err != nil {
		return
	}
	go daemonPushRosterLoop(ctx)
	go daemonEnsureMTULoop(ctx, pl)
}

// daemonEnsureMTULoop keeps the Tailscale interface MTU clamped for broken-PMTU
// direct paths (see EnsureTailnetMTU). It asserts once at startup and then on a slow
// ticker, because a Tailscale self-update recreates the adapter and silently resets
// its MTU with no netmap event to announce it — so this is the only thing that heals
// the revert without waiting for the next logon.
func daemonEnsureMTULoop(ctx context.Context, pl Platform) {
	ensure := func() {
		if err := pl.EnsureTailnetMTU(); err != nil {
			log.Printf("daemon: mtu: %v", err)
		}
	}
	ensure()
	t := time.NewTicker(daemonMTUInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ensure()
		}
	}
}

// daemonPushRosterLoop keeps CLI-less peers discoverable. Starting tailssh doesn't
// change the tailnet netmap, so a freshly-installed peer (a phone) raises no event for
// watchIPN to catch — this steady push is how it gets discovered. The receiver only
// re-syncs when the roster actually changed, so repeated identical pushes are free.
func daemonPushRosterLoop(ctx context.Context) {
	interval := daemonRosterPushActiveInterval
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			pushed := 0
			if devs, err := discover(); err == nil {
				pushed = pushRoster(devs)
			}
			if pushed > 0 {
				interval = daemonRosterPushActiveInterval
			} else {
				interval = daemonRosterPushIdleInterval
			}
		}
	}
}

// daemonStopSyncing stops scheduling new syncs before draining the in-flight one, in
// that order, so nothing can write files after runDaemon returns.
func daemonStopSyncing(resyncDebounce *debounce, engine *syncEngine) {
	resyncDebounce.Stop()
	engine.shutdown()
}

// syncEngine serializes runSync calls. At most one runs at a time; a trigger that
// arrives mid-run sets a dirty flag so exactly one follow-up run happens afterwards.
type syncEngine struct {
	pl Platform
	// beforeSync runs ahead of every sync pass (the keyserver supervisor's ensure):
	// each pass then both serves on and syncs against the same, current tailnet IP.
	beforeSync func()
	mu         sync.Mutex
	running    bool
	dirty      bool
	relay      bool           // push the roster to Android peers after the next run
	closed     bool           // once true, trigger is a no-op (shutdown in progress)
	wg         sync.WaitGroup // tracks the in-flight loop goroutine
}

// trigger requests a sync, coalescing into a single rerun if one is already running.
// relay carries whether the resulting sync should push the roster to Android peers.
// Once the engine is closed (shutdown), trigger does nothing.
func (e *syncEngine) trigger(relay bool) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	if relay {
		e.relay = true
	}
	if e.running {
		e.dirty = true
		e.mu.Unlock()
		return
	}
	e.running = true
	e.wg.Add(1)
	e.mu.Unlock()
	go e.loop()
}

// shutdown blocks new syncs and waits for any in-flight one to finish, guaranteeing
// no sync writes files after it returns.
func (e *syncEngine) shutdown() {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	e.wg.Wait()
}

// loop drains sync requests one at a time until none are pending.
func (e *syncEngine) loop() {
	defer e.wg.Done()
	for {
		e.mu.Lock()
		relay := e.relay
		e.relay = false
		e.mu.Unlock()

		e.runOnce(relay)

		e.mu.Lock()
		if !e.dirty {
			e.running = false
			e.mu.Unlock()
			return
		}
		e.dirty = false
		e.mu.Unlock()
	}
}

// runOnce performs a single sync under recover() so one flaky peer or panic can never
// kill the daemon. It releases memory afterwards and, on the event path, pushes the
// fresh roster to Android peers (which have no bus to notice the change themselves).
func (e *syncEngine) runOnce(relay bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("daemon: sync panic recovered: %v", r)
		}
	}()
	if e.beforeSync != nil {
		e.beforeSync()
	}
	if err := runSync(e.pl); err != nil {
		log.Printf("daemon: sync error: %v", err)
	}
	debug.FreeOSMemory()
	if relay {
		if devs, err := discover(); err == nil {
			pushRoster(devs)
		}
	}
}

// debounce arms a single resettable timer: repeated arm() calls within the window
// collapse into one fn() call. No timer is armed while idle, so there are no idle
// wakeups. The maxD ceiling bounds how long a steady stream of arm() calls can
// postpone the fire, so fn runs at least once every maxD during a burst.
type debounce struct {
	mu       sync.Mutex
	timer    *time.Timer
	d        time.Duration
	maxD     time.Duration
	deadline time.Time // hard fire time for the current burst; zero when idle
	fn       func()
}

func newDebounce(d, maxD time.Duration, fn func()) *debounce {
	return &debounce{d: d, maxD: maxD, fn: fn}
}

// arm (re)starts the debounce window; fn runs once the calls go quiet for d, or at
// the burst deadline (maxD after the first arm), whichever comes first.
func (b *debounce) arm() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.beginBurstIfIdle()
	if b.timer == nil {
		b.timer = time.AfterFunc(b.d, b.fire)
		return
	}
	b.timer.Reset(b.waitCappedByDeadline())
}

// beginBurstIfIdle opens a new burst deadline when none is pending, which covers both
// the very first arm and a timer that already fired but was not rearmed since.
func (b *debounce) beginBurstIfIdle() {
	if b.maxD > 0 && b.deadline.IsZero() {
		b.deadline = time.Now().Add(b.maxD)
	}
}

// waitCappedByDeadline is the quiet window d, shortened so the timer never fires past
// the current burst deadline.
func (b *debounce) waitCappedByDeadline() time.Duration {
	wait := b.d
	if b.deadline.IsZero() {
		return wait
	}
	if rem := time.Until(b.deadline); rem < wait {
		wait = rem
		if wait < 0 {
			wait = 0
		}
	}
	return wait
}

// fire runs the callback and closes the current burst so the next arm() starts fresh.
func (b *debounce) fire() {
	b.mu.Lock()
	b.deadline = time.Time{}
	b.mu.Unlock()
	b.fn()
}

// Stop cancels any pending timer so no further fn() call can fire. It does not join a
// fire() already in progress; callers that must exclude in-flight work should also
// drain the work fn() schedules (see syncEngine.shutdown).
func (b *debounce) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.timer != nil {
		b.timer.Stop()
	}
	b.deadline = time.Time{}
}

// watchIPN follows `tailscale debug watch-ipn`, arming a debounced sync on every
// netmap change, and respawns the stream with capped backoff whenever it drops
// (e.g. tailscaled restart), running an immediate sync on each reconnect so changes
// missed while disconnected are still caught.
func watchIPN(ctx context.Context, engine *syncEngine) {
	ipnDebounce := newDebounce(2*time.Second, 10*time.Second, func() { engine.trigger(true) })
	defer ipnDebounce.Stop()
	attempt := 0
	for ctx.Err() == nil {
		start := time.Now()
		err := streamIPN(ctx, ipnDebounce)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("daemon: watch-ipn ended: %v", err)
		}
		if time.Since(start) > daemonHealthyStreamDuration {
			attempt = 0
		}
		wait := backoff(attempt, time.Second, 30*time.Second)
		attempt++
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		engine.trigger(true)
	}
}

// ipnNotify is the minimal shape we decode from the watch-ipn stream. Netmaps can
// exceed 64 KiB and be pretty-printed, so we stream-decode with json.Decoder and keep
// the payload as RawMessage — we never parse peers here (sync re-reads status).
type ipnNotify struct {
	NetMap json.RawMessage `json:"NetMap"`
}

// carriesNetmap reports whether the frame is a real netmap change; engine and stats
// frames arrive on the same stream and must not trigger a sync.
func (n ipnNotify) carriesNetmap() bool {
	return len(n.NetMap) > 0 && string(n.NetMap) != "null"
}

// streamIPN runs one watch-ipn subprocess to completion, arming deb on each netmap
// event. It returns when the stream ends (EOF/err) or ctx is cancelled.
func streamIPN(ctx context.Context, deb *debounce) error {
	bin, err := tailscaleBin()
	if err != nil {
		return err
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(cctx, bin, "debug", "watch-ipn")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer daemonReapWatcher(cancel, cmd)

	dec := json.NewDecoder(stdout)
	for {
		var n ipnNotify
		if err := dec.Decode(&n); err != nil {
			return err
		}
		if n.carriesNetmap() {
			deb.arm()
		}
	}
}

// daemonReapWatcher terminates the watch-ipn subprocess and waits for it, which also
// closes the stdout pipe. Must run on every return path or the child is left orphaned.
func daemonReapWatcher(cancel context.CancelFunc, cmd *exec.Cmd) {
	cancel()
	cmd.Wait()
}

// pollLoop is the Android/no-bus path. It relies on the keyserver /resync receiver
// plus the initial sync, and additionally reconciles on a slow ticker so revoked keys
// are pruned and drift is corrected even when no /resync ever arrives (these devices
// have no IPN bus to notice changes).
func pollLoop(ctx context.Context, engine *syncEngine) {
	t := time.NewTicker(daemonReconcileInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			engine.trigger(false)
		}
	}
}

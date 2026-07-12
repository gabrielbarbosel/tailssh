package main

import (
	"context"
	"encoding/json"
	"fmt"
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
		if out, err := exec.Command("id", "-un").Output(); err == nil {
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
func runDaemon(pl Platform) error {
	// Keep the footprint tiny: one OS thread, hard memory ceiling, lazy GC.
	runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(64 << 20)
	debug.SetGCPercent(40)

	_, pubLine, err := ensureIdentity(pl)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	// The keyserver binds exclusively to this device's tailnet IP. Prefer the value
	// from discover(), but fall back to scanning interfaces for the 100.64/10 address
	// so a CLI-less node (Termux, no seed yet) still comes up and serves its key —
	// enough for CLI-capable peers to discover and authorize it inbound.
	selfIP := ""
	if devs, err := discover(); err == nil {
		if self, ok := selfDevice(devs); ok {
			selfIP = self.ip
		}
	}
	if selfIP == "" {
		selfIP = selfTailnetIP()
	}
	if selfIP == "" {
		return fmt.Errorf("cannot determine this device's tailnet IP (is Tailscale connected?)")
	}

	engine := &syncEngine{pl: pl}

	// A /resync POST schedules a debounced (non-relaying) sync. This is the only
	// change signal on Android, and a belt-and-suspenders one on desktops.
	ksDebounce := newDebounce(2*time.Second, 10*time.Second, func() { engine.trigger(false) })
	metaBytes, _ := json.Marshal(nodeMeta{User: localUsername(), OS: pl.Name(), Port: pl.SSHListenPort()})
	// A CLI peer's push replaces our cached map; adopt it and re-sync so this
	// CLI-less node rebuilds ssh_config/authorized_keys against the new peers.
	onRoster := func(raw []byte) {
		if changed, err := saveRosterCache(raw); err == nil && changed {
			engine.trigger(false)
		}
	}
	ks, err := startKeyserver(selfIP, pubLine, string(metaBytes), readHostKey(pl.SSHListenPort()), rosterJSON, ksDebounce.arm, onRoster)
	if err != nil {
		return fmt.Errorf("keyserver: %w", err)
	}
	defer ks.Close()

	// Cancelling ctx tears down the watch-ipn subprocess and unblocks the event loops.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("daemon: %s up on %s (ipn-bus=%v)", pl.Name(), selfIP, pl.SupportsIPNBus())

	// One initial sync self-corrects even if no event ever arrives.
	engine.trigger(false)

	// Announce ourselves so peers already on the tailnet re-sync and authorize us —
	// joining the mesh doesn't change the netmap, so nothing else nudges them — and
	// push our roster to any CLI-less peer so it can reach everyone without a seed.
	if devs, err := discover(); err == nil {
		announceAll(devs)
		pushRoster(devs)
	}

	// Only nodes with the tailscale CLI can seed the mesh. Two cadences:
	if _, err := tailscaleBin(); err == nil {
		// Roster push. Starting tailssh doesn't change the tailnet netmap, so a
		// freshly-installed CLI-less peer (a phone) raises no event for watchIPN to
		// catch — this steady push is how it gets discovered. The cadence is adaptive:
		// 60s while any CLI-less peer is online (fast onboarding), relaxing to 5m when
		// there are none, so a tailnet of only desktops does almost no idle work.
		// onRoster only re-syncs the receiver when the roster changed, so repeated
		// identical pushes are effectively free on the phone too.
		go func() {
			const active, idle = 60 * time.Second, 5 * time.Minute
			interval := active
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
						interval = active
					} else {
						interval = idle
					}
				}
			}
		}()
		// Fleet onboarding (Taildrop push to devices not yet in the mesh), slower.
		fleet := newOnboardState()
		go fleetSweep(fleet)
		go func() {
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					fleetSweep(fleet)
				}
			}
		}()
	}

	if pl.SupportsIPNBus() {
		watchIPN(ctx, engine)
	} else {
		pollLoop(ctx, engine)
	}

	// Order matters: stop scheduling new syncs before draining the in-flight one, so
	// nothing can write files after we return.
	ksDebounce.Stop()
	engine.shutdown()

	log.Printf("daemon: shutting down")
	return nil
}

// syncEngine serializes runSync calls. At most one runs at a time; a trigger that
// arrives mid-run sets a dirty flag so exactly one follow-up run happens afterwards.
type syncEngine struct {
	pl      Platform
	mu      sync.Mutex
	running bool
	dirty   bool
	relay   bool           // push the roster to Android peers after the next run
	closed  bool           // once true, trigger is a no-op (shutdown in progress)
	wg      sync.WaitGroup // tracks the in-flight loop goroutine
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
	if b.timer == nil {
		if b.maxD > 0 {
			b.deadline = time.Now().Add(b.maxD)
		}
		b.timer = time.AfterFunc(b.d, b.fire)
		return
	}
	// A fired-but-not-rearmed timer starts a fresh burst.
	if b.maxD > 0 && b.deadline.IsZero() {
		b.deadline = time.Now().Add(b.maxD)
	}
	wait := b.d
	if !b.deadline.IsZero() {
		if rem := time.Until(b.deadline); rem < wait {
			wait = rem
			if wait < 0 {
				wait = 0
			}
		}
	}
	b.timer.Reset(wait)
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
// (e.g. tailscaled restart), running an immediate sync on each reconnect.
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
		// A stream that survived a while means the transport is healthy: reset backoff.
		if time.Since(start) > 30*time.Second {
			attempt = 0
		}
		wait := backoff(attempt, time.Second, 30*time.Second)
		attempt++
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		// Immediate sync on reconnect catches any change missed while disconnected.
		engine.trigger(true)
	}
}

// ipnNotify is the minimal shape we decode from the watch-ipn stream. Netmaps can
// exceed 64 KiB and be pretty-printed, so we stream-decode with json.Decoder and keep
// the payloads as RawMessage — we never parse peers here (sync re-reads status).
type ipnNotify struct {
	NetMap json.RawMessage `json:"NetMap"`
	Engine json.RawMessage `json:"Engine"`
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
	// Always reap the child and close the pipe, even on early return.
	defer func() {
		cancel()
		cmd.Wait()
	}()

	dec := json.NewDecoder(stdout)
	for {
		var n ipnNotify
		if err := dec.Decode(&n); err != nil {
			return err
		}
		// Only a real netmap counts as a change; ignore engine/stats frames.
		if len(n.NetMap) > 0 && string(n.NetMap) != "null" {
			deb.arm()
		}
	}
}

// pollLoop is the Android/no-bus path. It relies on the keyserver /resync receiver
// plus the initial sync, and additionally reconciles on a slow ticker so revoked keys
// are pruned and drift is corrected even when no /resync ever arrives (these devices
// have no IPN bus to notice changes). Set reconcileInterval <= 0 to disable.
func pollLoop(ctx context.Context, engine *syncEngine) {
	// 15 minutes, Doze-aligned: real-time changes already arrive via the /resync and
	// roster pushes, so this only backstops drift/revocations — rare enough that a
	// long interval keeps mobile wakeups (and battery) minimal.
	const reconcileInterval = 15 * time.Minute
	if reconcileInterval <= 0 {
		<-ctx.Done()
		return
	}
	t := time.NewTicker(reconcileInterval)
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

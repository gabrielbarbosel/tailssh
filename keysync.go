package main

// keysync.go — the `sync` core: the federated key exchange.
//
// runSync builds the trusted peer set from a live `tailscale status`, fetches
// each online peer's ed25519 public key from its keyserver, and regenerates two
// marker-delimited managed blocks:
//   - the SSH authorized_keys file (inbound auth), and
//   - ~/.ssh/config (outbound convenience Host entries).
//
// Everything is offline-first: peer key material is cached in peers.json and
// reused when a peer is offline or unreachable. A peer's key is pruned only when
// the peer is absent from a *successful* discover() (it left the tailnet or
// changed owner) — never merely because it was offline or a fetch failed.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Managed-block markers. Everything between them is owned by tailssh and fully
// regenerated each sync; anything outside is preserved untouched.
const (
	managedBegin = "# >>> tailssh managed >>>"
	managedEnd   = "# <<< tailssh managed <<<"
)

// keyPort is the fixed port each node's keyserver listens on.
const keyPort = 8021

// cachedPeer is one entry of peers.json — the offline-first cache of everything
// needed to authorize a peer inbound and to reach it outbound (key + user + port).
type cachedPeer struct {
	Name      string    `json:"name"`
	IP        string    `json:"ip"`
	OS        string    `json:"os"`
	Pubkey    string    `json:"pubkey"`
	User      string    `json:"user"`              // remote login for ssh_config (from /meta)
	Port      int       `json:"port"`              // remote sshd port (from /meta)
	HostKey   string    `json:"hostKey,omitempty"` // sshd host key for known_hosts (from /hostkey)
	FetchedAt time.Time `json:"fetchedAt"`
}

// peerInfo is what a single peer serves us this pass: its key, /meta and host key.
type peerInfo struct {
	pubkey  string
	user    string
	port    int
	hostKey string
}

// selfDevice returns the tailnet member that is this device.
func selfDevice(devs []device) (device, bool) {
	for _, d := range devs {
		if d.self {
			return d, true
		}
	}
	return device{}, false
}

// runSync performs one full key-exchange pass. It returns an error only when the
// tailnet membership can't be read (discover failed) — with no live membership no
// managed block is touched, so a blind pass can never prune a peer. Per-peer and
// per-file problems are logged and tolerated so a single flaky peer never fails the
// sync.
func runSync(pl Platform) error {
	defer debug.FreeOSMemory()

	devs, err := discover()
	if err != nil {
		return err
	}
	self, ok := selfDevice(devs)
	if !ok {
		return fmt.Errorf("sync: no self device in tailnet status")
	}

	owned := syncTrustedPeers(devs, self)
	keyed := syncMergePeerCache(owned, fetchPeerKeys(owned), loadPeers(), time.Now().UTC())

	var firstErr error
	note := func(e error) {
		if e != nil {
			fmt.Fprintln(os.Stderr, "sync:", e)
			if firstErr == nil {
				firstErr = e
			}
		}
	}

	if err := writeAuthorizedKeys(pl, syncPubkeyLines(keyed)); err != nil {
		note(err)
	}

	if err := writeSSHConfig(pl, owned, keyed); err != nil {
		note(err)
	}

	if err := writeKnownHosts(keyed); err != nil {
		note(err)
	}

	if err := savePeers(keyed); err != nil {
		note(err)
	}

	return firstErr
}

// syncTrustedPeers is the set one sync pass may authorize: same-owner, addressable
// peers present in this successful discover(). Peers absent from it are pruned (they
// left the tailnet or changed owner); other owners are excluded entirely.
func syncTrustedPeers(devs []device, self device) []device {
	var owned []device
	for _, d := range devs {
		if d.self || d.ip == "" {
			continue
		}
		if self.owner == "" || d.owner != self.owner {
			continue
		}
		owned = append(owned, d)
	}
	sort.Slice(owned, func(i, j int) bool { return owned[i].name < owned[j].name })
	return owned
}

// syncMergePeerCache folds this pass's fetches into the on-disk cache, one entry per
// owned peer. A freshly fetched key wins; an offline or unreachable peer keeps its
// whole last-known entry instead of being dropped. When the key is fresh but a
// best-effort field (/meta, /hostkey) failed this pass, the cached value is retained
// rather than clobbered. A peer with neither a fresh nor a cached key is omitted —
// there is nothing to authorize for it yet.
func syncMergePeerCache(owned []device, fetched map[string]peerInfo, cache map[string]cachedPeer, now time.Time) map[string]cachedPeer {
	merged := make(map[string]cachedPeer, len(owned))
	for _, p := range owned {
		info := fetched[p.name]
		key, usr, prt, hk, at := info.pubkey, info.user, info.port, info.hostKey, now
		if key == "" {
			if c, ok := cache[p.name]; ok {
				key, usr, prt, hk, at = c.Pubkey, c.User, c.Port, c.HostKey, c.FetchedAt
			}
		} else if c, ok := cache[p.name]; ok {
			if usr == "" && prt == 0 {
				usr, prt = c.User, c.Port
			}
			if hk == "" {
				hk = c.HostKey
			}
		}
		if key == "" {
			continue
		}
		merged[p.name] = cachedPeer{Name: p.name, IP: p.ip, OS: p.os, Pubkey: key, User: usr, Port: prt, HostKey: hk, FetchedAt: at}
	}
	return merged
}

// peerNamesSorted lists the cache's peer names in order, so every generated file is
// byte-stable across passes and an unchanged file can be skipped.
func peerNamesSorted(keyed map[string]cachedPeer) []string {
	names := make([]string, 0, len(keyed))
	for n := range keyed {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// syncPubkeyLines renders the authorized_keys managed-block body.
func syncPubkeyLines(keyed map[string]cachedPeer) string {
	var lines []string
	for _, n := range peerNamesSorted(keyed) {
		lines = append(lines, keyed[n].Pubkey)
	}
	return strings.Join(lines, "\n")
}

// fetchPeerKeys pulls /pubkey from every online peer concurrently (<=8 workers)
// under a 60s deadline, returning name→validated-key for the successes only. Offline
// peers and per-peer failures are simply absent: the cache covers them.
func fetchPeerKeys(peers []device) map[string]peerInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out := make(map[string]peerInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for _, p := range peers {
		if !p.online || p.ip == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p device) {
			defer wg.Done()
			defer func() { <-sem }()
			info, ok := fetchPeerInfo(ctx, p.ip)
			if !ok {
				return
			}
			mu.Lock()
			out[p.name] = info
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return out
}

// fetchPeerInfo collects everything one peer serves this pass. Only /pubkey is
// required: /meta and /hostkey are best-effort, so a peer answering with a key alone
// still joins the mesh and falls back to its cached user, port and host key.
func fetchPeerInfo(ctx context.Context, ip string) (peerInfo, bool) {
	line, err := fetchPubkey(ctx, ip)
	if err != nil {
		return peerInfo{}, false
	}
	info := peerInfo{pubkey: line}
	if m, err := fetchMeta(ctx, ip); err == nil {
		info.user, info.port = m.User, m.Port
	}
	info.hostKey = fetchHostKey(ctx, ip)
	return info, true
}

// fetchMeta GETs http://<ip>:8021/meta (3s, <=4 KiB) and decodes the peer's
// self-description (remote user + sshd port) for ssh_config generation. A user that
// fails validSSHUser is blanked rather than trusted — it is written verbatim into
// ssh_config, where a newline would inject arbitrary directives.
func fetchMeta(parent context.Context, ip string) (nodeMeta, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	url := fmt.Sprintf("http://%s:%d/meta", hostForURL(ip), keyPort)
	body, err := getBounded(ctx, url, 4096)
	if err != nil {
		return nodeMeta{}, err
	}
	var m nodeMeta
	if err := json.Unmarshal(body, &m); err != nil {
		return nodeMeta{}, err
	}
	if !validSSHUser(m.User) {
		m.User = ""
	}
	return m, nil
}

// validSSHUser reports whether s is a safe remote login to embed in ssh_config.
// It must be non-empty, not padded with whitespace, and free of anything that
// could break out of the (possibly quoted) User directive or the managed block:
// control characters, DEL, double quotes and backslashes. Interior spaces ARE
// allowed — Windows account names often contain them — and sshConfigUser quotes
// any value that isn't a bare token.
func validSSHUser(s string) bool {
	if s == "" || s != strings.TrimSpace(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

// sshConfigUser renders a login name for an ssh_config User line, quoting it when
// it isn't a bare [A-Za-z0-9._-] token (e.g. "Jane Doe"). validSSHUser has
// already excluded quotes/backslashes, so wrapping in double quotes is safe.
func sshConfigUser(u string) string {
	for _, r := range u {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
		default:
			return `"` + u + `"`
		}
	}
	return u
}

// keysyncFirstLine trims a keyserver response body down to its first line, the only
// part any of the single-value endpoints carries.
func keysyncFirstLine(body []byte) string {
	line := strings.TrimSpace(string(body))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	return line
}

// fetchPubkey GETs http://<ip>:8021/pubkey (3s), reads at most 8 KiB, and
// returns the line only if it parses as a valid ssh-ed25519 authorized key.
func fetchPubkey(parent context.Context, ip string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	url := fmt.Sprintf("http://%s:%d/pubkey", hostForURL(ip), keyPort)
	body, err := getBounded(ctx, url, 8192)
	if err != nil {
		return "", err
	}
	line := keysyncFirstLine(body)
	if !validEd25519Line(line) {
		return "", fmt.Errorf("peer %s served an invalid ssh-ed25519 key", ip)
	}
	return line, nil
}

// fetchHostKey GETs http://<ip>:8021/hostkey (3s) and returns the peer's sshd host
// key as "type base64" only if it is a valid ssh-ed25519 line; "" otherwise, since
// known_hosts pre-population is optional (accept-new covers the miss).
func fetchHostKey(parent context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	url := fmt.Sprintf("http://%s:%d/hostkey", hostForURL(ip), keyPort)
	body, err := getBounded(ctx, url, 8192)
	if err != nil {
		return ""
	}
	f := strings.Fields(keysyncFirstLine(body))
	if len(f) < 2 || !validEd25519Line(f[0]+" "+f[1]) {
		return ""
	}
	return f[0] + " " + f[1]
}

// readHostKey returns this node's sshd ed25519 host public key as "type base64"
// (comment stripped), served at /hostkey for peers' known_hosts. It prefers the
// on-disk .pub but falls back to ssh-keyscan when that file is unreadable — e.g.
// Windows OpenSSH ACL-locks the host key from a non-admin daemon. "" if both fail.
func readHostKey(port int) string {
	if b, err := os.ReadFile(sshHostKeyPubPath()); err == nil {
		f := strings.Fields(strings.TrimSpace(string(b)))
		if len(f) >= 2 && validEd25519Line(f[0]+" "+f[1]) {
			return f[0] + " " + f[1]
		}
	}
	return scanLocalHostKey(port)
}

// scanLocalHostKey retrieves the local sshd's ed25519 host key via ssh-keyscan (a
// plain SSH handshake to 127.0.0.1) — needs no file access, so it works for an
// unprivileged daemon. Its output is "127.0.0.1 ssh-ed25519 AAAA..." lines mixed with
// '#' comment lines. Returns "type base64" or "" on failure.
func scanLocalHostKey(port int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh-keyscan", "-t", "ed25519",
		"-p", strconv.Itoa(port), "127.0.0.1").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 3 && validEd25519Line(f[1]+" "+f[2]) {
			return f[1] + " " + f[2]
		}
	}
	return ""
}

// knownHostsPath is the tailssh-managed known_hosts file (fully owned by tailssh).
func knownHostsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tailssh", "known_hosts"), nil
}

// sshPortFor resolves a peer's sshd port: the one it advertised via /meta, else the
// platform default — 8022 on Android, where sshd is Termux's unprivileged one.
func sshPortFor(peerOS string, advertised int) int {
	if advertised != 0 {
		return advertised
	}
	if peerOS == "android" {
		return 8022
	}
	return 22
}

// hostPattern renders the comma-joined known_hosts host patterns for a peer reached
// by name and IP on port; non-22 ports use ssh's "[host]:port" form.
func hostPattern(name, ip string, port int) string {
	one := func(h string) string {
		if h == "" {
			return ""
		}
		if port != 22 {
			return fmt.Sprintf("[%s]:%d", h, port)
		}
		return h
	}
	var parts []string
	if h := one(name); h != "" {
		parts = append(parts, h)
	}
	if h := one(ip); h != "" {
		parts = append(parts, h)
	}
	return strings.Join(parts, ",")
}

// writeKnownHosts writes the tailssh-managed known_hosts: one line per in-mesh peer
// whose sshd host key we hold, so `ssh <name>` verifies the host silently instead of
// prompting on first connect. Tailscale-SSH peers aren't in the key cache and so are
// skipped (Tailscale verifies those). The whole file is tailssh's, so it is replaced
// wholesale (no managed-block markers needed).
func writeKnownHosts(keyed map[string]cachedPeer) error {
	path, err := knownHostsPath()
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, n := range peerNamesSorted(keyed) {
		c := keyed[n]
		if c.HostKey == "" {
			continue
		}
		if pat := hostPattern(c.Name, c.IP, sshPortFor(c.OS, c.Port)); pat != "" {
			fmt.Fprintf(&b, "%s %s\n", pat, c.HostKey)
		}
	}
	out := []byte(b.String())
	if sameContent(path, out) {
		return nil
	}
	return atomicWrite(path, out, 0o600)
}

// postResync fires a best-effort /resync POST at a peer (1s budget).
func postResync(ip string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	url := fmt.Sprintf("http://%s:%d/resync", hostForURL(ip), keyPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	resp.Body.Close()
}

// onlineOwnedPeers returns the reachable peers this node may talk to: online,
// addressable and sharing self's owner.
func onlineOwnedPeers(devs []device, self device) []device {
	var peers []device
	for _, p := range devs {
		if p.self || !p.online || p.ip == "" || p.owner != self.owner {
			continue
		}
		peers = append(peers, p)
	}
	return peers
}

// lacksTailscaleCLI reports whether a peer's OS ships no `tailscale` binary and so
// cannot enumerate the tailnet on its own. Android (Termux) is the only such
// platform, which is why the roster has to be pushed to it.
func lacksTailscaleCLI(peerOS string) bool { return peerOS == "android" }

// pushRoster hands each CLI-less peer this node's full tailnet view, so it can reach
// every device without a manually supplied seed — the map flows to the phone instead
// of the phone having to go find it. Only a CLI node's roster is authoritative, so
// this no-ops from a CLI-less node (its rosterJSON is just its own cache), and the
// roster (a `tailscale status` call) is built only when there is somewhere to send it.
func pushRoster(devs []device) int {
	if _, err := tailscaleBin(); err != nil {
		return 0
	}
	self, ok := selfDevice(devs)
	if !ok {
		return 0
	}
	var targets []string
	for _, p := range onlineOwnedPeers(devs, self) {
		if lacksTailscaleCLI(p.os) {
			targets = append(targets, p.ip)
		}
	}
	if len(targets) == 0 {
		return 0
	}
	body := rosterJSON()
	for _, ip := range targets {
		go postRoster(ip, body)
	}
	return len(targets)
}

// postRoster fires a best-effort roster push at a peer (3s budget).
func postRoster(ip, body string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	url := fmt.Sprintf("http://%s:%d/roster", hostForURL(ip), keyPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	resp.Body.Close()
}

// announceAll nudges every online same-owner peer to re-sync, so nodes already on
// the tailnet pick up THIS node's key right after it starts serving. A node joining
// the mesh doesn't change the netmap, so nothing else would trigger them.
func announceAll(devs []device) {
	self, ok := selfDevice(devs)
	if !ok {
		return
	}
	for _, p := range onlineOwnedPeers(devs, self) {
		go postResync(p.ip)
	}
}

// writeAuthorizedKeys renders the managed block into the platform's
// authorized_keys file, preserving user keys, and secures it — skipping the
// write entirely when the content is already identical.
func writeAuthorizedKeys(pl Platform, body string) error {
	path, err := pl.AuthorizedKeysPath()
	if err != nil {
		return err
	}
	existing, _ := os.ReadFile(path)
	out := withManagedBlock(existing, body)
	if sameContent(path, out) {
		return nil
	}
	if err := atomicWrite(path, out, 0o600); err != nil {
		return err
	}
	return pl.SecureKeyFile(path)
}

// sshConfigPaths are the files a generated Host entry points ssh at.
type sshConfigPaths struct {
	// identity is this node's tailssh private key, used with IdentitiesOnly.
	identity string
	// managedKnownHosts holds the peer host keys tailssh pre-populated (see
	// writeKnownHosts). It is read alongside userKnownHosts under accept-new, which
	// keeps a peer whose host key we couldn't fetch reachable via first-connect trust.
	managedKnownHosts string
	// userKnownHosts is the user's own file, where ssh records newly accepted hosts.
	userKnownHosts string
}

// peerUsesTailscaleSSH reports whether a peer should be reached over keyless
// Tailscale SSH instead of the tailssh key mesh. The mesh wins whenever the peer runs
// tailssh (we hold its key and its login user from /meta): it is self-contained and
// needs no tailnet ACL. Tailscale SSH is the fallback only for Linux/macOS peers not
// yet in the mesh — zero-install on them, at the cost of the ssh accept rule.
func peerUsesTailscaleSSH(peerOS string, inMesh bool) bool {
	return !inMesh && (peerOS == "linux" || peerOS == "macOS")
}

// sshConfigHostEntry renders one peer's "Host <name>" stanza. ok is false when the
// peer can't be reached at all: an empty DNSName (which would emit a malformed
// "Host " line), or a peer outside the mesh with no Tailscale SSH fallback
// (Windows/Android). Tailscale SSH authenticates by tailnet identity, so those
// entries carry no key, port or IdentityFile.
func sshConfigHostEntry(p device, keyed map[string]cachedPeer, paths sshConfigPaths) (string, bool) {
	if p.name == "" {
		return "", false
	}
	c, inMesh := keyed[p.name]
	useTailscaleSSH := peerUsesTailscaleSSH(p.os, inMesh)
	if !inMesh && !useTailscaleSSH {
		return "", false
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Host %s\n", p.name)
	fmt.Fprintf(&b, "    HostName %s\n", p.name)
	if inMesh && c.User != "" {
		fmt.Fprintf(&b, "    User %s\n", sshConfigUser(c.User))
	}
	if useTailscaleSSH {
		return b.String(), true
	}

	if port := sshPortFor(p.os, c.Port); port != 22 {
		fmt.Fprintf(&b, "    Port %d\n", port)
	}
	fmt.Fprintf(&b, "    IdentityFile \"%s\"\n", paths.identity)
	b.WriteString("    IdentitiesOnly yes\n")
	if paths.managedKnownHosts != "" {
		fmt.Fprintf(&b, "    UserKnownHostsFile \"%s\" \"%s\"\n", paths.userKnownHosts, paths.managedKnownHosts)
		b.WriteString("    StrictHostKeyChecking accept-new\n")
	}
	return b.String(), true
}

// sshConfigManagedBlock renders the blank-line-separated Host stanzas for every
// reachable peer.
func sshConfigManagedBlock(owned []device, keyed map[string]cachedPeer, paths sshConfigPaths) string {
	var entries []string
	for _, p := range owned {
		if entry, ok := sshConfigHostEntry(p, keyed, paths); ok {
			entries = append(entries, entry)
		}
	}
	return strings.Join(entries, "\n")
}

// writeSSHConfig generates the managed Host block for `ssh <name>`, choosing the
// transport per peer (see peerUsesTailscaleSSH). User comes from /meta, so
// `ssh <name>` needs no hand-entered username on any OS. A read failure that is not
// "absent" (a permission/ACL problem, say) aborts: treating it as an empty file would
// regenerate the config from the managed block alone and silently discard every Host
// entry the user wrote by hand.
//
// The write is secured exactly like authorized_keys (SecureKeyFile). Without it, an
// elevated daemon's atomicWrite hands the config the token's default DACL — SYSTEM
// plus Administrators, but not the user's own SID — so the config the daemon just
// wrote becomes unreadable to the very user whose ssh must parse it, silently
// breaking every `ssh <name>` until an elevated takeown repairs the ACL.
func writeSSHConfig(pl Platform, owned []device, keyed map[string]cachedPeer) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".ssh", "config")
	managedKH, _ := knownHostsPath()
	block := sshConfigManagedBlock(owned, keyed, sshConfigPaths{
		identity:          appKeyPath(),
		managedKnownHosts: managedKH,
		userKnownHosts:    filepath.Join(home, ".ssh", "known_hosts"),
	})

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w (refusing to rewrite it — user Host entries would be lost)", path, err)
	}
	out := withManagedBlock(existing, strings.TrimRight(block, "\n"))
	if sameContent(path, out) {
		return nil
	}
	if err := atomicWrite(path, out, 0o600); err != nil {
		return err
	}
	return pl.SecureKeyFile(path)
}

// withManagedBlock returns existing with its tailssh-managed region replaced by
// body. Non-managed lines are preserved in order; the fresh block is appended.
func withManagedBlock(existing []byte, body string) []byte {
	preserved := stripManagedBlock(string(existing))
	preserved = strings.TrimRight(preserved, "\n")

	var b strings.Builder
	if strings.TrimSpace(preserved) != "" {
		b.WriteString(preserved)
		b.WriteString("\n\n")
	}
	b.WriteString(managedBegin)
	b.WriteByte('\n')
	if body != "" {
		b.WriteString(body)
		if !strings.HasSuffix(body, "\n") {
			b.WriteByte('\n')
		}
	}
	b.WriteString(managedEnd)
	b.WriteByte('\n')
	return []byte(b.String())
}

// stripManagedBlock drops every line inside the marker pair (and the markers
// themselves), returning only the user-owned content.
func stripManagedBlock(content string) string {
	if content == "" {
		return ""
	}
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	inBlock := false
	for _, ln := range lines {
		switch strings.TrimSpace(ln) {
		case managedBegin:
			inBlock = true
			continue
		case managedEnd:
			inBlock = false
			continue
		}
		if !inBlock {
			out = append(out, ln)
		}
	}
	return strings.Join(out, "\n")
}

// validEd25519Line reports whether line is a well-formed "ssh-ed25519 <b64>"
// authorized_keys entry with a 32-byte key — validated with the stdlib alone. The
// decoded blob is SSH wire format: string(algorithm) followed by string(public key).
func validEd25519Line(line string) bool {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) < 2 || f[0] != "ssh-ed25519" {
		return false
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return false
	}
	algo, rest, ok := sshWireString(blob)
	if !ok || string(algo) != "ssh-ed25519" {
		return false
	}
	key, _, ok := sshWireString(rest)
	if !ok || len(key) != ed25519.PublicKeySize {
		return false
	}
	return true
}

// sshWireString reads one length-prefixed (uint32 big-endian) field.
func sshWireString(b []byte) (val, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b[:4])
	if uint32(len(b)-4) < n {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// hostForURL bracketizes IPv6 literals so they are safe in a URL authority.
func hostForURL(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}

// peersCachePath is UserConfigDir/tailssh/peers.json.
func peersCachePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tailssh", "peers.json"), nil
}

// loadPeers reads the offline-first key cache (best-effort; empty on any error).
func loadPeers() map[string]cachedPeer {
	m := make(map[string]cachedPeer)
	path, err := peersCachePath()
	if err != nil {
		return m
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	var list []cachedPeer
	if json.Unmarshal(b, &list) == nil {
		for _, c := range list {
			m[c.Name] = c
		}
	}
	return m
}

// savePeers writes the cache atomically at 0600, skipping unchanged content.
func savePeers(m map[string]cachedPeer) error {
	path, err := peersCachePath()
	if err != nil {
		return err
	}
	list := make([]cachedPeer, 0, len(m))
	for _, c := range m {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if sameContent(path, b) {
		return nil
	}
	return atomicWrite(path, b, 0o600)
}

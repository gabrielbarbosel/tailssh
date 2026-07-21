package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// deviceWire is the JSON shape a node serves at /roster (device's fields are
// unexported, so this is the serializable mirror).
type deviceWire struct {
	Name   string `json:"name"`
	Host   string `json:"host"`
	OS     string `json:"os"`
	IP     string `json:"ip"`
	Owner  string `json:"owner"`
	Online bool   `json:"online"`
	Port   int    `json:"port"`
}

func wireOf(d device) deviceWire {
	return deviceWire{Name: d.name, Host: d.host, OS: d.os, IP: d.ip, Owner: d.owner, Online: d.online, Port: d.sshPort}
}

func (w deviceWire) toDevice() device {
	return device{name: w.Name, host: w.Host, os: w.OS, ip: w.IP, owner: w.Owner, online: w.Online, sshPort: w.Port}
}

// rosterJSON serializes this node's tailnet view for the /roster endpoint. Only
// CLI nodes have an authoritative view; a CLI-less node serves what it knows.
func rosterJSON() string {
	devs, err := discoverCLI()
	if err != nil {
		devs, _ = discover()
	}
	wires := make([]deviceWire, 0, len(devs))
	for _, d := range devs {
		wires = append(wires, wireOf(d))
	}
	b, _ := json.Marshal(wires)
	return string(b)
}

// selfTailnetIP finds this device's own Tailscale IP (the 100.64.0.0/10 CGNAT
// range) without the CLI and — crucially — without enumerating interfaces, which
// Android 11+ forbids for apps (so the Termux interface scan comes back empty).
//
// Primary method: "connect" a UDP socket to the Tailscale DNS resolver
// (100.100.100.100). No packet is sent, but the kernel selects the source IP it
// would route from; with Tailscale up that is our tailnet IP, and with it down it
// is a non-tailnet address, which we reject. Interface scanning stays as a
// fallback for hosts where the route lookup doesn't yield a CGNAT source.
func selfTailnetIP() string {
	_, cgnat, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		return ""
	}
	if conn, err := net.Dial("udp", "100.100.100.100:53"); err == nil {
		ua, ok := conn.LocalAddr().(*net.UDPAddr)
		conn.Close()
		if ok {
			if ip := ua.IP.To4(); ip != nil && cgnat.Contains(ip) {
				return ip.String()
			}
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil && cgnat.Contains(ip4) {
			return ip4.String()
		}
	}
	return ""
}

// seedIPs are the peer IPs a CLI-less node can ask for the roster: the pushed
// roster cache and the persisted key cache, then $TAILSSH_SEED (comma-separated)
// as a last resort for a first run with no CLI peer online.
func seedIPs() []string {
	var ips []string
	seen := map[string]bool{}
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	for _, w := range loadRosterCache() {
		add(w.IP)
	}
	for _, c := range loadPeers() {
		add(c.IP)
	}
	for _, s := range strings.Split(os.Getenv("TAILSSH_SEED"), ",") {
		add(strings.TrimSpace(s))
	}
	return ips
}

// discoverCLIless is the discovery path for a node with no tailscale CLI — the
// Tailscale Android app never exposes the CLI or LocalAPI to Termux, so
// `tailscale status` is unavailable there. It prefers the roster a CLI peer has
// pushed to us (the complete, current map, so no seed is ever needed), and only
// falls back to pulling /roster from a seed if nothing has been pushed yet.
func discoverCLIless() ([]device, error) {
	if wires := loadRosterCache(); len(wires) > 0 {
		return devicesFromWires(wires), nil
	}
	return discoverViaRoster(seedIPs())
}

// discoverViaRoster builds the tailnet view from the first reachable seed's
// /roster, tagging self by matching this device's own tailnet IP.
func discoverViaRoster(seeds []string) ([]device, error) {
	if len(seeds) == 0 {
		return nil, fmt.Errorf("no tailscale CLI and no roster yet (start the daemon on a device that has the CLI)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	for _, seed := range seeds {
		body, err := getBounded(ctx, fmt.Sprintf("http://%s:%d/roster", hostForURL(seed), keyPort), 256<<10)
		if err != nil {
			continue
		}
		var wires []deviceWire
		if json.Unmarshal(body, &wires) != nil {
			continue
		}
		return devicesFromWires(wires), nil
	}
	return nil, fmt.Errorf("no reachable seed for /roster (tried %d)", len(seeds))
}

// devicesFromWires converts a wire roster into devices, tagging this node as self
// by matching its own tailnet IP and guaranteeing a self entry exists so the
// keyserver always has an IP to bind.
func devicesFromWires(wires []deviceWire) []device {
	selfIP := selfTailnetIP()
	devices := make([]device, 0, len(wires))
	haveSelf := false
	for _, w := range wires {
		d := w.toDevice()
		if selfIP != "" && d.ip == selfIP {
			d.self, d.online, haveSelf = true, true, true
		}
		devices = append(devices, d)
	}
	if !haveSelf && selfIP != "" {
		devices = append(devices, device{name: "self", ip: selfIP, os: "android", self: true, online: true, sshPort: 8022})
	}
	return devices
}

// rosterCachePath is where a CLI-less node stores the roster pushed to it by a
// CLI peer (UserConfigDir/tailssh/roster.json).
func rosterCachePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tailssh", "roster.json"), nil
}

// loadRosterCache reads the pushed roster (best-effort; nil on any error).
func loadRosterCache() []deviceWire {
	path, err := rosterCachePath()
	if err != nil {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var wires []deviceWire
	if json.Unmarshal(b, &wires) != nil {
		return nil
	}
	return wires
}

// saveRosterCache validates and persists a pushed roster, ignoring anything that
// isn't a well-formed []deviceWire so a peer can't write garbage to our cache. It
// reports whether the roster actually changed, so a CLI-less node can re-sync only
// when it did — steady no-op pushes then cost nothing on the receiver.
func saveRosterCache(raw []byte) (changed bool, err error) {
	var wires []deviceWire
	if err := json.Unmarshal(raw, &wires); err != nil {
		return false, err
	}
	b, err := json.MarshalIndent(wires, "", "  ")
	if err != nil {
		return false, err
	}
	b = append(b, '\n')
	path, err := rosterCachePath()
	if err != nil {
		return false, err
	}
	if sameContent(path, b) {
		return false, nil
	}
	if err := atomicWrite(path, b, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

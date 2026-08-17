package main

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestValidSSHUser(t *testing.T) {
	ok := []string{"ubuntu", "root", "u0_a123", "Jane Doe", "a.b-c_d", "ec2-user"}
	for _, s := range ok {
		if !validSSHUser(s) {
			t.Errorf("validSSHUser(%q) = false, want true", s)
		}
	}
	bad := []string{"", " ", " leading", "trailing ", "a\nb", "a\tb", "a\"b", `a\b`, "a\x00b", "a\x7fb"}
	for _, s := range bad {
		if validSSHUser(s) {
			t.Errorf("validSSHUser(%q) = true, want false", s)
		}
	}
}

func TestParseTailscaleInUseBy(t *testing.T) {
	locked := map[string]string{
		`failed to connect to local tailscaled (which appears to be running as tailscaled.exe, pid 5580). Got error: 401 Unauthorized: Tailscale already in use by POA-AVEL-521\Admin, pid 28496`: `POA-AVEL-521\Admin`,
		"tailscale status failed: exit status 1: Got error: 401 Unauthorized: Tailscale already in use by HOST\\user":                                                                             `HOST\user`,
	}
	for in, want := range locked {
		owner, ok := parseTailscaleInUseBy(in)
		if !ok || owner != want {
			t.Errorf("parseTailscaleInUseBy(%q) = (%q, %v), want (%q, true)", in, owner, ok, want)
		}
	}
	free := []string{
		"",
		"tailscale status failed: exit status 1",
		"Logged out.",
		"already in use by ", // marker with no owner
	}
	for _, in := range free {
		if owner, ok := parseTailscaleInUseBy(in); ok {
			t.Errorf("parseTailscaleInUseBy(%q) = (%q, true), want locked=false", in, owner)
		}
	}
}

func TestSSHConfigUser(t *testing.T) {
	cases := map[string]string{
		"ubuntu":    "ubuntu",
		"a.b-c_d":   "a.b-c_d",
		"Jane Doe":  `"Jane Doe"`,
		"has space": `"has space"`,
	}
	for in, want := range cases {
		if got := sshConfigUser(in); got != want {
			t.Errorf("sshConfigUser(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestManagedBlockRoundTrip(t *testing.T) {
	user := "Host keep\n    HostName 1.2.3.4\n"
	out := string(withManagedBlock([]byte(user), "Host peer\n    HostName peer"))
	t.Run("fresh block appends to preserved user content", func(t *testing.T) {
		if !strings.Contains(out, "Host keep") {
			t.Fatal("user content not preserved")
		}
		if !strings.Contains(out, managedBegin) || !strings.Contains(out, managedEnd) {
			t.Fatal("managed markers missing")
		}
	})
	out2 := string(withManagedBlock([]byte(out), "Host peer2\n    HostName peer2"))
	t.Run("re-applying rewrites only the managed region without duplicating user content", func(t *testing.T) {
		if strings.Count(out2, "Host keep") != 1 {
			t.Errorf("user content duplicated: %q", out2)
		}
		if strings.Contains(out2, "Host peer\n") {
			t.Error("old managed content leaked into the rewrite")
		}
		if strings.TrimSpace(stripManagedBlock(out2)) != strings.TrimSpace(user) {
			t.Errorf("stripManagedBlock did not recover user content: %q", stripManagedBlock(out2))
		}
	})
}

func TestHostPattern(t *testing.T) {
	cases := []struct {
		name, ip string
		port     int
		want     string
	}{
		{"host1", "100.64.0.10", 22, "host1,100.64.0.10"},
		{"phone", "100.64.0.20", 8022, "[phone]:8022,[100.64.0.20]:8022"},
		{"h", "", 22, "h"},
		{"", "1.2.3.4", 2222, "[1.2.3.4]:2222"},
	}
	for _, c := range cases {
		if got := hostPattern(c.name, c.ip, c.port); got != c.want {
			t.Errorf("hostPattern(%q,%q,%d) = %q, want %q", c.name, c.ip, c.port, got, c.want)
		}
	}
}

func TestEnsureSSHRule(t *testing.T) {
	t.Run("existing accept rule is left untouched", func(t *testing.T) {
		with := `{"ssh": [{"action": "accept", "src": ["autogroup:member"]}]}`
		if _, changed := ensureSSHRule(with); changed {
			t.Error("ensureSSHRule modified a policy that already had an accept rule")
		}
	})
	t.Run("policy missing a rule gains exactly one, preserving existing content", func(t *testing.T) {
		without := "{\n\t// keep this comment\n\t\"acls\": [{\"action\": \"accept\"}],\n\t\"ssh\": [],\n}"
		got, changed := ensureSSHRule(without)
		if !changed {
			t.Fatal("ensureSSHRule did not add a rule to a policy missing one")
		}
		if !strings.Contains(got, "keep this comment") || !strings.Contains(got, `"acls"`) {
			t.Error("ensureSSHRule dropped existing policy content")
		}
		if !sshHasAccept(got) {
			t.Error("ensureSSHRule output has no accept rule")
		}
	})
}

func TestValidateSelfOwner(t *testing.T) {
	self := &node{StableID: "nSelf", DNSName: "pc.example.ts.net.", UserID: 7}
	t.Run("resolvable owner passes", func(t *testing.T) {
		st := status{Self: self, User: map[string]userProfile{"7": {LoginName: "me@example.com"}}}
		if err := validateSelfOwner(st); err != nil {
			t.Errorf("validateSelfOwner rejected a complete status: %v", err)
		}
	})
	t.Run("status with no user profiles is refused", func(t *testing.T) {
		if err := validateSelfOwner(status{Self: self}); err == nil {
			t.Error("validateSelfOwner accepted a status whose User map cannot resolve the local owner")
		}
	})
	t.Run("profiles present but none matching self is refused", func(t *testing.T) {
		st := status{Self: self, User: map[string]userProfile{"9": {LoginName: "other@example.com"}}}
		if err := validateSelfOwner(st); err == nil {
			t.Error("validateSelfOwner accepted a status with no profile for the local UserID")
		}
	})
	t.Run("missing self node is refused", func(t *testing.T) {
		if err := validateSelfOwner(status{User: map[string]userProfile{"7": {LoginName: "me@example.com"}}}); err == nil {
			t.Error("validateSelfOwner accepted a status with no self node")
		}
	})
}

// closerFunc adapts a func into an io.Closer for supervisor tests.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func TestKeyserverSupervisorEnsure(t *testing.T) {
	ip := "100.64.0.1"
	resolveErr := error(nil)
	openErr := error(nil)
	opens, closes := 0, 0
	s := &keyserverSupervisor{
		resolve: func() (string, error) { return ip, resolveErr },
		open: func(string) (io.Closer, error) {
			if openErr != nil {
				return nil, openErr
			}
			opens++
			return closerFunc(func() error { closes++; return nil }), nil
		},
	}

	t.Run("first ensure binds once", func(t *testing.T) {
		s.ensure()
		if opens != 1 || s.bound != ip {
			t.Fatalf("opens=%d bound=%q, want one bind on %q", opens, s.bound, ip)
		}
	})
	t.Run("same IP is a no-op", func(t *testing.T) {
		s.ensure()
		if opens != 1 || closes != 0 {
			t.Errorf("opens=%d closes=%d after unchanged IP, want 1/0", opens, closes)
		}
	})
	t.Run("changed IP closes the old listener and rebinds", func(t *testing.T) {
		ip = "100.64.0.2"
		s.ensure()
		if opens != 2 || closes != 1 || s.bound != ip {
			t.Errorf("opens=%d closes=%d bound=%q, want rebind on %q", opens, closes, s.bound, ip)
		}
	})
	t.Run("resolve failure keeps the current listener", func(t *testing.T) {
		resolveErr = fmt.Errorf("tailscale down")
		s.ensure()
		if opens != 2 || closes != 1 {
			t.Errorf("opens=%d closes=%d after resolve failure, want listener untouched", opens, closes)
		}
		resolveErr = nil
	})
	t.Run("failed rebind is retried by the next ensure", func(t *testing.T) {
		ip, openErr = "100.64.0.3", fmt.Errorf("bind refused")
		s.ensure()
		if closes != 2 || s.ks != nil {
			t.Fatalf("closes=%d ks=%v: old listener must be gone even when the rebind fails", closes, s.ks)
		}
		openErr = nil
		s.ensure()
		if opens != 3 || s.bound != ip {
			t.Errorf("opens=%d bound=%q, want recovery bind on %q", opens, s.bound, ip)
		}
	})
}

func TestSyncTrustedPeers(t *testing.T) {
	self := device{name: "pc", ip: "100.0.0.1", owner: "me@example.com", self: true}
	peers := []device{
		self,
		{name: "vm", ip: "100.0.0.2", owner: "me@example.com"},
		{name: "theirs", ip: "100.0.0.3", owner: "other@example.com"},
		{name: "noaddr", owner: "me@example.com"},
	}
	t.Run("keeps same-owner addressable peers only", func(t *testing.T) {
		owned, err := syncTrustedPeers(peers, self)
		if err != nil {
			t.Fatalf("syncTrustedPeers failed on a valid tailnet: %v", err)
		}
		if len(owned) != 1 || owned[0].name != "vm" {
			t.Errorf("syncTrustedPeers = %v, want just vm", owned)
		}
	})
	t.Run("unknown local owner is an error, not an empty prune set", func(t *testing.T) {
		owned, err := syncTrustedPeers(peers, device{name: "pc", ip: "100.0.0.1", self: true})
		if err == nil {
			t.Fatalf("syncTrustedPeers accepted an owner-less local node, returning %v — a pass would prune every peer", owned)
		}
		if owned != nil {
			t.Errorf("syncTrustedPeers returned peers alongside an error: %v", owned)
		}
	})
}

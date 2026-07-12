package main

import (
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
	// A fresh block appends to preserved user content.
	out := string(withManagedBlock([]byte(user), "Host peer\n    HostName peer"))
	if !strings.Contains(out, "Host keep") {
		t.Fatal("user content not preserved")
	}
	if !strings.Contains(out, managedBegin) || !strings.Contains(out, managedEnd) {
		t.Fatal("managed markers missing")
	}
	// Re-applying replaces only the managed region, never duplicating user content.
	out2 := string(withManagedBlock([]byte(out), "Host peer2\n    HostName peer2"))
	if strings.Count(out2, "Host keep") != 1 {
		t.Errorf("user content duplicated: %q", out2)
	}
	if strings.Contains(out2, "Host peer\n") {
		t.Error("old managed content leaked into the rewrite")
	}
	if strings.TrimSpace(stripManagedBlock(out2)) != strings.TrimSpace(user) {
		t.Errorf("stripManagedBlock did not recover user content: %q", stripManagedBlock(out2))
	}
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
	// An existing accept rule is left untouched.
	with := `{"ssh": [{"action": "accept", "src": ["autogroup:member"]}]}`
	if _, changed := ensureSSHRule(with); changed {
		t.Error("ensureSSHRule modified a policy that already had an accept rule")
	}
	// A policy without one gains exactly the rule, preserving existing content.
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
}

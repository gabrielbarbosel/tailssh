package main

// acl.go — automate the one tailnet-level prerequisite of the hybrid: the
// `ssh accept` rule that lets Tailscale SSH authenticate without the periodic
// browser "check". Editing the tailnet policy requires ADMIN authorization
// (Tailscale forbids a node from rewriting the policy on its own), so it needs a
// Tailscale API token in $TS_API_KEY — created once, for the whole tailnet.
//
// The policy is edited as HuJSON TEXT: only the ssh accept rule is inserted, and
// every existing rule, comment and bit of formatting is preserved untouched.
//
//   tailssh acl            # report whether the ssh accept rule exists
//   tailssh acl --apply    # insert it (preserving everything else)
//
// `up` also applies it opportunistically when $TS_API_KEY is set, so setting the
// token once on the first install self-configures the whole tailnet.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const aclURL = "https://api.tailscale.com/api/v2/tailnet/-/acl"

// sshArrayBounds returns the byte offsets of the top-level "ssh" array's opening
// '[' and closing ']' via bracket matching.
func sshArrayBounds(s string) (open, close int, ok bool) {
	k := strings.Index(s, `"ssh"`)
	if k < 0 {
		return 0, 0, false
	}
	rel := strings.IndexByte(s[k:], '[')
	if rel < 0 {
		return 0, 0, false
	}
	open = k + rel
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return open, i, true
			}
		}
	}
	return 0, 0, false
}

// sshHasAccept reports whether the ssh array already contains an accept rule.
func sshHasAccept(s string) bool {
	o, c, ok := sshArrayBounds(s)
	return ok && strings.Contains(s[o:c], `"accept"`)
}

// ensureSSHRule inserts a same-owner ssh accept rule if none exists, editing the
// HuJSON text in place so all existing content is preserved. Returns the possibly
// modified policy and whether it changed.
func ensureSSHRule(s string) (string, bool) {
	if sshHasAccept(s) {
		return s, false
	}
	const rule = `{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot", "root"]}`
	if o, _, ok := sshArrayBounds(s); ok {
		pos := o + 1
		return s[:pos] + "\n\t\t" + rule + "," + s[pos:], true
	}
	if ob := strings.IndexByte(s, '{'); ob >= 0 {
		pos := ob + 1
		return s[:pos] + "\n\t\"ssh\": [\n\t\t" + rule + ",\n\t]," + s[pos:], true
	}
	return s, false
}

// runACL ensures the `ssh accept` rule exists with progress reporting; it is the
// CLI entry point (`up` calls applyACL directly with quiet set).
func runACL(apply bool) error { return applyACL(apply, false) }

// applyACL ensures the tailnet policy contains an `ssh accept` rule, editing the
// HuJSON in place. apply performs the write; without it the missing/present state
// is only reported. quiet suppresses that report chatter for the opportunistic
// call from `up`, including the case where TS_API_KEY is absent.
func applyACL(apply, quiet bool) error {
	token := os.Getenv("TS_API_KEY")
	if token == "" {
		if quiet {
			return nil
		}
		return fmt.Errorf("set TS_API_KEY to a Tailscale API access token (login.tailscale.com › Settings › Keys)")
	}
	client := &http.Client{Timeout: 20 * time.Second}

	policy, etag, err := aclFetchPolicy(client, token)
	if err != nil {
		return err
	}

	updated, changed := ensureSSHRule(policy)
	if !changed {
		if !quiet {
			fmt.Println("acl: an `ssh accept` rule is already present — Tailscale SSH is seamless.")
		}
		return nil
	}
	if !apply {
		fmt.Println("acl: no `ssh accept` rule found (Tailscale SSH will prompt a browser check).")
		fmt.Println("     run `tailssh acl --apply` to add it (existing policy is preserved).")
		return nil
	}

	if err := aclPostPolicy(client, token, updated, etag); err != nil {
		return err
	}
	fmt.Println("acl: `ssh accept` rule added (rest of the policy preserved) — Tailscale SSH seamless in all directions.")
	return nil
}

// aclFetchPolicy GETs the tailnet policy as HuJSON — the Accept header keeps
// comments and formatting intact so the rule can be inserted surgically. It also
// returns the ETag, which the write path replays as If-Match.
func aclFetchPolicy(client *http.Client, token string) (policy, etag string, err error) {
	req, _ := http.NewRequest(http.MethodGet, aclURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/hujson")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	etag = resp.Header.Get("ETag")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("acl GET failed (%d): %s", resp.StatusCode, string(body))
	}
	return string(body), etag, nil
}

// aclPostPolicy writes the edited policy back. The ETag is sent as If-Match for
// optimistic concurrency, so a policy changed by someone else in the meantime is
// rejected rather than clobbered.
func aclPostPolicy(client *http.Client, token, policy, etag string) error {
	req, _ := http.NewRequest(http.MethodPost, aclURL, bytes.NewReader([]byte(policy)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/hujson")
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("acl POST failed (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

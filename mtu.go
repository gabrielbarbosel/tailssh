package main

// tailnetSafeMTU is the Tailscale interface MTU tailssh clamps every node it can to.
//
// Some direct paths — notably to a phone on a mobile carrier — silently drop inner
// packets larger than roughly 1200 bytes: the carrier breaks Path MTU Discovery, so
// neither end is told to shrink and the oversized WireGuard packet just vanishes
// (a blackhole, not a rejection). Tailscale's default 1280 sits above that ceiling,
// so anything that emits a full-size packet stalls with no error: the SSH handshake
// (its post-quantum sntrup761 KEX reply is ~1.1 KB) hangs at KEX_ECDH_REPLY, and
// even once past it any large session burst — a file dump, a TUI redraw — freezes,
// while tiny packets (a keystroke, `whoami`) sail through and mask the cause.
//
// 1120 keeps the largest inner packet under the carrier ceiling with headroom.
// Lowering one end clamps TCP in both directions (the outgoing link MTU caps the
// segments this node sends, and the smaller advertised MSS caps what peers send
// back), so clamping the desktops and servers is enough — the phone's app-managed
// tun, which tailssh cannot set, never has to change.
//
// This is a property of the tailnet path, not of any app riding over it, which is
// why tailssh owns it here rather than any per-tool wrapper: the same blackhole
// would break scp, git, or VS Code Remote to the phone identically.
const tailnetSafeMTU = 1120

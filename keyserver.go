package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// nodeMeta is the small self-description a node serves at /meta so peers can
// generate a correct ssh_config entry (right remote user, right port) without
// the operator ever typing a username.
type nodeMeta struct {
	User string `json:"user"`
	OS   string `json:"os"`
	Port int    `json:"port"`
}

// keyserver is the running HTTP endpoint a node exposes on its tailnet IP so peers
// can fetch its keys and metadata and nudge it to re-sync.
type keyserver struct {
	srv *http.Server
}

// keyserverRosterMaxBytes caps a pushed /roster body so a peer cannot stream an
// unbounded map into memory.
const keyserverRosterMaxBytes = 256 << 10

// startKeyserver binds an HTTP server to listenIP:keyPort ONLY (the node's tailnet
// IP) and serves the local public key and node metadata. The payload is non-secret
// and travels over WireGuard, so it is served in the clear (no TLS). It refuses to
// start without an explicit listen IP — never 0.0.0.0/::/localhost — since tailnet
// membership is the authorization boundary. onResync is invoked (in a goroutine)
// when a peer POSTs /resync, letting bus-less peers (Android) nudge us to re-sync.
func startKeyserver(listenIP, pubLine, metaJSON, hostKey string, roster func() string, onResync func(), onRoster func([]byte)) (io.Closer, error) {
	if listenIP == "" {
		return nil, fmt.Errorf("keyserver: refusing to start without a tailnet listen IP")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/pubkey", keyserverAllowOnly(http.MethodGet, keyserverServePubkey(pubLine)))
	mux.HandleFunc("/hostkey", keyserverAllowOnly(http.MethodGet, keyserverServeHostKey(hostKey)))
	mux.HandleFunc("/meta", keyserverAllowOnly(http.MethodGet, keyserverServeMeta(metaJSON)))
	mux.HandleFunc("/roster", keyserverServeRoster(roster, onRoster))
	mux.HandleFunc("/resync", keyserverAllowOnly(http.MethodPost, keyserverServeResync(onResync)))

	addr := net.JoinHostPort(listenIP, fmt.Sprint(keyPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("keyserver: listen %s: %w", addr, err)
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	go keyserverServe(srv, ln)

	return &keyserver{srv: srv}, nil
}

// keyserverAllowOnly wraps h so it answers only `method`; any other verb gets a 405
// with the matching Allow header, keeping each route free of that boilerplate.
func keyserverAllowOnly(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

// keyserverServePubkey serves the node's local ed25519 authorized-key line.
func keyserverServePubkey(pubLine string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, pubLine+"\n")
	}
}

// keyserverServeHostKey serves this node's sshd ed25519 host public key so peers
// can pre-populate known_hosts and skip the first-connect TOFU prompt. Empty when
// the host key can't be read, in which case peers fall back to accept-new.
func keyserverServeHostKey(hostKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, hostKey+"\n")
	}
}

// keyserverServeMeta serves this node's {user, os, port} so peers build a correct
// ssh_config Host entry.
func keyserverServeMeta(metaJSON string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		io.WriteString(w, metaJSON)
	}
}

// keyserverServeRoster answers /roster: GET serves this node's tailnet view (JSON)
// so a CLI-less peer can pull it; POST accepts a peer's pushed full map, which is
// how a CLI-less node (Android) learns every peer with no seed and no CLI. The push
// is handled out of band so the peer's request never blocks on it.
func keyserverServeRoster(roster func() string, onRoster func([]byte)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			if roster != nil {
				io.WriteString(w, roster())
			} else {
				io.WriteString(w, "[]")
			}
		case http.MethodPost:
			body, _ := io.ReadAll(io.LimitReader(r.Body, keyserverRosterMaxBytes))
			w.WriteHeader(http.StatusAccepted)
			if onRoster != nil {
				go onRoster(body)
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// keyserverServeResync accepts a peer's /resync nudge, replies immediately, and
// runs the resync out of band so a slow sync never holds the peer's request open.
func keyserverServeResync(onResync func()) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		if onResync != nil {
			go onResync()
		}
	}
}

// keyserverServe runs srv on ln in the background; the http.ErrServerClosed that
// Serve returns when Close shuts the server down is expected and discarded.
func keyserverServe(srv *http.Server, ln net.Listener) {
	_ = srv.Serve(ln)
}

func (k *keyserver) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return k.srv.Shutdown(ctx)
}

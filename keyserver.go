package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// The keyserver binds the single tailnet port 8021 on which every node serves
// its public key (and receives /resync nudges). Non-secret payload over
// WireGuard, so no TLS. The literal is inlined (not a shared const) to avoid
// colliding with the same value used by keysync.go/daemon.go.

// nodeMeta is the small self-description a node serves at /meta so peers can
// generate a correct ssh_config entry (right remote user, right port) without
// the operator ever typing a username.
type nodeMeta struct {
	User string `json:"user"`
	OS   string `json:"os"`
	Port int    `json:"port"`
}

type keyserver struct {
	srv *http.Server
}

// startKeyserver binds an HTTP server to listenIP:8021 ONLY (the node's tailnet
// IP) and serves the local public key. It refuses to start without an explicit
// listen IP — never 0.0.0.0/::/localhost — since tailnet membership is the
// authorization boundary. onResync is invoked (in a goroutine) when a peer POSTs
// /resync, letting bus-less peers (Android) nudge us to re-sync.
func startKeyserver(listenIP, pubLine, metaJSON, hostKey string, roster func() string, onResync func(), onRoster func([]byte)) (io.Closer, error) {
	if listenIP == "" {
		return nil, fmt.Errorf("keyserver: refusing to start without a tailnet listen IP")
	}

	mux := http.NewServeMux()

	// GET /pubkey -> the local ed25519 authorized-key line.
	mux.HandleFunc("/pubkey", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, pubLine+"\n")
	})

	// GET /hostkey -> this node's sshd ed25519 host public key, so peers can
	// pre-populate known_hosts and skip the first-connect TOFU prompt (empty when
	// the host key can't be read, in which case peers fall back to accept-new).
	mux.HandleFunc("/hostkey", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, hostKey+"\n")
	})

	// GET /meta -> this node's {user, os, port} so peers build a correct
	// ssh_config Host entry.
	mux.HandleFunc("/meta", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		io.WriteString(w, metaJSON)
	})

	// /roster — GET serves this node's tailnet view (JSON) so a CLI-less peer can
	// pull it; POST lets a CLI peer PUSH us the full map, which is how a CLI-less
	// node (Android) learns every peer with no seed and no CLI.
	mux.HandleFunc("/roster", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			if roster != nil {
				io.WriteString(w, roster())
			} else {
				io.WriteString(w, "[]")
			}
		case http.MethodPost:
			body, _ := io.ReadAll(io.LimitReader(r.Body, 256<<10))
			w.WriteHeader(http.StatusAccepted)
			if onRoster != nil {
				go onRoster(body)
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// POST /resync -> accept immediately and run the resync out of band, so a
	// slow sync never holds the peer's request open.
	mux.HandleFunc("/resync", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		if onResync != nil {
			go onResync()
		}
	})

	addr := net.JoinHostPort(listenIP, "8021")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("keyserver: listen %s: %w", addr, err)
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	go srv.Serve(ln) // returns http.ErrServerClosed on Close; ignored

	return &keyserver{srv: srv}, nil
}

func (k *keyserver) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return k.srv.Shutdown(ctx)
}

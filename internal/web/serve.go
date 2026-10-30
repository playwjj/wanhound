// Package web implements `wanhound serve`: the same audit engine
// behind a password-gated web UI.
//
// P0 scope: a safe skeleton — health check, basic-auth gate, and a
// placeholder page. The scan form, live progress and report views
// land in P1. The access-control rules below are load-bearing and
// must not be relaxed by the P1 work: a web-reachable scanner is a
// jump host for whoever can open the page, and the abuse lands on
// the operator's IP.
package web

import (
	"crypto/subtle"
	_ "embed"
	"fmt"
	"net"
	"net/http"
	"time"
)

//go:embed index.html
var indexHTML []byte

// Options controls the server.
type Options struct {
	Addr     string // listen address, e.g. "127.0.0.1:8687"
	Password string // required; there is no unauthenticated mode
}

// Serve starts the HTTP server and blocks.
// It refuses to bind a non-loopback address without a password.
func Serve(opts Options) error {
	if opts.Password == "" {
		return fmt.Errorf("serve requires a password: an unauthenticated scanner UI must never be reachable")
	}
	host, _, err := net.SplitHostPort(opts.Addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", opts.Addr, err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		// Non-loopback bind: password gate is the only thing between
		// the internet and a scanner running on the operator's IP.
		// Allowed, but the startup log makes the exposure explicit.
		fmt.Printf("warning: binding %s — the UI is reachable beyond this machine; the password is the only gate.\n", opts.Addr)
		fmt.Println("         Prefer binding a Tailscale/LAN address, or front it with a reverse proxy.")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})

	srv := &http.Server{
		Addr:              opts.Addr,
		Handler:           basicAuth(opts.Password, mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Printf("WanHound web UI (P0 skeleton) listening on %s\n", opts.Addr)
	return srv.ListenAndServe()
}

func basicAuth(password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "wanhound" ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="wanhound"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// TODO(P1): login rate limiting, session cookie instead of
		// per-request basic auth, scan-task mutex + cancel, audit log.
		next.ServeHTTP(w, r)
	})
}

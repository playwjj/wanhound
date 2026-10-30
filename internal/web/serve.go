// Package web implements `wanhound serve`: the same audit engine
// behind a password-gated web UI.
//
// The access-control rules here are load-bearing: a web-reachable
// scanner is a jump host for whoever can open the page, and the abuse
// lands on the operator's IP. So:
//
//   - there is no unauthenticated mode: serve refuses to start without
//     a password (stored only as a PBKDF2 hash);
//   - failed logins are throttled per client and globally;
//   - every audit is recorded in an append-only audit log with the
//     target, the client address and the time, and must be submitted
//     with an explicit "I own / am authorized to test this" assertion;
//   - one audit at a time, a global hourly cap, and engine rate limits
//     the browser cannot raise.
package web

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/playwjj/wanhound/internal/audit"
	"github.com/playwjj/wanhound/internal/i18n"
	"github.com/playwjj/wanhound/internal/knowledge"
	"github.com/playwjj/wanhound/internal/report"
	"github.com/playwjj/wanhound/internal/scan"
	"github.com/playwjj/wanhound/internal/store"
)

//go:embed static
var staticFS embed.FS

// maxLogSize is when audit.log rotates to audit.log.1.
const maxLogSize = 5 << 20

// Options controls the server.
type Options struct {
	Addr         string // listen address, e.g. "127.0.0.1:8687"
	Password     string // plaintext (hashed at startup) …
	PasswordHash string // … or a hash from `wanhound hash-password`
	DataDir      string
	ScansPerHour int  // global cap; <=0 means 6
	Lab          bool // allow loopback/private targets (test bench)
	Version      string
}

// Server is the HTTP handler plus its state.
type Server struct {
	opts     Options
	hash     *passwordHash
	st       *store.Store
	sessions *sessions
	limiter  *limiter
	tasks    *tasks
	logMu    sync.Mutex
	logPath  string
}

// New validates options and builds the server.
func New(opts Options) (*Server, error) {
	if opts.Password == "" && opts.PasswordHash == "" {
		return nil, fmt.Errorf("serve requires a password (WANHOUND_PASSWORD or WANHOUND_PASSWORD_HASH): an unauthenticated scanner UI must never be reachable")
	}
	var h *passwordHash
	var err error
	if opts.PasswordHash != "" {
		if h, err = parseHash(opts.PasswordHash); err != nil {
			return nil, err
		}
	} else {
		if len(opts.Password) < 10 {
			return nil, fmt.Errorf("the web password must be at least 10 characters")
		}
		h, _ = parseHash(HashPassword(opts.Password))
		opts.Password = ""
	}
	if opts.ScansPerHour <= 0 {
		opts.ScansPerHour = 6
	}
	st, err := store.Open(opts.DataDir)
	if err != nil {
		return nil, err
	}
	return &Server{opts: opts, hash: h, st: st, sessions: newSessions(), limiter: newLimiter(),
		tasks: &tasks{}, logPath: filepath.Join(st.Dir(), "audit.log")}, nil
}

// Serve starts the HTTP server and blocks.
func Serve(opts Options) error {
	s, err := New(opts)
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(opts.Addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", opts.Addr, err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		fmt.Printf("warning: binding %s — the UI is reachable beyond this machine; the password is the only gate.\n", opts.Addr)
		fmt.Println("         Prefer a Tailscale/LAN address, and put TLS (a reverse proxy) in front of anything public.")
	}
	srv := &http.Server{
		Addr:              opts.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	fmt.Printf("WanHound %s web UI listening on http://%s (audit log: %s)\n", opts.Version, opts.Addr, s.logPath)
	return srv.ListenAndServe()
}

// Handler returns the full HTTP handler (exported for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	files := http.FileServer(http.FS(static))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	// The app shell carries no data; everything else needs a session.
	mux.Handle("GET /", files)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /api/session", s.handleSession)
	mux.Handle("POST /api/logout", s.auth(http.HandlerFunc(s.handleLogout)))
	mux.Handle("POST /api/scan", s.auth(http.HandlerFunc(s.handleScan)))
	mux.Handle("GET /api/task", s.auth(http.HandlerFunc(s.handleTask)))
	mux.Handle("POST /api/task/cancel", s.auth(http.HandlerFunc(s.handleCancel)))
	mux.Handle("GET /api/labels", s.auth(http.HandlerFunc(s.handleLabels)))
	mux.Handle("GET /api/history", s.auth(http.HandlerFunc(s.handleHistory)))
	mux.Handle("GET /api/snapshot", s.auth(http.HandlerFunc(s.handleSnapshot)))
	mux.Handle("GET /api/snapshot/html", s.auth(http.HandlerFunc(s.handleSnapshotHTML)))
	mux.Handle("GET /api/diff", s.auth(http.HandlerFunc(s.handleDiff)))
	mux.Handle("GET /api/audit-log", s.auth(http.HandlerFunc(s.handleAuditLog)))
	mux.Handle("POST /api/lanhound/preview", s.auth(http.HandlerFunc(s.handleLanHoundPreview)))
	mux.Handle("POST /api/lanhound/scan", s.auth(http.HandlerFunc(s.handleLanHoundScan)))
	mux.Handle("POST /api/snapshot/delete", s.auth(http.HandlerFunc(s.handleDeleteSnapshot)))
	mux.Handle("POST /api/label/delete", s.auth(http.HandlerFunc(s.handleDeleteLabel)))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// auth requires a valid session; state-changing requests must also
// carry the X-WanHound header, which a cross-site form cannot send.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || !s.sessions.valid(c.Value) {
			writeErr(w, http.StatusUnauthorized, "login required")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-WanHound") != "1" {
			writeErr(w, http.StatusForbidden, "missing X-WanHound header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error { return readJSONLimit(r, v, 64*1024) }

func readJSONLimit(r *http.Request, v any, limit int64) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("expected application/json")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, limit))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if blocked, wait := s.limiter.blocked(ip); blocked {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed logins; try again in %s", wait.Round(time.Second)))
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.hash.verify(body.Password) {
		s.limiter.fail(ip)
		s.audit(r, map[string]any{"action": "login_failed"})
		time.Sleep(failureDelay)
		writeErr(w, http.StatusUnauthorized, "wrong password")
		return
	}
	s.limiter.success(ip)
	s.audit(r, map[string]any{"action": "login"})
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: s.sessions.create(), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		MaxAge: int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	authed := err == nil && s.sessions.valid(c.Value)
	out := map[string]any{"authenticated": authed}
	if authed {
		out["version"] = s.opts.Version
		out["rules_version"] = knowledge.Version()
		out["lab"] = s.opts.Lab
		out["scans_per_hour"] = s.opts.ScansPerHour
		out["quick_ports"] = len(scan.QuickPorts)
		out["udp_ports"] = scan.UDPPorts()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.revoke(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type scanBody struct {
	IPv4         string `json:"ipv4"`
	IPv6         string `json:"ipv6"`
	Label        string `json:"label"`
	PortSet      string `json:"port_set"`
	Ports        string `json:"ports"`
	UDP          bool   `json:"udp"`
	Offline      bool   `json:"offline"`
	AcceptInside bool   `json:"accept_inside"`
	Authorized   bool   `json:"authorized"`
	Lang         string `json:"lang"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var b scanBody
	if err := readJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !b.Authorized {
		writeErr(w, http.StatusBadRequest, "confirm that you own the target addresses or are authorized to test them")
		return
	}
	req := audit.Request{
		IPv4: strings.TrimSpace(b.IPv4), IPv6: strings.TrimSpace(b.IPv6), Label: strings.TrimSpace(b.Label),
		PortSet: b.PortSet, UDP: b.UDP, Offline: b.Offline, AcceptInside: b.AcceptInside, Lab: s.opts.Lab, Lang: i18n.Normalize(b.Lang),
		// Engine limits are fixed server-side; the browser cannot raise them.
		Concurrency: scan.DefaultConcurrency, Rate: scan.DefaultRate,
	}
	if req.PortSet == "custom" {
		ports, err := scan.ParsePorts(b.Ports)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Ports = ports
	}
	if err := req.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	entry := map[string]any{"action": "scan_start", "label": req.Label, "ipv4": req.IPv4, "ipv6": req.IPv6,
		"port_set": req.PortSet, "udp": req.UDP, "offline": req.Offline, "accept_inside": req.AcceptInside, "authorized": true}
	s.launch(w, r, req.Label, []audit.Request{req}, nil, entry)
}

// launch starts a task and writes the response; entry is the audit-log
// record of the request.
func (s *Server) launch(w http.ResponseWriter, r *http.Request, label string, reqs []audit.Request, devices []string, entry map[string]any) {
	task, err := s.tasks.start(s.st, label, reqs, devices, s.opts.ScansPerHour, func(t *Task) {
		e := map[string]any{"action": "scan_" + t.State, "task": t.ID, "label": t.Label, "targets": t.Targets}
		code := 0
		for _, rep := range t.Reports {
			if rep.ExitCode > code {
				code = rep.ExitCode
			}
		}
		if len(t.Reports) > 0 {
			e["exit_code"] = code
		}
		if t.Error != "" {
			e["error"] = t.Error
		}
		s.auditEntry(e)
	})
	if err != nil {
		var se *startError
		if errors.As(err, &se) {
			entry["action"] = "scan_rejected"
			entry["reason"] = se.msg
			s.audit(r, entry)
			writeErr(w, se.status, se.msg)
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	entry["task"] = task.ID
	s.audit(r, entry)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": task.ID})
}

func (s *Server) handleTask(w http.ResponseWriter, r *http.Request) {
	t := s.tasks.snapshot()
	if t != nil {
		lang := langOf(r)
		for i, orig := range t.Reports {
			rep := *orig
			rep.Targets = nil
			for _, snap := range orig.Targets {
				rep.Targets = append(rep.Targets, snap.Localized(lang))
			}
			rep.Errors = nil
			for _, e := range orig.Errors {
				e.Reason = e.Reason.Localized(lang)
				rep.Errors = append(rep.Errors, e)
			}
			t.Reports[i] = &rep
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"task": t})
}

// langOf reads the ?lang= parameter (default English).
func langOf(r *http.Request) string { return i18n.Normalize(r.URL.Query().Get("lang")) }

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	if !s.tasks.cancelCurrent() {
		writeErr(w, http.StatusConflict, "no audit is running")
		return
	}
	s.audit(r, map[string]any{"action": "scan_cancel_requested"})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLabels(w http.ResponseWriter, r *http.Request) {
	labels, err := s.st.Labels()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type entry struct {
		Label string      `json:"label"`
		Count int         `json:"count"`
		Last  *store.Meta `json:"last,omitempty"`
	}
	out := []entry{}
	for _, l := range labels {
		snaps, err := s.st.List(l)
		if err != nil {
			continue
		}
		e := entry{Label: l, Count: len(snaps)}
		if len(snaps) > 0 {
			m := store.MetaOf(snaps[len(snaps)-1])
			e.Last = &m
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Last == nil || out[j].Last == nil {
			return out[i].Label < out[j].Label
		}
		return out[i].Last.Time.After(out[j].Last.Time)
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	snaps, err := s.st.List(r.URL.Query().Get("label"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := []store.Meta{}
	for i := len(snaps) - 1; i >= 0; i-- {
		out = append(out, store.MetaOf(snaps[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) loadSnapshot(w http.ResponseWriter, r *http.Request, idParam string) *store.Snapshot {
	snap, err := s.st.Get(r.URL.Query().Get("label"), r.URL.Query().Get(idParam))
	if err != nil {
		writeErr(w, http.StatusNotFound, "snapshot not found")
		return nil
	}
	return snap
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if snap := s.loadSnapshot(w, r, "id"); snap != nil {
		writeJSON(w, http.StatusOK, snap.Localized(langOf(r)))
	}
}

func (s *Server) handleSnapshotHTML(w http.ResponseWriter, r *http.Request) {
	snap := s.loadSnapshot(w, r, "id")
	if snap == nil {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="wanhound-%s.html"`, snap.ID))
	// The exported page is standalone (inline CSS) and must render when
	// opened from disk, not under this server's CSP.
	report.SnapshotHTML(w, snap, snap.Intel == nil, langOf(r))
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	a := s.loadSnapshot(w, r, "a")
	if a == nil {
		return
	}
	b := s.loadSnapshot(w, r, "b")
	if b == nil {
		return
	}
	if b.Time.Before(a.Time) {
		a, b = b, a
	}
	lang := langOf(r)
	ch := store.Diff(a, b)
	if ch.Coverage != nil {
		m := ch.Coverage.Localized(lang)
		ch.Coverage = &m
	}
	out := map[string]any{"a": a.Localized(lang), "b": b.Localized(lang), "changes": ch}
	if a.Family != b.Family {
		out["warning"] = i18n.T(lang, "web.warn_family")
	} else if a.IP != b.IP {
		out["warning"] = i18n.T(lang, "web.warn_addr", a.IP, b.IP)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.logPath)
	if err != nil && !os.IsNotExist(err) {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := []json.RawMessage{}
	for i := len(lines) - 1; i >= 0 && len(out) < 200; i-- {
		if json.Valid([]byte(lines[i])) {
			out = append(out, json.RawMessage(lines[i]))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// audit appends a request-scoped entry (client address, user agent).
func (s *Server) audit(r *http.Request, e map[string]any) {
	e["remote"] = clientIP(r)
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		e["forwarded_for"] = fwd // recorded, never trusted for limits
	}
	e["user_agent"] = r.UserAgent()
	s.auditEntry(e)
}

func (s *Server) auditEntry(e map[string]any) {
	e["time"] = time.Now().UTC().Format(time.RFC3339)
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.logMu.Lock()
	defer s.logMu.Unlock()
	// Rotate at maxLogSize: keep one previous generation (audit.log.1).
	if fi, err := os.Stat(s.logPath); err == nil && fi.Size() > maxLogSize {
		os.Rename(s.logPath, s.logPath+".1")
	}
	f, err := os.OpenFile(s.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit log:", err)
		return
	}
	f.Write(append(line, '\n'))
	f.Close()
}

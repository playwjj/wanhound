package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/wanhound/internal/store"
)

const testPassword = "correct horse battery"

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(Options{Password: testPassword, DataDir: t.TempDir(), Lab: true, ScansPerHour: 2})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func do(t *testing.T, c *http.Client, method, url, body string, csrf bool) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf {
		req.Header.Set("X-WanHound", "1")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func login(t *testing.T, ts *httptest.Server) *http.Client {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	if r := do(t, c, "POST", ts.URL+"/api/login", `{"password":"`+testPassword+`"}`, false); r.StatusCode != 200 {
		t.Fatalf("login: %d", r.StatusCode)
	}
	return c
}

func TestNoPasswordNoServer(t *testing.T) {
	if _, err := New(Options{DataDir: t.TempDir()}); err == nil {
		t.Error("serve must refuse to start without a password")
	}
	if _, err := New(Options{Password: "short", DataDir: t.TempDir()}); err == nil {
		t.Error("serve must refuse a trivially short password")
	}
	if _, err := New(Options{PasswordHash: "plain-text", DataDir: t.TempDir()}); err == nil {
		t.Error("malformed hash must be rejected")
	}
}

func TestUnauthenticatedIsRejected(t *testing.T) {
	_, ts := newTestServer(t)
	c := ts.Client()
	for _, ep := range []struct{ m, p string }{
		{"GET", "/api/task"}, {"GET", "/api/labels"}, {"GET", "/api/history?label=home"},
		{"GET", "/api/snapshot?label=home&id=x"}, {"GET", "/api/snapshot/html?label=home&id=x"},
		{"GET", "/api/diff?label=home&a=x&b=y"}, {"GET", "/api/audit-log"},
		{"POST", "/api/scan"}, {"POST", "/api/task/cancel"}, {"POST", "/api/logout"},
		{"POST", "/api/lanhound/preview"}, {"POST", "/api/lanhound/scan"},
		{"POST", "/api/snapshot/delete"}, {"POST", "/api/label/delete"},
	} {
		if r := do(t, c, ep.m, ts.URL+ep.p, "", true); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without session = %d, want 401", ep.m, ep.p, r.StatusCode)
		}
	}
	// A forged cookie is no better.
	req, _ := http.NewRequest("GET", ts.URL+"/api/labels", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: strings.Repeat("a", 64)})
	if r, _ := c.Do(req); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("forged session = %d", r.StatusCode)
	}
	// The app shell and health check are public (they carry no data).
	if r := do(t, c, "GET", ts.URL+"/", "", false); r.StatusCode != 200 || r.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("GET / = %d, CSP %q", r.StatusCode, r.Header.Get("Content-Security-Policy"))
	}
}

func TestLoginThrottle(t *testing.T) {
	_, ts := newTestServer(t)
	c := ts.Client()
	start := time.Now()
	for i := 0; i < failsPerIP; i++ {
		if r := do(t, c, "POST", ts.URL+"/api/login", `{"password":"nope"}`, false); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong password #%d = %d", i, r.StatusCode)
		}
	}
	if time.Since(start) < time.Duration(failsPerIP)*failureDelay {
		t.Error("failed logins should be slowed down")
	}
	// Locked out now — even the right password is refused.
	r := do(t, c, "POST", ts.URL+"/api/login", `{"password":"`+testPassword+`"}`, false)
	if r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") == "" {
		t.Errorf("after %d failures: %d, want 429 with Retry-After", failsPerIP, r.StatusCode)
	}
}

func TestCSRFHeaderRequired(t *testing.T) {
	_, ts := newTestServer(t)
	c := login(t, ts)
	if r := do(t, c, "POST", ts.URL+"/api/task/cancel", "", false); r.StatusCode != http.StatusForbidden {
		t.Errorf("POST without X-WanHound = %d, want 403", r.StatusCode)
	}
}

func TestScanRules(t *testing.T) {
	s, ts := newTestServer(t)
	c := login(t, ts)
	scan := func(body string) int {
		return do(t, c, "POST", ts.URL+"/api/scan", body, true).StatusCode
	}
	// The authorization assertion is mandatory.
	if code := scan(`{"ipv4":"127.0.0.1","label":"home","port_set":"custom","ports":"1","offline":true}`); code != 400 {
		t.Errorf("scan without authorized = %d, want 400", code)
	}
	// Ranges are not targets.
	if code := scan(`{"ipv4":"127.0.0.0/8","label":"home","port_set":"quick","authorized":true}`); code != 400 {
		t.Errorf("CIDR target = %d, want 400", code)
	}
	// Engine knobs are not part of the API.
	if code := scan(`{"ipv4":"127.0.0.1","label":"home","port_set":"quick","authorized":true,"rate":100000}`); code != 400 {
		t.Errorf("unknown field = %d, want 400", code)
	}
	// One audit at a time: a full scan of loopback runs long enough to collide.
	if code := scan(`{"ipv4":"127.0.0.1","label":"home","port_set":"full","offline":true,"authorized":true}`); code != 202 {
		t.Fatalf("first scan = %d, want 202", code)
	}
	if code := scan(`{"ipv4":"127.0.0.1","label":"home","port_set":"quick","offline":true,"authorized":true}`); code != 409 {
		t.Errorf("concurrent scan = %d, want 409", code)
	}
	if r := do(t, c, "POST", ts.URL+"/api/task/cancel", "", true); r.StatusCode != 200 {
		t.Errorf("cancel = %d", r.StatusCode)
	}
	deadline := time.Now().Add(10 * time.Second)
	for s.tasks.snapshot().State == "running" && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if st := s.tasks.snapshot().State; st != "cancelled" {
		t.Errorf("task state after cancel = %q", st)
	}
	// Hourly cap (2 in this test server): two starts used, third refused.
	if code := scan(`{"ipv4":"127.0.0.1","label":"home","port_set":"custom","ports":"1","offline":true,"authorized":true}`); code != 202 {
		t.Fatalf("second scan = %d", code)
	}
	for s.tasks.snapshot().State == "running" {
		time.Sleep(20 * time.Millisecond)
	}
	if code := scan(`{"ipv4":"127.0.0.1","label":"home","port_set":"custom","ports":"1","offline":true,"authorized":true}`); code != 429 {
		t.Errorf("over hourly cap = %d, want 429", code)
	}

	// Every attempt is in the audit log, with the client address.
	data, err := os.ReadFile(filepath.Join(s.st.Dir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)
	for _, want := range []string{`"action":"login"`, `"action":"scan_start"`, `"action":"scan_rejected"`, `"action":"scan_cancelled"`, `"remote":"127.0.0.1"`, `"ipv4":"127.0.0.1"`} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log missing %s", want)
		}
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := parseHash(HashPassword("s3cret-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if !h.verify("s3cret-passphrase") || h.verify("s3cret-passphrasf") {
		t.Error("hash verify mismatch")
	}
}

func TestLanHoundPreviewAndBatchRules(t *testing.T) {
	_, ts := newTestServer(t)
	c := login(t, ts)
	csv := "name,hostname,ip,ipv6,mac\nNAS,,192.168.1.2,2408:8207::10 fe80::1,aa\nCam,,192.168.1.3,fd00::3,bb\n"
	body, _ := json.Marshal(map[string]any{"csv": csv})
	req, _ := http.NewRequest("POST", ts.URL+"/api/lanhound/preview", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-WanHound", "1")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Targets []struct{ Device, IPv6 string }
	}
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if len(got.Targets) != 1 || got.Targets[0].Device != "NAS" || got.Targets[0].IPv6 != "2408:8207::10" {
		t.Errorf("preview = %+v, want only NAS's public IPv6", got.Targets)
	}

	scan := func(body string) int {
		return do(t, c, "POST", ts.URL+"/api/lanhound/scan", body, true).StatusCode
	}
	if code := scan(`{"label":"home","port_set":"quick","targets":[{"device":"NAS","ipv6":"2408:8207::10"}]}`); code != 400 {
		t.Errorf("batch without authorization = %d, want 400", code)
	}
	if code := scan(`{"label":"home","port_set":"quick","authorized":true,"targets":[{"device":"x","ipv6":"198.51.100.7"}]}`); code != 400 {
		t.Errorf("IPv4 in an IPv6 batch = %d, want 400", code)
	}
	var many []string
	for i := 0; i <= maxBatch; i++ {
		many = append(many, fmt.Sprintf(`{"device":"d%d","ipv6":"2408:8207::%x"}`, i, i+1))
	}
	if code := scan(`{"label":"home","port_set":"quick","authorized":true,"targets":[` + strings.Join(many, ",") + `]}`); code != 400 {
		t.Errorf("batch over the cap = %d, want 400", code)
	}
	if code := scan(`{"label":"home","port_set":"custom","authorized":true,"targets":[{"device":"NAS","ipv6":"::1"}]}`); code != 400 {
		t.Errorf("custom port set in a batch = %d, want 400", code)
	}
}

func TestDeleteEndpoints(t *testing.T) {
	s, ts := newTestServer(t)
	c := login(t, ts)
	snap := &store.Snapshot{Label: "home", Family: "v4", IP: "127.0.0.1", Time: time.Now(), PortSet: "quick", Scanned: "22"}
	if err := s.st.Save(snap); err != nil {
		t.Fatal(err)
	}
	if r := do(t, c, "POST", ts.URL+"/api/snapshot/delete", `{"label":"home","id":"nope"}`, true); r.StatusCode != 404 {
		t.Errorf("deleting a missing snapshot = %d", r.StatusCode)
	}
	if r := do(t, c, "POST", ts.URL+"/api/snapshot/delete", `{"label":"home","id":"`+snap.ID+`"}`, true); r.StatusCode != 200 {
		t.Errorf("delete snapshot = %d", r.StatusCode)
	}
	s.st.Save(snap)
	if r := do(t, c, "POST", ts.URL+"/api/label/delete", `{"label":"home"}`, true); r.StatusCode != 200 {
		t.Errorf("delete label = %d", r.StatusCode)
	}
	if labels, _ := s.st.Labels(); len(labels) != 0 {
		t.Errorf("labels left: %v", labels)
	}
	data, _ := os.ReadFile(filepath.Join(s.st.Dir(), "audit.log"))
	if !strings.Contains(string(data), `"action":"snapshot_deleted"`) || !strings.Contains(string(data), `"action":"label_deleted"`) {
		t.Error("deletions must be audit-logged")
	}
}

// The CSP forbids inline style attributes, so the UI must never set one:
// it would silently not apply (the login button once lost its margin).
func TestNoInlineStyles(t *testing.T) {
	for _, f := range []string{"static/app.js", "static/index.html"} {
		data, err := staticFS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{`style: "`, `style="`, `setAttribute("style"`} {
			if strings.Contains(string(data), bad) {
				t.Errorf("%s uses an inline style (%s) that the CSP blocks; use a CSS class", f, bad)
			}
		}
	}
}

// Package probe identifies what is listening behind an open port:
// a plain banner read, a TLS handshake (certificate details), and an
// HTTP request over plaintext or TLS. All probes are read-only and
// speak first only where the protocol expects the client to speak
// first (HTTP request, TLS ClientHello).
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Info is everything probe learned about one open port.
type Info struct {
	Port   int       `json:"port"`
	Banner string    `json:"banner,omitempty"` // first line a speak-first service sent, sanitized
	TLS    *TLSInfo  `json:"tls,omitempty"`
	HTTP   *HTTPInfo `json:"http,omitempty"`
}

// TLSInfo summarizes the server certificate. It is read, never trusted.
type TLSInfo struct {
	Version    string    `json:"version"`
	CN         string    `json:"cn,omitempty"`
	SANs       []string  `json:"sans,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed,omitempty"`
	Expired    bool      `json:"expired,omitempty"`
}

// HTTPInfo is what an HTTP GET / revealed.
type HTTPInfo struct {
	Status    int    `json:"status"`
	Server    string `json:"server,omitempty"`
	PoweredBy string `json:"powered_by,omitempty"`
	Title     string `json:"title,omitempty"`
	Location  string `json:"location,omitempty"`
	AuthRealm string `json:"auth_realm,omitempty"` // WWW-Authenticate challenge
	// HTTPSOnly: the port refused a plaintext request with a "this is an
	// HTTPS port" error, e.g. a TLS server that needs a hostname (SNI)
	// before it will complete a handshake.
	HTTPSOnly bool `json:"https_only,omitempty"`
}

// Evidence renders the identifying facts as one line for reports.
func (i Info) Evidence() string {
	var parts []string
	if i.Banner != "" {
		parts = append(parts, fmt.Sprintf("banner=%q", i.Banner))
	}
	if t := i.TLS; t != nil {
		s := "tls"
		if t.CN != "" {
			s += fmt.Sprintf(" cn=%q", t.CN)
		}
		if t.Issuer != "" && t.Issuer != t.CN {
			s += fmt.Sprintf(" issuer=%q", t.Issuer)
		}
		if t.SelfSigned {
			s += " self-signed"
		}
		if t.Expired {
			s += " EXPIRED"
		}
		parts = append(parts, s)
	}
	if h := i.HTTP; h != nil {
		s := fmt.Sprintf("http %d", h.Status)
		if h.Title != "" {
			s += fmt.Sprintf(" title=%q", h.Title)
		}
		if h.Server != "" {
			s += fmt.Sprintf(" server=%q", h.Server)
		}
		if h.AuthRealm != "" {
			s += fmt.Sprintf(" auth=%q", h.AuthRealm)
		}
		if h.Location != "" {
			s += fmt.Sprintf(" location=%q", h.Location)
		}
		if h.HTTPSOnly {
			s += " (HTTPS-only port: plaintext request rejected)"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

// Probe inspects one open port. timeout bounds each step.
func Probe(ip string, port int, timeout time.Duration) Info {
	info := Info{Port: port}
	addr := net.JoinHostPort(ip, fmt.Sprint(port))
	if t, conn := probeTLS(addr, timeout); t != nil {
		info.TLS = t
		info.HTTP = httpGet(conn, ip, "/", timeout)
		conn.Close()
	} else {
		info.Banner, info.HTTP = probePlain(addr, ip, timeout)
	}
	followRedirect(&info, addr, ip, timeout)
	return info
}

// followRedirect fetches one same-origin redirect target so apps that
// bounce "/" to "/web/index.html" (media servers, NAS UIs) still yield
// a page title. Never leaves the probed host and port.
func followRedirect(info *Info, addr, host string, timeout time.Duration) {
	h := info.HTTP
	if h == nil || h.Title != "" || h.Status < 300 || h.Status > 399 || h.Location == "" {
		return
	}
	u, err := url.Parse(h.Location)
	if err != nil || (u.Host != "" && u.Host != addr) || (u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https") {
		return
	}
	path := u.EscapedPath()
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	d := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	if info.TLS != nil {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return
	}
	defer conn.Close()
	if next := httpGet(conn, host, path, timeout); next != nil {
		h.Title = next.Title
		if h.Server == "" {
			h.Server = next.Server
		}
	}
}

// ProbeAll probes ports concurrently (bounded) and returns results in
// the order given.
func ProbeAll(ctx context.Context, ip string, ports []int, timeout time.Duration) []Info {
	out := make([]Info, len(ports))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i, p := range ports {
		if ctx.Err() != nil {
			out[i] = Info{Port: p}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i, p int) {
			defer func() { <-sem; wg.Done() }()
			out[i] = Probe(ip, p, timeout)
		}(i, p)
	}
	wg.Wait()
	return out
}

func probeTLS(addr string, timeout time.Duration) (*TLSInfo, *tls.Conn) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // auditing, not trusting: we only read the cert
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return nil, nil
	}
	state := conn.ConnectionState()
	t := &TLSInfo{Version: tls.VersionName(state.Version)}
	if len(state.PeerCertificates) > 0 {
		c := state.PeerCertificates[0]
		t.CN = sanitize(c.Subject.CommonName)
		for _, s := range c.DNSNames {
			if len(t.SANs) < 8 {
				t.SANs = append(t.SANs, sanitize(s))
			}
		}
		t.Issuer = sanitize(issuerName(c))
		t.NotAfter = c.NotAfter
		t.Expired = time.Now().After(c.NotAfter)
		t.SelfSigned = c.Subject.String() == c.Issuer.String() && c.CheckSignatureFrom(c) == nil
	}
	return t, conn
}

func issuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return c.Issuer.String()
}

func probePlain(addr, host string, timeout time.Duration) (string, *HTTPInfo) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return "", nil
	}
	defer conn.Close()

	// Many services (SSH, FTP, SMTP, databases) speak first. Give
	// them a short window; services that wait for the client fall
	// through to the HTTP probe.
	r := bufio.NewReader(io.LimitReader(conn, 4096))
	conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	line, err := r.ReadString('\n')
	if line != "" {
		return sanitize(line), nil
	}
	if err != nil {
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			return "", nil // closed on us without a word
		}
	}
	return "", httpGet(conn, host, "/", timeout)
}

// httpGet sends one GET / on an established connection and parses the
// response head plus the start of the body.
func httpGet(conn net.Conn, host, path string, timeout time.Duration) *HTTPInfo {
	conn.SetDeadline(time.Now().Add(timeout))
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: WanHound (home exposure self-audit)\r\nAccept: text/html\r\nConnection: close\r\n\r\n", path, host)
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 256*1024)), nil)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	h := &HTTPInfo{
		Status:    resp.StatusCode,
		Server:    sanitize(resp.Header.Get("Server")),
		PoweredBy: sanitize(resp.Header.Get("X-Powered-By")),
		Location:  sanitize(resp.Header.Get("Location")),
		AuthRealm: sanitize(resp.Header.Get("WWW-Authenticate")),
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	h.Title = extractTitle(string(body))
	if resp.StatusCode == http.StatusBadRequest && httpsOnly.Match(body) {
		h.HTTPSOnly = true
	}
	return h
}

// httpsOnly matches the stock "you spoke HTTP to a TLS port" errors of
// Go/Caddy, nginx and Apache.
var httpsOnly = regexp.MustCompile(`(?i)(to an https server|https port|ssl-enabled server port|speaking plain http)`)

func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 120 {
		s = string(r[:120])
	}
	return s
}

func extractTitle(html string) string {
	// ASCII-only lowering keeps byte offsets aligned with html.
	b := []byte(html)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	lo := string(b)
	i := strings.Index(lo, "<title")
	if i < 0 {
		return ""
	}
	k := strings.Index(lo[i:], ">")
	if k < 0 {
		return ""
	}
	start := i + k + 1
	j := strings.Index(lo[start:], "</title>")
	if j < 0 {
		return ""
	}
	return sanitize(html[start : start+j])
}

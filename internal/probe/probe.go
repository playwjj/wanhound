// Package probe identifies what is listening behind an open port:
// a plain banner read, a TLS handshake, or an HTTP response. All
// probes are read-only and speak first only where the protocol
// expects the client to speak first (HTTP, TLS ClientHello).
package probe

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Info is everything probe learned about one open port.
type Info struct {
	Port     int      `json:"port"`
	Banner   string   `json:"banner,omitempty"`  // first line, sanitized
	TLS      bool     `json:"tls,omitempty"`     // TLS handshake succeeded
	CertCN   string   `json:"cert_cn,omitempty"` // certificate subject CN
	CertSANs []string `json:"cert_sans,omitempty"`
	HTTP     bool     `json:"http,omitempty"`
	Title    string   `json:"title,omitempty"` // <title> of an HTTP response page
	Server   string   `json:"server,omitempty"`
}

// Probe inspects one open port. timeout bounds each step.
func Probe(ip string, port int, timeout time.Duration) Info {
	info := Info{Port: port}
	if t := probeTLS(ip, port, timeout); t != nil {
		info.TLS = true
		info.CertCN = t.CertCN
		info.CertSANs = t.CertSANs
		// A TLS port may still be HTTPS; the banner step is skipped
		// for it (plaintext reads on TLS ports are meaningless).
		return info
	}
	banner, httpInfo := probePlain(ip, port, timeout)
	info.Banner = banner
	if httpInfo != nil {
		info.HTTP = true
		info.Title = httpInfo.Title
		info.Server = httpInfo.Server
	}
	return info
}

func probeTLS(ip string, port int, timeout time.Duration) *Info {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)), &tls.Config{
		InsecureSkipVerify: true, // auditing, not trusting: we only read the cert
		ServerName:         ip,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return &Info{}
	}
	cert := state.PeerCertificates[0]
	return &Info{CertCN: cert.Subject.CommonName, CertSANs: cert.DNSNames}
}

type httpResult struct {
	Title  string
	Server string
}

func probePlain(ip string, port int, timeout time.Duration) (string, *httpResult) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		return "", nil
	}
	defer conn.Close()
	r := bufio.NewReader(io.LimitReader(conn, 4096))

	// Many services (SSH, FTP, SMTP, databases) speak first. Give
	// them a short window; services that wait for the client fall
	// through to the HTTP probe with a fresh deadline.
	conn.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	if line, err := r.ReadString('\n'); err == nil && line != "" {
		return sanitize(line), nil
	}

	// Otherwise try HTTP: enough to identify web interfaces, which
	// are the most common accidental home exposure.
	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: wanhound\r\n\r\n", ip)
	head, _ := r.ReadString('\n')
	if strings.HasPrefix(head, "HTTP/") {
		res := &httpResult{Server: headerValue(head, "Server")}
		if body, err := io.ReadAll(io.LimitReader(r, 64*1024)); err == nil {
			res.Title = extractTitle(string(body))
		}
		return "", res
	}
	if head != "" {
		return sanitize(head), nil
	}
	return "", nil
}

func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func headerValue(head, name string) string {
	for _, line := range strings.Split(head, "\n") {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(name)+":") {
			return sanitize(strings.TrimSpace(strings.SplitN(line, ":", 2)[1]))
		}
	}
	return ""
}

func extractTitle(html string) string {
	lo := strings.ToLower(html)
	i := strings.Index(lo, "<title>")
	if i < 0 {
		return ""
	}
	j := strings.Index(lo[i:], "</title>")
	if j < 0 {
		return ""
	}
	return sanitize(html[i+7 : i+j])
}

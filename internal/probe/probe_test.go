package probe

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func hostPort(t *testing.T, url string) (string, int) {
	t.Helper()
	var host, port string
	var err error
	for _, pfx := range []string{"https://", "http://"} {
		if len(url) > len(pfx) && url[:len(pfx)] == pfx {
			host, port, err = net.SplitHostPort(url[len(pfx):])
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	return host, p
}

func page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "lighttpd")
	fmt.Fprint(w, "<html><HEAD><Title id=x>  Synology\n DiskStation </TITLE></head></html>")
}

func TestProbeHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(page))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	info := Probe(host, port, 2*time.Second)
	if info.TLS == nil || info.TLS.Version == "" {
		t.Fatalf("TLS not detected: %+v", info)
	}
	if info.HTTP == nil || info.HTTP.Title != "Synology DiskStation" || info.HTTP.Server != "lighttpd" {
		t.Errorf("HTTP over TLS: %+v", info.HTTP)
	}
}

func TestProbeHTTPAndBanner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(page))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	info := Probe(host, port, 2*time.Second)
	if info.TLS != nil || info.HTTP == nil || info.HTTP.Status != 200 || info.HTTP.Title != "Synology DiskStation" {
		t.Errorf("plain HTTP: %+v / %+v", info, info.HTTP)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_9.6\x00\x01\r\n"))
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()
	info = Probe("127.0.0.1", ln.Addr().(*net.TCPAddr).Port, 2*time.Second)
	if info.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("banner = %q (control bytes must be stripped)", info.Banner)
	}
}

func TestExtractTitle(t *testing.T) {
	for in, want := range map[string]string{
		"<title>天翼网关</title>":           "天翼网关",
		"<TITLE>A</TITLE>":              "A",
		"no title":                      "",
		"<title>unterminated":           "",
		"\xff\xfe<title>x\xffy</title>": "x y",
	} {
		if got := extractTitle(in); got != want {
			t.Errorf("extractTitle(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProbeFollowsSameOriginRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "web/index.html", http.StatusFound)
			return
		}
		fmt.Fprint(w, "<title>Emby</title>")
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	info := Probe(host, port, 2*time.Second)
	if info.HTTP == nil || info.HTTP.Status != 302 || info.HTTP.Title != "Emby" {
		t.Errorf("redirect not followed: %+v", info.HTTP)
	}
}

func TestProbeHTTPSOnly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 && buf[0] == 0x16 { // TLS ClientHello without SNI: refuse
					c.Close()
					return
				}
				c.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n"))
				c.Close()
			}()
		}
	}()
	info := Probe("127.0.0.1", ln.Addr().(*net.TCPAddr).Port, 2*time.Second)
	if info.HTTP == nil || !info.HTTP.HTTPSOnly {
		t.Errorf("HTTPS-only port not recognized: %+v", info.HTTP)
	}
}

// A TLS server that refuses handshakes without SNI (reverse proxies, Caddy,
// nginx ssl_reject_handshake) must still be recognized as TLS.
func TestProbeTLSRefusedWithoutSNI(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.StartTLS()
	defer srv.Close()
	cert := srv.TLS.Certificates[0]
	srv.TLS.Certificates = nil
	srv.TLS.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == "" {
			return nil, fmt.Errorf("no SNI")
		}
		return &cert, nil
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	host, port := hostPort(t, srv.URL)
	info := Probe(host, port, 2*time.Second)
	if info.TLS == nil || info.TLS.Refused == "" {
		t.Fatalf("SNI-only TLS server not recognized: %+v", info)
	}
	if !strings.Contains(info.Evidence(), "SNI") {
		t.Errorf("evidence = %q", info.Evidence())
	}
}

// nginx-style: plaintext requests get a TLS alert record back.
func TestProbeTLSAlertToPlaintext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 1024)
				c.Read(buf)
				c.Write([]byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x70}) // fatal alert
				c.Close()
			}()
		}
	}()
	info := Probe("127.0.0.1", ln.Addr().(*net.TCPAddr).Port, 2*time.Second)
	if info.TLS == nil || info.TLS.Refused == "" || info.HTTP != nil {
		t.Errorf("TLS alert to plaintext not recognized: %+v", info)
	}
}

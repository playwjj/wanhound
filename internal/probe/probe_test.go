package probe

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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

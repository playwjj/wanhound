package audit_test

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/wanhound/internal/audit"
	"github.com/playwjj/wanhound/internal/report"
	"github.com/playwjj/wanhound/internal/store"
)

// listen starts a loopback service that greets with banner.
func listen(t *testing.T, banner string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte(banner))
			go func() { time.Sleep(time.Second); c.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func TestAuditBaselineThenNewPort(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ssh := listen(t, "SSH-2.0-OpenSSH_9.6\r\n")
	spare := freePort(t)
	req := audit.Request{IPv4: "127.0.0.1", Label: "武汉的家", PortSet: "custom", Ports: []int{ssh, spare},
		Lab: true, Offline: true, Timeout: 300 * time.Millisecond}

	rep, err := audit.Run(context.Background(), st, req, audit.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ExitCode != 0 || len(rep.Targets) != 1 {
		t.Fatalf("baseline: exit %d, %d targets, errors %v", rep.ExitCode, len(rep.Targets), rep.Errors)
	}
	s := rep.Targets[0]
	if s.Changes != nil || s.Counts.Open != 1 || s.Counts.Closed != 1 {
		t.Errorf("baseline snapshot: changes=%v counts=%+v", s.Changes, s.Counts)
	}

	// Something new starts listening on the spare port: exit code 1.
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(spare)))
	if err != nil {
		t.Skipf("spare port taken meanwhile: %v", err)
	}
	defer ln.Close()
	rep, err = audit.Run(context.Background(), st, req, audit.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	ch := rep.Targets[0].Changes
	if rep.ExitCode != 1 || ch == nil || len(ch.Opened) != 1 || ch.Opened[0] != spare {
		t.Fatalf("second run: exit %d, changes %+v", rep.ExitCode, ch)
	}

	var buf bytes.Buffer
	report.Print(&buf, rep, false, "en")
	if out := buf.String(); !strings.Contains(out, "NEW open TCP ports: "+itoa(spare)) || !strings.Contains(out, "KH-031") {
		t.Errorf("terminal report missing diff or rule id:\n%s", out)
	}
	buf.Reset()
	if err := report.HTML(&buf, rep, "en"); err != nil || !strings.Contains(buf.String(), "NEW open: "+itoa(spare)) {
		t.Errorf("html report: %v", err)
	}
	buf.Reset()
	report.Print(&buf, rep, false, "zh")
	if out := buf.String(); !strings.Contains(out, "新开放的 TCP 端口："+itoa(spare)) || !strings.Contains(out, "SSH") || !strings.Contains(out, "中危") {
		t.Errorf("Chinese terminal report:\n%s", out)
	}
	buf.Reset()
	if err := report.HTML(&buf, rep, "zh"); err != nil || !strings.Contains(buf.String(), `lang="zh-CN"`) || !strings.Contains(buf.String(), "新开放") {
		t.Errorf("Chinese html report: %v", err)
	}
	snaps, _ := st.List("武汉的家")
	if len(snaps) != 2 {
		t.Errorf("history has %d snapshots, want 2", len(snaps))
	}
}

func TestAuditRefusals(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	cases := []audit.Request{
		{IPv4: "192.168.1.1", Label: "home", PortSet: "quick", Offline: true},           // private, no lab
		{IPv4: "100.64.1.2", Label: "home", PortSet: "quick", Offline: true, Lab: true}, // CGNAT: even in lab
	}
	for _, req := range cases {
		rep, err := audit.Run(context.Background(), st, req, audit.Hooks{})
		if err != nil {
			t.Fatal(err)
		}
		if rep.ExitCode != 2 || len(rep.Errors) != 1 || len(rep.Targets) != 0 {
			t.Errorf("%s: exit %d errors %v, want refusal with exit 2", req.IPv4, rep.ExitCode, rep.Errors)
		}
	}
	for _, bad := range []audit.Request{
		{Label: "home"},                                  // no target
		{IPv4: "2001:db8::1", Label: "home"},             // v6 in the v4 slot
		{IPv4: "198.51.100.0/24", Label: "home"},         // ranges are out of scope
		{IPv4: "198.51.100.7", Label: ""},                // label required
		{IPv4: "198.51.100.7", Label: "h", PortSet: "x"}, // unknown port set
	} {
		if bad.Validate() == nil {
			t.Errorf("Validate accepted %+v", bad)
		}
	}
}

func TestAuditCancel(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := audit.Run(ctx, st, audit.Request{IPv4: "127.0.0.1", Label: "home", Lab: true, Offline: true, Timeout: time.Second}, audit.Hooks{})
	if err == nil {
		t.Fatal("cancelled run must return an error")
	}
	if snaps, _ := st.List("home"); len(snaps) != 0 {
		t.Error("cancelled runs must not be saved")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

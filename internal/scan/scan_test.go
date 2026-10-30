package scan

import (
	"context"
	"net"
	"testing"
	"time"
)

// Fixture test: a live listener must classify as open, a port with
// no listener as closed. (Filtered needs a DROP rule and is covered
// by manual acceptance runs, not unit tests.)
func TestScanOpenClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// Find a closed port: bind then release.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()

	res := Scan(context.Background(), "127.0.0.1", Options{
		Ports:       []int{openPort, closedPort},
		Concurrency: 4,
		Timeout:     500 * time.Millisecond,
	}, nil)
	got := map[int]State{}
	for _, pr := range res.Ports {
		got[pr.Port] = pr.State
	}
	if got[openPort] != StateOpen {
		t.Errorf("port %d = %v, want open", openPort, got[openPort])
	}
	if got[closedPort] != StateClosed {
		t.Errorf("port %d = %v, want closed", closedPort, got[closedPort])
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("22,80,8000-8002,80")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Errorf("ParsePorts dedup/range = %v, want 5 ports", got)
	}
	for _, bad := range []string{"", "0", "65536", "abc", "80-", "-80"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("ParsePorts(%q): expected error", bad)
		}
	}
}

package scan

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Test bench, part 1: real sockets. A live listener must classify as
// open, a port with no listener as closed.
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

// timeoutErr mimics a dial timeout (a silently dropped SYN).
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func opErr(err error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", err)}
}

// Test bench, part 2: a simulated target with known per-port behavior,
// so the filtered state (a firewall DROP, which needs root to build for
// real) is asserted too. The real DROP bench is scripts/testbed.sh.
func TestScanThreeStates(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var hostUnreach atomic.Int32
	dial := func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		switch port {
		case "22", "443":
			return a, nil
		case "23":
			return nil, opErr(syscall.ECONNREFUSED)
		case "25":
			hostUnreach.Add(1)
			return nil, opErr(syscall.EHOSTUNREACH) // ICMP unreachable: filtered
		default:
			return nil, &net.OpError{Op: "dial", Err: timeoutErr{}}
		}
	}
	res := Scan(context.Background(), "192.0.2.1", Options{
		Ports: []int{22, 23, 25, 443, 8080}, Timeout: 50 * time.Millisecond, Dial: dial,
	}, nil)
	want := map[int]State{22: StateOpen, 23: StateClosed, 25: StateFiltered, 443: StateOpen, 8080: StateFiltered}
	for _, pr := range res.Ports {
		if pr.State != want[pr.Port] {
			t.Errorf("port %d = %v, want %v", pr.Port, pr.State, want[pr.Port])
		}
	}
	if o, c, f := res.Counts(); o != 2 || c != 1 || f != 2 {
		t.Errorf("counts = %d/%d/%d, want 2/1/2", o, c, f)
	}
	// Two scattered filtered ports out of five: the retry pass runs.
	if res.Retried != 2 || hostUnreach.Load() != 2 {
		t.Errorf("retried = %d (dials to 25: %d), want a second pass over 2 ports", res.Retried, hostUnreach.Load())
	}
}

// A filtered port that answers on the slower retry pass is recovered.
func TestScanRetryRecovers(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var calls atomic.Int32
	dial := func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		if _, port, _ := net.SplitHostPort(addr); port == "8443" && calls.Add(1) > 1 {
			return a, nil
		}
		if _, port, _ := net.SplitHostPort(addr); port == "8443" {
			return nil, &net.OpError{Op: "dial", Err: timeoutErr{}}
		}
		return nil, opErr(syscall.ECONNREFUSED)
	}
	res := Scan(context.Background(), "192.0.2.1", Options{Ports: []int{80, 8443}, Timeout: 50 * time.Millisecond, Dial: dial}, nil)
	if res.Ports[1].State != StateOpen {
		t.Errorf("8443 after retry = %v, want open", res.Ports[1].State)
	}
}

// Local resource exhaustion must be retried, not reported as closed.
func TestScanLocalTransient(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var calls atomic.Int32
	dial := func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		if calls.Add(1) <= 2 {
			return nil, opErr(syscall.EMFILE)
		}
		return a, nil
	}
	res := Scan(context.Background(), "192.0.2.1", Options{Ports: []int{80}, Timeout: 50 * time.Millisecond, Dial: dial}, nil)
	if res.Ports[0].State != StateOpen {
		t.Errorf("state = %v after EMFILE retries, want open", res.Ports[0].State)
	}
}

func TestScanCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dial := func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	res := Scan(ctx, "192.0.2.1", Options{Ports: FullPorts(), Timeout: time.Second, Dial: dial}, nil)
	if !res.Cancelled {
		t.Error("expected Cancelled")
	}
	if len(res.Ports) != 0 {
		t.Errorf("cancelled probes must not be recorded, got %d results", len(res.Ports))
	}
}

func TestTimeoutFor(t *testing.T) {
	if got := TimeoutFor(0); got != SilentTimeout {
		t.Errorf("no answer: %v, want %v", got, SilentTimeout)
	}
	if got := TimeoutFor(time.Millisecond); got != MinTimeout {
		t.Errorf("tiny rtt: %v, want floor %v", got, MinTimeout)
	}
	if got := TimeoutFor(100 * time.Millisecond); got != 550*time.Millisecond {
		t.Errorf("100ms rtt: %v, want 550ms", got)
	}
	if got := TimeoutFor(5 * time.Second); got != MaxTimeout {
		t.Errorf("huge rtt: %v, want cap %v", got, MaxTimeout)
	}
}

func TestEstimate(t *testing.T) {
	// 65535 ports, 512 workers, 800ms timeout → ~640/s → ~102s.
	got := Estimate(65535, Options{Timeout: 800 * time.Millisecond})
	if got < 95*time.Second || got > 110*time.Second {
		t.Errorf("full-scan estimate = %v, want ~102s", got)
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

func TestFormatPortsRoundTrip(t *testing.T) {
	if got := FormatPorts(FullPorts()); got != "1-65535" {
		t.Errorf("FormatPorts(full) = %q", got)
	}
	in := []int{443, 22, 80, 81, 82, 8080}
	s := FormatPorts(in)
	if s != "22,80-82,443,8080" {
		t.Errorf("FormatPorts = %q", s)
	}
	back, err := ParsePorts(s)
	if err != nil || len(back) != len(in) {
		t.Errorf("round trip: %v %v", back, err)
	}
}

func TestQuickPortsSortedUnique(t *testing.T) {
	for i := 1; i < len(QuickPorts); i++ {
		if QuickPorts[i] <= QuickPorts[i-1] {
			t.Fatalf("QuickPorts not sorted/unique at %d", QuickPorts[i])
		}
	}
}

func TestUDPClosedAndSilent(t *testing.T) {
	// A bound-then-closed UDP port on loopback yields ICMP unreachable
	// → closed; a listener that never replies → open|filtered; one that
	// echoes → open.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	r := probeUDP(context.Background(), "127.0.0.1", udpProbe{port: port, service: "x", payload: ntpRequest}, 300*time.Millisecond)
	if r.State != UDPClosed {
		t.Errorf("unbound UDP port = %v, want closed", r.State)
	}

	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := append([]byte(nil), buf[:n]...)
			resp[3] = 0x80 // RA set, rcode 0
			resp[7] = 1    // one answer
			echo.WriteTo(resp, addr)
		}
	}()
	r = probeUDP(context.Background(), "127.0.0.1", udpProbe{port: echo.LocalAddr().(*net.UDPAddr).Port, service: "DNS", payload: dnsQuery, parse: dnsDetail}, 300*time.Millisecond)
	if r.State != UDPOpen || r.Detail == "" {
		t.Errorf("echoing UDP port = %v %q, want open with detail", r.State, r.Detail)
	}
}

// Package scan implements the TCP connect-scan engine and the small
// UDP probe set.
//
// The engine deliberately uses plain connect() calls: no raw sockets,
// no SYN tricks, no privileges required. A completed handshake means
// "open", an immediate refusal means "closed", and silence (or an ICMP
// unreachable) means "filtered" — something on the path dropped or
// rejected the packet. From one vantage point that is a statement about
// the path, not proof that nothing listens.
//
// Pacing is conservative and adaptive: a short RTT calibration picks the
// per-connection timeout (so a silent gateway does not stretch a
// full-port audit with long fixed timeouts), a token pacer caps the
// connection rate, and filtered ports get one slower retry pass when
// there are few enough of them for packet loss to be the likely cause.
package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"syscall"
	"time"
)

// State is the three-valued outcome of probing one TCP port.
type State int

const (
	StateOpen State = iota
	StateClosed
	StateFiltered
)

func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	default:
		return "filtered"
	}
}

// MarshalText makes states readable in JSON ("open", not 0).
func (s State) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText parses the JSON form back.
func (s *State) UnmarshalText(b []byte) error {
	switch string(b) {
	case "open":
		*s = StateOpen
	case "closed":
		*s = StateClosed
	case "filtered":
		*s = StateFiltered
	default:
		return fmt.Errorf("unknown port state %q", b)
	}
	return nil
}

// PortResult is the outcome for a single port.
type PortResult struct {
	Port    int           `json:"port"`
	State   State         `json:"state"`
	Latency time.Duration `json:"latency_ns,omitempty"`
}

// DialFunc opens a TCP connection; tests substitute it to simulate
// refusals and silent drops without firewall privileges.
type DialFunc func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error)

func defaultDial(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, addr)
}

// Defaults. Conservative on purpose: WanHound audits one home, it does
// not race anyone. All are overridable but there is no "fast/stealth"
// preset.
const (
	DefaultConcurrency = 512
	DefaultRate        = 2000 // new connections per second
	MaxConcurrency     = 2048
	MaxRate            = 10000
	MinTimeout         = 250 * time.Millisecond
	MaxTimeout         = 2 * time.Second
	// SilentTimeout is used when calibration got no answer at all: a
	// gateway that drops everything. Any real service answers well
	// inside this on a home line.
	SilentTimeout = 800 * time.Millisecond
	// retryLimit: the filtered retry pass runs only when this few ports
	// were filtered — scattered drops look like packet loss; tens of
	// thousands are a firewall policy, and retrying them is just time.
	retryLimit = 4096
)

// Options controls a scan run.
type Options struct {
	Ports       []int
	Concurrency int           // default DefaultConcurrency
	Rate        int           // connections per second, default DefaultRate
	Timeout     time.Duration // per connection; 0 = adaptive (Calibrate)
	NoRetry     bool          // skip the filtered-port retry pass
	Dial        DialFunc      // default net.Dialer
}

// Result is the full outcome of scanning one target address.
type Result struct {
	IP        string        `json:"ip"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration_ns"`
	Timeout   time.Duration `json:"timeout_ns"`       // per-connection timeout used
	RTT       time.Duration `json:"rtt_ns,omitempty"` // calibration baseline, 0 = no answer
	Retried   int           `json:"retried,omitempty"`
	Cancelled bool          `json:"cancelled,omitempty"`
	Ports     []PortResult  `json:"ports"` // sorted by port
}

// Open returns only the open ports, in ascending order.
func (r *Result) Open() []PortResult { return r.only(StateOpen) }

func (r *Result) only(s State) []PortResult {
	var out []PortResult
	for _, p := range r.Ports {
		if p.State == s {
			out = append(out, p)
		}
	}
	return out
}

// Counts returns the number of open, closed and filtered ports.
func (r *Result) Counts() (open, closed, filtered int) {
	for _, p := range r.Ports {
		switch p.State {
		case StateOpen:
			open++
		case StateClosed:
			closed++
		default:
			filtered++
		}
	}
	return
}

// Progress is called as results arrive (completed, total).
type Progress func(completed, total int)

func (o *Options) normalize() {
	if o.Concurrency <= 0 {
		o.Concurrency = DefaultConcurrency
	}
	if o.Concurrency > MaxConcurrency {
		o.Concurrency = MaxConcurrency
	}
	if o.Rate <= 0 {
		o.Rate = DefaultRate
	}
	if o.Rate > MaxRate {
		o.Rate = MaxRate
	}
	if o.Dial == nil {
		o.Dial = defaultDial
	}
}

// calibrationPorts are tried to measure a round-trip baseline: either a
// SYN-ACK or a RST gives an RTT. Common home ports plus two that are
// almost never open (a RST from those is just as good).
var calibrationPorts = []int{443, 80, 22, 7547, 8080, 53, 1, 65000}

// Calibrate measures the target's connect RTT and derives a timeout.
// It returns rtt=0 when nothing answered (a silently dropping gateway).
func Calibrate(ctx context.Context, ip string, dial DialFunc) (rtt, timeout time.Duration) {
	if dial == nil {
		dial = defaultDial
	}
	var mu sync.Mutex
	var best time.Duration
	var wg sync.WaitGroup
	for _, p := range calibrationPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			start := time.Now()
			conn, err := dial(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)), 2*time.Second)
			lat := time.Since(start)
			if err == nil {
				conn.Close()
			} else if classify(err) != StateClosed {
				return
			}
			mu.Lock()
			if best == 0 || lat < best {
				best = lat
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return best, TimeoutFor(best)
}

// TimeoutFor derives the per-connection timeout from an RTT baseline:
// a generous multiple (jitter, SYN-ACK queues on small routers), bounded.
func TimeoutFor(rtt time.Duration) time.Duration {
	if rtt <= 0 {
		return SilentTimeout
	}
	t := 4*rtt + 150*time.Millisecond
	if t < MinTimeout {
		t = MinTimeout
	}
	if t > MaxTimeout {
		t = MaxTimeout
	}
	return t
}

// Estimate is the worst-case duration of a scan: every port filtered,
// limited by either the pacer or the concurrency/timeout product.
func Estimate(nPorts int, opts Options) time.Duration {
	opts.normalize()
	t := opts.Timeout
	if t <= 0 {
		t = SilentTimeout
	}
	perSec := float64(opts.Concurrency) / t.Seconds()
	if r := float64(opts.Rate); r < perSec {
		perSec = r
	}
	return time.Duration(float64(nPorts) / perSec * float64(time.Second))
}

// Scan probes every port in opts.Ports against ip and returns the
// classified results. It never returns an error for unreachable hosts:
// total silence simply yields all-filtered. When ctx is cancelled the
// partial result is returned with Cancelled set.
func Scan(ctx context.Context, ip string, opts Options, progress Progress) *Result {
	opts.normalize()
	res := &Result{IP: ip, StartedAt: time.Now()}
	if opts.Timeout <= 0 {
		res.RTT, opts.Timeout = Calibrate(ctx, ip, opts.Dial)
	}
	res.Timeout = opts.Timeout

	total := len(opts.Ports)
	done := 0
	report := func() {
		done++
		if progress != nil {
			progress(done, total)
		}
	}
	res.Ports = run(ctx, ip, opts.Ports, opts, report)

	// Retry pass: a slower second look at scattered filtered ports.
	if !opts.NoRetry && ctx.Err() == nil {
		var filtered []int
		idx := map[int]int{}
		for i, p := range res.Ports {
			if p.State == StateFiltered {
				filtered = append(filtered, p.Port)
				idx[p.Port] = i
			}
		}
		if n := len(filtered); n > 0 && n <= retryLimit && n < len(res.Ports) {
			ro := opts
			ro.Timeout = 2 * opts.Timeout
			if ro.Timeout > MaxTimeout {
				ro.Timeout = MaxTimeout
			}
			res.Retried = n
			for _, pr := range run(ctx, ip, filtered, ro, nil) {
				if pr.State != StateFiltered {
					res.Ports[idx[pr.Port]] = pr
				}
			}
		}
	}

	res.Cancelled = ctx.Err() != nil
	sort.Slice(res.Ports, func(i, j int) bool { return res.Ports[i].Port < res.Ports[j].Port })
	res.Duration = time.Since(res.StartedAt)
	return res
}

// run is one paced, bounded-concurrency pass over ports.
func run(ctx context.Context, ip string, ports []int, opts Options, onResult func()) []PortResult {
	jobs := make(chan int)
	results := make(chan PortResult)
	var wg sync.WaitGroup
	workers := opts.Concurrency
	if workers > len(ports) {
		workers = len(ports)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				if pr, ok := probe(ctx, opts, ip, port); ok {
					results <- pr
				}
			}
		}()
	}
	go func() {
		defer func() {
			close(jobs)
			wg.Wait()
			close(results)
		}()
		interval := time.Second / time.Duration(opts.Rate)
		start := time.Now()
		for i, p := range ports {
			// Pace: job i may start no earlier than start+i*interval.
			// Sleep only when meaningfully ahead, so the pacer batches
			// instead of sleeping per port.
			if ahead := time.Until(start.Add(time.Duration(i) * interval)); ahead > 2*time.Millisecond {
				select {
				case <-time.After(ahead):
				case <-ctx.Done():
					return
				}
			}
			select {
			case jobs <- p:
			case <-ctx.Done():
				return
			}
		}
	}()
	var out []PortResult
	for pr := range results {
		out = append(out, pr)
		if onResult != nil {
			onResult()
		}
	}
	return out
}

// probe dials one port. ok=false means the attempt was abandoned
// (scan cancelled) and has no result.
func probe(ctx context.Context, opts Options, ip string, port int) (PortResult, bool) {
	addr := net.JoinHostPort(ip, fmt.Sprint(port))
	backoff := 20 * time.Millisecond
	for attempt := 0; ; attempt++ {
		start := time.Now()
		conn, err := opts.Dial(ctx, "tcp", addr, opts.Timeout)
		lat := time.Since(start)
		if err == nil {
			conn.Close()
			return PortResult{Port: port, State: StateOpen, Latency: lat}, true
		}
		if ctx.Err() != nil {
			return PortResult{}, false
		}
		// Local resource exhaustion (fd limit, ephemeral ports) says
		// nothing about the target: back off and try again rather than
		// recording a bogus "closed".
		if isLocalTransient(err) && attempt < 8 {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return PortResult{}, false
			}
			backoff *= 2
			continue
		}
		st := classify(err)
		pr := PortResult{Port: port, State: st}
		if st == StateClosed {
			pr.Latency = lat
		}
		return pr, true
	}
}

// classify maps a dial error to a port state. Only an explicit refusal
// (RST) is "closed"; timeouts and ICMP unreachables are "filtered",
// matching how nmap reads the same signals.
func classify(err error) State {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return StateClosed
	}
	return StateFiltered
}

func isLocalTransient(err error) bool {
	for _, e := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.EADDRNOTAVAIL, syscall.EAGAIN} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

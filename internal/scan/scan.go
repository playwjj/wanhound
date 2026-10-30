// Package scan implements the TCP connect-scan engine.
//
// The engine deliberately uses plain connect() calls: no raw sockets,
// no SYN tricks, no privileges required. A completed handshake means
// "open", an immediate refusal means "closed", and a timeout means
// "filtered" (something silently dropped the packet — from one
// vantage point this is a statement about the path, not proof that
// nothing listens).
//
// TODO(P1): adaptive timeout derived from a measured RTT baseline;
// a retry pass for filtered ports; UDP probe set.
package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// State is the three-valued outcome of probing one port.
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

// PortResult is the outcome for a single port.
type PortResult struct {
	Port    int           `json:"port"`
	State   State         `json:"state"`
	Latency time.Duration `json:"latency_ns,omitempty"`
}

// Options controls a scan run.
type Options struct {
	Ports       []int
	Concurrency int           // default 256
	Timeout     time.Duration // per-connection, default 1s
}

// Result is the full outcome of scanning one target address.
type Result struct {
	IP        string        `json:"ip"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration_ns"`
	Ports     []PortResult  `json:"ports"` // sorted by port
}

// Open returns only the open ports, in ascending order.
func (r *Result) Open() []PortResult {
	var out []PortResult
	for _, p := range r.Ports {
		if p.State == StateOpen {
			out = append(out, p)
		}
	}
	return out
}

// Progress is called as results arrive (completed, total).
type Progress func(completed, total int)

// Scan probes every port in opts.Ports against ip and returns the
// classified results. It never returns an error for unreachable hosts:
// total silence simply yields all-filtered.
func Scan(ctx context.Context, ip string, opts Options, progress Progress) *Result {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 256
	}
	if opts.Timeout <= 0 {
		opts.Timeout = time.Second
	}
	res := &Result{IP: ip, StartedAt: time.Now()}
	jobs := make(chan int)
	results := make(chan PortResult)
	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := &net.Dialer{Timeout: opts.Timeout}
			for port := range jobs {
				results <- probe(ctx, d, ip, port)
			}
		}()
	}
	go func() {
		for _, p := range opts.Ports {
			select {
			case jobs <- p:
			case <-ctx.Done():
				break
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	done := 0
	for pr := range results {
		res.Ports = append(res.Ports, pr)
		done++
		if progress != nil {
			progress(done, len(opts.Ports))
		}
	}
	sort.Slice(res.Ports, func(i, j int) bool { return res.Ports[i].Port < res.Ports[j].Port })
	res.Duration = time.Since(res.StartedAt)
	return res
}

func probe(ctx context.Context, d *net.Dialer, ip string, port int) PortResult {
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	lat := time.Since(start)
	if err == nil {
		conn.Close()
		return PortResult{Port: port, State: StateOpen, Latency: lat}
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return PortResult{Port: port, State: StateFiltered}
	}
	// A refusal (ECONNREFUSED) also surfaces as other dial errors when
	// a firewall actively rejects; anything that is not a timeout and
	// not a success is reported as closed. Truly silent drops are the
	// timeout case above.
	return PortResult{Port: port, State: StateClosed}
}

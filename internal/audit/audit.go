// Package audit runs one complete WanHound audit — classify, self-check,
// profile, scan, identify, evaluate, diff, save — for up to one IPv4
// and one IPv6 address. The CLI and the web UI both drive this package,
// so they cannot drift apart.
package audit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/playwjj/wanhound/internal/i18n"
	"github.com/playwjj/wanhound/internal/intel"
	"github.com/playwjj/wanhound/internal/knowledge"
	"github.com/playwjj/wanhound/internal/probe"
	"github.com/playwjj/wanhound/internal/scan"
	"github.com/playwjj/wanhound/internal/store"
)

// Request describes one audit.
type Request struct {
	IPv4, IPv6 string
	Label      string
	PortSet    string // "full" (default), "quick" or "custom"
	Ports      []int  // for PortSet "custom"
	UDP        bool
	// Offline disables every third-party lookup: ASN/PTR profile and
	// the egress self-check. Only local address classification remains.
	Offline bool
	// AcceptInside continues even when the scanning machine appears to
	// be inside the target network (results will be distorted).
	AcceptInside bool
	// Lab permits non-public targets (loopback, private) for the test
	// bench. CGNAT stays refused: it is never a meaningful target.
	Lab bool
	// Lang is the language of progress messages ("en" or "zh").
	Lang string

	Concurrency int
	Rate        int
	Timeout     time.Duration // 0 = adaptive
	NoRetry     bool
}

// Event reports progress.
type Event struct {
	Target  string `json:"target,omitempty"`
	Stage   string `json:"stage"` // "check", "profile", "tcp", "probe", "udp", "done"
	Done    int    `json:"done,omitempty"`
	Total   int    `json:"total,omitempty"`
	Message string `json:"message,omitempty"`
}

// Hooks lets callers observe and steer a run. All are optional.
type Hooks struct {
	Progress func(Event)
	// ConfirmInside is asked when the scanner looks like it is inside
	// the target network and Request.AcceptInside is false.
	ConfirmInside func(target string, why i18n.Msg) bool
}

// TargetError is a target that could not be audited.
type TargetError struct {
	IP     string   `json:"ip"`
	Reason i18n.Msg `json:"reason"`
	// Inside marks the "you are inside the network" refusal, which a
	// caller may retry with AcceptInside.
	Inside bool `json:"inside,omitempty"`
}

// Report is the result of one audit run.
type Report struct {
	Label        string            `json:"label"`
	Started      time.Time         `json:"started"`
	Duration     time.Duration     `json:"duration_ns"`
	Offline      bool              `json:"offline"`
	RulesVersion string            `json:"rules_version"`
	Targets      []*store.Snapshot `json:"targets"`
	Errors       []TargetError     `json:"errors,omitempty"`
	ExitCode     int               `json:"exit_code"`
}

// ErrNoTarget is returned when the request names no address.
var ErrNoTarget = errors.New("provide at least one of IPv4 / IPv6")

// PortList resolves the request's port set.
func (r Request) PortList() ([]int, string, error) {
	switch r.PortSet {
	case "", "full":
		return scan.FullPorts(), "full", nil
	case "quick":
		return scan.QuickPorts, "quick", nil
	case "custom":
		if len(r.Ports) == 0 {
			return nil, "", fmt.Errorf("custom port set is empty")
		}
		return r.Ports, "custom", nil
	}
	return nil, "", fmt.Errorf("unknown port set %q", r.PortSet)
}

// Validate checks the request without touching the network.
func (r Request) Validate() error {
	if r.IPv4 == "" && r.IPv6 == "" {
		return ErrNoTarget
	}
	if err := store.ValidLabel(r.Label); err != nil {
		return err
	}
	for _, t := range []struct{ addr, fam string }{{r.IPv4, "v4"}, {r.IPv6, "v6"}} {
		if t.addr == "" {
			continue
		}
		ip, _, err := intel.Classify(t.addr)
		if err != nil {
			return err
		}
		if intel.Family(ip) != t.fam {
			return fmt.Errorf("%s is not an IP%s address", t.addr, t.fam)
		}
	}
	_, _, err := r.PortList()
	return err
}

func (h Hooks) emit(e Event) {
	if h.Progress != nil {
		h.Progress(e)
	}
}

// Run executes the audit and saves a snapshot per audited target.
// The returned error is reserved for failures of the run itself
// (storage, cancellation); per-target refusals land in Report.Errors.
func Run(ctx context.Context, st *store.Store, req Request, hooks Hooks) (*Report, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	ports, portSet, _ := req.PortList()
	rep := &Report{Label: req.Label, Started: time.Now(), Offline: req.Offline, RulesVersion: knowledge.Version()}

	for _, addr := range []string{req.IPv4, req.IPv6} {
		if addr == "" {
			continue
		}
		snap, terr, err := auditOne(ctx, st, req, addr, ports, portSet, hooks)
		if err != nil {
			return rep, err
		}
		if terr != nil {
			rep.Errors = append(rep.Errors, *terr)
			continue
		}
		rep.Targets = append(rep.Targets, snap)
	}
	rep.Duration = time.Since(rep.Started)
	rep.ExitCode = ExitCode(rep)
	hooks.emit(Event{Stage: "done"})
	return rep, nil
}

// vantageArg references a vantage reason by key so composite messages
// translate it when rendered.
func vantageArg(why i18n.Msg) string { return "@" + why.Key }

// canaryPorts are almost never open on a real host. If every one of
// them completes a handshake, the "target" answering is not the target.
var canaryPorts = []int{1, 47391, 65001}

// interceptionCanary returns len(canaryPorts) when all canaries
// connect, else 0.
func interceptionCanary(ctx context.Context, ip string) int {
	var d net.Dialer
	for _, p := range canaryPorts {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(p)))
		cancel()
		if err != nil {
			return 0
		}
		conn.Close()
	}
	return len(canaryPorts)
}

// ExitCode implements the CLI contract: 1 when anything is high risk or
// newly opened (an alert outranks a partial failure), else 2 when a
// target could not be audited, else 0.
func ExitCode(rep *Report) int {
	for _, s := range rep.Targets {
		if knowledge.MaxRisk(s.Findings) >= knowledge.RiskHigh {
			return 1
		}
		if c := s.Changes; c != nil && (len(c.Opened) > 0 || len(c.UDPOpened) > 0) {
			return 1
		}
	}
	if len(rep.Errors) > 0 || len(rep.Targets) == 0 {
		return 2
	}
	return 0
}

func auditOne(ctx context.Context, st *store.Store, req Request, addr string, ports []int, portSet string, hooks Hooks) (*store.Snapshot, *TargetError, error) {
	ip, class, err := intel.Classify(addr)
	if err != nil {
		return nil, &TargetError{IP: addr, Reason: i18n.M("err.generic", err.Error())}, nil
	}
	ipStr := ip.String()
	family := intel.Family(ip)
	snap := &store.Snapshot{Label: req.Label, Family: family, IP: ipStr, PortSet: portSet,
		Scanned: scan.FormatPorts(ports), RulesVersion: knowledge.Version()}

	if ok, why := intel.Scannable(class); !ok {
		if !req.Lab || class == intel.ClassCGNAT || class == intel.ClassUnspecified {
			return nil, &TargetError{IP: ipStr, Reason: why}, nil
		}
		snap.Notes = append(snap.Notes, i18n.M("note.lab", class))
	}

	// Vantage-point self-check.
	hooks.emit(Event{Target: ipStr, Stage: "check", Message: i18n.T(req.Lang, "prog.check")})
	var inside string // catalog key of the vantage problem, if any
	if intel.IsLocal(ip) {
		inside = "inside.local"
	}
	if !req.Offline {
		snap.Egress, snap.EgressSource = intel.Egress(ctx, family), "echo"
	}
	if snap.Egress == "" {
		snap.Egress, snap.EgressSource = intel.LocalEgress(family), "local"
	}
	if snap.Egress == "" {
		snap.EgressSource = "failed"
		if req.Offline {
			snap.EgressSource = "offline"
		}
	}
	if snap.EgressSource == "failed" {
		snap.Notes = append(snap.Notes, i18n.M("note.egress_failed", "IP"+family))
	}
	if !req.Offline {
		if inside == "" && snap.Egress == ipStr {
			inside = "inside.egress"
		}
	} else {
		snap.Notes = append(snap.Notes, i18n.M("note.offline"))
	}
	if inside == "" {
		if interceptionCanary(ctx, ipStr) > 0 {
			inside = "inside.canary"
		}
	}
	why := i18n.M(inside)
	if inside != "" && !req.Lab {
		ok := req.AcceptInside || (hooks.ConfirmInside != nil && hooks.ConfirmInside(ipStr, why))
		if !ok {
			return nil, &TargetError{IP: ipStr, Inside: true, Reason: i18n.M("err.vantage", vantageArg(why))}, nil
		}
		snap.Notes = append(snap.Notes, i18n.M("note.override", vantageArg(why)))
	}

	if inside != "" && req.Lab {
		snap.Notes = append(snap.Notes, i18n.M("note.labvantage", vantageArg(why)))
	}

	if !req.Offline {
		hooks.emit(Event{Target: ipStr, Stage: "profile", Message: i18n.T(req.Lang, "prog.profile")})
		p := intel.Lookup(ctx, ip)
		snap.Intel = &p
	}

	// TCP.
	opts := scan.Options{Ports: ports, Concurrency: req.Concurrency, Rate: req.Rate, Timeout: req.Timeout, NoRetry: req.NoRetry}
	if opts.Timeout <= 0 {
		rtt, t := scan.Calibrate(ctx, ipStr, nil)
		opts.Timeout = t
		snap.RTT = rtt
	}
	est := scan.Estimate(len(ports), opts)
	hooks.emit(Event{Target: ipStr, Stage: "tcp", Total: len(ports),
		Message: i18n.T(req.Lang, "prog.tcp", len(ports), opts.Timeout.Round(time.Millisecond), est.Round(time.Second))})
	res := scan.Scan(ctx, ipStr, opts, func(done, total int) {
		if done%256 == 0 || done == total {
			hooks.emit(Event{Target: ipStr, Stage: "tcp", Done: done, Total: total})
		}
	})
	if res.Cancelled {
		return nil, nil, ctx.Err()
	}
	snap.Time = res.StartedAt
	snap.Timeout = res.Timeout
	snap.Retried = res.Retried
	o, c, f := res.Counts()
	snap.Counts = store.Counts{Open: o, Closed: c, Filtered: f}

	// Identify what answers.
	var open []int
	for _, p := range res.Open() {
		open = append(open, p.Port)
	}
	if len(open) > 0 {
		hooks.emit(Event{Target: ipStr, Stage: "probe", Total: len(open), Message: i18n.T(req.Lang, "prog.probe", len(open))})
		snap.Open = probe.ProbeAll(ctx, ipStr, open, 3*time.Second)
	}
	if req.UDP {
		hooks.emit(Event{Target: ipStr, Stage: "udp", Message: i18n.T(req.Lang, "prog.udp")})
		snap.UDP = scan.ScanUDP(ctx, ipStr, 0)
	}
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	snap.Findings = knowledge.Evaluate(knowledge.Target{Family: family, TCP: snap.Open, UDP: snap.UDP})
	snap.Duration = time.Since(res.StartedAt)

	if family == "v4" && o > 0 {
		snap.Notes = append(snap.Notes, i18n.M("note.v4"))
	}
	if f > 0 && f < len(ports) {
		snap.Notes = append(snap.Notes, i18n.M("note.filtered", f))
	} else if f == len(ports) {
		snap.Notes = append(snap.Notes, i18n.M("note.all_filtered"))
	}

	prev, err := st.Latest(req.Label, family)
	if err != nil {
		return nil, nil, err
	}
	snap.Changes = store.Diff(prev, snap)
	if err := st.Save(snap); err != nil {
		return nil, nil, err
	}
	return snap, nil, nil
}

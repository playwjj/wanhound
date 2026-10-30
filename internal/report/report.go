// Package report renders audit results for humans: the terminal
// report, a short text summary (for push notifications), and a
// standalone HTML page. The exit-code contract lives in package audit.
package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/playwjj/wanhound/internal/audit"
	"github.com/playwjj/wanhound/internal/knowledge"
	"github.com/playwjj/wanhound/internal/scan"
	"github.com/playwjj/wanhound/internal/store"
)

type palette struct{ bold, dim, red, yellow, blue, green, reset string }

func colors(on bool) palette {
	if !on {
		return palette{}
	}
	return palette{"\033[1m", "\033[2m", "\033[31m", "\033[33m", "\033[36m", "\033[32m", "\033[0m"}
}

func (p palette) risk(r knowledge.Risk) string {
	switch r {
	case knowledge.RiskHigh:
		return p.red + p.bold
	case knowledge.RiskMedium:
		return p.yellow
	case knowledge.RiskLow:
		return p.blue
	}
	return p.dim
}

// Print writes the full human-readable report.
func Print(w io.Writer, rep *audit.Report, color bool) {
	c := colors(color)
	fmt.Fprintf(w, "%sWanHound audit — label %q%s\n", c.bold, rep.Label, c.reset)
	for _, e := range rep.Errors {
		fmt.Fprintf(w, "\n%sNot audited: %s%s\n  %s\n", c.yellow, e.IP, c.reset, e.Reason)
	}
	for _, s := range rep.Targets {
		printTarget(w, s, c)
	}
	fmt.Fprintf(w, "\n%s── Audit record ──%s\n", c.dim, c.reset)
	fmt.Fprintf(w, "  time      %s (took %s)\n", rep.Started.Format("2006-01-02 15:04:05 MST"), rep.Duration.Round(time.Second))
	for _, s := range rep.Targets {
		src := s.Egress
		if src == "" {
			src = "not checked"
			if rep.Offline {
				src += " (offline)"
			}
		}
		fmt.Fprintf(w, "  target    %s (IP%s) · source %s · %s ports %s · snapshot %s\n", s.IP, s.Family, src, s.PortSet, shortSpec(s.Scanned), s.ID)
	}
	fmt.Fprintf(w, "  rules     %s\n", rep.RulesVersion)
	fmt.Fprintln(w, "  Only audit addresses you own or are authorized to test.")
}

func printTarget(w io.Writer, s *store.Snapshot, c palette) {
	fmt.Fprintf(w, "\n%s━━ %s (IP%s) ━━%s\n", c.bold, s.IP, s.Family, c.reset)
	if p := s.Intel; p != nil {
		var parts []string
		if p.ASN != "" || p.Org != "" {
			parts = append(parts, strings.TrimSpace(p.ASN+" "+p.Org))
		}
		if p.Country != "" {
			parts = append(parts, p.Country)
		}
		if len(p.PTR) > 0 {
			parts = append(parts, "ptr "+strings.Join(p.PTR, ", "))
		}
		if len(parts) > 0 {
			fmt.Fprintf(w, "%s%s  (via %s — the address was shown to that service)%s\n", c.dim, strings.Join(parts, " · "), p.Source, c.reset)
		}
		for _, h := range p.Hints {
			fmt.Fprintf(w, "%s! %s%s\n", c.yellow, h, c.reset)
		}
	}
	rtt := "no answer to calibration"
	if s.RTT > 0 {
		rtt = "rtt " + s.RTT.Round(time.Millisecond).String()
	}
	fmt.Fprintf(w, "Scanned %d TCP ports in %s (timeout %s, %s): %s%d open%s · %d closed · %d filtered\n",
		s.Counts.Open+s.Counts.Closed+s.Counts.Filtered, s.Duration.Round(100*time.Millisecond),
		s.Timeout.Round(time.Millisecond), rtt, c.bold, s.Counts.Open, c.reset, s.Counts.Closed, s.Counts.Filtered)

	printChanges(w, s.Changes, c)

	byPort := findingsByPort(s.Findings)
	if len(s.Open) > 0 {
		fmt.Fprintf(w, "\n  %-10s %-26s %-7s %s\n", "PORT", "SERVICE", "RISK", "FINDING")
		for _, o := range s.Open {
			fs := byPort[o.Port]
			top := fs[0]
			fmt.Fprintf(w, "  %-10s %-26s %s%-7s%s %s\n", fmt.Sprintf("%d/tcp", o.Port), trunc(top.Service, 26),
				c.risk(top.Risk), strings.ToUpper(top.Risk.String()), c.reset, top.Title)
		}
	}
	if len(s.UDP) > 0 {
		var parts []string
		for _, u := range s.UDP {
			parts = append(parts, fmt.Sprintf("%d %s", u.Port, u.State))
		}
		fmt.Fprintf(w, "\n  UDP (advisory: silence cannot tell open from filtered): %s\n", strings.Join(parts, " · "))
	}

	if len(s.Findings) == 0 {
		fmt.Fprintf(w, "\n%sNothing answered. From this vantage point, nothing is exposed.%s\n", c.green, c.reset)
	} else {
		fmt.Fprintf(w, "\nFindings (worst first):\n")
		for _, f := range s.Findings {
			where := "whole target"
			if f.Port != 0 {
				where = fmt.Sprintf("%d/%s", f.Port, f.Proto)
			}
			fmt.Fprintf(w, "\n%s[%s]%s %s  %s%s%s  %s(%s", c.risk(f.Risk), strings.ToUpper(f.Risk.String()), c.reset,
				where, c.bold, f.Title, c.reset, c.dim, f.RuleID)
			if f.Confidence != "" {
				fmt.Fprintf(w, ", confidence %s", confidenceText(f.Confidence))
			}
			fmt.Fprintf(w, ")%s\n", c.reset)
			if f.Evidence != "" {
				fmt.Fprintf(w, "    evidence  %s\n", f.Evidence)
			}
			fmt.Fprintf(w, "    what      %s\n", f.Explain)
			fmt.Fprintf(w, "    do        %s\n", f.Advice)
		}
	}
	if len(s.Notes) > 0 {
		fmt.Fprintln(w, "\nNotes:")
		for _, n := range s.Notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
	}
}

func printChanges(w io.Writer, ch *store.Changes, c palette) {
	if ch == nil {
		fmt.Fprintln(w, "No previous snapshot for this label and address family: this run is the baseline.")
		return
	}
	fmt.Fprintf(w, "Compared with %s (%s):\n", ch.PrevTime.Local().Format("2006-01-02 15:04"), ch.PrevIP)
	if ch.IPChanged {
		fmt.Fprintf(w, "  %s! address changed %s → this run; it may not be the same line, compare with care%s\n", c.yellow, ch.PrevIP, c.reset)
	}
	if len(ch.Opened) > 0 {
		fmt.Fprintf(w, "  %sNEW open TCP ports: %s%s\n", c.red+c.bold, JoinInts(ch.Opened), c.reset)
	}
	if len(ch.UDPOpened) > 0 {
		fmt.Fprintf(w, "  %sNEW answering UDP ports: %s%s\n", c.red+c.bold, JoinInts(ch.UDPOpened), c.reset)
	}
	if len(ch.Closed) > 0 {
		fmt.Fprintf(w, "  %sno longer open: %s%s\n", c.green, JoinInts(ch.Closed), c.reset)
	}
	if len(ch.UDPClosed) > 0 {
		fmt.Fprintf(w, "  %sUDP no longer answering: %s%s\n", c.green, JoinInts(ch.UDPClosed), c.reset)
	}
	for _, sc := range ch.Changed {
		fmt.Fprintf(w, "  %d/tcp now answers differently:\n      before %s\n      after  %s\n", sc.Port, sc.Before, sc.After)
	}
	if ch.Empty() {
		fmt.Fprintln(w, "  no change in open ports")
	}
	if ch.Coverage != "" {
		fmt.Fprintf(w, "  %snote: %s%s\n", c.dim, ch.Coverage, c.reset)
	}
}

func findingsByPort(fs []knowledge.Finding) map[int][]knowledge.Finding {
	m := map[int][]knowledge.Finding{}
	for _, f := range fs {
		if f.Proto == "tcp" {
			m[f.Port] = append(m[f.Port], f) // already worst-first
		}
	}
	return m
}

func confidenceText(c string) string {
	switch c {
	case "high":
		return "high — matched identifying evidence"
	case "medium":
		return "medium — protocol recognized"
	default:
		return "low — port number only"
	}
}

// Summary is a short plain-text digest (for chat notifications).
func Summary(rep *audit.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "WanHound — %s\n", rep.Label)
	for _, s := range rep.Targets {
		fmt.Fprintf(&b, "%s: %d open", s.IP, s.Counts.Open)
		if len(s.Findings) > 0 {
			fmt.Fprintf(&b, ", worst %s", knowledge.MaxRisk(s.Findings))
		}
		b.WriteString("\n")
		if ch := s.Changes; ch != nil {
			if ch.IPChanged {
				fmt.Fprintf(&b, "  address changed from %s\n", ch.PrevIP)
			}
			if len(ch.Opened) > 0 {
				fmt.Fprintf(&b, "  NEW open: %s\n", JoinInts(ch.Opened))
			}
			if len(ch.Closed) > 0 {
				fmt.Fprintf(&b, "  closed: %s\n", JoinInts(ch.Closed))
			}
		}
		for _, f := range s.Findings {
			if f.Risk >= knowledge.RiskHigh {
				port := "*"
				if f.Port != 0 {
					port = fmt.Sprintf("%d/%s", f.Port, f.Proto)
				}
				fmt.Fprintf(&b, "  [HIGH] %s %s\n", port, f.Title)
			}
		}
	}
	for _, e := range rep.Errors {
		fmt.Fprintf(&b, "%s: not audited\n", e.IP)
	}
	return b.String()
}

// JoinInts renders "22, 80, 443".
func JoinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprint(x)
	}
	return strings.Join(parts, ", ")
}

func shortSpec(s string) string {
	if len(s) > 40 {
		ports, err := scan.ParsePorts(s)
		if err == nil {
			return fmt.Sprintf("(%d ports)", len(ports))
		}
		return s[:40] + "…"
	}
	return s
}

func trunc(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

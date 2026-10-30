// Package report renders audit results for humans (terminal) and
// computes the CLI exit code contract:
//
//	0 — no high-risk findings
//	1 — high-risk finding present, or new ports opened vs last snapshot
//	2 — the audit itself failed (handled by the caller before render)
package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/playwjj/wanhound/internal/knowledge"
	"github.com/playwjj/wanhound/internal/scan"
	"github.com/playwjj/wanhound/internal/store"
)

// ExitCode implements the contract for a completed audit.
func ExitCode(findings []knowledge.Finding, ch store.Changes) int {
	if knowledge.MaxRisk(findings) >= knowledge.RiskHigh || len(ch.OpenedPorts) > 0 {
		return 1
	}
	return 0
}

// Print writes the human-readable report.
func Print(w io.Writer, label string, res *scan.Result, findings []knowledge.Finding, evidence map[int]string, ch store.Changes, hasPrev bool) {
	fmt.Fprintf(w, "WanHound audit — label %q, target %s\n", label, res.IP)
	fmt.Fprintf(w, "Scanned %d ports in %s: %d open\n\n",
		len(res.Ports), res.Duration.Round(100*time.Millisecond), len(res.Open()))
	if !hasPrev {
		fmt.Fprintln(w, "No previous snapshot under this label; this run is the baseline.")
	} else {
		if ch.IPChanged {
			fmt.Fprintln(w, "Note: the address under this label changed since the last run; treat comparisons with care.")
		}
		if len(ch.OpenedPorts) > 0 {
			fmt.Fprintf(w, "NEW open ports since last run: %s\n", joinInts(ch.OpenedPorts))
		}
		if len(ch.ClosedPorts) > 0 {
			fmt.Fprintf(w, "No longer open: %s\n", joinInts(ch.ClosedPorts))
		}
		if len(ch.OpenedPorts) == 0 && len(ch.ClosedPorts) == 0 {
			fmt.Fprintln(w, "No change in open ports since the last run.")
		}
	}
	fmt.Fprintln(w)
	if len(findings) == 0 {
		fmt.Fprintln(w, "No open ports found. From this vantage point, nothing is exposed.")
		return
	}
	for _, f := range findings {
		fmt.Fprintf(w, "[%-6s] %d/tcp  %s\n", strings.ToUpper(f.Risk.String()), f.Port, f.Title)
		if ev := evidence[f.Port]; ev != "" {
			fmt.Fprintf(w, "         evidence: %s\n", ev)
		}
		fmt.Fprintf(w, "         %s (%s)\n", f.Advice, f.RuleID)
	}
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprint(x)
	}
	return strings.Join(parts, ", ")
}

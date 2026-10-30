// Package report renders audit results for humans: the terminal
// report, a short text summary (for push notifications), and a
// standalone HTML page, in English or Simplified Chinese. The
// exit-code contract lives in package audit.
package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/playwjj/wanhound/internal/audit"
	"github.com/playwjj/wanhound/internal/i18n"
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

// printer carries the output language and colors.
type printer struct {
	w    io.Writer
	c    palette
	lang string
}

func (p printer) t(key string, args ...any) string { return i18n.T(p.lang, key, args...) }

func (p printer) riskName(r knowledge.Risk) string { return p.t("risk." + r.String()) }

// Print writes the full human-readable report in lang.
func Print(w io.Writer, rep *audit.Report, color bool, lang string) {
	p := printer{w: w, c: colors(color), lang: i18n.Normalize(lang)}
	c := p.c
	fmt.Fprintf(w, "%s%s%s\n", c.bold, p.t("r.title", rep.Label), c.reset)
	for _, e := range rep.Errors {
		fmt.Fprintf(w, "\n%s%s%s\n  %s\n", c.yellow, p.t("r.not_audited", e.IP), c.reset, e.Reason.Render(p.lang))
	}
	for _, s := range rep.Targets {
		p.target(s.Localized(p.lang))
	}
	fmt.Fprintf(w, "\n%s%s%s\n", c.dim, p.t("r.record"), c.reset)
	fmt.Fprintln(w, p.t("r.rec_time", rep.Started.Format("2006-01-02 15:04:05 MST"), rep.Duration.Round(time.Second)))
	for _, s := range rep.Targets {
		fmt.Fprintln(w, p.t("r.rec_target", s.IP, s.Family, egressText(s, rep.Offline, p.lang), p.t("portset."+s.PortSet), shortSpec(s.Scanned, p.lang), s.ID))
	}
	fmt.Fprintln(w, p.t("r.rec_rules", rep.RulesVersion))
	fmt.Fprintln(w, p.t("r.footer"))
}

func (p printer) target(s *store.Snapshot) {
	w, c := p.w, p.c
	fmt.Fprintf(w, "\n%s━━ %s (IP%s) ━━%s\n", c.bold, s.IP, s.Family, c.reset)
	if pr := s.Intel; pr != nil {
		var parts []string
		if pr.ASN != "" || pr.Org != "" {
			parts = append(parts, strings.TrimSpace(pr.ASN+" "+pr.Org))
		}
		if pr.Country != "" {
			parts = append(parts, pr.Country)
		}
		if len(pr.PTR) > 0 {
			parts = append(parts, p.t("r.ptr", strings.Join(pr.PTR, ", ")))
		}
		if len(parts) > 0 {
			fmt.Fprintf(w, "%s%s  %s%s\n", c.dim, strings.Join(parts, " · "), p.t("r.via", pr.Source), c.reset)
		}
		for _, h := range pr.Hints {
			fmt.Fprintf(w, "%s! %s%s\n", c.yellow, h.Render(p.lang), c.reset)
		}
	}
	rtt := p.t("r.rtt_none")
	if s.RTT > 0 {
		rtt = p.t("r.rtt", roundRTT(s.RTT))
	}
	total := s.Counts.Open + s.Counts.Closed + s.Counts.Filtered
	fmt.Fprintln(w, p.t("r.scanned", total, s.Duration.Round(100*time.Millisecond), s.Timeout.Round(time.Millisecond), rtt,
		c.bold+p.t("r.open_n", s.Counts.Open)+c.reset, s.Counts.Closed, s.Counts.Filtered))

	p.changes(s.Changes)

	byPort := findingsByPort(s.Findings)
	if len(s.Open) > 0 {
		fmt.Fprintf(w, "\n  %s %s %s %s\n", pad(p.t("r.col_port"), 10), pad(p.t("r.col_service"), 26), pad(p.t("r.col_risk"), 7), p.t("r.col_finding"))
		for _, o := range s.Open {
			top := byPort[o.Port][0]
			fmt.Fprintf(w, "  %s %s %s%s%s %s\n", pad(fmt.Sprintf("%d/tcp", o.Port), 10), pad(trunc(top.Service, 26), 26),
				c.risk(top.Risk), pad(strings.ToUpper(p.riskName(top.Risk)), 7), c.reset, top.Title)
		}
	}
	if len(s.UDP) > 0 {
		var parts []string
		for _, u := range s.UDP {
			parts = append(parts, fmt.Sprintf("%d %s", u.Port, p.t("udp."+u.State.String())))
		}
		fmt.Fprintf(w, "\n  %s\n", p.t("r.udp_line", strings.Join(parts, " · ")))
	}

	if len(s.Findings) == 0 {
		fmt.Fprintf(w, "\n%s%s%s\n", c.green, p.t("r.nothing"), c.reset)
	} else {
		fmt.Fprintf(w, "\n%s\n", p.t("r.findings"))
		for _, f := range s.Findings {
			where := p.t("whole")
			if f.Port != 0 {
				where = fmt.Sprintf("%d/%s", f.Port, f.Proto)
			}
			fmt.Fprintf(w, "\n%s[%s]%s %s  %s%s%s  %s(%s", c.risk(f.Risk), strings.ToUpper(p.riskName(f.Risk)), c.reset,
				where, c.bold, f.Title, c.reset, c.dim, f.RuleID)
			if f.Confidence != "" {
				fmt.Fprint(w, p.t("r.confidence", p.t("conf."+f.Confidence)))
			}
			fmt.Fprintf(w, ")%s\n", c.reset)
			if f.Evidence != "" {
				fmt.Fprintf(w, "    %s  %s\n", pad(p.t("r.evidence"), 8), f.Evidence)
			}
			fmt.Fprintf(w, "    %s  %s\n", pad(p.t("r.what"), 8), f.Explain)
			fmt.Fprintf(w, "    %s  %s\n", pad(p.t("r.do"), 8), f.Advice)
		}
	}
	if len(s.Notes) > 0 {
		fmt.Fprintf(w, "\n%s\n", p.t("r.notes"))
		for _, n := range s.Notes {
			fmt.Fprintf(w, "  - %s\n", n.Render(p.lang))
		}
	}
}

func (p printer) changes(ch *store.Changes) {
	w, c := p.w, p.c
	if ch == nil {
		fmt.Fprintln(w, p.t("r.baseline"))
		return
	}
	fmt.Fprintln(w, p.t("r.compared", ch.PrevTime.Local().Format("2006-01-02 15:04"), ch.PrevIP))
	if ch.IPChanged {
		fmt.Fprintf(w, "  %s%s%s\n", c.yellow, p.t("r.ip_changed", ch.PrevIP), c.reset)
	}
	if len(ch.Opened) > 0 {
		fmt.Fprintf(w, "  %s%s%s\n", c.red+c.bold, p.t("r.new_tcp", JoinInts(ch.Opened)), c.reset)
	}
	if len(ch.UDPOpened) > 0 {
		fmt.Fprintf(w, "  %s%s%s\n", c.red+c.bold, p.t("r.new_udp", JoinInts(ch.UDPOpened)), c.reset)
	}
	if len(ch.Closed) > 0 {
		fmt.Fprintf(w, "  %s%s%s\n", c.green, p.t("r.closed", JoinInts(ch.Closed)), c.reset)
	}
	if len(ch.UDPClosed) > 0 {
		fmt.Fprintf(w, "  %s%s%s\n", c.green, p.t("r.udp_closed", JoinInts(ch.UDPClosed)), c.reset)
	}
	for _, sc := range ch.Changed {
		fmt.Fprintf(w, "  %s\n      %s %s\n      %s %s\n", p.t("r.changed", sc.Port), p.t("r.before"), sc.Before, p.t("r.after"), sc.After)
	}
	if ch.Empty() {
		fmt.Fprintf(w, "  %s\n", p.t("r.no_change"))
	}
	if ch.Coverage != nil {
		fmt.Fprintf(w, "  %s%s%s\n", c.dim, p.t("r.note", ch.Coverage.Render(p.lang)), c.reset)
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

// Summary is a short plain-text digest (for chat notifications).
func Summary(rep *audit.Report, lang string) string {
	t := func(key string, args ...any) string { return i18n.T(lang, key, args...) }
	var b strings.Builder
	b.WriteString(t("s.title", rep.Label) + "\n")
	for _, s := range rep.Targets {
		s = s.Localized(lang)
		b.WriteString(t("s.line", s.IP, s.Counts.Open))
		if len(s.Findings) > 0 {
			b.WriteString(t("s.worst", t("risk."+knowledge.MaxRisk(s.Findings).String())))
		}
		b.WriteString("\n")
		if ch := s.Changes; ch != nil {
			if ch.IPChanged {
				b.WriteString(t("s.addr", ch.PrevIP) + "\n")
			}
			if len(ch.Opened) > 0 {
				b.WriteString(t("s.new", JoinInts(ch.Opened)) + "\n")
			}
			if len(ch.Closed) > 0 {
				b.WriteString(t("s.closed", JoinInts(ch.Closed)) + "\n")
			}
		}
		for _, f := range s.Findings {
			if f.Risk >= knowledge.RiskHigh {
				port := "*"
				if f.Port != 0 {
					port = fmt.Sprintf("%d/%s", f.Port, f.Proto)
				}
				fmt.Fprintf(&b, "  [%s] %s %s\n", strings.ToUpper(t("risk.high")), port, f.Title)
			}
		}
	}
	for _, e := range rep.Errors {
		b.WriteString(t("s.not_audited", e.IP) + "\n")
	}
	return b.String()
}

// egressText describes the scanning machine's public address for the
// audit record, saying why it is missing when it is.
func egressText(s *store.Snapshot, offline bool, lang string) string {
	switch {
	case s.Egress != "":
		return s.Egress
	case s.EgressSource == "failed":
		return i18n.T(lang, "r.egress_failed")
	case s.EgressSource == "offline" || offline:
		return i18n.T(lang, "r.not_checked") + i18n.T(lang, "r.offline_suffix")
	}
	return i18n.T(lang, "r.not_checked")
}

// JoinInts renders "22, 80, 443".
func JoinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprint(x)
	}
	return strings.Join(parts, ", ")
}

func shortSpec(s, lang string) string {
	if len(s) > 40 {
		ports, err := scan.ParsePorts(s)
		if err == nil {
			return i18n.T(lang, "r.ports_count", len(ports))
		}
		return s[:40] + "…"
	}
	return s
}

func roundRTT(d time.Duration) string {
	if d < time.Millisecond {
		return "<1ms"
	}
	return d.Round(time.Millisecond).String()
}

// width approximates terminal columns: CJK characters take two.
func width(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x1100 && (r <= 0x115f || r >= 0x2e80 && r <= 0xa4cf || r >= 0xac00 && r <= 0xd7a3 || r >= 0xf900 && r <= 0xfaff || r >= 0xfe30 && r <= 0xfe4f || r >= 0xff00 && r <= 0xff60 || r >= 0xffe0 && r <= 0xffe6) {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// pad right-pads s to n terminal columns.
func pad(s string, n int) string {
	if w := width(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}

func trunc(s string, n int) string {
	if width(s) <= n {
		return s
	}
	var b strings.Builder
	w := 0
	for _, r := range s {
		rw := width(string(r))
		if w+rw > n-1 {
			break
		}
		b.WriteRune(r)
		w += rw
	}
	return b.String() + "…"
}

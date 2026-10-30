// WanHound — audit your own home network's public exposure.
//
//	wanhound scan    --ipv4 <home-ipv4> [--ipv6 <home-ipv6>] [--label home]
//	wanhound scan-lanhound --csv devices.csv [--label home]
//	wanhound serve   --addr 127.0.0.1:8687  (password via WANHOUND_PASSWORD[_HASH])
//	wanhound history [--label home]
//	wanhound show    --label home [--id <snapshot>] [--html out.html]
//	wanhound rules
//	wanhound hash-password
//
// scan exit codes: 0 = no high-risk findings, 1 = high-risk finding
// or newly opened ports vs the last snapshot, 2 = the audit itself
// could not run (bad input, unscannable address class).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/playwjj/wanhound/internal/audit"
	"github.com/playwjj/wanhound/internal/i18n"
	"github.com/playwjj/wanhound/internal/knowledge"
	"github.com/playwjj/wanhound/internal/report"
	"github.com/playwjj/wanhound/internal/scan"
	"github.com/playwjj/wanhound/internal/store"
	"github.com/playwjj/wanhound/internal/web"
)

// version is stamped at release time via -ldflags -X main.version.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "scan":
		err = runScan(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "scan-lanhound":
		err = runScanLanHound(os.Args[2:])
	case "history":
		err = runHistory(os.Args[2:])
	case "delete":
		err = runDelete(os.Args[2:])
	case "accept":
		err = runAccept(os.Args[2:])
	case "show":
		err = runShow(os.Args[2:])
	case "rules":
		err = runRules()
	case "hash-password":
		err = runHashPassword()
	case "version", "--version":
		fmt.Println("wanhound", version, "· rules", knowledge.Version())
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		var code exitError
		if errors.As(err, &code) {
			os.Exit(int(code))
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func usage() {
	fmt.Fprintf(os.Stderr, `WanHound %s — audit your own home network's public exposure.

Usage:
  wanhound scan    --ipv4 <addr> [--ipv6 <addr>] [--label home] [--quick | --ports 22,80,8000-8100]
  wanhound scan-lanhound --csv devices.csv [--label home]   audit each device's public IPv6 from a LanHound export
  wanhound serve   [--addr 127.0.0.1:8687]   (WANHOUND_PASSWORD or WANHOUND_PASSWORD_HASH required)
  wanhound history [--label <name>]
  wanhound show    --label <name> [--id <snapshot-id>] [--json | --html <file>]
  wanhound delete  --label <name> (--id <snapshot-id> | --keep <n> | --all)
  wanhound accept  --label <name> --rule <id> [--port <n>] --reason "<why>" [--days 30]   | --list | --remove <id>
  wanhound rules   list the built-in rule base
  wanhound hash-password   read a password on stdin, print a hash for WANHOUND_PASSWORD_HASH

Run "wanhound <command> -h" for options.
Only audit addresses you own or are authorized to test.
Run scan from OUTSIDE the network being audited (e.g. a VPS).
`, version)
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var (
		req                     audit.Request
		quick, noUDP, withUDP   bool
		jsonOut                 bool
		noColor, yes            bool
		portsSpec, dataDir      string
		htmlOut                 string
		timeoutMS               int
		tgToken, tgChat, notify string
		lang                    string
	)
	fs.StringVar(&req.IPv4, "ipv4", "", "public IPv4 address to audit")
	fs.StringVar(&req.IPv6, "ipv6", "", "public IPv6 address to audit")
	fs.StringVar(&req.Label, "label", "home", "home label: history and diffs are kept per label, not per IP")
	fs.BoolVar(&quick, "quick", false, "scan only the curated quick port set (default: all 65535)")
	fs.StringVar(&portsSpec, "ports", "", "explicit port list, e.g. \"22,80,8000-8010\" (overrides --quick)")
	fs.BoolVar(&noUDP, "no-udp", false, "skip the small home UDP probe set")
	fs.BoolVar(&withUDP, "udp", false, "with --ports: also run the UDP probe set (on by default for full and quick scans)")
	fs.BoolVar(&req.Offline, "offline", false, "no third-party lookups: no ASN/PTR profile, no egress self-check")
	fs.IntVar(&timeoutMS, "timeout", 0, "per-connection timeout in ms (default: adaptive from measured RTT)")
	fs.IntVar(&req.Concurrency, "concurrency", scan.DefaultConcurrency, "max concurrent connection attempts")
	fs.IntVar(&req.Rate, "rate", scan.DefaultRate, "max new connections per second")
	fs.BoolVar(&req.NoRetry, "no-retry", false, "skip the slower second pass over scattered filtered ports")
	fs.StringVar(&dataDir, "data-dir", envOr("WANHOUND_DATA", ""), "snapshot directory (default ~/.local/share/wanhound)")
	fs.BoolVar(&jsonOut, "json", false, "print the machine-readable audit JSON instead of the report")
	fs.StringVar(&htmlOut, "html", "", "also write a standalone HTML report to this file")
	fs.BoolVar(&noColor, "no-color", false, "disable colored output")
	fs.BoolVar(&yes, "yes", false, "continue even if this machine looks like it is inside the target network")
	fs.BoolVar(&req.Lab, "lab", false, "test bench only: allow loopback/private targets")
	fs.StringVar(&tgToken, "telegram-token", os.Getenv("WANHOUND_TELEGRAM_TOKEN"), "Telegram bot token for a result push")
	fs.StringVar(&tgChat, "telegram-chat", os.Getenv("WANHOUND_TELEGRAM_CHAT"), "Telegram chat ID for a result push")
	fs.StringVar(&notify, "notify", "alert", "when to push to Telegram: alert (exit code 1) | always")
	fs.StringVar(&lang, "lang", i18n.FromEnv(), "report language: en | zh (default from WANHOUND_LANG / LANG)")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "scan: unexpected argument %q (WanHound audits one --ipv4 and/or one --ipv6 address)\n", fs.Arg(0))
		return exitError(2)
	}
	req.UDP = !noUDP
	lang = i18n.Normalize(lang)
	req.Lang = lang
	req.AcceptInside = yes
	req.Timeout = time.Duration(timeoutMS) * time.Millisecond
	switch {
	case portsSpec != "":
		ports, err := scan.ParsePorts(portsSpec)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
			return exitError(2)
		}
		req.PortSet, req.Ports = "custom", ports
		req.UDP = withUDP && !noUDP // custom lists: UDP only when asked
	case quick:
		req.PortSet = "quick"
	default:
		req.PortSet = "full"
	}
	if err := req.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
		return exitError(2)
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tty := isTerminal(os.Stderr)
	rep, err := audit.Run(ctx, st, req, audit.Hooks{
		Progress:      progressPrinter(tty),
		ConfirmInside: func(target string, why i18n.Msg) bool { return confirmInside(target, why.Render(lang)) },
	})
	if tty {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "scan cancelled; nothing saved")
			return exitError(2)
		}
		return err
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
	} else {
		report.Print(os.Stdout, rep, !noColor && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout), lang)
	}
	if htmlOut != "" {
		if err := writeHTML(htmlOut, rep, lang); err != nil {
			fmt.Fprintln(os.Stderr, "html:", err)
		} else if !jsonOut {
			fmt.Fprintln(os.Stderr, "HTML report written to", htmlOut)
		}
	}
	if tgToken != "" && tgChat != "" && (notify == "always" || rep.ExitCode == 1) {
		if err := sendTelegram(ctx, tgToken, tgChat, report.Summary(rep, lang)); err != nil {
			fmt.Fprintln(os.Stderr, "telegram:", err)
		}
	}
	return exitError(rep.ExitCode)
}

func writeHTML(path string, rep *audit.Report, lang string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := report.HTML(f, rep, lang); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func progressPrinter(tty bool) func(audit.Event) {
	lastPct := -1
	return func(e audit.Event) {
		switch {
		case e.Stage == "done":
		case e.Message != "":
			if tty {
				fmt.Fprint(os.Stderr, "\r\033[K")
			}
			fmt.Fprintf(os.Stderr, "%s: %s\n", e.Target, e.Message)
			lastPct = -1
		case e.Stage == "tcp" && e.Total > 0:
			pct := e.Done * 100 / e.Total
			if tty {
				fmt.Fprintf(os.Stderr, "\r\033[K%s: %3d%%  %d/%d", e.Target, pct, e.Done, e.Total)
			} else if pct/10 != lastPct/10 {
				fmt.Fprintf(os.Stderr, "%s: %d%%\n", e.Target, pct)
			}
			lastPct = pct
		}
	}
}

func confirmInside(target, why string) bool {
	fmt.Fprintf(os.Stderr, "\nwarning: %s — %s.\n", target, why)
	if !isTerminal(os.Stdin) {
		fmt.Fprintln(os.Stderr, "Not a terminal: refusing to continue (pass --yes to override).")
		return false
	}
	fmt.Fprint(os.Stderr, "Results from inside are distorted. Continue anyway? [y/N] ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func runHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	label := fs.String("label", "", "show snapshots for this label (default: list labels)")
	dataDir := fs.String("data-dir", envOr("WANHOUND_DATA", ""), "snapshot directory")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	st, err := store.Open(*dataDir)
	if err != nil {
		return err
	}
	if *label == "" {
		labels, err := st.Labels()
		if err != nil {
			return err
		}
		if len(labels) == 0 {
			fmt.Println("No snapshots yet. Run: wanhound scan --ipv4 <addr> --label home")
		}
		for _, l := range labels {
			snaps, _ := st.List(l)
			fmt.Printf("%-24s %d snapshot(s)\n", l, len(snaps))
		}
		return nil
	}
	snaps, err := st.List(*label)
	if err != nil {
		return err
	}
	for _, s := range snaps {
		m := store.MetaOf(s)
		line := fmt.Sprintf("%s  %-28s IP%s %-40s %-6s open=%-3d worst=%-6s", m.Time.Local().Format("2006-01-02 15:04"), m.ID, m.Family, m.IP, m.PortSet, m.Counts.Open, m.MaxRisk)
		if m.IPChange != "" {
			line += "  address " + m.IPChange
		}
		if len(m.Opened) > 0 {
			line += "  NEW " + report.JoinInts(m.Opened)
		}
		if len(m.Closed) > 0 {
			line += "  closed " + report.JoinInts(m.Closed)
		}
		fmt.Println(line)
	}
	return nil
}

func runDelete(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	label := fs.String("label", "", "label to delete from")
	id := fs.String("id", "", "delete one snapshot")
	keep := fs.Int("keep", 0, "keep only the newest N snapshots per address family")
	all := fs.Bool("all", false, "delete the label and its whole history")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	dataDir := fs.String("data-dir", envOr("WANHOUND_DATA", ""), "snapshot directory")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	modes := 0
	for _, on := range []bool{*id != "", *keep > 0, *all} {
		if on {
			modes++
		}
	}
	if *label == "" || modes != 1 {
		fmt.Fprintln(os.Stderr, "delete: give --label and exactly one of --id, --keep or --all")
		return exitError(2)
	}
	st, err := store.Open(*dataDir)
	if err != nil {
		return err
	}
	snaps, err := st.List(*label)
	if err != nil {
		return err
	}
	if len(snaps) == 0 {
		return fmt.Errorf("no snapshots under label %q", *label)
	}
	if !*yes {
		what := fmt.Sprintf("all %d snapshot(s) of label %q", len(snaps), *label)
		if *id != "" {
			what = fmt.Sprintf("snapshot %s of label %q", *id, *label)
		} else if *keep > 0 {
			what = fmt.Sprintf("all but the newest %d snapshot(s) per family of label %q", *keep, *label)
		}
		if !isTerminal(os.Stdin) {
			fmt.Fprintf(os.Stderr, "delete: would delete %s; pass --yes to confirm\n", what)
			return exitError(2)
		}
		fmt.Fprintf(os.Stderr, "Delete %s? This cannot be undone. [y/N] ", what)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return exitError(2)
		}
	}
	switch {
	case *id != "":
		err = st.Delete(*label, *id)
		if err == nil {
			fmt.Println("deleted", *id)
		}
	case *keep > 0:
		var n int
		n, err = st.Prune(*label, *keep)
		fmt.Printf("deleted %d snapshot(s)\n", n)
	default:
		err = st.DeleteLabel(*label)
		if err == nil {
			fmt.Printf("deleted label %q\n", *label)
		}
	}
	return err
}

func runAccept(args []string) error {
	fs := flag.NewFlagSet("accept", flag.ContinueOnError)
	label := fs.String("label", "home", "label the finding belongs to")
	rule := fs.String("rule", "", "rule ID of the finding, e.g. KU-001")
	port := fs.Int("port", 0, "port of the finding (0 for whole-target KC-* findings)")
	reason := fs.String("reason", "", "why this risk is acceptable for now (required)")
	days := fs.Int("days", 30, fmt.Sprintf("how long the acceptance lasts (1-%d days)", store.MaxAcceptDays))
	list := fs.Bool("list", false, "list accepted risks")
	remove := fs.String("remove", "", "remove an accepted risk by ID")
	dataDir := fs.String("data-dir", envOr("WANHOUND_DATA", ""), "snapshot directory")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	st, err := store.Open(*dataDir)
	if err != nil {
		return err
	}
	switch {
	case *list:
		as, err := st.Acceptances()
		if err != nil {
			return err
		}
		if len(as) == 0 {
			fmt.Println("No accepted risks.")
		}
		now := time.Now()
		for _, a := range as {
			state := "active"
			if !a.Active(now) {
				state = "EXPIRED"
			}
			fmt.Printf("%s  %-7s %-24s %-7s port %-5d until %s  %s\n", a.ID, state, a.Label, a.RuleID, a.Port, a.Until.Local().Format("2006-01-02"), a.Reason)
		}
		return nil
	case *remove != "":
		if err := st.Unaccept(*remove); err != nil {
			return err
		}
		fmt.Println("removed", *remove)
		return nil
	}
	if *rule == "" {
		fmt.Fprintln(os.Stderr, "accept: give --rule (and --port, --reason), or --list / --remove")
		return exitError(2)
	}
	if !knowledge.KnownID(*rule) {
		return fmt.Errorf("unknown rule %q (see `wanhound rules`)", *rule)
	}
	a, err := st.Accept(*label, *rule, *port, *reason, *days)
	if err != nil {
		return err
	}
	fmt.Printf("accepted %s on port %d for label %q until %s (id %s)\n", a.RuleID, a.Port, a.Label, a.Until.Local().Format("2006-01-02"), a.ID)
	fmt.Println("It stays in reports, marked as accepted, but no longer raises the exit code or Telegram alerts.")
	return nil
}

func runShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	label := fs.String("label", "home", "label")
	id := fs.String("id", "", "snapshot ID (default: latest)")
	jsonOut := fs.Bool("json", false, "print the snapshot JSON")
	htmlOut := fs.String("html", "", "write a standalone HTML report to this file")
	dataDir := fs.String("data-dir", envOr("WANHOUND_DATA", ""), "snapshot directory")
	lang := fs.String("lang", i18n.FromEnv(), "report language: en | zh")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	st, err := store.Open(*dataDir)
	if err != nil {
		return err
	}
	acc, _ := st.Acceptances()
	var snap *store.Snapshot
	if *id != "" {
		snap, err = st.Get(*label, *id)
	} else {
		var all []*store.Snapshot
		all, err = st.List(*label)
		if len(all) > 0 {
			snap = all[len(all)-1]
		}
	}
	if err != nil {
		return err
	}
	if snap == nil {
		return fmt.Errorf("no snapshots under label %q", *label)
	}
	store.ApplyAcceptances(snap.Findings, snap.Label, acc, time.Now()) // show the current decisions
	rep := &audit.Report{Label: snap.Label, Started: snap.Time, Duration: snap.Duration,
		RulesVersion: snap.RulesVersion, Targets: []*store.Snapshot{snap}, Offline: snap.Intel == nil}
	switch {
	case *htmlOut != "":
		return writeHTML(*htmlOut, rep, *lang)
	case *jsonOut:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	default:
		report.Print(os.Stdout, rep, os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout), *lang)
	}
	return nil
}

func runRules() error {
	fmt.Printf("WanHound rule base %s\n\n", knowledge.Version())
	for _, r := range knowledge.Rules() {
		m := r.Match
		cond := m.Proto
		if len(m.Ports) > 0 {
			cond += " " + report.JoinInts(m.Ports)
		} else {
			cond += " any port"
		}
		var ev []string
		for k, v := range map[string]string{"banner": m.Banner, "title": m.Title, "server": m.Server, "cert": m.Cert, "auth": m.Auth, "detail": m.Detail, "any": m.Any} {
			if v != "" {
				ev = append(ev, k)
			}
		}
		sort.Strings(ev)
		if m.HTTP != nil && *m.HTTP {
			ev = append(ev, "http")
		}
		if m.TLS != nil {
			ev = append(ev, fmt.Sprintf("tls=%v", *m.TLS))
		}
		if len(ev) > 0 {
			cond += " + " + strings.Join(ev, ",")
		}
		fmt.Printf("%-7s %-7s %-34s %s\n", r.ID, r.Risk, cond, r.Title)
	}
	return nil
}

func runHashPassword() error {
	fmt.Fprint(os.Stderr, "Password (read from stdin): ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return err
	}
	pw := strings.TrimRight(line, "\r\n")
	if len(pw) < 10 {
		return fmt.Errorf("use at least 10 characters")
	}
	fmt.Fprintln(os.Stderr)
	fmt.Println(web.HashPassword(pw))
	return nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var o web.Options
	fs.StringVar(&o.Addr, "addr", "127.0.0.1:8687", "listen address")
	fs.StringVar(&o.DataDir, "data-dir", envOr("WANHOUND_DATA", ""), "snapshot + audit-log directory")
	fs.IntVar(&o.ScansPerHour, "scans-per-hour", 6, "global cap on audits started per hour")
	fs.BoolVar(&o.Lab, "lab", false, "test bench only: allow loopback/private targets")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	o.Password = os.Getenv("WANHOUND_PASSWORD")
	o.PasswordHash = os.Getenv("WANHOUND_PASSWORD_HASH")
	o.Version = version
	return web.Serve(o)
}

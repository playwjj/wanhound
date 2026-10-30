// WanHound — audit your own home network's public exposure.
//
//	wanhound scan  --ipv4 203.0.113.7 [--ipv6 2001:db8::7] [--label home]
//	wanhound serve --addr 127.0.0.1:8687 --password <secret>
//
// scan exit codes: 0 = no high-risk findings, 1 = high-risk finding
// or newly opened ports vs the last snapshot, 2 = the audit itself
// could not run (bad input, unscannable address class).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/playwjj/wanhound/internal/intel"
	"github.com/playwjj/wanhound/internal/knowledge"
	"github.com/playwjj/wanhound/internal/probe"
	"github.com/playwjj/wanhound/internal/report"
	"github.com/playwjj/wanhound/internal/scan"
	"github.com/playwjj/wanhound/internal/store"
	"github.com/playwjj/wanhound/internal/web"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "scan":
		err = runScan(os.Args[2:])
		if err != nil {
			if code, ok := err.(exitError); ok {
				os.Exit(int(code))
			}
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
	case "serve":
		err = runServe(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func usage() {
	fmt.Fprintf(os.Stderr, `WanHound — audit your own home network's public exposure.

Usage:
  wanhound scan  --ipv4 <addr> [--ipv6 <addr>] [options]
  wanhound serve --addr <host:port> --password <secret>

Only audit addresses you own or are authorized to test.
Run scan from OUTSIDE the network being audited (e.g. a VPS).
`)
}

type scanFlags struct {
	ipv4, ipv6  string
	label       string
	quick       bool
	portsSpec   string
	offline     bool
	timeoutMS   int
	concurrency int
	dataDir     string
	jsonOut     bool
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var f scanFlags
	fs.StringVar(&f.ipv4, "ipv4", "", "public IPv4 address to audit")
	fs.StringVar(&f.ipv6, "ipv6", "", "public IPv6 address to audit")
	fs.StringVar(&f.label, "label", "home", "snapshot label for this home (history/diff key)")
	fs.BoolVar(&f.quick, "quick", false, "scan only the curated quick port set (default: all 65535)")
	fs.StringVar(&f.portsSpec, "ports", "", "explicit port list, e.g. \"22,80,8000-8010\" (overrides --quick)")
	fs.BoolVar(&f.offline, "offline", false, "no third-party lookups (address intel stays local)")
	fs.IntVar(&f.timeoutMS, "timeout", 1000, "per-connection timeout, milliseconds")
	fs.IntVar(&f.concurrency, "concurrency", 256, "max concurrent probes")
	fs.StringVar(&f.dataDir, "data-dir", "", "snapshot directory (default: ~/.local/share/wanhound)")
	fs.BoolVar(&f.jsonOut, "json", false, "print the machine-readable audit JSON instead of the table")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	if f.ipv4 == "" && f.ipv6 == "" {
		fmt.Fprintln(os.Stderr, "scan: provide at least one of --ipv4 / --ipv6")
		return exitError(2)
	}

	ports, err := choosePorts(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
		return exitError(2)
	}
	st, err := store.Open(f.dataDir)
	if err != nil {
		return err
	}

	targets := []struct{ name, addr string }{{"ipv4", f.ipv4}, {"ipv6", f.ipv6}}
	scanned := 0
	worst := 0
	for _, t := range targets {
		if t.addr == "" {
			continue
		}
		code, err := auditOne(st, f, t.addr, ports)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan %s: %v\n", t.addr, err)
			continue
		}
		scanned++
		if code > worst {
			worst = code
		}
	}
	if scanned == 0 {
		return exitError(2)
	}
	return exitError(worst)
}

// auditOne audits a single address and returns its exit code.
func auditOne(st *store.Store, f scanFlags, addr string, ports []int) (int, error) {
	_, class, err := intel.Classify(addr)
	if err != nil {
		return 2, err
	}
	if ok, why := intel.Scannable(class); !ok {
		fmt.Fprintf(os.Stderr, "%s: not auditing — %s\n", addr, why)
		return 2, fmt.Errorf("address class %s is not auditable", class)
	}
	// TODO(P1): egress self-check — if this machine's public egress
	// equals the target, warn that NAT hairpin may distort results.
	// TODO(P1): optional online intel (ASN/ISP) unless --offline.

	opts := scan.Options{
		Ports:       ports,
		Concurrency: f.concurrency,
		Timeout:     time.Duration(f.timeoutMS) * time.Millisecond,
	}
	lastPct := -1
	progress := func(done, total int) {
		pct := done * 100 / total
		if pct/10 != lastPct/10 {
			lastPct = pct
			fmt.Fprintf(os.Stderr, "\r%s: scanning… %d%%", addr, pct)
		}
	}
	res := scan.Scan(context.Background(), addr, opts, progress)
	fmt.Fprintln(os.Stderr)

	// Identify services on open ports and map to findings.
	evidence := map[int]string{}
	var probes []probe.Info
	var findings []knowledge.Finding
	for _, pr := range res.Open() {
		info := probe.Probe(addr, pr.Port, 2*time.Second)
		probes = append(probes, info)
		ev := evidenceOf(info)
		evidence[pr.Port] = ev
		findings = append(findings, knowledge.Lookup(pr.Port, ev)...)
	}
	knowledge.SortFindings(findings)

	snap := store.FromScan(f.label, res, probes)
	prev, err := st.Latest(f.label + "-" + addrFamily(addr))
	if err != nil {
		return 2, err
	}
	ch := store.Diff(prev, snap)
	if err := st.Save(withKey(snap, f.label+"-"+addrFamily(addr))); err != nil {
		return 2, err
	}

	if f.jsonOut {
		out := map[string]any{
			"label": f.label, "ip": addr, "time": snap.Time,
			"open": snap.Open, "findings": findings, "changes": ch,
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
	} else {
		report.Print(os.Stdout, f.label, res, findings, evidence, ch, prev != nil)
	}
	return report.ExitCode(findings, ch), nil
}

// Snapshots are keyed label+family so the v4 and v6 histories of the
// same home do not clobber each other.
func addrFamily(addr string) string {
	if ip, _, err := intel.Classify(addr); err == nil && ip.To4() == nil {
		return "v6"
	}
	return "v4"
}

func withKey(snap store.Snapshot, key string) store.Snapshot {
	snap.Label = key
	return snap
}

func evidenceOf(info probe.Info) string {
	switch {
	case info.Title != "":
		return fmt.Sprintf("title=%q server=%q", info.Title, info.Server)
	case info.TLS:
		return fmt.Sprintf("tls cert CN=%q SANs=%v", info.CertCN, info.CertSANs)
	case info.Banner != "":
		return "banner=" + info.Banner
	default:
		return ""
	}
}

func choosePorts(f scanFlags) ([]int, error) {
	if f.portsSpec != "" {
		return scan.ParsePorts(f.portsSpec)
	}
	if f.quick {
		return scan.QuickPorts, nil
	}
	return scan.FullPorts(), nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var addr, password string
	fs.StringVar(&addr, "addr", "127.0.0.1:8687", "listen address")
	fs.StringVar(&password, "password", "", "access password (required; or WANHOUND_PASSWORD)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if password == "" {
		password = os.Getenv("WANHOUND_PASSWORD")
	}
	return web.Serve(web.Options{Addr: addr, Password: password})
}

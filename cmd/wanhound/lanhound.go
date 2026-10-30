package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/playwjj/wanhound/internal/audit"
	"github.com/playwjj/wanhound/internal/i18n"
	"github.com/playwjj/wanhound/internal/knowledge"
	"github.com/playwjj/wanhound/internal/lanhound"
	"github.com/playwjj/wanhound/internal/report"
	"github.com/playwjj/wanhound/internal/scan"
	"github.com/playwjj/wanhound/internal/store"
)

// runScanLanHound audits the public IPv6 address of every device in a
// LanHound export, one device at a time, each under its own label.
func runScanLanHound(args []string) error {
	fs := flag.NewFlagSet("scan-lanhound", flag.ContinueOnError)
	var (
		csvPath, label, dataDir, lang string
		quick, all, yes, dryRun, full bool
		noUDP, offline                bool
		max                           int
	)
	fs.StringVar(&csvPath, "csv", "", "LanHound device export (devices.csv from LanHound's device table)")
	fs.StringVar(&label, "label", "home", "home label; each device is kept as \"<label> · <device>\"")
	fs.BoolVar(&quick, "quick", false, "scan the quick port set instead of all 65535 ports")
	fs.BoolVar(&all, "all-addresses", false, "audit every public IPv6 of each device, not just the most recent")
	fs.IntVar(&max, "max", 32, "refuse to start when the export yields more targets than this")
	fs.BoolVar(&yes, "yes", false, "do not ask for confirmation")
	fs.BoolVar(&dryRun, "dry-run", false, "only list the targets")
	fs.BoolVar(&full, "full", false, "print the full report of every device (default: one summary line each)")
	fs.BoolVar(&noUDP, "no-udp", false, "skip the UDP probe set")
	fs.BoolVar(&offline, "offline", false, "no third-party lookups")
	fs.StringVar(&dataDir, "data-dir", envOr("WANHOUND_DATA", ""), "snapshot directory")
	fs.StringVar(&lang, "lang", i18n.FromEnv(), "report language: en | zh")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	lang = i18n.Normalize(lang)
	if csvPath == "" {
		fmt.Fprintln(os.Stderr, "scan-lanhound: --csv is required")
		return exitError(2)
	}
	f, err := os.Open(csvPath)
	if err != nil {
		return err
	}
	targets, err := lanhound.Parse(f, all)
	f.Close()
	if err != nil {
		return err
	}
	zh := lang == i18n.ZH
	say := func(en, cn string, a ...any) {
		if zh {
			fmt.Fprintf(os.Stderr, cn, a...)
		} else {
			fmt.Fprintf(os.Stderr, en, a...)
		}
	}
	if len(targets) == 0 {
		say("No device in the export has a public IPv6 address — nothing to audit.\n", "导出文件中没有任何设备拥有公网 IPv6 地址——无需审计。\n")
		return nil
	}
	say("%d device address(es) from the LanHound export, audited one at a time:\n", "从 LanHound 导出中得到 %d 个设备地址，将逐个审计：\n", len(targets))
	for _, t := range targets {
		fmt.Fprintf(os.Stderr, "  %-40s %s\n", t.IPv6, t.Device)
	}
	say("Note: IPv6 privacy (temporary) addresses rotate; an address LanHound saw a while ago may no longer be in use.\n",
		"注意：IPv6 隐私（临时）地址会轮换，LanHound 较早看到的地址可能已不再使用。\n")
	if dryRun {
		return nil
	}
	if len(targets) > max {
		say("Refusing: %d targets exceed --max %d. Raise --max if this is really your network.\n", "已拒绝：%d 个目标超过 --max %d。如果确实是你自己的网络，请调高 --max。\n", len(targets), max)
		return exitError(2)
	}
	if !yes {
		if !isTerminal(os.Stdin) {
			say("Not a terminal: pass --yes to confirm.\n", "非交互终端：请加 --yes 确认。\n")
			return exitError(2)
		}
		say("Audit these addresses? Only continue if they are yours. [y/N] ", "审计这些地址？仅在它们属于你时继续。[y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return exitError(2)
		}
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := 0
	color := os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout)
	for i, t := range targets {
		req := audit.Request{IPv6: t.IPv6, Label: lanhound.Label(label, t.Device), UDP: !noUDP, Offline: offline,
			Lang: lang, Concurrency: scan.DefaultConcurrency, Rate: scan.DefaultRate}
		if quick {
			req.PortSet = "quick"
		}
		say("\n[%d/%d] %s (%s)\n", "\n[%d/%d] %s（%s）\n", i+1, len(targets), t.Device, t.IPv6)
		rep, err := audit.Run(ctx, st, req, audit.Hooks{Progress: progressPrinter(isTerminal(os.Stderr))})
		if isTerminal(os.Stderr) {
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
		if err != nil {
			if ctx.Err() != nil {
				say("cancelled\n", "已取消\n")
				return exitError(2)
			}
			return err
		}
		if full {
			report.Print(os.Stdout, rep, color, lang)
		} else {
			printDeviceLine(t, rep, lang)
		}
		switch {
		case rep.ExitCode == 1:
			code = 1
		case rep.ExitCode == 2 && code == 0:
			code = 2
		}
	}
	return exitError(code)
}

func printDeviceLine(t lanhound.Target, rep *audit.Report, lang string) {
	if len(rep.Targets) == 0 {
		for _, e := range rep.Errors {
			fmt.Printf("%-24s %-40s %s\n", t.Device, t.IPv6, e.Reason.Render(lang))
		}
		return
	}
	s := rep.Targets[0]
	worst := "none"
	if len(s.Findings) > 0 {
		worst = knowledge.MaxRisk(s.Findings).String()
	}
	line := fmt.Sprintf("%-24s %-40s %s=%d %s=%s", t.Device, t.IPv6, i18n.T(lang, "h.open"), s.Counts.Open,
		i18n.T(lang, "r.col_risk"), i18n.T(lang, "risk."+worst))
	if c := s.Changes; c != nil && len(c.Opened) > 0 {
		line += "  " + i18n.T(lang, "s.new", report.JoinInts(c.Opened))
	}
	fmt.Println(line)
}

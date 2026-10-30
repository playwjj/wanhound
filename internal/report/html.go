package report

import (
	_ "embed"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/wanhound/internal/audit"
	"github.com/playwjj/wanhound/internal/knowledge"
	"github.com/playwjj/wanhound/internal/store"
)

//go:embed report.html.tmpl
var htmlTmpl string

var page = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
	"risk":  func(r knowledge.Risk) string { return r.String() },
	"maxrisk": func(fs []knowledge.Finding) string {
		if len(fs) == 0 {
			return "none"
		}
		return knowledge.MaxRisk(fs).String()
	},
	"when":  func(t time.Time) string { return t.Local().Format("2006-01-02 15:04 MST") },
	"dur":   func(d time.Duration) string { return d.Round(time.Second).String() },
	"ms":    func(d time.Duration) string { return d.Round(time.Millisecond).String() },
	"ints":  JoinInts,
	"spec":  shortSpec,
	"conf":  confidenceText,
	"where": where,
}).Parse(htmlTmpl))

func where(f knowledge.Finding) string {
	if f.Port == 0 {
		return "whole target"
	}
	return strconv.Itoa(f.Port) + "/" + f.Proto
}

// HTML writes a standalone, printable one-page report (no external
// assets) for archiving or showing the family.
func HTML(w io.Writer, rep *audit.Report) error {
	return page.Execute(w, rep)
}

// SnapshotHTML renders a single stored snapshot as a report page.
func SnapshotHTML(w io.Writer, s *store.Snapshot, offline bool) error {
	rep := &audit.Report{Label: s.Label, Started: s.Time, Duration: s.Duration, Offline: offline,
		RulesVersion: s.RulesVersion, Targets: []*store.Snapshot{s}}
	return HTML(w, rep)
}

package report

import (
	_ "embed"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/wanhound/internal/audit"
	"github.com/playwjj/wanhound/internal/i18n"
	"github.com/playwjj/wanhound/internal/knowledge"
	"github.com/playwjj/wanhound/internal/store"
)

//go:embed report.html.tmpl
var htmlTmpl string

var page = template.Must(template.New("report").Funcs(template.FuncMap{
	"t":     func(lang, key string, args ...any) string { return i18n.T(lang, key, args...) },
	"upper": strings.ToUpper,
	"risk":  func(r knowledge.Risk) string { return r.String() },
	"maxrisk": func(fs []knowledge.Finding) string {
		if len(fs) == 0 {
			return "none"
		}
		return knowledge.MaxRisk(fs).String()
	},
	"when":   func(t time.Time) string { return t.Local().Format("2006-01-02 15:04 MST") },
	"dur":    func(d time.Duration) string { return d.Round(time.Second).String() },
	"ms":     func(d time.Duration) string { return d.Round(time.Millisecond).String() },
	"ints":   JoinInts,
	"spec":   shortSpec,
	"render": func(m i18n.Msg, lang string) string { return m.Render(lang) },
	"where": func(f knowledge.Finding, lang string) string {
		if f.Port == 0 {
			return i18n.T(lang, "whole")
		}
		return strconv.Itoa(f.Port) + "/" + f.Proto
	},
}).Parse(htmlTmpl))

// view is what the template sees: the report with its targets already
// localized, plus the language.
type view struct {
	*audit.Report
	Lang string
}

// HTML writes a standalone, printable one-page report (no external
// assets) in lang, for archiving or showing the family.
func HTML(w io.Writer, rep *audit.Report, lang string) error {
	lang = i18n.Normalize(lang)
	r := *rep
	r.Targets = nil
	for _, s := range rep.Targets {
		r.Targets = append(r.Targets, s.Localized(lang))
	}
	return page.Execute(w, view{Report: &r, Lang: lang})
}

// SnapshotHTML renders a single stored snapshot as a report page.
func SnapshotHTML(w io.Writer, s *store.Snapshot, offline bool, lang string) error {
	rep := &audit.Report{Label: s.Label, Started: s.Time, Duration: s.Duration, Offline: offline,
		RulesVersion: s.RulesVersion, Targets: []*store.Snapshot{s}}
	return HTML(w, rep, lang)
}

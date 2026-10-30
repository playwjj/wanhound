// Package knowledge maps scan evidence to plain-language findings
// using a curated, versioned rule base (rules.json, embedded).
//
// Every rule has the same shape: a match condition (protocol, port
// list, and optional evidence patterns — banner, HTTP title/server,
// TLS certificate, auth challenge) → risk, explanation, advice and a
// stable rule ID. Reports cite the ID so a reader can trace exactly
// why the report said what it said.
//
// Rules are deliberately conservative: a finding states what the
// evidence supports ("a database port is reachable"), never a
// vulnerability claim. Rules sharing a group are alternatives for
// the same port: the first match in file order wins, so specific
// evidence rules come before port-number fallbacks.
//
// Combination rules (KC-*) then look at a target's findings as a
// whole — router management exposed, databases on a home line, many
// open ports (DMZ host?), IPv6 hits with no NAT in front.
package knowledge

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/playwjj/wanhound/internal/i18n"
	"github.com/playwjj/wanhound/internal/probe"
	"github.com/playwjj/wanhound/internal/scan"
)

// Risk ranks findings. Higher is worse.
type Risk int

const (
	RiskInfo Risk = iota
	RiskLow
	RiskMedium
	RiskHigh
)

func (r Risk) String() string {
	switch r {
	case RiskHigh:
		return "high"
	case RiskMedium:
		return "medium"
	case RiskLow:
		return "low"
	default:
		return "info"
	}
}

func (r Risk) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

func (r *Risk) UnmarshalText(b []byte) error {
	v, ok := parseRisk(string(b))
	if !ok {
		return fmt.Errorf("unknown risk %q", b)
	}
	*r = v
	return nil
}

func parseRisk(s string) (Risk, bool) {
	switch s {
	case "high":
		return RiskHigh, true
	case "medium":
		return RiskMedium, true
	case "low":
		return RiskLow, true
	case "info":
		return RiskInfo, true
	}
	return RiskInfo, false
}

// Match is a rule's condition. All present fields must hold. String
// fields are regular expressions; "Any" is matched against all the
// identifying text at once (banner, HTTP title/server/auth, TLS names).
type Match struct {
	Proto      string `json:"proto,omitempty"` // "tcp" (default) or "udp"
	Ports      []int  `json:"ports,omitempty"` // empty = any port
	Banner     string `json:"banner,omitempty"`
	Title      string `json:"title,omitempty"`
	Server     string `json:"server,omitempty"`
	Cert       string `json:"cert,omitempty"` // TLS CN, SANs, issuer
	Auth       string `json:"auth,omitempty"` // WWW-Authenticate
	Detail     string `json:"detail,omitempty"`
	Any        string `json:"any,omitempty"`
	HTTP       *bool  `json:"http,omitempty"`
	TLS        *bool  `json:"tls,omitempty"`
	TLSExpired *bool  `json:"tls_expired,omitempty"`
	SelfSigned *bool  `json:"self_signed,omitempty"`

	re map[string]*regexp.Regexp
}

// Rule is one knowledge-base entry for a single port/service.
type Rule struct {
	ID      string   `json:"id"`
	Group   string   `json:"group"`
	Service string   `json:"service"`
	Risk    string   `json:"risk"`
	Title   string   `json:"title"`
	Explain string   `json:"explain"`
	Advice  string   `json:"advice"`
	Tags    []string `json:"tags,omitempty"`
	Match   Match    `json:"match"`
}

// Combo is a whole-target rule evaluated over the port findings.
type Combo struct {
	ID      string `json:"id"`
	Risk    string `json:"risk"`
	Title   string `json:"title"`
	Explain string `json:"explain"`
	Advice  string `json:"advice"`
	When    struct {
		TagsAny []string `json:"tags_any,omitempty"`
		Family  string   `json:"family,omitempty"`   // "v4" | "v6"
		MinOpen int      `json:"min_open,omitempty"` // open TCP ports
	} `json:"when"`
}

// Base is the whole rule base.
type Base struct {
	Version string  `json:"version"`
	Rules   []Rule  `json:"rules"`
	Combos  []Combo `json:"combos"`
}

// Finding is a rule matched against one open port (Port 0 = a
// whole-target combination finding), with the evidence behind it.
type Finding struct {
	RuleID  string `json:"rule_id"`
	Port    int    `json:"port,omitempty"`
	Proto   string `json:"proto,omitempty"`
	Service string `json:"service"`
	Risk    Risk   `json:"risk"`
	Title   string `json:"title"`
	Explain string `json:"explain"`
	Advice  string `json:"advice"`
	// Evidence is the probe output (banner, TLS names, HTTP title)
	// that supports the finding; may be empty.
	Evidence string `json:"evidence,omitempty"`
	// Confidence: "high" when identifying evidence (banner, title,
	// certificate…) matched, "medium" when only the protocol was
	// recognized (it speaks HTTP/TLS), "low" for port number alone.
	Confidence string   `json:"confidence,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	// Accepted is set when the user has recorded this risk as known and
	// accepted: the finding is still reported, but no longer counts
	// towards the worst risk or the alert exit code.
	Accepted *Acceptance `json:"accepted,omitempty"`
}

// Acceptance is the user's record that a finding is a known risk.
type Acceptance struct {
	ID     string    `json:"id"`
	Reason string    `json:"reason"`
	Until  time.Time `json:"until"`
}

//go:embed rules.json
var rulesJSON []byte

// rules.zh.json holds the Simplified Chinese service/title/explain/advice
// for every rule and combo ID; findings are localized at render time.
//
//go:embed rules.zh.json
var rulesZH []byte

// Text is the translatable part of a rule.
type Text struct {
	Service string `json:"service,omitempty"`
	Title   string `json:"title"`
	Explain string `json:"explain"`
	Advice  string `json:"advice"`
}

var (
	base         Base
	translations = map[string]map[string]Text{}
)

func init() {
	b, err := Parse(rulesJSON)
	if err != nil {
		panic(fmt.Sprintf("knowledge: built-in rules.json is invalid: %v", err))
	}
	base = *b
	zh := map[string]Text{}
	if err := json.Unmarshal(rulesZH, &zh); err != nil {
		panic(fmt.Sprintf("knowledge: built-in rules.zh.json is invalid: %v", err))
	}
	translations[i18n.ZH] = zh
}

// Translation returns the rule text for id in lang, if there is one.
func Translation(lang, id string) (Text, bool) {
	t, ok := translations[i18n.Normalize(lang)][id]
	return t, ok
}

// Localize returns f with its human text in lang. Unknown-port findings
// (KH-000) are rendered from the message catalog.
func Localize(f Finding, lang string) Finding {
	lang = i18n.Normalize(lang)
	switch {
	case f.RuleID == "KH-000":
		f.Service = i18n.T(lang, "rule.unknown.service")
		f.Title = i18n.T(lang, "rule.unknown.title", fmt.Sprint(f.Port))
		f.Explain = i18n.T(lang, "rule.unknown.explain")
		f.Advice = i18n.T(lang, "rule.unknown.advice")
	case lang != i18n.EN:
		if t, ok := Translation(lang, f.RuleID); ok {
			if t.Service != "" {
				f.Service = t.Service
			}
			f.Title, f.Explain, f.Advice = t.Title, t.Explain, t.Advice
		}
	}
	if f.Port == 0 {
		f.Service = i18n.T(lang, "whole")
		if ports, ok := strings.CutPrefix(f.Evidence, "ports "); ok {
			f.Evidence = i18n.T(lang, "f.ports", ports)
		}
	}
	return f
}

// LocalizeAll localizes a slice of findings (copy).
func LocalizeAll(fs []Finding, lang string) []Finding {
	out := make([]Finding, len(fs))
	for i, f := range fs {
		out[i] = Localize(f, lang)
	}
	return out
}

// Parse loads and validates a rule base.
func Parse(data []byte) (*Base, error) {
	var b Base
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if b.Version == "" {
		return nil, fmt.Errorf("missing version")
	}
	seen := map[string]bool{}
	for i := range b.Rules {
		r := &b.Rules[i]
		if r.ID == "" || seen[r.ID] {
			return nil, fmt.Errorf("rule %d: missing or duplicate id %q", i, r.ID)
		}
		seen[r.ID] = true
		if _, ok := parseRisk(r.Risk); !ok {
			return nil, fmt.Errorf("%s: bad risk %q", r.ID, r.Risk)
		}
		if r.Group == "" || r.Title == "" || r.Explain == "" || r.Advice == "" {
			return nil, fmt.Errorf("%s: group, title, explain and advice are required", r.ID)
		}
		m := &r.Match
		if m.Proto == "" {
			m.Proto = "tcp"
		}
		if m.Proto != "tcp" && m.Proto != "udp" {
			return nil, fmt.Errorf("%s: bad proto %q", r.ID, m.Proto)
		}
		m.re = map[string]*regexp.Regexp{}
		for k, v := range map[string]string{"banner": m.Banner, "title": m.Title, "server": m.Server, "cert": m.Cert, "auth": m.Auth, "detail": m.Detail, "any": m.Any} {
			if v == "" {
				continue
			}
			re, err := regexp.Compile(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %v", r.ID, k, err)
			}
			m.re[k] = re
		}
		if len(m.Ports) == 0 && len(m.re) == 0 && m.HTTP == nil && m.TLS == nil && m.TLSExpired == nil && m.SelfSigned == nil {
			return nil, fmt.Errorf("%s: match has no condition", r.ID)
		}
	}
	for _, c := range b.Combos {
		if c.ID == "" || seen[c.ID] {
			return nil, fmt.Errorf("combo: missing or duplicate id %q", c.ID)
		}
		seen[c.ID] = true
		if _, ok := parseRisk(c.Risk); !ok {
			return nil, fmt.Errorf("%s: bad risk %q", c.ID, c.Risk)
		}
	}
	return &b, nil
}

// KnownID reports whether id names a rule or combination rule (KH-000,
// the unknown-port fallback, included).
func KnownID(id string) bool {
	if id == "KH-000" {
		return true
	}
	for _, r := range base.Rules {
		if r.ID == id {
			return true
		}
	}
	for _, c := range base.Combos {
		if c.ID == id {
			return true
		}
	}
	return false
}

// Version is the embedded rule base version.
func Version() string { return base.Version }

// Rules returns the loaded rule base (for reporting/tests).
func Rules() []Rule { return base.Rules }

// Target is everything the rule base looks at for one address.
type Target struct {
	Family string       // "v4" or "v6"
	TCP    []probe.Info // one per open TCP port
	UDP    []scan.UDPResult
}

// Evaluate returns all findings for a target, worst first.
func Evaluate(t Target) []Finding { return base.Evaluate(t) }

// PortFindings returns only the per-port findings (no combinations), so
// a caller can mark accepted risks before Combine runs.
func PortFindings(t Target) []Finding { return base.portFindings(t) }

// Combine appends the whole-target combination findings to fs and sorts
// the result. Accepted findings do not feed combinations.
func Combine(t Target, fs []Finding) []Finding {
	out := append(fs, base.combos(t, fs)...)
	SortFindings(out)
	return out
}

// Evaluate runs this rule base against t.
func (b *Base) Evaluate(t Target) []Finding {
	out := b.portFindings(t)
	out = append(out, b.combos(t, out)...)
	SortFindings(out)
	return out
}

func (b *Base) portFindings(t Target) []Finding {
	var out []Finding
	for _, info := range t.TCP {
		out = append(out, b.lookup("tcp", info.Port, facts(info))...)
	}
	for _, u := range t.UDP {
		if u.State != scan.UDPOpen {
			continue // open|filtered is advisory only; closed is fine
		}
		out = append(out, b.lookup("udp", u.Port, evidence{detail: u.Detail, text: u.Detail})...)
	}
	return out
}

// evidence is the flattened, matchable view of a probe.
type evidence struct {
	banner, title, server, cert, auth, detail string
	http, tls, expired, selfSigned            bool
	text                                      string // all of the above, for "any"
	summary                                   string
}

func facts(i probe.Info) evidence {
	e := evidence{banner: i.Banner, summary: i.Evidence()}
	if h := i.HTTP; h != nil {
		e.http = true
		e.title = h.Title
		e.server = strings.TrimSpace(h.Server + " " + h.PoweredBy)
		e.auth = h.AuthRealm
		e.tls = h.HTTPSOnly // a TLS port that refused our SNI-less handshake
	}
	if t := i.TLS; t != nil {
		e.tls = true
		e.cert = strings.Join(append([]string{t.CN, t.Issuer}, t.SANs...), " ")
		e.expired = t.Expired
		e.selfSigned = t.SelfSigned
	}
	e.text = strings.Join([]string{e.banner, e.title, e.server, e.auth, e.cert}, " | ")
	return e
}

func (b *Base) lookup(proto string, port int, ev evidence) []Finding {
	var out []Finding
	taken := map[string]bool{}
	for i := range b.Rules {
		r := &b.Rules[i]
		if taken[r.Group] || r.Match.Proto != proto {
			continue
		}
		conf, ok := r.Match.matches(port, ev)
		if !ok {
			continue
		}
		taken[r.Group] = true
		risk, _ := parseRisk(r.Risk)
		out = append(out, Finding{
			RuleID: r.ID, Port: port, Proto: proto, Service: r.Service,
			Risk: risk, Title: r.Title, Explain: r.Explain, Advice: r.Advice,
			Evidence: ev.summary, Confidence: conf, Tags: r.Tags,
		})
	}
	out = dropCovered(out)
	if len(out) == 0 && proto == "tcp" {
		conf := "low"
		if ev.summary != "" {
			conf = "medium"
		}
		out = append(out, Localize(Finding{
			RuleID: "KH-000", Port: port, Proto: proto, Risk: RiskLow,
			Evidence: ev.summary, Confidence: conf,
		}, i18n.EN))
	}
	return out
}

// dropCovered removes port-number-only findings when a finding backed by
// real evidence on the same port already shares one of their tags: "a
// NAS page answers on 5001" makes "5001 is Synology's default port"
// redundant.
func dropCovered(fs []Finding) []Finding {
	strong := map[string]bool{}
	for _, f := range fs {
		if f.Confidence != "low" {
			for _, t := range f.Tags {
				strong[t] = true
			}
		}
	}
	out := fs[:0]
	for _, f := range fs {
		covered := false
		if f.Confidence == "low" {
			for _, t := range f.Tags {
				covered = covered || strong[t]
			}
		}
		if !covered {
			out = append(out, f)
		}
	}
	return out
}

func (m *Match) matches(port int, ev evidence) (confidence string, ok bool) {
	if len(m.Ports) > 0 {
		found := false
		for _, p := range m.Ports {
			if p == port {
				found = true
				break
			}
		}
		if !found {
			return "", false
		}
	}
	checks := map[string]string{"banner": ev.banner, "title": ev.title, "server": ev.server, "cert": ev.cert, "auth": ev.auth, "detail": ev.detail, "any": ev.text}
	for k, re := range m.re {
		if !re.MatchString(checks[k]) {
			return "", false
		}
	}
	for _, c := range []struct {
		want *bool
		got  bool
	}{{m.HTTP, ev.http}, {m.TLS, ev.tls}, {m.TLSExpired, ev.expired}, {m.SelfSigned, ev.selfSigned}} {
		if c.want != nil && *c.want != c.got {
			return "", false
		}
	}
	switch {
	case len(m.re) > 0 || m.TLSExpired != nil || m.SelfSigned != nil:
		return "high", true
	case m.HTTP != nil || m.TLS != nil:
		return "medium", true
	default:
		return "low", true
	}
}

func (b *Base) combos(t Target, fs []Finding) []Finding {
	tags := map[string][]int{}
	for _, f := range fs {
		if f.Accepted != nil {
			continue // an accepted risk does not feed whole-target rules
		}
		for _, tag := range f.Tags {
			tags[tag] = append(tags[tag], f.Port)
		}
	}
	var out []Finding
	for _, c := range b.Combos {
		w := c.When
		if w.Family != "" && w.Family != t.Family {
			continue
		}
		if w.MinOpen > 0 && len(t.TCP) < w.MinOpen {
			continue
		}
		var ports []int
		if len(w.TagsAny) > 0 {
			for _, tag := range w.TagsAny {
				ports = append(ports, tags[tag]...)
			}
			if len(ports) == 0 {
				continue
			}
		}
		if w.Family != "" && w.MinOpen == 0 && len(w.TagsAny) == 0 && len(t.TCP) == 0 {
			continue // a family-only combo needs at least one open port
		}
		risk, _ := parseRisk(c.Risk)
		f := Finding{RuleID: c.ID, Service: i18n.T(i18n.EN, "whole"), Risk: risk, Title: c.Title, Explain: c.Explain, Advice: c.Advice}
		if len(ports) > 0 {
			sort.Ints(ports)
			f.Evidence = "ports " + joinInts(dedupe(ports))
		}
		out = append(out, f)
	}
	return out
}

func dedupe(xs []int) []int {
	var out []int
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprint(x)
	}
	return strings.Join(parts, ", ")
}

// SortFindings orders findings worst-first, then per-port before
// whole-target, then by port.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Risk != fs[j].Risk {
			return fs[i].Risk > fs[j].Risk
		}
		if (fs[i].Port == 0) != (fs[j].Port == 0) {
			return fs[i].Port == 0
		}
		return fs[i].Port < fs[j].Port
	})
}

// MaxRisk returns the highest risk among findings that are not accepted,
// or RiskInfo when there are none.
func MaxRisk(fs []Finding) Risk {
	m := RiskInfo
	for _, f := range fs {
		if f.Accepted == nil && f.Risk > m {
			m = f.Risk
		}
	}
	return m
}

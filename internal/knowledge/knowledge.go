// Package knowledge maps scan evidence to plain-language findings
// using a curated, versioned rule base (rules.json, embedded).
//
// Rules are deliberately conservative: a finding states what the
// evidence supports ("a database port is reachable"), never a
// vulnerability claim. Every finding carries its rule ID so a reader
// can trace exactly why the report said what it said.
//
// TODO(P1): refine matches with banner substrings, TLS presence and
// HTTP title keywords; combination rules (e.g. "management interface
// + home profile" escalation).
package knowledge

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
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

func parseRisk(s string) Risk {
	switch s {
	case "high":
		return RiskHigh
	case "medium":
		return RiskMedium
	case "low":
		return RiskLow
	default:
		return RiskInfo
	}
}

// Rule is one knowledge-base entry.
type Rule struct {
	ID      string `json:"id"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Risk    string `json:"risk"`
	Title   string `json:"title"`
	Advice  string `json:"advice"`
}

// Finding is a rule matched against one open port, with the evidence
// that triggered it.
type Finding struct {
	RuleID  string `json:"rule_id"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Risk    Risk   `json:"risk"`
	Title   string `json:"title"`
	Advice  string `json:"advice"`
	// Evidence is the probe output (banner, TLS CN, HTTP title) that
	// supports the finding; may be empty.
	Evidence string `json:"evidence,omitempty"`
}

//go:embed rules.json
var rulesJSON []byte

var rules []Rule

func init() {
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		panic(fmt.Sprintf("knowledge: built-in rules.json is invalid: %v", err))
	}
}

// Rules returns the loaded rule base (for reporting/tests).
func Rules() []Rule { return rules }

// Lookup returns findings for one open port. evidence is free-form
// probe output attached to any finding. Unmatched ports return a
// generic informational finding — an unknown open port on a home
// gateway is always worth a human look.
func Lookup(port int, evidence string) []Finding {
	var out []Finding
	for _, r := range rules {
		if r.Port == port {
			out = append(out, Finding{
				RuleID:   r.ID,
				Port:     port,
				Service:  r.Service,
				Risk:     parseRisk(r.Risk),
				Title:    r.Title,
				Advice:   r.Advice,
				Evidence: evidence,
			})
		}
	}
	if len(out) == 0 {
		out = append(out, Finding{
			RuleID:   "KH-000",
			Port:     port,
			Service:  "unknown",
			Risk:     RiskLow,
			Title:    fmt.Sprintf("Port %d is open and not in the known-service list", port),
			Advice:   "If you did not open this deliberately, check the router for an unexpected port forward or a UPnP mapping created by a device or app.",
			Evidence: evidence,
		})
	}
	return out
}

// SortFindings orders findings worst-first, then by port.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Risk != fs[j].Risk {
			return fs[i].Risk > fs[j].Risk
		}
		return fs[i].Port < fs[j].Port
	})
}

// MaxRisk returns the highest risk in fs, or RiskInfo when empty.
func MaxRisk(fs []Finding) Risk {
	m := RiskInfo
	for _, f := range fs {
		if f.Risk > m {
			m = f.Risk
		}
	}
	return m
}

package knowledge

import (
	"strings"
	"testing"

	"github.com/playwjj/wanhound/internal/probe"
	"github.com/playwjj/wanhound/internal/scan"
)

func ids(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.RuleID] = f
	}
	return m
}

func TestRuleBaseLoads(t *testing.T) {
	if Version() == "" || len(Rules()) < 30 {
		t.Fatalf("rule base %q has %d rules, want a versioned base of 30+", Version(), len(Rules()))
	}
	for _, r := range Rules() {
		if !strings.HasPrefix(r.ID, "KH-") && !strings.HasPrefix(r.ID, "KU-") {
			t.Errorf("rule %s: IDs are KH-* (TCP) or KU-* (UDP)", r.ID)
		}
	}
}

func TestParseRejectsBadRules(t *testing.T) {
	bad := []string{
		`{"rules":[]}`, // no version
		`{"version":"1","rules":[{"id":"X","group":"g","risk":"high","title":"t","explain":"e","advice":"a","match":{}}]}`,
		`{"version":"1","rules":[{"id":"X","group":"g","risk":"severe","title":"t","explain":"e","advice":"a","match":{"ports":[1]}}]}`,
		`{"version":"1","rules":[{"id":"X","group":"g","risk":"high","title":"t","explain":"e","advice":"a","match":{"banner":"("}}]}`,
		`{"version":"1","rules":[{"id":"X","group":"g","risk":"high","title":"t","explain":"e","advice":"a","match":{"ports":[1]}},{"id":"X","group":"g","risk":"high","title":"t","explain":"e","advice":"a","match":{"ports":[2]}}]}`,
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("Parse accepted %s", b)
		}
	}
}

func TestEvidenceBeatsPortFallback(t *testing.T) {
	fs := Evaluate(Target{Family: "v4", TCP: []probe.Info{
		{Port: 22, Banner: "SSH-2.0-OpenSSH_9.6"},
		{Port: 2222, Banner: "SSH-2.0-dropbear"}, // SSH on a non-standard port
		{Port: 21},                               // no banner: port fallback
	}})
	m := ids(fs)
	if f, ok := m["KH-031"]; !ok || f.Confidence != "high" {
		t.Errorf("SSH banner should match KH-031 with high confidence: %+v", fs)
	}
	if _, ok := m["KH-010"]; ok {
		t.Error("port-22 fallback must not stack on top of the banner rule (same group)")
	}
	n := 0
	for _, f := range fs {
		if f.RuleID == "KH-031" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("KH-031 matched %d ports, want 22 and 2222", n)
	}
	if f, ok := m["KH-011"]; !ok || f.Confidence != "low" {
		t.Errorf("bare port 21 should hit the FTP fallback with low confidence")
	}
}

func TestWebIdentification(t *testing.T) {
	fs := Evaluate(Target{Family: "v4", TCP: []probe.Info{
		{Port: 8443, TLS: &probe.TLSInfo{CN: "synology.me", SelfSigned: true}, HTTP: &probe.HTTPInfo{Status: 200, Title: "Synology DiskStation"}},
		{Port: 80, HTTP: &probe.HTTPInfo{Status: 401, AuthRealm: `Basic realm="ZXHN F650"`, Title: "中兴光猫"}},
		{Port: 9999, HTTP: &probe.HTTPInfo{Status: 200, Title: "My blog"}},
	}})
	m := ids(fs)
	for _, id := range []string{"KH-042", "KH-051", "KH-040", "KH-047", "KH-017", "KC-001"} {
		if _, ok := m[id]; !ok {
			t.Errorf("expected %s in %v", id, keys(m))
		}
	}
	if fs[0].Risk != RiskHigh {
		t.Errorf("findings not sorted worst-first: %v", fs[0])
	}
}

func TestUnknownPort(t *testing.T) {
	fs := Evaluate(Target{Family: "v4", TCP: []probe.Info{{Port: 41234}}})
	if len(fs) != 1 || fs[0].RuleID != "KH-000" || fs[0].Risk != RiskLow {
		t.Errorf("unknown port: %+v", fs)
	}
}

func TestUDPRules(t *testing.T) {
	fs := Evaluate(Target{Family: "v4", UDP: []scan.UDPResult{
		{Port: 53, State: scan.UDPOpen, Detail: "open resolver: resolves arbitrary names"},
		{Port: 1900, State: scan.UDPOpen},
		{Port: 123, State: scan.UDPOpenFiltered}, // advisory only: no finding
	}})
	m := ids(fs)
	if _, ok := m["KU-001"]; !ok {
		t.Error("open resolver should match KU-001")
	}
	if _, ok := m["KU-002"]; ok {
		t.Error("KU-002 must not stack on KU-001")
	}
	if _, ok := m["KU-004"]; !ok {
		t.Error("SSDP answering should match KU-004")
	}
	if _, ok := m["KU-003"]; ok {
		t.Error("open|filtered UDP must not produce findings")
	}
	if _, ok := m["KC-001"]; !ok {
		t.Error("SSDP on WAN counts as router management (KC-001)")
	}
}

func TestCombos(t *testing.T) {
	var many []probe.Info
	for p := 40000; p < 40010; p++ {
		many = append(many, probe.Info{Port: p})
	}
	m := ids(Evaluate(Target{Family: "v6", TCP: many}))
	if _, ok := m["KC-003"]; !ok {
		t.Error("10 open ports should trigger KC-003 (DMZ?)")
	}
	if _, ok := m["KC-004"]; !ok {
		t.Error("open IPv6 ports should trigger KC-004")
	}
	if m := ids(Evaluate(Target{Family: "v6"})); len(m) != 0 {
		t.Errorf("nothing open must mean no findings, got %v", keys(m))
	}
	if m := ids(Evaluate(Target{Family: "v4", TCP: []probe.Info{{Port: 3306}}})); m["KC-002"].RuleID == "" {
		t.Error("exposed database should trigger KC-002")
	}
}

func keys(m map[string]Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestEveryRuleTranslated(t *testing.T) {
	ids := []string{}
	for _, r := range Rules() {
		ids = append(ids, r.ID)
	}
	for _, c := range base.Combos {
		ids = append(ids, c.ID)
	}
	for _, id := range ids {
		tr, ok := Translation("zh", id)
		if !ok || tr.Title == "" || tr.Explain == "" || tr.Advice == "" {
			t.Errorf("%s: missing Chinese translation", id)
		}
	}
	if len(translations["zh"]) != len(ids) {
		t.Errorf("rules.zh.json has %d entries for %d rules: stale IDs?", len(translations["zh"]), len(ids))
	}
}

func TestLocalize(t *testing.T) {
	fs := Evaluate(Target{Family: "v4", TCP: []probe.Info{{Port: 41234}, {Port: 23}}})
	zh := LocalizeAll(fs, "zh-CN")
	for i, f := range zh {
		if f.Title == fs[i].Title || f.RuleID != fs[i].RuleID || f.Risk != fs[i].Risk {
			t.Errorf("%s not localized: %q", f.RuleID, f.Title)
		}
	}
	if got := Localize(fs[0], "en"); got.Title != fs[0].Title {
		t.Errorf("English localization changed the text: %q", got.Title)
	}
}

func TestPortFallbackCoveredByEvidence(t *testing.T) {
	m := ids(Evaluate(Target{Family: "v4", TCP: []probe.Info{
		{Port: 5001, HTTP: &probe.HTTPInfo{Status: 200, Title: "Synology DiskStation"}},
	}}))
	if _, ok := m["KH-042"]; !ok {
		t.Error("NAS page should match KH-042")
	}
	if _, ok := m["KH-037"]; ok {
		t.Error("port-only DSM fallback must be dropped when the NAS page already matched")
	}
	m = ids(Evaluate(Target{Family: "v4", TCP: []probe.Info{{Port: 5001}}}))
	if _, ok := m["KH-037"]; !ok {
		t.Error("without evidence the DSM port fallback still applies")
	}
}

// A TLS port that refuses handshakes without SNI is HTTPS, not an
// unidentified port-number guess.
func TestRefusedTLSIsHTTPS(t *testing.T) {
	m := ids(Evaluate(Target{Family: "v6", TCP: []probe.Info{{Port: 443, TLS: &probe.TLSInfo{Refused: "alert: internal error"}}}}))
	if f, ok := m["KH-018"]; !ok || f.Confidence != "medium" {
		t.Errorf("want KH-018 (HTTPS, protocol recognized), got %v", keys(m))
	}
	if _, ok := m["KH-020"]; ok {
		t.Error("port-only KH-020 must not apply once TLS is recognized")
	}
}

package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/wanhound/internal/knowledge"
	"github.com/playwjj/wanhound/internal/probe"
)

func snap(label, ip, portSet, scanned string, t time.Time, open ...int) *Snapshot {
	s := &Snapshot{Label: label, Family: "v4", IP: ip, Time: t, PortSet: portSet, Scanned: scanned}
	for _, p := range open {
		s.Open = append(s.Open, probe.Info{Port: p})
	}
	return s
}

func TestSaveListLatestPerLabel(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	// Two non-ASCII labels must not collide on disk.
	for i, label := range []string{"武汉的家", "上海的家"} {
		if err := st.Save(snap(label, "198.51.100.1", "full", "1-65535", t0.Add(time.Duration(i)*time.Hour), 22)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Save(snap("武汉的家", "198.51.100.9", "full", "1-65535", t0.Add(48*time.Hour), 22, 443)); err != nil {
		t.Fatal(err)
	}
	labels, _ := st.Labels()
	if len(labels) != 2 {
		t.Fatalf("labels = %v, want 2 distinct", labels)
	}
	all, _ := st.List("武汉的家")
	if len(all) != 2 || !all[0].Time.Before(all[1].Time) {
		t.Fatalf("List: %d snapshots, want 2 oldest-first", len(all))
	}
	latest, _ := st.Latest("武汉的家", "v4")
	if latest.IP != "198.51.100.9" {
		t.Errorf("Latest = %s", latest.IP)
	}
	if none, _ := st.Latest("武汉的家", "v6"); none != nil {
		t.Error("v6 history must be separate from v4")
	}
	if _, err := st.Get("武汉的家", "../../etc/passwd"); err == nil {
		t.Error("path traversal in snapshot id must be rejected")
	}
}

func TestDiff(t *testing.T) {
	t0 := time.Now()
	prev := snap("home", "198.51.100.1", "full", "1-65535", t0, 22, 80)
	curr := snap("home", "198.51.100.2", "full", "1-65535", t0.Add(time.Hour), 22, 8291)
	ch := Diff(prev, curr)
	if !ch.IPChanged || len(ch.Opened) != 1 || ch.Opened[0] != 8291 || len(ch.Closed) != 1 || ch.Closed[0] != 80 {
		t.Errorf("diff = %+v", ch)
	}
	if Diff(nil, curr) != nil {
		t.Error("no previous snapshot means baseline (nil changes)")
	}
}

// A quick re-check after a full audit must not report every high port
// as closed, and a full audit after a quick one must not call every
// high port new.
func TestDiffRespectsCoverage(t *testing.T) {
	t0 := time.Now()
	full := snap("home", "198.51.100.1", "full", "1-65535", t0, 22, 40000)
	quick := snap("home", "198.51.100.1", "quick", "22,80,443", t0.Add(time.Hour), 22)
	ch := Diff(full, quick)
	if len(ch.Closed) != 0 || ch.Coverage == nil {
		t.Errorf("full→quick: closed=%v coverage=%v", ch.Closed, ch.Coverage)
	}
	ch = Diff(quick, full)
	if len(ch.Opened) != 0 || ch.Coverage == nil {
		t.Errorf("quick→full: opened=%v coverage=%v", ch.Opened, ch.Coverage)
	}
}

func TestDiffServiceChange(t *testing.T) {
	t0 := time.Now()
	prev := snap("home", "198.51.100.1", "full", "1-65535", t0)
	prev.Open = []probe.Info{{Port: 8080, HTTP: &probe.HTTPInfo{Status: 200, Title: "Jellyfin"}}}
	curr := snap("home", "198.51.100.1", "full", "1-65535", t0.Add(time.Hour))
	curr.Open = []probe.Info{{Port: 8080, HTTP: &probe.HTTPInfo{Status: 200, Title: "TP-LINK Router"}}}
	if ch := Diff(prev, curr); len(ch.Changed) != 1 || ch.Changed[0].Port != 8080 {
		t.Errorf("service change on 8080 not reported: %+v", ch)
	}
}

func TestValidLabel(t *testing.T) {
	for _, bad := range []string{"", "   ", "a/b", "x\n"} {
		if ValidLabel(bad) == nil {
			t.Errorf("ValidLabel(%q) accepted", bad)
		}
	}
	if ValidLabel("武汉的家") != nil {
		t.Error("unicode labels must be allowed")
	}
}

// Snapshots written by v0.2.0 stored notes and coverage as plain strings.
func TestReadsV020Snapshot(t *testing.T) {
	var s Snapshot
	err := json.Unmarshal([]byte(`{"id":"x","label":"home","family":"v4","ip":"198.51.100.1","notes":["old note"],"changes":{"coverage":"old coverage"}}`), &s)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Notes) != 1 || s.Notes[0].Render("zh") != "old note" || s.Changes.Coverage.Render("en") != "old coverage" {
		t.Errorf("v0.2.0 strings not preserved: %+v", s)
	}
}

func TestCoverageLocalized(t *testing.T) {
	t0 := time.Now()
	ch := Diff(snap("home", "198.51.100.1", "full", "1-65535", t0, 22, 40000), snap("home", "198.51.100.1", "quick", "22", t0, 22))
	if zh := ch.Coverage.Render("zh"); !strings.Contains(zh, "全端口") || !strings.Contains(zh, "快速") {
		t.Errorf("coverage zh = %q", zh)
	}
}

func TestDeleteAndPrune(t *testing.T) {
	st, _ := Open(t.TempDir())
	t0 := time.Now()
	for i := 0; i < 5; i++ {
		if err := st.Save(snap("home", "198.51.100.1", "full", "1-65535", t0.Add(time.Duration(i)*time.Hour), 22)); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := st.List("home")
	if err := st.Delete("home", all[4].ID); err != nil {
		t.Fatal(err)
	}
	if latest, _ := st.Latest("home", "v4"); latest.ID != all[3].ID {
		t.Error("after deleting the newest, Latest must fall back to the previous one")
	}
	if n, err := st.Prune("home", 2); err != nil || n != 2 {
		t.Errorf("Prune = %d, %v; want 2 removed", n, err)
	}
	if err := st.Delete("home", "../x"); err == nil {
		t.Error("traversal id must be rejected")
	}
	if err := st.DeleteLabel("home"); err != nil {
		t.Fatal(err)
	}
	if labels, _ := st.Labels(); len(labels) != 0 {
		t.Errorf("labels after DeleteLabel = %v", labels)
	}
}

func TestAcceptances(t *testing.T) {
	st, _ := Open(t.TempDir())
	if _, err := st.Accept("home", "KU-001", 53, "", 30); err == nil {
		t.Error("a reason must be required")
	}
	if _, err := st.Accept("home", "KU-001", 53, "router DNS; bridge mode planned", 400); err == nil {
		t.Error("over the maximum days must be refused")
	}
	a, err := st.Accept("home", "KU-001", 53, "router DNS; bridge mode planned", 30)
	if err != nil {
		t.Fatal(err)
	}
	// Re-accepting the same risk replaces, not duplicates.
	if _, err := st.Accept("home", "KU-001", 53, "updated reason", 30); err != nil {
		t.Fatal(err)
	}
	as, _ := st.Acceptances()
	if len(as) != 1 || as[0].Reason != "updated reason" {
		t.Fatalf("acceptances = %+v", as)
	}

	fs := []knowledge.Finding{
		{RuleID: "KU-001", Port: 53, Proto: "udp", Risk: knowledge.RiskHigh},
		{RuleID: "KH-016", Port: 53, Proto: "tcp", Risk: knowledge.RiskMedium},
	}
	if exp := ApplyAcceptances(fs, "home", as, time.Now()); len(exp) != 0 {
		t.Errorf("nothing should be expired: %v", exp)
	}
	if fs[0].Accepted == nil || fs[1].Accepted != nil {
		t.Errorf("only KU-001 on 53 should be accepted: %+v", fs)
	}
	if knowledge.MaxRisk(fs) != knowledge.RiskMedium {
		t.Errorf("accepted findings must not count towards the worst risk")
	}
	if ApplyAcceptances(fs, "other-home", as, time.Now()); fs[0].Accepted != nil {
		t.Error("acceptances are per label")
	}
	if exp := ApplyAcceptances(fs, "home", as, time.Now().AddDate(0, 0, 31)); len(exp) != 1 || fs[0].Accepted != nil {
		t.Error("an expired acceptance must stop applying and be reported")
	}
	if err := st.Unaccept(as[0].ID); err != nil || st.Unaccept(a.ID) == nil {
		t.Errorf("unaccept: %v", err)
	}
}

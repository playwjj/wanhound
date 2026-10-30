package store

import (
	"testing"
	"time"

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
	if len(ch.Closed) != 0 || ch.Coverage == "" {
		t.Errorf("full→quick: closed=%v coverage=%q", ch.Closed, ch.Coverage)
	}
	ch = Diff(quick, full)
	if len(ch.Opened) != 0 || ch.Coverage == "" {
		t.Errorf("quick→full: opened=%v coverage=%q", ch.Opened, ch.Coverage)
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

package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/wanhound/internal/audit"
	"github.com/playwjj/wanhound/internal/store"
)

func TestEgressText(t *testing.T) {
	cases := []struct {
		s       store.Snapshot
		offline bool
		lang    string
		want    string
	}{
		{store.Snapshot{Egress: "203.0.113.9", EgressSource: "echo"}, false, "en", "203.0.113.9"},
		{store.Snapshot{EgressSource: "failed"}, false, "zh", "查询失败"},
		{store.Snapshot{EgressSource: "offline"}, true, "en", "not checked (offline)"},
		{store.Snapshot{}, false, "en", "not checked"}, // v0.4 and older
	}
	for _, c := range cases {
		if got := egressText(&c.s, c.offline, c.lang); got != c.want {
			t.Errorf("egressText(%+v) = %q, want %q", c.s, got, c.want)
		}
	}
}

// A comparison with no differences must say so instead of an empty line.
func TestHTMLNoChange(t *testing.T) {
	s := &store.Snapshot{Label: "home", Family: "v6", IP: "2001:db8::1", Time: time.Now(), PortSet: "full", Scanned: "1-65535",
		EgressSource: "failed", Changes: &store.Changes{PrevIP: "2001:db8::1", PrevTime: time.Now()}}
	rep := &audit.Report{Label: "home", Targets: []*store.Snapshot{s}}
	for lang, want := range map[string][]string{"en": {"No change in open ports.", "lookup failed"}, "zh": {"开放端口没有变化。", "查询失败"}} {
		var b bytes.Buffer
		if err := HTML(&b, rep, lang); err != nil {
			t.Fatal(err)
		}
		for _, w := range want {
			if !strings.Contains(b.String(), w) {
				t.Errorf("%s HTML missing %q", lang, w)
			}
		}
	}
}

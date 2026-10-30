package lanhound

import (
	"strings"
	"testing"
)

const export = "\ufeffname,hostname,ip,ipv6,mac,all_macs\n" +
	"NAS,diskstation,192.168.1.10,2408:8207:1:2::10 fd00::10,aa:bb:cc:00:00:01,\n" +
	",cam-01,192.168.1.20,fe80::1 2408:8207:1:2::20 2408:8207:1:2::21,aa:bb:cc:00:00:02,\n" +
	"'=evil,,192.168.1.30,,aa:bb:cc:00:00:03,\n" +
	"Dup,,192.168.1.40,2408:8207:1:2::10,aa:bb:cc:00:00:04,\n"

func TestParse(t *testing.T) {
	ts, err := Parse(strings.NewReader(export), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 2 || ts[0].Device != "NAS" || ts[0].IPv6 != "2408:8207:1:2::10" || ts[1].Device != "cam-01" || ts[1].IPv6 != "2408:8207:1:2::20" {
		t.Errorf("most-recent public address per device, duplicates dropped: %+v", ts)
	}
	all, _ := Parse(strings.NewReader(export), true)
	if len(all) != 3 {
		t.Errorf("--all-addresses: %d targets, want 3 (ULA, link-local and duplicates skipped): %+v", len(all), all)
	}
	if _, err := Parse(strings.NewReader("a,b\n1,2\n"), false); err == nil {
		t.Error("a CSV without an ipv6 column must be rejected")
	}
}

func TestLabel(t *testing.T) {
	if got := Label("武汉的家", "NAS/1"); got != "武汉的家 · NAS-1" {
		t.Errorf("Label = %q", got)
	}
}

// Package lanhound reads the device table exported by LanHound
// (/api/devices.csv) and turns it into a list of single IPv6 targets.
//
// This is not range scanning: every target is one concrete device
// address LanHound saw on the LAN, and each is audited on its own,
// under its own label. Non-public addresses (ULA, link-local) are
// skipped — they are not reachable from the internet.
package lanhound

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/playwjj/wanhound/internal/intel"
)

// Target is one device address to audit.
type Target struct {
	Device string // display name: name, else hostname, else MAC
	MAC    string
	IPv6   string
}

// Parse reads a LanHound CSV export. With all=false only the most
// recent public IPv6 of each device is kept (LanHound lists the most
// recent first); with all=true every public address is.
func Parse(r io.Reader, all bool) ([]Target, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("reading CSV header: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))] = i
	}
	if _, ok := col["ipv6"]; !ok {
		return nil, fmt.Errorf("not a LanHound device export: no \"ipv6\" column (export it from LanHound's device table, /api/devices.csv)")
	}
	get := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			// LanHound prefixes formula-like cells with ' for spreadsheets.
			return strings.TrimPrefix(strings.TrimSpace(rec[i]), "'")
		}
		return ""
	}
	seen := map[string]bool{}
	var out []Target
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := get(rec, "name")
		if name == "" {
			name = get(rec, "hostname")
		}
		mac := get(rec, "mac")
		if name == "" {
			name = mac
		}
		for _, a := range strings.Fields(strings.ReplaceAll(get(rec, "ipv6"), ",", " ")) {
			ip, class, err := intel.Classify(a)
			if err != nil || class != intel.ClassPublic || ip.To4() != nil || seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			out = append(out, Target{Device: name, MAC: mac, IPv6: ip.String()})
			if !all {
				break
			}
		}
	}
	return out, nil
}

// Label is the history label for one device under a home label, so each
// device keeps its own timeline and diff.
func Label(home, device string) string {
	l := home + " · " + strings.NewReplacer("/", "-", "\\", "-").Replace(device)
	if r := []rune(l); len(r) > 64 {
		l = string(r[:64])
	}
	return l
}

package scan

import (
	"fmt"
	"sort"
	"strings"
)

// QuickPorts is the curated set used by --quick: services a home
// network plausibly exposes, weighted toward management interfaces,
// remote access, file sharing and IoT protocols. The default scan
// covers all 65535 ports; this list exists for fast re-checks.
//
// Maintained by hand from IANA assignments and public port-frequency
// statistics. Keep it auditable: one port per entry, sorted.
var QuickPorts = []int{
	21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 123, 135, 139, 143,
	161, 389, 443, 445, 465, 514, 515, 548, 554, 587, 631, 873, 993,
	995, 1080, 1194, 1433, 1723, 1883, 1900, 2049, 2181, 2375, 2376,
	3000, 3128, 3260, 3306, 3389, 4443, 5000, 5001, 5060, 5432, 5555,
	5900, 6379, 7547, 8000, 8008, 8080, 8081, 8086, 8089, 8090, 8123,
	8291, 8443, 8888, 9000, 9090, 9100, 9200, 9418, 10000, 11211,
	27017, 32400, 51820,
}

// FullPorts returns every TCP port, 1..65535.
func FullPorts() []int {
	ports := make([]int, 0, 65535)
	for p := 1; p <= 65535; p++ {
		ports = append(ports, p)
	}
	return ports
}

// ParsePorts parses a --ports value like "22,80,8000-8010".
func ParsePorts(spec string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	add := func(p int) error {
		if p < 1 || p > 65535 {
			return errBadPort(spec)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
		return nil
	}
	cur := 0
	have := false
	rangeStart := -1
	flush := func() error {
		if !have {
			return nil
		}
		if rangeStart >= 0 {
			for p := rangeStart; p <= cur; p++ {
				if err := add(p); err != nil {
					return err
				}
			}
			rangeStart = -1
		} else {
			if err := add(cur); err != nil {
				return err
			}
		}
		cur, have = 0, false
		return nil
	}
	for _, r := range spec {
		switch {
		case r >= '0' && r <= '9':
			cur = cur*10 + int(r-'0')
			have = true
		case r == '-':
			if !have || rangeStart >= 0 {
				return nil, errBadPort(spec)
			}
			rangeStart, cur, have = cur, 0, false
		case r == ',':
			if err := flush(); err != nil {
				return nil, err
			}
		case r == ' ':
		default:
			return nil, errBadPort(spec)
		}
	}
	// trailing range "8000-" with no end is invalid
	if rangeStart >= 0 && !have {
		return nil, errBadPort(spec)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errBadPort(spec)
	}
	return out, nil
}

type portError string

func (e portError) Error() string  { return "invalid port list: " + string(e) }
func errBadPort(spec string) error { return portError(spec) }

// FormatPorts renders a port list compactly ("1-1024,8080"), the
// inverse of ParsePorts. Snapshots store coverage this way so a later
// diff knows which ports were actually looked at.
func FormatPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	ps := append([]int(nil), ports...)
	sort.Ints(ps)
	var b strings.Builder
	for i := 0; i < len(ps); {
		j := i
		for j+1 < len(ps) && ps[j+1] <= ps[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		if ps[j] > ps[i] {
			fmt.Fprintf(&b, "%d-%d", ps[i], ps[j])
		} else {
			fmt.Fprint(&b, ps[i])
		}
		i = j + 1
	}
	return b.String()
}

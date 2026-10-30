// Package store persists audit snapshots keyed by a user-chosen home
// label (e.g. "home", "武汉的家"), not by IP: a home's public IPv4 is
// usually dynamic, so history must survive address changes. Each
// snapshot records the address it was taken against; when the address
// under a label changes, that is surfaced as an event instead of
// silently diffing two different lines.
//
// Layout: <dir>/labels/<slug>/<snapshot-id>.json, one file per
// snapshot, plain JSON. The slug is an ASCII rendering of the label
// plus a short hash, so distinct non-ASCII labels never collide.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/playwjj/wanhound/internal/i18n"
	"github.com/playwjj/wanhound/internal/intel"
	"github.com/playwjj/wanhound/internal/knowledge"
	"github.com/playwjj/wanhound/internal/probe"
	"github.com/playwjj/wanhound/internal/scan"
)

// Counts summarizes TCP port states.
type Counts struct {
	Open     int `json:"open"`
	Closed   int `json:"closed"`
	Filtered int `json:"filtered"`
}

// Snapshot is one completed audit of one address under one label.
type Snapshot struct {
	ID           string              `json:"id"`
	Label        string              `json:"label"`
	Family       string              `json:"family"` // "v4" | "v6"
	IP           string              `json:"ip"`
	Time         time.Time           `json:"time"`
	Duration     time.Duration       `json:"duration_ns"`
	PortSet      string              `json:"port_set"` // "full" | "quick" | "custom"
	Scanned      string              `json:"scanned"`  // compact port list actually covered
	Counts       Counts              `json:"counts"`
	Timeout      time.Duration       `json:"timeout_ns"`
	RTT          time.Duration       `json:"rtt_ns,omitempty"`
	Retried      int                 `json:"retried,omitempty"`
	Open         []probe.Info        `json:"open"` // one per open TCP port, with identification
	UDP          []scan.UDPResult    `json:"udp,omitempty"`
	Findings     []knowledge.Finding `json:"findings"`
	RulesVersion string              `json:"rules_version"`
	Intel        *intel.Profile      `json:"intel,omitempty"`
	Egress       string              `json:"egress,omitempty"` // scanning machine's public address
	Notes        []i18n.Msg          `json:"notes,omitempty"`
	Changes      *Changes            `json:"changes,omitempty"` // vs the previous snapshot
}

// OpenPorts returns the open TCP port numbers.
func (s *Snapshot) OpenPorts() []int {
	out := make([]int, len(s.Open))
	for i, o := range s.Open {
		out[i] = o.Port
	}
	return out
}

// Meta is the summary of a snapshot used for history listings.
type Meta struct {
	ID       string    `json:"id"`
	Label    string    `json:"label"`
	Family   string    `json:"family"`
	IP       string    `json:"ip"`
	Time     time.Time `json:"time"`
	PortSet  string    `json:"port_set"`
	Counts   Counts    `json:"counts"`
	MaxRisk  string    `json:"max_risk"`
	Opened   []int     `json:"opened,omitempty"`
	Closed   []int     `json:"closed,omitempty"`
	IPChange string    `json:"ip_change,omitempty"` // "A → B" when the address changed
}

// MetaOf summarizes s.
func MetaOf(s *Snapshot) Meta {
	m := Meta{ID: s.ID, Label: s.Label, Family: s.Family, IP: s.IP, Time: s.Time,
		PortSet: s.PortSet, Counts: s.Counts, MaxRisk: knowledge.MaxRisk(s.Findings).String()}
	if len(s.Findings) == 0 {
		m.MaxRisk = "none"
	}
	if c := s.Changes; c != nil {
		m.Opened, m.Closed = c.Opened, c.Closed
		if c.IPChanged {
			m.IPChange = c.PrevIP + " → " + s.IP
		}
	}
	return m
}

// Store is a directory of snapshot files.
type Store struct {
	dir string
}

// DefaultDir is ~/.local/share/wanhound (./.wanhound without a home).
func DefaultDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "share", "wanhound")
	}
	return ".wanhound"
}

// Open returns a Store rooted at dir ("" = DefaultDir).
func Open(dir string) (*Store, error) {
	if dir == "" {
		dir = DefaultDir()
	}
	if err := os.MkdirAll(filepath.Join(dir, "labels"), 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// Dir is the store's root directory.
func (s *Store) Dir() string { return s.dir }

// ValidLabel checks a user-supplied label.
func ValidLabel(label string) error {
	if strings.TrimSpace(label) == "" {
		return fmt.Errorf("label must not be empty")
	}
	if len([]rune(label)) > 64 {
		return fmt.Errorf("label is longer than 64 characters")
	}
	for _, r := range label {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' {
			return fmt.Errorf("label contains an invalid character")
		}
	}
	return nil
}

func slug(label string) string {
	var b strings.Builder
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
		if b.Len() >= 24 {
			break
		}
	}
	sum := sha256.Sum256([]byte(label))
	return b.String() + "-" + hex.EncodeToString(sum[:4])
}

func (s *Store) labelDir(label string) string {
	return filepath.Join(s.dir, "labels", slug(label))
}

// NewID makes a sortable snapshot ID.
func NewID(t time.Time, family string) string {
	return t.UTC().Format("20060102T150405.000Z") + "-" + family
}

// Save writes a snapshot (assigning an ID if it has none).
func (s *Store) Save(snap *Snapshot) error {
	if err := ValidLabel(snap.Label); err != nil {
		return err
	}
	if snap.ID == "" {
		snap.ID = NewID(snap.Time, snap.Family)
	}
	dir := s.labelDir(snap.Label)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, snap.ID+".json.tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, snap.ID+".json"))
}

// Get loads one snapshot.
func (s *Store) Get(label, id string) (*Snapshot, error) {
	if strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
		return nil, fmt.Errorf("invalid snapshot id")
	}
	data, err := os.ReadFile(filepath.Join(s.labelDir(label), id+".json"))
	if err != nil {
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("snapshot %s is corrupt: %w", id, err)
	}
	return &snap, nil
}

// List returns all snapshots under label, oldest first.
func (s *Store) List(label string) ([]*Snapshot, error) {
	entries, err := os.ReadDir(s.labelDir(label))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Snapshot
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		snap, err := s.Get(label, strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, err
		}
		out = append(out, snap)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out, nil
}

// Latest returns the most recent snapshot for label and family, or nil.
func (s *Store) Latest(label, family string) (*Snapshot, error) {
	all, err := s.List(label)
	if err != nil {
		return nil, err
	}
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Family == family {
			return all[i], nil
		}
	}
	return nil, nil
}

// Labels returns every label that has history, sorted.
func (s *Store) Labels() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "labels"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.dir, "labels", e.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".json") {
				data, err := os.ReadFile(filepath.Join(s.dir, "labels", e.Name(), f.Name()))
				if err != nil {
					break
				}
				var head struct {
					Label string `json:"label"`
				}
				if json.Unmarshal(data, &head) == nil && head.Label != "" {
					out = append(out, head.Label)
				}
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// Changes is the diff between a snapshot and the previous one.
type Changes struct {
	PrevID    string    `json:"prev_id"`
	PrevIP    string    `json:"prev_ip"`
	PrevTime  time.Time `json:"prev_time"`
	IPChanged bool      `json:"ip_changed,omitempty"`
	Opened    []int     `json:"opened,omitempty"` // TCP open now, not before
	Closed    []int     `json:"closed,omitempty"` // TCP open before, not now
	// Changed lists open ports whose identification changed (a
	// different service now answers on the same port).
	Changed   []ServiceChange `json:"changed,omitempty"`
	UDPOpened []int           `json:"udp_opened,omitempty"`
	UDPClosed []int           `json:"udp_closed,omitempty"`
	// Coverage explains ports that could not be compared because one
	// of the two runs did not look at them (e.g. --quick vs full).
	Coverage *i18n.Msg `json:"coverage,omitempty"`
}

// ServiceChange is a port whose evidence differs between runs.
type ServiceChange struct {
	Port   int    `json:"port"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Empty reports whether nothing changed (address aside).
func (c *Changes) Empty() bool {
	return len(c.Opened) == 0 && len(c.Closed) == 0 && len(c.Changed) == 0 &&
		len(c.UDPOpened) == 0 && len(c.UDPClosed) == 0
}

// Diff compares prev with curr. A port only counts as newly opened if
// the previous run actually scanned it, and as closed only if this run
// scanned it — otherwise a quick re-check after a full audit would
// "close" every high port.
func Diff(prev, curr *Snapshot) *Changes {
	if prev == nil {
		return nil
	}
	ch := &Changes{PrevID: prev.ID, PrevIP: prev.IP, PrevTime: prev.Time, IPChanged: prev.IP != curr.IP}
	prevCov := coverage(prev.Scanned)
	currCov := coverage(curr.Scanned)
	before := map[int]probe.Info{}
	for _, p := range prev.Open {
		before[p.Port] = p
	}
	now := map[int]probe.Info{}
	for _, p := range curr.Open {
		now[p.Port] = p
	}
	skipped := 0
	for p, info := range now {
		old, was := before[p]
		switch {
		case !was && prevCov(p):
			ch.Opened = append(ch.Opened, p)
		case !was:
			skipped++
		case old.Evidence() != info.Evidence() && old.Evidence() != "" && info.Evidence() != "":
			ch.Changed = append(ch.Changed, ServiceChange{Port: p, Before: old.Evidence(), After: info.Evidence()})
		}
	}
	for p := range before {
		if _, is := now[p]; is {
			continue
		}
		if currCov(p) {
			ch.Closed = append(ch.Closed, p)
		} else {
			skipped++
		}
	}
	if skipped > 0 {
		m := i18n.M("diff.coverage", skipped, "@portset."+prev.PortSet, "@portset."+curr.PortSet)
		ch.Coverage = &m
	}
	if len(prev.UDP) > 0 && len(curr.UDP) > 0 {
		pu, cu := udpOpen(prev.UDP), udpOpen(curr.UDP)
		for p := range cu {
			if !pu[p] {
				ch.UDPOpened = append(ch.UDPOpened, p)
			}
		}
		for p := range pu {
			if !cu[p] {
				ch.UDPClosed = append(ch.UDPClosed, p)
			}
		}
	}
	sort.Ints(ch.Opened)
	sort.Ints(ch.Closed)
	sort.Ints(ch.UDPOpened)
	sort.Ints(ch.UDPClosed)
	sort.Slice(ch.Changed, func(i, j int) bool { return ch.Changed[i].Port < ch.Changed[j].Port })
	return ch
}

func udpOpen(rs []scan.UDPResult) map[int]bool {
	m := map[int]bool{}
	for _, r := range rs {
		if r.State == scan.UDPOpen {
			m[r.Port] = true
		}
	}
	return m
}

func coverage(spec string) func(int) bool {
	ports, err := scan.ParsePorts(spec)
	if err != nil {
		return func(int) bool { return false }
	}
	set := make(map[int]bool, len(ports))
	for _, p := range ports {
		set[p] = true
	}
	return func(p int) bool { return set[p] }
}

// Localized returns a copy of s with every human-readable text (findings,
// notes, hints, coverage) rendered in lang, for display and APIs.
func (s *Snapshot) Localized(lang string) *Snapshot {
	c := *s
	c.Findings = knowledge.LocalizeAll(s.Findings, lang)
	c.Notes = i18n.LocalizeAll(s.Notes, lang)
	if s.Intel != nil {
		p := *s.Intel
		p.Hints = i18n.LocalizeAll(p.Hints, lang)
		c.Intel = &p
	}
	if s.Changes != nil {
		ch := *s.Changes
		if ch.Coverage != nil {
			m := ch.Coverage.Localized(lang)
			ch.Coverage = &m
		}
		c.Changes = &ch
	}
	return &c
}

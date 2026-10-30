// Package store persists scan snapshots keyed by a user-chosen home
// label (e.g. "home"), not by IP: a home's public IPv4 is usually
// dynamic, so history must survive address changes. Each snapshot
// records the address it was taken against; when the address under a
// label changes, that is surfaced as an event instead of silently
// diffing two different lines.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/playwjj/wanhound/internal/probe"
	"github.com/playwjj/wanhound/internal/scan"
)

// Snapshot is one saved scan for one target under one label.
type Snapshot struct {
	Label    string        `json:"label"`
	IP       string        `json:"ip"`
	Time     time.Time     `json:"time"`
	Open     []OpenPort    `json:"open"`
	Probes   []probe.Info  `json:"probes,omitempty"`
	Duration time.Duration `json:"duration_ns"`
}

// OpenPort is the compact per-port record kept in snapshots.
type OpenPort struct {
	Port int `json:"port"`
}

// Changes is the diff between two snapshots.
type Changes struct {
	IPChanged   bool  // target address differs from previous snapshot
	OpenedPorts []int // open now, not open before
	ClosedPorts []int // open before, not open now
}

// Store is a directory of snapshot files.
type Store struct {
	dir string
}

// Open returns a Store rooted at dir (created on first save). An
// empty dir means the default (~/.local/share/wanhound, falling back
// to ./.wanhound).
func Open(dir string) (*Store, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			dir = filepath.Join(home, ".local", "share", "wanhound")
		} else {
			dir = ".wanhound"
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) file(label string) string {
	// labels are user-chosen names; keep them filesystem-safe.
	safe := make([]rune, 0, len(label))
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			safe = append(safe, r)
		default:
			safe = append(safe, '_')
		}
	}
	return filepath.Join(s.dir, string(safe)+".json")
}

type historyFile struct {
	Snapshots []Snapshot `json:"snapshots"`
}

// Save appends a snapshot under its label.
func (s *Store) Save(snap Snapshot) error {
	h, err := s.load(snap.Label)
	if err != nil {
		return err
	}
	h.Snapshots = append(h.Snapshots, snap)
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.file(snap.Label), data, 0o644)
}

// Latest returns the most recent snapshot for label, or nil.
func (s *Store) Latest(label string) (*Snapshot, error) {
	h, err := s.load(label)
	if err != nil {
		return nil, err
	}
	if len(h.Snapshots) == 0 {
		return nil, nil
	}
	last := h.Snapshots[len(h.Snapshots)-1]
	return &last, nil
}

func (s *Store) load(label string) (*historyFile, error) {
	data, err := os.ReadFile(s.file(label))
	if os.IsNotExist(err) {
		return &historyFile{}, nil
	}
	if err != nil {
		return nil, err
	}
	var h historyFile
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("snapshot file for label %q is corrupt: %w", label, err)
	}
	return &h, nil
}

// FromScan builds a Snapshot from a scan result and its probes.
func FromScan(label string, res *scan.Result, probes []probe.Info) Snapshot {
	snap := Snapshot{
		Label:    label,
		IP:       res.IP,
		Time:     res.StartedAt,
		Probes:   probes,
		Duration: res.Duration,
	}
	for _, p := range res.Open() {
		snap.Open = append(snap.Open, OpenPort{Port: p.Port})
	}
	return snap
}

// Diff compares prev (may be nil) with curr.
func Diff(prev *Snapshot, curr Snapshot) Changes {
	var ch Changes
	if prev == nil {
		return ch
	}
	ch.IPChanged = prev.IP != curr.IP
	before := map[int]bool{}
	for _, p := range prev.Open {
		before[p.Port] = true
	}
	now := map[int]bool{}
	for _, p := range curr.Open {
		now[p.Port] = true
	}
	for p := range now {
		if !before[p] {
			ch.OpenedPorts = append(ch.OpenedPorts, p)
		}
	}
	for p := range before {
		if !now[p] {
			ch.ClosedPorts = append(ch.ClosedPorts, p)
		}
	}
	sort.Ints(ch.OpenedPorts)
	sort.Ints(ch.ClosedPorts)
	return ch
}

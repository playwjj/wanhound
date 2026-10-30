package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/playwjj/wanhound/internal/knowledge"
)

// Acceptance records that a finding (rule on a port, under a label) is a
// known risk the user has decided to live with for now. It expires, so an
// accepted risk is looked at again instead of being forgotten.
type Acceptance struct {
	ID      string    `json:"id"`
	Label   string    `json:"label"`
	RuleID  string    `json:"rule_id"`
	Port    int       `json:"port"` // 0: whole-target finding
	Reason  string    `json:"reason"`
	Created time.Time `json:"created"`
	Until   time.Time `json:"until"`
}

// Active reports whether a is in force at t.
func (a Acceptance) Active(t time.Time) bool { return t.Before(a.Until) }

// MaxAcceptDays bounds how long a risk can be accepted at once.
const MaxAcceptDays = 365

func (s *Store) acceptFile() string { return filepath.Join(s.dir, "accepted.json") }

// Acceptances returns every recorded acceptance, newest first.
func (s *Store) Acceptances() ([]Acceptance, error) {
	data, err := os.ReadFile(s.acceptFile())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var as []Acceptance
	if err := json.Unmarshal(data, &as); err != nil {
		return nil, fmt.Errorf("accepted.json is corrupt: %w", err)
	}
	sort.Slice(as, func(i, j int) bool { return as[i].Created.After(as[j].Created) })
	return as, nil
}

func (s *Store) writeAcceptances(as []Acceptance) error {
	data, err := json.MarshalIndent(as, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.acceptFile() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.acceptFile())
}

// Accept records an acceptance for days (1..MaxAcceptDays). An existing
// acceptance for the same label, rule and port is replaced.
func (s *Store) Accept(label, ruleID string, port int, reason string, days int) (Acceptance, error) {
	reason = strings.TrimSpace(reason)
	switch {
	case ValidLabel(label) != nil:
		return Acceptance{}, ValidLabel(label)
	case ruleID == "" || len(ruleID) > 16:
		return Acceptance{}, fmt.Errorf("invalid rule id")
	case reason == "":
		return Acceptance{}, fmt.Errorf("a reason is required: write down why this risk is acceptable")
	case len([]rune(reason)) > 300:
		return Acceptance{}, fmt.Errorf("reason is longer than 300 characters")
	case days < 1 || days > MaxAcceptDays:
		return Acceptance{}, fmt.Errorf("days must be between 1 and %d", MaxAcceptDays)
	case port < 0 || port > 65535:
		return Acceptance{}, fmt.Errorf("invalid port")
	}
	as, err := s.Acceptances()
	if err != nil {
		return Acceptance{}, err
	}
	kept := as[:0]
	for _, a := range as {
		if !(a.Label == label && a.RuleID == ruleID && a.Port == port) {
			kept = append(kept, a)
		}
	}
	b := make([]byte, 6)
	rand.Read(b)
	now := time.Now().UTC()
	a := Acceptance{ID: hex.EncodeToString(b), Label: label, RuleID: ruleID, Port: port, Reason: reason,
		Created: now, Until: now.AddDate(0, 0, days)}
	return a, s.writeAcceptances(append(kept, a))
}

// Unaccept removes an acceptance by ID.
func (s *Store) Unaccept(id string) error {
	as, err := s.Acceptances()
	if err != nil {
		return err
	}
	kept := as[:0]
	found := false
	for _, a := range as {
		if a.ID == id {
			found = true
			continue
		}
		kept = append(kept, a)
	}
	if !found {
		return fmt.Errorf("no accepted risk with id %q", id)
	}
	return s.writeAcceptances(kept)
}

// ApplyAcceptances marks the findings of a label that match an active
// acceptance (in place) and returns the acceptances for this label that
// have expired and match a finding again — those deserve a note.
func ApplyAcceptances(fs []knowledge.Finding, label string, as []Acceptance, now time.Time) (expired []Acceptance) {
	for i := range fs {
		fs[i].Accepted = nil
		for _, a := range as {
			if a.Label != label || a.RuleID != fs[i].RuleID || a.Port != fs[i].Port {
				continue
			}
			if a.Active(now) {
				fs[i].Accepted = &knowledge.Acceptance{ID: a.ID, Reason: a.Reason, Until: a.Until}
			} else {
				expired = append(expired, a)
			}
		}
	}
	return expired
}

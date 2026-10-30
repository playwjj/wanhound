package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/playwjj/wanhound/internal/audit"
	"github.com/playwjj/wanhound/internal/i18n"
	"github.com/playwjj/wanhound/internal/intel"
	"github.com/playwjj/wanhound/internal/knowledge"
	"github.com/playwjj/wanhound/internal/lanhound"
	"github.com/playwjj/wanhound/internal/scan"
	"github.com/playwjj/wanhound/internal/store"
)

// maxBatch caps a LanHound batch: a home, not a hosting provider.
const maxBatch = 32

// handleLanHoundPreview parses an uploaded LanHound devices.csv and
// returns the device addresses that could be audited. It scans nothing.
func (s *Server) handleLanHoundPreview(w http.ResponseWriter, r *http.Request) {
	var b struct {
		CSV string `json:"csv"`
		All bool   `json:"all"`
	}
	if err := readJSONLimit(r, &b, 2<<20); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	targets, err := lanhound.Parse(strings.NewReader(b.CSV), b.All)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	type row struct {
		Device string `json:"device"`
		IPv6   string `json:"ipv6"`
	}
	out := []row{}
	for _, t := range targets {
		out = append(out, row{t.Device, t.IPv6})
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": out, "max": maxBatch})
}

// handleLanHoundScan audits the selected device addresses one after
// another as a single task, each under "<label> · <device>".
func (s *Server) handleLanHoundScan(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Label      string `json:"label"`
		PortSet    string `json:"port_set"`
		UDP        bool   `json:"udp"`
		Offline    bool   `json:"offline"`
		Authorized bool   `json:"authorized"`
		Lang       string `json:"lang"`
		Targets    []struct {
			Device string `json:"device"`
			IPv6   string `json:"ipv6"`
		} `json:"targets"`
	}
	if err := readJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !b.Authorized {
		writeErr(w, http.StatusBadRequest, "confirm that you own the target addresses or are authorized to test them")
		return
	}
	if len(b.Targets) == 0 || len(b.Targets) > maxBatch {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("select between 1 and %d devices", maxBatch))
		return
	}
	if b.PortSet != "full" && b.PortSet != "quick" {
		writeErr(w, http.StatusBadRequest, "port set must be full or quick")
		return
	}
	var reqs []audit.Request
	var devices, addrs []string
	seen := map[string]bool{}
	for _, t := range b.Targets {
		// Only public IPv6 device addresses: this is the per-device
		// IPv6 audit, not a way to submit arbitrary target lists.
		ip, class, err := intel.Classify(strings.TrimSpace(t.IPv6))
		if err != nil || ip.To4() != nil || (class != intel.ClassPublic && !s.opts.Lab) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("%q is not a public IPv6 address", t.IPv6))
			return
		}
		if seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		device := strings.TrimSpace(t.Device)
		if device == "" {
			device = ip.String()
		}
		req := audit.Request{IPv6: ip.String(), Label: lanhound.Label(strings.TrimSpace(b.Label), device),
			PortSet: b.PortSet, UDP: b.UDP, Offline: b.Offline, Lab: s.opts.Lab, Lang: i18n.Normalize(b.Lang),
			Concurrency: scan.DefaultConcurrency, Rate: scan.DefaultRate}
		if err := req.Validate(); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		reqs = append(reqs, req)
		devices = append(devices, device)
		addrs = append(addrs, ip.String())
	}
	entry := map[string]any{"action": "scan_start", "batch": "lanhound", "label": b.Label, "ipv6": addrs,
		"devices": devices, "port_set": b.PortSet, "udp": b.UDP, "offline": b.Offline, "authorized": true}
	s.launch(w, r, strings.TrimSpace(b.Label), reqs, devices, entry)
}

func (s *Server) handleDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Label string `json:"label"`
		ID    string `json:"id"`
	}
	if err := readJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.Delete(b.Label, b.ID); err != nil {
		writeErr(w, http.StatusNotFound, "snapshot not found")
		return
	}
	s.audit(r, map[string]any{"action": "snapshot_deleted", "label": b.Label, "id": b.ID})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteLabel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Label string `json:"label"`
	}
	if err := readJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.tasks.busyWith(b.Label) {
		writeErr(w, http.StatusConflict, "an audit for this label is running")
		return
	}
	if err := s.st.DeleteLabel(b.Label); err != nil {
		writeErr(w, http.StatusNotFound, "label not found")
		return
	}
	s.audit(r, map[string]any{"action": "label_deleted", "label": b.Label})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// markAccepted shows a stored snapshot with today's accepted-risk
// decisions, so accepting a finding is reflected immediately.
func (s *Server) markAccepted(snap *store.Snapshot) {
	if as, err := s.st.Acceptances(); err == nil {
		store.ApplyAcceptances(snap.Findings, snap.Label, as, time.Now())
	}
}

func (s *Server) handleAccepted(w http.ResponseWriter, r *http.Request) {
	as, err := s.st.Acceptances()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type row struct {
		store.Acceptance
		Active bool `json:"active"`
	}
	out := []row{}
	for _, a := range as {
		out = append(out, row{a, a.Active(time.Now())})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAccept(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Label  string `json:"label"`
		RuleID string `json:"rule_id"`
		Port   int    `json:"port"`
		Reason string `json:"reason"`
		Days   int    `json:"days"`
	}
	if err := readJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !knowledge.KnownID(b.RuleID) {
		writeErr(w, http.StatusBadRequest, "unknown rule")
		return
	}
	a, err := s.st.Accept(b.Label, b.RuleID, b.Port, b.Reason, b.Days)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, map[string]any{"action": "risk_accepted", "label": a.Label, "rule": a.RuleID, "port": a.Port,
		"until": a.Until.Format(time.RFC3339), "reason": a.Reason, "id": a.ID})
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleUnaccept(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.Unaccept(b.ID); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	s.audit(r, map[string]any{"action": "risk_unaccepted", "id": b.ID})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

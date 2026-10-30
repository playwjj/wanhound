package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/playwjj/wanhound/internal/audit"
	"github.com/playwjj/wanhound/internal/store"
)

// Task is the single audit the server may run at a time.
type Task struct {
	ID       string        `json:"id"`
	State    string        `json:"state"` // running | done | failed | cancelled
	Label    string        `json:"label"`
	Targets  []string      `json:"targets"`
	PortSet  string        `json:"port_set"`
	Started  time.Time     `json:"started"`
	Finished time.Time     `json:"finished,omitzero"`
	Current  audit.Event   `json:"current"` // latest progress
	Log      []string      `json:"log"`     // stage messages
	Report   *audit.Report `json:"report,omitempty"`
	Error    string        `json:"error,omitempty"`

	cancel context.CancelFunc
}

// tasks enforces "one audit at a time" and keeps the last one for the UI.
type tasks struct {
	mu   sync.Mutex
	cur  *Task
	runs []time.Time // start times, for the per-hour cap
}

type startError struct {
	status int
	msg    string
}

func (e *startError) Error() string { return e.msg }

// start launches req unless a task is running or the hourly cap is hit.
func (t *tasks) start(st *store.Store, req audit.Request, perHour int, onDone func(*Task)) (*Task, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur != nil && t.cur.State == "running" {
		return nil, &startError{409, "an audit is already running — wait for it or cancel it"}
	}
	now := time.Now()
	recent := t.runs[:0]
	for _, r := range t.runs {
		if now.Sub(r) < time.Hour {
			recent = append(recent, r)
		}
	}
	t.runs = recent
	if perHour > 0 && len(t.runs) >= perHour {
		return nil, &startError{429, "hourly audit limit reached on this server; try again later"}
	}
	t.runs = append(t.runs, now)

	b := make([]byte, 8)
	rand.Read(b)
	ctx, cancel := context.WithCancel(context.Background())
	task := &Task{ID: hex.EncodeToString(b), State: "running", Label: req.Label, PortSet: req.PortSet, Started: now, cancel: cancel}
	for _, a := range []string{req.IPv4, req.IPv6} {
		if a != "" {
			task.Targets = append(task.Targets, a)
		}
	}
	t.cur = task

	go func() {
		rep, err := audit.Run(ctx, st, req, audit.Hooks{Progress: func(e audit.Event) {
			t.mu.Lock()
			defer t.mu.Unlock()
			task.Current = e
			if e.Message != "" && len(task.Log) < 100 {
				task.Log = append(task.Log, e.Target+": "+e.Message)
			}
		}})
		t.mu.Lock()
		task.Finished = time.Now()
		switch {
		case ctx.Err() != nil:
			task.State = "cancelled"
		case err != nil:
			task.State, task.Error = "failed", err.Error()
		default:
			task.State, task.Report = "done", rep
		}
		cancel()
		t.mu.Unlock()
		if onDone != nil {
			onDone(task)
		}
	}()
	return task, nil
}

func (t *tasks) cancelCurrent() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur == nil || t.cur.State != "running" {
		return false
	}
	t.cur.cancel()
	return true
}

// snapshot returns a copy of the current task safe to serialize.
func (t *tasks) snapshot() *Task {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur == nil {
		return nil
	}
	c := *t.cur
	c.Log = append([]string(nil), t.cur.Log...)
	return &c
}

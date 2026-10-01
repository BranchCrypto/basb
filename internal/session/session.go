package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"

	"basb/internal/event"
	"basb/internal/store"
)

// Status is the sandbox / session lifecycle (docs §23).
type Status string

const (
	StatusCreated    Status = "created"
	StatusStarting   Status = "starting"
	StatusRunning    Status = "running"
	StatusFinished   Status = "finished"
	StatusCollecting Status = "collecting"
	StatusDestroyed  Status = "destroyed"
	StatusPaused     Status = "paused"
	StatusTerminated Status = "terminated"
	StatusFailed     Status = "failed"
)

// Meta is persisted as meta.json in the session directory.
type Meta struct {
	ID        string     `json:"id"`
	SandboxID string     `json:"sandbox_id"`
	AgentID   string     `json:"agent_id"`
	Agent     string     `json:"agent"`
	WorkDir   string     `json:"workdir"`
	Args      []string   `json:"args,omitempty"`
	Mode      event.Mode `json:"mode"`
	Status    Status     `json:"status"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	ExitCode  *int       `json:"exit_code,omitempty"`
	Error     string     `json:"error,omitempty"`
	RootPID   uint32     `json:"root_pid,omitempty"`
}

// Session owns the on-disk layout and event store for one run.
type Session struct {
	mu       sync.Mutex
	Root     string
	Meta     Meta
	Store    *store.JSONLStore
	Dir      string
	emitErrs int
	emitLast error
}

// Manager creates and opens sessions under Root.
type Manager struct {
	Root string
}

// NewManager uses root as the sessions data directory.
func NewManager(root string) *Manager {
	if root == "" {
		root = "data"
	}
	return &Manager{Root: root}
}

// validSessionID rejects path separators and ".." so Join cannot escape the sessions root.
func validSessionID(id string) error {
	if id == "" {
		return fmt.Errorf("empty session id")
	}
	if strings.Contains(id, "..") {
		return fmt.Errorf("invalid session id %q", id)
	}
	for _, r := range id {
		if r == '/' || r == '\\' || r == 0 || !unicode.IsPrint(r) {
			return fmt.Errorf("invalid session id %q", id)
		}
	}
	if filepath.Base(id) != id {
		return fmt.Errorf("invalid session id %q", id)
	}
	return nil
}

// Create allocates a new session directory and opens the event store.
// Directory creation uses exclusive Mkdir to avoid TOCTOU races.
func (m *Manager) Create(id, agent, workdir string, args []string) (*Session, error) {
	if id == "" {
		id = time.Now().UTC().Format("20060102-150405") + "-" + uuid.NewString()[:8]
	}
	if err := validSessionID(id); err != nil {
		return nil, err
	}
	base := filepath.Join(m.Root, "sessions")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir sessions: %w", err)
	}
	dir := filepath.Join(base, id)
	if err := os.Mkdir(dir, 0o755); err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("session %q already exists", id)
		}
		return nil, fmt.Errorf("mkdir session %q: %w", id, err)
	}
	st, err := store.OpenJSONL(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	meta := Meta{
		ID:        id,
		SandboxID: id,
		AgentID:   "agent-001",
		Agent:     agent,
		WorkDir:   workdir,
		Args:      args,
		Mode:      event.ModeObserve,
		Status:    StatusCreated,
		StartedAt: time.Now().UTC(),
	}
	s := &Session{Root: m.Root, Meta: meta, Store: st, Dir: dir}
	if err := s.writeMeta(); err != nil {
		_ = st.Close()
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return s, nil
}

// SetStatus updates lifecycle status and persists meta.
func (s *Session) SetStatus(st Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Meta.Status = st
	return s.writeMetaLocked()
}

// Open loads an existing session (read-only store access via ReadEvents).
func (m *Manager) Open(id string) (*Session, error) {
	if err := validSessionID(id); err != nil {
		return nil, err
	}
	dir := filepath.Join(m.Root, "sessions", id)
	metaPath := filepath.Join(dir, "meta.json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("open session %q: %w", id, err)
	}
	var meta Meta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, err
	}
	if meta.Mode == "" {
		meta.Mode = event.ModeObserve
	}
	if meta.SandboxID == "" {
		meta.SandboxID = meta.ID
	}
	if meta.AgentID == "" {
		meta.AgentID = "agent-001"
	}
	return &Session{Root: m.Root, Meta: meta, Dir: dir}, nil
}

// List returns session metas sorted by directory name (roughly time order).
func (m *Manager) List() ([]Meta, error) {
	base := filepath.Join(m.Root, "sessions")
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Meta
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		s, err := m.Open(e.Name())
		if err != nil {
			continue
		}
		out = append(out, s.Meta)
	}
	return out, nil
}

// Emit appends an event, stamping sandbox/session/agent/mode from meta.
func (s *Session) Emit(ev event.Event) error {
	s.mu.Lock()
	if s.Store == nil {
		err := fmt.Errorf("session store not open for writing")
		s.emitErrs++
		s.emitLast = err
		s.mu.Unlock()
		return err
	}
	ev.SessionID = s.Meta.ID
	ev.SandboxID = s.Meta.SandboxID
	ev.AgentID = s.Meta.AgentID
	mode := s.Meta.Mode
	trace := s.Meta.ID
	store := s.Store
	s.mu.Unlock()

	if mode == event.ModeObserve || mode == "" {
		ev.StampObserve()
	} else {
		ev.Decision.Mode = mode
		// Protect enforcement is Phase 4 — still record mode, default ALLOW unless set.
		if ev.Decision.Result == "" {
			ev.Decision.Result = event.ResultAllow
		}
	}
	if ev.Correlation.TraceID == "" {
		ev.Correlation.TraceID = trace
	}
	if err := store.Append(ev); err != nil {
		s.mu.Lock()
		s.emitErrs++
		s.emitLast = err
		s.mu.Unlock()
		return err
	}
	return nil
}

// TakeEmitFault returns a summary error if any Emit failed, and clears the counter.
func (s *Session) TakeEmitFault() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.emitErrs == 0 {
		return nil
	}
	n, last := s.emitErrs, s.emitLast
	s.emitErrs, s.emitLast = 0, nil
	if n == 1 {
		return fmt.Errorf("ledger emit failed: %w", last)
	}
	return fmt.Errorf("ledger incomplete: %d emit failures, last: %w", n, last)
}

// ReadEvents loads events.jsonl for this session.
func (s *Session) ReadEvents() ([]event.Event, error) {
	return store.ReadAll(filepath.Join(s.Dir, "events.jsonl"))
}

// BeginRun marks starting → running and records root pid.
func (s *Session) BeginRun(rootPID uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Meta.RootPID = rootPID
	s.Meta.Status = StatusRunning
	return s.writeMetaLocked()
}

// Complete marks finished → collecting → destroyed (or failed).
func (s *Session) Complete(exitCode int, runErr error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.Meta.EndedAt = &now
	s.Meta.ExitCode = &exitCode
	if runErr != nil {
		s.Meta.Status = StatusFailed
		s.Meta.Error = runErr.Error()
	} else {
		s.Meta.Status = StatusCollecting
		if err := s.writeMetaLocked(); err != nil {
			return err
		}
		s.Meta.Status = StatusFinished
		if err := s.writeMetaLocked(); err != nil {
			return err
		}
		s.Meta.Status = StatusDestroyed
	}
	if err := s.writeMetaLocked(); err != nil {
		return err
	}
	if s.Store != nil {
		err := s.Store.Close()
		s.Store = nil
		return err
	}
	return nil
}

func (s *Session) writeMeta() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeMetaLocked()
}

func (s *Session) writeMetaLocked() error {
	raw, err := json.MarshalIndent(s.Meta, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.Dir, "meta.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	// Windows cannot always rename-over an open file; retry replace.
	var last error
	for i := 0; i < 25; i++ {
		last = os.Rename(tmp, path)
		if last == nil {
			return nil
		}
		// Fallback: remove destination then rename (brief absent window).
		_ = os.Remove(path)
		last = os.Rename(tmp, path)
		if last == nil {
			return nil
		}
		time.Sleep(time.Millisecond * time.Duration(i+1))
	}
	_ = os.Remove(tmp)
	return last
}

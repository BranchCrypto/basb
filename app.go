package main

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"basb/internal/analysis"
	"basb/internal/api"
	"basb/internal/event"
	"basb/internal/session"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails backend binding surface.
type App struct {
	ctx      context.Context
	dataRoot string
	runMu    sync.Mutex
}

// NewApp creates the application struct.
func NewApp() *App {
	return &App{dataRoot: "data"}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	runtime.WindowMaximise(ctx)
}

// SessionInfo is a UI-friendly session row.
type SessionInfo struct {
	ID        string `json:"id"`
	SandboxID string `json:"sandbox_id"`
	AgentID   string `json:"agent_id"`
	Agent     string `json:"agent"`
	WorkDir   string `json:"workdir"`
	Mode      string `json:"mode"`
	Status    string `json:"status"`
	StartedAt string `json:"started_at"`
	ExitCode  *int   `json:"exit_code,omitempty"`
	RootPID   uint32 `json:"root_pid,omitempty"`
}

// EventInfo is a UI-friendly event row.
type EventInfo struct {
	TS       string `json:"ts"`
	Type     string `json:"type"`
	Category string `json:"category"`
	Action   string `json:"action"`
	PID      uint32 `json:"pid"`
	PPID     uint32 `json:"ppid"`
	Target   string `json:"target"`
	Risk     string `json:"risk"`
	Mode     string `json:"mode"`
	Decision string `json:"decision"`
}

// ReportInfo is the dashboard payload.
type ReportInfo struct {
	SessionID   string                 `json:"session_id"`
	Mode        string                 `json:"mode"`
	Status      string                 `json:"status"`
	Counts      analysis.Counts        `json:"counts"`
	ProcessTree []analysis.ProcessNode `json:"process_tree"`
	Sensitive   []analysis.TimelineItem `json:"sensitive_events"`
}

// ListSessions returns recorded sessions newest-first (by id string).
func (a *App) ListSessions() ([]SessionInfo, error) {
	metas, err := api.ListSessions(a.dataRoot)
	if err != nil {
		return nil, err
	}
	out := make([]SessionInfo, 0, len(metas))
	for i := len(metas) - 1; i >= 0; i-- {
		out = append(out, toInfo(metas[i]))
	}
	return out, nil
}

// GetEvents returns the timeline for a session (chronological).
func (a *App) GetEvents(sessionID string) ([]EventInfo, error) {
	sess, err := session.NewManager(a.dataRoot).Open(sessionID)
	if err != nil {
		return nil, err
	}
	events, err := sess.ReadEvents()
	if err != nil {
		return nil, err
	}
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	out := make([]EventInfo, 0, len(events))
	for _, ev := range events {
		out = append(out, toEventInfo(ev))
	}
	return out, nil
}

// GetReport returns dashboard counts + process tree.
func (a *App) GetReport(sessionID string) (*ReportInfo, error) {
	rep, err := api.SessionReport(a.dataRoot, sessionID)
	if err != nil {
		return nil, err
	}
	return &ReportInfo{
		SessionID:   rep.SessionID,
		Mode:        string(rep.Mode),
		Status:      string(rep.Status),
		Counts:      rep.Counts,
		ProcessTree: rep.ProcessTree,
		Sensitive:   rep.Sensitive,
	}, nil
}

// GetSession returns one session meta.
func (a *App) GetSession(sessionID string) (*SessionInfo, error) {
	sess, err := session.NewManager(a.dataRoot).Open(sessionID)
	if err != nil {
		return nil, err
	}
	info := toInfo(sess.Meta)
	return &info, nil
}

// RunAgent starts a sandboxed run in observe mode (blocking until exit).
// Emits "basb:run-ready" with SessionInfo as soon as the process is running,
// so the UI can show live details while waiting for exit.
func (a *App) RunAgent(agent, workdir, sessionID string, args []string) (*SessionInfo, error) {
	a.runMu.Lock()
	defer a.runMu.Unlock()

	res, err := api.Run(api.RunOptions{
		DataRoot: a.dataRoot,
		Session:  sessionID,
		Agent:    agent,
		WorkDir:  workdir,
		Args:     args,
		Quiet:    true,
		Light:    true,
		Mode:     event.ModeObserve,
		OnReady: func(id string) {
			if a.ctx == nil {
				return
			}
			sess, openErr := session.NewManager(a.dataRoot).Open(id)
			if openErr != nil {
				runtime.EventsEmit(a.ctx, "basb:run-ready", SessionInfo{
					ID:     id,
					Agent:  agent,
					Status: string(session.StatusRunning),
				})
				return
			}
			info := toInfo(sess.Meta)
			runtime.EventsEmit(a.ctx, "basb:run-ready", info)
		},
	})
	if err != nil && res == nil {
		if a.ctx != nil {
			runtime.EventsEmit(a.ctx, "basb:run-failed", err.Error())
		}
		return nil, err
	}
	sess, openErr := session.NewManager(a.dataRoot).Open(res.SessionID)
	if openErr != nil {
		return nil, openErr
	}
	info := toInfo(sess.Meta)
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "basb:run-finished", info)
	}
	// Session already finalized (destroyed/failed in meta). Do not reject the
	// promise with waitErr — the UI reads status from SessionInfo instead.
	return &info, nil
}

// ExportSession writes an audit pack zip next to the data root.
func (a *App) ExportSession(sessionID string) (string, error) {
	out := filepath.Join(".", sessionID+"-audit.zip")
	if err := api.ExportSession(a.dataRoot, sessionID, out); err != nil {
		return "", err
	}
	abs, _ := filepath.Abs(out)
	return abs, nil
}

// DataRoot returns the configured data directory.
func (a *App) DataRoot() string {
	return a.dataRoot
}

// PickExecutable opens a native file picker for programs.
func (a *App) PickExecutable() (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("窗口尚未就绪")
	}
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择要监测的 Agent",
		Filters: []runtime.FileFilter{
			{DisplayName: "可执行文件 (*.exe)", Pattern: "*.exe"},
			{DisplayName: "所有文件", Pattern: "*.*"},
		},
	})
}

// PickFolder opens a native folder picker.
func (a *App) PickFolder() (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("窗口尚未就绪")
	}
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择工作目录",
	})
}

// RevealPath shows a file in Explorer.
func (a *App) RevealPath(path string) error {
	if path == "" {
		return fmt.Errorf("路径为空")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return exec.Command("explorer.exe", "/select,", abs).Start()
}

func toInfo(m session.Meta) SessionInfo {
	mode := string(m.Mode)
	if mode == "" {
		mode = string(event.ModeObserve)
	}
	return SessionInfo{
		ID:        m.ID,
		SandboxID: m.SandboxID,
		AgentID:   m.AgentID,
		Agent:     m.Agent,
		WorkDir:   m.WorkDir,
		Mode:      mode,
		Status:    string(m.Status),
		StartedAt: m.StartedAt.UTC().Format(time.RFC3339),
		ExitCode:  m.ExitCode,
		RootPID:   m.RootPID,
	}
}

func toEventInfo(ev event.Event) EventInfo {
	return EventInfo{
		TS:       ev.Timestamp.UTC().Format(time.RFC3339Nano),
		Type:     ev.TypeString(),
		Category: string(ev.Action.Category),
		Action:   ev.Action.Type,
		PID:      ev.Actor.PID,
		PPID:     ev.Actor.PPID,
		Target:   ev.DisplayTarget(),
		Risk:     string(ev.RiskLevel),
		Mode:     string(ev.Decision.Mode),
		Decision: string(ev.Decision.Result),
	}
}

// Health is a trivial ping for the frontend.
func (a *App) Health() string {
	return fmt.Sprintf("ok data=%s mode=observe", a.dataRoot)
}

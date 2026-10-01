package api

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"basb/internal/analysis"
	"basb/internal/collect/fs"
	"basb/internal/collect/module"
	collectnet "basb/internal/collect/net"
	"basb/internal/collect/process"
	"basb/internal/collect/snapshot"
	"basb/internal/event"
	sandbox "basb/internal/sandbox/windows"
	"basb/internal/session"
	"basb/internal/summary"
)

// RunOptions configures a sandboxed agent run.
type RunOptions struct {
	DataRoot string
	Session  string
	Agent    string
	WorkDir  string
	Args     []string
	Quiet    bool // skip printing summary; discard agent stdout/stderr
	Light    bool // skip slow firewall/tasks/services/defender snapshots
	// Mode defaults to observe. Protect is accepted but not enforced in Phase 1–3.
	Mode event.Mode
	// OnReady is called once the agent process is running and the session is writable.
	// Safe for UI to start polling events while Wait continues.
	OnReady func(sessionID string)
}

// RunResult is returned after a run completes.
type RunResult struct {
	SessionID string
	ExitCode  int
	Dir       string
}

// Run creates a session, starts the agent in a Job Object, and records observe-first telemetry.
func Run(opts RunOptions) (*RunResult, error) {
	if opts.Agent == "" {
		return nil, fmt.Errorf("--agent is required")
	}
	if opts.Mode == "" {
		opts.Mode = event.ModeObserve
	}
	mgr := session.NewManager(opts.DataRoot)
	sess, err := mgr.Create(opts.Session, opts.Agent, opts.WorkDir, opts.Args)
	if err != nil {
		return nil, err
	}
	sess.Meta.Mode = opts.Mode
	_ = sess.SetStatus(session.StatusStarting)

	// sandbox.create
	_ = sess.Emit(sandboxLifecycle(sess.Meta.ID, event.TypeCreate))

	takeSnap := snapshot.TakeFull
	if opts.Light {
		takeSnap = snapshot.TakeLight
	}
	beforeSys := takeSnap()

	var before fs.Snapshot
	if opts.WorkDir != "" {
		_ = os.MkdirAll(opts.WorkDir, 0o755)
		before, _ = fs.Take(opts.WorkDir)
	}

	sb, err := sandbox.New()
	if err != nil {
		_ = sess.Complete(-1, err)
		return nil, err
	}
	defer sb.Close()

	var stdout, stderr io.Writer
	if opts.Quiet {
		stdout, stderr = io.Discard, io.Discard
	}

	_ = sess.Emit(sandboxLifecycle(sess.Meta.ID, event.TypeStart))

	started, err := sb.Start(opts.Agent, opts.Args, opts.WorkDir, stdout, stderr)
	if err != nil {
		_ = sess.Complete(-1, err)
		return nil, err
	}
	_ = sess.BeginRun(started.PID)
	if opts.OnReady != nil {
		opts.OnReady(sess.Meta.ID)
	}

	cmdline := process.JoinCmdline(opts.Agent, opts.Args)
	meta := map[string]any{}
	if abs, err := filepath.Abs(opts.Agent); err == nil {
		meta["image"] = abs
		if h, err := sandbox.FileSHA256(abs); err == nil {
			meta["sha256"] = h
		}
	}
	if u, err := sandbox.UserName(started.PID); err == nil && u != "" {
		meta["user"] = u
	}
	if elev, err := sandbox.IsElevated(started.PID); err == nil {
		meta["elevated"] = elev
	}
	if opts.WorkDir != "" {
		meta["cwd"] = opts.WorkDir
	}

	// agent.task.start
	agentEv := event.New(sess.Meta.ID, event.CatAgent, event.TypeStart)
	agentEv.WithActorPID(started.PID, uint32(os.Getpid())).WithCmdline(cmdline)
	agentEv.Target.Type = "agent"
	agentEv.Target.Value = cmdline
	for k, v := range meta {
		agentEv.Meta[k] = v
	}
	agentEv.Meta["args"] = opts.Args
	if img, ok := meta["image"].(string); ok {
		agentEv.Actor.Executable = img
	}
	if u, ok := meta["user"].(string); ok {
		agentEv.Actor.User = u
	}
	if cwd, ok := meta["cwd"].(string); ok {
		agentEv.Actor.Cwd = cwd
	}
	_ = sess.Emit(agentEv)

	if err := process.RecordStartMeta(sess, sess.Meta.ID, started.PID, uint32(os.Getpid()), cmdline, meta); err != nil {
		_ = sess.Complete(-1, err)
		return nil, err
	}

	watch := process.NewWatcher(sb, sess, sess.Meta.ID)
	watch.Seed(started.PID)
	watch.Start()

	netWatch := collectnet.NewWatcher(sb, sess, sess.Meta.ID)
	netWatch.Start()

	modWatch := module.NewWatcher(sb, sess, sess.Meta.ID)
	modWatch.Start()

	exitCode, waitErr := sandbox.Wait(started.Cmd)
	// Root may exit while children are still in the job — keep probes briefly.
	sb.WaitEmpty(2 * time.Second)
	watch.Stop()
	netWatch.Stop()
	modWatch.Stop()

	_ = process.RecordExit(sess, sess.Meta.ID, started.PID, exitCode)

	agentExit := event.New(sess.Meta.ID, event.CatAgent, event.TypeExit)
	agentExit.WithActorPID(started.PID, 0)
	agentExit.Target.Type = "agent"
	agentExit.Target.Value = fmt.Sprintf("exit=%d", exitCode)
	agentExit.Meta["exit_code"] = exitCode
	_ = sess.Emit(agentExit)

	_ = sess.SetStatus(session.StatusCollecting)

	if opts.WorkDir != "" {
		_ = fs.DiffEmit(sess, sess.Meta.ID, opts.WorkDir, before)
	}

	afterSys := takeSnap()
	snapshot.DiffEmit(sess, sess.Meta.ID, beforeSys, afterSys)

	_ = sess.Emit(sandboxLifecycle(sess.Meta.ID, event.TypeStop))
	_ = sess.Emit(sandboxLifecycle(sess.Meta.ID, event.TypeDestroy))

	if fault := sess.TakeEmitFault(); fault != nil {
		if waitErr == nil {
			waitErr = fault
		}
	}

	if err := sess.Complete(exitCode, waitErr); err != nil {
		return nil, err
	}

	if !opts.Quiet {
		reopened, _ := mgr.Open(sess.Meta.ID)
		if reopened != nil {
			events, _ := reopened.ReadEvents()
			summary.Print(os.Stdout, reopened.Meta, events)
		}
	}

	return &RunResult{SessionID: sess.Meta.ID, ExitCode: exitCode, Dir: sess.Dir}, waitErr
}

func sandboxLifecycle(sessionID, typ string) event.Event {
	ev := event.New(sessionID, event.CatSandbox, typ)
	ev.Target.Type = "sandbox"
	ev.Target.Value = sessionID
	return ev
}

// ListSessions returns session metadata under dataRoot.
func ListSessions(dataRoot string) ([]session.Meta, error) {
	return session.NewManager(dataRoot).List()
}

// ShowSession loads and optionally filters events.
func ShowSession(dataRoot, id, typesCSV string) (*session.Session, error) {
	sess, err := session.NewManager(dataRoot).Open(id)
	if err != nil {
		return nil, err
	}
	events, err := sess.ReadEvents()
	if err != nil {
		return nil, err
	}
	events = summary.Filter(events, typesCSV)
	summary.Print(os.Stdout, sess.Meta, events)
	for _, ev := range events {
		fmt.Printf("%s  %-18s  pid=%d  risk=%s  %s\n",
			ev.Timestamp.Format("15:04:05.000"), ev.TypeString(), ev.Actor.PID, ev.RiskLevel, ev.DisplayTarget())
	}
	return sess, nil
}

// SessionReport builds a deterministic analysis report for a session.
func SessionReport(dataRoot, id string) (*analysis.Report, error) {
	sess, err := session.NewManager(dataRoot).Open(id)
	if err != nil {
		return nil, err
	}
	events, err := sess.ReadEvents()
	if err != nil {
		return nil, err
	}
	rep := analysis.Build(sess.Meta, events)
	return &rep, nil
}

// ExportSession writes an audit-pack zip.
func ExportSession(dataRoot, id, outPath string) error {
	sess, err := session.NewManager(dataRoot).Open(id)
	if err != nil {
		return err
	}
	if outPath == "" {
		outPath = id + "-audit.zip"
	}
	if dir := filepath.Dir(outPath); dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	return summary.ExportZip(sess, outPath)
}

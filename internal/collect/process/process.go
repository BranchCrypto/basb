package process

import (
	"fmt"
	"path/filepath"
	"strings"

	"basb/internal/collect/marker"
	"basb/internal/event"
)

// Emitter writes process audit events.
type Emitter interface {
	Emit(ev event.Event) error
}

// RecordStart emits a process start event for the sandboxed root (and optional children later).
func RecordStart(em Emitter, sessionID string, pid, ppid uint32, cmdline string) error {
	return RecordStartMeta(em, sessionID, pid, ppid, cmdline, nil)
}

// RecordStartMeta emits process.create plus category-derived events (shell/ssh/priv/…).
func RecordStartMeta(em Emitter, sessionID string, pid, ppid uint32, cmdline string, meta map[string]any) error {
	ev := event.New(sessionID, event.CatProcess, event.TypeCreate)
	ev.WithActorPID(pid, ppid).WithCmdline(cmdline)
	applyActorMeta(&ev, meta)
	ev.Target.Type = "process"
	ev.Target.Value = cmdline
	if err := em.Emit(ev); err != nil {
		return err
	}
	return deriveFromProcess(em, sessionID, pid, ppid, cmdline, meta)
}

// RecordExit emits a process.exit event.
func RecordExit(em Emitter, sessionID string, pid uint32, exitCode int) error {
	ev := event.New(sessionID, event.CatProcess, event.TypeExit)
	ev.WithActorPID(pid, 0)
	ev.Target.Type = "process"
	ev.Target.Value = fmt.Sprintf("exit=%d", exitCode)
	ev.Meta["exit_code"] = exitCode
	return em.Emit(ev)
}

// JoinCmdline builds a display cmdline from exe + args.
func JoinCmdline(exe string, args []string) string {
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, quote(exe))
	for _, a := range args {
		parts = append(parts, quote(a))
	}
	return strings.Join(parts, " ")
}

func quote(s string) string {
	if strings.ContainsAny(s, " \t\"") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}

func applyActorMeta(ev *event.Event, meta map[string]any) {
	if meta == nil {
		return
	}
	if u, ok := meta["user"].(string); ok {
		ev.Actor.User = u
	}
	if img, ok := meta["image"].(string); ok {
		ev.Actor.Executable = img
	}
	if cwd, ok := meta["cwd"].(string); ok {
		ev.Actor.Cwd = cwd
	}
	for k, v := range meta {
		ev.Meta[k] = v
	}
}

func deriveFromProcess(em Emitter, sessionID string, pid, ppid uint32, cmdline string, meta map[string]any) error {
	base := strings.ToLower(filepath.Base(firstToken(cmdline)))
	lower := strings.ToLower(cmdline)

	if isShell(base) {
		ev := event.New(sessionID, event.CatShell, event.TypeExecute)
		ev.WithActorPID(pid, ppid).WithCmdline(cmdline)
		applyActorMeta(&ev, meta)
		ev.Target.Type = "command"
		ev.Target.Value = cmdline
		ev.Meta["shell"] = base
		if err := em.Emit(ev); err != nil {
			return err
		}
	}

	if base == "ssh.exe" || base == "ssh" || base == "scp.exe" || base == "scp" || base == "sftp.exe" {
		ev := event.New(sessionID, event.CatSSH, event.TypeExecute)
		ev.WithActorPID(pid, ppid).WithCmdline(cmdline)
		applyActorMeta(&ev, meta)
		ev.Target.Type = "command"
		ev.Target.Value = cmdline
		if err := em.Emit(ev); err != nil {
			return err
		}
	}

	if elevated, _ := meta["elevated"].(bool); elevated {
		ev := event.New(sessionID, event.CatPrivilege, event.TypeElevate)
		ev.WithActorPID(pid, ppid).WithCmdline(cmdline)
		applyActorMeta(&ev, meta)
		ev.Target.Type = "process"
		ev.Target.Value = cmdline
		ev.RiskLevel = event.RiskHigh
		if err := em.Emit(ev); err != nil {
			return err
		}
	}
	if strings.Contains(lower, "runas") || base == "sudo" || base == "sudo.exe" {
		ev := event.New(sessionID, event.CatPrivilege, event.TypeElevate)
		ev.WithActorPID(pid, ppid).WithCmdline(cmdline)
		ev.Target.Type = "process"
		ev.Target.Value = cmdline
		ev.Meta["via"] = "cmdline"
		ev.RiskLevel = event.RiskHigh
		if err := em.Emit(ev); err != nil {
			return err
		}
	}

	if isArchiveTool(base) {
		ev := event.New(sessionID, event.CatExfil, event.TypeExecute)
		ev.WithActorPID(pid, ppid).WithCmdline(cmdline)
		ev.Target.Type = "command"
		ev.Target.Value = cmdline
		ev.Meta["tool"] = base
		ev.RiskLevel = event.RiskMedium
		if err := em.Emit(ev); err != nil {
			return err
		}
	}

	if isDownloadTool(base) {
		ev := event.New(sessionID, event.CatDownload, event.TypeExecute)
		ev.WithActorPID(pid, ppid).WithCmdline(cmdline)
		ev.Target.Type = "command"
		ev.Target.Value = cmdline
		ev.Meta["tool"] = base
		if err := em.Emit(ev); err != nil {
			return err
		}
	}

	fields := splitCmdline(cmdline)
	for i, tok := range fields {
		if i == 0 {
			continue
		}
		tok = strings.Trim(tok, `"'`)
		if strings.ContainsAny(tok, `/\`) {
			_ = marker.EmitPathHit(em, sessionID, pid, tok, "cmdline")
		}
	}
	return nil
}

func splitCmdline(cmdline string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(cmdline); i++ {
		c := cmdline[i]
		switch {
		case c == '"':
			inQ = !inQ
			cur.WriteByte(c)
		case (c == ' ' || c == '\t') && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func firstToken(cmdline string) string {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return ""
	}
	if cmdline[0] == '"' {
		if i := strings.Index(cmdline[1:], `"`); i >= 0 {
			return cmdline[1 : i+1]
		}
	}
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func isShell(base string) bool {
	switch base {
	case "cmd.exe", "cmd", "powershell.exe", "powershell", "pwsh.exe", "pwsh",
		"bash.exe", "bash", "zsh", "zsh.exe", "sh", "sh.exe", "wsl.exe", "wsl":
		return true
	}
	return false
}

func isArchiveTool(base string) bool {
	switch base {
	case "tar.exe", "tar", "7z.exe", "7z", "rar.exe", "rar", "zip.exe", "zip",
		"makecab.exe", "compact.exe":
		return true
	}
	return false
}

func isDownloadTool(base string) bool {
	switch base {
	case "curl.exe", "curl", "wget.exe", "wget", "bitsadmin.exe", "certutil.exe":
		return true
	}
	return false
}

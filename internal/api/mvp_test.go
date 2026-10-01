package api_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"basb/internal/analysis"
	"basb/internal/api"
	"basb/internal/event"
	"basb/internal/session"
)

func TestMVP_ProcessTreeAndWorkdirWrite(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows Job Object MVP")
	}

	root := t.TempDir()
	data := filepath.Join(root, "data")
	workdir := filepath.Join(root, "work")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		t.Fatal(err)
	}

	_, thisFile, _, _ := runtime.Caller(0)
	bat := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "fake-agent.bat")
	bat, err := filepath.Abs(bat)
	if err != nil {
		t.Fatal(err)
	}

	res, err := api.Run(api.RunOptions{
		DataRoot: data,
		Session:  "mvp-test",
		Agent:    `C:\Windows\System32\cmd.exe`,
		WorkDir:  workdir,
		Args:     []string{"/c", bat},
		Quiet:    true,
		Light:    true,
		Mode:     event.ModeObserve,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code %d", res.ExitCode)
	}

	sess, err := session.NewManager(data).Open("mvp-test")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Meta.Mode != event.ModeObserve {
		t.Fatalf("mode=%s want observe", sess.Meta.Mode)
	}
	events, err := sess.ReadEvents()
	if err != nil {
		t.Fatal(err)
	}

	var starts int
	var sawPing bool
	var sawWrite bool
	var sawSchema bool
	var sawDecisionAllow bool
	for _, ev := range events {
		if ev.SchemaVersion == event.SchemaVersion {
			sawSchema = true
		}
		if ev.Decision.Mode == event.ModeObserve && ev.Decision.Result == event.ResultAllow {
			sawDecisionAllow = true
		}
		if ev.Action.Category == event.CatProcess && ev.Action.Type == event.TypeCreate {
			starts++
			if strings.Contains(strings.ToLower(ev.DisplayTarget()), "ping") ||
				strings.Contains(strings.ToLower(ev.Actor.CommandLine), "ping") {
				sawPing = true
			}
		}
		if ev.Action.Category == event.CatFile && (ev.Action.Type == event.TypeWrite || ev.Action.Type == event.TypeCreate) {
			if strings.Contains(strings.ToLower(ev.DisplayTarget()), "out.txt") {
				sawWrite = true
			}
		}
	}

	if !sawSchema {
		t.Fatal("expected schema_version on events")
	}
	if !sawDecisionAllow {
		t.Fatal("expected observe/ALLOW decision on events")
	}
	if starts < 2 {
		t.Fatalf("want at least 2 process starts (cmd + child), got %d events=%v", starts, summarize(events))
	}
	if !sawPing {
		t.Fatalf("expected ping.exe child process in timeline, events=%v", summarize(events))
	}
	if !sawWrite {
		t.Fatalf("expected out.txt file event, events=%v", summarize(events))
	}

	rep := analysis.Build(sess.Meta, events)
	if rep.Counts.Process < 2 {
		t.Fatalf("report process count=%d", rep.Counts.Process)
	}
	if len(rep.ProcessTree) == 0 {
		t.Fatal("expected process tree")
	}
}

func summarize(events []event.Event) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.TypeString()+":"+ev.DisplayTarget())
	}
	return out
}

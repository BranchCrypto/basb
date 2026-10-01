//go:build !windows

package windows

import (
	"fmt"
	"io"
	"os/exec"
	"time"
)

// Sandbox is a stub on non-Windows platforms.
type Sandbox struct{}

// New always fails outside Windows for v0.1.
func New() (*Sandbox, error) {
	return nil, fmt.Errorf("Windows Job Object sandbox is only available on Windows")
}

func (s *Sandbox) Close() error { return nil }

// StartResult mirrors the Windows type.
type StartResult struct {
	Cmd *exec.Cmd
	PID uint32
}

func (s *Sandbox) Start(exe string, args []string, workdir string, stdout, stderr io.Writer) (*StartResult, error) {
	return nil, fmt.Errorf("sandbox not supported on this OS")
}

func Wait(cmd *exec.Cmd) (int, error) {
	return -1, fmt.Errorf("sandbox not supported on this OS")
}

func (s *Sandbox) WaitEmpty(timeout time.Duration) {}

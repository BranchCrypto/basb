//go:build windows

package windows

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procCreateJobObjectW         = modKernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = modKernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = modKernel32.NewProc("AssignProcessToJobObject")
	procNtResumeProcess          = modNtdll.NewProc("NtResumeProcess")
)

// JobObjectLimitKillOnJobClose causes all processes in the job to die when the job handle closes.
const JobObjectLimitKillOnJobClose = 0x00002000

// JOBOBJECT_EXTENDED_LIMIT_INFORMATION (partial) for KillOnJobClose.
type jobObjectExtendedLimitInformation struct {
	BasicLimitInformation struct {
		PerProcessUserTimeLimit int64
		PerJobUserTimeLimit     int64
		LimitFlags              uint32
		MinimumWorkingSetSize   uintptr
		MaximumWorkingSetSize   uintptr
		ActiveProcessLimit      uint32
		Affinity                uintptr
		PriorityClass           uint32
		SchedulingClass         uint32
	}
	IoInfo struct {
		ReadOperationCount  uint64
		WriteOperationCount uint64
		OtherOperationCount uint64
		ReadTransferCount   uint64
		WriteTransferCount  uint64
		OtherTransferCount  uint64
	}
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

const jobObjectExtendedLimitInformationClass = 9

// Sandbox runs a process inside a Windows Job Object so the whole tree is managed.
type Sandbox struct {
	job windows.Handle
}

// New creates a Job Object with KillOnJobClose.
func New() (*Sandbox, error) {
	h, _, err := procCreateJobObjectW.Call(0, 0)
	if h == 0 {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}
	job := windows.Handle(h)

	var info jobObjectExtendedLimitInformation
	info.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose
	r1, _, err := procSetInformationJobObject.Call(
		uintptr(job),
		uintptr(jobObjectExtendedLimitInformationClass),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r1 == 0 {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return &Sandbox{job: job}, nil
}

// Close closes the job handle (and kills remaining processes if KillOnJobClose is set).
func (s *Sandbox) Close() error {
	if s.job == 0 {
		return nil
	}
	err := windows.CloseHandle(s.job)
	s.job = 0
	return err
}

// StartResult is the launched process and its OS pid.
type StartResult struct {
	Cmd *exec.Cmd
	PID uint32
}

// Start launches exe with args in workdir and assigns it to the job before it runs.
// The process is created suspended, assigned to the job, then resumed — closing the
// race where children could escape the job between Start and AssignProcessToJobObject.
// stdout/stderr default to the current process std handles when nil.
func (s *Sandbox) Start(exe string, args []string, workdir string, stdout, stderr io.Writer) (*StartResult, error) {
	abs, err := filepath.Abs(exe)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("agent binary: %w", err)
	}
	if workdir != "" {
		if err := os.MkdirAll(workdir, 0o755); err != nil {
			return nil, fmt.Errorf("workdir: %w", err)
		}
	}
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}

	cmd := exec.Command(abs, args...)
	cmd.Dir = workdir
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_SUSPENDED,
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start process: %w", err)
	}
	pid := uint32(cmd.Process.Pid)

	handle, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_SUSPEND_RESUME,
		false,
		pid,
	)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(handle)

	r1, _, jerr := procAssignProcessToJobObject.Call(uintptr(s.job), uintptr(handle))
	if r1 == 0 {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, fmt.Errorf("AssignProcessToJobObject: %w", jerr)
	}

	if err := resumeProcess(handle); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, fmt.Errorf("resume process: %w", err)
	}

	return &StartResult{Cmd: cmd, PID: pid}, nil
}

func resumeProcess(h windows.Handle) error {
	r1, _, err := procNtResumeProcess.Call(uintptr(h))
	// NTSTATUS success is 0; some versions return STATUS_SUCCESS only.
	if r1 != 0 {
		if err != nil && err != windows.ERROR_SUCCESS {
			return fmt.Errorf("NtResumeProcess: status=0x%x: %w", r1, err)
		}
		return fmt.Errorf("NtResumeProcess: status=0x%x", r1)
	}
	return nil
}

// Wait waits for the root process to exit and returns its exit code.
func Wait(cmd *exec.Cmd) (int, error) {
	err := cmd.Wait()
	if err == nil {
		return 0, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), nil
	}
	return -1, err
}

// WaitEmpty polls until the job has no member processes or timeout elapses.
// Used after the root exits so short-lived children are still observed.
func (s *Sandbox) WaitEmpty(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pids, err := s.ListPIDs()
		if err != nil || len(pids) == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modNtdll                       = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationProcess  = modNtdll.NewProc("NtQueryInformationProcess")
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")
)

type processBasicInformation struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

// ImagePath returns the full image path for pid.
func ImagePath(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	var size uint32 = 260
	for i := 0; i < 3; i++ {
		buf := make([]uint16, size)
		n := size
		r1, _, e := procQueryFullProcessImageNameW.Call(
			uintptr(h),
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&n)),
		)
		if r1 != 0 {
			return windows.UTF16ToString(buf[:n]), nil
		}
		if e == windows.ERROR_INSUFFICIENT_BUFFER {
			size *= 2
			continue
		}
		return "", e
	}
	return "", fmt.Errorf("QueryFullProcessImageName failed")
}

// ParentPID returns the parent process id via Toolhelp snapshot.
func ParentPID(pid uint32) (uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return 0, err
	}
	for {
		if pe.ProcessID == pid {
			return pe.ParentProcessID, nil
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return 0, fmt.Errorf("pid %d not found", pid)
}

// Cmdline reads the process command line from the PEB (best-effort).
func Cmdline(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return ImagePath(pid)
	}
	defer windows.CloseHandle(h)

	var pbi processBasicInformation
	var retLen uint32
	r1, _, _ := procNtQueryInformationProcess.Call(
		uintptr(h),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r1 != 0 || pbi.PebBaseAddress == 0 {
		return ImagePath(pid)
	}

	var paramsAddr uintptr
	if err := readMemory(h, pbi.PebBaseAddress+0x20, (*byte)(unsafe.Pointer(&paramsAddr)), unsafe.Sizeof(paramsAddr)); err != nil || paramsAddr == 0 {
		return ImagePath(pid)
	}

	var us unicodeString
	if err := readMemory(h, paramsAddr+0x70, (*byte)(unsafe.Pointer(&us)), unsafe.Sizeof(us)); err != nil || us.Buffer == 0 || us.Length == 0 {
		return ImagePath(pid)
	}

	nChars := int(us.Length / 2)
	buf := make([]uint16, nChars)
	if err := readMemory(h, us.Buffer, (*byte)(unsafe.Pointer(&buf[0])), uintptr(us.Length)); err != nil {
		return ImagePath(pid)
	}
	return windows.UTF16ToString(buf), nil
}

func readMemory(h windows.Handle, addr uintptr, dest *byte, size uintptr) error {
	var read uintptr
	return windows.ReadProcessMemory(h, addr, dest, size, &read)
}

// ExitCode returns the process exit code if it has exited.
func ExitCode(pid uint32) (code int, exited bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return -1, true
	}
	defer windows.CloseHandle(h)
	var c uint32
	if err := windows.GetExitCodeProcess(h, &c); err != nil {
		return -1, true
	}
	if c == 259 { // STILL_ACTIVE
		return 0, false
	}
	return int(c), true
}

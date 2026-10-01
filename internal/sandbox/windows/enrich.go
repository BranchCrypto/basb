//go:build windows

package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FileSHA256 returns a SHA-256 hex digest of path (capped at 32 MiB).
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 32<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// IsElevated reports whether the process token has a high integrity / elevated admin token.
func IsElevated(pid uint32) (bool, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)

	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return false, err
	}
	defer token.Close()
	return token.IsElevated(), nil
}

// UserName returns DOMAIN\User for the process token.
func UserName(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return "", err
	}
	defer token.Close()

	tokUser, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	sid := tokUser.User.Sid
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String(), nil
	}
	if domain != "" {
		return domain + `\` + account, nil
	}
	return account, nil
}

// Cwd reads the process current directory from the PEB (best-effort).
func Cwd(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	var pbi processBasicInformation
	var retLen uint32
	r1, _, _ := procNtQueryInformationProcess.Call(
		uintptr(h),
		0,
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r1 != 0 || pbi.PebBaseAddress == 0 {
		return "", err
	}
	var paramsAddr uintptr
	if err := readMemory(h, pbi.PebBaseAddress+0x20, (*byte)(unsafe.Pointer(&paramsAddr)), unsafe.Sizeof(paramsAddr)); err != nil || paramsAddr == 0 {
		return "", err
	}
	// RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath is a UNICODE_STRING at offset 0x38 on x64.
	var us unicodeString
	if err := readMemory(h, paramsAddr+0x38, (*byte)(unsafe.Pointer(&us)), unsafe.Sizeof(us)); err != nil || us.Buffer == 0 || us.Length == 0 {
		return "", err
	}
	nChars := int(us.Length / 2)
	buf := make([]uint16, nChars)
	if err := readMemory(h, us.Buffer, (*byte)(unsafe.Pointer(&buf[0])), uintptr(us.Length)); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf), nil
}

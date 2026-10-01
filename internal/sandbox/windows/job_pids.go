//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const jobObjectBasicProcessIdListClass = 3

// ListPIDs returns process IDs currently assigned to the job.
func (s *Sandbox) ListPIDs() ([]uint32, error) {
	if s.job == 0 {
		return nil, fmt.Errorf("job closed")
	}
	// Header is two ULONGS (8 bytes) then ULONG_PTR ProcessIdList[].
	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	bufSize := uint32(8 + 64*ptrSize)
	buf := make([]byte, bufSize)

	var needed uint32
	err := windows.QueryInformationJobObject(
		s.job,
		jobObjectBasicProcessIdListClass,
		uintptr(unsafe.Pointer(&buf[0])),
		bufSize,
		&needed,
	)
	if err != nil {
		if needed > bufSize {
			buf = make([]byte, needed)
			bufSize = needed
			err = windows.QueryInformationJobObject(
				s.job,
				jobObjectBasicProcessIdListClass,
				uintptr(unsafe.Pointer(&buf[0])),
				bufSize,
				&needed,
			)
		}
		if err != nil {
			return nil, fmt.Errorf("QueryInformationJobObject: %w", err)
		}
	}

	numberInList := *(*uint32)(unsafe.Pointer(&buf[4]))
	n := int(numberInList)
	maxFit := (len(buf) - 8) / ptrSize
	if n > maxFit {
		n = maxFit
	}
	out := make([]uint32, 0, n)
	for i := 0; i < n; i++ {
		pid := *(*uintptr)(unsafe.Pointer(&buf[8+i*ptrSize]))
		out = append(out, uint32(pid))
	}
	return out, nil
}

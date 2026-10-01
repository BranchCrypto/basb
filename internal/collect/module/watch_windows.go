//go:build windows

package module

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"basb/internal/event"
	"golang.org/x/sys/windows"
)

var (
	modPsapi             = windows.NewLazySystemDLL("psapi.dll")
	procEnumProcessModules = modPsapi.NewProc("EnumProcessModules")
	procGetModuleFileNameExW = modPsapi.NewProc("GetModuleFileNameExW")
)

// Emitter writes module events.
type Emitter interface {
	Emit(ev event.Event) error
}

// PIDSource lists job PIDs.
type PIDSource interface {
	ListPIDs() ([]uint32, error)
}

// Watcher polls loaded modules for job processes.
type Watcher struct {
	pids      PIDSource
	em        Emitter
	sessionID string
	interval  time.Duration

	mu        sync.Mutex
	seen      map[string]struct{}
	baselined bool
	stopCh    chan struct{}
	doneCh    chan struct{}
	started   atomic.Bool
	stopOnce  sync.Once
}

// NewWatcher creates a module watcher.
func NewWatcher(pids PIDSource, em Emitter, sessionID string) *Watcher {
	return &Watcher{
		pids:      pids,
		em:        em,
		sessionID: sessionID,
		interval:  time.Second,
		seen:      map[string]struct{}{},
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

// Start begins polling. Idempotent: a second call is a no-op.
func (w *Watcher) Start() {
	if !w.started.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer close(w.doneCh)
		t := time.NewTicker(w.interval)
		defer t.Stop()
		w.poll()
		for {
			select {
			case <-w.stopCh:
				w.poll()
				return
			case <-t.C:
				w.poll()
			}
		}
	}()
}

// Stop ends polling. No-op if Start was never called.
func (w *Watcher) Stop() {
	if !w.started.Load() {
		return
	}
	w.stopOnce.Do(func() { close(w.stopCh) })
	<-w.doneCh
}

func (w *Watcher) poll() {
	pids, err := w.pids.ListPIDs()
	if err != nil {
		return
	}
	emit := true
	w.mu.Lock()
	if !w.baselined {
		emit = false
		w.baselined = true
	}
	w.mu.Unlock()

	for _, pid := range pids {
		mods, err := listModules(pid)
		if err != nil {
			continue
		}
		for _, m := range mods {
			key := fmt.Sprintf("%d|%s", pid, strings.ToLower(m))
			w.mu.Lock()
			_, known := w.seen[key]
			if !known {
				w.seen[key] = struct{}{}
			}
			w.mu.Unlock()
			if known || !emit {
				continue
			}
			base := strings.ToLower(filepath.Base(m))
			if strings.HasSuffix(base, ".exe") {
				continue
			}
			// Skip ubiquitous system DLLs unless loaded from a non-system path.
			lower := strings.ToLower(m)
			if strings.Contains(lower, `\windows\system32\`) || strings.Contains(lower, `\windows\syswow64\`) {
				continue
			}
			ev := event.New(w.sessionID, event.CatModule, event.TypeLoad)
			ev.WithActorPID(pid, 0)
			ev.WithFileTarget(m)
			ev.Meta["name"] = base
			_ = w.em.Emit(ev)
		}
	}
}

func listModules(pid uint32) ([]string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	ptrSize := int(unsafe.Sizeof(windows.Handle(0)))
	handles := make([]windows.Handle, 256)
	var n int
	for attempt := 0; attempt < 4; attempt++ {
		var needed uint32
		r1, _, e := procEnumProcessModules.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&handles[0])),
			uintptr(len(handles)*ptrSize),
			uintptr(unsafe.Pointer(&needed)),
		)
		if r1 == 0 {
			return nil, e
		}
		n = int(needed) / ptrSize
		if n <= len(handles) {
			break
		}
		handles = make([]windows.Handle, n+8)
		n = 0
	}
	if n <= 0 {
		return nil, nil
	}
	if n > len(handles) {
		n = len(handles)
	}
	var out []string
	for i := 0; i < n; i++ {
		var buf [windows.MAX_PATH]uint16
		r1, _, _ := procGetModuleFileNameExW.Call(
			uintptr(h),
			uintptr(handles[i]),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if r1 == 0 {
			continue
		}
		out = append(out, windows.UTF16ToString(buf[:]))
	}
	return out, nil
}

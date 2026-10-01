//go:build windows

package process

import (
	"sync"
	"sync/atomic"
	"time"

	sandbox "basb/internal/sandbox/windows"
)

// Watcher polls a Job Object for member processes and emits start/exit events.
type Watcher struct {
	sb        *sandbox.Sandbox
	em        Emitter
	sessionID string
	interval  time.Duration
	rootPID   uint32

	mu       sync.Mutex
	seen     map[uint32]struct{}
	stopCh   chan struct{}
	doneCh   chan struct{}
	started  atomic.Bool
	stopOnce sync.Once
}

// NewWatcher watches processes inside sb.
func NewWatcher(sb *sandbox.Sandbox, em Emitter, sessionID string) *Watcher {
	return &Watcher{
		sb:        sb,
		em:        em,
		sessionID: sessionID,
		interval:  100 * time.Millisecond,
		seen:      map[uint32]struct{}{},
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

// Seed marks the sandboxed root pid as already recorded (start/exit owned by Run).
func (w *Watcher) Seed(rootPID uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rootPID = rootPID
	w.seen[rootPID] = struct{}{}
}

// Start begins polling until Stop. Idempotent: a second call is a no-op.
func (w *Watcher) Start() {
	if !w.started.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer close(w.doneCh)
		t := time.NewTicker(w.interval)
		defer t.Stop()
		w.poll(false)
		for {
			select {
			case <-w.stopCh:
				w.poll(true)
				return
			case <-t.C:
				w.poll(false)
			}
		}
	}()
}

// Stop ends polling and waits for the final sweep. No-op if Start was never called.
func (w *Watcher) Stop() {
	if !w.started.Load() {
		return
	}
	w.stopOnce.Do(func() { close(w.stopCh) })
	<-w.doneCh
}

func (w *Watcher) poll(final bool) {
	pids, err := w.sb.ListPIDs()
	if err != nil {
		return
	}
	if len(pids) == 0 && !final {
		return
	}

	alive := map[uint32]struct{}{}
	for _, pid := range pids {
		alive[pid] = struct{}{}

		w.mu.Lock()
		_, known := w.seen[pid]
		if !known {
			w.seen[pid] = struct{}{}
		}
		w.mu.Unlock()
		if known {
			continue
		}

		cmdline, _ := sandbox.Cmdline(pid)
		image, _ := sandbox.ImagePath(pid)
		if cmdline == "" {
			cmdline = image
		}
		ppid, _ := sandbox.ParentPID(pid)
		meta := map[string]any{}
		if image != "" {
			meta["image"] = image
			if h, err := sandbox.FileSHA256(image); err == nil {
				meta["sha256"] = h
			}
		}
		if u, err := sandbox.UserName(pid); err == nil && u != "" {
			meta["user"] = u
		}
		if cwd, err := sandbox.Cwd(pid); err == nil && cwd != "" {
			meta["cwd"] = cwd
		}
		if elev, err := sandbox.IsElevated(pid); err == nil {
			meta["elevated"] = elev
		}
		_ = RecordStartMeta(w.em, w.sessionID, pid, ppid, cmdline, meta)
	}

	w.mu.Lock()
	var gone []uint32
	for pid := range w.seen {
		if pid == w.rootPID {
			continue
		}
		if _, ok := alive[pid]; !ok {
			gone = append(gone, pid)
		}
	}
	w.mu.Unlock()

	for _, pid := range gone {
		code, _ := sandbox.ExitCode(pid)
		_ = RecordExit(w.em, w.sessionID, pid, code)
		w.mu.Lock()
		delete(w.seen, pid)
		w.mu.Unlock()
	}
}

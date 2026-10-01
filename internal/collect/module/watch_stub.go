//go:build !windows

package module

import "basb/internal/event"

// Emitter writes module events.
type Emitter interface {
	Emit(ev event.Event) error
}

// PIDSource lists job PIDs.
type PIDSource interface {
	ListPIDs() ([]uint32, error)
}

// Watcher is a no-op on non-Windows.
type Watcher struct{}

// NewWatcher returns a stub.
func NewWatcher(pids PIDSource, em Emitter, sessionID string) *Watcher {
	return &Watcher{}
}

func (w *Watcher) Start() {}
func (w *Watcher) Stop()  {}

//go:build !windows

package net

import "basb/internal/event"

// Emitter writes net audit events.
type Emitter interface {
	Emit(ev event.Event) error
}

// PIDSource lists live PIDs.
type PIDSource interface {
	ListPIDs() ([]uint32, error)
}

// Watcher is a no-op on non-Windows.
type Watcher struct{}

// NewWatcher returns a stub watcher.
func NewWatcher(pids PIDSource, em Emitter, sessionID string) *Watcher {
	return &Watcher{}
}

func (w *Watcher) Start() {}
func (w *Watcher) Stop()  {}

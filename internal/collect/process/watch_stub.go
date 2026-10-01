//go:build !windows

package process

import sandbox "basb/internal/sandbox/windows"

// Watcher is a no-op outside Windows.
type Watcher struct{}

func NewWatcher(sb *sandbox.Sandbox, em Emitter, sessionID string) *Watcher {
	return &Watcher{}
}

func (w *Watcher) Seed(rootPID uint32) {}
func (w *Watcher) Start()              {}
func (w *Watcher) Stop()               {}

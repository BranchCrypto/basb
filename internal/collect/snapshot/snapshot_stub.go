//go:build !windows

package snapshot

import "basb/internal/event"

// Emitter writes audit events.
type Emitter interface {
	Emit(ev event.Event) error
}

// Bundle is empty on non-Windows.
type Bundle struct {
	Startup  map[string]string
	Users    map[string]string
	Firewall map[string]string
	Tasks    map[string]string
	Services map[string]string
	Policy   map[string]string
}

// Take returns empty maps.
func Take() Bundle { return TakeLight() }

// TakeLight returns empty maps.
func TakeLight() Bundle {
	return Bundle{
		Startup:  map[string]string{},
		Users:    map[string]string{},
		Firewall: map[string]string{},
		Tasks:    map[string]string{},
		Services: map[string]string{},
		Policy:   map[string]string{},
	}
}

// TakeFull returns empty maps.
func TakeFull() Bundle { return TakeLight() }

// DiffEmit is a no-op on non-Windows.
func DiffEmit(em Emitter, sessionID string, before, after Bundle) {}

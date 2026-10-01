package collect

import "basb/internal/event"

// Emitter writes audit events (typically a session store).
type Emitter interface {
	Emit(ev event.Event) error
}

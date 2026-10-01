package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"basb/internal/event"
)

// JSONLStore appends events to a session's events.jsonl file.
type JSONLStore struct {
	mu   sync.Mutex
	path string
	f    *os.File
	enc  *json.Encoder
}

// openStores tracks live writers so ReadAll can share the same mutex.
var openStores sync.Map // abs path -> *JSONLStore

// OpenJSONL creates or appends to events.jsonl under dir.
func OpenJSONL(dir string) (*JSONLStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir session dir: %w", err)
	}
	path := filepath.Join(dir, "events.jsonl")
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open events.jsonl: %w", err)
	}
	enc := json.NewEncoder(f)
	s := &JSONLStore{path: abs, f: f, enc: enc}
	openStores.Store(abs, s)
	return s, nil
}

// Path returns the events.jsonl path.
func (s *JSONLStore) Path() string { return s.path }

// Append writes one event as a JSON line.
func (s *JSONLStore) Append(ev event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return fmt.Errorf("store closed")
	}
	if err := s.enc.Encode(ev); err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	return s.f.Sync()
}

// Close flushes and closes the file.
func (s *JSONLStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	openStores.Delete(s.path)
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// snapshot reads all events while holding the writer mutex so concurrent
// Append cannot tear a line mid-read in-process.
func (s *JSONLStore) snapshot() ([]event.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return readFile(s.path)
}

// ReadAll loads all events from a JSONL file.
// If a writer is open for the same path in-process, shares its mutex.
// A trailing incomplete line (cross-process writer) is skipped rather than failing.
func ReadAll(path string) ([]event.Event, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if v, ok := openStores.Load(abs); ok {
		return v.(*JSONLStore).snapshot()
	}
	return readFile(abs)
}

func readFile(path string) ([]event.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []event.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lines [][]byte
	for sc.Scan() {
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		cp := make([]byte, len(raw))
		copy(cp, raw)
		lines = append(lines, cp)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for i, raw := range lines {
		var ev event.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			// Tolerate a torn trailing line while another process is appending.
			if i == len(lines)-1 {
				break
			}
			return out, fmt.Errorf("line %d: %w", i+1, err)
		}
		out = append(out, ev)
	}
	return out, nil
}

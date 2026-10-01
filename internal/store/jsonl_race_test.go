package store_test

import (
	"path/filepath"
	"sync"
	"testing"

	"basb/internal/event"
	"basb/internal/store"
)

func TestReadAllWhileAppend(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenJSONL(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	path := filepath.Join(dir, "events.jsonl")
	var wg sync.WaitGroup
	errCh := make(chan error, 8)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			ev := event.New("s1", event.CatProcess, event.TypeCreate)
			if err := st.Append(ev); err != nil {
				errCh <- err
				return
			}
		}
	}()

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				evs, err := store.ReadAll(path)
				if err != nil {
					errCh <- err
					return
				}
				_ = evs
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	evs, err := store.ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 200 {
		t.Fatalf("want 200 events, got %d", len(evs))
	}
}

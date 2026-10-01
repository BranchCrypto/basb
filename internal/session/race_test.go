package session_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"basb/internal/session"
)

func TestCreateExclusiveSameID(t *testing.T) {
	root := t.TempDir()
	mgr := session.NewManager(root)

	const n = 16
	var okCount atomic.Int32
	var existCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			s, err := mgr.Create("same-id", "agent.exe", "", nil)
			if err == nil {
				okCount.Add(1)
				_ = s.Store.Close()
				return
			}
			if err.Error() == `session "same-id" already exists` {
				existCount.Add(1)
				return
			}
			t.Errorf("unexpected err: %v", err)
		}()
	}
	wg.Wait()
	if okCount.Load() != 1 {
		t.Fatalf("want exactly 1 successful Create, got %d", okCount.Load())
	}
	if existCount.Load() != int32(n-1) {
		t.Fatalf("want %d already-exists, got %d", n-1, existCount.Load())
	}
}

func TestCreateEmptyIDUnique(t *testing.T) {
	root := t.TempDir()
	mgr := session.NewManager(root)
	const n = 32
	ids := make(chan string, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			s, err := mgr.Create("", "agent.exe", "", nil)
			if err != nil {
				t.Errorf("Create: %v", err)
				return
			}
			ids <- s.Meta.ID
			_ = s.Store.Close()
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[string]struct{}{}
	for id := range ids {
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate empty-id session: %s", id)
		}
		seen[id] = struct{}{}
	}
	if len(seen) != n {
		t.Fatalf("want %d unique ids, got %d", n, len(seen))
	}
}

func TestWriteMetaAtomicReadable(t *testing.T) {
	root := t.TempDir()
	mgr := session.NewManager(root)
	s, err := mgr.Create("meta-race", "agent.exe", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Store.Close()

	statuses := []session.Status{
		session.StatusStarting,
		session.StatusRunning,
		session.StatusCollecting,
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			if err := s.SetStatus(statuses[i%len(statuses)]); err != nil {
				errCh <- err
			}
		}(i)
		go func() {
			defer wg.Done()
			opened, err := mgr.Open("meta-race")
			if err != nil {
				errCh <- err
				return
			}
			if opened.Meta.ID != "meta-race" {
				errCh <- fmt.Errorf("bad id %q", opened.Meta.ID)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

package session_test

import (
	"strings"
	"testing"

	"basb/internal/event"
	"basb/internal/session"
)

func TestTakeEmitFaultAfterClosedStore(t *testing.T) {
	root := t.TempDir()
	mgr := session.NewManager(root)
	s, err := mgr.Create("emit-fault", "agent.exe", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.Close(); err != nil {
		t.Fatal(err)
	}

	ev := event.New(s.Meta.ID, event.CatProcess, event.TypeCreate)
	if err := s.Emit(ev); err == nil {
		t.Fatal("expected Emit to fail on closed store")
	}
	fault := s.TakeEmitFault()
	if fault == nil {
		t.Fatal("expected TakeEmitFault after failed Emit")
	}
	if !strings.Contains(fault.Error(), "emit") && !strings.Contains(fault.Error(), "store") {
		t.Fatalf("unexpected fault: %v", fault)
	}
	if s.TakeEmitFault() != nil {
		t.Fatal("TakeEmitFault should clear after read")
	}
}

func TestTakeEmitFaultNilStore(t *testing.T) {
	root := t.TempDir()
	mgr := session.NewManager(root)
	s, err := mgr.Create("emit-nil", "agent.exe", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Complete(0, nil) // closes store and nils it

	ev := event.New(s.Meta.ID, event.CatProcess, event.TypeCreate)
	if err := s.Emit(ev); err == nil {
		t.Fatal("expected Emit to fail when store is nil")
	}
	if s.TakeEmitFault() == nil {
		t.Fatal("expected TakeEmitFault when store is nil")
	}
}

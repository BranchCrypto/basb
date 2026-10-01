package session_test

import (
	"strings"
	"testing"

	"basb/internal/session"
)

func TestCreateRejectsPathTraversalID(t *testing.T) {
	root := t.TempDir()
	mgr := session.NewManager(root)
	for _, id := range []string{`..\evil`, `..\\evil`, `a/b`, `a\b`, `..`} {
		_, err := mgr.Create(id, "agent.exe", "", nil)
		if err == nil {
			t.Fatalf("Create(%q) should reject path-like id", id)
		}
		if !strings.Contains(err.Error(), "invalid session id") {
			t.Fatalf("Create(%q): want invalid session id, got %v", id, err)
		}
	}
}

func TestOpenRejectsPathTraversalID(t *testing.T) {
	root := t.TempDir()
	mgr := session.NewManager(root)
	_, err := mgr.Open(`..\..\windows`)
	if err == nil || !strings.Contains(err.Error(), "invalid session id") {
		t.Fatalf("Open path traversal: %v", err)
	}
}

package marker_test

import (
	"testing"

	"basb/internal/collect/marker"
	"basb/internal/event"
)

func TestClassifyPath(t *testing.T) {
	cases := []struct {
		path string
		cat  event.Category
		ok   bool
	}{
		{`C:\Users\a\.ssh\id_rsa`, event.CatCredential, true},
		{`D:\proj\.env`, event.CatCredential, true},
		{`C:\Windows\System32\cmd.exe`, event.CatSensitive, true},
		{`C:\temp\out.txt`, "", false},
	}
	for _, c := range cases {
		m, ok := marker.ClassifyPath(c.path)
		if ok != c.ok {
			t.Fatalf("%s: ok=%v want %v", c.path, ok, c.ok)
		}
		if ok && m.Category != c.cat {
			t.Fatalf("%s: category=%s want %s", c.path, m.Category, c.cat)
		}
	}
}

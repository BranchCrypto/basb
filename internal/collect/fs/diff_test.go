package fs

import "testing"

func TestLooksDownloadArtifact(t *testing.T) {
	cases := map[string]bool{
		"out.txt":           false,
		"notes.md":          false,
		"tool.exe":          true,
		"setup.msi":         true,
		"script.ps1":        true,
		"pkg.whl":           true,
		"Chrome.Download":   true,
		"subdir/tool.DLL":   true,
		"data.zip":          false, // archive → exfil, not download
	}
	for name, want := range cases {
		if got := looksDownloadArtifact(name); got != want {
			t.Fatalf("%q: got %v want %v", name, got, want)
		}
	}
}

func TestLooksArchive(t *testing.T) {
	if !looksArchive(`dir\payload.zip`) {
		t.Fatal("expected zip archive")
	}
	if looksArchive("out.txt") {
		t.Fatal("txt is not archive")
	}
}

package fs

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"basb/internal/collect/marker"
	"basb/internal/event"
)

// Emitter writes fs audit events.
type Emitter interface {
	Emit(ev event.Event) error
}

// Snapshot is a simple path → modtime+size map for workdir diff.
type Snapshot map[string]fileInfo

type fileInfo struct {
	Size    int64
	ModTime time.Time
}

// Take walks root and records regular files.
func Take(root string) (Snapshot, error) {
	out := Snapshot{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		out[rel] = fileInfo{Size: info.Size(), ModTime: info.ModTime()}
		return nil
	})
	return out, err
}

// DiffEmit writes file.create / file.write / file.delete events for workdir changes.
func DiffEmit(em Emitter, sessionID, root string, before Snapshot) error {
	after, err := Take(root)
	if err != nil {
		return err
	}
	for rel, info := range after {
		prev, ok := before[rel]
		abs := filepath.Join(root, rel)
		var actionType string
		if !ok {
			actionType = event.TypeCreate
		} else if prev.Size == info.Size && prev.ModTime.Equal(info.ModTime) {
			continue
		} else {
			actionType = event.TypeWrite
		}
		ev := event.New(sessionID, event.CatFile, actionType)
		ev.WithFileTarget(abs)
		ev.Meta["size"] = info.Size
		ev.Meta["rel"] = rel
		if h, err := fileSHA256(abs); err == nil {
			ev.Meta["sha256"] = h
		}
		if err := em.Emit(ev); err != nil {
			return err
		}
		_ = marker.EmitPathHit(em, sessionID, 0, abs, "fs_diff")
		maybeDownloadOrExfil(em, sessionID, abs, rel, info.Size, actionType)
	}
	for rel := range before {
		if _, ok := after[rel]; ok {
			continue
		}
		abs := filepath.Join(root, rel)
		ev := event.New(sessionID, event.CatFile, event.TypeDelete)
		ev.WithFileTarget(abs)
		ev.Meta["rel"] = rel
		if err := em.Emit(ev); err != nil {
			return err
		}
		_ = marker.EmitPathHit(em, sessionID, 0, abs, "fs_unlink")
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 32<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func maybeDownloadOrExfil(em Emitter, sessionID, abs, rel string, size int64, actionType string) {
	lower := strings.ToLower(filepath.ToSlash(rel))
	if actionType == event.TypeCreate && looksDownloadArtifact(lower) {
		ev := event.New(sessionID, event.CatDownload, event.TypeCreate)
		ev.WithFileTarget(abs)
		ev.Meta["size"] = size
		ev.Meta["rel"] = rel
		ev.Meta["note"] = "new payload-like file in workdir"
		_ = em.Emit(ev)
	}
	if looksArchive(lower) {
		ev := event.New(sessionID, event.CatExfil, event.TypeCopy)
		ev.WithFileTarget(abs)
		ev.Meta["size"] = size
		ev.Meta["note"] = "archive created/modified in workdir"
		ev.RiskLevel = event.RiskMedium
		_ = em.Emit(ev)
	}
}

func looksDownloadArtifact(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	if strings.Contains(base, ".download") || strings.HasPrefix(base, "download") {
		return true
	}
	for _, suf := range []string{
		".exe", ".msi", ".msix", ".dll", ".sys",
		".ps1", ".bat", ".cmd", ".vbs", ".js",
		".jar", ".apk", ".dmg", ".pkg", ".deb", ".rpm",
		".iso", ".img", ".bin", ".whl", ".nupkg",
	} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return false
}

func looksArchive(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	for _, suf := range []string{".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2"} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return false
}

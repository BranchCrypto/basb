package summary

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"basb/internal/analysis"
	"basb/internal/session"
)

// ExportZip packs meta.json, events.jsonl, report.json, and summary.json.
func ExportZip(sess *session.Session, outPath string) error {
	events, err := sess.ReadEvents()
	if err != nil {
		return fmt.Errorf("read events: %w", err)
	}

	rep := analysis.Build(sess.Meta, events)
	repRaw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}

	sum := map[string]any{
		"session":     sess.Meta,
		"mode":        sess.Meta.Mode,
		"event_count": len(events),
		"counts":      rep.Counts,
	}
	sumRaw, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil && filepath.Dir(outPath) != "." {
		return err
	}

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	addFile := func(name, src string) error {
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, in)
		return err
	}

	if err := addFile("meta.json", filepath.Join(sess.Dir, "meta.json")); err != nil {
		return err
	}
	if err := addFile("events.jsonl", filepath.Join(sess.Dir, "events.jsonl")); err != nil {
		return err
	}
	for _, item := range []struct {
		name string
		data []byte
	}{
		{"report.json", repRaw},
		{"summary.json", sumRaw},
	} {
		w, err := zw.Create(item.name)
		if err != nil {
			return err
		}
		if _, err := w.Write(item.data); err != nil {
			return err
		}
	}
	return zw.Close()
}

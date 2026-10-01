package summary

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"basb/internal/analysis"
	"basb/internal/event"
	"basb/internal/session"
)

// Print writes a human-readable session summary to w.
func Print(w io.Writer, meta session.Meta, events []event.Event) {
	rep := analysis.Build(meta, events)

	fmt.Fprintf(w, "Session:   %s\n", meta.ID)
	fmt.Fprintf(w, "Sandbox:   %s\n", meta.SandboxID)
	fmt.Fprintf(w, "Agent:     %s\n", meta.Agent)
	fmt.Fprintf(w, "Mode:      %s\n", meta.Mode)
	fmt.Fprintf(w, "WorkDir:   %s\n", meta.WorkDir)
	fmt.Fprintf(w, "Status:    %s\n", meta.Status)
	if meta.ExitCode != nil {
		fmt.Fprintf(w, "ExitCode:  %d\n", *meta.ExitCode)
	}
	if meta.EndedAt != nil {
		fmt.Fprintf(w, "Duration:  %s\n", meta.EndedAt.Sub(meta.StartedAt).Round(time.Millisecond))
	}
	fmt.Fprintln(w)

	c := rep.Counts
	fmt.Fprintf(w, "Events: total=%d\n", c.Total)
	fmt.Fprintf(w, "  process      %d\n", c.Process)
	fmt.Fprintf(w, "  shell        %d\n", c.Shell)
	fmt.Fprintf(w, "  file.create  %d\n", c.FileCreate)
	fmt.Fprintf(w, "  file.write   %d\n", c.FileWrite)
	fmt.Fprintf(w, "  file.delete  %d\n", c.FileDelete)
	fmt.Fprintf(w, "  network      %d\n", c.Network)
	fmt.Fprintf(w, "  dns          %d\n", c.DNS)
	fmt.Fprintf(w, "  download     %d\n", c.Download)
	fmt.Fprintf(w, "  sensitive    %d\n", c.Sensitive)
	fmt.Fprintf(w, "  credential   %d\n", c.Credential)
	fmt.Fprintln(w)

	if len(rep.ProcessTree) > 0 {
		fmt.Fprintln(w, "Process tree:")
		fmt.Fprint(w, analysis.FormatTree(rep.ProcessTree))
		fmt.Fprintln(w)
	}

	if len(rep.Sensitive) > 0 {
		fmt.Fprintln(w, "Sensitive / credential (observe=ALLOW):")
		for _, item := range rep.Sensitive {
			fmt.Fprintf(w, "  [%s] %s  %s\n", item.Risk, item.Type, item.Target)
		}
	}
}

// Filter returns events whose category or "category.type" is in the allow list (empty = all).
// Accepts short aliases: net→network, fs/file→file, secret→credential, risk→sensitive.
func Filter(events []event.Event, typesCSV string) []event.Event {
	typesCSV = strings.TrimSpace(typesCSV)
	if typesCSV == "" {
		return events
	}
	aliases := map[string]string{
		"net":    "network",
		"fs":     "file",
		"secret": "credential",
		"risk":   "sensitive",
	}
	allow := map[string]bool{}
	for _, t := range strings.Split(typesCSV, ",") {
		key := strings.TrimSpace(strings.ToLower(t))
		if key == "" {
			continue
		}
		if canon, ok := aliases[key]; ok {
			key = canon
		}
		allow[key] = true
	}
	var out []event.Event
	for _, ev := range events {
		cat := strings.ToLower(string(ev.Action.Category))
		full := strings.ToLower(ev.TypeString())
		if allow[cat] || allow[full] || allow[strings.ToLower(ev.Action.Type)] {
			out = append(out, ev)
			continue
		}
		// "sensitive" / "risk" match the same surface as analysis.IsSensitive
		if allow["sensitive"] && analysis.IsSensitive(ev) {
			out = append(out, ev)
		}
	}
	return out
}

// UniqueStrings returns sorted unique strings.
func UniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

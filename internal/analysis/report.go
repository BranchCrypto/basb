package analysis

import (
	"sort"
	"strings"
	"time"

	"basb/internal/event"
	"basb/internal/session"
)

// Counts are deterministic Phase-1/2 stats (docs §19).
type Counts struct {
	Process        int `json:"process"`
	FileRead       int `json:"file_read"`
	FileWrite      int `json:"file_write"`
	FileCreate     int `json:"file_create"`
	FileDelete     int `json:"file_delete"`
	Network        int `json:"network"`
	DNS            int `json:"dns"`
	Download       int `json:"download"`
	Upload         int `json:"upload"`
	Sensitive      int `json:"sensitive"`
	Credential     int `json:"credential"`
	Shell          int `json:"shell"`
	Total          int `json:"total"`
}

// ProcessNode is one node in the process tree.
type ProcessNode struct {
	PID         uint32         `json:"pid"`
	PPID        uint32         `json:"ppid"`
	CommandLine string         `json:"command_line"`
	Executable  string         `json:"executable,omitempty"`
	Children    []ProcessNode  `json:"children,omitempty"`
}

// TimelineItem is a simplified timeline row.
type TimelineItem struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	PID       uint32          `json:"pid"`
	Target    string          `json:"target"`
	Risk      event.RiskLevel `json:"risk,omitempty"`
	Mode      event.Mode      `json:"mode"`
	Decision  string          `json:"decision"`
}

// Report is the task report surface for UI / export.
type Report struct {
	SessionID   string          `json:"session_id"`
	SandboxID   string          `json:"sandbox_id"`
	AgentID     string          `json:"agent_id"`
	Agent       string          `json:"agent"`
	Mode        event.Mode      `json:"mode"`
	Status      session.Status  `json:"status"`
	RootPID     uint32          `json:"root_pid,omitempty"`
	Counts      Counts          `json:"counts"`
	ProcessTree []ProcessNode   `json:"process_tree"`
	Timeline    []TimelineItem  `json:"timeline"`
	Sensitive   []TimelineItem  `json:"sensitive_events"`
}

// Build produces a deterministic report from session meta + events.
func Build(meta session.Meta, events []event.Event) Report {
	rep := Report{
		SessionID: meta.ID,
		SandboxID: meta.SandboxID,
		AgentID:   meta.AgentID,
		Agent:     meta.Agent,
		Mode:      meta.Mode,
		Status:    meta.Status,
		RootPID:   meta.RootPID,
		Counts:    countEvents(events),
		Timeline:  makeTimeline(events, 0),
		Sensitive: filterSensitive(events),
	}
	rep.ProcessTree = BuildProcessTree(meta.RootPID, events)
	return rep
}

// IsSensitive reports whether an event belongs in the risk / sensitive surface.
// Kept in sync with UI "风险" filter and Counts.Sensitive.
func IsSensitive(ev event.Event) bool {
	if ev.RiskLevel == event.RiskHigh || ev.RiskLevel == event.RiskCritical {
		return true
	}
	switch ev.Action.Category {
	case event.CatCredential, event.CatSensitive:
		return true
	default:
		return false
	}
}

func countEvents(events []event.Event) Counts {
	var c Counts
	c.Total = len(events)
	for _, ev := range events {
		switch ev.Action.Category {
		case event.CatProcess:
			if ev.Action.Type == event.TypeCreate {
				c.Process++
			}
		case event.CatFile:
			switch ev.Action.Type {
			case event.TypeRead:
				c.FileRead++
			case event.TypeWrite:
				c.FileWrite++
			case event.TypeCreate:
				c.FileCreate++
			case event.TypeDelete:
				c.FileDelete++
			}
		case event.CatNetwork:
			c.Network++
			if ev.Action.Type == event.TypeDNS {
				c.DNS++
			}
		case event.CatDownload:
			c.Download++
		case event.CatUpload:
			c.Upload++
		case event.CatCredential:
			c.Credential++
		case event.CatShell:
			c.Shell++
		}
		if IsSensitive(ev) {
			c.Sensitive++
		}
	}
	return c
}

func makeTimeline(events []event.Event, limit int) []TimelineItem {
	sorted := sortedByTime(events)
	out := make([]TimelineItem, 0, len(sorted))
	for _, ev := range sorted {
		out = append(out, toTimelineItem(ev))
	}
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

func filterSensitive(events []event.Event) []TimelineItem {
	sorted := sortedByTime(events)
	var out []TimelineItem
	for _, ev := range sorted {
		if IsSensitive(ev) {
			out = append(out, toTimelineItem(ev))
		}
	}
	return out
}

func toTimelineItem(ev event.Event) TimelineItem {
	return TimelineItem{
		Timestamp: ev.Timestamp.UTC().Format(time.RFC3339Nano),
		Type:      ev.TypeString(),
		PID:       ev.Actor.PID,
		Target:    ev.DisplayTarget(),
		Risk:      ev.RiskLevel,
		Mode:      ev.Decision.Mode,
		Decision:  string(ev.Decision.Result),
	}
}

func sortedByTime(events []event.Event) []event.Event {
	out := make([]event.Event, len(events))
	copy(out, events)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Timestamp.Before(out[j].Timestamp)
	})
	return out
}

type procInfo struct {
	pid, ppid uint32
	cmdline   string
	exe       string
}

// BuildProcessTree reconstructs a tree from process.create events.
func BuildProcessTree(rootPID uint32, events []event.Event) []ProcessNode {
	byPID := map[uint32]*procInfo{}
	order := make([]uint32, 0)
	for _, ev := range events {
		if ev.Action.Category != event.CatProcess || ev.Action.Type != event.TypeCreate {
			continue
		}
		pid := ev.Actor.PID
		if pid == 0 {
			continue
		}
		if _, ok := byPID[pid]; ok {
			continue
		}
		info := &procInfo{
			pid:     pid,
			ppid:    ev.Actor.PPID,
			cmdline: ev.Actor.CommandLine,
			exe:     ev.Actor.Executable,
		}
		if info.cmdline == "" {
			info.cmdline = ev.DisplayTarget()
		}
		byPID[pid] = info
		order = append(order, pid)
	}
	if len(byPID) == 0 {
		return nil
	}

	children := map[uint32][]uint32{}
	var roots []uint32
	for _, pid := range order {
		info := byPID[pid]
		if info.ppid == 0 || byPID[info.ppid] == nil || info.ppid == pid {
			roots = append(roots, pid)
			continue
		}
		children[info.ppid] = append(children[info.ppid], pid)
	}
	if rootPID != 0 {
		if _, ok := byPID[rootPID]; ok {
			roots = []uint32{rootPID}
			// orphan nodes whose parent isn't under root still appear as extra roots
			for _, pid := range order {
				if pid == rootPID {
					continue
				}
				info := byPID[pid]
				if byPID[info.ppid] == nil {
					roots = append(roots, pid)
				}
			}
		}
	}

	seen := map[uint32]bool{}
	var build func(pid uint32) ProcessNode
	build = func(pid uint32) ProcessNode {
		seen[pid] = true
		info := byPID[pid]
		node := ProcessNode{
			PID:         pid,
			PPID:        info.ppid,
			CommandLine: info.cmdline,
			Executable:  info.exe,
		}
		kids := children[pid]
		sort.Slice(kids, func(i, j int) bool { return kids[i] < kids[j] })
		for _, c := range kids {
			if seen[c] {
				continue
			}
			node.Children = append(node.Children, build(c))
		}
		return node
	}

	var tree []ProcessNode
	for _, r := range roots {
		if seen[r] {
			continue
		}
		tree = append(tree, build(r))
	}
	return tree
}

// FormatTree returns a text process tree for CLI.
func FormatTree(nodes []ProcessNode) string {
	var b strings.Builder
	var walk func(n ProcessNode, prefix string, isRoot, last bool)
	walk = func(n ProcessNode, prefix string, isRoot, last bool) {
		branch := "├── "
		next := prefix + "│   "
		if last {
			branch = "└── "
			next = prefix + "    "
		}
		if isRoot {
			branch = ""
			next = ""
		}
		line := n.CommandLine
		if line == "" {
			line = n.Executable
		}
		b.WriteString(prefix + branch + "pid=" + itoa(n.PID) + "  " + line + "\n")
		for i, c := range n.Children {
			walk(c, next, false, i == len(n.Children)-1)
		}
	}
	for i, n := range nodes {
		walk(n, "", true, i == len(nodes)-1)
	}
	return b.String()
}

func itoa(u uint32) string {
	if u == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	return string(buf[i:])
}

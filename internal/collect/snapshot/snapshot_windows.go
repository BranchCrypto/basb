//go:build windows

package snapshot

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"basb/internal/event"
	"golang.org/x/sys/windows/registry"
)

// Emitter writes audit events.
type Emitter interface {
	Emit(ev event.Event) error
}

// Bundle is a before/after snapshot of system surfaces covered by doc.md.
type Bundle struct {
	Startup  map[string]string
	Users    map[string]string
	Firewall map[string]string
	Tasks    map[string]string
	Services map[string]string
	Policy   map[string]string
}

// Take captures current startup / user / firewall / persist / policy state (best-effort).
func Take() Bundle {
	return TakeFull()
}

// TakeLight captures fast surfaces only (registry startup, users, UAC policy).
func TakeLight() Bundle {
	return Bundle{
		Startup:  takeStartup(),
		Users:    takeUsers(),
		Firewall: map[string]string{},
		Tasks:    map[string]string{},
		Services: map[string]string{},
		Policy:   takePolicyLight(),
	}
}

// TakeFull includes firewall rules, scheduled tasks, services, and Defender status.
func TakeFull() Bundle {
	return Bundle{
		Startup:  takeStartup(),
		Users:    takeUsers(),
		Firewall: takeFirewall(),
		Tasks:    takeTasks(),
		Services: takeServices(),
		Policy:   takePolicy(),
	}
}

// DiffEmit emits add/modify/delete events comparing before and after.
func DiffEmit(em Emitter, sessionID string, before, after Bundle) {
	diffMap(em, sessionID, event.CatStartup, "registry", before.Startup, after.Startup)
	diffMap(em, sessionID, event.CatIdentity, "user", before.Users, after.Users)
	diffMap(em, sessionID, event.CatFirewall, "firewall_rule", before.Firewall, after.Firewall)
	diffMap(em, sessionID, event.CatPersistence, "scheduled_task", before.Tasks, after.Tasks)
	diffMap(em, sessionID, event.CatPersistence, "service", before.Services, after.Services)
	diffMap(em, sessionID, event.CatSecurity, "policy", before.Policy, after.Policy)
}

func diffMap(em Emitter, sessionID string, cat event.Category, targetType string, before, after map[string]string) {
	for k, v := range after {
		prev, ok := before[k]
		if !ok {
			ev := event.New(sessionID, cat, event.TypeAdd)
			ev.WithValueTarget(targetType, k)
			ev.Meta["value"] = truncate(v, 512)
			if cat == event.CatPersistence || cat == event.CatFirewall || cat == event.CatSecurity {
				ev.RiskLevel = event.RiskMedium
			}
			_ = em.Emit(ev)
			continue
		}
		if prev != v {
			ev := event.New(sessionID, cat, event.TypeModify)
			ev.WithValueTarget(targetType, k)
			ev.Meta["before"] = truncate(prev, 256)
			ev.Meta["after"] = truncate(v, 256)
			if cat == event.CatPersistence || cat == event.CatFirewall || cat == event.CatSecurity {
				ev.RiskLevel = event.RiskMedium
			}
			_ = em.Emit(ev)
		}
	}
	for k, v := range before {
		if _, ok := after[k]; ok {
			continue
		}
		ev := event.New(sessionID, cat, event.TypeDelete)
		ev.WithValueTarget(targetType, k)
		ev.Meta["value"] = truncate(v, 512)
		_ = em.Emit(ev)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func takeStartup() map[string]string {
	out := map[string]string{}
	readRunKey := func(root registry.Key, path, label string) {
		k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
		if err != nil {
			return
		}
		defer k.Close()
		names, err := k.ReadValueNames(-1)
		if err != nil {
			return
		}
		for _, name := range names {
			val, _, err := k.GetStringValue(name)
			if err != nil {
				continue
			}
			out[label+`\`+name] = val
		}
	}
	readRunKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\Run`)
	readRunKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKCU\RunOnce`)
	readRunKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Run`)
	readRunKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\RunOnce`)
	return out
}

func takeUsers() map[string]string {
	out := map[string]string{}
	cmd := exec.Command("net", "user")
	raw, err := cmd.Output()
	if err != nil {
		return out
	}
	lines := strings.Split(string(raw), "\n")
	inList := false
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.Contains(line, "---") {
			inList = true
			continue
		}
		if !inList {
			continue
		}
		if strings.HasPrefix(line, "The command completed") || strings.Contains(line, "命令成功") {
			break
		}
		for _, name := range strings.Fields(line) {
			out["user:"+name] = "present"
		}
	}
	return out
}

func takeFirewall() map[string]string {
	out := map[string]string{}
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in")
	raw, err := cmd.Output()
	if err != nil {
		return out
	}
	var name, enabled, action string
	flush := func() {
		if name == "" {
			return
		}
		out["fw:"+name] = fmt.Sprintf("enabled=%s;action=%s", enabled, action)
		name, enabled, action = "", "", ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "rule name:") || strings.HasPrefix(line, "规则名称:") {
			flush()
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				name = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(lower, "enabled:") || strings.HasPrefix(line, "已启用:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				enabled = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(lower, "action:") || strings.HasPrefix(line, "操作:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				action = strings.TrimSpace(parts[1])
			}
		}
	}
	flush()
	return out
}

func takeTasks() map[string]string {
	out := map[string]string{}
	cmd := exec.Command("schtasks", "/query", "/fo", "CSV", "/nh")
	raw, err := cmd.Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		fields := parseCSVLine(line)
		if len(fields) >= 1 && fields[0] != "" {
			out["task:"+fields[0]] = strings.Join(fields, "|")
		}
	}
	return out
}

func takeServices() map[string]string {
	out := map[string]string{}
	cmd := exec.Command("sc", "query", "type=", "service", "state=", "all")
	raw, err := cmd.Output()
	if err != nil {
		return out
	}
	var name, state string
	flush := func() {
		if name == "" {
			return
		}
		out["service:"+name] = state
		name, state = "", ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		trim := strings.TrimSpace(line)
		lower := strings.ToLower(trim)
		if strings.HasPrefix(lower, "service_name:") {
			flush()
			parts := strings.SplitN(trim, ":", 2)
			if len(parts) == 2 {
				name = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(lower, "state:") {
			parts := strings.SplitN(trim, ":", 2)
			if len(parts) == 2 {
				state = strings.TrimSpace(parts[1])
			}
		}
	}
	flush()
	return out
}

func takePolicyLight() map[string]string {
	out := map[string]string{}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		if v, _, err := k.GetIntegerValue("EnableLUA"); err == nil {
			out["uac.enable_lua"] = fmt.Sprintf("%d", v)
		}
		if v, _, err := k.GetIntegerValue("ConsentPromptBehaviorAdmin"); err == nil {
			out["uac.consent_admin"] = fmt.Sprintf("%d", v)
		}
	}
	return out
}

func takePolicy() map[string]string {
	out := takePolicyLight()
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"try { (Get-MpPreference).DisableRealtimeMonitoring } catch { 'unknown' }")
	if raw, err := cmd.Output(); err == nil {
		out["defender.disable_realtime"] = strings.TrimSpace(string(raw))
	}
	cmd = exec.Command("powershell", "-NoProfile", "-Command",
		"try { (Get-MpComputerStatus).AMServiceEnabled } catch { 'unknown' }")
	if raw, err := cmd.Output(); err == nil {
		out["defender.am_service_enabled"] = strings.TrimSpace(string(raw))
	}
	return out
}

func parseCSVLine(line string) []string {
	var fields []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQ = !inQ
		case c == ',' && !inQ:
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	fields = append(fields, cur.String())
	return fields
}

// SortedKeys is a helper for tests/debug.
func SortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

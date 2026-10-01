package marker

import (
	"path/filepath"
	"strings"

	"basb/internal/event"
)

// Match describes a sensitive-path rule hit.
type Match struct {
	Category  event.Category
	Rule      string
	Reason    string
	RiskLevel event.RiskLevel
}

var pathRules = []struct {
	substr   string
	category event.Category
	rule     string
	reason   string
	risk     event.RiskLevel
}{
	{`id_rsa`, event.CatCredential, "ssh_key", "SSH private key", event.RiskCritical},
	{`id_ed25519`, event.CatCredential, "ssh_key", "SSH private key", event.RiskCritical},
	{`id_ecdsa`, event.CatCredential, "ssh_key", "SSH private key", event.RiskCritical},
	{`id_dsa`, event.CatCredential, "ssh_key", "SSH private key", event.RiskCritical},
	{`known_hosts`, event.CatSSH, "ssh_known_hosts", "SSH known_hosts", event.RiskLow},
	{`authorized_keys`, event.CatSSH, "ssh_authorized_keys", "SSH authorized_keys", event.RiskMedium},
	{`.ssh`, event.CatSSH, "ssh_dir", "SSH key / config directory", event.RiskHigh},
	{`.env`, event.CatCredential, "dotenv", "Environment secrets file", event.RiskHigh},
	{`credentials`, event.CatCredential, "credentials", "Credentials file", event.RiskHigh},
	{`credential`, event.CatCredential, "credentials", "Credentials file", event.RiskHigh},
	{`secret`, event.CatCredential, "secret", "Secret-bearing path", event.RiskHigh},
	{`token`, event.CatCredential, "token", "Token-bearing path", event.RiskHigh},
	{`cookie`, event.CatCredential, "browser_cookie", "Browser cookie store", event.RiskHigh},
	{`cookies`, event.CatCredential, "browser_cookie", "Browser cookie store", event.RiskHigh},
	{`login data`, event.CatCredential, "browser_login", "Browser login database", event.RiskHigh},
	{`logins.json`, event.CatCredential, "browser_login", "Browser login store", event.RiskHigh},
	{`web data`, event.CatCredential, "browser_data", "Browser data store", event.RiskMedium},
	{`appdata\roaming\microsoft\credentials`, event.CatCredential, "win_cred", "Windows credential store", event.RiskCritical},
	{`appdata\local\microsoft\credentials`, event.CatCredential, "win_cred", "Windows credential store", event.RiskCritical},
	{`\windows\system32`, event.CatSensitive, "system32", "Windows system directory", event.RiskMedium},
	{`\windows\syswow64`, event.CatSensitive, "syswow64", "Windows system directory", event.RiskMedium},
	{`\program files`, event.CatSensitive, "program_files", "Program Files", event.RiskLow},
	{`.git\config`, event.CatSensitive, "git_config", "Git repository config", event.RiskLow},
	{`.git\`, event.CatSensitive, "git_repo", "Git repository", event.RiskLow},
	{`\etc\passwd`, event.CatSensitive, "etc_passwd", "Unix passwd file", event.RiskMedium},
	{`\etc\shadow`, event.CatCredential, "etc_shadow", "Unix shadow file", event.RiskCritical},
}

// ClassifyPath returns the first matching sensitive rule for path, if any.
func ClassifyPath(path string) (Match, bool) {
	n := strings.ToLower(filepath.ToSlash(path))
	n = strings.ReplaceAll(n, "/", `\`)
	for _, r := range pathRules {
		if strings.Contains(n, r.substr) {
			return Match{Category: r.category, Rule: r.rule, Reason: r.reason, RiskLevel: r.risk}, true
		}
	}
	return Match{}, false
}

// EmitPathHit writes credential/sensitive/ssh events for a path touch.
// In observe mode these are recorded with risk but never blocked.
func EmitPathHit(em interface{ Emit(event.Event) error }, sessionID string, pid uint32, path string, via string) error {
	m, ok := ClassifyPath(path)
	if !ok {
		return nil
	}
	actionType := event.TypeHit
	if m.Category == event.CatCredential {
		actionType = event.TypeRead
	}
	ev := event.New(sessionID, m.Category, actionType)
	ev.WithActorPID(pid, 0)
	ev.WithFileTarget(path)
	ev.RiskLevel = m.RiskLevel
	ev.Meta["rule"] = m.Rule
	ev.Meta["reason"] = m.Reason
	ev.Meta["via"] = via
	return em.Emit(ev)
}

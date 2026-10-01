package event

import (
	"time"

	"github.com/google/uuid"
)

const SchemaVersion = "1.0"

// Mode is the product execution mode (Observe vs Protect).
type Mode string

const (
	ModeObserve Mode = "observe"
	ModeProtect Mode = "protect"
)

// DecisionResult is the execution outcome recorded on an event.
type DecisionResult string

const (
	ResultAllow DecisionResult = "ALLOW"
	ResultDeny  DecisionResult = "DENY"
	ResultAsk   DecisionResult = "ASK"
	ResultBlock DecisionResult = "BLOCK"
)

// RiskLevel is analysis output and must not imply blocking in observe mode.
type RiskLevel string

const (
	RiskInfo     RiskLevel = "INFO"
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// Category is action.category in the unified event model.
type Category string

const (
	CatProcess     Category = "process"
	CatShell       Category = "shell"
	CatFile        Category = "file"
	CatNetwork     Category = "network"
	CatDownload    Category = "download"
	CatUpload      Category = "upload"
	CatSSH         Category = "ssh"
	CatIdentity    Category = "identity"
	CatCredential  Category = "credential"
	CatPrivilege   Category = "privilege"
	CatPersistence Category = "persistence"
	CatFirewall    Category = "firewall"
	CatSecurity    Category = "security"
	CatStartup     Category = "startup"
	CatAgent       Category = "agent"
	CatSandbox     Category = "sandbox"
	CatModule      Category = "module"
	CatExfil       Category = "exfil"
	CatSensitive   Category = "sensitive"
)

// Action type strings (action.type) — aligned with docs §10.
const (
	TypeCreate   = "create"
	TypeExit     = "exit"
	TypeStart    = "start"
	TypeStop     = "stop"
	TypeDestroy  = "destroy"
	TypeExecute  = "execute"
	TypeRead     = "read"
	TypeWrite    = "write"
	TypeRename   = "rename"
	TypeDelete   = "delete"
	TypeConnect  = "connect"
	TypeClose    = "close"
	TypeDNS      = "dns"
	TypeHit      = "hit"
	TypeAdd      = "add"
	TypeModify   = "modify"
	TypeLoad     = "load"
	TypeElevate  = "elevate"
	TypeUpload   = "upload"
	TypeDownload = "download"
	TypeCopy     = "copy"
)

// Actor describes the process that caused the event.
type Actor struct {
	PID         uint32 `json:"pid,omitempty"`
	PPID        uint32 `json:"ppid,omitempty"`
	User        string `json:"user,omitempty"`
	Executable  string `json:"executable,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	Cwd         string `json:"cwd,omitempty"`
}

// ActionSpec is the categorized verb.
type ActionSpec struct {
	Category Category `json:"category"`
	Type     string   `json:"type"`
}

// Target describes the object of the action.
type Target struct {
	Type   string `json:"type,omitempty"` // file | host | process | registry | user | …
	Path   string `json:"path,omitempty"`
	Value  string `json:"value,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Network holds connection / DNS metadata (prefer metadata over bodies).
type Network struct {
	Domain          string `json:"domain,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	LocalPort       int    `json:"local_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	BytesSent       uint64 `json:"bytes_sent,omitempty"`
	BytesReceived   uint64 `json:"bytes_received,omitempty"`
	State           string `json:"state,omitempty"`
	Scheme          string `json:"scheme,omitempty"`
}

// Decision records mode + execution result. In observe mode result is always ALLOW.
type Decision struct {
	Mode     Mode           `json:"mode"`
	Result   DecisionResult `json:"result"`
	PolicyID *string        `json:"policy_id"`
}

// Correlation links events into behavior chains.
type Correlation struct {
	ParentEventID *string `json:"parent_event_id"`
	TraceID       string  `json:"trace_id,omitempty"`
}

// Event is one structured audit record (JSONL line) — docs §9.
type Event struct {
	SchemaVersion string       `json:"schema_version"`
	EventID       string       `json:"event_id"`
	Timestamp     time.Time    `json:"timestamp"`
	SandboxID     string       `json:"sandbox_id"`
	SessionID     string       `json:"session_id"`
	AgentID       string       `json:"agent_id,omitempty"`
	Actor         Actor        `json:"actor"`
	Action        ActionSpec   `json:"action"`
	Target        Target       `json:"target"`
	Network       *Network     `json:"network"`
	Decision      Decision     `json:"decision"`
	Correlation   Correlation  `json:"correlation"`
	RiskLevel     RiskLevel    `json:"risk_level,omitempty"`
	Meta          map[string]any `json:"meta,omitempty"`
}

// New builds an Observe-mode event with schema version and UUID.
func New(sessionID string, category Category, actionType string) Event {
	return Event{
		SchemaVersion: SchemaVersion,
		EventID:       uuid.NewString(),
		Timestamp:     time.Now().UTC(),
		SessionID:     sessionID,
		SandboxID:     sessionID,
		Action:        ActionSpec{Category: category, Type: actionType},
		Network:       nil,
		Decision: Decision{
			Mode:     ModeObserve,
			Result:   ResultAllow,
			PolicyID: nil,
		},
		Correlation: Correlation{
			ParentEventID: nil,
		},
		Meta: map[string]any{},
	}
}

// Category returns action.category for filters / UI chips.
func (e Event) Category() Category { return e.Action.Category }

// TypeString returns "category.type" (e.g. process.create).
func (e Event) TypeString() string {
	if e.Action.Category == "" {
		return e.Action.Type
	}
	if e.Action.Type == "" {
		return string(e.Action.Category)
	}
	return string(e.Action.Category) + "." + e.Action.Type
}

// DisplayTarget is a single-line target for timelines.
func (e Event) DisplayTarget() string {
	if e.Target.Path != "" {
		return e.Target.Path
	}
	if e.Target.Value != "" {
		return e.Target.Value
	}
	if e.Target.Detail != "" {
		return e.Target.Detail
	}
	if e.Actor.CommandLine != "" {
		return e.Actor.CommandLine
	}
	if e.Network != nil {
		if e.Network.Domain != "" {
			return e.Network.Domain
		}
		if e.Network.DestinationIP != "" {
			return e.Network.DestinationIP
		}
	}
	return ""
}

// WithActorPID sets actor pid/ppid.
func (e *Event) WithActorPID(pid, ppid uint32) *Event {
	e.Actor.PID = pid
	e.Actor.PPID = ppid
	return e
}

// WithCmdline sets actor command line (and executable if empty).
func (e *Event) WithCmdline(cmdline string) *Event {
	e.Actor.CommandLine = cmdline
	return e
}

// WithFileTarget sets a file path target.
func (e *Event) WithFileTarget(path string) *Event {
	e.Target.Type = "file"
	e.Target.Path = path
	return e
}

// WithValueTarget sets a generic value target (registry key, user name, …).
func (e *Event) WithValueTarget(typ, value string) *Event {
	e.Target.Type = typ
	e.Target.Value = value
	return e
}

// StampObserve ensures decision is observe/ALLOW (default product path).
func (e *Event) StampObserve() {
	e.Decision.Mode = ModeObserve
	e.Decision.Result = ResultAllow
	e.Decision.PolicyID = nil
}

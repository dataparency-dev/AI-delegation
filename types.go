// Package types defines the core data structures for the Intelligent AI Delegation framework.
// Maps directly to concepts from Tomašev et al. (2026): task characteristics, agent profiles,
// delegation contracts, reputation records, and monitoring events.
package types

import "time"

// ─── Agent Identity & Capabilities ───────────────────────────────────────────

// AgentRole defines whether an agent acts as delegator, delegatee, or both.
type AgentRole string

const (
	RoleDelegator AgentRole = "delegator"
	RoleDelegatee AgentRole = "delegatee"
	RoleBoth      AgentRole = "both"
	RoleOverseer  AgentRole = "overseer"
)

// AgentType distinguishes human participants from AI agents.
type AgentType string

const (
	AgentTypeAI    AgentType = "ai"
	AgentTypeHuman AgentType = "human"
)

// AgentProfile is the core identity registered as an Entity in the NATS-backed store.
// Corresponds to the paper's delegator/delegatee agent card concept and A2A agent cards.
type AgentProfile struct {
	AgentID      string            `json:"agent_id"`      // Unique identifier (maps to entity identity)
	Name         string            `json:"name"`          // Human-readable name
	Type         AgentType         `json:"type"`          // AI or Human
	Role         AgentRole         `json:"role"`          // Delegator, Delegatee, Both, Overseer
	Capabilities []string          `json:"capabilities"`  // Skills/domains this agent can handle
	MaxLoad      int               `json:"max_load"`      // Max concurrent tasks (span of control)
	CurrentLoad  int               `json:"current_load"`  // Current active tasks
	Status       AgentStatus       `json:"status"`        // Online, Busy, Offline
	TrustScore   float64           `json:"trust_score"`   // Aggregate reputation [0.0 - 1.0]
	CostPerUnit  float64           `json:"cost_per_unit"` // Cost rate
	Metadata     map[string]string `json:"metadata"`      // Extensible fields
	RegisteredAt time.Time         `json:"registered_at"`
	LastSeenAt   time.Time         `json:"last_seen_at"`
}

type AgentStatus string

const (
	StatusOnline  AgentStatus = "online"
	StatusBusy    AgentStatus = "busy"
	StatusOffline AgentStatus = "offline"
)

// ─── Task Characteristics (Section 2.2 of the paper) ─────────────────────────

// Criticality levels for tasks.
type Criticality string

const (
	CriticalityLow      Criticality = "low"
	CriticalityMedium   Criticality = "medium"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

// TaskStatus tracks lifecycle states.
type TaskStatus string

const (
	TaskPending      TaskStatus = "pending"
	TaskDecomposed   TaskStatus = "decomposed"
	TaskBidding      TaskStatus = "bidding"
	TaskAssigned     TaskStatus = "assigned"
	TaskInProgress   TaskStatus = "in_progress"
	TaskCheckpoint   TaskStatus = "checkpoint"
	TaskCompleted    TaskStatus = "completed"
	TaskFailed       TaskStatus = "failed"
	TaskCancelled    TaskStatus = "cancelled"
	TaskVerifying    TaskStatus = "verifying"
	TaskVerified     TaskStatus = "verified"
	TaskDisputed     TaskStatus = "disputed"
	TaskReAllocating TaskStatus = "re_allocating"
)

// TaskSpec defines a task or sub-task, incorporating all characteristics from Section 2.2.
type TaskSpec struct {
	TaskID       string      `json:"task_id"`
	ParentTaskID string      `json:"parent_task_id,omitempty"` // Empty if root task
	DelegatorID  string      `json:"delegator_id"`
	DelegateeID  string      `json:"delegatee_id,omitempty"`
	Title        string      `json:"title"`
	Description  string      `json:"description"`
	Status       TaskStatus  `json:"status"`
	Criticality  Criticality `json:"criticality"`

	// Task Characteristics (Section 2.2)
	Complexity         int     `json:"complexity"`          // 1-10 scale
	Uncertainty        float64 `json:"uncertainty"`         // 0.0-1.0
	EstimatedDuration  int64   `json:"estimated_duration"`  // Seconds
	MaxBudget          float64 `json:"max_budget"`          // Cost ceiling
	Reversible         bool    `json:"reversible"`          // Can effects be undone?
	Verifiability      float64 `json:"verifiability"`       // 0.0-1.0 how easily verified
	Subjectivity       float64 `json:"subjectivity"`        // 0.0-1.0 how subjective
	ContextSensitivity float64 `json:"context_sensitivity"` // Privacy surface area

	// Decomposition
	SubTaskIDs []string `json:"sub_task_ids,omitempty"`
	IsLeaf     bool     `json:"is_leaf"` // True if no further decomposition

	// Execution constraints
	RequiredCapabilities []string          `json:"required_capabilities"`
	AutonomyLevel        AutonomyLevel     `json:"autonomy_level"`
	MonitoringMode       MonitoringMode    `json:"monitoring_mode"`
	Permissions          []Permission      `json:"permissions"`
	VerificationPolicy   *VerificationPolicy `json:"verification_policy,omitempty"`

	// Timing
	CreatedAt   time.Time  `json:"created_at"`
	Deadline    *time.Time `json:"deadline,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type AutonomyLevel string

const (
	AutonomyAtomic   AutonomyLevel = "atomic"    // Strict spec, no sub-delegation
	AutonomyBounded  AutonomyLevel = "bounded"   // Can sub-delegate within constraints
	AutonomyOpenEnd  AutonomyLevel = "open_ended" // Full decomposition authority
)

type MonitoringMode string

const (
	MonitorContinuous    MonitoringMode = "continuous"
	MonitorPeriodic      MonitoringMode = "periodic"
	MonitorEventTriggered MonitoringMode = "event_triggered"
	MonitorOutcomeOnly   MonitoringMode = "outcome_only"
)

// ─── Contracts & Bidding (Section 4.2) ───────────────────────────────────────

// Bid represents a delegatee's offer to execute a task.
type Bid struct {
	BidID          string    `json:"bid_id"`
	TaskID         string    `json:"task_id"`
	AgentID        string    `json:"agent_id"`
	EstimatedCost  float64   `json:"estimated_cost"`
	EstimatedTime  int64     `json:"estimated_time"` // Seconds
	Confidence     float64   `json:"confidence"`     // 0.0-1.0
	ReputationBond float64   `json:"reputation_bond"`
	Capabilities   []string  `json:"capabilities"`
	SubmittedAt    time.Time `json:"submitted_at"`
}

// DelegationContract formalizes the agreement between delegator and delegatee.
type DelegationContract struct {
	ContractID     string             `json:"contract_id"`
	TaskID         string             `json:"task_id"`
	DelegatorID    string             `json:"delegator_id"`
	DelegateeID    string             `json:"delegatee_id"`
	AcceptedBid    *Bid               `json:"accepted_bid"`
	Terms          ContractTerms      `json:"terms"`
	Status         ContractStatus     `json:"status"`
	Permissions    []Permission       `json:"permissions"`
	BackupAgentID  string             `json:"backup_agent_id,omitempty"`
	CreatedAt      time.Time          `json:"created_at"`
	SignedAt       *time.Time         `json:"signed_at,omitempty"`
}

type ContractTerms struct {
	MaxCost           float64        `json:"max_cost"`
	Deadline          time.Time      `json:"deadline"`
	MonitoringMode    MonitoringMode `json:"monitoring_mode"`
	ReportingInterval int64          `json:"reporting_interval"` // Seconds between status reports
	EscrowAmount      float64        `json:"escrow_amount"`
	PenaltyRate       float64        `json:"penalty_rate"` // Per-unit penalty for SLA breach
	DisputePeriod     int64          `json:"dispute_period"` // Seconds after completion
	VerificationMode  string         `json:"verification_mode"` // "direct", "third_party", "consensus"
}

type ContractStatus string

const (
	ContractDraft     ContractStatus = "draft"
	ContractActive    ContractStatus = "active"
	ContractCompleted ContractStatus = "completed"
	ContractBreached  ContractStatus = "breached"
	ContractDisputed  ContractStatus = "disputed"
)

// ─── Permissions (Section 4.7) ───────────────────────────────────────────────

// Permission implements privilege attenuation — each sub-delegation narrows scope.
type Permission struct {
	Resource   string   `json:"resource"`   // What resource (API, dataset, tool)
	Operations []string `json:"operations"` // Allowed ops: read, write, execute
	Scope      string   `json:"scope"`      // Narrowing constraint
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	GrantedBy  string   `json:"granted_by"` // Agent who granted this
}

// ─── Verification (Section 4.8) ──────────────────────────────────────────────

type VerificationPolicy struct {
	Mode      string               `json:"mode"` // "strict", "standard", "optimistic"
	Artifacts []VerificationArtifact `json:"artifacts"`
}

type VerificationArtifact struct {
	Type              string `json:"type"` // "unit_test", "proof", "human_review", "consensus"
	ValidatorAgentID  string `json:"validator_agent_id,omitempty"`
	SignatureRequired bool   `json:"signature_required"`
}

type VerificationResult struct {
	TaskID     string    `json:"task_id"`
	VerifierID string    `json:"verifier_id"`
	Passed     bool      `json:"passed"`
	Score      float64   `json:"score"` // Quality score 0.0-1.0
	Details    string    `json:"details"`
	VerifiedAt time.Time `json:"verified_at"`
}

// ─── Monitoring Events (Section 4.5) ─────────────────────────────────────────

type MonitorEventType string

const (
	EventTaskStarted      MonitorEventType = "TASK_STARTED"
	EventCheckpoint       MonitorEventType = "CHECKPOINT_REACHED"
	EventResourceWarning  MonitorEventType = "RESOURCE_WARNING"
	EventProgressUpdate   MonitorEventType = "PROGRESS_UPDATE"
	EventTaskCompleted    MonitorEventType = "TASK_COMPLETED"
	EventTaskFailed       MonitorEventType = "TASK_FAILED"
	EventPerformanceDrop  MonitorEventType = "PERFORMANCE_DEGRADATION"
	EventBudgetOverrun    MonitorEventType = "BUDGET_OVERRUN"
	EventSecurityAlert    MonitorEventType = "SECURITY_ALERT"
	EventAgentUnresp      MonitorEventType = "AGENT_UNRESPONSIVE"
)

type MonitorEvent struct {
	EventID     string           `json:"event_id"`
	TaskID      string           `json:"task_id"`
	AgentID     string           `json:"agent_id"`
	EventType   MonitorEventType `json:"event_type"`
	Severity    Criticality      `json:"severity"`
	Progress    float64          `json:"progress"`     // 0.0-1.0
	ResourceUse float64          `json:"resource_use"` // Budget consumed so far
	Message     string           `json:"message"`
	Timestamp   time.Time        `json:"timestamp"`
}

// ─── Reputation (Section 4.6) ────────────────────────────────────────────────

type ReputationRecord struct {
	AgentID          string    `json:"agent_id"`
	TaskID           string    `json:"task_id"`
	Outcome          string    `json:"outcome"` // "success", "failure", "partial"
	QualityScore     float64   `json:"quality_score"`
	TimelinessScore  float64   `json:"timeliness_score"`
	CostAdherence    float64   `json:"cost_adherence"`
	SafetyCompliance float64   `json:"safety_compliance"`
	DelegatorID      string    `json:"delegator_id"` // Who issued this rating
	RecordedAt       time.Time `json:"recorded_at"`
}

// ─── Adaptive Coordination Triggers (Section 4.4) ────────────────────────────

type TriggerType string

const (
	TriggerExtTaskChange    TriggerType = "task_change"
	TriggerExtResourceShift TriggerType = "resource_change"
	TriggerExtPriorityShift TriggerType = "priority_change"
	TriggerExtSecurityAlert TriggerType = "security_alert"
	TriggerIntPerfDrop      TriggerType = "performance_degradation"
	TriggerIntBudgetOverrun TriggerType = "budget_overrun"
	TriggerIntVerifyFail    TriggerType = "verification_failure"
	TriggerIntUnresponsive  TriggerType = "agent_unresponsive"
)

type AdaptiveTrigger struct {
	TriggerID   string      `json:"trigger_id"`
	TaskID      string      `json:"task_id"`
	Type        TriggerType `json:"type"`
	AgentID     string      `json:"agent_id"`
	Description string      `json:"description"`
	Urgent      bool        `json:"urgent"`
	Timestamp   time.Time   `json:"timestamp"`
}

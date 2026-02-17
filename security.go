// Package security implements the security layer of the Intelligent Delegation framework.
// Covers threat detection, permission attenuation (Delegation Capability Tokens),
// and circuit breakers for reputation anomalies (Sections 4.7, 4.9).
package security

import (
	"fmt"
	"strings"
	"time"

	t "github.com/yourorg/delegation/types"
)

// ─── Delegation Capability Token (DCT) ───────────────────────────────────────
// Implements attenuated authorization as described in Section 6.1 of the paper.
// Each sub-delegation narrows the permission scope via chained caveats.

// DCT represents a Delegation Capability Token with restriction caveats.
type DCT struct {
	TokenID     string       `json:"token_id"`
	GranterID   string       `json:"granter_id"`
	BearerID    string       `json:"bearer_id"`
	Resource    string       `json:"resource"`
	Caveats     []Caveat     `json:"caveats"`     // Restriction chain
	IssuedAt    time.Time    `json:"issued_at"`
	ExpiresAt   time.Time    `json:"expires_at"`
	Revoked     bool         `json:"revoked"`
}

// Caveat is a single restriction in the attenuation chain.
type Caveat struct {
	Type  string `json:"type"`  // "scope", "operation", "time", "budget"
	Key   string `json:"key"`
	Value string `json:"value"`
}

// MintDCT creates a new Delegation Capability Token with initial caveats.
func MintDCT(granterID, bearerID, resource string, ttl time.Duration, caveats ...Caveat) *DCT {
	now := time.Now()
	return &DCT{
		TokenID:   fmt.Sprintf("dct_%s_%s_%d", granterID, bearerID, now.UnixNano()),
		GranterID: granterID,
		BearerID:  bearerID,
		Resource:  resource,
		Caveats:   caveats,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
}

// Attenuate creates a child DCT with additional restrictions.
// This is the key mechanism for privilege attenuation in delegation chains:
// A→B→C: B attenuates the token before passing to C.
func (d *DCT) Attenuate(newBearerID string, additionalCaveats ...Caveat) (*DCT, error) {
	if d.Revoked {
		return nil, fmt.Errorf("cannot attenuate revoked token %s", d.TokenID)
	}
	if time.Now().After(d.ExpiresAt) {
		return nil, fmt.Errorf("cannot attenuate expired token %s", d.TokenID)
	}

	// Child inherits all parent caveats plus new ones (monotonic restriction)
	allCaveats := make([]Caveat, len(d.Caveats)+len(additionalCaveats))
	copy(allCaveats, d.Caveats)
	copy(allCaveats[len(d.Caveats):], additionalCaveats)

	child := MintDCT(d.BearerID, newBearerID, d.Resource, time.Until(d.ExpiresAt), allCaveats...)
	return child, nil
}

// ValidateAccess checks whether a DCT permits a given operation.
func (d *DCT) ValidateAccess(operation, scope string) error {
	if d.Revoked {
		return fmt.Errorf("token revoked")
	}
	if time.Now().After(d.ExpiresAt) {
		return fmt.Errorf("token expired")
	}

	for _, c := range d.Caveats {
		switch c.Type {
		case "operation":
			if !strings.Contains(c.Value, operation) {
				return fmt.Errorf("operation %q not permitted (allowed: %s)", operation, c.Value)
			}
		case "scope":
			if !strings.HasPrefix(scope, c.Value) {
				return fmt.Errorf("scope %q outside permitted boundary %q", scope, c.Value)
			}
		}
	}
	return nil
}

// ─── Threat Detection ────────────────────────────────────────────────────────

// ThreatType categorizes security threats from Section 4.9.
type ThreatType string

const (
	ThreatDataExfiltration  ThreatType = "data_exfiltration"
	ThreatDataPoisoning     ThreatType = "data_poisoning"
	ThreatPromptInjection   ThreatType = "prompt_injection"
	ThreatResourceExhaust   ThreatType = "resource_exhaustion"
	ThreatUnauthorizedAccess ThreatType = "unauthorized_access"
	ThreatBackdoor          ThreatType = "backdoor_implant"
	ThreatSybilAttack       ThreatType = "sybil_attack"
	ThreatCollusion         ThreatType = "collusion"
	ThreatReputationSabotage ThreatType = "reputation_sabotage"
)

// SecurityAlert represents a detected or suspected threat.
type SecurityAlert struct {
	AlertID     string     `json:"alert_id"`
	TaskID      string     `json:"task_id"`
	AgentID     string     `json:"agent_id"`
	ThreatType  ThreatType `json:"threat_type"`
	Severity    t.Criticality `json:"severity"`
	Description string     `json:"description"`
	Evidence    string     `json:"evidence"`
	Timestamp   time.Time  `json:"timestamp"`
}

// ─── Circuit Breaker ─────────────────────────────────────────────────────────
// Implements algorithmic circuit breakers from Section 4.7:
// "if an agent's reputation score drops suddenly... active tokens should be
// immediately invalidated across the delegation chain."

// CircuitBreaker monitors agent health and trips when thresholds are crossed.
type CircuitBreaker struct {
	AgentID          string
	FailureCount     int
	FailureThreshold int
	TrustFloor       float64 // Minimum trust score before tripping
	CooldownPeriod   time.Duration
	State            CBState
	LastTripped      time.Time
}

type CBState string

const (
	CBClosed   CBState = "closed"   // Normal operation
	CBOpen     CBState = "open"     // Tripped — agent blocked
	CBHalfOpen CBState = "half_open" // Testing if agent recovered
)

func NewCircuitBreaker(agentID string, failureThreshold int, trustFloor float64) *CircuitBreaker {
	return &CircuitBreaker{
		AgentID:          agentID,
		FailureThreshold: failureThreshold,
		TrustFloor:       trustFloor,
		CooldownPeriod:   30 * time.Minute,
		State:            CBClosed,
	}
}

// RecordFailure increments the failure counter and may trip the breaker.
func (cb *CircuitBreaker) RecordFailure() bool {
	cb.FailureCount++
	if cb.FailureCount >= cb.FailureThreshold {
		cb.State = CBOpen
		cb.LastTripped = time.Now()
		return true // Tripped
	}
	return false
}

// RecordSuccess resets the failure counter.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.FailureCount = 0
	cb.State = CBClosed
}

// CheckTrustDrop trips the breaker if trust drops below the floor.
func (cb *CircuitBreaker) CheckTrustDrop(currentTrust float64) bool {
	if currentTrust < cb.TrustFloor {
		cb.State = CBOpen
		cb.LastTripped = time.Now()
		return true
	}
	return false
}

// IsAllowed checks if the agent is currently allowed to accept tasks.
func (cb *CircuitBreaker) IsAllowed() bool {
	switch cb.State {
	case CBClosed:
		return true
	case CBOpen:
		if time.Since(cb.LastTripped) > cb.CooldownPeriod {
			cb.State = CBHalfOpen
			return true // Allow one probe
		}
		return false
	case CBHalfOpen:
		return true // Probing
	}
	return false
}

// ─── Task Screening ──────────────────────────────────────────────────────────
// Basic screening for malicious delegator patterns (Section 4.9 — Malicious Delegator).

// ScreenTask checks a task specification for red flags.
func ScreenTask(task t.TaskSpec) []string {
	var warnings []string

	// Flag tasks requesting excessive permissions
	if len(task.Permissions) > 10 {
		warnings = append(warnings, "excessive permissions requested")
	}

	// Flag irreversible tasks with open-ended autonomy
	if !task.Reversible && task.AutonomyLevel == t.AutonomyOpenEnd {
		warnings = append(warnings, "irreversible task with open-ended autonomy — high risk")
	}

	// Flag high-context tasks with low verifiability
	if task.ContextSensitivity > 0.8 && task.Verifiability < 0.3 {
		warnings = append(warnings, "high context sensitivity with low verifiability — potential exfiltration vector")
	}

	// Flag tasks with unrealistically short deadlines for their complexity
	if task.Deadline != nil && task.Complexity > 7 {
		remaining := time.Until(*task.Deadline)
		if remaining < time.Duration(task.Complexity)*5*time.Minute {
			warnings = append(warnings, "deadline too tight for complexity — potential pressure tactic")
		}
	}

	return warnings
}

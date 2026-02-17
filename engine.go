// Package delegation implements the Intelligent AI Delegation framework core.
// It uses natsclient as the storage/messaging backbone, mapping:
//   - Agent profiles     → EntityRegister/EntityRetrieve/EntityUpdate
//   - Task state         → Post/Get on domain "Delegation" with entity=taskID
//   - Contracts          → Post/Get on domain "Contract"
//   - Secure messaging   → SecureChannel* for agent-to-agent communication
//   - Access control     → RelationRegister/RelationRetrieve for RDID-based permissions
package delegation

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	nc "github.com/dataparency-dev/natsclient" // The uploaded natsclient package
	t "github.com/dataparency-dev/AI-delegation/types"
)

const (
	DomainAgents     = "Agents"
	DomainTasks      = "Tasks"
	DomainContracts  = "Contracts"
	DomainBids       = "Bids"
	DomainMonitoring = "Monitoring"
	DomainReputation = "Reputation"
	DomainTriggers   = "Triggers"
)

// Engine is the central delegation orchestrator. It holds a reference to the
// NATS server topic and the authenticated session token, and provides methods
// implementing each pillar of the framework.
type Engine struct {
	Server string       // NATS server topic for the D-DDN backend
	Token  nc.APIToken  // Authenticated session token
	SelfID string       // This engine's agent identity
}

// NewEngine connects to the NATS backend, authenticates, and returns a
// ready-to-use delegation engine.
func NewEngine(natsURL, serverTopic, user, password, selfID string) (*Engine, error) {
	conn := nc.ConnectAPI(natsURL, serverTopic)
	if conn == nil {
		return nil, fmt.Errorf("failed to connect to NATS at %s", natsURL)
	}

	token := nc.LoginAPI(serverTopic, user, password)
	if token.Token == "" {
		return nil, fmt.Errorf("authentication failed for user %s", user)
	}

	log.Printf("Delegation engine authenticated as %s", user)

	return &Engine{
		Server: serverTopic,
		Token:  token,
		SelfID: selfID,
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// AGENT REGISTRATION & MANAGEMENT
// Maps to: EntityRegister, EntityRetrieve, EntityUpdate, EntityRemove
// Paper ref: Section 4.2 (Task Assignment — agent capability matching)
// ═══════════════════════════════════════════════════════════════════════════════

// RegisterAgent creates a new agent entity in the system.
// Uses EntityRegister to create the identity, then stores the full profile
// as structured data under the "Agents" domain.
func (e *Engine) RegisterAgent(profile t.AgentProfile) error {
	profile.RegisteredAt = time.Now()
	profile.LastSeenAt = time.Now()
	if profile.TrustScore == 0 {
		profile.TrustScore = 0.5 // Default neutral trust
	}

	// 1. Register the entity identity for access control
	body, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshal agent profile: %w", err)
	}

	passCd, status := nc.EntityRegister(
		e.Server,
		profile.AgentID,
		e.Token,
		string(profile.Role),   // roles
		"",                      // groups
		e.Server,                // queue
		[]byte(""),              // genesis
		body,                    // body
	)
	if status != http.StatusOK {
		return fmt.Errorf("entity register failed: %s (status %d)", passCd, status)
	}

	// 2. Register an RDID for this agent (access control relation)
	_, status = nc.RelationRegister(e.Server, profile.AgentID, e.Token, "write")
	if status != http.StatusOK {
		return fmt.Errorf("relation register failed for agent %s (status %d)", profile.AgentID, status)
	}

	// 3. Store the full profile as structured data
	if err := e.storeData(DomainAgents, profile.AgentID, "profile", body); err != nil {
		return fmt.Errorf("store agent profile: %w", err)
	}

	log.Printf("Agent registered: %s (%s, %s)", profile.AgentID, profile.Type, profile.Role)
	return nil
}

// GetAgent retrieves an agent profile by ID.
func (e *Engine) GetAgent(agentID string) (*t.AgentProfile, error) {
	data, err := e.retrieveData(DomainAgents, agentID, "profile")
	if err != nil {
		return nil, err
	}
	var profile t.AgentProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("unmarshal agent profile: %w", err)
	}
	return &profile, nil
}

// UpdateAgent modifies an existing agent profile.
func (e *Engine) UpdateAgent(profile t.AgentProfile) error {
	profile.LastSeenAt = time.Now()
	body, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshal agent profile: %w", err)
	}

	_, status := nc.EntityUpdate(e.Server, profile.AgentID, e.Token, body)
	if status != http.StatusOK {
		return fmt.Errorf("entity update failed for %s (status %d)", profile.AgentID, status)
	}

	return e.storeData(DomainAgents, profile.AgentID, "profile", body)
}

// RemoveAgent deregisters an agent.
func (e *Engine) RemoveAgent(agentID string) error {
	_, status := nc.EntityRemove(e.Server, agentID, e.Token)
	if status != http.StatusOK {
		return fmt.Errorf("entity remove failed for %s (status %d)", agentID, status)
	}
	nc.RelationRemove(e.Server, agentID, e.Token)
	return nil
}

// FindAgentsByCapability searches for agents matching required capabilities.
// This is core to Task Assignment (Section 4.2) — capability matching.
func (e *Engine) FindAgentsByCapability(required []string) ([]t.AgentProfile, error) {
	// Query agents domain for matching capabilities
	dflags := make(map[string]interface{})
	nc.SetDomain(dflags, DomainAgents)
	nc.SetEntity(dflags, "index")
	nc.SetAspect(dflags, "capabilities")
	nc.SetTag(dflags, "data")

	query, _ := json.Marshal(map[string]interface{}{
		"capabilities": required,
		"status":       t.StatusOnline,
	})
	nc.SetMatch(dflags, string(query))

	rsp := nc.Get(e.Server, dflags, e.Token)
	if rsp.Header.Status != http.StatusOK {
		return nil, fmt.Errorf("capability search failed: %s", rsp.Header.ErrorStr)
	}

	var agents []t.AgentProfile
	if err := json.Unmarshal(rsp.Response, &agents); err != nil {
		return nil, err
	}
	return agents, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// TASK DECOMPOSITION (Section 4.1)
// Stores task tree in "Tasks" domain, each task as its own entity.
// ═══════════════════════════════════════════════════════════════════════════════

// CreateTask stores a new task specification.
func (e *Engine) CreateTask(task t.TaskSpec) error {
	task.CreatedAt = time.Now()
	task.Status = t.TaskPending

	body, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("marshal task: %w", err)
	}

	// Register task as an entity for access control
	_, status := nc.EntityRegister(e.Server, task.TaskID, e.Token,
		"task", "", e.Server, []byte(""), body)
	if status != http.StatusOK {
		return fmt.Errorf("task entity register failed (status %d)", status)
	}

	// Register RDID for task access
	nc.RelationRegister(e.Server, task.TaskID, e.Token, "write")

	// Store task data
	return e.storeData(DomainTasks, task.TaskID, "spec", body)
}

// DecomposeTask breaks a parent task into sub-tasks.
// Implements "contract-first decomposition" — sub-tasks must have verifiable outputs.
// Returns the updated parent with sub-task IDs populated.
func (e *Engine) DecomposeTask(parentID string, subTasks []t.TaskSpec) (*t.TaskSpec, error) {
	parent, err := e.GetTask(parentID)
	if err != nil {
		return nil, fmt.Errorf("get parent task: %w", err)
	}

	subIDs := make([]string, 0, len(subTasks))
	for i := range subTasks {
		sub := &subTasks[i]
		sub.ParentTaskID = parentID
		sub.DelegatorID = parent.DelegatorID

		// Contract-first: verify that the sub-task has adequate verifiability
		if sub.Verifiability < 0.3 && !sub.IsLeaf {
			return nil, fmt.Errorf(
				"sub-task %s has low verifiability (%.2f); decompose further or add verification artifacts",
				sub.TaskID, sub.Verifiability,
			)
		}

		if err := e.CreateTask(*sub); err != nil {
			return nil, fmt.Errorf("create sub-task %s: %w", sub.TaskID, err)
		}
		subIDs = append(subIDs, sub.TaskID)
	}

	parent.SubTaskIDs = subIDs
	parent.Status = t.TaskDecomposed
	parent.IsLeaf = false

	if err := e.UpdateTask(*parent); err != nil {
		return nil, fmt.Errorf("update parent task: %w", err)
	}

	log.Printf("Task %s decomposed into %d sub-tasks", parentID, len(subTasks))
	return parent, nil
}

// GetTask retrieves a task by ID.
func (e *Engine) GetTask(taskID string) (*t.TaskSpec, error) {
	data, err := e.retrieveData(DomainTasks, taskID, "spec")
	if err != nil {
		return nil, err
	}
	var task t.TaskSpec
	if err := json.Unmarshal(data, &task); err != nil {
		return nil, fmt.Errorf("unmarshal task: %w", err)
	}
	return &task, nil
}

// UpdateTask persists task state changes.
func (e *Engine) UpdateTask(task t.TaskSpec) error {
	body, err := json.Marshal(task)
	if err != nil {
		return err
	}
	return e.storeData(DomainTasks, task.TaskID, "spec", body)
}

// ═══════════════════════════════════════════════════════════════════════════════
// TASK ASSIGNMENT & BIDDING (Section 4.2)
// Uses secure channels for bid submission and contract negotiation.
// ═══════════════════════════════════════════════════════════════════════════════

// PublishTaskForBidding opens a task to the market via a secure channel.
// Delegatee agents subscribe to the bidding channel and submit bids.
func (e *Engine) PublishTaskForBidding(task t.TaskSpec) (string, error) {
	// Create a secure channel for this task's bidding process
	channelName := fmt.Sprintf("bid_%s", task.TaskID)
	rdid, err := nc.InitChannel(e.Server, channelName, e.Token, true)
	if err != nil {
		return "", fmt.Errorf("init bidding channel: %w", err)
	}

	task.Status = t.TaskBidding
	if err := e.UpdateTask(task); err != nil {
		return "", err
	}

	// Publish task spec to the bidding channel
	taskBytes, _ := json.Marshal(task)
	err = nc.SecureChannelPublish(
		taskBytes, e.Server, channelName, e.Token, rdid, 3600, // 1hr expiry
	)
	if err != nil {
		return "", fmt.Errorf("publish to bidding channel: %w", err)
	}

	log.Printf("Task %s published for bidding on channel %s", task.TaskID, channelName)
	return channelName, nil
}

// SubmitBid allows a delegatee agent to bid on a task.
func (e *Engine) SubmitBid(bid t.Bid) error {
	bid.SubmittedAt = time.Now()
	body, err := json.Marshal(bid)
	if err != nil {
		return err
	}

	// Store bid under the Bids domain keyed by task
	return e.storeData(DomainBids, bid.TaskID, bid.BidID, body)
}

// AcceptBid selects a bid and creates a delegation contract.
func (e *Engine) AcceptBid(bid t.Bid, terms t.ContractTerms) (*t.DelegationContract, error) {
	now := time.Now()
	contract := &t.DelegationContract{
		ContractID:  fmt.Sprintf("contract_%s_%s", bid.TaskID, bid.AgentID),
		TaskID:      bid.TaskID,
		DelegatorID: e.SelfID,
		DelegateeID: bid.AgentID,
		AcceptedBid: &bid,
		Terms:       terms,
		Status:      t.ContractActive,
		CreatedAt:   now,
		SignedAt:     &now,
	}

	body, err := json.Marshal(contract)
	if err != nil {
		return nil, err
	}

	// Store contract
	if err := e.storeData(DomainContracts, contract.ContractID, "terms", body); err != nil {
		return nil, err
	}

	// Update task with assigned delegatee
	task, err := e.GetTask(bid.TaskID)
	if err != nil {
		return nil, err
	}
	task.DelegateeID = bid.AgentID
	task.Status = t.TaskAssigned
	task.StartedAt = &now
	if err := e.UpdateTask(*task); err != nil {
		return nil, err
	}

	// Grant permissions to delegatee via RDID
	nc.RelationRegister(e.Server, bid.TaskID, e.Token, "write")

	log.Printf("Contract %s created: %s → %s for task %s",
		contract.ContractID, e.SelfID, bid.AgentID, bid.TaskID)
	return contract, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// MONITORING (Section 4.5)
// Uses secure channels for real-time event streaming.
// Events stored in "Monitoring" domain for audit trail.
// ═══════════════════════════════════════════════════════════════════════════════

// SetupMonitoringChannel creates a dedicated secure channel for task monitoring events.
func (e *Engine) SetupMonitoringChannel(taskID string) (channelName, rdid string, err error) {
	channelName = fmt.Sprintf("monitor_%s", taskID)
	rdid, err = nc.InitChannel(e.Server, channelName, e.Token, true)
	if err != nil {
		return "", "", fmt.Errorf("init monitoring channel: %w", err)
	}
	return channelName, rdid, nil
}

// EmitMonitorEvent publishes a monitoring event for a task.
func (e *Engine) EmitMonitorEvent(event t.MonitorEvent) error {
	event.Timestamp = time.Now()
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// Persist event to audit log
	eventKey := fmt.Sprintf("%s_%s", event.EventID, event.Timestamp.Format(time.RFC3339Nano))
	if err := e.storeData(DomainMonitoring, event.TaskID, eventKey, body); err != nil {
		return err
	}

	// Publish to monitoring channel
	channelName := fmt.Sprintf("monitor_%s", event.TaskID)
	rdid, _ := nc.RelationRetrieve(e.Server, channelName, e.Token)
	if rdid != "" {
		nc.SecureChannelPublish(body, e.Server, channelName, e.Token, rdid, 86400)
	}

	return nil
}

// SubscribeToMonitoring listens for monitoring events on a task.
func (e *Engine) SubscribeToMonitoring(taskID string, handler func(t.MonitorEvent)) error {
	channelName := fmt.Sprintf("monitor_%s", taskID)
	rdid, _ := nc.RelationRetrieve(e.Server, channelName, e.Token)
	if rdid == "" {
		return fmt.Errorf("no monitoring channel for task %s", taskID)
	}

	_, err := nc.SecureChannelQueueSubscribe(
		e.Server, channelName, "monitors", e.Token, rdid,
		func(msg interface{}) {
			// Note: actual type is *nats.Msg but simplified for framework illustration
			// In production, unmarshal msg.Data into MonitorEvent
			var event t.MonitorEvent
			// json.Unmarshal(msg.Data, &event)
			handler(event)
		},
	)
	return err
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADAPTIVE COORDINATION (Section 4.4)
// Trigger detection → root cause → response selection → execution
// ═══════════════════════════════════════════════════════════════════════════════

// RaiseTrigger records an adaptive coordination trigger and initiates response.
func (e *Engine) RaiseTrigger(trigger t.AdaptiveTrigger) error {
	trigger.Timestamp = time.Now()
	body, _ := json.Marshal(trigger)

	// Persist trigger
	if err := e.storeData(DomainTriggers, trigger.TaskID, trigger.TriggerID, body); err != nil {
		return err
	}

	log.Printf("TRIGGER [%s] on task %s: %s (urgent=%v)",
		trigger.Type, trigger.TaskID, trigger.Description, trigger.Urgent)

	// Evaluate response based on task characteristics
	task, err := e.GetTask(trigger.TaskID)
	if err != nil {
		return err
	}

	return e.evaluateAndRespond(task, trigger)
}

// evaluateAndRespond implements the adaptive response cycle from Figure 2.
func (e *Engine) evaluateAndRespond(task *t.TaskSpec, trigger t.AdaptiveTrigger) error {
	// Step A: Check reversibility
	if !task.Reversible && trigger.Urgent {
		// Irreversible + urgent → immediate termination or human escalation
		log.Printf("ESCALATION: Irreversible task %s with urgent trigger — halting", task.TaskID)
		task.Status = t.TaskCancelled
		return e.UpdateTask(*task)
	}

	// Step B: Check urgency
	if trigger.Urgent {
		// Fast-path: re-delegate immediately
		return e.reDelegate(task)
	}

	// Step C: Determine scope — can we just adjust parameters?
	switch trigger.Type {
	case t.TriggerIntBudgetOverrun:
		// Try to extend budget before re-delegating
		log.Printf("Budget overrun on task %s — evaluating extension", task.TaskID)
		task.MaxBudget *= 1.2 // 20% extension
		return e.UpdateTask(*task)

	case t.TriggerIntPerfDrop, t.TriggerIntUnresponsive:
		// Re-delegate the task
		return e.reDelegate(task)

	case t.TriggerIntVerifyFail:
		// Request re-execution
		task.Status = t.TaskReAllocating
		return e.UpdateTask(*task)

	default:
		log.Printf("Non-urgent trigger %s on task %s — monitoring", trigger.Type, task.TaskID)
		return nil
	}
}

// reDelegate cancels current assignment and re-publishes for bidding.
func (e *Engine) reDelegate(task *t.TaskSpec) error {
	log.Printf("RE-DELEGATING task %s (was assigned to %s)", task.TaskID, task.DelegateeID)

	// Record reputation hit for failed delegatee
	if task.DelegateeID != "" {
		e.RecordReputation(t.ReputationRecord{
			AgentID:         task.DelegateeID,
			TaskID:          task.TaskID,
			Outcome:         "failure",
			QualityScore:    0.0,
			TimelinessScore: 0.0,
			DelegatorID:     e.SelfID,
		})
	}

	task.DelegateeID = ""
	task.Status = t.TaskReAllocating
	if err := e.UpdateTask(*task); err != nil {
		return err
	}

	// Re-publish for bidding
	_, err := e.PublishTaskForBidding(*task)
	return err
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPUTATION (Section 4.6)
// Immutable ledger via Post to "Reputation" domain.
// ═══════════════════════════════════════════════════════════════════════════════

// RecordReputation appends a reputation record for an agent.
func (e *Engine) RecordReputation(record t.ReputationRecord) error {
	record.RecordedAt = time.Now()
	body, _ := json.Marshal(record)

	key := fmt.Sprintf("%s_%s", record.TaskID, record.RecordedAt.Format(time.RFC3339Nano))
	return e.storeData(DomainReputation, record.AgentID, key, body)
}

// GetReputationHistory retrieves all reputation records for an agent.
func (e *Engine) GetReputationHistory(agentID string) ([]t.ReputationRecord, error) {
	data, err := e.retrieveData(DomainReputation, agentID, "history")
	if err != nil {
		return nil, err
	}
	var records []t.ReputationRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return records, nil
}

// ComputeTrustScore calculates an aggregate trust score from reputation history.
// Implements weighted scoring: recent tasks weighted higher (exponential decay).
func (e *Engine) ComputeTrustScore(agentID string) (float64, error) {
	records, err := e.GetReputationHistory(agentID)
	if err != nil || len(records) == 0 {
		return 0.5, err // Default neutral
	}

	var weightedSum, totalWeight float64
	now := time.Now()
	for _, rec := range records {
		age := now.Sub(rec.RecordedAt).Hours() / 24.0 // Days old
		weight := 1.0 / (1.0 + age/30.0)              // 30-day half-life

		score := (rec.QualityScore + rec.TimelinessScore + rec.CostAdherence + rec.SafetyCompliance) / 4.0
		weightedSum += score * weight
		totalWeight += weight
	}

	if totalWeight == 0 {
		return 0.5, nil
	}
	return weightedSum / totalWeight, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// VERIFICATION (Section 4.8)
// ═══════════════════════════════════════════════════════════════════════════════

// SubmitForVerification marks a task as ready for verification and stores the result artifact.
func (e *Engine) SubmitForVerification(taskID string, artifact []byte) error {
	task, err := e.GetTask(taskID)
	if err != nil {
		return err
	}

	task.Status = t.TaskVerifying
	if err := e.UpdateTask(*task); err != nil {
		return err
	}

	// Store the result artifact
	return e.storeData(DomainTasks, taskID, "result_artifact", artifact)
}

// RecordVerification records verification outcome and updates task + reputation.
func (e *Engine) RecordVerification(result t.VerificationResult) error {
	body, _ := json.Marshal(result)
	if err := e.storeData(DomainTasks, result.TaskID, "verification", body); err != nil {
		return err
	}

	task, err := e.GetTask(result.TaskID)
	if err != nil {
		return err
	}

	if result.Passed {
		now := time.Now()
		task.Status = t.TaskVerified
		task.CompletedAt = &now

		// Record positive reputation
		e.RecordReputation(t.ReputationRecord{
			AgentID:         task.DelegateeID,
			TaskID:          task.TaskID,
			Outcome:         "success",
			QualityScore:    result.Score,
			TimelinessScore: 1.0, // Could compute from deadline adherence
			CostAdherence:   1.0,
			SafetyCompliance: 1.0,
			DelegatorID:     e.SelfID,
		})
	} else {
		task.Status = t.TaskFailed
		// Trigger re-delegation
		e.RaiseTrigger(t.AdaptiveTrigger{
			TriggerID:   fmt.Sprintf("verfail_%s", result.TaskID),
			TaskID:      result.TaskID,
			Type:        t.TriggerIntVerifyFail,
			AgentID:     task.DelegateeID,
			Description: result.Details,
			Urgent:      task.Criticality == t.CriticalityCritical,
		})
	}

	return e.UpdateTask(*task)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PERMISSION HANDLING (Section 4.7)
// Uses RelationRegister for RDID-based access and entity flags for scoping.
// ═══════════════════════════════════════════════════════════════════════════════

// GrantPermission creates an attenuated permission for a delegatee on a resource.
func (e *Engine) GrantPermission(delegateeID, resource string, perm t.Permission) error {
	// Register a relation for the delegatee on the resource entity
	_, status := nc.RelationRegister(e.Server, resource, e.Token, perm.Operations[0])
	if status != http.StatusOK {
		return fmt.Errorf("permission grant failed (status %d)", status)
	}

	// Store the permission record
	body, _ := json.Marshal(perm)
	key := fmt.Sprintf("perm_%s_%s", delegateeID, resource)
	return e.storeData(DomainAgents, delegateeID, key, body)
}

// RevokePermission removes a delegatee's access to a resource.
func (e *Engine) RevokePermission(delegateeID, resource string) error {
	_, status := nc.RelationRemove(e.Server, resource, e.Token)
	if status != http.StatusOK {
		return fmt.Errorf("permission revoke failed (status %d)", status)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURE CHANNEL SETUP FOR AGENT-TO-AGENT COMMUNICATION
// ═══════════════════════════════════════════════════════════════════════════════

// SetupAgentChannel creates a secure channel between two agents for a task.
func (e *Engine) SetupAgentChannel(taskID, delegateeID string) (string, error) {
	channelName := fmt.Sprintf("task_%s_%s_%s", taskID, e.SelfID, delegateeID)
	rdid, err := nc.InitChannel(e.Server, channelName, e.Token, true)
	if err != nil {
		return "", err
	}
	_ = rdid
	return channelName, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS — natsclient data store/retrieve wrappers
// ═══════════════════════════════════════════════════════════════════════════════

// storeData wraps natsclient.Post to store JSON data under domain/entity/aspect.
func (e *Engine) storeData(domain, entity, aspect string, data []byte) error {
	// Look up RDID for this entity
	rdid, status := nc.RelationRetrieve(e.Server, entity, e.Token)
	if status != http.StatusOK {
		// Auto-register relation if not found
		rdid, status = nc.RelationRegister(e.Server, entity, e.Token, "write")
		if status != http.StatusOK {
			return fmt.Errorf("cannot establish RDID for %s/%s (status %d)", domain, entity, status)
		}
	}

	dflags := make(map[string]interface{})
	nc.SetDomain(dflags, domain)
	nc.SetEntity(dflags, entity)
	nc.SetRDID(dflags, rdid)
	nc.SetAspect(dflags, aspect)

	rsp := nc.Post(e.Server, data, dflags, e.Token)
	if rsp.Header.Status != http.StatusOK {
		return fmt.Errorf("store %s/%s/%s failed: %s (status %d)",
			domain, entity, aspect, rsp.Header.ErrorStr, rsp.Header.Status)
	}
	return nil
}

// retrieveData wraps natsclient.Get to read data from domain/entity/aspect.
func (e *Engine) retrieveData(domain, entity, aspect string) ([]byte, error) {
	rdid, status := nc.RelationRetrieve(e.Server, entity, e.Token)
	if status != http.StatusOK {
		return nil, fmt.Errorf("no RDID for %s/%s (status %d)", domain, entity, status)
	}

	dflags := make(map[string]interface{})
	nc.SetDomain(dflags, domain)
	nc.SetEntity(dflags, entity)
	nc.SetRDID(dflags, rdid)
	nc.SetAspect(dflags, aspect)
	nc.SetTag(dflags, "data")
	nc.SetTimestamp(dflags, "latest")

	rsp := nc.Get(e.Server, dflags, e.Token)
	if rsp.Header.Status != http.StatusOK {
		return nil, fmt.Errorf("retrieve %s/%s/%s failed: %s (status %d)",
			domain, entity, aspect, rsp.Header.ErrorStr, rsp.Header.Status)
	}
	return rsp.Response, nil
}

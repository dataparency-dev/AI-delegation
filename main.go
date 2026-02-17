// Example: Full Intelligent Delegation Lifecycle
//
// Demonstrates the end-to-end flow from the paper:
//   1. Connect & authenticate via natsclient
//   2. Register agents (delegator + delegatees)
//   3. Create and decompose a task
//   4. Publish for bidding, score bids, accept winner
//   5. Setup monitoring, emit events
//   6. Verification and reputation update
//   7. Adaptive coordination on failure
//   8. Permission attenuation in delegation chains
//
// This maps natsclient functions to framework concepts:
//   ConnectAPI/LoginAPI         → Engine initialization
//   EntityRegister/Retrieve     → Agent & task identity management
//   RelationRegister/Retrieve   → RDID-based access control & permissions
//   Post/Get                    → Structured data store/retrieve (profiles, tasks, bids, reputation)
//   InitChannel/SecureChannel*  → Agent-to-agent secure messaging (bidding, monitoring)
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/dataparency-dev/AI-delegation/delegation"
	"github.com/dataparency-dev/AI-delegation/market"
	"github.com/dataparency-dev/AI-delegation/security"
	t "github.com/dataparency-dev/AI-delegation/types"
)

func main() {
	// ═══════════════════════════════════════════════════════════════
	// STEP 1: Initialize the Delegation Engine
	// Uses: ConnectAPI, LoginAPI, session key management
	// ═══════════════════════════════════════════════════════════════

	engine, err := delegation.NewEngine(
		"nats://localhost:4222", // NATS URL
		"delegation-server",     // Server topic
		"orchestrator",          // Username
		"secret",                // Password
		"agent-orchestrator-01", // Self identity
	)
	if err != nil {
		log.Fatalf("Failed to initialize engine: %v", err)
	}

	// ═══════════════════════════════════════════════════════════════
	// STEP 2: Register Agents
	// Uses: EntityRegister → creates entity identity
	//       RelationRegister → creates RDID for access control
	//       Post → stores profile data under Agents domain
	// ═══════════════════════════════════════════════════════════════

	// Register the orchestrator (delegator)
	orchestrator := t.AgentProfile{
		AgentID:      "agent-orchestrator-01",
		Name:         "Task Orchestrator",
		Type:         t.AgentTypeAI,
		Role:         t.RoleDelegator,
		Capabilities: []string{"planning", "decomposition", "coordination"},
		MaxLoad:      50,
		Status:       t.StatusOnline,
	}
	if err := engine.RegisterAgent(orchestrator); err != nil {
		log.Printf("Register orchestrator: %v", err)
	}

	// Register specialist delegatee agents
	coder := t.AgentProfile{
		AgentID:      "agent-coder-01",
		Name:         "Code Specialist",
		Type:         t.AgentTypeAI,
		Role:         t.RoleDelegatee,
		Capabilities: []string{"go", "python", "code_review", "testing"},
		MaxLoad:      10,
		CostPerUnit:  0.05,
		TrustScore:   0.85,
		Status:       t.StatusOnline,
	}

	analyst := t.AgentProfile{
		AgentID:      "agent-analyst-01",
		Name:         "Data Analyst",
		Type:         t.AgentTypeAI,
		Role:         t.RoleDelegatee,
		Capabilities: []string{"data_analysis", "sql", "visualization", "python"},
		MaxLoad:      8,
		CostPerUnit:  0.08,
		TrustScore:   0.78,
		Status:       t.StatusOnline,
	}

	reviewer := t.AgentProfile{
		AgentID:      "human-reviewer-01",
		Name:         "Senior Engineer",
		Type:         t.AgentTypeHuman,
		Role:         t.RoleOverseer,
		Capabilities: []string{"code_review", "architecture", "security_audit"},
		MaxLoad:      5,
		CostPerUnit:  0.50,
		TrustScore:   0.95,
		Status:       t.StatusOnline,
	}

	for _, agent := range []t.AgentProfile{coder, analyst, reviewer} {
		if err := engine.RegisterAgent(agent); err != nil {
			log.Printf("Register %s: %v", agent.AgentID, err)
		}
	}

	fmt.Println("=== Agents Registered ===")

	// ═══════════════════════════════════════════════════════════════
	// STEP 3: Create and Decompose a Task
	// Uses: EntityRegister → task identity
	//       RelationRegister → task RDID
	//       Post → stores task spec under Tasks domain
	// Paper: Section 4.1 (Task Decomposition)
	// ═══════════════════════════════════════════════════════════════

	deadline := time.Now().Add(24 * time.Hour)
	rootTask := t.TaskSpec{
		TaskID:      "task-build-dashboard",
		DelegatorID: "agent-orchestrator-01",
		Title:       "Build Analytics Dashboard",
		Description: "Create a full-stack analytics dashboard with data pipeline and visualization",
		Criticality: t.CriticalityHigh,
		Complexity:  8,
		Uncertainty: 0.3,
		EstimatedDuration: 28800, // 8 hours
		MaxBudget:          50.0,
		Reversible:         true,
		Verifiability:      0.7,
		Subjectivity:       0.4,
		ContextSensitivity: 0.5,
		RequiredCapabilities: []string{"python", "data_analysis", "go", "visualization"},
		AutonomyLevel:  t.AutonomyBounded,
		MonitoringMode: t.MonitorPeriodic,
		Deadline:       &deadline,
		VerificationPolicy: &t.VerificationPolicy{
			Mode: "strict",
			Artifacts: []t.VerificationArtifact{
				{Type: "unit_test", SignatureRequired: true},
				{Type: "human_review", ValidatorAgentID: "human-reviewer-01"},
			},
		},
	}

	if err := engine.CreateTask(rootTask); err != nil {
		log.Fatalf("Create root task: %v", err)
	}

	// Decompose into sub-tasks (contract-first: each must be verifiable)
	subTasks := []t.TaskSpec{
		{
			TaskID:               "task-data-pipeline",
			Title:                "Build Data Pipeline",
			Description:          "ETL pipeline: extract from source, transform, load to analytics DB",
			Criticality:          t.CriticalityHigh,
			Complexity:           6,
			Verifiability:        0.8, // Unit-testable
			Reversible:           true,
			IsLeaf:               true,
			RequiredCapabilities: []string{"python", "sql", "data_analysis"},
			AutonomyLevel:        t.AutonomyAtomic,
			MonitoringMode:       t.MonitorPeriodic,
			EstimatedDuration:    14400, // 4 hours
			MaxBudget:            20.0,
		},
		{
			TaskID:               "task-api-backend",
			Title:                "Build API Backend",
			Description:          "REST API serving analytics data to the frontend",
			Criticality:          t.CriticalityMedium,
			Complexity:           5,
			Verifiability:        0.9, // Auto-testable
			Reversible:           true,
			IsLeaf:               true,
			RequiredCapabilities: []string{"go", "testing"},
			AutonomyLevel:        t.AutonomyAtomic,
			MonitoringMode:       t.MonitorEventTriggered,
			EstimatedDuration:    10800, // 3 hours
			MaxBudget:            15.0,
		},
		{
			TaskID:               "task-visualization",
			Title:                "Build Visualization Layer",
			Description:          "Interactive charts and dashboard UI",
			Criticality:          t.CriticalityMedium,
			Complexity:           5,
			Verifiability:        0.5, // Partially subjective
			Subjectivity:         0.6,
			Reversible:           true,
			IsLeaf:               true,
			RequiredCapabilities: []string{"visualization", "python"},
			AutonomyLevel:        t.AutonomyBounded,
			MonitoringMode:       t.MonitorPeriodic,
			EstimatedDuration:    10800, // 3 hours
			MaxBudget:            15.0,
		},
	}

	parent, err := engine.DecomposeTask("task-build-dashboard", subTasks)
	if err != nil {
		log.Fatalf("Decompose task: %v", err)
	}
	fmt.Printf("=== Task Decomposed into %d sub-tasks ===\n", len(parent.SubTaskIDs))

	// ═══════════════════════════════════════════════════════════════
	// STEP 4: Market — Publish for Bidding, Score, Accept
	// Uses: InitChannel → creates secure bidding channel
	//       SecureChannelPublish → broadcasts task to market
	//       Post → stores bids, contracts
	// Paper: Sections 4.2 (Assignment), 4.3 (Multi-objective Optimization)
	// ═══════════════════════════════════════════════════════════════

	// Check if task warrants delegation overhead
	for _, sub := range subTasks {
		if market.ShouldBypassDelegation(sub) {
			fmt.Printf("Task %s below complexity floor — execute directly\n", sub.TaskID)
			continue
		}

		// Publish for bidding
		channel, err := engine.PublishTaskForBidding(sub)
		if err != nil {
			log.Printf("Publish %s: %v", sub.TaskID, err)
			continue
		}
		fmt.Printf("Task %s published on channel %s\n", sub.TaskID, channel)
	}

	// Simulate receiving bids for the data pipeline task
	bids := []t.Bid{
		{
			BidID:         "bid-coder-pipeline",
			TaskID:        "task-data-pipeline",
			AgentID:       "agent-coder-01",
			EstimatedCost: 18.0,
			EstimatedTime: 14400,
			Confidence:    0.85,
		},
		{
			BidID:         "bid-analyst-pipeline",
			TaskID:        "task-data-pipeline",
			AgentID:       "agent-analyst-01",
			EstimatedCost: 22.0,
			EstimatedTime: 10800,
			Confidence:    0.92,
		},
	}

	// Score bids using multi-objective optimization
	weights := market.SelectWeightsForTask(subTasks[0]) // Auto-select based on criticality
	trustMap := map[string]float64{
		"agent-coder-01":   coder.TrustScore,
		"agent-analyst-01": analyst.TrustScore,
	}
	capsMap := map[string][]string{
		"agent-coder-01":   coder.Capabilities,
		"agent-analyst-01": analyst.Capabilities,
	}

	ranked := market.RankBids(bids, weights, trustMap, subTasks[0].RequiredCapabilities, capsMap)

	fmt.Println("\n=== Bid Rankings (Data Pipeline) ===")
	for i, sb := range ranked {
		fmt.Printf("  #%d: %s — Score: %.3f (cost=%.2f speed=%.2f trust=%.2f cap=%.2f)\n",
			i+1, sb.Bid.AgentID, sb.Score,
			sb.CostScore, sb.SpeedScore, sb.TrustScore, sb.CapMatchScore)
	}

	// Accept the top bid
	winner := ranked[0]
	contract, err := engine.AcceptBid(winner.Bid, t.ContractTerms{
		MaxCost:           winner.Bid.EstimatedCost * 1.1, // 10% buffer
		Deadline:          deadline,
		MonitoringMode:    t.MonitorPeriodic,
		ReportingInterval: 1800, // 30 min
		EscrowAmount:      winner.Bid.EstimatedCost * 0.2,
		DisputePeriod:     86400, // 24 hours
		VerificationMode:  "direct",
	})
	if err != nil {
		log.Printf("Accept bid: %v", err)
	} else {
		fmt.Printf("\n=== Contract Created: %s ===\n", contract.ContractID)
	}

	// ═══════════════════════════════════════════════════════════════
	// STEP 5: Permission Attenuation (Delegation Capability Tokens)
	// Uses: RelationRegister → RDID-based access
	// Paper: Section 4.7 (Permission Handling), Section 6.1 (DCTs)
	// ═══════════════════════════════════════════════════════════════

	// Mint a DCT for the winning agent — scoped to read-only on the data source
	dct := security.MintDCT(
		"agent-orchestrator-01",
		winner.Bid.AgentID,
		"analytics-db",
		8*time.Hour,
		security.Caveat{Type: "operation", Key: "ops", Value: "read,execute"},
		security.Caveat{Type: "scope", Key: "tables", Value: "raw_events"},
	)
	fmt.Printf("\n=== DCT Minted: %s ===\n", dct.TokenID)
	fmt.Printf("  Bearer: %s, Resource: %s, Expires: %v\n", dct.BearerID, dct.Resource, dct.ExpiresAt)

	// If the delegatee needs to sub-delegate, it attenuates the token further
	childDCT, err := dct.Attenuate("agent-sub-worker-01",
		security.Caveat{Type: "operation", Key: "ops", Value: "read"}, // Narrowed: no execute
		security.Caveat{Type: "scope", Key: "tables", Value: "raw_events/2026"}, // Narrowed scope
	)
	if err != nil {
		log.Printf("Attenuate DCT: %v", err)
	} else {
		fmt.Printf("  Child DCT: %s (attenuated: read-only, scoped to 2026)\n", childDCT.TokenID)
	}

	// Validate access
	if err := dct.ValidateAccess("read", "raw_events"); err != nil {
		fmt.Printf("  Access denied: %v\n", err)
	} else {
		fmt.Println("  Access validated: read on raw_events")
	}
	if err := dct.ValidateAccess("write", "raw_events"); err != nil {
		fmt.Printf("  Access denied (expected): %v\n", err)
	}

	// ═══════════════════════════════════════════════════════════════
	// STEP 6: Monitoring
	// Uses: InitChannel → monitoring channel per task
	//       SecureChannelPublish → emit events
	//       Post → persist to Monitoring domain for audit
	// Paper: Section 4.5 (Monitoring)
	// ═══════════════════════════════════════════════════════════════

	monCh, monRDID, err := engine.SetupMonitoringChannel("task-data-pipeline")
	if err != nil {
		log.Printf("Setup monitoring: %v", err)
	}
	fmt.Printf("\n=== Monitoring Channel: %s (RDID: %s) ===\n", monCh, monRDID)

	// Simulate delegatee emitting progress events
	events := []t.MonitorEvent{
		{
			EventID:   "evt-001",
			TaskID:    "task-data-pipeline",
			AgentID:   winner.Bid.AgentID,
			EventType: t.EventTaskStarted,
			Severity:  t.CriticalityLow,
			Progress:  0.0,
			Message:   "Pipeline construction started",
		},
		{
			EventID:     "evt-002",
			TaskID:      "task-data-pipeline",
			AgentID:     winner.Bid.AgentID,
			EventType:   t.EventCheckpoint,
			Severity:    t.CriticalityLow,
			Progress:    0.5,
			ResourceUse: 9.0,
			Message:     "ETL extract phase complete, transform in progress",
		},
		{
			EventID:     "evt-003",
			TaskID:      "task-data-pipeline",
			AgentID:     winner.Bid.AgentID,
			EventType:   t.EventTaskCompleted,
			Severity:    t.CriticalityLow,
			Progress:    1.0,
			ResourceUse: 17.5,
			Message:     "Pipeline complete, all tests passing",
		},
	}

	for _, evt := range events {
		if err := engine.EmitMonitorEvent(evt); err != nil {
			log.Printf("Emit event: %v", err)
		}
		fmt.Printf("  [%s] Progress: %.0f%% — %s\n", evt.EventType, evt.Progress*100, evt.Message)
	}

	// ═══════════════════════════════════════════════════════════════
	// STEP 7: Verification & Reputation
	// Uses: Post → store verification result, reputation record
	//       EntityUpdate → update agent trust score
	// Paper: Sections 4.8 (Verification), 4.6 (Reputation)
	// ═══════════════════════════════════════════════════════════════

	fmt.Println("\n=== Verification ===")

	// Submit artifact for verification
	engine.SubmitForVerification("task-data-pipeline", []byte(`{"tests_passed": 42, "coverage": 0.89}`))

	// Record verification (passed)
	engine.RecordVerification(t.VerificationResult{
		TaskID:     "task-data-pipeline",
		VerifierID: "human-reviewer-01",
		Passed:     true,
		Score:      0.92,
		Details:    "Pipeline correct, good test coverage, clean code",
	})

	// Compute updated trust score
	trust, _ := engine.ComputeTrustScore(winner.Bid.AgentID)
	fmt.Printf("  Updated trust score for %s: %.3f\n", winner.Bid.AgentID, trust)

	// ═══════════════════════════════════════════════════════════════
	// STEP 8: Adaptive Coordination (Failure Scenario)
	// Uses: Post → store trigger
	//       Get → retrieve task state
	//       SecureChannelPublish → re-publish for bidding
	// Paper: Section 4.4 (Adaptive Coordination)
	// ═══════════════════════════════════════════════════════════════

	fmt.Println("\n=== Adaptive Coordination (Simulated Failure) ===")

	// Simulate: the API backend agent becomes unresponsive
	engine.RaiseTrigger(t.AdaptiveTrigger{
		TriggerID:   "trigger-api-unresponsive",
		TaskID:      "task-api-backend",
		Type:        t.TriggerIntUnresponsive,
		AgentID:     "agent-coder-01",
		Description: "Agent failed to respond to 3 consecutive health checks",
		Urgent:      false, // Task is reversible, not critical
	})
	fmt.Println("  Trigger raised → engine evaluates and re-delegates")

	// ═══════════════════════════════════════════════════════════════
	// STEP 9: Security — Task Screening & Circuit Breakers
	// Paper: Section 4.9 (Security)
	// ═══════════════════════════════════════════════════════════════

	fmt.Println("\n=== Security Screening ===")

	// Screen a suspicious task
	suspiciousTask := t.TaskSpec{
		TaskID:             "task-suspicious",
		Reversible:         false,
		AutonomyLevel:      t.AutonomyOpenEnd,
		ContextSensitivity: 0.9,
		Verifiability:      0.1,
		Complexity:         9,
	}
	warnings := security.ScreenTask(suspiciousTask)
	for _, w := range warnings {
		fmt.Printf("  WARNING: %s\n", w)
	}

	// Circuit breaker for an agent
	cb := security.NewCircuitBreaker("agent-coder-01", 3, 0.4)
	cb.RecordFailure()
	cb.RecordFailure()
	tripped := cb.RecordFailure() // Third failure → trips
	fmt.Printf("  Circuit breaker tripped: %v (state: %s)\n", tripped, cb.State)
	fmt.Printf("  Agent allowed: %v\n", cb.IsAllowed())

	fmt.Println("\n=== Delegation Lifecycle Complete ===")
}

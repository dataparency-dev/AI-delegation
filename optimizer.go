// Package market implements the multi-objective optimization and market coordination
// components of the Intelligent Delegation framework (Sections 4.3, 4.2).
//
// It scores and ranks bids using Pareto-optimality across cost, speed, trust,
// and capability match, then helps the delegator select the best assignment.
package market

import (
	"math"
	"sort"

	t "github.com/yourorg/delegation/types"
)

// Weights for multi-objective optimization. Delegators can tune these
// based on task characteristics (Section 4.3).
type OptimizationWeights struct {
	Cost       float64 `json:"cost"`        // Lower is better
	Speed      float64 `json:"speed"`       // Lower estimated time is better
	Trust      float64 `json:"trust"`       // Higher trust score is better
	Confidence float64 `json:"confidence"`  // Higher bid confidence is better
	CapMatch   float64 `json:"cap_match"`   // Capability overlap ratio
}

// DefaultWeights returns balanced weights.
func DefaultWeights() OptimizationWeights {
	return OptimizationWeights{
		Cost:       0.20,
		Speed:      0.15,
		Trust:      0.30,
		Confidence: 0.15,
		CapMatch:   0.20,
	}
}

// HighStakesWeights prioritizes trust and capability for critical tasks.
func HighStakesWeights() OptimizationWeights {
	return OptimizationWeights{
		Cost:       0.05,
		Speed:      0.05,
		Trust:      0.45,
		Confidence: 0.20,
		CapMatch:   0.25,
	}
}

// CostOptimizedWeights for low-criticality routine tasks.
func CostOptimizedWeights() OptimizationWeights {
	return OptimizationWeights{
		Cost:       0.40,
		Speed:      0.25,
		Trust:      0.15,
		Confidence: 0.10,
		CapMatch:   0.10,
	}
}

// ScoredBid pairs a bid with its computed multi-objective score.
type ScoredBid struct {
	Bid   t.Bid
	Score float64
	// Individual normalized scores for transparency
	CostScore       float64
	SpeedScore      float64
	TrustScore      float64
	ConfidenceScore float64
	CapMatchScore   float64
}

// RankBids scores and ranks bids for a task using multi-objective optimization.
// agentTrust maps agent IDs to their current trust scores.
// requiredCaps is the task's required capabilities list.
func RankBids(
	bids []t.Bid,
	weights OptimizationWeights,
	agentTrust map[string]float64,
	requiredCaps []string,
	agentCaps map[string][]string,
) []ScoredBid {
	if len(bids) == 0 {
		return nil
	}

	// Find min/max for normalization
	var minCost, maxCost float64 = math.MaxFloat64, 0
	var minTime, maxTime int64 = math.MaxInt64, 0
	for _, b := range bids {
		if b.EstimatedCost < minCost {
			minCost = b.EstimatedCost
		}
		if b.EstimatedCost > maxCost {
			maxCost = b.EstimatedCost
		}
		if b.EstimatedTime < minTime {
			minTime = b.EstimatedTime
		}
		if b.EstimatedTime > maxTime {
			maxTime = b.EstimatedTime
		}
	}

	scored := make([]ScoredBid, len(bids))
	for i, bid := range bids {
		// Normalize cost (inverted — lower is better)
		costScore := 1.0
		if maxCost > minCost {
			costScore = 1.0 - (bid.EstimatedCost-minCost)/(maxCost-minCost)
		}

		// Normalize speed (inverted — faster is better)
		speedScore := 1.0
		if maxTime > minTime {
			speedScore = 1.0 - float64(bid.EstimatedTime-minTime)/float64(maxTime-minTime)
		}

		// Trust from pre-computed scores
		trust := agentTrust[bid.AgentID]

		// Capability match ratio
		capScore := capabilityMatchScore(requiredCaps, agentCaps[bid.AgentID])

		// Weighted sum
		total := weights.Cost*costScore +
			weights.Speed*speedScore +
			weights.Trust*trust +
			weights.Confidence*bid.Confidence +
			weights.CapMatch*capScore

		scored[i] = ScoredBid{
			Bid:             bid,
			Score:           total,
			CostScore:       costScore,
			SpeedScore:      speedScore,
			TrustScore:      trust,
			ConfidenceScore: bid.Confidence,
			CapMatchScore:   capScore,
		}
	}

	// Sort descending by score
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Score > scored[j].Score
	})

	return scored
}

// capabilityMatchScore computes the Jaccard-like overlap between required and offered capabilities.
func capabilityMatchScore(required, offered []string) float64 {
	if len(required) == 0 {
		return 1.0
	}
	offeredSet := make(map[string]bool, len(offered))
	for _, c := range offered {
		offeredSet[c] = true
	}
	matched := 0
	for _, r := range required {
		if offeredSet[r] {
			matched++
		}
	}
	return float64(matched) / float64(len(required))
}

// ShouldBypassDelegation implements the "complexity floor" check from Section 4.3.
// Tasks below this threshold should be executed directly rather than delegated,
// because delegation overhead exceeds the task's value.
func ShouldBypassDelegation(task t.TaskSpec) bool {
	return task.Criticality == t.CriticalityLow &&
		task.Complexity <= 2 &&
		task.Uncertainty < 0.2 &&
		task.EstimatedDuration < 60 // Under 1 minute
}

// SelectWeightsForTask auto-selects optimization weights based on task characteristics.
func SelectWeightsForTask(task t.TaskSpec) OptimizationWeights {
	switch {
	case task.Criticality == t.CriticalityCritical || task.Criticality == t.CriticalityHigh:
		return HighStakesWeights()
	case task.Criticality == t.CriticalityLow && task.Complexity <= 3:
		return CostOptimizedWeights()
	default:
		return DefaultWeights()
	}
}

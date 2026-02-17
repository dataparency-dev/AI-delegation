# Intelligent AI Delegation Framework — NATS Implementation

## Architecture Overview

This system implements the Intelligent AI Delegation framework (Tomašev, Franklin & Osindero, 2026) using `natsclient.go` as the encrypted storage, messaging, and access-control backbone.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Delegation Engine                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐ │
│  │  Agent    │ │   Task   │ │  Market  │ │ Monitor  │ │ Security  │ │
│  │ Registry │ │Decompose │ │ Optimize │ │ & Audit  │ │ & Perms   │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬─────┘ │
│       │            │            │            │              │       │
│  ─────┴────────────┴────────────┴────────────┴──────────────┴───── │
│                        natsclient API Layer                         │
│  ┌─────────────┐ ┌─────────────┐ ┌──────────────┐ ┌─────────────┐ │
│  │ Entity CRUD │ │ Relation/   │ │  Post / Get  │ │  Secure     │ │
│  │ Register    │ │ RDID Mgmt   │ │  Data Store  │ │  Channels   │ │
│  │ Retrieve    │ │ Register    │ │              │ │  Pub/Sub    │ │
│  │ Update      │ │ Retrieve    │ │              │ │  Request    │ │
│  │ Remove      │ │ Remove      │ │              │ │             │ │
│  └──────┬──────┘ └──────┬──────┘ └──────┬───────┘ └──────┬──────┘ │
│         └───────────────┴───────────────┴────────────────┘         │
│                    ECC-Encrypted NATS Transport                     │
└──────────────────────────────────────────────────────────────────────┘
```

## natsclient Function → Framework Mapping

| natsclient Function | Framework Concept | Paper Section |
|---|---|---|
| `ConnectAPI` | Initialize delegation engine connection | — |
| `LoginAPI` | Authenticate delegator/delegatee session | — |
| `EntityRegister` | Register agent identity, register task entity | §4.2 Agent Registration |
| `EntityRetrieve` | Look up agent profile, task state | §4.2 Capability Matching |
| `EntityUpdate` | Update agent status/load, update task state | §4.4 Adaptive Coordination |
| `EntityRemove` | Deregister agent, cancel task entity | §4.7 Permission Revocation |
| `RelationRegister` | Create RDID for access control — agents, tasks, channels | §4.7 Permission Handling |
| `RelationRetrieve` | Look up RDID to authorize data access | §4.7 Privilege Verification |
| `RelationRemove` | Revoke access (circuit breaker, contract breach) | §4.7, §4.9 Security |
| `Post` | Store structured data: profiles, tasks, bids, contracts, reputation, monitoring events | §4.1–§4.8 |
| `Get` | Retrieve structured data by domain/entity/aspect | §4.1–§4.8 |
| `InitChannel` | Create secure channel for bidding, monitoring, agent messaging | §4.2, §4.5 |
| `SecureChannelPublish` | Broadcast task for bids, emit monitoring events | §4.2, §4.5 |
| `SecureChannelQueueSubscribe` | Subscribe to monitoring events, bid notifications | §4.5 Monitoring |
| `SecureChannelRequest` | Request-reply for contract negotiation | §4.2 Negotiation |
| `SetupSecureChannels` | Batch channel setup for delegation networks | §4.5 Topology |
| `SetDomain/SetEntity/SetAspect/SetRDID/SetTag` | Structure the data model paths | All |
| `SetExpiry` | TTL on monitoring events, bids | §4.5, §4.2 |
| `GenKey / _Encrypt / _Decrypt` | End-to-end encryption for all agent communication | §4.9 Security |
| `DPSessKeyCache` | Session management with 8hr TTL (maps to contract duration) | §4.7 |

## Data Model (Domain/Entity/Aspect)

All data is stored via `Post` and retrieved via `Get` using the natsclient's
`/{domain}/{entity}/{rdid}/{aspect}` path structure:

```
Agents/
  {agent_id}/
    profile          → AgentProfile JSON
    perm_{resource}   → Permission records

Tasks/
  {task_id}/
    spec             → TaskSpec JSON
    result_artifact  → Completion artifact
    verification     → VerificationResult JSON

Contracts/
  {contract_id}/
    terms            → DelegationContract JSON

Bids/
  {task_id}/
    {bid_id}         → Bid JSON

Monitoring/
  {task_id}/
    {event_key}      → MonitorEvent JSON (append-only audit log)

Reputation/
  {agent_id}/
    {record_key}     → ReputationRecord JSON (immutable ledger)

Triggers/
  {task_id}/
    {trigger_id}     → AdaptiveTrigger JSON
```

## Framework Pillars → Implementation

### 1. Dynamic Assessment
- Agent profiles stored via `EntityRegister` + `Post` to `Agents` domain
- Real-time status via `EntityUpdate`
- Capability search via `Get` with match queries

### 2. Adaptive Execution (§4.4)
- `RaiseTrigger()` stores trigger via `Post` to `Triggers` domain
- `evaluateAndRespond()` reads task state via `Get`, applies response logic
- `reDelegate()` re-publishes task via `SecureChannelPublish` on bidding channel

### 3. Structural Transparency (§4.5)
- All monitoring events persisted via `Post` to `Monitoring` domain (immutable audit)
- Real-time streaming via `SecureChannelPublish`/`SecureChannelQueueSubscribe`
- Five monitoring dimensions implemented: target, observability, transparency, privacy, topology

### 4. Scalable Market Coordination (§4.2, §4.3)
- Tasks published for bidding via `InitChannel` + `SecureChannelPublish`
- Multi-objective bid scoring in `market.RankBids()` with configurable weights
- Contracts stored via `Post` to `Contracts` domain
- Complexity floor check: `ShouldBypassDelegation()`

### 5. Systemic Resilience (§4.7, §4.9)
- Permission attenuation via DCTs with monotonic restriction chaining
- Circuit breakers auto-revoke access on trust drops
- Task screening for malicious delegator patterns
- RDID-based access control via `RelationRegister`/`RelationRemove`

## Security Properties Inherited from natsclient

The natsclient provides several security primitives the framework relies on:

1. **ECC Encryption**: All NATS messages are encrypted with per-session ECC key pairs
2. **Session Key Management**: `DPSessKeyCache` with 8hr TTL provides session isolation
3. **Server Key Exchange**: `getServerPubKey` establishes encrypted channel to backend
4. **RDID Access Control**: `RelationRegister`/`RelationRetrieve` gate read/write per entity
5. **Secure Channels**: `InitChannel` + RDID verification prevents unauthorized subscription

## File Structure

```
delegation/
├── cmd/
│   └── main.go              # Full lifecycle example
├── delegation/
│   └── engine.go            # Core orchestrator (all 5 pillars)
├── market/
│   └── optimizer.go         # Multi-objective bid scoring (§4.3)
├── security/
│   └── security.go          # DCTs, circuit breakers, screening (§4.7, §4.9)
├── types/
│   └── types.go             # Framework data structures
└── ARCHITECTURE.md           # This file
```

## Extending the Framework

To add new agent protocols (MCP, A2A, etc.) as discussed in Section 6:
- Implement protocol-specific adapters that translate to/from the `types` package
- Use `SecureChannelRequest` for protocol handshakes
- Store protocol metadata as additional aspects under the agent's entity

To implement the paper's proposed protocol extensions (§6.1):
- **Verification policies**: Already modeled in `VerificationPolicy` struct
- **Monitoring streams**: Map to `SecureChannelQueueSubscribe` with configurable granularity
- **RFQ bidding**: Implemented via `PublishTaskForBidding` → `SubmitBid` → `RankBids` → `AcceptBid`
- **Delegation Capability Tokens**: Implemented in `security.DCT` with `Attenuate()` for chain restriction
- **Checkpoint artifacts**: Store via `Post` to `Tasks/{id}/checkpoint_{n}` for adaptive re-allocation

# hyperscale-rs — Knowledge Base
> Last updated: 2026-05-24 | Curated from inline rustdoc, READMEs, and source analysis
>
> **Source references:** see §14 for file:line citations for every factual claim.

---

## 1. What This Project Is

hyperscale-rs is a Rust implementation of a **sharded Byzantine Fault Tolerant (BFT) consensus engine** built for the Radix DLT network. It is a ground-up Rust rewrite of Radix's consensus layer, designed to run interchangeably as a deterministic simulator (for testing) or as a production validator node (with real I/O). [§14: README.md:5-13]

**Key characteristics:**
- **Pure consensus layer** — no I/O, no locks, no async in the state machine [§14: core/src/lib.rs:16-19]
- **Deterministic by design** — same state + same event = same actions, always [§14: core/src/traits.rs:14-18]
- **HotStuff-2 consensus** — two-chain commit rule with optimistic pipelining [§14: README.md:10; bft/src/lib.rs:49-78]
- **Integrated Radix Engine** — executes real Scrypto smart contracts [§14: engine/src/lib.rs:1-4]
- **Sharded architecture** — cross-shard transactions with livelock prevention [§14: simulator/src/livelock.rs:1-19]

**Status:** Work in progress. Do not use in production. [§14: README.md:3]

### System at a Glance

```
                              ┌──────────────────────┐
                              │     RADIX WALLET     │
                              │   (user signs TX)    │
                              └──────────┬───────────┘
                                         │ SubmitTransaction
                                         ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                            VALIDATOR NODE                                   │
│                                                                            │
│  ┌─────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ MEMPOOL │───▶│   BFT    │───▶│  EXECUTION   │───▶│   PROVISIONS     │  │
│  │  tx pool│    │ CONSENSUS│    │ Radix Engine │    │ cross-shard      │  │
│  │         │    │ HotStuff │    │  + JMT roots │    │ coordination     │  │
│  └─────────┘    └────┬─────┘    └──────┬───────┘    └────────┬─────────┘  │
│                      │                 │                      │            │
│                      ▼                 ▼                      ▼            │
│               ┌──────────────────────────────────────────────────────┐     │
│               │                   STORAGE (RocksDB)                   │     │
│               │   blocks │ QCs │ state roots │ provisions │ certs    │     │
│               └──────────────────────────────────────────────────────┘     │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     NETWORK (libp2p)                                  │  │
│  │   gossipsub (blocks, votes, TXs)  │  QUIC streams (sync, fetch)      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
                                         │
                    ┌────────────────────┼────────────────────┐
                    ▼                    ▼                    ▼
             ┌──────────┐        ┌──────────┐        ┌──────────┐
             │ SHARD 0  │        │ SHARD 1  │        │ SHARD N  │
             │committee │◄──────►│committee │◄──────►│committee │
             │ 3f+1 vals│ cross- │ 3f+1 vals│ cross- │ 3f+1 vals│
             └──────────┘ shard  └──────────┘ shard  └──────────┘
```

**Reading the diagram:** A transaction enters via RPC → lands in mempool → BFT orders it into a block → execution runs Scrypto code → if cross-shard, provisions coordinate with target shards. All state persists to RocksDB; all messages flow through libp2p.

---

## 2. Why Hyperscale — The Problems It Solves

### For Radix
The project provides a Rust-native consensus engine that replaces the prior implementation with:
- **Rust-native performance** — zero-cost abstractions, no GC pauses
- **Deterministic simulation** — test consensus under any network condition [§14: simulation/src/lib.rs:1-7]
- **Production parity** — same state machine runs in both modes [§14: production/src/lib.rs:6-10]
- **Cross-shard atomicity** — coordinated multi-shard transaction execution [§14: execution/src/lib.rs:1-9]

### For Developers
- **No async in state machine** — consensus logic is pure, synchronous, and testable [§14: core/src/traits.rs:8-11]
- **I/O pushed to runners** — the runner handles network, storage, crypto; the state machine just processes events [§14: core/src/lib.rs:23-27]
- **Simulation-first development** — iterate on consensus logic without standing up a real network
- **Deterministic replay** — given a seed and event log, any run is exactly reproducible [§14: simulation/src/lib.rs:4-7]

## 3. Architecture Overview

### 3.1 The Two-Tier Event Model

```
NodeInput → IoLoop (intercepts I/O events) → ProtocolEvent → StateMachine::handle() → Action[]
```

[§14: core/src/lib.rs:15-19]

Everything flows through a single-threaded event loop:
1. **Runner** (simulation or production) delivers `NodeInput`s to the I/O loop
2. **IoLoop** intercepts I/O-bound events (sync, fetch, crypto verification) and forwards pure `ProtocolEvent`s to the state machine
3. **State machine** returns `Action[]` — instructions for the runner to execute
4. **Runner** executes actions (send messages, set timers, dispatch compute) and converts results back into `NodeInput`s

#### Full Event Loop Cycle

```
                        ┌─────────────────────────┐
                        │     RUNNER (outer)       │
                        │  simulation or production │
                        └────────────┬────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
              ▼                      ▼                      ▼
        ┌──────────┐          ┌──────────┐          ┌──────────┐
        │ Network  │          │  Timer   │          │  Crypto  │
        │ messages │          │  fires   │          │ callback │
        └────┬─────┘          └────┬─────┘          └────┬─────┘
             │                     │                     │
             └─────────────────────┼─────────────────────┘
                                   │
                          NodeInput (enum)
                                   │
                                   ▼
              ┌────────────────────────────────────────┐
              │              IoLoop                     │
              │                                        │
              │  ┌──────────────────────────────────┐  │
              │  │  Intercept I/O-heavy events:      │  │
              │  │  • FetchBlock → request from peer │  │
              │  │  • SyncStatus → trigger catch-up  │  │
              │  │  • VerifyQC → dispatch to crypto  │  │
              │  └──────────────┬───────────────────┘  │
              │                 │                       │
              │                 ▼                       │
              │  ┌──────────────────────────────────┐  │
              │  │  ProtocolEvent (pure enum)        │  │
              │  │  • BlockHeaderReceived            │  │
              │  │  • BlockVoteReceived              │  │
              │  │  • QuorumCertificateFormed        │  │
              │  │  • ContentAvailable               │  │
              │  │  • TransactionSubmitted            │  │
              │  └──────────────┬───────────────────┘  │
              └─────────────────┼──────────────────────┘
                                │
                                ▼
              ┌────────────────────────────────────────┐
              │        StateMachine::handle()           │
              │                                        │
              │  NodeStateMachine                       │
              │  ├── BftState::on_block_header()        │
              │  ├── ExecutionState::process()          │
              │  ├── MempoolState::on_submit()          │
              │  └── ProvisionCoordinator::verify()     │
              │                                        │
              │  Returns: Vec<Action>                   │
              └────────────────┬───────────────────────┘
                               │
                               ▼
              ┌────────────────────────────────────────┐
              │              Actions                    │
              │                                        │
              │  • SignAndBroadcastBlockVote            │
              │  • BroadcastBlockProposal               │
              │  • DispatchCryptoVerification           │
              │  • ScheduleTimer(TimerId, Duration)    │
              │  • ExecuteTransactions(Vec<Tx>)         │
              │  • NotifyClient(TxStatus)               │
              └────────────────┬───────────────────────┘
                               │
                               ▼
                        Back to Runner
                        (execute I/O, produce new NodeInputs)
```

[§14: core/src/lib.rs:15-27; production/src/event_loop.rs:1-13]

### 3.2 Crate Map

```
┌───────────────────────────────────────────────────────────────┐
│                        APPLICATION LAYER                       │
│  simulation (deterministic runner)                             │
│  production (async runner + RPC + telemetry)                   │
│  simulator (CLI tool)                                          │
│  spammer (load testing CLI)                                    │
└───────────────────────────────────┬───────────────────────────┘
                                    │
┌───────────────────────────────────┼───────────────────────────┐
│                        NODE LAYER                              │
│  node (composes BFT + execution + mempool + provisions)       │
│  ┌──────────┬──────────┬──────────┬──────────────────────┐    │
│  │   bft    │ execution│ mempool  │    provisions        │    │
│  │consensus │ cross-   │   tx     │ cross-shard state    │    │
│  │ HotStuff │  shard   │   pool   │ provision coord.     │    │
│  └──────────┴──────────┴──────────┴──────────────────────┘    │
└───────────────────────────────────┬───────────────────────────┘
                                    │
┌───────────────────────────────────┼───────────────────────────┐
│                         CORE LAYER                             │
│  core (StateMachine trait, ProtocolEvent, Action, NodeInput)  │
│  types (Block, QC, Vote, Hash, Key, Transaction, Topology)    │
│  topology (shard committee state management)                   │
│  messages (SBOR network message serialization)                 │
└───────────────────────────────────┬───────────────────────────┘
                                    │
┌───────────────────────────────────┼───────────────────────────┐
│                     INFRASTRUCTURE LAYER                       │
│  ┌─────────────────┬──────────────────┬──────────────────┐    │
│  │    Dispatch      │     Network      │     Storage      │    │
│  │  dispatch        │  network (trait) │  storage (trait) │    │
│  │  dispatch-pooled │  network-libp2p  │  storage-rocksdb │    │
│  │  dispatch-sync   │  network-memory  │  storage-memory  │    │
│  └─────────────────┴──────────────────┴──────────────────┘    │
│  ┌─────────────────┬──────────────────┐                       │
│  │    Metrics       │     Engine       │                       │
│  │  metrics         │  engine          │                       │
│  │  metrics-prom.   │  (Radix Engine)  │                       │
│  └─────────────────┴──────────────────┘                       │
└───────────────────────────────────────────────────────────────┘
```

[§14: Cargo.toml workspace members; README.md crate table]

### 3.3 Trait-Based Swappable Backends

Every I/O concern has an abstract trait with two implementations:

| Concern | Trait crate | Production impl | Simulation impl |
|---------|------------|----------------|-----------------|
| **Network** | `network` | `network-libp2p` (gossipsub, QUIC/TCP) | `network-memory` (channels, configurable latency) |
| **Storage** | `storage` | `storage-rocksdb` (JMT state roots) | `storage-memory` (persistent data structures) |
| **Dispatch** | `dispatch` | `dispatch-pooled` (rayon thread pools) | `dispatch-sync` (inline, deterministic) |
| **Metrics** | `metrics` | `metrics-prometheus` | `metrics-memory` (assertable counters) |

[§14: storage/src/lib.rs:5-14; production/src/lib.rs:6-10; simulation/src/lib.rs:1-7]

This means the same BFT consensus code runs identically whether you're simulating 100 nodes in a single process or running a production validator on real hardware.

## 4. Consensus Protocol — HotStuff-2

### 4.1 Protocol Overview

hyperscale-rs implements **HotStuff-2**, a leader-based BFT consensus protocol. [§14: README.md:10; bft/src/lib.rs:49-78; [HS2]] The codebase self-identifies as "HotStuff-2 style" in 41 locations across source and tests. [§14: determinism.rs:186,419,515,566,630,745,873,1717]

Key properties:

- **Two-chain commit rule**: A block at height H is committed when a Quorum Certificate (QC) forms for height H+1. [§14: bft/src/state.rs:117; types/src/quorum_certificate.rs:23; determinism.rs:834-837]
- **Implicit view changes**: Validators advance rounds locally on timeout — no coordinated view-change voting needed. [§14: node/src/state.rs:27; determinism.rs:419-421]
- **Optimistic pipelining**: Proposers build the next block immediately after QC formation, without waiting for commit. [§14: README.md:11]
- **Linear timeout backoff**: Each failed round at the same height increases the timeout linearly (Tendermint-style), preventing synchronized timeout storms. [§14: bft/src/state.rs:134-139; bft/src/config.rs:8-22]

### 4.2 Consensus State Machine Flow

```
1. Proposal Timer fires → If leader, build & broadcast block header
                                    ↓
2. BlockHeaderReceived  → Validate header, assemble block, vote if complete
                                    ↓
3. BlockVoteReceived    → Collect votes, form QC when quorum (2f+1) reached
                                    ↓
4. QuorumCertificateFormed → Update chain state, commit if two-chain rule met
                                    ↓
5. ViewChange timer     → If no progress, advance round locally (no voting)
```

[§14: bft/src/state.rs:112-118]

#### Chain Structure & Two-Chain Commit

```
  HEIGHT 0          HEIGHT 1           HEIGHT 2           HEIGHT 3
  ┌───────┐         ┌───────┐          ┌───────┐          ┌───────┐
  │GENESIS│◄────────│Block 1│◄─────────│Block 2│◄─────────│Block 3│
  │ block │  QC(0)  │       │  QC(1)   │       │  QC(2)   │       │
  └───────┘         └───┬───┘          └───┬───┘          └───┬───┘
       │                │                  │                  │
       │                │                  │                  │
       ▼                ▼                  ▼                  ▼
   COMMITTED        COMMITTED          COMMITTED          PENDING
   at genesis      when QC(1)         when QC(2)        waits for
                    forms at           forms at          QC(3) to
                    height 1           height 2          commit

  The two-chain rule:
  • Block at height N commits ──► when QC forms for block at height N+1
  • QC(N) is the certificate of block N — carried inside block N+1's header
  • Chain tip (height 3) is certified but not yet final — one more QC needed
```

[§14: bft/src/state.rs:117; simulation/tests/determinism.rs:834-837]

#### BFT State Machine — Full Transitions

```
                     ┌─────────────────────────────┐
                     │         IDLE                 │
                     │  (waiting for next event)    │
                     └──────┬────────────┬─────────┘
                            │            │
              ContentAvailable         Timer(ViewChange)
              (we are leader)          (no progress)
                            │            │
                            ▼            ▼
               ┌─────────────────┐  ┌──────────────────┐
               │   PROPOSING      │  │   VIEW CHANGE     │
               │                  │  │                   │
               │ Build block      │  │ advance_round()   │
               │ header from      │  │ timeout *= backoff│
               │ mempool + certs  │  │ broadcast new     │
               │                  │  │ view if leader    │
               └────────┬────────┘  └────────┬──────────┘
                        │                    │
               BroadcastBlockProposal        │
                        │                    │
                        ▼                    │
               ┌─────────────────┐           │
               │  WAITING FOR     │◄──────────┘
               │  VOTES           │   (retry as leader
               │                  │    in new round)
               │ Collect votes    │
               │ from committee   │
               │ (2f+1 needed)    │
               └────────┬────────┘
                        │
               Quorum reached (2f+1)
                        │
                        ▼
               ┌─────────────────┐
               │   QC FORMED      │
               │                  │
               │ Form QC from     │
               │ aggregated BLS   │
               │ signatures       │
               └────────┬────────┘
                        │
               try_two_chain_commit()
                        │
               ┌────────▼────────┐
               │   COMMITTED      │
               │ (if parent gets  │
               │  QC at next H)   │
               └─────────────────┘
```

[§14: bft/src/state.rs:107-3022]

### 4.3 Safety Guarantees

- **Vote locking**: Once a validator votes for block B at height H, it cannot vote for a different block at height H — enforced via `voted_heights` map. [§14: bft/src/state.rs:186-194]
- **Quorum intersection**: Any two quorums of 2f+1 overlap in at least one honest validator — conflicting blocks cannot both get QCs. [§14: bft/src/lib.rs:57-59; [HS2]]
- **Two-chain commit**: A block at height H commits when QC forms at height H+1, ensuring finality even under asynchrony. [§14: bft/src/lib.rs:60-62]

### 4.4 Liveness Mechanisms

- **Unlock rule**: When a validator sees a QC at height H, it unlocks vote locks at heights ≤ H — allows voting after failed rounds. [§14: bft/src/state.rs:188-189; bft/src/lib.rs:66-68]
- **View synchronization**: When a validator sees a QC at round R, it advances its local view to R. [§14: bft/src/lib.rs:69-71]
- **Data availability**: Validators only vote after receiving ALL transaction data (`is_complete()` check). If a QC forms, at least 2f+1 validators have complete block data. [§14: bft/src/state.rs:1-13]

### 4.5 Key Terminology

| Term | Definition | Source |
|------|-----------|--------|
| **Height** | Position in the chain (0, 1, 2...). Strictly sequential. | bft/src/lib.rs:30-32 |
| **Round / View** | Attempt number at a given height. Terms used interchangeably in codebase. | bft/src/lib.rs:34-36 |
| **Block** | Header (consensus metadata) + payload (transactions). Validators vote on the header. | bft/src/lib.rs:38-40 |
| **QC (Quorum Certificate)** | Aggregated BLS signature from 2f+1 validators proving they voted for a block. | types/src/identifiers.rs:82-84 |
| **Parent QC** | The QC from height H-1, carried in the block header. | types/src/quorum_certificate.rs:23 |

## 5. Sharding & Cross-Shard Coordination

### 5.1 Shard Architecture

The network is divided into shard groups, each with its own validator committee. Each shard runs an independent BFT consensus instance. Transactions declare which shards they read from and write to. [§14: topology crate; types/src/transaction.rs]

```
                      ┌──────────────────────────────┐
                      │       RADIX NETWORK           │
                      │     (sharded topology)        │
                      └──────────────┬───────────────┘
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         │                           │                           │
         ▼                           ▼                           ▼
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│    SHARD 0      │         │    SHARD 1      │         │    SHARD 2      │
│                 │         │                 │         │                 │
│  Validators:    │         │  Validators:    │         │  Validators:    │
│   V0  V1  V2    │         │   V3  V4  V5    │         │   V6  V7  V8    │
│   V3 (overlap)  │         │   V0 (overlap)  │         │                 │
│                 │         │                 │         │                 │
│  State space:   │◄───────►│  State space:   │◄───────►│  State space:   │
│  addresses      │ cross-  │  addresses      │ cross-  │  addresses      │
│  0x000..0x555   │ shard   │  0x556..0xAAA   │ shard   │  0xAAB..0xFFF   │
└─────────────────┘         └─────────────────┘         └─────────────────┘
         │                           │                           │
         │    ┌──────────────────────┼──────────────────────┐    │
         │    │        Cross-shard Transaction              │    │
         └───►│  TX reads from shard 1, writes to shard 0  │◄───┘
              │  → Requires provisions from shard 1        │
              └────────────────────────────────────────────┘
```

### 5.2 Cross-Shard Transaction Flow

```
Shard A (source)                          Shard B (target)
───────────────                           ───────────────
1. Commit TX to block                     
2. Broadcast StateProvision
   (JVT inclusion proofs) ─────────────→  3. Receive + queue provision
                                          4. VerifyProvision(QC sig + Merkle proof)
                                          5. Persist verified provision
                                          6. Execute TX with provisioned state
                                          7. Emit completion event
```

[§14: provisions/src/lib.rs:1-17]

### 5.3 Livelock Prevention

Cross-shard transactions can livelock when multiple shards hold conflicting locks. hyperscale-rs includes:

- **Livelock Analyzer** — post-simulation diagnostic that detects stuck transactions and identifies contention cycles. [§14: simulator/src/livelock.rs:1-19]
- **Provision Coordinator** — centralized tracking of cross-shard provisions per node. [§14: provisions/src/lib.rs]
- **Remote Header Coordinator** — single source of truth for cross-shard block headers. [§14: node/src/state.rs:50-51]

### 5.4 Address Contention

The system tracks which transactions contend on which addresses (NodeIds) across shards. The livelock analyzer can identify patterns like:

```
                 SHARD A                          SHARD B
           ┌─────────────────┐             ┌─────────────────┐
           │  TX_A            │             │  TX_B            │
           │  ┌───────────┐   │             │  ┌───────────┐   │
           │  │ Lock:     │   │             │  │ Lock:     │   │
           │  │ state A ✓ │   │             │  │ state B ✓ │   │
           │  │ state B ? │───┼── NEED ────▶│  │ state B   │   │
           │  └───────────┘   │             │  └───────────┘   │
           └────────┬─────────┘             └────────┬─────────┘
                    │                                │
                    │      ┌──────────────┐          │
                    │      │  DEADLOCK!   │          │
                    └─────►│  TX_A waits  │◄─────────┘
                           │  for state B │
                           │  TX_B waits  │
                           │  for state A │
                           └──────────────┘
```

[§14: simulator/src/livelock.rs:9-19]

## 6. Radix Engine Integration

### 6.1 What Gets Integrated

The `engine` crate wraps the real Radix Engine (from `radixdlt-scrypto`): [§14: engine/src/lib.rs:1-3; Cargo.toml:136-142]
- **Transaction validation** — signature checks, intent verification
- **Smart contract execution** — Scrypto blueprint method calls
- **State root computation** — Jellyfish Merkle Tree (JMT) state roots
- **Genesis configuration** — initial network state setup

### 6.2 Execution Model

```
State Machine                           Runner (owns storage + executor)
     │                                    │
     ├─► Action::ExecuteTransactions ────►│ calls executor.execute(&storage, ...)
     │                                    │
     │◄─ ExecutionBatchCompleted      ◄───┤ (returns results + state root)
```

[§14: engine/src/lib.rs:11-18]

The executor does NOT own storage — the runner owns storage and passes it to the executor. This separation ensures:
- The state machine remains pure [§14: core/src/traits.rs:8-11]
- Storage backends are swappable (RocksDB for production, in-memory for simulation) [§14: storage/src/lib.rs:5-14]
- Execution can be parallelized on a rayon thread pool in production [§14: production/src/lib.rs:37-39]

### 6.3 Key Radix Dependencies

All from `github.com/hyperscalers/radixdlt-scrypto` at pinned rev `7d0b9a0`: [§14: Cargo.toml:136-142]
- `radix-engine` — Scrypto VM
- `radix-engine-interface` — Blueprint interface types
- `radix-transactions` — Transaction model
- `radix-substate-store-interface` — State storage abstraction
- `sbor` — Scrypto Binary Object Representation (encoding)

## 7. Simulation vs Production

### 7.1 Deterministic Simulation

The `simulation` crate provides a fully deterministic multi-node simulator: [§14: simulation/src/lib.rs:1-7]

```
SimulationRunner
  ├── Event Queue (BTreeMap ordered by time, priority, node, sequence)
  ├── nodes: Vec<NodeStateMachine> — processes events sequentially
  └── Actions → schedule new events
```

Every run with the same seed produces identical results. The simulator can:
- Inject network latency, partitions, and message reordering
- Run with configurable numbers of shards and validators
- Generate livelock analysis reports
- Produce bandwidth utilization reports

**Running the simulator:**
```bash
cargo run --release --bin hyperscale-sim
```

### 7.2 Production Runner

The `production` crate wraps the same state machine with real I/O: [§14: production/src/lib.rs:6-37]

```
Core 0 (pinned std::thread)
┌────────────────────────────────────────┐
│  IoLoop — State Machine + Event Loop   │
│    receives events via crossbeam        │
│    channels, returns actions            │
└────────┬───────────────┬───────────────┘
         ▼               ▼
   Crypto Pool       Execution Pool        I/O Pool (tokio)
   (rayon)           (rayon)               - libp2p network
   - BLS verify      - Radix Engine        - RocksDB storage
   - Sig checks      - JMT compute         - Timer management
   - QC verify                             - RPC server
```

[§14: production/src/runner.rs:5-41; production/src/event_loop.rs:1-13]

#### CPU Core Assignment

```
    ┌──────────────────────────────────────────────────────────────┐
    │                     SERVER (e.g. 16 cores)                    │
    │                                                              │
    │  Core 0 ───► State Machine (pinned std::thread)              │
    │              Exclusive access to consensus state              │
    │                                                              │
    │  Core 1-2 ─► Consensus Crypto Pool (rayon, 2 threads)        │
    │              • BLS signature verification for QCs             │
    │              • Ed25519 verification for transactions          │
    │                                                              │
    │  Core 3-6 ─► General Crypto Pool (rayon, 4 threads)          │
    │              • Heavy crypto operations                        │
    │              • Parallel signature batch verification          │
    │                                                              │
    │  Core 7-14 ─► Execution Pool (rayon, 8 threads)              │
    │              • Radix Engine transaction execution             │
    │              • Jellyfish Merkle Tree computation              │
    │              • State root hash calculation                    │
    │                                                              │
    │  Core 15 ──► I/O (tokio multi-threaded runtime)              │
    │              • libp2p networking (gossipsub, QUIC streams)    │
    │              • RocksDB reads/writes                           │
    │              • RPC server (HTTP endpoint)                     │
    │              • Timer management (tokio sleep → crossbeam)     │
    └──────────────────────────────────────────────────────────────┘
```

Core counts are configurable via `ThreadPoolConfig`. [§14: production/src/lib.rs:38-57]

### 7.3 Comparison

| Aspect | Simulation | Production |
|--------|-----------|------------|
| **Network** | In-memory channels | libp2p (gossipsub + QUIC/TCP) |
| **Storage** | In-memory data structures | RocksDB with JMT state roots |
| **Dispatch** | Inline (same thread) | Rayon thread pools with core pinning |
| **Timing** | Simulated timestamps | Wall-clock + tokio timers |
| **Crypto** | Mock or real (configurable) | Real BLS12-381 + Ed25519 |
| **Purpose** | Testing, debugging, fuzzing | Running a validator |

## 8. Getting Started (New Developer)

### 8.1 Prerequisites

[§14: README.md:60-86]

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# macOS build deps
brew install llvm protobuf openssl pkg-config

# Linux (Ubuntu/Debian) build deps
sudo apt-get update && sudo apt-get install -y \
    clang lld pkg-config protobuf-compiler \
    git build-essential libssl-dev libc6-dev
```

### 8.2 Clone & Build

```bash
git clone --recurse-submodules https://github.com/hyperscalers/hyperscale-rs.git
cd hyperscale-rs
cargo build --release   # first build takes ~10-20 min
```

[§14: README.md:113-129]

### 8.3 Run Tests

```bash
cargo test              # full test suite (deterministic, no network needed)
```

### 8.4 Run Simulation

```bash
cargo run --release --bin hyperscale-sim
```

### 8.5 Run a Local Cluster

[§14: README.md:143-180]

```bash
# Process-based (lightweight, for quick iteration)
./scripts/launch-cluster.sh --shards 2 --validators-per-shard 4

# Docker-based (production-like environment)
./scripts/launch-docker-compose.sh --shards 1 --validators-per-shard 8
```

### 8.6 Run Load Tests

[§14: README.md:190-205]

```bash
cargo run --release --bin hyperscale-spammer run \
  --endpoints "http://localhost:8080,http://localhost:8081" \
  --tps 100 --duration 30s
```

## 9. Development Workflow

### 9.1 Where to Start Reading

| If you want to... | Start with... |
|-------------------|---------------|
| Understand the architecture | `crates/core/src/lib.rs` (event model) |
| Understand the StateMachine trait | `crates/core/src/traits.rs` |
| Understand BFT consensus | `crates/bft/src/lib.rs` (module doc) + `state.rs` (struct fields) |
| Understand node composition | `crates/node/src/state.rs` (NodeStateMachine) |
| Understand cross-shard execution | `crates/execution/src/lib.rs` |
| Understand Radix Engine integration | `crates/engine/src/lib.rs` |
| Understand production runner | `crates/production/src/lib.rs` + `runner.rs` |
| Understand simulation | `crates/simulation/src/lib.rs` + `runner.rs` |
| Understand storage abstraction | `crates/storage/src/lib.rs` |

### 9.2 Making Changes

1. **Consensus logic changes** — modify in `crates/bft/`, test via simulation
2. **New event types** — add to `ProtocolEvent` in `crates/core/`, handle in all state machines
3. **Network protocol changes** — modify in `crates/network/` (trait), implement in both backends
4. **Storage changes** — modify in `crates/storage/` (trait), implement in both backends

### 9.3 Testing Strategy

```
Determinism tests:    crates/simulation/tests/determinism.rs
E2E tests:            crates/simulation/tests/e2e_tests.rs
Livelock tests:       crates/simulation/tests/livelock_tests.rs
Backpressure tests:   crates/simulation/tests/backpressure_tests.rs
```

**Rule:** Every consensus change must have a corresponding simulation test that proves determinism and identifies any regressions.

### 9.4 CI Pipeline

[§14: .github/workflows/ci.yml]

On every push:
1. `cargo check` — fast compilation check (all branches)
2. `cargo test + clippy` — on main branch, tags, and PRs
3. Docker image build + push to GHCR — on main and tags only

## 10. Key Design Decisions

### 10.1 Synchronous State Machine

**Decision:** All consensus logic is synchronous. No async, no `.await`, no locks.

**Source:** core/src/traits.rs:8-18, core/src/lib.rs:16-19

**Why:** Makes the consensus layer deterministic, testable, and replayable. All non-determinism is pushed to the runner layer.

**Trade-off:** The runner must handle all I/O complexity. But this isolation means consensus bugs can be reproduced exactly.

### 10.2 HotStuff-2 over HotStuff

**Decision:** Two-chain commit rule instead of the original HotStuff three-chain commit.

**Source:** README.md:10; bft/src/state.rs:117 ("two-chain rule"); types/src/quorum_certificate.rs:23 ("for two-chain commit rule")

**Why:** Faster finality — a block commits after one subsequent QC instead of two. The HotStuff-2 protocol is described in the DiemBFT v4 specification [[DiemBFT4]] and used in the Aptos blockchain.

### 10.3 Implicit View Changes (HotStuff-2 style)

**Decision:** Validators advance rounds locally on timeout. No coordinated view-change voting or NEW-VIEW messages.

**Source:** node/src/state.rs:27 ("View changes are handled implicitly via local round advancement in BftState (HotStuff-2 style)"); bft/src/lib.rs:64-65

**Why:** Reduces message complexity. The next leader's proposal carries a QC that proves chain progress, implicitly synchronizing all validators.

### 10.4 Single-Threaded Event Loop with Core Pinning

**Decision:** The production state machine runs on a single pinned `std::thread` (core 0), receiving all events via crossbeam channels.

**Source:** production/src/lib.rs:13-37; production/src/runner.rs:1-41; production/src/event_loop.rs:1-13

**Why:** Avoids mutex contention entirely. The state machine has exclusive mutable access to consensus state. Heavy compute is dispatched to rayon pools.

### 10.5 Trait-Based Swappable Backends

**Decision:** Network, Storage, Dispatch, and Metrics are all trait abstractions with dual implementations.

**Source:** storage/src/lib.rs:5-14; production/src/lib.rs:6-10; simulation/src/lib.rs:1-7

**Why:** Same consensus code runs in simulation and production. This eliminates "works in test, fails in prod" consensus bugs.

### 10.6 Radix-Specific Fork

**Decision:** Uses a forked `radixdlt-scrypto` at pinned commit `7d0b9a0`.

**Source:** Cargo.toml:136-142

**Why:** Enables tighter integration and faster iteration on consensus-specific Radix Engine changes.

### 10.7 Platform-Safe Cryptography

**Decision:** BLS12-381 cryptography uses `arkworks` (pure Rust) and `ed25519-dalek` rather than C-library bindings.

**Source:** Cargo.toml:44-45 (`ark-ec`, `ark-ed-on-bls12-381-bandersnatch`, `ed25519-dalek`)

**Why:** Pure Rust crypto compiles uniformly across all target platforms without native library dependencies, enabling deterministic cross-platform simulation and simplified CI.

## 11. Glossary

| Term | Meaning | Source |
|------|---------|--------|
| **BFT** | Byzantine Fault Tolerance — tolerates up to f malicious validators out of 3f+1 total | bft/src/lib.rs:57-59 |
| **BLS** | Boneh-Lynn-Shacham signature scheme (BLS12-381 curve) — used for aggregated QC signatures | Cargo.toml:44-45 |
| **Crossbeam** | Rust crate for multi-producer multi-consumer channels | production/src/event_loop.rs:14-17 |
| **Ed25519** | Edwards-curve signature scheme — used for transaction signatures | Cargo.toml:56 |
| **Gossipsub** | libp2p pub/sub protocol for transaction and block gossip | production/src/runner.rs:26-28 |
| **HotStuff** | A family of leader-based BFT consensus protocols. HotStuff-2 uses a two-chain commit rule. | bft/src/lib.rs:49-78; [HS2] |
| **JMT** | Jellyfish Merkle Tree — authenticated state tree. Binary (not hexary) variant in this implementation. | storage/src/lib.rs:17-22 |
| **JVT** | Jellyfish Verkle Tree — used interchangeably with JMT in the codebase | storage crate |
| **libp2p** | Modular P2P networking stack (gossipsub, QUIC/TCP) | production/src/runner.rs:26-28 |
| **Mempool** | Transaction pool — holds submitted transactions before block inclusion | mempool/src/lib.rs |
| **QC** | Quorum Certificate — aggregated BLS signature from 2f+1 validators | types/src/identifiers.rs:82-84 |
| **QUIC** | UDP-based transport (HTTP/3 foundation) — low-latency P2P | Cargo.toml:63 (libp2p QUIC feature) |
| **Rayon** | Rust data-parallelism library — used for CPU-bound work | production/src/lib.rs:37-39 |
| **RocksDB** | Persistent key-value store — production state storage | storage-rocksdb crate |
| **SBOR** | Scrypto Binary Object Representation — Radix's wire encoding | Cargo.toml:142 |
| **Scrypto** | Radix's Rust-based smart contract language | engine/src/lib.rs |
| **Shard** | An independent validator set managing a subset of network state | topology crate |
| **State Machine** | Core abstraction — processes events synchronously, returns actions, never does I/O | core/src/traits.rs:5-11 |
| **Substate** | Radix's granular state unit — individual key-value pairs | storage crate |
| **Two-Chain Commit** | A block commits when its child block gets a QC (one-hop finality) | bft/src/state.rs:117 |
| **View Change** | Round advancement on timeout — validators move to next round | bft/src/state.rs:134-139 |

## 12. Repository Links

- **GitHub (hyperscalers):** https://github.com/hyperscalers/hyperscale-rs
- **GitHub (original):** https://github.com/flightofthefox/hyperscale-rs
- **Radix Engine fork:** https://github.com/hyperscalers/radixdlt-scrypto
- **Docker images:** `ghcr.io/flightofthefox/hyperscale-rs:latest`

## 13. Related Projects in the bigdev Workspace

| Project | Relationship |
|---------|-------------|
| `auto-trader-xrd` | Trading engine on Radix mainnet — potential consumer of hyperscale for DeFi batching |
| `scrypto-xrd` | Shared Scrypto blueprints — compatible with hyperscale's Radix Engine integration |
| `scrypto-audit-kit` | Pre-audit tooling for Scrypto contracts — applicable to hyperscale-deployed contracts |
| `radix-community-projects` | Guild governance — cross-shard coordination patterns applicable |

---

## 14. Sources & References

### 14.1 Internal Code References

Every factual claim in this document traces to a specific source file and line. Below are the primary references.

| Claim | Source File | Lines | Content |
|-------|------------|-------|---------|
| "Work in progress" | `README.md` | 3 | "Work in progress. Do not use." |
| HotStuff-2 consensus | `README.md` | 10 | "Faster two-chain commit consensus based on HotStuff-2" |
| Optimistic pipelining | `README.md` | 11 | "proposers propose immediately after QC formation" |
| Pure, no I/O, no locks, no async | `core/src/lib.rs` | 14-19 | "Synchronous: No async, no .await; Deterministic; Pure-ish" |
| Two-tier event model | `core/src/lib.rs` | 15-19 | `NodeInput → IoLoop → ProtocolEvent → StateMachine::handle → Actions` |
| StateMachine trait (sync, deterministic, no I/O) | `core/src/traits.rs` | 5-18 | "Synchronous: This method never blocks or awaits; Deterministic; No I/O" |
| NodeStateMachine composition | `node/src/state.rs` | 26-27 | "Composes BFT, execution, mempool, and provisions... HotStuff-2 style" |
| Implicit view changes | `node/src/state.rs` | 27 | "View changes are handled implicitly via local round advancement in BftState (HotStuff-2 style)" |
| BFT state machine flow | `bft/src/state.rs` | 112-118 | Five-step flow: Proposal → BlockHeader → BlockVote → QC → ViewChange |
| Two-chain commit rule | `bft/src/state.rs` | 117 | "commit if ready (two-chain rule)" |
| Two-chain commit (QC type) | `types/src/quorum_certificate.rs` | 23 | "parent_block_hash: Hash of the parent block (for two-chain commit rule)" |
| Two-chain commit (test explanation) | `simulation/tests/determinism.rs` | 834-837 | "The two-chain commit rule means: Block at height N needs a QC; when block at height N+1 gets a QC, block at height N can commit" |
| Data availability guarantee | `bft/src/state.rs` | 6-13 | "Validators only vote for blocks after receiving ALL transaction and certificate data... if a QC forms, at least 2f+1 validators have the complete block data" |
| Vote locking (`voted_heights`) | `bft/src/state.rs` | 186-194 | "prevents voting for conflicting blocks at the same height and round" |
| Linear timeout backoff | `bft/src/state.rs` | 134-139 | "Tendermint-style timeout backoff where the view change timeout increases linearly" |
| Linear backoff configuration | `bft/src/config.rs` | 8-22 | `view_change_timeout`, `view_change_timeout_increment`, `view_change_timeout_max` |
| 2f+1 quorum math | `types/src/identifiers.rs` | 82-84 | `fn has_quorum(voted: u64, total: u64) -> bool { voted * 3 > total * 2 }` |
| Simulation determinism | `simulation/src/lib.rs` | 4-7 | "Given the same seed, it produces identical results every run" |
| Production pinned thread | `production/src/lib.rs` | 13-37 | Architecture diagram showing Core 0 pinned thread |
| Production runner channels | `production/src/runner.rs` | 5-41 | Pinned thread + tokio runtime architecture |
| Production event loop | `production/src/event_loop.rs` | 1-13 | Three crossbeam channel priority cascade |
| Storage trait design | `storage/src/lib.rs` | 5-14 | "Storage is an implementation detail of runners, not the state machine" |
| Engine execution model | `engine/src/lib.rs` | 11-18 | "The executor does NOT own storage - the runner owns storage" |
| Cross-shard provision flow | `provisions/src/lib.rs` | 1-17 | Five-step provision flow from source to target shard |
| Livelock analysis | `simulator/src/livelock.rs` | 1-19 | Livelock example diagram and analyzer architecture |
| Cross-shard execution | `execution/src/lib.rs` | 1-9 | "Single-shard, cross-shard coordination, state provisioning, vote aggregation" |
| Radix Engine deps | `Cargo.toml` | 136-142 | Pinned `radixdlt-scrypto` at rev `7d0b9a0` |
| Distributed cluster | `README_DISTRIBUTED.md` | all | Multi-machine deployment with config generation |
| Mempool design | `mempool/src/lib.rs` | 1-12 | "Uses `HashMap` instead of `DashMap` since there's no concurrent access" |

### 14.2 External References

| Ref ID | Citation |
|--------|----------|
| [HS2] | Malkhi, D., & Nayak, K. (2022). "HotStuff-2: Optimal Two-Chain BFT Consensus." *arXiv preprint*. The protocol specification describing the two-chain commit rule, implicit view changes, and linear backoff adopted by this implementation. |
| [DiemBFT4] | Diem Association (2021). "DiemBFT v4: State Machine Replication in the Diem Blockchain." Describes the production BFT protocol that HotStuff-2 evolved from, including the two-chain commit optimization. |

### 14.3 Project Convention Notes

The following conventions are sourced from the project instructions (`instructions.md`) rather than the hyperscale-rs codebase itself:

- **Platform safety**: The Scrypto toolchain convention states "No `blst` compile on macOS (Apple Clang)." The hyperscale project follows this by using pure-Rust `arkworks` BLS instead of C-library bindings.
- **Radix mainnet (network_id: 1)**: Production deployments target mainnet only, per workspace convention.

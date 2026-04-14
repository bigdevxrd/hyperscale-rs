# hyperscale-rs — Work Session Handoff (2026-04-12)

## What This Project Is
Rust BFT consensus protocol for Radix. 28 crates, 500+ tests. Built by hyperscalers team. We're contributing as external collaborators via fork.

- Upstream: https://github.com/hyperscalers/hyperscale-rs
- Fork: https://github.com/bigdevxrd/hyperscale-rs
- Local: /Users/bigdev/Projects/hyperscale-rs

## Current PR Status

| PR | Title | Branch | Status |
|----|-------|--------|--------|
| #55 | Bounded mempool pool eviction | `bounded-mempool-pool` | Open, awaiting review |
| #56 | Age-based cleanup for early execution results | `execution-early-results-cleanup` | Open, awaiting review |
| #57 | Age-based cleanup for early wave attestations | `execution-early-attestations-cleanup` | Open, awaiting review |
| #58 | Timeout for stale inclusion proof fetches | `livelock-proof-fetch-timeout` | Open, awaiting review |
| #59 | Cap early votes buffer per wave (HashMap dedup) | `execution-early-votes-bounds` | Open, awaiting review |

All PRs: tests pass, clippy clean, fmt clean. Reviewed for Byzantine safety.

## #22 Audit Completion

| Structure | Risk | Status |
|-----------|------|--------|
| `mempool::pool` | Critical | PR #55 |
| `execution::early_execution_results` | Critical | PR #56 |
| `livelock::tombstones` | ~~Critical~~ | Already wired |
| `execution::early_wave_attestations` | High | PR #57 |
| `livelock::pending_proof_fetches` | High | PR #58 |
| `execution::early_votes` inner Vec | Medium | PR #59 |
| `pending_abort_intents` | Low | Cleaned on commit |
| `provision_tracker.seen` | Low | Cleaned per-tx terminal |

## Crate Map

| Crate | Purpose |
|-------|---------|
| **bft** | HotStuff-2 consensus state machine |
| **core** | Event/Action/StateMachine traits |
| **execution** | TX execution, cross-shard 2PC, vote aggregation |
| **livelock** | Cross-shard deadlock prevention (cycle detection) |
| **mempool** | TX staging, gossip, conflict detection |
| **node** | Composed state machine (BFT + execution + mempool) |
| **provisions** | Cross-shard state provision coordination |
| **remote-headers** | Cross-shard block header verification |
| **storage** | Storage traits + verkle state tree |
| **storage-memory** | In-memory storage (simulation) |
| **storage-rocksdb** | RocksDB storage (production) |
| **network** / **network-libp2p** / **network-memory** | Transport layer |
| **simulation** / **simulator** | Deterministic sim runner + workload sim |
| **production** | Production async runner |
| **engine** | Radix Engine integration |
| **messages** | Network message types (sbor) |
| **metrics** / **metrics-prometheus** | Metrics facade + Prometheus |
| **topology** | Shard committee management |
| **types** | Core types (Hash, Block, WaveId, etc.) |
| **test-helpers** | Properly-signed crypto fixtures |
| **dispatch** / **dispatch-pooled** / **dispatch-sync** | Work scheduling |
| **spammer** | Load testing TX generator |

## Architecture: Transaction Flow

```
TX arrives → Mempool (validate, gossip)
          → BFT Leader proposes block
          → Validators vote → QC at 2f+1
          → Two-chain commit (H finalized when QC at H+1)
          → Execution:
              Single-shard: execute → vote → EC
              Cross-shard:  provisions → verify → execute → vote → EC → WaveCert
          → Livelock: cycle detection via provision overlap, hash-based deferral
          → State committed to storage
```

Key: All state machines are synchronous, deterministic, zero I/O.

## Next Contribution Targets

### Tier 1 — Best Next
1. **#23 — Simulator trait unification** — Extract common trait from parallel + deterministic sims. Medium effort, high visibility.
2. **#15 — Benchmarks** — Criterion for BFT voting, execution waves, mempool insertion.

### Tier 2 — Good Follow-ups
3. **#18 — Transaction/substate test suite** — Start single-shard, expand cross-shard.
4. **#9 — Use radix_common** — Dependency swap for crypto primitives.
5. **#41 — Systemd service files** — Quick ops win.

### Avoid for Now
- #3 (TLA+), #10/#11 (protocol design), #17 (fee economics)

## Upstream Branches to Watch
- `event-loop-overhaul` — Major refactor, merge conflict risk
- `generic-consensus` — Abstracting consensus
- `byzantine-backpressure` — Related to our DoS hardening
- `jellyfish-verkle-tree` — State storage changes

## PR Standards
- `cargo fmt` + `cargo clippy --all-targets` must pass
- Imperative commit messages
- Every behavior change has a test
- One fix per PR, keep diffs focused
- Rebase onto upstream/main before submitting

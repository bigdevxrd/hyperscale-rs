# hyperscale-rs — Production Readiness Audit
> **Audit date:** 2026-05-24 | **Scope:** All 28 crates | **Target:** Xi'An production deployment
>
> **Methodology:** Grep sweep for TODOs/FIXMEs/HACKs/panics/unsafe; test coverage enumeration; subsystem deep-read.

---

## Executive Summary

**Overall readiness:** Alpha → Beta transition. The consensus core is heavily tested (~100 BFT unit tests + ~70 simulation tests) and architecturally sound. Three production-critical issues block Beta: storage panics, missing slashing proofs, and incomplete storage indexes. The path to production is clear and sequenced below.

| Layer | Readiness | Critical Issues | Tests |
|-------|-----------|----------------|-------|
| **BFT Consensus** | 🟡 Beta-ready | 1 TODO (slashing) | ~97 unit tests |
| **Execution + Engine** | 🟢 Beta-ready | — | Extensive |
| **Node + IoLoop** | 🟢 Beta-ready | 1 TODO (epoch events) | ~45 unit tests |
| **Simulation** | 🟢 Beta-ready | 1 TODO (sync hardening) | ~70 tests |
| **Network (libp2p)** | 🟡 Needs review | Configuration hardening | — |
| **Storage (RocksDB)** | 🔴 Blocks Beta | **3 panics in production paths** | Unit tested |
| **Cross-Shard** | 🟡 Beta-ready | Integration hardening | Livelock + backpressure tests |
| **Production Runner** | 🟡 Beta-ready | 1 panic (genesis) | — |
| **Cryptography** | 🟢 Beta-ready | 1 unsafe (well-documented FFI) | — |

**Legend:** 🔴 = blocks next phase | 🟡 = must address before GA | 🟢 = acceptable for Beta

---

## Phase 0: Crash Barriers (blocks Beta — must fix first)

These are panics in production code paths. A validator hitting these would crash, not recover.

### P0.1 — RocksDB Iterator Panics
**File:** `crates/storage-rocksdb/src/typed_cf.rs:355, 392`
**Severity:** 🔴 CRITICAL
```
panic!("BFT CRITICAL: RocksDB iterator error: {e}");
```
**Problem:** Two iterator implementations panic on RocksDB read errors instead of propagating them. A disk error or corrupted SST file will crash the validator.
**Fix:** Convert to `Result` return types. The caller (IoLoop) can then decide: retry, skip, or graceful shutdown.
**Effort:** Medium (API change across `typed_cf.rs`)

### P0.2 — Genesis Failure Panic
**File:** `crates/production/src/runner.rs:650`
**Severity:** 🔴 CRITICAL
```
panic!("Radix Engine genesis failed: {e:?}");
```
**Problem:** If the Radix Engine fails during genesis bootstrap (e.g., invalid genesis config, engine version mismatch), the validator panics at startup.
**Fix:** Return a `RunnerError` variant. The main binary should log the error and exit with a non-zero code — not panic.
**Effort:** Small (one `panic!` → `return Err(...)`)

### P0.3 — Missing Column Family Panic
**File:** `crates/storage-rocksdb/src/column_families.rs:113`
**Severity:** 🟡 HIGH
```
.unwrap_or_else(|| panic!("column family '{name}' must exist"))
```
**Problem:** If a RocksDB instance is opened without the expected column families (e.g., wrong configuration, corrupted MANIFEST), the validator panics.
**Fix:** Return a `StorageError::MissingColumnFamily` variant. The startup logic can then attempt recovery or refuse to start.
**Effort:** Small

---

## Phase 1: Safety Hardening (must complete before GA)

### P1.1 — Slashing Proof Collection
**File:** `crates/bft/src/state.rs:2450`
**Severity:** 🟡 HIGH
```
// TODO: Collect both conflicting votes as slashing proof for economic penalties.
```
**Problem:** Equivocation is detected but not preserved. Without slashing proofs, Byzantine validators face no economic penalty for double-voting.
**Fix:** Store conflicting vote pairs in a `SlashingStore` trait (backed by RocksDB CF). Emit `Action::ReportEquivocation` for the network layer to gossip.
**Effort:** Medium (new storage CF + gossip message type)

### P1.2 — Transaction Index Lookups
**File:** `crates/storage-rocksdb/src/chain_reader.rs:58, 63`
**Severity:** 🟡 HIGH
```
// TODO: populate and read a `tx_to_wave` CF at block commit time.
// TODO: populate and read a `tx_to_ec` CF at block commit time.
```
**Problem:** Two `ChainReader` methods return `None` unconditionally. This means:
- Transaction status queries can't find wave certificates
- Execution certificate lookups are broken
- RPC `tx_status` endpoints will never return post-commit state
**Fix:** Implement the RocksDB column families. At block commit time, write the tx→wave and tx→EC mappings. Add tests verifying round-trip.
**Effort:** Medium (new CFs + commit-time writes)

### P1.3 — Epoch Transition Events
**File:** `crates/node/src/state.rs:756`
**Severity:** 🟡 MEDIUM
```
// TODO(epoch): After transition_to_next_epoch() / mark_shard_splitting() /
// clear_shard_splitting() mutates self.topology, emit
// Action::TopologyChanged { topology: Arc::clone(self.topology.snapshot()) }
```
**Problem:** When the topology changes (epoch transition, shard split), no event is emitted. Other subsystems won't know the validator set or shard assignments changed.
**Fix:** Emit `Action::TopologyChanged` after each topology mutation. All consumers (BFT, provisions, network) handle the new snapshot.
**Effort:** Small

---

## Phase 2: Operational Readiness (GA blockers)

### P2.1 — Graceful Shutdown
**Area:** `ProductionRunner` / `IoLoop`
**Current state:** `ShutdownHandle` exists (`production/src/runner.rs:96-119`) but panics in storage (P0.1) could prevent clean shutdown.
**Gap:** No flush-before-shutdown of RocksDB memtables. No drain of in-flight crypto/execution callbacks.
**Fix:** On shutdown signal: (1) stop accepting new RPC requests, (2) drain the event channel, (3) flush RocksDB WAL, (4) close RocksDB, (5) close libp2p connections.
**Effort:** Medium

### P2.2 — Configuration Validation
**Area:** All config structs (`BftConfig`, `NodeConfig`, `Libp2pConfig`, `RocksDbConfig`, `ThreadPoolConfig`)
**Gap:** No validation method on config structs. Invalid combinations (e.g., `view_change_timeout_increment > view_change_timeout_max`, `crypto_threads > available cores`) are not caught until runtime.
**Fix:** Add `validate() -> Result<(), ConfigError>` to each config struct. Call during builder `.build()`. Reject invalid configs at startup.
**Effort:** Small

### P2.3 — Monitoring & Alerting Hooks
**Area:** Metrics facade (`metrics` crate)
**Current state:** Prometheus backend exists (`metrics-prometheus`). Good metric coverage in BFT, mempool, and provisions.
**Gap:** No alert thresholds defined. No health-check endpoint. No liveness probe.
**Fix:** Add `/health` RPC endpoint (returns 200 if state machine is processing events, 503 if stalled). Add metric for `consecutive_view_changes` with a hard-coded warning threshold.
**Effort:** Small

### P2.4 — Backup & Recovery
**Area:** Storage layer
**Gap:** No backup mechanism for RocksDB. No snapshot export. No tool for verifying JMT state root integrity.
**Fix:** At minimum: document how to run `rocksdb-backup` on the data directory. Add a `--verify-state` CLI flag that walks the JMT and confirms the root hash matches.
**Effort:** Medium

---

## Phase 3: Network & Security Hardening

### P3.1 — libp2p Configuration Audit
**Area:** `network-libp2p` crate
**Gap:** No explicit peer scoring, no connection limits per peer, no DoS protection beyond what libp2p provides by default.
**Fix:** Review and configure: (1) `libp2p::identify` agent string to prevent version mismatch connections, (2) connection limits (max 50 peers per validator), (3) gossipsub message validation timeout, (4) QUIC stream limits.
**Effort:** Small (configuration only)

### P3.2 — Unsafe Code Review
**File:** `crates/types/src/crypto.rs:194`
**Severity:** 🟢 LOW (well-documented)
```
unsafe { blst::blst_scalar_from_bendian(&mut scalar, rand_bytes.as_ptr()); }
```
**Assessment:** FFI call to `blst`. Safety invariants documented in comments. 32-byte array from `fill_bytes` — valid. `scalar` zero-initialized — valid. This is the only `unsafe` block in the entire non-test codebase.
**Action:** No change needed. Flag for security audit.

### P3.3 — Message Validation Depth
**Area:** `messages` crate + BFT verification
**Gap:** Block header validation includes signature checks and duplicate detection, but no size limits on transaction payloads, no rate limiting per peer.
**Fix:** Add max message size config (e.g., 16MB block, 1MB transaction). Reject oversized messages before deserialization.
**Effort:** Small

---

## Phase 4: Testing & Simulation Hardening

### P4.1 — Partition Recovery Tests
**File:** `crates/simulation/tests/determinism.rs:2284`
```
// TODO: Once sync mechanisms are enhanced (e.g., via block gossip or
// explicit sync requests), tighten this assertion.
```
**Gap:** Partition tests have a loose assertion because sync isn't fast enough in the simulation window.
**Fix:** After sync enhancement (P4.2), tighten the partition recovery assertion to require all nodes converge to the same height within N blocks.
**Effort:** Small (remove TODO, tighten assertion)

### P4.2 — Sync Protocol Hardening (from Phase 0-1 fixes)
**Dependency:** P1.2 (transaction index lookups)
**Gap:** Syncing validators rely on block headers and QC verification but don't have guaranteed access to historical transaction data.
**Fix:** After P1.2 implements tx→wave/EC indexes, add sync test that verifies a late-joining validator can serve all RPC queries for historical transactions.
**Effort:** Medium

### P4.3 — Fuzz Testing Infrastructure
**Gap:** No fuzz targets exist. The deterministic simulator is powerful but doesn't explore random input spaces.
**Fix:** Add `cargo fuzz` targets for: (1) block header deserialization, (2) QC signature aggregation, (3) transaction validation, (4) SBOR message parsing.
**Effort:** Medium

---

## Test Coverage Summary

| Subsystem | Unit Tests | Simulation Tests | Total | Coverage Assessment |
|-----------|-----------|-----------------|-------|-------------------|
| **BFT Consensus** | ~97 | via determinism/e2e | ~97 | **Strong** — linear backoff, vote locking, equivocation, QC formation, recovery all tested |
| **Execution** | Inline in state.rs | via e2e_tests | — | **Adequate** — wave leader rotation, cross-shard tested |
| **Mempool** | ~20 estimated | via e2e | ~20 | **Adequate** — submission, dedup, backpressure integration |
| **Node/IoLoop** | ~45 | implicit | ~45 | **Strong** — all fetch protocols tested (header, cert, provision) |
| **Provisions** | Inline | via backpressure_tests | — | **Adequate** — lifecycle tracking, verification, consistency |
| **Simulation** | N/A | ~68 | 68 | **Strong** — determinism, e2e, livelock, backpressure, throughput |
| **Storage-RocksDB** | Inline | N/A | — | **Weak** — panic paths not covered by error-recovery tests |
| **Network-libp2p** | Minimal | N/A | — | **Gap** — no unit tests for network error handling |
| **Production Runner** | Minimal | N/A | — | **Gap** — no integration tests for crash recovery |
| **Cryptography** | Implicit via consensus | implicit | — | **Adequate** — exercised by all consensus tests |

---

## Xi'An Production Roadmap

```
                    NOW                          BETA                        GA
                    │                             │                          │
Phase 0 ────────────┤                             │                          │
  P0.1 RocksDB panic ████                         │                          │
  P0.2 Genesis panic ██                           │                          │
  P0.3 CF missing     ██                           │                          │
                    │                             │                          │
Phase 1 ────────────┼─────────────────────────────┤                          │
  P1.1 Slashing       ████████████████             │                          │
  P1.2 TX indexes      ████████████████            │                          │
  P1.3 Epoch events     ██                         │                          │
                    │                             │                          │
Phase 2 ────────────┼─────────────────────────────┼──────────────────────────┤
  P2.1 Graceful shutdown  ████████████             │                          │
  P2.2 Config validation   ██                      │                          │
  P2.3 Health endpoint      ██                     │                          │
  P2.4 Backup tooling        ████████              │                          │
                    │                             │                          │
Phase 3 ────────────┼─────────────────────────────┼──────────────────────────┤
  P3.1 libp2p hardening     ██                     │                          │
  P3.2 Unsafe audit (no-op)  █                     │                          │
  P3.3 Message size limits    █                    │                          │
                    │                             │                          │
Phase 4 ────────────┼─────────────────────────────┼──────────────────────────┤
  P4.1 Partition tests       ██                    │                          │
  P4.2 Sync hardening          ██████              │                          │
  P4.3 Fuzz targets               ██████████████████                          │
                    │                             │                          │
────────────────────┼─────────────────────────────┼──────────────────────────┤
MILESTONE           │   ALPHA (current)            │   BETA                    │   GA
                    │   P0 complete                │   P1 + P2 complete        │   All phases
```

**Estimated effort:**

| Phase | Work Days | Parallelizable |
|-------|-----------|---------------|
| Phase 0 | 3-5 days | P0.1 + P0.2 + P0.3 can be done in parallel |
| Phase 1 | 5-8 days | P1.1 + P1.2 can be parallel; P1.3 is small |
| Phase 2 | 5-7 days | P2.2 + P2.3 parallel; P2.1 + P2.4 depend on P0 |
| Phase 3 | 2-3 days | All parallel |
| Phase 4 | 5-10 days | P4.2 depends on P1.2; P4.1 + P4.3 independent |
| **Total** | **20-33 days** | |

---

## Immediate Next Actions

1. **Today:** Fix P0.1 (RocksDB panics) — highest blast radius, touches production path
2. **Today:** Fix P0.2 (genesis panic) — 1-line change, prevents clean startup failure
3. **This week:** Phase 0 complete → tag as `v0.2.0-beta`
4. **Next week:** Begin Phase 1 (slashing + TX indexes) — these are the GA differentiators

The codebase is architecturally sound. The issues found are implementation gaps, not design flaws. The BFT core in particular is battle-tested through simulation — the remaining work is operational hardening.

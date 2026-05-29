# hyperscale-rs — Community Task Board
> Generated from PRODUCTION-AUDIT.md | 2026-05-24
>
> Each task is self-contained, scoped to ~2-4 hours, with clear acceptance criteria.
> Pick any task from Phase 0 to start. No prior knowledge of the full codebase needed.

---

## How to Use This Board

1. Pick a task from the highest incomplete phase
2. Read the linked source file (paths are from repo root)
3. Make the fix, add a test where indicated
4. Run `cargo test` and `cargo clippy` before submitting

**Label meanings:**
- 🟢 **good first issue** — minimal context needed, pure code change
- 🟡 **medium** — requires understanding one subsystem
- 🔴 **large** — touches multiple crates, coordinate with others

---

## Phase 0: Crash Barriers (3 tasks — do these first)

### Task 0.1 — Replace RocksDB Iterator Panics with Errors 🟡
**Priority:** CRITICAL | **Est:** 3-4 hours | **File:** `crates/storage-rocksdb/src/typed_cf.rs:355, 392`

**What:** Two iterator functions (`iter_to_typed`, `bounded_iter_to_typed`) call `panic!` when RocksDB returns an error. Change them to return `Result`.

**Steps:**
1. Change the return type of both `from_fn` closures to yield `Result<Item, StorageError>`
2. Replace `panic!("BFT CRITICAL: ...")` with `return Some(Err(StorageError::IteratorError(e)))`
3. Update all callers to handle the `Result` — propagate up or log-and-skip
4. Add a unit test that injects a RocksDB error and verifies it doesn't panic

**Acceptance:** No panics in the storage read path. A corrupted SST file causes an error log, not a crash.

---

### Task 0.2 — Genesis Failure: Panic → Error 🟢
**Priority:** CRITICAL | **Est:** 1 hour | **File:** `crates/production/src/runner.rs:650`

**What:** `panic!("Radix Engine genesis failed")`. Change to return a `RunnerError`.

**Steps:**
1. Replace `panic!(...)` with `return Err(RunnerError::GenesisError(e))`
2. Add the `GenesisError` variant to the `RunnerError` enum
3. In the calling code, log the error and exit with code 1

**Acceptance:** Running with a broken genesis config prints an error message and exits cleanly — no panic backtrace.

---

### Task 0.3 — Missing Column Family: Panic → Error 🟢
**Priority:** HIGH | **Est:** 1 hour | **File:** `crates/storage-rocksdb/src/column_families.rs:113`

**What:** `.unwrap_or_else(|| panic!(...))` on missing column family. Return a `StorageError`.

**Steps:**
1. Add `StorageError::MissingColumnFamily { name: String }` variant
2. Replace the `panic!` with `return Err(StorageError::MissingColumnFamily { name: name.to_string() })`
3. In the caller, attempt auto-repair or refuse startup with a clear message

**Acceptance:** Opening a RocksDB with missing CFs fails gracefully with a descriptive error.

---

## Phase 1: Safety Hardening (3 tasks)

### Task 1.1 — Implement Slashing Proof Collection 🟡
**Priority:** HIGH | **Est:** 4-5 hours | **File:** `crates/bft/src/state.rs:2450`

**What:** The TODO at line 2450 asks for storing conflicting votes as slashing evidence. Equivocation is detected but the proof is discarded.

**Steps:**
1. Define a `SlashingStore` trait in `crates/storage/` with `store_equivocation_proof(height, vote_a, vote_b)`
2. Implement it for RocksDB (new column family) and in-memory storage
3. In the equivocation detection block (`state.rs:2444-`), after detecting a conflict, call the store
4. Emit `Action::ReportEquivocation { height, votes }` for gossip
5. Add a simulation test: one Byzantine node double-votes, verify the proof is available via storage

**Acceptance:** A double-voting validator produces a slashing proof retrievable from storage. The proof is gossiped to peers.

---

### Task 1.2 — Implement Transaction Index Column Families 🟡
**Priority:** HIGH | **Est:** 4-5 hours | **Files:** `crates/storage-rocksdb/src/chain_reader.rs:58,63`

**What:** Two `ChainReader` methods return `None` unconditionally. Transaction status lookups and execution certificate queries are broken.

**Steps:**
1. Add `tx_to_wave` and `tx_to_ec` RocksDB column families
2. At block commit time (in `ChainWriter`), write the mapping: `tx_hash → (shard, wave_id)` and `tx_hash → Vec<(shard, ec_hash)>`
3. Implement the read side in `chain_reader.rs`
4. Add a test: submit a TX, wait for commit, query the index, verify the wave and EC are found

**Acceptance:** After a transaction commits, `get_wave_certificate_for_tx()` and `get_ec_hashes_for_tx()` return the correct data.

---

### Task 1.3 — Emit Topology Change Events 🟢
**Priority:** MEDIUM | **Est:** 1-2 hours | **File:** `crates/node/src/state.rs:756`

**What:** Epoch transitions mutate topology but don't notify other subsystems.

**Steps:**
1. Add `Action::TopologyChanged { topology: Arc<TopologySnapshot> }` to the Action enum
2. After each topology mutation (epoch transition, shard split, shard clear), emit this action
3. In IoLoop, handle `TopologyChanged` by updating the shared snapshot and notifying BFT + provisions

**Acceptance:** After an epoch transition, all node subsystems see the new validator set and shard assignments.

---

## Phase 2: Operational Readiness (4 tasks)

### Task 2.1 — Graceful Shutdown Sequence 🟡
**Priority:** HIGH | **Est:** 3-4 hours | **Files:** `crates/production/src/runner.rs`, `event_loop.rs`

**What:** Shutdown mechanism exists but doesn't flush storage or drain in-flight operations.

**Steps:**
1. On shutdown signal: stop accepting RPC requests
2. Drain the event channel until empty (process remaining events)
3. Flush RocksDB WAL (`db.flush_wal(true)`)
4. Close RocksDB (`drop(storage)`)
5. Close libp2p connections
6. Add an integration test: start validator, send shutdown, verify clean exit with no data loss

**Acceptance:** The validator shuts down cleanly. Restarting recovers the correct committed state.

---

### Task 2.2 — Configuration Validation 🟢
**Priority:** MEDIUM | **Est:** 2 hours | **Files:** All `*config.rs` files

**What:** No config validation. Invalid combinations are caught at runtime.

**Steps:**
1. Add `validate(&self) -> Result<(), ConfigError>` to: `BftConfig`, `Libp2pConfig`, `RocksDbConfig`, `ThreadPoolConfig`
2. Basic checks: timeouts are positive, backoff increment ≤ backoff max, thread counts ≤ available cores, ports are valid
3. Call `validate()` in each `Builder::build()`
4. Add tests for invalid configs being rejected

**Acceptance:** The validator refuses to start with an invalid config, printing a descriptive error.

---

### Task 2.3 — Health Check Endpoint 🟢
**Priority:** MEDIUM | **Est:** 1-2 hours | **File:** `crates/production/src/rpc/`

**What:** No liveness probe endpoint for orchestration (Kubernetes, systemd).

**Steps:**
1. Add `GET /health` to the RPC server
2. Returns 200 if: event loop is processing (last event < 30s ago), storage is accessible
3. Returns 503 if: stalled (no events processed for >30s), storage error
4. Add `consecutive_view_changes` metric to Prometheus with a warning at >5 consecutive changes

**Acceptance:** `curl localhost:8080/health` returns `{"status":"ok"}` or `{"status":"stalled"}`.

---

### Task 2.4 — Storage Backup Documentation & Verification 🟡
**Priority:** MEDIUM | **Est:** 2-3 hours | **Files:** `crates/storage-rocksdb/`, docs

**What:** No backup tooling or state verification.

**Steps:**
1. Document how to run RocksDB backup: `rocksdb-backup --db-path /data/validator --backup-path /backups/`
2. Add a `--verify-state` CLI flag that: reads the JMT root from the latest committed block, walks the tree, confirms hash matches
3. If mismatch, print the path where the corruption is
4. Add this to the validator binary help text

**Acceptance:** A `--verify-state` run confirms integrity or reports the corrupted path.

---

## Phase 3: Network Hardening (3 tasks)

### Task 3.1 — libp2p Connection Limits 🟢
**Priority:** MEDIUM | **Est:** 1-2 hours | **File:** `crates/network-libp2p/src/`

**What:** No explicit peer limits. A flood of connections could exhaust resources.

**Steps:**
1. Add config: `max_peers: usize` (default 50), `max_connections_per_peer: usize` (default 3)
2. Configure the libp2p swarm to enforce these limits
3. Add `identify` agent string: `hyperscale/0.2.0` (prevent version mismatch)
4. Document the configuration in README

**Acceptance:** A validator rejects connections beyond the configured limits.

---

### Task 3.2 — Message Size Limits 🟢
**Priority:** LOW | **Est:** 1 hour | **Files:** `crates/messages/`, `crates/network/`

**What:** No size limits on incoming messages. A malicious peer could send oversized blocks.

**Steps:**
1. Add config: `max_block_size_bytes: usize` (default 16MB), `max_transaction_size_bytes: usize` (default 1MB)
2. In the network message handler, reject oversized messages before deserialization
3. Log and increment a `rejected_oversized_messages` metric

**Acceptance:** Blocks >16MB or transactions >1MB are rejected at the network layer.

---

### Task 3.3 — Unsafe Code Audit Documentation 🟢
**Priority:** LOW | **Est:** 30 min | **File:** `crates/types/src/crypto.rs:194`

**What:** One `unsafe` block. Document it for auditors.

**Steps:**
1. Verify the safety invariants in the existing comment (lines 191-193)
2. Add a `// SAFETY:` block documenting: pointer validity, buffer size guarantees, zero-initialization
3. No code change needed — this is documentation only

**Acceptance:** The unsafe block has a complete SAFETY comment suitable for a security audit.

---

## Phase 4: Testing Hardening (3 tasks)

### Task 4.1 — Tighten Partition Recovery Assertion 🟢
**Priority:** MEDIUM | **Est:** 1-2 hours | **File:** `crates/simulation/tests/determinism.rs:2284`

**What:** TODO at line 2284. Partition test has a loose assertion.

**Steps:**
1. After Phases 0-1 are complete (sync/index fixes), remove the TODO
2. Change the assertion to require all nodes to converge to the same committed height within N blocks after the partition heals
3. Run the test 100 times with different seeds to verify determinism

**Acceptance:** Partition recovery test passes with a strict convergence requirement.

---

### Task 4.2 — Late-Joiner Sync Test 🟡
**Priority:** MEDIUM | **Est:** 3-4 hours | **Dependency:** Task 1.2 | **File:** `crates/simulation/tests/`

**What:** No test for a validator that joins after blocks have already committed.

**Steps:**
1. Start a 4-validator simulation, commit 50 blocks
2. Add a 5th validator that missed the first 50 blocks
3. Verify it syncs to the same committed height
4. Verify it can serve RPC queries for historical transactions (depends on Task 1.2)

**Acceptance:** A late-joining validator catches up and serves correct historical data.

---

### Task 4.3 — Add Cargo-Fuzz Targets 🔴
**Priority:** LOW | **Est:** 5-8 hours | **Files:** `fuzz/` (new directory)

**What:** No fuzz testing. The simulator is deterministic but doesn't explore random inputs.

**Steps:**
1. Set up `cargo fuzz` in the workspace
2. Add fuzz targets for: block header deserialization, QC signature aggregation, transaction validation, SBOR message parsing
3. Run each target for 1M+ iterations
4. Fix any crashes found

**Acceptance:** 4 fuzz targets pass 1M iterations without crashes.

---

## Quick Reference: Task Dependencies

```
P0.1 ──┬── P2.1 (graceful shutdown needs P0.1)
       ├── P2.4 (backup verification needs P0.1)
       │
P0.2 ── (independent)
P0.3 ── (independent)
       │
P1.1 ── (independent) 
P1.2 ──┬── P4.2 (sync test needs TX indexes)
       │
P1.3 ── (independent)
       │
P2.1 ── (depends on P0.1)
P2.2 ── (independent)
P2.3 ── (independent)
P2.4 ── (depends on P0.1)
       │
P3.1 ── (independent)
P3.2 ── (independent)
P3.3 ── (independent)
       │
P4.1 ── (depends on P1+P2 completion)
P4.2 ── (depends on P1.2)
P4.3 ── (independent)
```

**Parallel sprint capacity:**
- Sprint 1 (Week 1): P0.1 + P0.2 + P0.3 + P2.2 + P2.3 + P3.1 + P3.2 + P3.3 = 8 independent tasks
- Sprint 2 (Week 2): P1.1 + P1.2 + P1.3 + P2.1 + P2.4 = 5 tasks
- Sprint 3 (Week 3): P4.1 + P4.2 + P4.3 = 3 tasks

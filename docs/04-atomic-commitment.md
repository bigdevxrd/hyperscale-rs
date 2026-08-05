# Atomic cross-shard commitment

This document covers the machinery that gives Hyperscale single-chain semantics across shards: a transaction touching state on several shards commits atomically — the same terminal outcome, on every participating shard, with BFT finality — or aborts everywhere. The protocol is a deterministic **provision–execute–certify** pipeline built from three ingredients: **declared state access** (the transaction says up front what it touches), **provisions** (QC-attested state transfer between shards), and **execution certificates** (per-shard quorum agreement on a shared outcome vector, described in [01-consensus-layers.md](01-consensus-layers.md) §2).

**If you know two-phase commit, read this first.** The family resemblance is real — ordering a transaction under locks plays the role prepare plays classically — but the three defining features of 2PC are all absent. There is **no coordinator**: the protocol is symmetric across shards, so the coordinator-failure blocking problem that defines textbook 2PC has no analogue. There are **no votes on the outcome**: in 2PC the result is genuinely open until participants' votes are tallied, whereas here it is a deterministic function of committed chain content — which transactions ordered, which provisions landed by the attested deadline, which conflicts resolved which way. Execution certificates *attest* an outcome every honest replica already computed rather than *choosing* one. (The closer lineage is deterministic databases, where determinism replaces commit-time agreement, not distributed transactions.) And **participants don't fail in the 2PC sense**: each "participant" is a BFT-replicated committee, and even a participant shard ceasing to exist mid-flight — a case classical 2PC has no answer for — resolves deterministically through the settled-set fence ([02-dynamic-sharding.md](02-dynamic-sharding.md) §4).

Main code homes: `crates/mempool` (admission, ready set), `crates/provisions` (provision coordination and DA), `crates/execution` (waves, conflict detection, vote aggregation), `crates/engine-vm` (the effect-typed engine and its fee rules), `crates/engine` (the Radix Engine integration it replaces), with the wire types in `crates/types` (`Provisions`, `ProvisionEntry`, `ExecutionCertificate`, `WaveCertificate`, `FinalizedWave`).

The pipeline is engine-agnostic and this document describes it as such. Where the two engines differ the difference is named: the Radix Engine resolves ownership at execution time and needs a map transferred with every provision (§5), while the effect-typed engine's substate keys carry their owner's prefix, so nothing about placement has to be transferred, claimed, or arbitrated.

---

## 1. Declared access and the mempool

Every transaction declares the set of global nodes (accounts and other global engine objects) it reads and writes. Declaration is the foundation of everything downstream: it determines routing (which shards participate — the shards owning the declared nodes, via the shard trie), it bounds execution (writes outside the declared/derived set are deterministically dropped), and it enables conflict analysis without executing.

The mempool (`MempoolCoordinator`) admits transactions into a hash-ordered pool with process-level dedup caches shared across co-hosted vnodes (`CanonicalTxs` — one signature/SBOR validation per transaction per process; `TxStatusCache` — one status truth for RPC). Terminal-state tombstones prevent re-admission of finished transactions.

**The ready set is the livelock firewall.** `ReadySet::add` enforces **partial coupling**: no two transactions that are simultaneously in flight (committed and holding locks) or ready (eligible for proposal) may share *any* declared node (INV-EXEC-3). A transaction whose declared nodes overlap a lock or another ready transaction is deferred, indexed by the blocking node, and promoted the moment the node frees. Locks are held from commit until the transaction's wave finalizes, and cross-shard transactions extend their locks over all provisioning dependencies. Consequences:

- Two local transactions can never deadlock — they are never in flight together if they could contend.
- Proposal selection is deterministic (hash-ordered iteration up to the block budget — a transaction count, with a gas budget planned), so all replicas agree on eligibility reasoning.
- The invariant is deliberately a *superset* of the minimum needed for cross-shard coupling safety, which structurally defuses gaming strategies that exploit partially-coupled scheduling.

An in-flight cap (`MAX_TX_IN_FLIGHT`) bounds the total lock-holding population, providing backpressure.

**Authorization is admission's business.** A VM manifest node names its target by address, and an address is public — naming one is evidence of nothing. Each method a package publishes declares whether reaching it requires the target's own authority: `deposit` does not, because being paid is not a decision the recipient makes, while `withdraw` and the entropy stamp do, because spending an account's funds and writing its leaves are. A gated node is well-formed only inside an intent its target signed — the composer's account for a root-intent node, the declared signer's for a subintent node — so moving a second party's funds takes a subintent that party signed, and an ordinary transfer still settles under the sender's single signature (INV-VM-12). The verdict reads only signed content and content-addressed package metadata, never state, so it sits beside the rest of derivation, ahead of ordering and ahead of any fee exposure: an envelope that fails it never enters a block and nobody pays for it. Accessibility is a declaration the package makes about its own methods, carried in the metadata section its content address covers, so no transaction can weaken it and every shard reads the same one.

## 2. Provision: proven state transfer

When a source shard commits a block containing cross-shard transactions, its proposer broadcasts **`Provisions`** to each destination shard — one bundle per (source block, destination shard):

- Per transaction: the substate values the destination needs (`entries`, canonically sorted), the nodes the transaction needs *from* the destination (`target_nodes`, for conflict detection), and — for a Radix transaction only — the source's ownership map for its declared accounts (`owned_nodes`: internal object → owning account, see §5).
- A JMT merkle **multiproof** over all carried substates against the source block's state root.

A VM transaction's bundle carries the **read set and nothing else**: fresh reads, and the prior values of read-modify-write keys. A blind write provisions nothing because the destination never needs what it is about to overwrite; an increment provisions nothing because it never reads the value it adds to; a reservation's feasibility is judged where the reserved substate lives. A leg whose dependency set is empty dispatches immediately rather than waiting on a bundle that would carry no state.

An empty bundle is still emitted, and that is a second job the same wire edge does. A counterpart engages a cross-shard VM transaction only against evidence that the shard paying its fee committed it, and that evidence is exactly the payer's bundle bound to its source block through the header's `provision_tx_roots`, consumable only against a commit-proven header (INV-VM-9). Every other participant echoes its own commitment back to the payer the same way, which is what lets the payer's single vote be a pure function of its own chain (INV-VM-11).

Verification at the destination is two-stage and entirely artifact-based. The source block's header is already held and QC-verified via remote-header sync ([03-state-and-sync.md](03-state-and-sync.md) §6), so verifying a provision bundle means one QC check per source block plus merkle verification of every entry against the attested state root. A provision is a *proof about a committed remote block* — no node in the source shard is trusted, only its quorum (INV-EXEC-10). Verified provisions are persisted and flow into wave assembly.

**The header also pre-announces.** Source block headers carry `provision_targets` (which shards this block provisions) and per-destination `provision_tx_roots`, so destinations know what to expect and can detect absence — absence of data, unlike presence, needs an announcement to be actionable.

## 3. Execute and certify: outcome agreement by determinism

At the destination (and symmetrically on every participant), committed cross-shard transactions group into **waves** keyed by their provisioning dependency set. A wave dispatches when fully provisioned; execution merges local snapshot state with the provisioned remote entries and runs the Radix Engine once per transaction, atomically for the wave.

Determinism across shards is engineered, not assumed:

- **Same inputs.** All participants execute from the same declared set, the same provisioned entries (QC-attested), and — under the Radix engine — the same merged ownership map (§5). Both engines take the same per-transaction environment: the clock and the randomness draw are anchored on the payer shard's committing block, locally available there and riding the payer's bundle everywhere else, so one transaction executes under one environment on every participant.
- **Same engine, same outputs.** The engine's output is projected to a shard-invariant form (`CachedVmOutput`): the receipt hash, application events, and outcome are identical everywhere; only the *database updates* are then filtered per shard (each shard persists writes for the nodes it owns). All failures collapse to one canonical failed-receipt hash.
- **Same filtering.** Writes to undeclared/underived nodes are dropped by rule, so engine-internal nondeterminism cannot leak into committed state (INV-EXEC-9).

Validators vote on the wave's `global_receipt_root`; 2f+1 matching votes form the shard's **ExecutionCertificate** with the explicit per-transaction outcome vector, each success outcome carrying its transaction's receipt hash. A wave finalizes per transaction, from the ECs collected local and remote: a transaction succeeds only with a success outcome from **every** participating shard, and an abort outcome from any shard is terminal. Abort is dominant; success is unanimous. Every EC binds its root to its outcome vector (recompute-on-decode, INV-EXEC-2), and deterministic execution means honest quorums attest identical per-transaction receipt hashes, so divergent success content cannot arise within the committee-honesty premise. Atomic commitment is enforced by the unanimity rule over attested outcomes (INV-EXEC-1). The `FinalizedWave` (certificate plus attested local receipts) then rides in a subsequent block, locks release, and the transaction is terminal.

## 4. Aborts: deterministic, total, timely

Every path to abort is a pure function of committed chain state, so all replicas — and all shards — reach the same verdict:

- **Conflict detection** (`ConflictDetector`). A true cross-shard deadlock requires bidirectional overlap: a remote transaction's source entries overlap what a local transaction needs from that shard *and* the remote's targets overlap what the local one owns locally. Conflicts are detected on provision commit (forward) and on local registration (reverse), and resolved by deterministic tiebreak — the lower transaction hash wins, and the loser aborts before executing. Both shards derive identical conflicts from identical committed inputs (INV-EXEC-4).
- **Wave deadline.** Every wave carries a deadline anchored on BFT-attested time (source-block weighted timestamp plus `WAVE_TIMEOUT`). A wave not fully provisioned by its deadline **all-aborts**: every transaction in it aborts, on every participant, regardless of which provisions did arrive (INV-EXEC-5). This is the liveness backstop that guarantees termination even under permanent provision loss — and because the deadline derives from attested time, no two replicas disagree about whether it passed.
- **Payer deadline.** The unprovisioned-wave deadline is unreachable for one shape: a VM payer whose own leg has no dependencies dispatches at birth, executes at commit, and has no second statement to make. Its backstop is the other side of the same evidence rule — past its transaction's signed validity window without every counterpart's engagement echo committed on its own chain, the payer's single vote is the all-abort carrying the fee record (INV-VM-11). Both vote conditions read only the payer's chain, so its committee cannot split into vote buckets, and a counterpart engaging at the window's edge resolves through abort dominance rather than as a verdict split.
- **Reshape-boundary aborts.** When a participating shard terminates in a split/merge, the settled-set fence and counterpart sweep decide every straddler from frozen chain content ([02-dynamic-sharding.md](02-dynamic-sharding.md) §4).

Abort is a first-class terminal outcome inside the EC's outcome vector — an aborted cross-shard transaction is *agreed aborted* with the same finality as a success.

## 5. Ownership: a seam the key format closes

Radix Engine internal objects (vaults, KV stores) carry no structural pointer to their owner, and their NodeIds don't reveal their shard. Ownership is resolved by walking declared accounts' substates for SBOR `Own(..)` references (`resolve_owned_nodes`), yielding the vault-to-account map that owner-prefixed keying ([03-state-and-sync.md](03-state-and-sync.md) §2) and update filtering depend on. For cross-shard execution each participant merges that resolution with each remote shard's `owned_nodes` claims (`build_cross_shard_ownership`), and a vault claimed by both sides deterministically aborts the transaction: healthy state holds one owner per vault, so a contested claim is bogus input, and aborting on a verdict both shards derive from identical bytes keeps them in agreement rather than risking shard-divergent write placement (INV-EXEC-6).

That whole apparatus is a consequence of resolving ownership at execution time, which the effect-typed engine does not do. A VM substate key **is** its placement: the owner's prefix is the leading half of the key, so which shard owns a cell is a property of the cell's name rather than a claim to be transferred, merged, or contested. Remote-owned keys reach a participant only through provisions and local keys only through its own snapshot, so there is no precedence rule to arbitrate and no contested-claim abort to reach. The merge, the map, and the invariant that governs them are Radix-only and retire with the engine.

The map's attestation goes with it, and that is the part worth stating plainly. A provision's substate entries are proven into the QC-attested state root, but an `owned_nodes` map is attested only through the per-transaction roots at transaction-hash granularity — a bounded window in which a Byzantine source committee member's ownership claims reach a destination's execution, contained to liveness because both shards apply identical merge rules to identical bytes. No traffic reaches that window: the Radix path carries the beacon's system-action channel and nothing else, and a system action is single-shard. Closing a trust seam by making the claim unnecessary beats attesting it, and it is the key format rather than any protocol machinery that does so.

## 6. Data availability

The DA design principle: **the artifact you need is either held by someone obligated to serve it, or provably expired.** Every retention decision keys on BFT-attested weighted time, so eviction is a consensus-consistent fact, not a local heuristic (INV-EXEC-7).

- **Outbound provisions** (`OutboundProvisionTracker`): a source shard retains what it broadcast until the destination's EC covers every transaction in the batch (a positive, quorum-signed acknowledgment) or the attested deadline passes. Until then, any destination node can fetch from any source node.
- **Serving fallback**: provision requests are answerable from committed storage — RocksDB plus historical JMT reads — bounded by the JMT retention window, so even a source node that restarted can serve.
- **Expected-transaction backfill** (`ExpectedTxs`): a destination that learns (from provisions) of transactions it never received by gossip fetches them from the source committee after a grace period, and abandons past the retention horizon.
- **Expected provisions**: symmetric tracking on the destination side, with fetch fallback when the gossip path fails.
- **Execution dedup** (`ProcessExecutionCache`): one VM execution per transaction per process, shared across co-hosted vnodes and shards, evicted only when every hosted participant has finalized — so a cached result can never disagree with a certificate a hosted shard later admits.
- **Voting-time DA**: independent of all of the above, a validator votes only holding full block content, so every QC certifies 2f+1 complete copies of everything the block carries ([01-consensus-layers.md](01-consensus-layers.md) §1.2).

Fetch-path plumbing (unified `IdFetch` protocols, abandon-on-terminal notifications, class-based network prioritization so bulk DA traffic cannot starve consensus) is covered in [05-byzantine-safety.md](05-byzantine-safety.md) §6 and [07-determinism-and-testing.md](07-determinism-and-testing.md).

## 7. End-to-end walkthrough

A transaction declaring accounts on shards A and B:

1. **Admission.** Both shards admit it (routing by declared nodes); each shard's ready set holds it until no declared node is contended locally.
2. **Ordering.** A and B each commit it in a block, independently — there is no cross-shard coordination in consensus itself. Locks engage on both sides.
3. **Provisioning.** A's proposer sends B a proven bundle of A's declared substates (and vice versa). Each side verifies against the other's QC-attested header.
4. **Execution.** Both sides now hold identical merged inputs; both execute; both compute the same receipts and the same `global_receipt_root`.
5. **Certification.** A's committee quorum-signs EC_A; B's signs EC_B; the certificates cross by gossip/fetch.
6. **Finalization.** Each side assembles the wave certificate {EC_A, EC_B}, checks root equality, finalizes the wave into a later block, releases locks. The transaction is terminal — identically — on both shards.

Any deviation lands in an abort path whose verdict both sides compute identically: conflict tiebreak (step 2-3), wave deadline (step 3-4 stall), or — if one shard terminates in a reshape — the settled-set fence.

## 8. Properties

The atomic-commitment invariants this document motivates — INV-EXEC-1 through INV-EXEC-10, and the VM's target-authority rule INV-VM-12 — are stated precisely in [08-invariants.md](08-invariants.md).

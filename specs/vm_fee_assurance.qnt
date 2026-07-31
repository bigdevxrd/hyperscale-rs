// Model J (register: specs/README.md) — VM cross-shard fee assurance:
// payer-first commitment with the max_fee reservation as block validity,
// commit-proof-gated counterpart engagement, the validity-window deadline
// abort with floor settlement, and the successor sweep under payer-shard
// termination. Checked for INV-VM-9 (no counterpart engages without an
// engaged reservation) and INV-VM-10 (every engaged reservation resolves
// exactly once, burn classes by verdict, conservation).
//
// Shard P is the payer's (fee_payer's prefix routes there); shard Q is a
// non-payer counterpart. One cross-shard VM transaction whose legs are
// commutative (D23: empty dependency sets), so the payer's bundle carries
// transaction hashes and no state — it exists because it is the
// engagement evidence, not because state needs provisioning.
//
// Model C (atomic_commitment.qnt) supplies the EC-exchange shape: shard
// consensus is an oracle, committees are honest (INV-SEC-1), emitted ECs
// deliver asynchronously, success finalization needs unanimous coverage.
// The fee layer this model adds on top:
//   - P's block commits the transaction only if the payer's balance
//     covers max_fee; commitment engages the reservation (held, not
//     spent).
//   - Q engages — its commit of the transaction, which in the
//     implementation is proposal inclusion, lock acquisition, and the
//     deadline clock starting — only holding the commit proof.
//   - Engagement is barred outside the transaction's validity window on
//     Q's attested clock; a window that closed on Q's chain without
//     inclusion is a frozen fact P can consume (the barred signal — in
//     the implementation, Q's remote header stream past the window with
//     the transaction absent).
//   - Resolution at P: success burns ACTUAL and releases the surplus;
//     any abort burns FLOOR and releases the remainder; the deadline
//     abort fires only on the barred fact, after which no honest Q can
//     ever emit an EC, so no success finalization is forgone.
//   - P terminating mid-flight (reshape) stamps abort-by-omission for an
//     unfinalized wave (Model D's rule) and the successor sweep resolves
//     the reservation it inherited; the sweep is modeled atomic with the
//     terminal stamp.
//
// Code anchors (intended seams — this model precedes the implementation;
// anchors firm up as milestone 3 lands):
//   - Reservation as block validity: `validate_block_for_vote`
//     (crates/shard/src/validation.rs) gains the payer-side feasibility
//     check over proposed VM transactions.
//   - Engagement gate: the proposal seam consults the
//     `ProvisioningTracker` (crates/execution/src/provisioning.rs) —
//     the payer's bundle is absorbable only against a commit-proven
//     header (`on_committed_remote_header`,
//     crates/provisions/src/coordinator.rs), so "payer ∈ received"
//     is the commit proof held.
//   - Burn and release: wave finalization at the payer shard; abort
//     floor on the deadline path.
//   - Successor sweep: the straddler counterpart sweep
//     (crates/execution/src/coordinator.rs), extended to resolve
//     inherited reservations.
//
// Modeling assumptions (on top of Model C's):
//   - One transaction, wave = transaction; amounts are integers with
//     FLOOR < ACTUAL < MAX_FEE so the burn classes are distinguishable.
//   - Execution outcomes are honest-success: a user-error abort at Q
//     resolves through the same abort-dominant EC exchange and burns the
//     same floor class, so it adds no new fee behavior.
//   - Atomicity under P's termination is Model D's property (the
//     straddler fence, INV-RESHAPE-5) and is taken as an oracle:
//     invAtomic is scoped to runs where P has not terminated. This model
//     checks only that the reservation resolves under termination.
//   - Liveness is not checked temporally (as in Model C): "terminally
//     settles or releases" is checked as safety at every terminal state,
//     plus the scripted deadline-abort run.
//
// Run:
//   quint typecheck specs/vm_fee_assurance.qnt
//   quint verify --main=fee_ok        --invariant=invAll --max-steps=12 specs/vm_fee_assurance.qnt
//     (the shipped gate: engagement only on commit proof, conservation,
//      resolution at every terminal)
//   quint verify --main=fee_insolvent --invariant=invAllIdle --max-steps=12 specs/vm_fee_assurance.qnt
//     (an insolvent payer commits nowhere and engages nothing)
//   quint test   --main=fee_ok        --match=deadlineFloor specs/vm_fee_assurance.qnt
//     (scripted: the barred window resolves the reservation at the floor)
//   quint verify --main=fee_ungated   --invariant=invEngageGated --max-steps=8 specs/vm_fee_assurance.qnt
//     (pre-D21 twin: an optimistic counterpart engages locks for an
//      insolvent payer that never commits)
//   quint test   --main=fee_certified --match=certifiedAbandon specs/vm_fee_assurance.qnt
//   quint verify --main=fee_certified --invariant=invEngageGated --max-steps=8 specs/vm_fee_assurance.qnt
//     (certified-not-committed twin: the payer's certified block is
//      abandoned on a fork after the counterpart engaged)
//   quint verify --main=fee_unswept   --invariant=invResolvedAtTerminal --max-steps=12 specs/vm_fee_assurance.qnt
//     (no-sweep twin: P terminates holding the reservation forever)

module vm_fee_assurance {
  // Max clock advance per step.
  const MAX_TICK: int
  // The signed fee ceiling the payer's block reserves.
  const MAX_FEE: int
  // The EC-attested actual a success burns. FLOOR < ACTUAL < MAX_FEE.
  const ACTUAL: int
  // The abort-class floor.
  const FLOOR: int
  // The payer's liquid balance at genesis.
  const BALANCE: int
  // The validity window's end on Q's attested clock: engagement is
  // barred strictly after it.
  const WINDOW: int
  // Broken twin: Q engages without the commit proof (the pre-D21
  // optimistic counterpart).
  const ENGAGE_UNGATED: bool
  // Broken twin: the payer's bundle is consumable against a certified
  // header, before the block commit-proves.
  const ENGAGE_ON_CERTIFIED: bool
  // The successor sweep resolves an inherited reservation at P's
  // terminal; the twin drops it.
  const SWEEP_ON_TERMINATION: bool

  pure val P = 1
  pure val Q = 2
  pure val SHARDS = Set(P, Q)
  pure def other(s: int): int = if (s == P) Q else P

  pure val NONE = -1
  pure val SUCC = 1
  pure val ABORT = 2

  // Per-shard attested chain clock (monotone; Model A).
  var clock: int -> int
  // P's proposal carrying the transaction is certified (a QC exists). A
  // certified block can still be abandoned on a fork — that distinction
  // is the whole reason engagement demands commitment.
  var pCert: bool
  // P's certified proposal was abandoned; the transaction never commits
  // at P in this run.
  var pAbandoned: bool
  // Clock value at which each shard committed the transaction (NONE
  // before). At P this is the payer block engaging the reservation; at Q
  // it is engagement — inclusion, locks, deadline clock.
  var committedAt: int -> int
  // Q holds the transaction commit proof: the payer's bundle, verified
  // against a commit-proven header of P's committing block.
  var qHasProof: bool
  // Frozen fact: the validity window closed on Q's chain without the
  // transaction — no honest Q committee can ever engage it now.
  var qBarred: bool
  // P has consumed the barred fact (delivered asynchronously — in the
  // implementation, by following Q's committed headers past the window).
  var pSeesBarred: bool
  // ECs each shard's committee emitted (honest: at most one, SUCC here —
  // abort classes enter via the deadline and termination paths).
  var emitted: int -> Set[int]
  // First-wins EC admission rows, as Model C.
  var admitted: int -> (int -> int)
  // Terminal verdict per shard.
  var terminal: int -> int
  // P has reached its reshape terminal block; its chain is frozen.
  var pTerminal: bool
  // The payer's fee accounting: liquid balance, held reservation,
  // cumulative burn. INV-VM-10's conserved quantities.
  var balance: int
  var held: int
  var burned: int

  action init = all {
    clock' = SHARDS.mapBy(s => 0),
    pCert' = false,
    pAbandoned' = false,
    committedAt' = SHARDS.mapBy(s => NONE),
    qHasProof' = false,
    qBarred' = false,
    pSeesBarred' = false,
    emitted' = SHARDS.mapBy(s => Set()),
    admitted' = SHARDS.mapBy(dst => SHARDS.mapBy(src => NONE)),
    terminal' = SHARDS.mapBy(s => NONE),
    pTerminal' = false,
    balance' = BALANCE,
    held' = 0,
    burned' = 0,
  }

  // Frame groups: every action updates some groups and frames the rest
  // explicitly (Quint actions assign every variable).
  action frameClock = clock' = clock
  action frameCert = all { pCert' = pCert, pAbandoned' = pAbandoned }
  action frameCommitted = committedAt' = committedAt
  action frameSignals = all {
    qHasProof' = qHasProof, qBarred' = qBarred, pSeesBarred' = pSeesBarred,
  }
  action frameEc = all { emitted' = emitted, admitted' = admitted }
  action frameTerm = all { terminal' = terminal, pTerminal' = pTerminal }
  action frameFees = all { balance' = balance, held' = held, burned' = burned }

  action tick = {
    nondet s = SHARDS.oneOf()
    nondet d = 1.to(MAX_TICK).oneOf()
    all {
      // A terminated P's chain is frozen; its clock no longer attests.
      s == Q or not(pTerminal),
      clock' = clock.setBy(s, c => c + d),
      frameCert, frameCommitted, frameSignals, frameEc, frameTerm, frameFees,
    }
  }

  // P's proposal carrying the transaction certifies. Block validity
  // (validate_block_for_vote's payer-side check) already held at
  // proposal: an insolvent payer's transaction is never in a valid
  // block, so certification itself requires the balance to cover the
  // reservation.
  action pCertify = all {
    not(pCert),
    not(pTerminal),
    balance >= MAX_FEE,
    pCert' = true,
    pAbandoned' = pAbandoned,
    frameClock, frameCommitted, frameSignals, frameEc, frameTerm, frameFees,
  }

  // The certified block commits (Model B's commit rule holds it): the
  // reservation engages — held, not spent.
  action pCommit = all {
    pCert,
    not(pAbandoned),
    not(pTerminal),
    committedAt.get(P) == NONE,
    committedAt' = committedAt.put(P, clock.get(P)),
    balance' = balance - MAX_FEE,
    held' = held + MAX_FEE,
    burned' = burned,
    frameClock, frameCert, frameSignals, frameEc, frameTerm,
  }

  // The certified block is abandoned on a fork; the transaction never
  // commits at P. Certification alone admits this — which is exactly
  // what the certified-evidence twin ignores.
  action pAbandon = all {
    pCert,
    committedAt.get(P) == NONE,
    not(pAbandoned),
    pAbandoned' = true,
    pCert' = pCert,
    frameClock, frameCommitted, frameSignals, frameEc, frameTerm, frameFees,
  }

  // Q receives the transaction commit proof. Healthy: the payer's
  // bundle joins a commit-proven header of P's committing block
  // (on_committed_remote_header), so the proof exists only once P
  // committed. Twin: the bundle is consumed against the certified
  // header.
  action deliverProof = all {
    not(qHasProof),
    if (ENGAGE_ON_CERTIFIED) pCert else committedAt.get(P) != NONE,
    qHasProof' = true,
    qBarred' = qBarred,
    pSeesBarred' = pSeesBarred,
    frameClock, frameCert, frameCommitted, frameEc, frameTerm, frameFees,
  }

  // Q engages: proposal inclusion, locks, the deadline clock — its
  // commit of the transaction. Gated on the proof (healthy) and on the
  // validity window on Q's own attested clock.
  action qEngage = all {
    committedAt.get(Q) == NONE,
    clock.get(Q) <= WINDOW,
    ENGAGE_UNGATED or qHasProof,
    committedAt' = committedAt.put(Q, clock.get(Q)),
    frameClock, frameCert, frameSignals, frameEc, frameTerm, frameFees,
  }

  // The window closes on Q's chain without the transaction: a frozen
  // fact — no honest Q committee engages past its window.
  action qBar = all {
    not(qBarred),
    clock.get(Q) > WINDOW,
    committedAt.get(Q) == NONE,
    qBarred' = true,
    qHasProof' = qHasProof,
    pSeesBarred' = pSeesBarred,
    frameClock, frameCert, frameCommitted, frameEc, frameTerm, frameFees,
  }

  // P consumes the barred fact (async delivery — Q's committed headers
  // past the window with the transaction absent).
  action deliverBarred = all {
    qBarred,
    not(pSeesBarred),
    pSeesBarred' = true,
    qHasProof' = qHasProof,
    qBarred' = qBarred,
    frameClock, frameCert, frameCommitted, frameEc, frameTerm, frameFees,
  }

  // A shard's committee emits its success EC: the leg executed at its
  // commit (both legs are dependency-free — D23). One EC per committee.
  action emitEc = {
    nondet s = SHARDS.oneOf()
    all {
      s == Q or not(pTerminal),
      committedAt.get(s) != NONE,
      emitted.get(s).size() == 0,
      emitted' = emitted.setBy(s, es => es.union(Set(SUCC))),
      admitted' = admitted.setBy(s, row =>
        if (row.get(s) == NONE) row.put(s, SUCC) else row),
      frameClock, frameCert, frameCommitted, frameSignals, frameTerm, frameFees,
    }
  }

  // Network delivers an emitted EC; first-wins admission. An emitted EC
  // is a gossip-time artifact — deliverable even after P terminates
  // (Model D's H2 lesson).
  action deliverEc = {
    nondet dst = SHARDS.oneOf()
    nondet o = emitted.get(other(dst)).oneOf()
    all {
      admitted.get(dst).get(other(dst)) == NONE,
      admitted' = admitted.setBy(dst, row => row.put(other(dst), o)),
      emitted' = emitted,
      frameClock, frameCert, frameCommitted, frameSignals, frameTerm, frameFees,
    }
  }

  // Success finalization: unanimous EC coverage (Model C). At P this
  // resolves the reservation — burn the attested actual, release the
  // surplus.
  action finalizeSucc = {
    nondet s = SHARDS.oneOf()
    val row = admitted.get(s)
    all {
      s == Q or not(pTerminal),
      terminal.get(s) == NONE,
      row.get(s) == SUCC,
      row.get(other(s)) == SUCC,
      terminal' = terminal.put(s, SUCC),
      if (s == P) all {
        balance' = balance + (MAX_FEE - ACTUAL),
        held' = held - MAX_FEE,
        burned' = burned + ACTUAL,
      } else all {
        balance' = balance, held' = held, burned' = burned,
      },
      pTerminal' = pTerminal,
      frameClock, frameCert, frameCommitted, frameSignals, frameEc,
    }
  }

  // The deadline abort with floor settlement: P resolves only on the
  // barred fact — Q's window closed without engagement, so no EC from Q
  // can ever exist and no success finalization is forgone anywhere.
  action pExpireAbort = all {
    not(pTerminal),
    terminal.get(P) == NONE,
    committedAt.get(P) != NONE,
    pSeesBarred,
    admitted.get(P).get(Q) == NONE,
    terminal' = terminal.put(P, ABORT),
    pTerminal' = pTerminal,
    balance' = balance + (MAX_FEE - FLOOR),
    held' = held - MAX_FEE,
    burned' = burned + FLOOR,
    frameClock, frameCert, frameCommitted, frameSignals, frameEc,
  }

  // P reaches its reshape terminal mid-flight: the chain freezes, an
  // unfinalized wave stamps abort-by-omission (Model D), and the
  // successor's sweep resolves the reservation it inherited — the
  // reservation is a substate and moves with the subtree. The sweep is
  // atomic with the stamp here; the twin drops it and the reservation
  // wedges.
  action pTerminate = all {
    not(pTerminal),
    committedAt.get(P) != NONE,
    terminal.get(P) == NONE,
    pTerminal' = true,
    terminal' = terminal.put(P, ABORT),
    if (SWEEP_ON_TERMINATION) all {
      balance' = balance + (MAX_FEE - FLOOR),
      held' = held - MAX_FEE,
      burned' = burned + FLOOR,
    } else all {
      balance' = balance, held' = held, burned' = burned,
    },
    frameClock, frameCert, frameCommitted, frameSignals, frameEc,
  }

  action step = any {
    tick, pCertify, pCommit, pAbandon, deliverProof, qEngage, qBar,
    deliverBarred, emitEc, deliverEc, finalizeSucc, pExpireAbort,
    pTerminate,
  }

  // INV-VM-9: engagement is evidence-gated. Q committed implies P
  // committed — under the healthy gate, Q moreover holds the proof.
  val invEngageGated =
    committedAt.get(Q) == NONE or committedAt.get(P) != NONE

  // INV-VM-10: the conserved quantities. Fees never move cross-shard —
  // Q has no fee state to conserve, structurally.
  val invConserve = balance + held + burned == BALANCE

  // The reservation is all-or-nothing while held.
  val invHeldShape = held == 0 or held == MAX_FEE

  // Burn classes: nothing before a terminal; the attested actual on
  // success; the floor on any abort.
  val invBurnClass = and {
    burned == 0 or terminal.get(P) != NONE,
    terminal.get(P) == NONE or
      (terminal.get(P) == SUCC and burned == ACTUAL) or
      (terminal.get(P) == ABORT and burned == FLOOR),
  }

  // Every engaged reservation terminally settles or releases: a
  // terminal P never still holds it.
  val invResolvedAtTerminal = terminal.get(P) == NONE or held == 0

  // Model C's atomicity, scoped away from P's termination (Model D's
  // fence owns that corner).
  val invAtomicScoped =
    pTerminal or terminal.get(P) == NONE or terminal.get(Q) == NONE or
    terminal.get(P) == terminal.get(Q)

  val invAll = and {
    invEngageGated, invConserve, invHeldShape, invBurnClass,
    invResolvedAtTerminal, invAtomicScoped,
  }

  // The insolvent payer's world: nothing certifies, commits, engages,
  // holds, or burns anywhere.
  val invIdle = and {
    committedAt.get(P) == NONE,
    committedAt.get(Q) == NONE,
    held == 0,
    burned == 0,
    balance == BALANCE,
  }

  val invAllIdle = and { invAll, invIdle }

  // Scripted: the deadline abort settles the floor. P commits and
  // reserves; Q's window closes without engagement (the proof is lost in
  // flight); P consumes the barred fact and resolves at the floor.
  run deadlineFloor =
    init
      .then(pCertify)
      .then(pCommit)
      .then(all {
        clock' = clock.setBy(Q, c => c + WINDOW + 1),
        frameCert, frameCommitted, frameSignals, frameEc, frameTerm, frameFees,
      })
      .then(qBar)
      .then(deliverBarred)
      .then(pExpireAbort)
      .expect(and {
        invAll,
        terminal.get(P) == ABORT,
        burned == FLOOR,
        held == 0,
        balance == BALANCE - FLOOR,
      })

  // Scripted (certified twin): the bundle joins a merely-certified
  // header; Q engages; the certified block abandons on a fork — Q holds
  // locks for a transaction the payer shard never committed.
  run certifiedAbandon =
    init
      .then(pCertify)
      .then(deliverProof)
      .then(qEngage)
      .then(pAbandon)
      .expect(and {
        not(invEngageGated),
        committedAt.get(Q) != NONE,
        committedAt.get(P) == NONE,
        held == 0,
      })
}

// Healthy configuration: the shipped gate. Engagement demands the commit
// proof, the deadline abort fires only on the barred fact, the successor
// sweep resolves inherited reservations.
module fee_ok {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 6,
    WINDOW = 4, ENGAGE_UNGATED = false, ENGAGE_ON_CERTIFIED = false,
    SWEEP_ON_TERMINATION = true
  ).*
}

// The insolvent payer: the balance cannot cover max_fee, so block
// validity refuses the transaction everywhere it could matter.
module fee_insolvent {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 3,
    WINDOW = 4, ENGAGE_UNGATED = false, ENGAGE_ON_CERTIFIED = false,
    SWEEP_ON_TERMINATION = true
  ).*
}

// Broken twin: the pre-D21 optimistic counterpart — engagement without
// evidence, against an insolvent payer that never commits.
module fee_ungated {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 3,
    WINDOW = 4, ENGAGE_UNGATED = true, ENGAGE_ON_CERTIFIED = false,
    SWEEP_ON_TERMINATION = true
  ).*
}

// Broken twin: engagement evidence anchored on certification — a
// certified block can be abandoned on a fork after the counterpart
// engaged.
module fee_certified {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 6,
    WINDOW = 4, ENGAGE_UNGATED = false, ENGAGE_ON_CERTIFIED = true,
    SWEEP_ON_TERMINATION = true
  ).*
}

// Broken twin: no successor sweep — P terminates holding the
// reservation, and nothing ever resolves it.
module fee_unswept {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 6,
    WINDOW = 4, ENGAGE_UNGATED = false, ENGAGE_ON_CERTIFIED = false,
    SWEEP_ON_TERMINATION = false
  ).*
}

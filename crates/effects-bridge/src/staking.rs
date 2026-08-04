//! The stake pool's events read as beacon facts.
//!
//! The beacon's control plane consumes lifecycle facts — a pool gained
//! stake, a pool lost stake — and the stake pool package emits them as
//! ordinary VM events. This module is the whole of the trust boundary
//! between those two statements: emission is unprivileged, and every
//! layer past this one is mechanical, so what a witness is allowed to be
//! is decided here and nowhere else.
//!
//! Three things must hold before an event is read as a fact, and they are
//! independent:
//!
//! 1. **The emitter is a recognised pool.** A pool the network folds stake
//!    for is one it was told about, not one that turned up. Anyone may
//!    instantiate the stake pool package; only recognised instances speak
//!    to the beacon.
//! 2. **The emitter runs the stake pool's code.** The registry says which
//!    instances count; the instance registry says what code each one runs.
//!    Checking both means neither alone is load-bearing for the other's
//!    claim.
//! 3. **The payload is the shape the package's event table declares.**
//!
//! What is deliberately *not* checked is which pool the fact concerns,
//! because nothing says: the kernel stamps an event's emitter from the
//! invocation, so the pool is the instance, and an instance cannot name
//! another. That is why a payload carries an amount and nothing else —
//! there is no field in it to get wrong or to forge.

use std::collections::BTreeMap;

use hyperscale_types::{BeaconWitnessEvent, Stake, StakePoolId, VmEvent};
use hyperscale_vm_effects::{Address, InstanceRegistry, PackageHash};

/// The stake pool's event table, by the index its guest emits.
///
/// The order is the package's contract: `staking_metadata` declares
/// `["staked", "unstaked"]` and the guest emits `0` and `1` against it.
/// A package is immutable and content-addressed, so an index can never
/// come to mean something else.
const STAKED: u32 = 0;
const UNSTAKED: u32 = 1;

/// The stake pools the beacon folds for: the instance address a fact must
/// come from, and the identifier it is folded under.
///
/// Genesis seeds it. A pool joining later is a governance act — the same
/// channel that admits a validator — because admitting a pool is admitting
/// a new source of beacon facts, which is not something a transaction
/// should be able to do on its own.
#[derive(Clone, Debug, Default)]
pub struct PoolRegistry {
    pools: BTreeMap<[u8; 16], StakePoolId>,
}

impl PoolRegistry {
    /// An empty registry: no instance speaks to the beacon.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pools: BTreeMap::new(),
        }
    }

    /// Recognise `address` as the pool the beacon folds under `id`.
    pub fn register(&mut self, address: [u8; 16], id: StakePoolId) {
        self.pools.insert(address, id);
    }

    /// The pool `address` is recognised as, if any.
    #[must_use]
    pub fn pool_of(&self, address: [u8; 16]) -> Option<StakePoolId> {
        self.pools.get(&address).copied()
    }

    /// Whether any pool is recognised — the cheap guard that keeps a
    /// network with no staking surface from walking every event.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }
}

/// The beacon fact `event` records, or `None` if it is not one.
///
/// Total and side-effect-free: every rejection is a `None`, so a
/// malformed or unrecognised event is simply not a fact rather than an
/// error some caller has to decide what to do with. That matters because
/// this runs on the execution path, where a verdict that varied by caller
/// would vary by replica.
#[must_use]
pub fn witness_from_event(
    event: &VmEvent,
    pools: &PoolRegistry,
    instances: &InstanceRegistry,
    staking_package: PackageHash,
) -> Option<BeaconWitnessEvent> {
    let pool_id = pools.pool_of(event.emitter)?;
    // The registry says this instance counts; the instance registry says
    // what code it runs. A recognised address running someone else's code
    // is a genesis defect rather than a runtime condition, and it stays a
    // refusal rather than a panic because the execution path cannot take
    // a view on which of two authorities is wrong.
    if instances.get(Address(event.emitter))?.package != staking_package {
        return None;
    }
    let amount = Stake::from_attos(amount_of(&event.payload)?);
    match event.event_type {
        STAKED => Some(BeaconWitnessEvent::StakeDeposit { pool_id, amount }),
        UNSTAKED => Some(BeaconWitnessEvent::StakeWithdraw { pool_id, amount }),
        _ => None,
    }
}

/// The amount a lifecycle fact carries: the kernel's own 16-byte
/// little-endian cell, and nothing else in the payload.
///
/// A payload of any other length is a package whose code and metadata
/// disagree — its author's defect, and not a fact.
fn amount_of(payload: &[u8]) -> Option<u128> {
    let cell: [u8; 16] = payload.try_into().ok()?;
    Some(u128::from_le_bytes(cell))
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{Hash32, InstanceMeta};

    use super::*;

    const POOL: [u8; 16] = [0x50; 16];
    const IMPOSTOR: [u8; 16] = [0x51; 16];
    const POOL_ID: u32 = 7;

    fn package(tag: u8) -> PackageHash {
        PackageHash(Hash32([tag; 32]))
    }

    fn world() -> (PoolRegistry, InstanceRegistry) {
        let mut pools = PoolRegistry::new();
        pools.register(POOL, StakePoolId::new(POOL_ID));
        let mut instances = InstanceRegistry::new();
        for address in [POOL, IMPOSTOR] {
            instances.register(
                Address(address),
                InstanceMeta {
                    package: package(1),
                    config: Vec::new(),
                },
            );
        }
        (pools, instances)
    }

    fn event(emitter: [u8; 16], event_type: u32, amount: u128) -> VmEvent {
        VmEvent {
            emitter,
            event_type,
            payload: amount.to_le_bytes().to_vec(),
        }
    }

    #[test]
    fn a_recognised_pools_events_read_as_beacon_facts() {
        let (pools, instances) = world();
        assert_eq!(
            witness_from_event(&event(POOL, STAKED, 500), &pools, &instances, package(1)),
            Some(BeaconWitnessEvent::StakeDeposit {
                pool_id: StakePoolId::new(POOL_ID),
                amount: Stake::from_attos(500),
            }),
        );
        assert_eq!(
            witness_from_event(&event(POOL, UNSTAKED, 40), &pools, &instances, package(1)),
            Some(BeaconWitnessEvent::StakeWithdraw {
                pool_id: StakePoolId::new(POOL_ID),
                amount: Stake::from_attos(40),
            }),
        );
    }

    /// The whole point of the registry: running the pool's code is not
    /// enough. An unrecognised instance of the very same package — which
    /// anyone may create — speaks to nobody.
    #[test]
    fn an_unrecognised_instance_of_the_same_package_is_not_a_pool() {
        let (pools, instances) = world();
        assert_eq!(
            witness_from_event(
                &event(IMPOSTOR, STAKED, 1_000_000),
                &pools,
                &instances,
                package(1)
            ),
            None,
        );
    }

    /// And the converse: a recognised address running code that is not the
    /// pool's speaks to nobody either, so neither authority is trusted to
    /// carry the other's claim.
    #[test]
    fn a_recognised_address_running_other_code_is_not_a_pool() {
        let (pools, instances) = world();
        assert_eq!(
            witness_from_event(&event(POOL, STAKED, 500), &pools, &instances, package(2)),
            None,
        );
    }

    #[test]
    fn an_event_the_table_does_not_declare_is_not_a_fact() {
        let (pools, instances) = world();
        assert_eq!(
            witness_from_event(&event(POOL, 2, 500), &pools, &instances, package(1)),
            None,
        );
    }

    #[test]
    fn a_payload_that_is_not_an_amount_cell_is_not_a_fact() {
        let (pools, instances) = world();
        for payload in [Vec::new(), vec![1; 8], vec![1; 17]] {
            let event = VmEvent {
                emitter: POOL,
                event_type: STAKED,
                payload,
            };
            assert_eq!(
                witness_from_event(&event, &pools, &instances, package(1)),
                None,
            );
        }
    }

    /// An empty registry is the state every network starts in and the one
    /// a network without staking stays in: nothing is a fact.
    #[test]
    fn an_empty_registry_recognises_nothing() {
        let (_, instances) = world();
        let pools = PoolRegistry::new();
        assert!(pools.is_empty());
        assert_eq!(
            witness_from_event(&event(POOL, STAKED, 500), &pools, &instances, package(1)),
            None,
        );
    }
}

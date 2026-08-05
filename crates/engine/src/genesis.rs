//! Genesis seeding: the stdlib world and the funded-account cells.
//!
//! [`GenesisConfig`] is the canonical input — the accounts a deployment
//! funds and the stake pools its beacon folds facts for — so two nodes
//! with the same config install byte-identical state. The metadata cache
//! holds the stdlib account package, the instance registry binds each
//! funded address to it, and the funded balances land as identity-keyed
//! vault cells in one genesis batch.

use std::sync::LazyLock;

use hyperscale_effects_bridge::vm_statics::{PackageCache, package_key};
use hyperscale_effects_bridge::{
    PoolRegistry, ProtocolHasher, admit_package, attach_metadata, validator_key,
};
pub use hyperscale_effects_bridge::{VM_XRD, entropy_key, vault_key};
use hyperscale_storage::{DatabaseUpdate, DbSortKey, PartitionDatabaseUpdates};
use hyperscale_types::StakePoolSeat;
use hyperscale_types::state_key::{VM_PARTITION, vm_db_node_key};
use hyperscale_vm_effects::{
    Address, InstanceMeta, InstanceRegistry, MetadataCache, PackageHash, Value, package_hash,
};
use hyperscale_vm_kernel::encode_amount;
use hyperscale_vm_stdlib::{
    ACCOUNT_COMPONENT, STAKING_COMPONENT, account_metadata, staking_metadata,
};
use indexmap::IndexMap;
use radix_substate_store_interface::interface::DatabaseUpdates;

/// The stdlib account package as a publishable artifact: the committed
/// guest blob with its effect metadata attached in the section a
/// published package carries it in.
///
/// Composition is deterministic — one committed blob, one authored
/// signature set, one frozen encoding — so every node holds the same
/// bytes and therefore the same content address. The vocabulary crate
/// stays wire-free, which is why the artifact is assembled here rather
/// than committed with the section already in it.
static ACCOUNT_ARTIFACT: LazyLock<Vec<u8>> = LazyLock::new(|| {
    attach_metadata(ACCOUNT_COMPONENT, &account_metadata())
        .expect("the stdlib account metadata attaches to its committed blob")
});

/// The stdlib stake pool package as a publishable artifact, assembled the
/// same way and for the same reason as the account's.
static STAKING_ARTIFACT: LazyLock<Vec<u8>> = LazyLock::new(|| {
    attach_metadata(STAKING_COMPONENT, &staking_metadata())
        .expect("the stdlib stake pool metadata attaches to its committed blob")
});

/// Configuration for genesis bootstrapping.
#[derive(Debug, Clone, Default)]
pub struct GenesisConfig {
    /// Funded accounts: owner prefix and initial balance. Seeded as
    /// identity-keyed vault cells and registered as account-package
    /// instances in the process's VM statics.
    pub accounts: Vec<([u8; 16], u128)>,

    /// Stake pools the beacon folds facts for: the pool instance's owner
    /// prefix and the identifier it is folded under. Seated as stake pool
    /// package instances in the process's VM statics, which is what makes
    /// their emitted events beacon facts — running the package never
    /// does, because anyone may run the package.
    pub pools: Vec<StakePoolSeat>,
}

/// The prefix genesis publishes the stdlib package under.
///
/// No key derives it, so nothing can ever publish beside it or spend
/// from it: the protocol's own packages sit where no signer reaches.
pub const GENESIS_PUBLISHER: [u8; 16] = [0; 16];

/// The stdlib account artifact: what the engine compiles and what the
/// package's content address covers.
#[must_use]
pub fn account_artifact() -> &'static [u8] {
    &ACCOUNT_ARTIFACT
}

/// The stdlib stake pool artifact.
#[must_use]
pub fn staking_artifact() -> &'static [u8] {
    &STAKING_ARTIFACT
}

/// The genesis-static VM world: published stdlib metadata and the funded
/// accounts' instance registrations.
#[derive(Debug, Clone)]
pub struct VmWorld {
    /// Published package metadata, growing as blocks commit.
    pub cache: PackageCache,
    /// Instance registrations.
    pub instances: InstanceRegistry,
    /// The stdlib account package's content address.
    pub account_package: PackageHash,
    /// The stdlib stake pool package's content address — the code a
    /// recognised pool must be running for its events to be read as
    /// beacon facts.
    pub staking_package: PackageHash,
    /// The stake pools the beacon folds for. Empty on a network with no
    /// staking surface, which is every network until genesis seats one.
    pub pools: PoolRegistry,
}

/// Build the world for `accounts` (owner prefix, balance): the account
/// package published under its artifact hash, one instance per funded
/// address.
///
/// The published signatures are the ones the artifact declares, admitted
/// through the same check a publish transaction runs — genesis is the
/// cold start of the cache, not a second source of truth for it.
///
/// # Panics
///
/// Panics if the stdlib artifact would not be admissible as a published
/// package — a build defect, not a runtime condition.
#[must_use]
pub fn genesis_world(accounts: &[([u8; 16], u128)]) -> VmWorld {
    genesis_world_with_pools(accounts, &[])
}

/// [`genesis_world`] seating `pools` as the stake pools the beacon folds
/// for: `(instance address, the identifier it is folded under)`.
///
/// A pool is an instance of the stdlib stake pool package configured with
/// the resource it stakes and the resource it issues. Seating it here is
/// what makes its events beacon facts — the package alone never does,
/// because anyone may run the package.
///
/// # Panics
///
/// Panics if a stdlib artifact would not be admissible as a published
/// package — a build defect, not a runtime condition.
#[must_use]
pub fn genesis_world_with_pools(accounts: &[([u8; 16], u128)], pools: &[StakePoolSeat]) -> VmWorld {
    let artifact = account_artifact();
    let account_package = package_hash(&ProtocolHasher, artifact);
    let metadata =
        admit_package(artifact).expect("the stdlib account artifact publishes as a package");
    let mut seed = MetadataCache::new();
    seed.publish(account_package, metadata);

    let staking_package = package_hash(&ProtocolHasher, staking_artifact());
    seed.publish(
        staking_package,
        admit_package(staking_artifact())
            .expect("the stdlib stake pool artifact publishes as a package"),
    );

    let cache = PackageCache::new(seed);
    let mut instances = InstanceRegistry::new();
    for (address, _) in accounts {
        instances.register(
            Address(*address),
            InstanceMeta {
                package: account_package,
                config: vec![],
            },
        );
    }
    let mut registry = PoolRegistry::new();
    for seat in pools {
        instances.register(
            Address(seat.address),
            InstanceMeta {
                package: staking_package,
                // The resource a delegation is denominated in, the one the
                // pool issues against it, and the principal its operator
                // surface admits. The pool's own identity is its address,
                // so nothing here names it.
                config: vec![
                    Value::Address(VM_XRD),
                    Value::Address(stake_unit(seat.address)),
                    Value::Address(Address(seat.operator)),
                ],
            },
        );
        registry.register(seat.address, seat.id);
    }
    VmWorld {
        cache,
        instances,
        account_package,
        staking_package,
        pools: registry,
    }
}

/// The resource a pool at `address` issues against delegations.
///
/// Derived from the pool rather than configured, so two pools can never be
/// seated on one stake-unit resource and a holder's units always name the
/// pool that owes them.
#[must_use]
pub fn stake_unit(pool: [u8; 16]) -> Address {
    Address(vault_key(pool, VM_XRD).local.0)
}

/// The funded accounts' genesis substate writes: one [`VM_XRD`] vault
/// cell per account, identity-keyed under the owner's prefix.
#[must_use]
pub fn vm_genesis_updates(
    accounts: &[([u8; 16], u128)],
    pools: &[StakePoolSeat],
) -> DatabaseUpdates {
    let mut updates = DatabaseUpdates::default();
    // The stdlib package as a committed cell, under the same content
    // address a publish would place it at. Genesis is then the cache's
    // cold start in the literal sense — the same projection of committed
    // state every later block extends, rather than a second source the
    // cache would have to be told about separately.
    let artifact = account_artifact();
    let package = package_hash(&ProtocolHasher, artifact);
    let cell = package_key(GENESIS_PUBLISHER, package);
    updates
        .node_updates
        .entry(vm_db_node_key(cell.owner.0))
        .or_default()
        .partition_updates
        .insert(
            VM_PARTITION,
            PartitionDatabaseUpdates::Delta {
                substate_updates: IndexMap::from([(
                    DbSortKey(cell.local.0.to_vec()),
                    DatabaseUpdate::Set(artifact.to_vec()),
                )]),
            },
        );
    // A seated pool's record of the validators it already operates.
    // Beacon genesis creates those memberships directly in beacon state,
    // so without this the contract would hold no record of validators it
    // demonstrably operates — and its own methods would refuse to speak
    // about them.
    for seat in pools {
        if seat.founding.is_empty() {
            continue;
        }
        let mut substate_updates = IndexMap::new();
        for (validator, pubkey) in &seat.founding {
            let key = validator_key(seat.address, validator.inner());
            substate_updates.insert(
                DbSortKey(key.local.0.to_vec()),
                DatabaseUpdate::Set(pubkey.as_bytes().to_vec()),
            );
        }
        updates
            .node_updates
            .entry(vm_db_node_key(seat.address))
            .or_default()
            .partition_updates
            .insert(
                VM_PARTITION,
                PartitionDatabaseUpdates::Delta { substate_updates },
            );
    }
    for (address, balance) in accounts {
        let key = vault_key(*address, VM_XRD);
        let mut substate_updates = IndexMap::new();
        substate_updates.insert(
            DbSortKey(key.local.0.to_vec()),
            DatabaseUpdate::Set(encode_amount(*balance).to_vec()),
        );
        updates
            .node_updates
            .entry(vm_db_node_key(key.owner.0))
            .or_default()
            .partition_updates
            .insert(
                VM_PARTITION,
                PartitionDatabaseUpdates::Delta { substate_updates },
            );
    }
    updates
}

#[cfg(test)]
mod tests {
    use hyperscale_types::state_key::{VM_FLAT_KEY_LEN, vm_flat_key_parts};

    use super::*;
    use crate::vm_account_address;

    #[test]
    fn genesis_updates_are_identity_keyed_vault_cells() {
        let alice = [0x11u8; 16];
        let bob = [0x22u8; 16];
        let updates = vm_genesis_updates(&[(alice, 500), (bob, 700)], &[]);
        // Two funded accounts, plus the stdlib package under the
        // publisher no key derives.
        assert_eq!(updates.node_updates.len(), 3);
        assert!(
            updates
                .node_updates
                .contains_key(&vm_db_node_key(GENESIS_PUBLISHER))
        );

        for (owner, balance) in [(alice, 500u128), (bob, 700)] {
            let key = vault_key(owner, VM_XRD);
            assert_eq!(key.owner.0, owner);
            let node = updates
                .node_updates
                .get(&vm_db_node_key(owner))
                .expect("entity keyed under the owner prefix");
            let PartitionDatabaseUpdates::Delta { substate_updates } = node
                .partition_updates
                .get(&VM_PARTITION)
                .expect("partition")
            else {
                panic!("VM genesis writes are Delta-only");
            };
            let update = substate_updates
                .get(&DbSortKey(key.local.0.to_vec()))
                .expect("vault cell present");
            assert_eq!(
                update,
                &DatabaseUpdate::Set(encode_amount(balance).to_vec())
            );

            // The flat key reassembles into the VM namespace.
            let mut flat = vm_db_node_key(owner);
            flat.push(VM_PARTITION);
            flat.extend_from_slice(&key.local.0);
            assert_eq!(flat.len(), VM_FLAT_KEY_LEN);
            assert_eq!(vm_flat_key_parts(&flat), Some((owner, key.local.0)));
        }
    }

    #[test]
    fn the_stdlib_artifact_describes_itself() {
        let artifact = account_artifact();

        // The code is the committed blob and the section is what was
        // added, so the address covers both.
        assert!(artifact.starts_with(ACCOUNT_COMPONENT));
        assert!(artifact.len() > ACCOUNT_COMPONENT.len());
        assert_ne!(
            package_hash(&ProtocolHasher, artifact),
            package_hash(&ProtocolHasher, ACCOUNT_COMPONENT)
        );

        // What genesis publishes is admitted out of the artifact by the
        // publish check, and it is the signature set the stdlib authors:
        // the real guest's exports back every method it declares.
        let declared = admit_package(artifact).expect("publishes as a package");
        assert_eq!(declared, account_metadata());
        let world = genesis_world(&[]);
        assert_eq!(
            world.cache.load().get(world.account_package),
            Some(&declared)
        );
        assert_eq!(
            world.account_package,
            package_hash(&ProtocolHasher, artifact)
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn both_runtimes_accept_the_section_carrying_artifact() {
        // The blessed engine's acceptance is proved by every guest test
        // in this crate, which now runs the artifact. The reference
        // interpreter ships only on wasm32, so its acceptance has no
        // native witness unless one is written.
        use hyperscale_vm_ref::RefComponent;

        RefComponent::decode(account_artifact())
            .expect("the reference interpreter decodes the stdlib artifact");
    }

    #[test]
    fn the_world_binds_every_funded_account_to_the_stdlib_package() {
        let world = genesis_world(&[([0x11; 16], 1), ([0x22; 16], 2)]);
        assert!(world.cache.load().get(world.account_package).is_some());
        for address in [[0x11; 16], [0x22; 16]] {
            assert_eq!(
                world.instances.get(Address(address)).map(|m| m.package),
                Some(world.account_package)
            );
        }
    }

    #[test]
    fn account_addresses_derive_deterministically_from_keys() {
        let a = vm_account_address(&[7u8; 32]);
        assert_eq!(a, vm_account_address(&[7u8; 32]));
        assert_ne!(a, vm_account_address(&[8u8; 32]));
    }
}

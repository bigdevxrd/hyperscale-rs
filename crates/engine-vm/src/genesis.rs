//! VM genesis seeding: the stdlib world and the funded-account cells.
//!
//! Every node derives the identical world from the genesis config's VM
//! account list — the metadata cache holds the stdlib account package,
//! the instance registry binds each funded address to it, and the funded
//! balances land as identity-keyed vault cells beside the Radix
//! bootstrap in one genesis batch.

use std::sync::LazyLock;

use hyperscale_effects_bridge::{ProtocolHasher, admit_package, attach_metadata};
pub use hyperscale_effects_bridge::{VM_XRD, entropy_key, vault_key};
use hyperscale_storage::{DatabaseUpdate, DbSortKey, PartitionDatabaseUpdates};
use hyperscale_types::state_key::{VM_PARTITION, vm_db_node_key};
use hyperscale_vm_effects::{
    Address, InstanceMeta, InstanceRegistry, MetadataCache, PackageHash, package_hash,
};
use hyperscale_vm_kernel::encode_amount;
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, account_metadata};
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

/// The stdlib account artifact: what the engine compiles and what the
/// package's content address covers.
#[must_use]
pub fn account_artifact() -> &'static [u8] {
    &ACCOUNT_ARTIFACT
}

/// The genesis-static VM world: published stdlib metadata and the funded
/// accounts' instance registrations.
#[derive(Debug, Clone)]
pub struct VmWorld {
    /// Published package metadata.
    pub cache: MetadataCache,
    /// Instance registrations.
    pub instances: InstanceRegistry,
    /// The stdlib account package's content address.
    pub account_package: PackageHash,
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
    let artifact = account_artifact();
    let account_package = package_hash(&ProtocolHasher, artifact);
    let metadata =
        admit_package(artifact).expect("the stdlib account artifact publishes as a package");
    let mut cache = MetadataCache::new();
    cache.publish(account_package, metadata);
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
    VmWorld {
        cache,
        instances,
        account_package,
    }
}

/// The funded accounts' genesis substate writes: one [`VM_XRD`] vault
/// cell per account, identity-keyed under the owner's prefix.
#[must_use]
pub fn vm_genesis_updates(accounts: &[([u8; 16], u128)]) -> DatabaseUpdates {
    let mut updates = DatabaseUpdates::default();
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
        let updates = vm_genesis_updates(&[(alice, 500), (bob, 700)]);
        assert_eq!(updates.node_updates.len(), 2);

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
        assert_eq!(world.cache.get(world.account_package), Some(&declared));
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
        assert!(world.cache.get(world.account_package).is_some());
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

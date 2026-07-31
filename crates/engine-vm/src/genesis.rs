//! VM genesis seeding: the stdlib world and the funded-account cells.
//!
//! Every node derives the identical world from the genesis config's VM
//! account list — the metadata cache holds the stdlib account package,
//! the instance registry binds each funded address to it, and the funded
//! balances land as identity-keyed vault cells beside the Radix
//! bootstrap in one genesis batch.

use hyperscale_effects_bridge::ProtocolHasher;
use hyperscale_storage::{DatabaseUpdate, DbSortKey, PartitionDatabaseUpdates};
use hyperscale_types::state_key::{VM_PARTITION, vm_db_node_key};
use hyperscale_vm_effects::stdlib::VAULT;
use hyperscale_vm_effects::{
    Address, Hasher, InstanceMeta, InstanceRegistry, MetadataCache, PackageHash, SubstateKey,
    Value, child_key,
};
use hyperscale_vm_kernel::encode_amount;
use hyperscale_vm_stdlib::{account_metadata, account_package_hash};
use indexmap::IndexMap;
use radix_substate_store_interface::interface::DatabaseUpdates;

/// The native fee/transfer resource of the VM namespace.
pub const VM_XRD: Address = Address([0x58; 16]);

const DOMAIN_VM_ACCOUNT: &[u8] = b"hyperscale/engine-vm/account-address";

/// The VM account address owned by an ed25519 public key: the protocol
/// hash of the key, truncated to the owner-prefix width.
///
/// Deterministic — genesis funding, transaction builders, and admission
/// all derive the same address from the same key.
#[must_use]
pub fn vm_account_address(public_key: &[u8; 32]) -> [u8; 16] {
    let digest = ProtocolHasher.hash(DOMAIN_VM_ACCOUNT, &[public_key]);
    let mut address = [0u8; 16];
    address.copy_from_slice(&digest.0[..16]);
    address
}

/// The vault cell for `resource` under `owner` — the same child key the
/// stdlib account metadata's effect clauses compute.
#[must_use]
pub fn vault_key(owner: [u8; 16], resource: Address) -> SubstateKey {
    child_key(
        &ProtocolHasher,
        Address(owner),
        VAULT,
        &[Value::Address(resource).canonical_bytes()],
    )
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
#[must_use]
pub fn genesis_world(accounts: &[([u8; 16], u128)]) -> VmWorld {
    let account_package = account_package_hash(&ProtocolHasher);
    let mut cache = MetadataCache::new();
    cache.publish(account_package, account_metadata());
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

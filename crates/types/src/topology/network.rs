//! Network identity — which chain a signature is for.
//!
//! [`NetworkDefinition::id`] is bound into every signed consensus message
//! and into the validator bind handshake, so a signature produced for one
//! network cannot be replayed against another. Nothing else about the
//! definition is signed; the name exists so a config file can say which
//! network it means.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use sbor::BasicSbor;

/// The identity of a network.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct NetworkDefinition {
    /// Domain byte mixed into every signed message. Distinct per network,
    /// which is what makes a cross-network replay produce a different
    /// digest and so fail verification.
    pub id: u8,
    /// The name a config file names this network by.
    pub logical_name: String,
}

impl NetworkDefinition {
    /// The deterministic simulation and test harnesses.
    #[must_use]
    pub fn simulator() -> Self {
        Self {
            id: 242,
            logical_name: "simulator".to_string(),
        }
    }

    /// The public test network.
    #[must_use]
    pub fn stokenet() -> Self {
        Self {
            id: 2,
            logical_name: "stokenet".to_string(),
        }
    }

    /// The production network.
    #[must_use]
    pub fn mainnet() -> Self {
        Self {
            id: 1,
            logical_name: "mainnet".to_string(),
        }
    }
}

impl Display for NetworkDefinition {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.logical_name)
    }
}

/// A network name no definition claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownNetwork(pub String);

impl Display for UnknownNetwork {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "unknown network `{}`", self.0)
    }
}

impl std::error::Error for UnknownNetwork {}

impl FromStr for NetworkDefinition {
    type Err = UnknownNetwork;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "simulator" => Ok(Self::simulator()),
            "stokenet" => Ok(Self::stokenet()),
            "mainnet" => Ok(Self::mainnet()),
            _ => Err(UnknownNetwork(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ids are what a signature binds, so two networks must never share
    /// one — a collision would make a cross-network replay verify.
    #[test]
    fn every_network_has_a_distinct_id() {
        let nets = [
            NetworkDefinition::simulator(),
            NetworkDefinition::stokenet(),
            NetworkDefinition::mainnet(),
        ];
        for (i, a) in nets.iter().enumerate() {
            for b in &nets[i + 1..] {
                assert_ne!(a.id, b.id, "{a} and {b} share an id");
            }
        }
    }

    #[test]
    fn names_round_trip_through_parsing() {
        for net in [
            NetworkDefinition::simulator(),
            NetworkDefinition::stokenet(),
            NetworkDefinition::mainnet(),
        ] {
            assert_eq!(
                net.logical_name.parse::<NetworkDefinition>(),
                Ok(net.clone())
            );
            // Parsing is case-insensitive so a config file can shout.
            assert_eq!(
                net.logical_name.to_uppercase().parse::<NetworkDefinition>(),
                Ok(net)
            );
        }
        assert!("nosuchnet".parse::<NetworkDefinition>().is_err());
    }
}

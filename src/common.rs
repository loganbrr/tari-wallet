//! Common utilities and shared functionality for the Tari lightweight wallet
//!
//! This module provides shared constants, utility functions, and type conversions
//! that are used across multiple modules in the library.

use crate::data_structures::address::Network;
use crate::errors::LightweightWalletError;

/// Convert network string to Network enum
pub fn string_to_network(network_str: &str) -> Network {
    match network_str.to_lowercase().as_str() {
        "mainnet" => Network::MainNet,
        "stagenet" => Network::StageNet,
        "localnet" => Network::LocalNet,
        "esmeralda" | "esme" => Network::Esmeralda,
        "nextnet" => Network::NextNet,
        "igor" => Network::Igor,
        _ => Network::Esmeralda, // Default to Esmeralda for unknown networks
    }
}

/// Convert Network enum to string representation
pub fn network_to_string(network: Network) -> String {
    match network {
        Network::MainNet => "mainnet".to_string(),
        Network::StageNet => "stagenet".to_string(),
        Network::LocalNet => "localnet".to_string(),
        Network::Esmeralda => "esmeralda".to_string(),
        Network::NextNet => "nextnet".to_string(),
        Network::Igor => "igor".to_string(),
    }
}

/// Validate that a string is a valid network identifier
pub fn validate_network_string(network_str: &str) -> Result<(), LightweightWalletError> {
    match network_str.to_lowercase().as_str() {
        "mainnet" | "stagenet" | "localnet" | "esmeralda" | "esme" | "nextnet" | "igor" => Ok(()),
        _ => Err(LightweightWalletError::InvalidArgument {
            argument: "network".to_string(),
            value: network_str.to_string(),
            message: "Must be one of: mainnet, stagenet, localnet, esmeralda, nextnet, igor".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_to_network() {
        assert_eq!(string_to_network("mainnet"), Network::MainNet);
        assert_eq!(string_to_network("MAINNET"), Network::MainNet);
        assert_eq!(string_to_network("stagenet"), Network::StageNet);
        assert_eq!(string_to_network("STAGENET"), Network::StageNet);
        assert_eq!(string_to_network("localnet"), Network::LocalNet);
        assert_eq!(string_to_network("esmeralda"), Network::Esmeralda);
        assert_eq!(string_to_network("esme"), Network::Esmeralda);
        assert_eq!(string_to_network("nextnet"), Network::NextNet);
        assert_eq!(string_to_network("igor"), Network::Igor);
        assert_eq!(string_to_network("unknown"), Network::Esmeralda); // default
    }

    #[test]
    fn test_network_to_string() {
        assert_eq!(network_to_string(Network::MainNet), "mainnet");
        assert_eq!(network_to_string(Network::StageNet), "stagenet");
        assert_eq!(network_to_string(Network::LocalNet), "localnet");
        assert_eq!(network_to_string(Network::Esmeralda), "esmeralda");
        assert_eq!(network_to_string(Network::NextNet), "nextnet");
        assert_eq!(network_to_string(Network::Igor), "igor");
    }

    #[test]
    fn test_validate_network_string() {
        assert!(validate_network_string("mainnet").is_ok());
        assert!(validate_network_string("MAINNET").is_ok());
        assert!(validate_network_string("stagenet").is_ok());
        assert!(validate_network_string("localnet").is_ok());
        assert!(validate_network_string("esmeralda").is_ok());
        assert!(validate_network_string("esme").is_ok());
        assert!(validate_network_string("nextnet").is_ok());
        assert!(validate_network_string("igor").is_ok());
        
        assert!(validate_network_string("invalid").is_err());
        assert!(validate_network_string("").is_err());
    }

    #[test]
    fn test_network_roundtrip() {
        let networks = [
            Network::MainNet,
            Network::StageNet,
            Network::LocalNet,
            Network::Esmeralda,
            Network::NextNet,
            Network::Igor,
        ];

        for network in networks {
            let string_repr = network_to_string(network);
            let parsed_network = string_to_network(&string_repr);
            assert_eq!(network, parsed_network);
        }
    }
}

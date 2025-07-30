//! Python wrapper classes for extraction-specific data structures
//!
//! This module provides Python-compatible wrapper classes for complex Rust types
//! used in the extraction module. Following the established pattern, complex types
//! are converted to hex strings for Python consumption.

use pyo3::prelude::*;
use lightweight_wallet_libs::{
    data_structures::{
        transaction_output::LightweightTransactionOutput,
        wallet_output::LightweightWalletOutput,
    },
};

/// Python wrapper for LightweightTransactionOutput
///
/// This class represents a transaction output with all cryptographic components
/// serialized as hex strings for Python compatibility.
#[pyclass]
#[derive(Clone)]
pub struct PyLightweightTransactionOutput {
    /// Output version
    #[pyo3(get)]
    pub version: u8,
    
    /// Output features (serialized as hex)
    #[pyo3(get)]
    pub features_hex: String,
    
    /// Homomorphic commitment (serialized as hex)
    #[pyo3(get)]
    pub commitment_hex: String,
    
    /// Range proof (optional, serialized as hex)
    #[pyo3(get)]
    pub proof_hex: Option<String>,
    
    /// Spending script (serialized as hex)
    #[pyo3(get)]
    pub script_hex: String,
    
    /// Sender offset public key (serialized as hex)
    #[pyo3(get)]
    pub sender_offset_public_key_hex: String,
    
    /// Metadata signature (serialized as hex)
    #[pyo3(get)]
    pub metadata_signature_hex: String,
    
    /// Covenant (serialized as hex)
    #[pyo3(get)]
    pub covenant_hex: String,
    
    /// Encrypted data (serialized as hex)
    #[pyo3(get)]
    pub encrypted_data_hex: String,
    
    /// Minimum value promise in micro Minotari
    #[pyo3(get)]
    pub minimum_value_promise: u64,
}

/// Python wrapper for LightweightWalletOutput
///
/// This class represents a wallet output with all cryptographic components
/// and wallet-specific information serialized for Python compatibility.
#[pyclass]
#[derive(Clone)]
pub struct PyLightweightWalletOutput {
    /// Output version
    #[pyo3(get)]
    pub version: u8,
    
    /// Output value in micro Minotari
    #[pyo3(get)]
    pub value: u64,
    
    /// Spending key identifier (serialized as hex)
    #[pyo3(get)]
    pub spending_key_id_hex: String,
    
    /// Output features (serialized as hex)
    #[pyo3(get)]
    pub features_hex: String,
    
    /// Script (serialized as hex)
    #[pyo3(get)]
    pub script_hex: String,
    
    /// Covenant (serialized as hex)
    #[pyo3(get)]
    pub covenant_hex: String,
    
    /// Input data/execution stack (serialized as hex)
    #[pyo3(get)]
    pub input_data_hex: String,
    
    /// Script key identifier (serialized as hex)
    #[pyo3(get)]
    pub script_key_id_hex: String,
    
    /// Sender offset public key (serialized as hex)
    #[pyo3(get)]
    pub sender_offset_public_key_hex: String,
    
    /// Metadata signature (serialized as hex)
    #[pyo3(get)]
    pub metadata_signature_hex: String,
    
    /// Script lock height
    #[pyo3(get)]
    pub script_lock_height: u64,
    
    /// Encrypted data (serialized as hex)
    #[pyo3(get)]
    pub encrypted_data_hex: String,
    
    /// Minimum value promise in micro Minotari
    #[pyo3(get)]
    pub minimum_value_promise: u64,
    
    /// Range proof (optional, serialized as hex)
    #[pyo3(get)]
    pub range_proof_hex: Option<String>,
    
    /// Payment ID (serialized as hex)
    #[pyo3(get)]
    pub payment_id_hex: String,
}

impl PyLightweightTransactionOutput {
    /// Convert from the internal Rust type to Python wrapper
    pub fn from_rust(output: &LightweightTransactionOutput) -> PyResult<Self> {
        use borsh::to_vec;
        
        let features_hex = hex::encode(to_vec(&output.features).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize features: {}", e))
        })?);
        
        let commitment_hex = hex::encode(output.commitment.as_bytes());
        
        let proof_hex = if let Some(ref proof) = output.proof {
            Some(hex::encode(to_vec(proof).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize proof: {}", e))
            })?))
        } else {
            None
        };
        
        let script_hex = hex::encode(to_vec(&output.script).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize script: {}", e))
        })?);
        
        let sender_offset_public_key_hex = hex::encode(output.sender_offset_public_key.as_bytes());
        
        let metadata_signature_hex = hex::encode(to_vec(&output.metadata_signature).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize metadata signature: {}", e))
        })?);
        
        let covenant_hex = hex::encode(to_vec(&output.covenant).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize covenant: {}", e))
        })?);
        
        let encrypted_data_hex = hex::encode(to_vec(&output.encrypted_data).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize encrypted data: {}", e))
        })?);
        
        Ok(Self {
            version: output.version,
            features_hex,
            commitment_hex,
            proof_hex,
            script_hex,
            sender_offset_public_key_hex,
            metadata_signature_hex,
            covenant_hex,
            encrypted_data_hex,
            minimum_value_promise: output.minimum_value_promise.as_u64(),
        })
    }
    
    /// Convert from Python wrapper to internal Rust type
    pub fn to_rust(&self) -> PyResult<LightweightTransactionOutput> {
        use borsh::from_slice;
        use lightweight_wallet_libs::data_structures::types::{CompressedCommitment, CompressedPublicKey, MicroMinotari};
        
        let features = from_slice(&hex::decode(&self.features_hex).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to decode features hex: {}", e))
        })?).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to deserialize features: {}", e))
        })?;
        
        let commitment = CompressedCommitment::from_hex(&self.commitment_hex).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to parse commitment: {}", e))
        })?;
        
        let proof = if let Some(ref proof_hex) = self.proof_hex {
            Some(from_slice(&hex::decode(proof_hex).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Failed to decode proof hex: {}", e))
            })?).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Failed to deserialize proof: {}", e))
            })?)
        } else {
            None
        };
        
        let script = from_slice(&hex::decode(&self.script_hex).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to decode script hex: {}", e))
        })?).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to deserialize script: {}", e))
        })?;
        
        let sender_offset_public_key = CompressedPublicKey::from_hex(&self.sender_offset_public_key_hex).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to parse sender offset public key: {}", e))
        })?;
        
        let metadata_signature = from_slice(&hex::decode(&self.metadata_signature_hex).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to decode metadata signature hex: {}", e))
        })?).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to deserialize metadata signature: {}", e))
        })?;
        
        let covenant = from_slice(&hex::decode(&self.covenant_hex).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to decode covenant hex: {}", e))
        })?).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to deserialize covenant: {}", e))
        })?;
        
        let encrypted_data = from_slice(&hex::decode(&self.encrypted_data_hex).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to decode encrypted data hex: {}", e))
        })?).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to deserialize encrypted data: {}", e))
        })?;
        
        let minimum_value_promise = MicroMinotari::from(self.minimum_value_promise);
        
        Ok(LightweightTransactionOutput::new(
            self.version,
            features,
            commitment,
            proof,
            script,
            sender_offset_public_key,
            metadata_signature,
            covenant,
            encrypted_data,
            minimum_value_promise,
        ))
    }
}

impl PyLightweightWalletOutput {
    /// Convert from the internal Rust type to Python wrapper
    pub fn from_rust(output: &LightweightWalletOutput) -> PyResult<Self> {
        use borsh::to_vec;
        
        let spending_key_id_hex = hex::encode(to_vec(&output.spending_key_id).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize spending key id: {}", e))
        })?);
        
        let features_hex = hex::encode(to_vec(&output.features).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize features: {}", e))
        })?);
        
        let script_hex = hex::encode(to_vec(&output.script).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize script: {}", e))
        })?);
        
        let covenant_hex = hex::encode(to_vec(&output.covenant).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize covenant: {}", e))
        })?);
        
        let input_data_hex = hex::encode(to_vec(&output.input_data).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize input data: {}", e))
        })?);
        
        let script_key_id_hex = hex::encode(to_vec(&output.script_key_id).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize script key id: {}", e))
        })?);
        
        let sender_offset_public_key_hex = hex::encode(output.sender_offset_public_key.as_bytes());
        
        let metadata_signature_hex = hex::encode(to_vec(&output.metadata_signature).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize metadata signature: {}", e))
        })?);
        
        let encrypted_data_hex = hex::encode(to_vec(&output.encrypted_data).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize encrypted data: {}", e))
        })?);
        
        let range_proof_hex = if let Some(ref proof) = output.range_proof {
            Some(hex::encode(to_vec(proof).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize range proof: {}", e))
            })?))
        } else {
            None
        };
        
        let payment_id_hex = hex::encode(to_vec(&output.payment_id).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize payment id: {}", e))
        })?);
        
        Ok(Self {
            version: output.version,
            value: output.value.as_u64(),
            spending_key_id_hex,
            features_hex,
            script_hex,
            covenant_hex,
            input_data_hex,
            script_key_id_hex,
            sender_offset_public_key_hex,
            metadata_signature_hex,
            script_lock_height: output.script_lock_height,
            encrypted_data_hex,
            minimum_value_promise: output.minimum_value_promise.as_u64(),
            range_proof_hex,
            payment_id_hex,
        })
    }
}

#[pymethods]
impl PyLightweightTransactionOutput {
    fn __repr__(&self) -> String {
        format!(
            "PyLightweightTransactionOutput(version={}, commitment={}...)",
            self.version,
            &self.commitment_hex[..8]
        )
    }
}

#[pymethods]
impl PyLightweightWalletOutput {
    fn __repr__(&self) -> String {
        format!(
            "PyLightweightWalletOutput(version={}, value={}, payment_id={}...)",
            self.version,
            self.value,
            &self.payment_id_hex[..8]
        )
    }
}

/// Register wrapper classes with Python module
pub fn register_wrapper_classes(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyLightweightTransactionOutput>()?;
    m.add_class::<PyLightweightWalletOutput>()?;
    Ok(())
}

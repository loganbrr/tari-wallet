//! Hybrid serialization system for PyO3 bindings
//!
//! This module provides a trait-based serialization system that supports both
//! structured PyO3 objects and optional hex string conversion for backward
//! compatibility. Uses borsh for efficient binary serialization of complex types.

use pyo3::prelude::*;

/// Python wrapper for cryptographic data with structured access
#[pyclass]
#[derive(Clone)]
pub struct CryptoPyWrapper {
    /// Hex-encoded serialized data
    #[pyo3(get)]
    pub data_hex: String,
    
    /// Type name for debugging
    #[pyo3(get)]
    pub data_type: String,
}

#[pymethods]
impl CryptoPyWrapper {
    /// Get raw hex data (for backward compatibility)
    #[getter]
    pub fn hex(&self) -> String {
        self.data_hex.clone()
    }
    
    /// Get the type name of the wrapped data
    #[getter]
    pub fn type_name(&self) -> String {
        self.data_type.clone()
    }
    
    /// String representation
    pub fn __str__(&self) -> String {
        format!("CryptoData[{}]({}...)", 
                self.data_type, 
                &self.data_hex[..std::cmp::min(16, self.data_hex.len())])
    }
    
    /// Representation
    pub fn __repr__(&self) -> String {
        self.__str__()
    }
    
    /// Check equality with another CryptoPyWrapper
    pub fn __eq__(&self, other: &Self) -> bool {
        self.data_hex == other.data_hex
    }
    
    /// Get hash for use in sets/dicts
    pub fn __hash__(&self) -> isize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.data_hex.hash(&mut hasher);
        hasher.finish() as isize
    }
}

/// Enhanced transaction output with hybrid serialization
#[pyclass]
#[derive(Clone)]
pub struct EnhancedTransactionOutput {
    // Native data access
    #[pyo3(get)]
    pub version: u8,
    
    #[pyo3(get)]
    pub minimum_value_promise: u64,
    
    // Structured cryptographic data
    pub features: CryptoPyWrapper,
    pub commitment: CryptoPyWrapper,
    pub proof: Option<CryptoPyWrapper>,
    pub script: CryptoPyWrapper,
    pub sender_offset_public_key: CryptoPyWrapper,
    pub metadata_signature: CryptoPyWrapper,
    pub covenant: CryptoPyWrapper,
    pub encrypted_data: CryptoPyWrapper,
}

#[pymethods]
impl EnhancedTransactionOutput {
    /// Get features as structured object
    #[getter]
    pub fn features(&self) -> CryptoPyWrapper {
        self.features.clone()
    }
    
    /// Get features as hex string (backward compatibility)
    #[getter]
    pub fn features_hex(&self) -> String {
        self.features.data_hex.clone()
    }
    
    /// Get commitment as structured object
    #[getter]
    pub fn commitment(&self) -> CryptoPyWrapper {
        self.commitment.clone()
    }
    
    /// Get commitment as hex string (backward compatibility)
    #[getter]
    pub fn commitment_hex(&self) -> String {
        self.commitment.data_hex.clone()
    }
    
    /// Get proof as structured object (optional)
    #[getter]
    pub fn proof(&self) -> Option<CryptoPyWrapper> {
        self.proof.clone()
    }
    
    /// Get proof as hex string (backward compatibility)
    #[getter]
    pub fn proof_hex(&self) -> Option<String> {
        self.proof.as_ref().map(|p| p.data_hex.clone())
    }
    
    /// Get script as structured object
    #[getter]
    pub fn script(&self) -> CryptoPyWrapper {
        self.script.clone()
    }
    
    /// Get script as hex string (backward compatibility)
    #[getter]
    pub fn script_hex(&self) -> String {
        self.script.data_hex.clone()
    }
    
    /// Get sender offset public key as structured object
    #[getter]
    pub fn sender_offset_public_key(&self) -> CryptoPyWrapper {
        self.sender_offset_public_key.clone()
    }
    
    /// Get sender offset public key as hex string (backward compatibility)
    #[getter]
    pub fn sender_offset_public_key_hex(&self) -> String {
        self.sender_offset_public_key.data_hex.clone()
    }
    
    /// Get metadata signature as structured object
    #[getter]
    pub fn metadata_signature(&self) -> CryptoPyWrapper {
        self.metadata_signature.clone()
    }
    
    /// Get metadata signature as hex string (backward compatibility)
    #[getter]
    pub fn metadata_signature_hex(&self) -> String {
        self.metadata_signature.data_hex.clone()
    }
    
    /// Get covenant as structured object
    #[getter]
    pub fn covenant(&self) -> CryptoPyWrapper {
        self.covenant.clone()
    }
    
    /// Get covenant as hex string (backward compatibility)
    #[getter]
    pub fn covenant_hex(&self) -> String {
        self.covenant.data_hex.clone()
    }
    
    /// Get encrypted data as structured object
    #[getter]
    pub fn encrypted_data(&self) -> CryptoPyWrapper {
        self.encrypted_data.clone()
    }
    
    /// Get encrypted data as hex string (backward compatibility)
    #[getter]
    pub fn encrypted_data_hex(&self) -> String {
        self.encrypted_data.data_hex.clone()
    }
    
    /// Convert to dictionary with format preference
    /// 
    /// Args:
    ///     format: "structured" (default) or "hex"
    /// 
    /// Returns:
    ///     dict: Transaction output data in specified format
    pub fn to_dict(&self, format: Option<&str>) -> PyResult<PyObject> {
        let format_str = format.unwrap_or("structured");
        
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new(py);
            
            // Always include primitive types
            dict.set_item("version", self.version)?;
            dict.set_item("minimum_value_promise", self.minimum_value_promise)?;
            
            match format_str {
                "hex" => {
                    // Backward compatible hex format
                    dict.set_item("features_hex", self.features_hex())?;
                    dict.set_item("commitment_hex", self.commitment_hex())?;
                    dict.set_item("proof_hex", self.proof_hex())?;
                    dict.set_item("script_hex", self.script_hex())?;
                    dict.set_item("sender_offset_public_key_hex", self.sender_offset_public_key_hex())?;
                    dict.set_item("metadata_signature_hex", self.metadata_signature_hex())?;
                    dict.set_item("covenant_hex", self.covenant_hex())?;
                    dict.set_item("encrypted_data_hex", self.encrypted_data_hex())?;
                },
                "structured" | _ => {
                    // Structured format with objects
                    dict.set_item("features", self.features())?;
                    dict.set_item("commitment", self.commitment())?;
                    dict.set_item("proof", self.proof())?;
                    dict.set_item("script", self.script())?;
                    dict.set_item("sender_offset_public_key", self.sender_offset_public_key())?;
                    dict.set_item("metadata_signature", self.metadata_signature())?;
                    dict.set_item("covenant", self.covenant())?;
                    dict.set_item("encrypted_data", self.encrypted_data())?;
                }
            }
            
            Ok(dict.into())
        })
    }
    
    /// String representation
    pub fn __str__(&self) -> String {
        format!("EnhancedTransactionOutput(version={}, value_promise={})", 
                self.version, self.minimum_value_promise)
    }
    
    /// Representation
    pub fn __repr__(&self) -> String {
        self.__str__()
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_crypto_py_wrapper_equality() {
        let wrapper1 = CryptoPyWrapper {
            data_hex: "deadbeef".to_string(),
            data_type: "TestType".to_string(),
        };
        
        let wrapper2 = CryptoPyWrapper {
            data_hex: "deadbeef".to_string(),
            data_type: "TestType".to_string(),
        };
        
        assert!(wrapper1.__eq__(&wrapper2));
    }
}

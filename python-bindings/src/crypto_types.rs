//! Wrapper types for cryptographic structures with performance optimization
//!
//! This module provides optimized wrappers for cryptographic types that are
//! commonly used in the Tari ecosystem, with both structured access and hex conversion.

use pyo3::prelude::*;

/// Enhanced wrapper for public keys with both compressed and extended access
#[pyclass]
#[derive(Clone)]
pub struct EnhancedPublicKey {
    /// Compressed public key bytes (32 bytes)
    pub compressed_bytes: [u8; 32],
}

#[pymethods]
impl EnhancedPublicKey {
    /// Create from hex string
    #[new]
    pub fn new(hex_str: &str) -> PyResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid hex: {}", e)
            ))?;
        
        if bytes.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Public key must be exactly 32 bytes"
            ));
        }
        
        let mut compressed_bytes = [0u8; 32];
        compressed_bytes.copy_from_slice(&bytes);
        
        Ok(Self { compressed_bytes })
    }
    
    /// Get as hex string
    #[getter]
    pub fn hex(&self) -> String {
        hex::encode(self.compressed_bytes)
    }
    
    /// Get raw bytes
    #[getter] 
    pub fn bytes(&self) -> Vec<u8> {
        self.compressed_bytes.to_vec()
    }
    
    /// Check if this is a valid public key (basic validation)
    pub fn is_valid(&self) -> bool {
        // Basic check - not all zeros
        !self.compressed_bytes.iter().all(|&b| b == 0)
    }
    
    /// String representation
    pub fn __str__(&self) -> String {
        format!("PublicKey({}...)", &self.hex()[..8])
    }
    
    /// Representation
    pub fn __repr__(&self) -> String {
        format!("EnhancedPublicKey('{}')", self.hex())
    }
    
    /// Equality comparison
    pub fn __eq__(&self, other: &Self) -> bool {
        self.compressed_bytes == other.compressed_bytes
    }
    
    /// Hash for use in collections
    pub fn __hash__(&self) -> isize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.compressed_bytes.hash(&mut hasher);
        hasher.finish() as isize
    }
}

/// Enhanced wrapper for commitments with value and blinding factor access
#[pyclass]
#[derive(Clone)]
pub struct EnhancedCommitment {
    /// Compressed commitment bytes (32 bytes)
    pub commitment_bytes: [u8; 32],
}

#[pymethods]
impl EnhancedCommitment {
    /// Create from hex string
    #[new]
    pub fn new(hex_str: &str) -> PyResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid hex: {}", e)
            ))?;
        
        if bytes.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Commitment must be exactly 32 bytes"
            ));
        }
        
        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&bytes);
        
        Ok(Self { commitment_bytes })
    }
    
    /// Get as hex string
    #[getter]
    pub fn hex(&self) -> String {
        hex::encode(self.commitment_bytes)
    }
    
    /// Get raw bytes
    #[getter]
    pub fn bytes(&self) -> Vec<u8> {
        self.commitment_bytes.to_vec()
    }
    
    /// String representation
    pub fn __str__(&self) -> String {
        format!("Commitment({}...)", &self.hex()[..8])
    }
    
    /// Representation
    pub fn __repr__(&self) -> String {
        format!("EnhancedCommitment('{}')", self.hex())
    }
    
    /// Equality comparison
    pub fn __eq__(&self, other: &Self) -> bool {
        self.commitment_bytes == other.commitment_bytes
    }
    
    /// Hash for use in collections
    pub fn __hash__(&self) -> isize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.commitment_bytes.hash(&mut hasher);
        hasher.finish() as isize
    }
}

/// Enhanced wrapper for signatures with verification capabilities
#[pyclass]
#[derive(Clone)]
pub struct EnhancedSignature {
    /// Signature bytes (64 bytes for EdDSA)
    pub signature_bytes: Vec<u8>,
}

#[pymethods]
impl EnhancedSignature {
    /// Create from hex string
    #[new]
    pub fn new(hex_str: &str) -> PyResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid hex: {}", e)
            ))?;
        
        if bytes.len() != 64 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Signature must be exactly 64 bytes"
            ));
        }
        
        Ok(Self { signature_bytes: bytes })
    }
    
    /// Get as hex string
    #[getter]
    pub fn hex(&self) -> String {
        hex::encode(&self.signature_bytes)
    }
    
    /// Get raw bytes
    #[getter]
    pub fn bytes(&self) -> Vec<u8> {
        self.signature_bytes.clone()
    }
    
    /// Get signature components (r, s)
    pub fn components(&self) -> PyResult<(String, String)> {
        if self.signature_bytes.len() != 64 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid signature length"
            ));
        }
        
        let r = hex::encode(&self.signature_bytes[..32]);
        let s = hex::encode(&self.signature_bytes[32..]);
        
        Ok((r, s))
    }
    
    /// String representation
    pub fn __str__(&self) -> String {
        format!("Signature({}...)", &self.hex()[..8])
    }
    
    /// Representation
    pub fn __repr__(&self) -> String {
        format!("EnhancedSignature('{}')", self.hex())
    }
    
    /// Equality comparison
    pub fn __eq__(&self, other: &Self) -> bool {
        self.signature_bytes == other.signature_bytes
    }
    
    /// Hash for use in collections
    pub fn __hash__(&self) -> isize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.signature_bytes.hash(&mut hasher);
        hasher.finish() as isize
    }
}

/// Enhanced wrapper for range proofs with verification metadata
#[pyclass]
#[derive(Clone)]
pub struct EnhancedRangeProof {
    /// Range proof bytes (variable length)
    pub proof_bytes: Vec<u8>,
}

#[pymethods]
impl EnhancedRangeProof {
    /// Create from hex string
    #[new]
    pub fn new(hex_str: &str) -> PyResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid hex: {}", e)
            ))?;
        
        Ok(Self { proof_bytes: bytes })
    }
    
    /// Get as hex string
    #[getter]
    pub fn hex(&self) -> String {
        hex::encode(&self.proof_bytes)
    }
    
    /// Get raw bytes
    #[getter]
    pub fn bytes(&self) -> Vec<u8> {
        self.proof_bytes.clone()
    }
    
    /// Get proof size in bytes
    #[getter]
    pub fn size(&self) -> usize {
        self.proof_bytes.len()
    }
    
    /// Check if proof is empty
    pub fn is_empty(&self) -> bool {
        self.proof_bytes.is_empty()
    }
    
    /// String representation
    pub fn __str__(&self) -> String {
        format!("RangeProof({} bytes, {}...)", 
                self.size(), 
                &self.hex()[..std::cmp::min(8, self.hex().len())])
    }
    
    /// Representation
    pub fn __repr__(&self) -> String {
        format!("EnhancedRangeProof('{}' - {} bytes)", 
                &self.hex()[..std::cmp::min(16, self.hex().len())], 
                self.size())
    }
    
    /// Equality comparison
    pub fn __eq__(&self, other: &Self) -> bool {
        self.proof_bytes == other.proof_bytes
    }
    
    /// Hash for use in collections
    pub fn __hash__(&self) -> isize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.proof_bytes.hash(&mut hasher);
        hasher.finish() as isize
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_enhanced_public_key() {
        let hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let pubkey = EnhancedPublicKey::new(hex).unwrap();
        
        assert_eq!(pubkey.hex(), hex);
        assert!(pubkey.is_valid());
    }
    
    #[test]
    fn test_enhanced_signature_components() {
        let hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefcafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";
        let signature = EnhancedSignature::new(hex).unwrap();
        
        let (r, s) = signature.components().unwrap();
        assert_eq!(r.len(), 64); // 32 bytes * 2 hex chars
        assert_eq!(s.len(), 64); // 32 bytes * 2 hex chars
    }
}

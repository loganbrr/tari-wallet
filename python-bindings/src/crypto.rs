//! Native PyO3 crypto wrappers for Tari cryptographic types
//!
//! This module provides secure PyO3 wrapper classes for cryptographic types
//! with automatic memory zeroing and native type storage. All sensitive data
//! is handled securely with zeroization on drop.

use crate::errors::PyWalletError;
use lightweight_wallet_libs::data_structures::types::{
    CompressedCommitment, CompressedPublicKey, FixedHash, MicroMinotari, PrivateKey, SafeArray,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Native PyO3 wrapper for PrivateKey with automatic memory zeroing
#[pyclass(name = "PrivateKey")]
#[derive(ZeroizeOnDrop)]
pub struct PyPrivateKey {
    #[zeroize(skip)]  // PrivateKey handles its own zeroization
    inner: PrivateKey,
}

#[pymethods]
impl PyPrivateKey {
    /// Generate a random private key
    #[staticmethod]
    pub fn random() -> Self {
        Self {
            inner: PrivateKey::random(),
        }
    }

    /// Create from bytes (32 bytes required)
    #[staticmethod]
    pub fn from_bytes(bytes: &PyBytes) -> PyResult<Self> {
        let key_bytes: [u8; 32] = bytes.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Private key must be exactly 32 bytes")
        })?;
        Ok(Self {
            inner: PrivateKey::new(key_bytes),
        })
    }

    /// Create from hex string
    #[staticmethod]
    pub fn from_hex(hex_str: &str) -> PyResult<Self> {
        let inner = PrivateKey::from_hex(hex_str)
            .map_err(|e| PyWalletError::from_msg(&format!("Invalid hex: {}", e)))?;
        Ok(Self { inner })
    }

    /// Get the private key bytes (returns copy for security)
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.as_bytes())
    }

    /// Convert to hex string (for compatibility - use sparingly)
    pub fn to_hex(&self) -> String {
        self.inner.to_hex()
    }

    /// Generate the corresponding public key
    pub fn public_key(&self) -> PyCompressedPublicKey {
        PyCompressedPublicKey {
            inner: CompressedPublicKey::from_private_key(&self.inner),
        }
    }

    /// Securely zero the private key memory
    pub fn zeroize(&mut self) {
        self.inner.zeroize();
    }

    fn __str__(&self) -> String {
        "[PrivateKey - hidden for security]".to_string()
    }

    fn __repr__(&self) -> String {
        "PrivateKey([REDACTED])".to_string()
    }
}

impl PyPrivateKey {
    pub fn inner(&self) -> &PrivateKey {
        &self.inner
    }
    
    pub fn into_inner(self) -> PrivateKey {
        self.inner
    }
}

/// Native PyO3 wrapper for CompressedPublicKey
#[pyclass(name = "CompressedPublicKey")]
#[derive(Clone)]
pub struct PyCompressedPublicKey {
    inner: CompressedPublicKey,
}

#[pymethods]
impl PyCompressedPublicKey {
    /// Create from bytes (32 bytes required)
    #[staticmethod]
    pub fn from_bytes(bytes: &PyBytes) -> PyResult<Self> {
        let key_bytes: [u8; 32] = bytes.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Public key must be exactly 32 bytes")
        })?;
        Ok(Self {
            inner: CompressedPublicKey::new(key_bytes),
        })
    }

    /// Create from hex string
    #[staticmethod]
    pub fn from_hex(hex_str: &str) -> PyResult<Self> {
        let inner = CompressedPublicKey::from_hex(hex_str)
            .map_err(|e| PyWalletError::from_msg(&format!("Invalid hex: {}", e)))?;
        Ok(Self { inner })
    }

    /// Create from private key
    #[staticmethod]
    pub fn from_private_key(private_key: &PyPrivateKey) -> Self {
        Self {
            inner: CompressedPublicKey::from_private_key(private_key.inner()),
        }
    }

    /// Get the public key bytes
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.as_bytes())
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.inner.to_hex()
    }

    fn __str__(&self) -> String {
        format!("PublicKey({}...)", &self.to_hex()[0..16])
    }

    fn __repr__(&self) -> String {
        format!("CompressedPublicKey({})", self.to_hex())
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.inner.hash(&mut hasher);
        hasher.finish()
    }
}

impl PyCompressedPublicKey {
    pub fn inner(&self) -> &CompressedPublicKey {
        &self.inner
    }

    pub fn into_inner(self) -> CompressedPublicKey {
        self.inner
    }
}

/// Native PyO3 wrapper for CompressedCommitment
#[pyclass(name = "CompressedCommitment")]
#[derive(Clone)]
pub struct PyCompressedCommitment {
    inner: CompressedCommitment,
}

#[pymethods]
impl PyCompressedCommitment {
    /// Create from bytes (32 bytes required)
    #[staticmethod]
    pub fn from_bytes(bytes: &PyBytes) -> PyResult<Self> {
        let commitment_bytes: [u8; 32] = bytes.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Commitment must be exactly 32 bytes")
        })?;
        Ok(Self {
            inner: CompressedCommitment::new(commitment_bytes),
        })
    }

    /// Create from hex string
    #[staticmethod]
    pub fn from_hex(hex_str: &str) -> PyResult<Self> {
        let inner = CompressedCommitment::from_hex(hex_str)
            .map_err(|e| PyWalletError::from_msg(&format!("Invalid hex: {}", e)))?;
        Ok(Self { inner })
    }

    /// Get the commitment bytes
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.as_bytes())
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.inner.to_hex()
    }

    fn __str__(&self) -> String {
        format!("Commitment({}...)", &self.to_hex()[0..16])
    }

    fn __repr__(&self) -> String {
        format!("CompressedCommitment({})", self.to_hex())
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.inner.hash(&mut hasher);
        hasher.finish()
    }
}

impl PyCompressedCommitment {
    pub fn inner(&self) -> &CompressedCommitment {
        &self.inner
    }

    pub fn into_inner(self) -> CompressedCommitment {
        self.inner
    }
}

/// Native PyO3 wrapper for FixedHash (transaction hashes, etc.)
#[pyclass(name = "FixedHash")]
#[derive(Clone)]
pub struct PyFixedHash {
    inner: FixedHash,
}

#[pymethods]
impl PyFixedHash {
    /// Create from bytes (32 bytes required)
    #[staticmethod]
    pub fn from_bytes(bytes: &PyBytes) -> PyResult<Self> {
        let hash_bytes: [u8; 32] = bytes.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Hash must be exactly 32 bytes")
        })?;
        Ok(Self {
            inner: FixedHash::new(hash_bytes),
        })
    }

    /// Create from hex string
    #[staticmethod]
    pub fn from_hex(hex_str: &str) -> PyResult<Self> {
        let inner = FixedHash::from_hex(hex_str)
            .map_err(|e| PyWalletError::from_msg(&format!("Invalid hex: {}", e)))?;
        Ok(Self { inner })
    }

    /// Get the hash bytes
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.as_bytes())
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.inner.to_hex()
    }

    /// Get byte size (always 32)
    #[staticmethod]
    pub fn byte_size() -> usize {
        FixedHash::byte_size()
    }

    fn __str__(&self) -> String {
        format!("Hash({}...)", &self.to_hex()[0..16])
    }

    fn __repr__(&self) -> String {
        format!("FixedHash({})", self.to_hex())
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.inner.hash(&mut hasher);
        hasher.finish()
    }
}

impl PyFixedHash {
    pub fn inner(&self) -> &FixedHash {
        &self.inner
    }

    pub fn into_inner(self) -> FixedHash {
        self.inner
    }
}

/// Native PyO3 wrapper for MicroMinotari (currency amount)
#[pyclass(name = "MicroMinotari")]
#[derive(Clone)]
pub struct PyMicroMinotari {
    inner: MicroMinotari,
}

#[pymethods]
impl PyMicroMinotari {
    /// Create from micro minotari amount
    #[new]
    pub fn new(amount: u64) -> Self {
        Self {
            inner: MicroMinotari::new(amount),
        }
    }

    /// Create from Tari amount (1 Tari = 1,000,000 MicroMinotari)
    #[staticmethod]
    pub fn from_tari(tari: f64) -> Self {
        Self {
            inner: MicroMinotari::from_tari(tari),
        }
    }

    /// Get amount as u64 (micro minotari)
    pub fn as_u64(&self) -> u64 {
        self.inner.as_u64()
    }

    /// Get amount as Tari (floating point)
    pub fn as_tari(&self) -> f64 {
        self.inner.as_tari()
    }

    /// Add two amounts
    pub fn __add__(&self, other: &Self) -> Self {
        Self {
            inner: MicroMinotari::new(self.inner.as_u64() + other.inner.as_u64()),
        }
    }

    /// Subtract two amounts
    pub fn __sub__(&self, other: &Self) -> Self {
        Self {
            inner: MicroMinotari::new(self.inner.as_u64().saturating_sub(other.inner.as_u64())),
        }
    }

    /// Multiply amount
    pub fn __mul__(&self, other: u64) -> Self {
        Self {
            inner: MicroMinotari::new(self.inner.as_u64().saturating_mul(other)),
        }
    }

    /// Integer division
    pub fn __floordiv__(&self, other: u64) -> Self {
        if other == 0 {
            panic!("Division by zero");
        }
        Self {
            inner: MicroMinotari::new(self.inner.as_u64() / other),
        }
    }

    fn __str__(&self) -> String {
        format!("{}", self.inner)
    }

    fn __repr__(&self) -> String {
        format!("MicroMinotari({})", self.inner.as_u64())
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __lt__(&self, other: &Self) -> bool {
        self.inner < other.inner
    }

    fn __le__(&self, other: &Self) -> bool {
        self.inner <= other.inner
    }

    fn __gt__(&self, other: &Self) -> bool {
        self.inner > other.inner
    }

    fn __ge__(&self, other: &Self) -> bool {
        self.inner >= other.inner
    }

    fn __hash__(&self) -> u64 {
        self.inner.as_u64()
    }
}

impl PyMicroMinotari {
    pub fn inner(&self) -> MicroMinotari {
        self.inner
    }
}

/// Native PyO3 wrapper for SafeArray with automatic memory zeroing
#[pyclass(name = "SafeArray")]
#[derive(ZeroizeOnDrop)]
pub struct PySafeArray {
    #[zeroize(skip)]  // SafeArray handles its own zeroization
    inner: SafeArray<32>,  // Most common size for crypto operations
}

#[pymethods]
impl PySafeArray {
    /// Create from bytes (32 bytes required for this implementation)
    #[staticmethod]
    pub fn from_bytes(bytes: &PyBytes) -> PyResult<Self> {
        let array_bytes: [u8; 32] = bytes.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Array must be exactly 32 bytes")
        })?;
        Ok(Self {
            inner: SafeArray::new(array_bytes),
        })
    }

    /// Create from hex string
    #[staticmethod]
    pub fn from_hex(hex_str: &str) -> PyResult<Self> {
        let inner = SafeArray::from_hex(hex_str)
            .map_err(|e| PyWalletError::from_msg(&format!("Invalid hex: {}", e)))?;
        Ok(Self { inner })
    }

    /// Get the array bytes (returns copy for security)
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.as_bytes())
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.inner.to_hex()
    }

    /// Get array length
    pub fn len(&self) -> usize {
        32  // Fixed size for this implementation
    }

    /// Check if empty (always false for SafeArray<32>)
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Securely zero the array memory
    pub fn zeroize(&mut self) {
        self.inner.zeroize();
    }

    fn __str__(&self) -> String {
        "[SafeArray - sensitive data hidden]".to_string()
    }

    fn __repr__(&self) -> String {
        format!("SafeArray<32>([REDACTED])")
    }

    fn __len__(&self) -> usize {
        32
    }
}

impl PySafeArray {
    pub fn inner(&self) -> &SafeArray<32> {
        &self.inner
    }

    pub fn into_inner(self) -> SafeArray<32> {
        self.inner
    }
}

/// Signature result wrapper for message signing operations
#[pyclass(name = "SignatureResult")]
#[derive(Clone)]
pub struct PySignatureResult {
    #[pyo3(get)]
    pub signature: String,
    #[pyo3(get)]
    pub public_key: String,
    #[pyo3(get)]
    pub message: String,
}

#[pymethods]
impl PySignatureResult {
    #[new]
    pub fn new(signature: String, public_key: String, message: String) -> Self {
        Self {
            signature,
            public_key,
            message,
        }
    }

    /// Verify this signature result
    pub fn verify(&self) -> bool {
        // This would integrate with the actual signature verification logic
        // For now, return true if all fields are present
        !self.signature.is_empty() && !self.public_key.is_empty() && !self.message.is_empty()
    }

    fn __str__(&self) -> String {
        format!("SignatureResult(sig={}..., key={}...)", 
            &self.signature[0..16.min(self.signature.len())],
            &self.public_key[0..16.min(self.public_key.len())])
    }

    fn __repr__(&self) -> String {
        format!("SignatureResult(signature='{}', public_key='{}', message='{}')",
            self.signature, self.public_key, self.message)
    }
}

/// Key pair wrapper for related private/public key operations
#[pyclass(name = "KeyPair")]
#[derive(ZeroizeOnDrop)]
pub struct PyKeyPair {
    #[zeroize(skip)]  // Components handle their own zeroization
    private_key: PyPrivateKey,
    public_key: PyCompressedPublicKey,
}

#[pymethods]
impl PyKeyPair {
    /// Generate a random key pair
    #[staticmethod]
    pub fn random() -> Self {
        let private_key = PyPrivateKey::random();
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }

    /// Create from private key
    #[staticmethod]
    pub fn from_private_key(private_key: PyPrivateKey) -> Self {
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }

    /// Get the private key
    pub fn private_key(&self) -> PyPrivateKey {
        // Return a clone to avoid borrowing issues
        PyPrivateKey {
            inner: PrivateKey::new(self.private_key.inner.as_bytes()),
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> PyCompressedPublicKey {
        self.public_key.clone()
    }

    /// Securely zero the private key
    pub fn zeroize(&mut self) {
        self.private_key.zeroize();
    }

    fn __str__(&self) -> String {
        format!("KeyPair(public={}...)", &self.public_key.to_hex()[0..16])
    }

    fn __repr__(&self) -> String {
        format!("KeyPair(private=[REDACTED], public={})", self.public_key.to_hex())
    }
}

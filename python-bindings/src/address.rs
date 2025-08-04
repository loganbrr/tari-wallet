//! Native PyO3 address wrappers for Tari address types
//!
//! This module provides clean PyO3 wrapper classes that store native Rust types
//! internally instead of relying on hex string serialization. This improves
//! performance and type safety while maintaining backward compatibility through
//! optional conversion methods.

use crate::errors::PyWalletError;
use lightweight_wallet_libs::data_structures::address::{
    DualAddress, Network, SingleAddress, TariAddress, TariAddressFeatures,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use lightweight_wallet_libs::data_structures::types::CompressedPublicKey;

/// Native PyO3 wrapper for TariAddressFeatures
#[pyclass(name = "TariAddressFeatures")]
#[derive(Clone)]
pub struct PyTariAddressFeatures {
    inner: TariAddressFeatures,
}

#[pymethods]
impl PyTariAddressFeatures {
    /// Create features for interactive-only addresses
    #[staticmethod]
    pub fn interactive_only() -> Self {
        Self {
            inner: TariAddressFeatures::create_interactive_only(),
        }
    }

    /// Create features for one-sided-only addresses
    #[staticmethod]
    pub fn one_sided_only() -> Self {
        Self {
            inner: TariAddressFeatures::create_one_sided_only(),
        }
    }

    /// Create features for interactive and one-sided addresses
    #[staticmethod]
    pub fn interactive_and_one_sided() -> Self {
        Self {
            inner: TariAddressFeatures::create_interactive_and_one_sided(),
        }
    }

    /// Create from raw bits (advanced usage)
    #[staticmethod]
    pub fn from_bits(bits: u8) -> PyResult<Self> {
        TariAddressFeatures::from_bits(bits)
            .map(|inner| Self { inner })
            .ok_or_else(|| PyWalletError::from_msg("Invalid feature bits").into())
    }

    /// Check if interactive features are enabled
    pub fn is_interactive(&self) -> bool {
        self.inner.is_interactive()
    }

    /// Check if one-sided features are enabled
    pub fn is_one_sided(&self) -> bool {
        self.inner.is_one_sided()
    }

    /// Get raw bits value
    pub fn to_bits(&self) -> u8 {
        self.inner.0
    }

    /// Convert to hex string (optional compatibility method)
    pub fn to_hex(&self) -> String {
        format!("{:02x}", self.inner.0)
    }

    fn __str__(&self) -> String {
        format!("TariAddressFeatures(interactive={}, one_sided={})", 
            self.is_interactive(), self.is_one_sided())
    }

    fn __repr__(&self) -> String {
        format!("TariAddressFeatures(bits=0x{:02x})", self.inner.0)
    }
}

impl PyTariAddressFeatures {
    pub fn inner(&self) -> TariAddressFeatures {
        self.inner
    }
}

/// Native PyO3 wrapper for Network
#[pyclass(name = "Network")]
#[derive(Clone)]
pub struct PyNetwork {
    inner: Network,
}

#[pymethods]
impl PyNetwork {
    /// MainNet network
    #[classattr]
    pub const MAINNET: u8 = 0x00;

    /// StageNet network (testing)
    #[classattr]
    pub const STAGENET: u8 = 0x01;

    /// NextNet network (experimental)
    #[classattr]
    pub const NEXTNET: u8 = 0x02;

    /// LocalNet network (local development)
    #[classattr]
    pub const LOCALNET: u8 = 0x10;

    /// Igor testnet
    #[classattr]
    pub const IGOR: u8 = 0x24;

    /// Esmeralda testnet (default)
    #[classattr]
    pub const ESMERALDA: u8 = 0x26;

    /// Create MainNet
    #[staticmethod]
    pub fn mainnet() -> Self {
        Self { inner: Network::MainNet }
    }

    /// Create StageNet
    #[staticmethod]
    pub fn stagenet() -> Self {
        Self { inner: Network::StageNet }
    }

    /// Create NextNet
    #[staticmethod]
    pub fn nextnet() -> Self {
        Self { inner: Network::NextNet }
    }

    /// Create LocalNet
    #[staticmethod]
    pub fn localnet() -> Self {
        Self { inner: Network::LocalNet }
    }

    /// Create Igor testnet
    #[staticmethod]
    pub fn igor() -> Self {
        Self { inner: Network::Igor }
    }

    /// Create Esmeralda testnet (default)
    #[staticmethod]
    pub fn esmeralda() -> Self {
        Self { inner: Network::Esmeralda }
    }

    /// Create from byte value
    #[staticmethod]
    pub fn from_byte(byte: u8) -> PyResult<Self> {
        Network::try_from(byte)
            .map(|inner| Self { inner })
            .map_err(|e| PyWalletError::from(e).into())
    }

    /// Create from string name
    #[staticmethod]
    pub fn from_str(name: &str) -> PyResult<Self> {
        name.parse::<Network>()
            .map(|inner| Self { inner })
            .map_err(|e| PyWalletError::from(e).into())
    }

    /// Get byte value
    pub fn to_byte(&self) -> u8 {
        self.inner.as_byte()
    }

    /// Get string key
    pub fn to_key(&self) -> &'static str {
        self.inner.as_key_str()
    }

    /// Convert to hex string (optional compatibility method)
    pub fn to_hex(&self) -> String {
        format!("{:02x}", self.inner.as_byte())
    }

    fn __str__(&self) -> String {
        self.inner.as_key_str().to_string()
    }

    fn __repr__(&self) -> String {
        format!("Network.{}(0x{:02x})", self.to_key(), self.to_byte())
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.to_byte().hash(&mut hasher);
        hasher.finish()
    }
}

impl PyNetwork {
    pub fn inner(&self) -> Network {
        self.inner
    }
}

impl std::hash::Hash for PyNetwork {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Use the byte value for hashing
        self.to_byte().hash(state);
    }
}

impl std::fmt::Display for PyNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner {
            Network::MainNet => write!(f, "mainnet"),
            Network::StageNet => write!(f, "stagenet"),
            Network::NextNet => write!(f, "testnet"),
            Network::LocalNet => write!(f, "localnet"),
            Network::Igor => write!(f, "igor"),
            Network::Esmeralda => write!(f, "esmeralda"),
        }
    }
}

/// Native PyO3 wrapper for TariAddress (enum wrapper)
#[pyclass(name = "TariAddress")]
#[derive(Clone)]
pub struct PyTariAddress {
    inner: TariAddress,
}

#[pymethods]
impl PyTariAddress {
    /// Create a new dual address
    #[staticmethod]
    pub fn new_dual_address(
        view_key: Bound<'_, PyBytes>,
        spend_key: Bound<'_, PyBytes>,
        network: &PyNetwork,
        features: &PyTariAddressFeatures,
        payment_id: Option<Bound<'_, PyBytes>>,
    ) -> PyResult<Self> {
        // Convert PyBytes to CompressedPublicKey
        let view_key_bytes: [u8; 32] = view_key.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("View key must be exactly 32 bytes")
        })?;
        let spend_key_bytes: [u8; 32] = spend_key.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Spend key must be exactly 32 bytes")
        })?;

        let view_key = lightweight_wallet_libs::data_structures::types::CompressedPublicKey::new(view_key_bytes);
        let spend_key = lightweight_wallet_libs::data_structures::types::CompressedPublicKey::new(spend_key_bytes);

        let payment_id_data = payment_id.map(|bytes| bytes.as_bytes().to_vec());

        let inner = TariAddress::new_dual_address(
            view_key,
            spend_key,
            network.inner(),
            features.inner(),
            payment_id_data,
        ).map_err(|e| PyWalletError::from(e))?;

        Ok(Self { inner })
    }

    /// Create a new single address
    #[staticmethod]
    pub fn new_single_address(
        spend_key: Bound<'_, PyBytes>,
        network: &PyNetwork,
        features: &PyTariAddressFeatures,
    ) -> PyResult<Self> {
        let spend_key_bytes: [u8; 32] = spend_key.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Spend key must be exactly 32 bytes")
        })?;

        let spend_key = lightweight_wallet_libs::data_structures::types::CompressedPublicKey::new(spend_key_bytes);

        let inner = TariAddress::new_single_address(
            spend_key,
            network.inner(),
            features.inner(),
        ).map_err(|e| PyWalletError::from(e))?;

        Ok(Self { inner })
    }

    /// Parse from string (auto-detects format: emoji, hex, or base58)
    #[staticmethod]
    pub fn from_string(address_str: &str) -> PyResult<Self> {
        let inner = TariAddress::from_string(address_str)
            .map_err(|e| PyWalletError::from(e))?;
        Ok(Self { inner })
    }

    /// Create from emoji string
    #[staticmethod]
    pub fn from_emoji(emoji_str: &str) -> PyResult<Self> {
        let inner = TariAddress::from_emoji_string(emoji_str)
            .map_err(|e| PyWalletError::from(e))?;
        Ok(Self { inner })
    }

    /// Create from hex string
    #[staticmethod]
    pub fn from_hex(hex_str: &str) -> PyResult<Self> {
        let inner = TariAddress::from_hex(hex_str)
            .map_err(|e| PyWalletError::from(e))?;
        Ok(Self { inner })
    }

    /// Create from base58 string
    #[staticmethod]
    pub fn from_base58(base58_str: &str) -> PyResult<Self> {
        let inner = TariAddress::from_base58(base58_str)
            .map_err(|e| PyWalletError::from(e))?;
        Ok(Self { inner })
    }

    /// Create a single address from spend key
    #[staticmethod]
    pub fn from_spend_key(
        spend_key: Bound<'_, PyBytes>,
        features: &PyTariAddressFeatures,
    ) -> PyResult<Self> {
        let spend_key_bytes: [u8; 32] = spend_key.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Invalid spend key length")
        })?;
        
        // Convert bytes to CompressedPublicKey
        let spend_pub_key = CompressedPublicKey::new(spend_key_bytes);
        
        let address = SingleAddress::new(
            spend_pub_key,
            Network::MainNet, // Default network
            features.inner().clone(),
        ).map_err(|e| PyWalletError::from_msg(&format!("Failed to create single address: {}", e)))?;
        
        Ok(Self { inner: TariAddress::Single(address) })
    }

    /// Create from bytes
    #[staticmethod]
    pub fn from_bytes(bytes: Bound<'_, PyBytes>) -> PyResult<Self> {
        let inner = TariAddress::from_bytes(bytes.as_bytes())
            .map_err(|e| PyWalletError::from_msg(&format!("Failed to parse address: {}", e)))?;
        Ok(Self { inner })
    }

    /// Create a dual address from view and spend keys
    #[staticmethod]
    pub fn from_keys(
        view_key: Bound<'_, PyBytes>,
        spend_key: Bound<'_, PyBytes>,
        features: &PyTariAddressFeatures,
        payment_id: Option<Bound<'_, PyBytes>>,
    ) -> PyResult<Self> {
        let view_key_bytes: [u8; 32] = view_key.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Invalid view key length")
        })?;
        
        let spend_key_bytes: [u8; 32] = spend_key.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Invalid spend key length")
        })?;
        
        let payment_id_data = payment_id.map(|bytes| bytes.as_bytes().to_vec());
        
        // Convert bytes to CompressedPublicKey
        let view_pub_key = CompressedPublicKey::new(view_key_bytes);
        let spend_pub_key = CompressedPublicKey::new(spend_key_bytes);
        
        let address = DualAddress::new(
            view_pub_key,
            spend_pub_key,
            Network::MainNet, // Default network
            features.inner().clone(),
            payment_id_data,
        ).map_err(|e| PyWalletError::from_msg(&format!("Failed to create dual address: {}", e)))?;
        
        Ok(Self { inner: TariAddress::Dual(address) })
    }

    /// Get network
    pub fn network(&self) -> PyNetwork {
        PyNetwork { inner: self.inner.network() }
    }

    /// Get features
    pub fn features(&self) -> PyTariAddressFeatures {
        PyTariAddressFeatures { inner: self.inner.features() }
    }

    /// Get public view key as bytes
    pub fn public_view_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        self.inner.public_view_key()
            .map(|key| PyBytes::new(py, &key.as_bytes()))
            .unwrap_or_else(|| PyBytes::new(py, &[]))
    }

    /// Get public spend key as bytes
    pub fn public_spend_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.public_spend_key().as_bytes())
    }

    /// Check if this is a dual address
    pub fn is_dual(&self) -> bool {
        matches!(self.inner, TariAddress::Dual(_))
    }

    /// Check if this is a single address
    pub fn is_single(&self) -> bool {
        matches!(self.inner, TariAddress::Single(_))
    }

    /// Get size in bytes
    pub fn size(&self) -> usize {
        self.inner.get_size()
    }

    /// Convert to emoji string
    pub fn to_emoji(&self) -> String {
        self.inner.to_emoji_string()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.inner.to_hex()
    }

    /// Convert to base58 string
    pub fn to_base58(&self) -> String {
        self.inner.to_base58()
    }

    /// Convert to bytes
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_vec())
    }

    fn __str__(&self) -> String {
        // Default to emoji representation
        self.to_emoji()
    }

    fn __repr__(&self) -> String {
        let addr_type = if self.is_dual() { "Dual" } else { "Single" };
        format!("TariAddress.{}({}...)", addr_type, &self.to_hex()[0..16])
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.to_hex().hash(&mut hasher);
        hasher.finish()
    }
}

impl PyTariAddress {
    pub fn inner(&self) -> &TariAddress {
        &self.inner
    }

    pub fn into_inner(self) -> TariAddress {
        self.inner
    }
}

impl std::hash::Hash for PyTariAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Use the hex representation for hashing
        self.to_hex().hash(state);
    }
}

/// Native PyO3 wrapper for DualAddress
#[pyclass(name = "DualAddress")]
#[derive(Clone)]
pub struct PyDualAddress {
    inner: DualAddress,
}

#[pymethods]
impl PyDualAddress {
    /// Create a new dual address
    #[staticmethod]
    pub fn new(
        view_key: Bound<'_, PyBytes>,
        spend_key: Bound<'_, PyBytes>,
        network: &PyNetwork,
        features: &PyTariAddressFeatures,
        payment_id: Option<Bound<'_, PyBytes>>,
    ) -> PyResult<Self> {
        let view_key_bytes: [u8; 32] = view_key.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("View key must be exactly 32 bytes")
        })?;
        let spend_key_bytes: [u8; 32] = spend_key.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Spend key must be exactly 32 bytes")
        })?;

        let view_key = CompressedPublicKey::new(view_key_bytes);
        let spend_key = CompressedPublicKey::new(spend_key_bytes);

        let payment_id_data = payment_id.map(|bytes| bytes.as_bytes().to_vec());

        let inner = DualAddress::new(
            view_key,
            spend_key,
            network.inner(),
            features.inner(),
            payment_id_data,
        ).map_err(|e| PyWalletError::from(e))?;

        Ok(Self { inner })
    }

    /// Create from emoji string
    #[staticmethod]
    pub fn from_emoji(emoji_str: &str) -> PyResult<Self> {
        let inner = DualAddress::from_emoji_string(emoji_str)
            .map_err(|e| PyWalletError::from(e))?;
        Ok(Self { inner })
    }

    /// Create from hex string
    #[staticmethod]
    pub fn from_hex(hex_str: &str) -> PyResult<Self> {
        let inner = DualAddress::from_hex(hex_str)
            .map_err(|e| PyWalletError::from(e))?;
        Ok(Self { inner })
    }

    /// Create from bytes
    #[staticmethod]
    pub fn from_bytes(bytes: Bound<'_, PyBytes>) -> PyResult<Self> {
        let inner = DualAddress::from_bytes(bytes.as_bytes())
            .map_err(|e| PyWalletError::from_msg(&format!("Failed to parse dual address: {}", e)))?;
        Ok(Self { inner })
    }

    /// Get network
    pub fn network(&self) -> PyNetwork {
        PyNetwork { inner: self.inner.network() }
    }

    /// Get features
    pub fn features(&self) -> PyTariAddressFeatures {
        PyTariAddressFeatures { inner: self.inner.features() }
    }

    /// Get public view key as bytes
    pub fn public_view_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.public_view_key().as_bytes())
    }

    /// Get public spend key as bytes
    pub fn public_spend_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.public_spend_key().as_bytes())
    }

    /// Get payment ID user data
    pub fn payment_id_user_data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.get_payment_id_user_data_bytes())
    }

    /// Convert to emoji string
    pub fn to_emoji(&self) -> String {
        self.inner.to_emoji_string()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.inner.to_hex()
    }

    /// Convert to base58 string
    pub fn to_base58(&self) -> String {
        self.inner.to_base58()
    }

    /// Convert to bytes
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_vec())
    }

    fn __str__(&self) -> String {
        self.to_emoji()
    }

    fn __repr__(&self) -> String {
        format!("DualAddress({}...)", &self.to_hex()[0..16])
    }
}

/// Native PyO3 wrapper for SingleAddress
#[pyclass(name = "SingleAddress")]
#[derive(Clone)]
pub struct PySingleAddress {
    inner: SingleAddress,
}

#[pymethods]
impl PySingleAddress {
    /// Create a new single address
    #[staticmethod]
    pub fn new(
        spend_key: Bound<'_, PyBytes>,
        network: &PyNetwork,
        features: &PyTariAddressFeatures,
    ) -> PyResult<Self> {
        let spend_key_bytes: [u8; 32] = spend_key.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Spend key must be exactly 32 bytes")
        })?;

        let spend_key = CompressedPublicKey::new(spend_key_bytes);

        let inner = SingleAddress::new(
            spend_key,
            network.inner(),
            features.inner(),
        ).map_err(|e| PyWalletError::from(e))?;

        Ok(Self { inner })
    }

    /// Create from emoji string
    #[staticmethod]
    pub fn from_emoji(emoji_str: &str) -> PyResult<Self> {
        let inner = SingleAddress::from_emoji_string(emoji_str)
            .map_err(|e| PyWalletError::from(e))?;
        Ok(Self { inner })
    }

    /// Create from hex string
    #[staticmethod]
    pub fn from_hex(hex_str: &str) -> PyResult<Self> {
        let inner = SingleAddress::from_hex(hex_str)
            .map_err(|e| PyWalletError::from(e))?;
        Ok(Self { inner })
    }

    /// Create from bytes
    #[staticmethod]
    pub fn from_bytes(bytes: Bound<'_, PyBytes>) -> PyResult<Self> {
        let inner = SingleAddress::from_bytes(bytes.as_bytes())
            .map_err(|e| PyWalletError::from_msg(&format!("Failed to parse single address: {}", e)))?;
        Ok(Self { inner })
    }

    /// Get network
    pub fn network(&self) -> PyNetwork {
        PyNetwork { inner: self.inner.network() }
    }

    /// Get features
    pub fn features(&self) -> PyTariAddressFeatures {
        PyTariAddressFeatures { inner: self.inner.features() }
    }

    /// Get public spend key as bytes
    pub fn public_spend_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.public_spend_key().as_bytes())
    }

    /// Convert to emoji string
    pub fn to_emoji(&self) -> String {
        self.inner.to_emoji_string()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.inner.to_hex()
    }

    /// Convert to base58 string
    pub fn to_base58(&self) -> String {
        self.inner.to_base58()
    }

    /// Convert to bytes
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_vec())
    }

    fn __str__(&self) -> String {
        self.to_emoji()
    }

    fn __repr__(&self) -> String {
        format!("SingleAddress({}...)", &self.to_hex()[0..16])
    }
}

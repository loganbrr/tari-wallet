//! Tari Lightweight Wallet Python Bindings - Native Object API
//!
//! Enhanced PyO3-based bindings providing native Python objects instead of hex strings.
//! This improves performance, type safety, and usability while maintaining backward
//! compatibility through optional conversion methods.
//!
//! ## Key Features
//!
//! - **Native Objects**: Returns PyTariAddress, PyPrivateKey, etc. instead of hex strings
//! - **Memory Safety**: Automatic zeroization of sensitive data on drop
//! - **Type Safety**: Strong typing prevents common errors
//! - **Performance**: Zero-copy operations where possible
//! - **Compatibility**: Optional hex conversion methods for legacy code
//!
//! ## Core Modules
//!
//! - [`PyTariWallet`]: Enhanced wallet with native object API  
//! - [`PyTariAddress`]: Native address types with format conversion
//! - [`PyPrivateKey`]: Secure private key handling with zeroization
//! - [`PyCompressedPublicKey`]: Public key operations
//! - [`PyTransactionOutput`]: Transaction components
//!
//! ## Security Design
//!
//! All sensitive data is handled securely with automatic memory zeroing on drop.
//! Private keys and other sensitive types implement ZeroizeOnDrop to prevent
//! memory leaks of cryptographic material.
//!
//! ## Usage Examples
//!
//! ```python
//! # Create a new wallet
//! wallet = TariWallet.generate_new_with_seed_phrase()
//! 
//! # Get native address object
//! features = TariAddressFeatures.interactive_and_one_sided()
//! address = wallet.get_dual_address(features, None)
//! 
//! # Address provides multiple formats
//! emoji_str = address.to_emoji()     # Emoji format
//! hex_str = address.to_hex()         # Hex format  
//! base58_str = address.to_base58()   # Base58 format
//! 
//! # Type-safe operations
//! network = address.network()        # Returns Network object
//! features = address.features()      # Returns TariAddressFeatures object
//! 
//! # Secure key handling
//! private_key = wallet.spend_private_key()  # Returns PrivateKey object
//! # private_key automatically zeros memory on drop
//! ```

use pyo3::prelude::*;
use pyo3::exceptions::PyException;
use lightweight_wallet_libs::errors::LightweightWalletError;

// Simple error type for wallet operations
#[derive(Debug, Clone)]
pub struct PyWalletError {
    message: String,
}

impl PyWalletError {
    pub fn from_msg(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl From<LightweightWalletError> for PyWalletError {
    fn from(error: LightweightWalletError) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}

impl From<PyWalletError> for PyErr {
    fn from(error: PyWalletError) -> Self {
        PyException::new_err(error.message)
    }
}

// Import all modules
mod address;
mod crypto;
mod transaction;
mod wallet;
// mod errors; // File was deleted

// Re-export core types
pub use address::{
    PyTariAddress, PyTariAddressFeatures, PyNetwork, 
    PyDualAddress, PySingleAddress
};
pub use crypto::{
    PyPrivateKey, PyCompressedPublicKey, PyCompressedCommitment, 
    PyFixedHash, PyMicroMinotari, PySafeArray, PySignatureResult, PyKeyPair,
    PyEnhancedSignature, PyEnhancedRangeProof
};
pub use transaction::{
    PyTransactionOutput, PyOutputFeatures, PyOutputType, PyScript, 
    PyCovenant, PySignature, PyRangeProof, PyEncryptedData
};
pub use wallet::{PyTariWallet, PyWalletGenerationResult};
// PyWalletError is defined in this module

// Legacy module compatibility (for existing integrations)
mod types;
mod error_hierarchy;
mod secure_wrapper;

#[macro_use]
mod field_extraction_macros;
mod transaction_utils;
// mod storage; // Temporarily disabled due to async threading issues
mod validation;
mod key_derivation;
// mod key_manager; // Temporarily disabled due to syntax issues
mod stealth_types;
mod stealth_address;
mod extraction;
mod batch_operations;
mod utils;
// Legacy types removed - using native types only
pub use validation::{BatchValidationResult};
pub use key_derivation::KeyDerivationPath;
// pub use key_manager::TariKeyManager; // Temporarily disabled
pub use stealth_types::{StealthAddressInfo, StealthScanResult, StealthScanResultIterator};
pub use stealth_address::TariStealthAddress;
pub use extraction::{
    PyExtractionConfig, PyBatchValidationOptions, PyOutputValidationResult, 
    PyBatchValidationSummary, PyBatchValidationResult
};

/// Python module definition
#[pymodule]
fn lightweight_wallet_libpy(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Core native object classes
    m.add_class::<PyTariWallet>()?;
    m.add_class::<PyWalletGenerationResult>()?;
    
    // Address types
    m.add_class::<PyTariAddress>()?;
    m.add_class::<PyTariAddressFeatures>()?;
    m.add_class::<PyNetwork>()?;
    m.add_class::<PyDualAddress>()?;
    m.add_class::<PySingleAddress>()?;
    
    // Crypto types
    m.add_class::<PyPrivateKey>()?;
    m.add_class::<PyCompressedPublicKey>()?;
    m.add_class::<PyCompressedCommitment>()?;
    m.add_class::<PyFixedHash>()?;
    m.add_class::<PyMicroMinotari>()?;
    m.add_class::<PySafeArray>()?;
    m.add_class::<PySignatureResult>()?;
    m.add_class::<PyKeyPair>()?;
    m.add_class::<PyEnhancedSignature>()?;
    m.add_class::<PyEnhancedRangeProof>()?;

    
    // Transaction types
    m.add_class::<PyTransactionOutput>()?;
    m.add_class::<PyOutputFeatures>()?;
    m.add_class::<PyOutputType>()?;
    m.add_class::<PyScript>()?;
    m.add_class::<PyCovenant>()?;
    m.add_class::<PySignature>()?;
    m.add_class::<PyRangeProof>()?;
    m.add_class::<PyEncryptedData>()?;
    
    // Error types - PyWalletError removed
    
    // Legacy compatibility classes removed - using native types only
    m.add_class::<BatchValidationResult>()?;
    m.add_class::<KeyDerivationPath>()?;
    // m.add_class::<TariKeyManager>()?; // Temporarily disabled
    m.add_class::<StealthAddressInfo>()?;
    m.add_class::<StealthScanResult>()?;
    m.add_class::<StealthScanResultIterator>()?;
    m.add_class::<TariStealthAddress>()?;
    m.add_class::<PyExtractionConfig>()?;
    m.add_class::<PyBatchValidationOptions>()?;
    m.add_class::<PyOutputValidationResult>()?;
    m.add_class::<PyBatchValidationSummary>()?;
    m.add_class::<PyBatchValidationResult>()?;

    // Register batch operations functions
    crate::batch_operations::register_batch_operation_functions(py, m)?;

    // Validation classes
    m.add_class::<crate::validation::PyMinimumValuePromiseValidationOptions>()?;
    m.add_class::<crate::validation::PyLightweightMinimumValuePromiseValidator>()?;
    
    // Script pattern classes
    m.add_class::<crate::validation::PyScriptPattern>()?;
    m.add_class::<crate::validation::PyScriptPatternAnalyzer>()?;
    
    // Module metadata
    m.add("__version__", "0.3.0")?;
    m.add("__doc__", "Tari Lightweight Wallet Python Bindings with Native Object API")?;
    
    // Convenience aliases for the new API
    m.add("TariWallet", py.get_type::<PyTariWallet>())?;
    m.add("WalletGenerationResult", py.get_type::<PyWalletGenerationResult>())?;
    m.add("TariAddress", py.get_type::<PyTariAddress>())?;
    m.add("TariAddressFeatures", py.get_type::<PyTariAddressFeatures>())?;
    m.add("Network", py.get_type::<PyNetwork>())?;
    m.add("DualAddress", py.get_type::<PyDualAddress>())?;
    m.add("SingleAddress", py.get_type::<PySingleAddress>())?;
    m.add("PrivateKey", py.get_type::<PyPrivateKey>())?;
    m.add("CompressedPublicKey", py.get_type::<PyCompressedPublicKey>())?;
    m.add("CompressedCommitment", py.get_type::<PyCompressedCommitment>())?;
    m.add("FixedHash", py.get_type::<PyFixedHash>())?;
    m.add("MicroMinotari", py.get_type::<PyMicroMinotari>())?;
    m.add("SafeArray", py.get_type::<PySafeArray>())?;
    m.add("SignatureResult", py.get_type::<PySignatureResult>())?;
    m.add("KeyPair", py.get_type::<PyKeyPair>())?;
    m.add("TransactionOutput", py.get_type::<PyTransactionOutput>())?;
    m.add("OutputFeatures", py.get_type::<PyOutputFeatures>())?;
    m.add("OutputType", py.get_type::<PyOutputType>())?;
    m.add("Script", py.get_type::<PyScript>())?;
    m.add("Covenant", py.get_type::<PyCovenant>())?;
    m.add("Signature", py.get_type::<PySignature>())?;
    m.add("RangeProof", py.get_type::<PyRangeProof>())?;
    m.add("EncryptedData", py.get_type::<PyEncryptedData>())?;
    
    // Validation convenience aliases
    m.add("MinimumValuePromiseValidationOptions", py.get_type::<crate::validation::PyMinimumValuePromiseValidationOptions>())?;
    m.add("LightweightMinimumValuePromiseValidator", py.get_type::<crate::validation::PyLightweightMinimumValuePromiseValidator>())?;
    
    // Script pattern convenience aliases
    m.add("ScriptPattern", py.get_type::<crate::validation::PyScriptPattern>())?;
    m.add("ScriptPatternAnalyzer", py.get_type::<crate::validation::PyScriptPatternAnalyzer>())?;
    
    Ok(())
}

/// Module constants and helpers
#[pymodule]
fn constants(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Network constants - temporarily disabled
    // m.add("MAINNET", PyNetwork::mainnet())?;
    // m.add("STAGENET", PyNetwork::stagenet())?;
    // m.add("NEXTNET", PyNetwork::nextnet())?;
    // m.add("LOCALNET", PyNetwork::localnet())?;
    // m.add("IGOR", PyNetwork::igor())?;
    // m.add("ESMERALDA", PyNetwork::esmeralda())?;
    
    // Feature constants - temporarily disabled
    // m.add("INTERACTIVE_ONLY", PyTariAddressFeatures::interactive_only())?;
    // m.add("ONE_SIDED_ONLY", PyTariAddressFeatures::one_sided_only())?;
    // m.add("INTERACTIVE_AND_ONE_SIDED", PyTariAddressFeatures::interactive_and_one_sided())?;
    
    // Output type constants
    m.add("OUTPUT_PAYMENT", PyOutputType::payment())?;
    m.add("OUTPUT_COINBASE", PyOutputType::coinbase())?;
    m.add("OUTPUT_BURN", PyOutputType::burn())?;
    m.add("OUTPUT_VALIDATOR_REGISTRATION", PyOutputType::validator_node_registration())?;
    m.add("OUTPUT_CODE_TEMPLATE_REGISTRATION", PyOutputType::code_template_registration())?;
    
    Ok(())
}

// Add sub-modules to main module
#[pymodule]
fn lightweight_wallet_libpy_full(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Main module
    lightweight_wallet_libpy(py, m)?;
    
    // Sub-modules
    let constants_module = PyModule::new(py, "constants")?;
    constants(py, &constants_module)?;
    m.add_submodule(&constants_module)?;
    
    let utils_module = PyModule::new(py, "utils")?;
    utils::utils_module(py, &utils_module)?;
    m.add_submodule(&utils_module)?;
    
    Ok(())
}

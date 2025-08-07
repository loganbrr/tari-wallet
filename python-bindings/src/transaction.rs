//! Native PyO3 transaction wrappers for Tari transaction types
//!
//! This module provides clean PyO3 wrapper classes that store native Rust types
//! internally for transaction components. This improves performance and type safety
//! compared to hex string serialization.

use crate::crypto::{PyCompressedCommitment, PyCompressedPublicKey, PyMicroMinotari};

use pyo3::exceptions::PyValueError;
use lightweight_wallet_libs::data_structures::{
    encrypted_data::EncryptedData,
    transaction_output::LightweightTransactionOutput,
    wallet_output::{
        LightweightCovenant, LightweightOutputFeatures, LightweightOutputType,
        LightweightRangeProof, LightweightScript, LightweightSignature,
        LightweightRangeProofType,
    },
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Native PyO3 wrapper for LightweightOutputType
#[pyclass(name = "OutputType")]
#[derive(Clone)]
pub struct PyOutputType {
    inner: LightweightOutputType,
}

#[pymethods]
impl PyOutputType {
    /// Payment output type
    #[staticmethod]
    pub fn payment() -> Self {
        Self {
            inner: LightweightOutputType::Payment,
        }
    }

    /// Coinbase output type
    #[staticmethod]
    pub fn coinbase() -> Self {
        Self {
            inner: LightweightOutputType::Coinbase,
        }
    }

    /// Burn output type  
    #[staticmethod]
    pub fn burn() -> Self {
        Self {
            inner: LightweightOutputType::Burn,
        }
    }

    /// Validator node registration output type
    #[staticmethod]
    pub fn validator_node_registration() -> Self {
        Self {
            inner: LightweightOutputType::ValidatorNodeRegistration,
        }
    }

    /// Code template registration output type
    #[staticmethod]
    pub fn code_template_registration() -> Self {
        Self {
            inner: LightweightOutputType::CodeTemplateRegistration,
        }
    }

    /// Check if this is a payment output
    pub fn is_payment(&self) -> bool {
        matches!(self.inner, LightweightOutputType::Payment)
    }

    /// Check if this is a coinbase output
    pub fn is_coinbase(&self) -> bool {
        matches!(self.inner, LightweightOutputType::Coinbase)
    }

    /// Check if this is a burn output
    pub fn is_burn(&self) -> bool {
        matches!(self.inner, LightweightOutputType::Burn)
    }

    fn __str__(&self) -> String {
        match self.inner {
            LightweightOutputType::Payment => "Payment".to_string(),
            LightweightOutputType::Coinbase => "Coinbase".to_string(),
            LightweightOutputType::Burn => "Burn".to_string(),
            LightweightOutputType::ValidatorNodeRegistration => "ValidatorNodeRegistration".to_string(),
            LightweightOutputType::CodeTemplateRegistration => "CodeTemplateRegistration".to_string(),
        }
    }

    fn __repr__(&self) -> String {
        format!("OutputType.{}()", self.__str__())
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl PyOutputType {
    pub fn inner(&self) -> LightweightOutputType {
        self.inner.clone()
    }
}

/// Native PyO3 wrapper for LightweightOutputFeatures
#[pyclass(name = "OutputFeatures")]
#[derive(Clone)]
pub struct PyOutputFeatures {
    inner: LightweightOutputFeatures,
}

#[pymethods]
impl PyOutputFeatures {
    /// Create new output features
    #[new]
    pub fn new(
        output_type: &PyOutputType,
        maturity: u64,
    ) -> Self {
        Self {
            inner: LightweightOutputFeatures {
                output_type: output_type.inner().clone(),
                maturity,
                range_proof_type: LightweightRangeProofType::BulletProofPlus,
            },
        }
    }

    /// Create payment output features
    #[staticmethod]
    pub fn payment(maturity: u64) -> Self {
        Self {
            inner: LightweightOutputFeatures {
                output_type: LightweightOutputType::Payment,
                maturity,
                range_proof_type: LightweightRangeProofType::BulletProofPlus,
            },
        }
    }

    /// Create coinbase output features
    #[staticmethod]
    pub fn coinbase(maturity: u64) -> Self {
        Self {
            inner: LightweightOutputFeatures {
                output_type: LightweightOutputType::Coinbase,
                maturity,
                range_proof_type: LightweightRangeProofType::BulletProofPlus,
            },
        }
    }



    /// Get output type
    #[getter]
    pub fn output_type(&self) -> PyOutputType {
        PyOutputType {
            inner: self.inner.output_type.clone(),
        }
    }

    /// Get maturity
    #[getter]
    pub fn maturity(&self) -> u64 {
        self.inner.maturity
    }



    fn __str__(&self) -> String {
        format!("OutputFeatures(type={}, maturity={})", 
            self.output_type().__str__(), self.maturity())
    }

    fn __repr__(&self) -> String {
        format!("OutputFeatures(output_type={}, maturity={})",
            self.output_type().__str__(), self.maturity())
    }
}

impl PyOutputFeatures {
    pub fn inner(&self) -> &LightweightOutputFeatures {
        &self.inner
    }

    pub fn into_inner(self) -> LightweightOutputFeatures {
        self.inner
    }
}

/// Native PyO3 wrapper for LightweightScript
#[pyclass(name = "Script")]
#[derive(Clone)]
pub struct PyScript {
    inner: LightweightScript,
}

#[pymethods]
impl PyScript {
    /// Create from bytes
    #[staticmethod]
    pub fn from_bytes(bytes: Bound<'_, PyBytes>) -> Self {
        Self {
            inner: LightweightScript {
                bytes: bytes.as_bytes().to_vec(),
            },
        }
    }

    /// Create empty script
    #[staticmethod]
    pub fn empty() -> Self {
        Self {
            inner: LightweightScript { bytes: Vec::new() },
        }
    }

    /// Get script bytes
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.bytes)
    }

    /// Get script length
    pub fn len(&self) -> usize {
        self.inner.bytes.len()
    }

    /// Check if script is empty
    pub fn is_empty(&self) -> bool {
        self.inner.bytes.is_empty()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.inner.bytes)
    }

    fn __str__(&self) -> String {
        if self.is_empty() {
            "Script(empty)".to_string()
        } else {
            format!("Script({} bytes, {}...)", self.len(), &self.to_hex()[0..16.min(self.to_hex().len())])
        }
    }

    fn __repr__(&self) -> String {
        format!("Script(bytes={})", self.to_hex())
    }

    fn __len__(&self) -> usize {
        self.len()
    }
}

impl PyScript {
    pub fn inner(&self) -> &LightweightScript {
        &self.inner
    }

    pub fn into_inner(self) -> LightweightScript {
        self.inner
    }
}

/// Native PyO3 wrapper for LightweightCovenant
#[pyclass(name = "Covenant")]
#[derive(Clone)]
pub struct PyCovenant {
    inner: LightweightCovenant,
}

#[pymethods]
impl PyCovenant {
    /// Create from bytes
    #[staticmethod]
    pub fn from_bytes(bytes: Bound<'_, PyBytes>) -> Self {
        Self {
            inner: LightweightCovenant {
                bytes: bytes.as_bytes().to_vec(),
            },
        }
    }

    /// Create empty covenant
    #[staticmethod]
    pub fn empty() -> Self {
        Self {
            inner: LightweightCovenant { bytes: Vec::new() },
        }
    }

    /// Get covenant bytes
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.bytes)
    }

    /// Get covenant length
    pub fn len(&self) -> usize {
        self.inner.bytes.len()
    }

    /// Check if covenant is empty
    pub fn is_empty(&self) -> bool {
        self.inner.bytes.is_empty()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.inner.bytes)
    }

    fn __str__(&self) -> String {
        if self.is_empty() {
            "Covenant(empty)".to_string()
        } else {
            format!("Covenant({} bytes, {}...)", self.len(), &self.to_hex()[0..16.min(self.to_hex().len())])
        }
    }

    fn __repr__(&self) -> String {
        format!("Covenant(bytes={})", self.to_hex())
    }

    fn __len__(&self) -> usize {
        self.len()
    }
}

impl PyCovenant {
    pub fn inner(&self) -> &LightweightCovenant {
        &self.inner
    }

    pub fn into_inner(self) -> LightweightCovenant {
        self.inner
    }
}

/// Native PyO3 wrapper for LightweightSignature
#[pyclass(name = "Signature")]
#[derive(Clone)]
pub struct PySignature {
    inner: LightweightSignature,
}

#[pymethods]
impl PySignature {
    /// Create from bytes
    #[staticmethod]
    pub fn from_bytes(bytes: Bound<'_, PyBytes>) -> Self {
        Self {
            inner: LightweightSignature {
                bytes: bytes.as_bytes().to_vec(),
            },
        }
    }

    /// Get signature bytes
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.bytes)
    }

    /// Get signature length
    pub fn len(&self) -> usize {
        self.inner.bytes.len()
    }

    /// Check if signature is empty
    pub fn is_empty(&self) -> bool {
        self.inner.bytes.is_empty()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.inner.bytes)
    }

    fn __str__(&self) -> String {
        format!("Signature({} bytes, {}...)", self.len(), &self.to_hex()[0..16.min(self.to_hex().len())])
    }

    fn __repr__(&self) -> String {
        format!("Signature(bytes={})", self.to_hex())
    }

    fn __len__(&self) -> usize {
        self.len()
    }
}

impl PySignature {
    pub fn inner(&self) -> &LightweightSignature {
        &self.inner
    }

    pub fn into_inner(self) -> LightweightSignature {
        self.inner
    }
}

/// Native PyO3 wrapper for LightweightRangeProof
#[pyclass(name = "RangeProof")]
#[derive(Clone)]
pub struct PyRangeProof {
    inner: LightweightRangeProof,
}

#[pymethods]
impl PyRangeProof {
    /// Create from bytes
    #[staticmethod]
    pub fn from_bytes(bytes: Bound<'_, PyBytes>) -> Self {
        Self {
            inner: LightweightRangeProof {
                bytes: bytes.as_bytes().to_vec(),
            },
        }
    }

    /// Get range proof bytes
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.bytes)
    }

    /// Get range proof length
    pub fn len(&self) -> usize {
        self.inner.bytes.len()
    }

    /// Check if range proof is empty
    pub fn is_empty(&self) -> bool {
        self.inner.bytes.is_empty()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.inner.bytes)
    }

    fn __str__(&self) -> String {
        format!("RangeProof({} bytes, {}...)", self.len(), &self.to_hex()[0..16.min(self.to_hex().len())])
    }

    fn __repr__(&self) -> String {
        format!("RangeProof(bytes={})", self.to_hex())
    }

    fn __len__(&self) -> usize {
        self.len()
    }
}

impl PyRangeProof {
    pub fn inner(&self) -> &LightweightRangeProof {
        &self.inner
    }

    pub fn into_inner(self) -> LightweightRangeProof {
        self.inner
    }
}

/// Native PyO3 wrapper for EncryptedData
#[pyclass(name = "EncryptedData")]
#[derive(Clone)]
pub struct PyEncryptedData {
    inner: EncryptedData,
}

#[pymethods]
impl PyEncryptedData {
    /// Create from raw data  
    #[staticmethod]
    pub fn from_data(data: Bound<'_, PyBytes>) -> Self {
        Self {
            inner: EncryptedData::from_bytes(data.as_bytes())
                .unwrap_or_else(|_| EncryptedData::default()),
        }
    }

    /// Create empty encrypted data
    #[staticmethod]
    pub fn empty() -> Self {
        Self {
            inner: EncryptedData::default(),
        }
    }

    /// Get encrypted data bytes
    pub fn data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.as_bytes())
    }

    /// Get data length
    pub fn data_len(&self) -> usize {
        self.inner.as_bytes().len()
    }

    /// Check if data is empty
    pub fn is_empty(&self) -> bool {
        self.inner.as_bytes().is_empty()
    }

    fn __str__(&self) -> String {
        format!("EncryptedData(data={} bytes)", self.data_len())
    }

    fn __repr__(&self) -> String {
        format!("EncryptedData(data={})", hex::encode(self.inner.as_bytes()))
    }
}

impl PyEncryptedData {
    pub fn inner(&self) -> &EncryptedData {
        &self.inner
    }

    pub fn into_inner(self) -> EncryptedData {
        self.inner
    }
}

/// Native PyO3 wrapper for LightweightTransactionOutput
#[pyclass(name = "TransactionOutput")]
#[derive(Clone)]
pub struct PyTransactionOutput {
    inner: LightweightTransactionOutput,
}

#[pymethods]
impl PyTransactionOutput {
    /// Create new transaction output
    #[new]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u8,
        features: &PyOutputFeatures,
        commitment: &PyCompressedCommitment,
        proof: Option<&PyRangeProof>,
        script: &PyScript,
        sender_offset_public_key: &PyCompressedPublicKey,
        metadata_signature: &PySignature,
        covenant: &PyCovenant,
        encrypted_data: &PyEncryptedData,
        minimum_value_promise: &PyMicroMinotari,
    ) -> Self {
        let rust_proof = proof.map(|p| p.inner().clone());
        
        Self {
            inner: LightweightTransactionOutput::new(
                version,
                features.inner().clone(),
                commitment.inner().clone(),
                rust_proof,
                script.inner().clone(),
                sender_offset_public_key.inner().clone(),
                metadata_signature.inner().clone(),
                covenant.inner().clone(),
                encrypted_data.inner().clone(),
                minimum_value_promise.inner(),
            ),
        }
    }

    /// Create with current version (convenience method)
    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    pub fn new_current_version(
        features: &PyOutputFeatures,
        commitment: &PyCompressedCommitment,
        proof: Option<&PyRangeProof>,
        script: &PyScript,
        sender_offset_public_key: &PyCompressedPublicKey,
        metadata_signature: &PySignature,
        covenant: &PyCovenant,
        encrypted_data: &PyEncryptedData,
        minimum_value_promise: &PyMicroMinotari,
    ) -> Self {
        let rust_proof = proof.map(|p| p.inner().clone());
        
        Self {
            inner: LightweightTransactionOutput::new_current_version(
                features.inner().clone(),
                commitment.inner().clone(),
                rust_proof,
                script.inner().clone(),
                sender_offset_public_key.inner().clone(),
                metadata_signature.inner().clone(),
                covenant.inner().clone(),
                encrypted_data.inner().clone(),
                minimum_value_promise.inner(),
            ),
        }
    }

    /// Get version
    #[getter]
    pub fn version(&self) -> u8 {
        self.inner.version()
    }

    /// Get features
    #[getter]
    pub fn features(&self) -> PyOutputFeatures {
        PyOutputFeatures {
            inner: self.inner.features().clone(),
        }
    }

    /// Get commitment
    #[getter]
    pub fn commitment(&self) -> PyCompressedCommitment {
        PyCompressedCommitment {
            inner: self.inner.commitment().clone(),
        }
    }

    /// Get range proof (if present)
    #[getter]
    pub fn proof(&self) -> Option<PyRangeProof> {
        self.inner.proof().map(|p| PyRangeProof {
            inner: p.clone(),
        })
    }

    /// Get script
    #[getter]
    pub fn script(&self) -> PyScript {
        PyScript {
            inner: self.inner.script().clone(),
        }
    }

    /// Get sender offset public key
    #[getter]
    pub fn sender_offset_public_key(&self) -> PyCompressedPublicKey {
        PyCompressedPublicKey {
            inner: self.inner.sender_offset_public_key().clone(),
        }
    }

    /// Get metadata signature
    #[getter]
    pub fn metadata_signature(&self) -> PySignature {
        PySignature {
            inner: self.inner.metadata_signature().clone(),
        }
    }

    /// Get covenant
    #[getter]
    pub fn covenant(&self) -> PyCovenant {
        PyCovenant {
            inner: self.inner.covenant().clone(),
        }
    }

    /// Get encrypted data
    #[getter]
    pub fn encrypted_data(&self) -> PyEncryptedData {
        PyEncryptedData {
            inner: self.inner.encrypted_data().clone(),
        }
    }

    /// Get minimum value promise
    #[getter]
    pub fn minimum_value_promise(&self) -> PyMicroMinotari {
        PyMicroMinotari::new(self.inner.minimum_value_promise().as_u64())
    }

    /// Calculate output hash
    pub fn hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.hash())
    }

    /// Calculate SMT hash
    pub fn smt_hash<'py>(&self, py: Python<'py>, mined_height: u64) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.smt_hash(mined_height))
    }

    /// Check if this is a coinbase output
    pub fn is_coinbase(&self) -> bool {
        self.inner.is_coinbase()
    }

    /// Check if this is a burned output
    pub fn is_burned(&self) -> bool {
        self.inner.is_burned()
    }

    /// Convert to hex representation
    pub fn to_hex(&self) -> PyResult<String> {
        borsh::to_vec(&self.inner)
            .map(|bytes| hex::encode(bytes))
            .map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e)).into())
    }

    /// Create from hex representation
    #[staticmethod]
    pub fn from_hex(hex_str: &str) -> PyResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| PyValueError::new_err(format!("Invalid hex: {}", e)))?;
        
        let inner = borsh::from_slice(&bytes)
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))?;
        
        Ok(Self { inner })
    }

    fn __str__(&self) -> String {
        format!("TransactionOutput(version={}, commitment={}..., type={})",
            self.version(),
            &self.commitment().to_hex()[0..16],
            self.features().output_type().__str__())
    }

    fn __repr__(&self) -> String {
        format!("TransactionOutput(hash={})", hex::encode(self.inner.hash()))
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl PyTransactionOutput {
    pub fn inner(&self) -> &LightweightTransactionOutput {
        &self.inner
    }

    pub fn into_inner(self) -> LightweightTransactionOutput {
        self.inner
    }

    pub fn to_rust(&self) -> Result<LightweightTransactionOutput, PyValueError> {
        Ok(self.inner.clone())
    }
}



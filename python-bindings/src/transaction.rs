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
    transaction_input::{TransactionInput as CoreTransactionInput, LightweightExecutionStack as CoreExecutionStack},
    transaction_kernel::TransactionKernel as CoreTransactionKernel,
    block::{Block as CoreBlock, BlockSummary as CoreBlockSummary},
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

/// Python wrapper for LightweightExecutionStack
#[pyclass(name = "ExecutionStack")]
#[derive(Clone)]
pub struct PyExecutionStack { inner: CoreExecutionStack }

#[pymethods]
impl PyExecutionStack {
    #[new]
    pub fn new() -> Self { Self { inner: CoreExecutionStack { items: Vec::new() } } }

    #[staticmethod]
    pub fn from_items(items: Vec<Bound<'_, PyBytes>>) -> Self {
        let mut stack = CoreExecutionStack { items: Vec::new() };
        for b in items { stack.items.push(b.as_bytes().to_vec()); }
        Self { inner: stack }
    }

    pub fn push(&mut self, item: Bound<'_, PyBytes>) { self.inner.items.push(item.as_bytes().to_vec()); }
    pub fn len(&self) -> usize { self.inner.items.len() }
    pub fn is_empty(&self) -> bool { self.inner.items.is_empty() }

    pub fn items<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.inner.items.iter().map(|v| PyBytes::new(py, v)).collect()
    }

    fn __repr__(&self) -> String { format!("ExecutionStack(len={})", self.len()) }
}

impl PyExecutionStack { pub fn inner(&self) -> &CoreExecutionStack { &self.inner } }

/// Python wrapper for TransactionInput
#[pyclass(name = "TransactionInput")]
#[derive(Clone)]
pub struct PyTransactionInput { inner: CoreTransactionInput }

#[pymethods]
impl PyTransactionInput {
    #[new]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u8,
        features: u8,
        commitment_hex: &str,
        script_signature_hex: &str,
        sender_offset_public_key: &PyCompressedPublicKey,
        covenant: &PyCovenant,
        input_stack: &PyExecutionStack,
        output_hash_hex: &str,
        output_features: u8,
        output_metadata_signature_hex: &str,
        maturity: u64,
        value: &PyMicroMinotari,
    ) -> PyResult<Self> {
        let commitment = hex::decode(commitment_hex).map_err(|e| PyValueError::new_err(format!("Invalid commitment hex: {}", e)))?;
        let script_sig = hex::decode(script_signature_hex).map_err(|e| PyValueError::new_err(format!("Invalid script signature hex: {}", e)))?;
        let output_hash = hex::decode(output_hash_hex).map_err(|e| PyValueError::new_err(format!("Invalid output hash hex: {}", e)))?;
        let output_meta_sig = hex::decode(output_metadata_signature_hex).map_err(|e| PyValueError::new_err(format!("Invalid metadata signature hex: {}", e)))?;

        if commitment.len() != 32 { return Err(PyValueError::new_err("commitment must be 32 bytes")); }
        if script_sig.len() != 64 { return Err(PyValueError::new_err("script_signature must be 64 bytes")); }
        if output_hash.len() != 32 { return Err(PyValueError::new_err("output_hash must be 32 bytes")); }
        if output_meta_sig.len() != 64 { return Err(PyValueError::new_err("output_metadata_signature must be 64 bytes")); }

        let mut commitment_arr = [0u8;32]; commitment_arr.copy_from_slice(&commitment);
        let mut script_sig_arr = [0u8;64]; script_sig_arr.copy_from_slice(&script_sig);
        let mut output_hash_arr = [0u8;32]; output_hash_arr.copy_from_slice(&output_hash);
        let mut output_meta_sig_arr = [0u8;64]; output_meta_sig_arr.copy_from_slice(&output_meta_sig);

        Ok(Self { inner: CoreTransactionInput {
            version,
            features,
            commitment: commitment_arr,
            script_signature: script_sig_arr,
            sender_offset_public_key: sender_offset_public_key.inner().clone(),
            covenant: covenant.inner().bytes.clone(),
            input_data: input_stack.inner().clone(),
            output_hash: output_hash_arr,
            output_features,
            output_metadata_signature: output_meta_sig_arr,
            maturity,
            value: lightweight_wallet_libs::data_structures::types::MicroMinotari::new(value.inner().into()),
        }})
    }

    #[getter]
    pub fn version(&self) -> u8 { self.inner.version }
    #[getter]
    pub fn features(&self) -> u8 { self.inner.features }

    pub fn commitment_hex(&self) -> String { hex::encode(self.inner.commitment) }
    pub fn script_signature_hex(&self) -> String { hex::encode(self.inner.script_signature) }
    pub fn output_hash_hex(&self) -> String { hex::encode(self.inner.output_hash) }
    pub fn output_metadata_signature_hex(&self) -> String { hex::encode(self.inner.output_metadata_signature) }
    pub fn maturity(&self) -> u64 { self.inner.maturity }
    pub fn value(&self) -> PyMicroMinotari { PyMicroMinotari::new(self.inner.value.as_u64()) }

    pub fn validate_lengths(&self) -> PyResult<()> {
        if self.inner.commitment.len() != 32 { return Err(PyValueError::new_err("Invalid commitment length")); }
        Ok(())
    }

    fn __repr__(&self) -> String { format!("TransactionInput(version={}, maturity={}, value={})", self.version(), self.maturity(), self.value().inner()) }
}

impl PyTransactionInput { pub fn inner(&self) -> &CoreTransactionInput { &self.inner } }

/// Python wrapper for TransactionKernel
#[pyclass(name = "TransactionKernel")]
#[derive(Clone)]
pub struct PyTransactionKernel { inner: CoreTransactionKernel }

#[pymethods]
impl PyTransactionKernel {
    #[new]
    pub fn new(
        version: u8,
        features: u8,
        fee: &PyMicroMinotari,
        lock_height: u64,
        excess: &PyCompressedPublicKey,
        excess_sig_hex: &str,
        hash_type: u8,
        burn_commitment: Option<&PyCompressedCommitment>,
    ) -> PyResult<Self> {
        let excess_sig = hex::decode(excess_sig_hex).map_err(|e| PyValueError::new_err(format!("Invalid excess_sig hex: {}", e)))?;
        if excess_sig.len() != 64 { return Err(PyValueError::new_err("excess_sig must be 64 bytes")); }
        let mut sig_arr = [0u8;64]; sig_arr.copy_from_slice(&excess_sig);
        Ok(Self { inner: CoreTransactionKernel {
            version,
            features,
            fee: lightweight_wallet_libs::data_structures::types::MicroMinotari::new(fee.inner().into()),
            lock_height,
            excess: excess.inner().clone(),
            excess_sig: sig_arr,
            hash_type,
            burn_commitment: burn_commitment.map(|c| c.inner().clone()),
        }})
    }

    pub fn to_hex(&self) -> PyResult<String> { borsh::to_vec(&self.inner).map(|b| hex::encode(b)).map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e))) }
    #[staticmethod]
    pub fn from_hex(hex_str: &str) -> PyResult<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| PyValueError::new_err(format!("Invalid hex: {}", e)))?;
        let inner: CoreTransactionKernel = borsh::from_slice(&bytes).map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))?;
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String { format!("TransactionKernel(version={}, fee={}, lock_height={})", self.inner.version, self.inner.fee.as_u64(), self.inner.lock_height) }
}

impl PyTransactionKernel { pub fn inner(&self) -> &CoreTransactionKernel { &self.inner } }

/// Python wrapper for BlockSummary
#[pyclass(name = "BlockSummary")]
#[derive(Clone)]
pub struct PyBlockSummary { inner: CoreBlockSummary }

#[pymethods]
impl PyBlockSummary {
    #[getter]
    pub fn height(&self) -> u64 { self.inner.height }
    #[getter]
    pub fn timestamp(&self) -> u64 { self.inner.timestamp }
    pub fn output_count(&self) -> usize { self.inner.output_count }
    pub fn input_count(&self) -> usize { self.inner.input_count }
    pub fn hash_hex(&self) -> String { hex::encode(&self.inner.hash) }
    fn __repr__(&self) -> String { format!("BlockSummary(height={}, outputs={}, inputs={})", self.height(), self.output_count(), self.input_count()) }
}

/// Python wrapper for Block
#[pyclass(name = "Block")]
pub struct PyBlock { inner: CoreBlock }

#[pymethods]
impl PyBlock {
    #[new]
    pub fn new(height: u64, hash_hex: &str, timestamp: u64, outputs: Vec<PyTransactionOutput>, inputs: Vec<PyTransactionInput>) -> PyResult<Self> {
        let hash = hex::decode(hash_hex).map_err(|e| PyValueError::new_err(format!("Invalid hash hex: {}", e)))?;
        let inner = CoreBlock::new(
            height,
            hash,
            timestamp,
            outputs.into_iter().map(|o| o.into_inner()).collect(),
            inputs.into_iter().map(|i| i.inner.clone()).collect(),
        );
        Ok(Self { inner })
    }

    pub fn output_count(&self) -> usize { self.inner.output_count() }
    pub fn input_count(&self) -> usize { self.inner.input_count() }
    pub fn summary(&self) -> PyBlockSummary { PyBlockSummary { inner: self.inner.summary() } }

    fn __repr__(&self) -> String { format!("Block(height={}, outputs={}, inputs={})", self.inner.height, self.inner.outputs.len(), self.inner.inputs.len()) }
}

impl PyBlock { pub fn inner(&self) -> &CoreBlock { &self.inner } }



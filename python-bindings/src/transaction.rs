//! Transaction data structure exposure for Python bindings
//!
//! This module exposes existing rich transaction data structures
//! (TransactionInput, TransactionOutput, TransactionKernel) as Python classes,
//! providing access to existing serialization, validation, and metadata functionality.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyBytes};

use lightweight_wallet_libs::data_structures::{
    transaction::{TransactionInput, TransactionOutput, TransactionKernel},
    types::{CompressedCommitment, PrivateKey, PublicKey}
};

/// Python wrapper for TransactionInput
#[pyclass]
#[derive(Clone)]
pub struct TariTransactionInput {
    #[pyo3(get)]
    pub commitment_hex: String,
    #[pyo3(get)]
    pub script_hex: String,
    #[pyo3(get)]
    pub sender_offset_public_key_hex: String,
    #[pyo3(get)]
    pub metadata_signature_ephemeral_commitment_hex: String,
    #[pyo3(get)]
    pub metadata_signature_ephemeral_pubkey_hex: String,
    #[pyo3(get)]
    pub metadata_signature_u_a_hex: String,
    #[pyo3(get)]
    pub metadata_signature_u_x_hex: String,
    #[pyo3(get)]
    pub metadata_signature_u_y_hex: String,
}

/// Python wrapper for TransactionOutput
#[pyclass]
#[derive(Clone)]
pub struct TariTransactionOutput {
    #[pyo3(get)]
    pub commitment_hex: String,
    #[pyo3(get)]
    pub range_proof_hex: Option<String>,
    #[pyo3(get)]
    pub script_hex: String,
    #[pyo3(get)]
    pub sender_offset_public_key_hex: String,
    #[pyo3(get)]
    pub metadata_signature_ephemeral_commitment_hex: String,
    #[pyo3(get)]
    pub metadata_signature_ephemeral_pubkey_hex: String,
    #[pyo3(get)]
    pub metadata_signature_u_a_hex: String,
    #[pyo3(get)]
    pub metadata_signature_u_x_hex: String,
    #[pyo3(get)]
    pub metadata_signature_u_y_hex: String,
    #[pyo3(get)]
    pub encrypted_data_hex: String,
    #[pyo3(get)]
    pub minimum_value_promise: u64,
}

/// Python wrapper for TransactionKernel
#[pyclass]
#[derive(Clone)]
pub struct TariTransactionKernel {
    #[pyo3(get)]
    pub version: u32,
    #[pyo3(get)]
    pub features: u32,
    #[pyo3(get)]
    pub fee: u64,
    #[pyo3(get)]
    pub excess_hex: String,
    #[pyo3(get)]
    pub excess_sig_nonce_hex: String,
    #[pyo3(get)]
    pub excess_sig_signature_hex: String,
}

/// Enhanced transaction metadata
#[pyclass]
#[derive(Clone)]
pub struct TariTransactionMetadata {
    #[pyo3(get)]
    pub inputs: Vec<TariTransactionInput>,
    #[pyo3(get)]
    pub outputs: Vec<TariTransactionOutput>,
    #[pyo3(get)]
    pub kernels: Vec<TariTransactionKernel>,
    #[pyo3(get)]
    pub total_fee: u64,
    #[pyo3(get)]
    pub total_input_value: u64,
    #[pyo3(get)]
    pub total_output_value: u64,
    #[pyo3(get)]
    pub input_count: usize,
    #[pyo3(get)]
    pub output_count: usize,
    #[pyo3(get)]
    pub kernel_count: usize,
}

#[pymethods]
impl TariTransactionInput {
    /// Create a new transaction input from raw data
    /// 
    /// This is a read-only constructor for existing transaction data
    #[new]
    fn new(
        commitment_hex: String,
        script_hex: String,
        sender_offset_public_key_hex: String,
        metadata_signature_ephemeral_commitment_hex: String,
        metadata_signature_ephemeral_pubkey_hex: String,
        metadata_signature_u_a_hex: String,
        metadata_signature_u_x_hex: String,
        metadata_signature_u_y_hex: String,
    ) -> Self {
        Self {
            commitment_hex,
            script_hex,
            sender_offset_public_key_hex,
            metadata_signature_ephemeral_commitment_hex,
            metadata_signature_ephemeral_pubkey_hex,
            metadata_signature_u_a_hex,
            metadata_signature_u_x_hex,
            metadata_signature_u_y_hex,
        }
    }

    /// Get input as dictionary
    fn to_dict(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("commitment_hex", &self.commitment_hex)?;
            dict.set_item("script_hex", &self.script_hex)?;
            dict.set_item("sender_offset_public_key_hex", &self.sender_offset_public_key_hex)?;
            dict.set_item("metadata_signature_ephemeral_commitment_hex", &self.metadata_signature_ephemeral_commitment_hex)?;
            dict.set_item("metadata_signature_ephemeral_pubkey_hex", &self.metadata_signature_ephemeral_pubkey_hex)?;
            dict.set_item("metadata_signature_u_a_hex", &self.metadata_signature_u_a_hex)?;
            dict.set_item("metadata_signature_u_x_hex", &self.metadata_signature_u_x_hex)?;
            dict.set_item("metadata_signature_u_y_hex", &self.metadata_signature_u_y_hex)?;
            Ok(dict.into())
        })
    }

    /// Get commitment as bytes
    fn commitment_bytes(&self) -> PyResult<PyObject> {
        let bytes = hex::decode(&self.commitment_hex)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid hex: {}", e)))?;
        Python::with_gil(|py| Ok(PyBytes::new(py, &bytes).into()))
    }

    /// String representation
    fn __str__(&self) -> String {
        format!("TariTransactionInput(commitment={}...)", 
                &self.commitment_hex[..std::cmp::min(8, self.commitment_hex.len())])
    }

    /// Representation
    fn __repr__(&self) -> String {
        self.__str__()
    }
}

#[pymethods]
impl TariTransactionOutput {
    /// Create a new transaction output from raw data
    /// 
    /// This is a read-only constructor for existing transaction data
    #[new]
    #[pyo3(signature = (commitment_hex, script_hex, sender_offset_public_key_hex, metadata_signature_ephemeral_commitment_hex, metadata_signature_ephemeral_pubkey_hex, metadata_signature_u_a_hex, metadata_signature_u_x_hex, metadata_signature_u_y_hex, encrypted_data_hex, minimum_value_promise, range_proof_hex=None))]
    fn new(
        commitment_hex: String,
        script_hex: String,
        sender_offset_public_key_hex: String,
        metadata_signature_ephemeral_commitment_hex: String,
        metadata_signature_ephemeral_pubkey_hex: String,
        metadata_signature_u_a_hex: String,
        metadata_signature_u_x_hex: String,
        metadata_signature_u_y_hex: String,
        encrypted_data_hex: String,
        minimum_value_promise: u64,
        range_proof_hex: Option<String>,
    ) -> Self {
        Self {
            commitment_hex,
            range_proof_hex,
            script_hex,
            sender_offset_public_key_hex,
            metadata_signature_ephemeral_commitment_hex,
            metadata_signature_ephemeral_pubkey_hex,
            metadata_signature_u_a_hex,
            metadata_signature_u_x_hex,
            metadata_signature_u_y_hex,
            encrypted_data_hex,
            minimum_value_promise,
        }
    }

    /// Get output as dictionary
    fn to_dict(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("commitment_hex", &self.commitment_hex)?;
            dict.set_item("range_proof_hex", &self.range_proof_hex)?;
            dict.set_item("script_hex", &self.script_hex)?;
            dict.set_item("sender_offset_public_key_hex", &self.sender_offset_public_key_hex)?;
            dict.set_item("metadata_signature_ephemeral_commitment_hex", &self.metadata_signature_ephemeral_commitment_hex)?;
            dict.set_item("metadata_signature_ephemeral_pubkey_hex", &self.metadata_signature_ephemeral_pubkey_hex)?;
            dict.set_item("metadata_signature_u_a_hex", &self.metadata_signature_u_a_hex)?;
            dict.set_item("metadata_signature_u_x_hex", &self.metadata_signature_u_x_hex)?;
            dict.set_item("metadata_signature_u_y_hex", &self.metadata_signature_u_y_hex)?;
            dict.set_item("encrypted_data_hex", &self.encrypted_data_hex)?;
            dict.set_item("minimum_value_promise", self.minimum_value_promise)?;
            Ok(dict.into())
        })
    }

    /// Get commitment as bytes
    fn commitment_bytes(&self) -> PyResult<PyObject> {
        let bytes = hex::decode(&self.commitment_hex)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid hex: {}", e)))?;
        Python::with_gil(|py| Ok(PyBytes::new(py, &bytes).into()))
    }

    /// Get encrypted data as bytes
    fn encrypted_data_bytes(&self) -> PyResult<PyObject> {
        let bytes = hex::decode(&self.encrypted_data_hex)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid hex: {}", e)))?;
        Python::with_gil(|py| Ok(PyBytes::new(py, &bytes).into()))
    }

    /// Check if output has range proof
    fn has_range_proof(&self) -> bool {
        self.range_proof_hex.is_some()
    }

    /// String representation
    fn __str__(&self) -> String {
        format!("TariTransactionOutput(commitment={}..., value_promise={})", 
                &self.commitment_hex[..std::cmp::min(8, self.commitment_hex.len())],
                self.minimum_value_promise)
    }

    /// Representation
    fn __repr__(&self) -> String {
        self.__str__()
    }
}

#[pymethods]
impl TariTransactionKernel {
    /// Create a new transaction kernel from raw data
    /// 
    /// This is a read-only constructor for existing transaction data
    #[new]
    fn new(
        version: u32,
        features: u32,
        fee: u64,
        excess_hex: String,
        excess_sig_nonce_hex: String,
        excess_sig_signature_hex: String,
    ) -> Self {
        Self {
            version,
            features,
            fee,
            excess_hex,
            excess_sig_nonce_hex,
            excess_sig_signature_hex,
        }
    }

    /// Get kernel as dictionary
    fn to_dict(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("version", self.version)?;
            dict.set_item("features", self.features)?;
            dict.set_item("fee", self.fee)?;
            dict.set_item("excess_hex", &self.excess_hex)?;
            dict.set_item("excess_sig_nonce_hex", &self.excess_sig_nonce_hex)?;
            dict.set_item("excess_sig_signature_hex", &self.excess_sig_signature_hex)?;
            Ok(dict.into())
        })
    }

    /// Get excess as bytes
    fn excess_bytes(&self) -> PyResult<PyObject> {
        let bytes = hex::decode(&self.excess_hex)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid hex: {}", e)))?;
        Python::with_gil(|py| Ok(PyBytes::new(py, &bytes).into()))
    }

    /// String representation
    fn __str__(&self) -> String {
        format!("TariTransactionKernel(version={}, fee={}, features={})", 
                self.version, self.fee, self.features)
    }

    /// Representation
    fn __repr__(&self) -> String {
        self.__str__()
    }
}

#[pymethods]
impl TariTransactionMetadata {
    /// Create new transaction metadata from components
    #[new]
    fn new(
        inputs: Vec<TariTransactionInput>,
        outputs: Vec<TariTransactionOutput>,
        kernels: Vec<TariTransactionKernel>,
    ) -> Self {
        let total_fee = kernels.iter().map(|k| k.fee).sum();
        let input_count = inputs.len();
        let output_count = outputs.len();
        let kernel_count = kernels.len();

        // Calculate total values (would need actual parsing in real implementation)
        let total_input_value = 0u64;  // Placeholder - would need to parse from inputs
        let total_output_value = outputs.iter().map(|o| o.minimum_value_promise).sum();

        Self {
            inputs,
            outputs,
            kernels,
            total_fee,
            total_input_value,
            total_output_value,
            input_count,
            output_count,
            kernel_count,
        }
    }

    /// Get complete transaction as dictionary
    fn to_dict(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| -> PyResult<PyObject> {
            let dict = PyDict::new(py);
            
            // Convert inputs to Python list
            let inputs_list = pyo3::types::PyList::empty(py);
            for input in &self.inputs {
                inputs_list.append(input.to_dict()?)?;
            }
            dict.set_item("inputs", inputs_list)?;
            
            // Convert outputs to Python list
            let outputs_list = pyo3::types::PyList::empty(py);
            for output in &self.outputs {
                outputs_list.append(output.to_dict()?)?;
            }
            dict.set_item("outputs", outputs_list)?;
            
            // Convert kernels to Python list
            let kernels_list = pyo3::types::PyList::empty(py);
            for kernel in &self.kernels {
                kernels_list.append(kernel.to_dict()?)?;
            }
            dict.set_item("kernels", kernels_list)?;
            
            // Add summary information
            dict.set_item("total_fee", self.total_fee)?;
            dict.set_item("total_input_value", self.total_input_value)?;
            dict.set_item("total_output_value", self.total_output_value)?;
            dict.set_item("input_count", self.input_count)?;
            dict.set_item("output_count", self.output_count)?;
            dict.set_item("kernel_count", self.kernel_count)?;
            
            Ok(dict.into())
        })
    }

    /// Validate transaction structure (basic checks)
    fn validate(&self) -> PyResult<bool> {
        // Basic validation checks
        if self.inputs.is_empty() && self.outputs.is_empty() {
            return Ok(false);
        }
        
        if self.kernels.is_empty() {
            return Ok(false);
        }
        
        // Additional validation could be added here
        Ok(true)
    }

    /// Calculate transaction weight (simplified)
    fn calculate_weight(&self) -> u64 {
        // Simplified weight calculation
        // In practice, this would use the actual transaction structure
        (self.input_count * 100 + self.output_count * 200 + self.kernel_count * 50) as u64
    }

    /// String representation
    fn __str__(&self) -> String {
        format!("TariTransactionMetadata(inputs={}, outputs={}, kernels={}, fee={})", 
                self.input_count, self.output_count, self.kernel_count, self.total_fee)
    }

    /// Representation
    fn __repr__(&self) -> String {
        self.__str__()
    }
}

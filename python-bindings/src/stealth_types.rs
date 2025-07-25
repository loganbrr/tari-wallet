//! Data structures for stealth address information and scanning results
//!
//! This module provides PyO3-compatible data structures for representing
//! stealth address information with proper field exposure and memory management.

use pyo3::prelude::*;

/// Python wrapper for stealth address information
/// 
/// Contains all the key information needed for a stealth address including
/// view and spend keys, stealth spending key, and sender offset.
#[pyclass]
#[derive(Clone, Debug, PartialEq)]
pub struct StealthAddressInfo {
    /// Public view key (for scanning) as hex string
    #[pyo3(get)]
    pub view_public_key: String,
    
    /// Public spend key (base spending key) as hex string  
    #[pyo3(get)]
    pub spend_public_key: String,
    
    /// Stealth spending key (derived key for actual spending) as hex string
    #[pyo3(get)]
    pub stealth_spending_key: String,
    
    /// Sender offset public key (ephemeral key) as hex string
    #[pyo3(get)]
    pub sender_offset_public_key: String,
}

#[pymethods]
impl StealthAddressInfo {
    /// Create a new stealth address info
    /// 
    /// Args:
    ///     view_public_key: View public key as hex string
    ///     spend_public_key: Spend public key as hex string
    ///     stealth_spending_key: Stealth spending key as hex string
    ///     sender_offset_public_key: Sender offset public key as hex string
    /// 
    /// Returns:
    ///     StealthAddressInfo: New stealth address info instance
    #[new]
    pub fn new(
        view_public_key: String,
        spend_public_key: String,
        stealth_spending_key: String,
        sender_offset_public_key: String,
    ) -> Self {
        Self {
            view_public_key,
            spend_public_key,
            stealth_spending_key,
            sender_offset_public_key,
        }
    }

    /// Check if all keys are valid hex strings
    /// 
    /// Returns:
    ///     bool: True if all keys are valid hex
    pub fn is_valid(&self) -> bool {
        self.view_public_key.len() == 64 &&
        self.spend_public_key.len() == 64 &&
        self.stealth_spending_key.len() == 64 &&
        self.sender_offset_public_key.len() == 64 &&
        hex::decode(&self.view_public_key).is_ok() &&
        hex::decode(&self.spend_public_key).is_ok() &&
        hex::decode(&self.stealth_spending_key).is_ok() &&
        hex::decode(&self.sender_offset_public_key).is_ok()
    }

    /// Get address as dictionary
    /// 
    /// Returns:
    ///     dict: Dictionary representation of the stealth address
    fn to_dict(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("view_public_key", &self.view_public_key)?;
            dict.set_item("spend_public_key", &self.spend_public_key)?;
            dict.set_item("stealth_spending_key", &self.stealth_spending_key)?;
            dict.set_item("sender_offset_public_key", &self.sender_offset_public_key)?;
            Ok(dict.into())
        })
    }

    /// Get unique identifier for this stealth address
    /// 
    /// Returns:
    ///     str: Hash-based unique identifier
    fn get_id(&self) -> String {
        use blake2b_simd::blake2b;
        let mut input = Vec::new();
        input.extend_from_slice(self.view_public_key.as_bytes());
        input.extend_from_slice(self.spend_public_key.as_bytes());
        input.extend_from_slice(self.stealth_spending_key.as_bytes());
        input.extend_from_slice(self.sender_offset_public_key.as_bytes());
        let hash = blake2b(&input);
        hex::encode(hash.as_bytes())
    }

    /// Check if this address can be used for spending
    /// 
    /// Returns:
    ///     bool: True if the stealth spending key is available
    fn can_spend(&self) -> bool {
        !self.stealth_spending_key.is_empty() && self.is_valid()
    }

    /// String representation
    fn __repr__(&self) -> String {
        format!(
            "StealthAddressInfo(view={}, spend={}, stealth={}, sender={})",
            &self.view_public_key[0..8],
            &self.spend_public_key[0..8],
            &self.stealth_spending_key[0..8],
            &self.sender_offset_public_key[0..8]
        )
    }

    /// String representation
    fn __str__(&self) -> String {
        self.__repr__()
    }

    /// Equality comparison
    fn __eq__(&self, other: &Self) -> bool {
        self.view_public_key == other.view_public_key &&
        self.spend_public_key == other.spend_public_key &&
        self.stealth_spending_key == other.stealth_spending_key &&
        self.sender_offset_public_key == other.sender_offset_public_key
    }

    /// Hash for use in collections
    fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.view_public_key.hash(&mut hasher);
        self.spend_public_key.hash(&mut hasher);
        self.stealth_spending_key.hash(&mut hasher);
        self.sender_offset_public_key.hash(&mut hasher);
        hasher.finish()
    }
}

/// Python wrapper for stealth address scanning results
/// 
/// Contains the results of a stealth address scanning operation including
/// found addresses and scanning statistics.
#[pyclass]
#[derive(Clone, Debug)]
pub struct StealthScanResult {
    /// List of discovered stealth addresses
    #[pyo3(get)]
    pub addresses: Vec<StealthAddressInfo>,
    
    /// Total number of outputs scanned
    #[pyo3(get)]
    pub total_scanned: usize,
    
    /// Number of addresses found
    #[pyo3(get)]
    pub addresses_found: usize,
    
    /// Start block height for the scan
    #[pyo3(get)]
    pub start_height: Option<u64>,
    
    /// End block height for the scan
    #[pyo3(get)]
    pub end_height: Option<u64>,
    
    /// Scan duration in milliseconds
    #[pyo3(get)]
    pub duration_ms: Option<u64>,
}

#[pymethods]
impl StealthScanResult {
    /// Create a new stealth scan result
    /// 
    /// Args:
    ///     addresses: List of found stealth addresses
    ///     total_scanned: Total number of outputs scanned
    ///     start_height: Optional start block height
    ///     end_height: Optional end block height
    ///     duration_ms: Optional scan duration in milliseconds
    /// 
    /// Returns:
    ///     StealthScanResult: New scan result instance
    #[new]
    #[pyo3(signature = (addresses, total_scanned, start_height=None, end_height=None, duration_ms=None))]
    pub fn new(
        addresses: Vec<StealthAddressInfo>,
        total_scanned: usize,
        start_height: Option<u64>,
        end_height: Option<u64>,
        duration_ms: Option<u64>,
    ) -> Self {
        let addresses_found = addresses.len();
        Self {
            addresses,
            total_scanned,
            addresses_found,
            start_height,
            end_height,
            duration_ms,
        }
    }

    /// Get scanning efficiency as a percentage
    /// 
    /// Returns:
    ///     float: Percentage of scanned outputs that contained stealth addresses
    fn success_rate(&self) -> f64 {
        if self.total_scanned == 0 {
            0.0
        } else {
            (self.addresses_found as f64 / self.total_scanned as f64) * 100.0
        }
    }

    /// Get average scanning rate
    /// 
    /// Returns:
    ///     float: Outputs scanned per millisecond, or None if duration not available
    fn scan_rate(&self) -> Option<f64> {
        self.duration_ms.map(|duration| {
            if duration == 0 {
                0.0
            } else {
                self.total_scanned as f64 / duration as f64
            }
        })
    }

    /// Get block height range
    /// 
    /// Returns:
    ///     tuple: (start_height, end_height) or None if not available
    fn height_range(&self) -> Option<(u64, u64)> {
        match (self.start_height, self.end_height) {
            (Some(start), Some(end)) => Some((start, end)),
            _ => None,
        }
    }

    /// Get summary statistics
    /// 
    /// Returns:
    ///     dict: Dictionary with scanning statistics
    fn get_stats(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("total_scanned", self.total_scanned)?;
            dict.set_item("addresses_found", self.addresses_found)?;
            dict.set_item("success_rate", self.success_rate())?;
            dict.set_item("start_height", self.start_height)?;
            dict.set_item("end_height", self.end_height)?;
            dict.set_item("duration_ms", self.duration_ms)?;
            dict.set_item("scan_rate", self.scan_rate())?;
            Ok(dict.into())
        })
    }

    /// Check if the scan was successful
    /// 
    /// Returns:
    ///     bool: True if at least one stealth address was found
    fn is_successful(&self) -> bool {
        self.addresses_found > 0
    }

    /// Get addresses by criteria
    /// 
    /// Args:
    ///     can_spend: Optional filter for spendable addresses
    /// 
    /// Returns:
    ///     list: Filtered list of stealth addresses
    #[pyo3(signature = (can_spend=None))]
    fn filter_addresses(&self, can_spend: Option<bool>) -> Vec<StealthAddressInfo> {
        match can_spend {
            Some(true) => self.addresses.iter()
                .filter(|addr| addr.can_spend())
                .cloned()
                .collect(),
            Some(false) => self.addresses.iter()
                .filter(|addr| !addr.can_spend())
                .cloned()
                .collect(),
            None => self.addresses.clone(),
        }
    }

    /// Merge with another scan result
    /// 
    /// Args:
    ///     other: Another StealthScanResult to merge with
    /// 
    /// Returns:
    ///     StealthScanResult: Combined scan result
    fn merge(&self, other: &StealthScanResult) -> Self {
        let mut combined_addresses = self.addresses.clone();
        combined_addresses.extend(other.addresses.clone());
        
        let combined_scanned = self.total_scanned + other.total_scanned;
        
        let start_height = match (self.start_height, other.start_height) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        
        let end_height = match (self.end_height, other.end_height) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        
        let duration_ms = match (self.duration_ms, other.duration_ms) {
            (Some(a), Some(b)) => Some(a + b),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        StealthScanResult::new(
            combined_addresses,
            combined_scanned,
            start_height,
            end_height,
            duration_ms,
        )
    }

    /// String representation
    fn __repr__(&self) -> String {
        format!(
            "StealthScanResult(found={}, scanned={}, rate={:.2}%)",
            self.addresses_found,
            self.total_scanned,
            self.success_rate()
        )
    }

    /// String representation  
    fn __str__(&self) -> String {
        self.__repr__()
    }

    /// Length (number of addresses found)
    fn __len__(&self) -> usize {
        self.addresses_found
    }

    /// Iteration support
    fn __iter__(slf: PyRef<'_, Self>) -> PyResult<StealthScanResultIterator> {
        Ok(StealthScanResultIterator {
            result: slf.into(),
            index: 0,
        })
    }

    /// Get item by index
    fn __getitem__(&self, index: isize) -> PyResult<StealthAddressInfo> {
        let len = self.addresses.len() as isize;
        let idx = if index < 0 { len + index } else { index };
        
        if idx < 0 || idx >= len {
            return Err(pyo3::exceptions::PyIndexError::new_err("Index out of range"));
        }
        
        Ok(self.addresses[idx as usize].clone())
    }
}

/// Iterator for StealthScanResult
#[pyclass]
pub struct StealthScanResultIterator {
    result: Py<StealthScanResult>,
    index: usize,
}

#[pymethods]
impl StealthScanResultIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self) -> Option<StealthAddressInfo> {
        Python::with_gil(|py| {
            let result = self.result.borrow(py);
            if self.index < result.addresses.len() {
                let addr = result.addresses[self.index].clone();
                self.index += 1;
                Some(addr)
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_address() -> StealthAddressInfo {
        StealthAddressInfo::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            "3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        )
    }

    #[test]
    fn test_stealth_address_info_creation() {
        let addr = create_test_address();
        assert!(addr.is_valid());
        assert!(addr.can_spend());
    }

    #[test]
    fn test_stealth_address_info_equality() {
        let addr1 = create_test_address();
        let addr2 = create_test_address();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_stealth_address_info_id() {
        let addr = create_test_address();
        let id = addr.get_id();
        assert_eq!(id.len(), 128); // Blake2b 64-byte hash as hex string (128 hex chars)
    }

    #[test]
    fn test_stealth_scan_result_creation() {
        let addresses = vec![create_test_address()];
        let result = StealthScanResult::new(addresses, 100, Some(1000), Some(2000), Some(5000));
        
        assert_eq!(result.addresses_found, 1);
        assert_eq!(result.total_scanned, 100);
        assert_eq!(result.success_rate(), 1.0);
        assert!(result.is_successful());
    }

    #[test]
    fn test_stealth_scan_result_merge() {
        let addresses1 = vec![create_test_address()];
        let result1 = StealthScanResult::new(addresses1, 50, Some(1000), Some(1500), Some(2000));
        
        let addresses2 = vec![create_test_address()];
        let result2 = StealthScanResult::new(addresses2, 75, Some(1600), Some(2000), Some(3000));
        
        let merged = result1.merge(&result2);
        assert_eq!(merged.addresses_found, 2);
        assert_eq!(merged.total_scanned, 125);
        assert_eq!(merged.start_height, Some(1000));
        assert_eq!(merged.end_height, Some(2000));
        assert_eq!(merged.duration_ms, Some(5000));
    }

    #[test]
    fn test_scan_result_filtering() {
        let addr1 = create_test_address();
        let mut addr2 = create_test_address();
        addr2.stealth_spending_key = "".to_string(); // Make it non-spendable
        
        let addresses = vec![addr1, addr2];
        let result = StealthScanResult::new(addresses, 100, None, None, None);
        
        let spendable = result.filter_addresses(Some(true));
        assert_eq!(spendable.len(), 1);
        
        let non_spendable = result.filter_addresses(Some(false));
        assert_eq!(non_spendable.len(), 1);
        
        let all = result.filter_addresses(None);
        assert_eq!(all.len(), 2);
    }
}

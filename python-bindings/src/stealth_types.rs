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
/// Contains the results of a stealth address scanning operation.
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
}

#[pymethods]
impl StealthScanResult {
    /// Create a new stealth scan result
    /// 
    /// Args:
    ///     addresses: List of found stealth addresses
    ///     total_scanned: Total number of outputs scanned
    /// 
    /// Returns:
    ///     StealthScanResult: New scan result instance
    #[new]
    pub fn new(
        addresses: Vec<StealthAddressInfo>,
        total_scanned: usize,
    ) -> Self {
        let addresses_found = addresses.len();
        Self {
            addresses,
            total_scanned,
            addresses_found,
        }
    }



    /// Check if the scan was successful
    /// 
    /// Returns:
    ///     bool: True if at least one stealth address was found
    fn is_successful(&self) -> bool {
        self.addresses_found > 0
    }

    /// Get all addresses
    /// 
    /// Returns:
    ///     list: List of all stealth addresses
    fn get_addresses(&self) -> Vec<StealthAddressInfo> {
        self.addresses.clone()
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

        StealthScanResult::new(
            combined_addresses,
            combined_scanned,
        )
    }

    /// String representation
    fn __repr__(&self) -> String {
        format!(
            "StealthScanResult(found={}, scanned={})",
            self.addresses_found,
            self.total_scanned
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
        assert!(!addr.view_public_key.is_empty());
        assert!(!addr.stealth_spending_key.is_empty());
    }

    #[test]
    fn test_stealth_address_info_equality() {
        let addr1 = create_test_address();
        let addr2 = create_test_address();
        assert_eq!(addr1, addr2);
    }



    #[test]
    fn test_stealth_scan_result_creation() {
        let addresses = vec![create_test_address()];
        let result = StealthScanResult::new(addresses, 100);
        
        assert_eq!(result.addresses_found, 1);
        assert_eq!(result.total_scanned, 100);
        assert!(result.is_successful());
    }

    #[test]
    fn test_stealth_scan_result_merge() {
        let addresses1 = vec![create_test_address()];
        let result1 = StealthScanResult::new(addresses1, 50);
        
        let addresses2 = vec![create_test_address()];
        let result2 = StealthScanResult::new(addresses2, 75);
        
        let merged = result1.merge(&result2);
        assert_eq!(merged.addresses_found, 2);
        assert_eq!(merged.total_scanned, 125);
    }

    #[test]
    fn test_scan_result_get_addresses() {
        let addr1 = create_test_address();
        let addr2 = create_test_address();
        
        let addresses = vec![addr1, addr2];
        let result = StealthScanResult::new(addresses, 100);
        
        let all = result.get_addresses();
        assert_eq!(all.len(), 2);
    }
}

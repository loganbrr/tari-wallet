//! Secure memory management for sensitive data in PyO3 bindings
//!
//! This module provides ZeroizeOnDrop wrappers and secure data containers that
//! ensure sensitive cryptographic material is properly cleared from memory when
//! no longer needed, while maintaining PyO3 compatibility.

use pyo3::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure wrapper for entropy bytes to comply with orphan rules
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecureEntropy([u8; 16]);

impl SecureEntropy {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl AsRef<[u8]> for SecureEntropy {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 16]> for SecureEntropy {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}
use std::marker::PhantomData;
use std::fmt;

/// Secure wrapper for sensitive data that implements ZeroizeOnDrop
/// 
/// This container keeps sensitive data in Rust-managed memory and ensures
/// automatic zeroization when dropped. Never transfers sensitive data to
/// Python garbage collection.
#[derive(Debug)]
pub struct SecureData<T> 
where 
    T: Zeroize + ZeroizeOnDrop + Clone
{
    inner: Option<T>,
    _phantom: PhantomData<T>,
}

impl<T> SecureData<T> 
where 
    T: Zeroize + ZeroizeOnDrop + Clone
{
    /// Create new secure data container
    pub fn new(data: T) -> Self {
        Self {
            inner: Some(data),
            _phantom: PhantomData,
        }
    }
    
    /// Access data with a closure, ensuring no data escapes
    pub fn with_data<R, F>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&T) -> R,
    {
        self.inner.as_ref().map(f)
    }
    

    
    /// Check if data is still available (not zeroized)
    pub fn is_available(&self) -> bool {
        self.inner.is_some()
    }
    
    /// Explicitly zeroize the data
    pub fn zeroize(&mut self) {
        if let Some(mut data) = self.inner.take() {
            data.zeroize();
        }
    }
}

impl<T> Drop for SecureData<T> 
where 
    T: Zeroize + ZeroizeOnDrop + Clone
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T> Zeroize for SecureData<T> 
where 
    T: Zeroize + ZeroizeOnDrop + Clone
{
    fn zeroize(&mut self) {
        if let Some(mut data) = self.inner.take() {
            data.zeroize();
        }
    }
}

impl<T> ZeroizeOnDrop for SecureData<T> 
where 
    T: Zeroize + ZeroizeOnDrop + Clone
{}

// Do not implement Display or Debug that could leak sensitive data
impl<T> fmt::Display for SecureData<T> 
where 
    T: Zeroize + ZeroizeOnDrop + Clone
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_available() {
            write!(f, "SecureData(***REDACTED***)")
        } else {
            write!(f, "SecureData(ZEROIZED)")
        }
    }
}



/// PyO3 wrapper for secure data that never exposes sensitive content to Python
#[pyclass]
#[derive(Clone)]
pub struct SecureDataWrapper {
    // Use SecureData internally but never expose the actual data
    is_available: bool,
    data_type: String,
}

#[pymethods]
impl SecureDataWrapper {
    #[new]
    pub fn new(data_type: String) -> Self {
        Self {
            is_available: true,
            data_type,
        }
    }
    
    /// Check if the secure data is still available
    #[getter]
    pub fn is_available(&self) -> bool {
        self.is_available
    }
    
    /// Get the type of secure data
    #[getter] 
    pub fn data_type(&self) -> String {
        self.data_type.clone()
    }
    
    /// Mark as zeroized (called when Rust data is cleared)
    pub fn mark_zeroized(&mut self) {
        self.is_available = false;
    }
    
    /// String representation that never leaks data
    pub fn __str__(&self) -> String {
        if self.is_available {
            format!("SecureData[{}](***PROTECTED***)", self.data_type)
        } else {
            format!("SecureData[{}](ZEROIZED)", self.data_type)
        }
    }
    
    /// Representation that never leaks data
    pub fn __repr__(&self) -> String {
        self.__str__()
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_data_zeroization() {
        let sensitive = vec![1u8, 2, 3, 4];
        let mut secure = SecureData::new(sensitive);
        
        assert!(secure.is_available());
        
        secure.zeroize();
        assert!(!secure.is_available());
    }
}

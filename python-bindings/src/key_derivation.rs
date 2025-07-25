//! Key derivation path structures for Python bindings
//!
//! This module provides PyO3 wrappers for hierarchical key derivation paths,
//! supporting both tuple and string inputs following BIP32-style conventions.

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use std::str::FromStr;
use std::fmt;

/// Python wrapper for hierarchical key derivation paths
/// 
/// Supports BIP32-style paths like "m/44'/0'/1" or simple component tuples
#[pyclass]
#[derive(Clone, Debug, PartialEq)]
pub struct KeyDerivationPath {
    /// Path components (each level in the hierarchy)
    pub components: Vec<u32>,
    /// Whether each component is hardened (uses ' notation in string format)
    pub hardened: Vec<bool>,
}

#[pymethods]
impl KeyDerivationPath {
    /// Create a new KeyDerivationPath from components
    /// 
    /// Args:
    ///     components: List of integers for each path level
    ///     hardened: Optional list of booleans indicating hardened derivation
    /// 
    /// Returns:
    ///     KeyDerivationPath: New path instance
    /// 
    /// Example:
    ///     path = KeyDerivationPath([44, 0, 1], [True, False, False])
    #[new]
    #[pyo3(signature = (components, hardened=None))]
    fn new(components: Vec<u32>, hardened: Option<Vec<bool>>) -> PyResult<Self> {
        if components.is_empty() {
            return Err(PyValueError::new_err("Path components cannot be empty"));
        }

        let hardened = match hardened {
            Some(h) => {
                if h.len() != components.len() {
                    return Err(PyValueError::new_err(
                        "Hardened array length must match components length"
                    ));
                }
                h
            }
            None => vec![false; components.len()], // Default to non-hardened
        };

        Ok(KeyDerivationPath {
            components,
            hardened,
        })
    }

    /// Create a KeyDerivationPath from a string representation
    /// 
    /// Args:
    ///     path_str: BIP32-style path string like "m/44'/0'/1"
    /// 
    /// Returns:
    ///     KeyDerivationPath: Parsed path instance
    /// 
    /// Example:
    ///     path = KeyDerivationPath.from_string("m/44'/0'/1")
    #[staticmethod]
    pub fn from_string(path_str: &str) -> PyResult<Self> {
        KeyDerivationPath::from_str(path_str)
            .map_err(|e| PyValueError::new_err(format!("Invalid path string: {}", e)))
    }

    /// Get the path components
    /// 
    /// Returns:
    ///     List[int]: Path component values
    #[getter]
    pub fn components(&self) -> Vec<u32> {
        self.components.clone()
    }

    /// Get the hardened flags
    /// 
    /// Returns:
    ///     List[bool]: Hardened derivation flags for each component
    #[getter]
    fn hardened(&self) -> Vec<bool> {
        self.hardened.clone()
    }

    /// Get the path depth (number of components)
    /// 
    /// Returns:
    ///     int: Number of derivation levels
    #[getter]
    fn depth(&self) -> usize {
        self.components.len()
    }

    /// Check if the path is valid
    /// 
    /// Returns:
    ///     bool: True if the path is valid
    fn is_valid(&self) -> bool {
        !self.components.is_empty() && self.components.len() == self.hardened.len()
    }

    /// Get a specific component at index
    /// 
    /// Args:
    ///     index: Component index
    /// 
    /// Returns:
    ///     tuple: (component_value, is_hardened)
    fn get_component(&self, index: usize) -> PyResult<(u32, bool)> {
        if index >= self.components.len() {
            return Err(PyValueError::new_err("Index out of bounds"));
        }
        Ok((self.components[index], self.hardened[index]))
    }

    /// Create a child path by appending a component
    /// 
    /// Args:
    ///     component: New component value
    ///     hardened: Whether the new component is hardened (default: False)
    /// 
    /// Returns:
    ///     KeyDerivationPath: New path with appended component
    #[pyo3(signature = (component, hardened=false))]
    fn child(&self, component: u32, hardened: bool) -> Self {
        let mut new_components = self.components.clone();
        let mut new_hardened = self.hardened.clone();
        
        new_components.push(component);
        new_hardened.push(hardened);
        
        KeyDerivationPath {
            components: new_components,
            hardened: new_hardened,
        }
    }

    /// Get the parent path by removing the last component
    /// 
    /// Returns:
    ///     KeyDerivationPath: Parent path, or None if at root
    fn parent(&self) -> Option<Self> {
        if self.components.len() <= 1 {
            return None;
        }

        let mut new_components = self.components.clone();
        let mut new_hardened = self.hardened.clone();
        
        new_components.pop();
        new_hardened.pop();
        
        Some(KeyDerivationPath {
            components: new_components,
            hardened: new_hardened,
        })
    }

    /// Convert to string representation
    /// 
    /// Returns:
    ///     str: BIP32-style path string
    fn to_string(&self) -> String {
        self.to_string_impl()
    }

    /// String representation for Python
    fn __str__(&self) -> String {
        self.to_string_impl()
    }

    /// Representation for Python
    fn __repr__(&self) -> String {
        format!("KeyDerivationPath('{}')", self.to_string_impl())
    }

    /// Equality comparison
    fn __eq__(&self, other: &Self) -> bool {
        self.components == other.components && self.hardened == other.hardened
    }

    /// Hash for use in collections
    fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.components.hash(&mut hasher);
        self.hardened.hash(&mut hasher);
        hasher.finish()
    }
}

impl KeyDerivationPath {
    /// Internal string conversion implementation
    fn to_string_impl(&self) -> String {
        if self.components.is_empty() {
            return "m".to_string();
        }

        let mut result = String::from("m");
        for (component, hardened) in self.components.iter().zip(self.hardened.iter()) {
            result.push('/');
            result.push_str(&component.to_string());
            if *hardened {
                result.push('\'');
            }
        }
        result
    }
}

impl FromStr for KeyDerivationPath {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        
        // Must start with 'm' for master key
        if !trimmed.starts_with('m') {
            return Err("Path must start with 'm'".to_string());
        }

        // Handle just "m" (root path)
        if trimmed == "m" {
            return Ok(KeyDerivationPath {
                components: vec![],
                hardened: vec![],
            });
        }

        // Must have '/' separator after 'm'
        if !trimmed.starts_with("m/") {
            return Err("Path must start with 'm/' for derivation".to_string());
        }

        let path_part = &trimmed[2..]; // Skip "m/"
        if path_part.is_empty() {
            return Ok(KeyDerivationPath {
                components: vec![],
                hardened: vec![],
            });
        }

        let parts: Vec<&str> = path_part.split('/').collect();
        let mut components = Vec::new();
        let mut hardened = Vec::new();

        for part in parts {
            if part.is_empty() {
                return Err("Empty path component".to_string());
            }

            let (component_str, is_hardened) = if part.ends_with('\'') {
                (&part[..part.len() - 1], true)
            } else {
                (part, false)
            };

            let component: u32 = component_str.parse()
                .map_err(|_| format!("Invalid component: {}", component_str))?;

            components.push(component);
            hardened.push(is_hardened);
        }

        Ok(KeyDerivationPath {
            components,
            hardened,
        })
    }
}

impl fmt::Display for KeyDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_impl())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_path() {
        let path = KeyDerivationPath::new(vec![44, 0, 1], Some(vec![true, false, false])).unwrap();
        assert_eq!(path.components, vec![44, 0, 1]);
        assert_eq!(path.hardened, vec![true, false, false]);
    }

    #[test]
    fn test_from_string_simple() {
        let path = KeyDerivationPath::from_string("m/44'/0/1").unwrap();
        assert_eq!(path.components, vec![44, 0, 1]);
        assert_eq!(path.hardened, vec![true, false, false]);
    }

    #[test]
    fn test_from_string_root() {
        let path = KeyDerivationPath::from_string("m").unwrap();
        assert_eq!(path.components, Vec::<u32>::new());
        assert_eq!(path.hardened, Vec::<bool>::new());
    }

    #[test]
    fn test_to_string() {
        let path = KeyDerivationPath::new(vec![44, 0, 1], Some(vec![true, false, false])).unwrap();
        assert_eq!(path.to_string(), "m/44'/0/1");
    }

    #[test]
    fn test_child() {
        let path = KeyDerivationPath::new(vec![44], Some(vec![true])).unwrap();
        let child = path.child(0, false);
        assert_eq!(child.components, vec![44, 0]);
        assert_eq!(child.hardened, vec![true, false]);
    }

    #[test]
    fn test_parent() {
        let path = KeyDerivationPath::new(vec![44, 0, 1], Some(vec![true, false, false])).unwrap();
        let parent = path.parent().unwrap();
        assert_eq!(parent.components, vec![44, 0]);
        assert_eq!(parent.hardened, vec![true, false]);
    }

    #[test]
    fn test_validation() {
        let path = KeyDerivationPath::new(vec![44, 0], Some(vec![true, false])).unwrap();
        assert!(path.is_valid());
        
        // Test invalid path
        let invalid_result = KeyDerivationPath::new(vec![], None);
        assert!(invalid_result.is_err());
    }

    #[test]
    fn test_equality() {
        let path1 = KeyDerivationPath::new(vec![44, 0], Some(vec![true, false])).unwrap();
        let path2 = KeyDerivationPath::new(vec![44, 0], Some(vec![true, false])).unwrap();
        let path3 = KeyDerivationPath::new(vec![44, 1], Some(vec![true, false])).unwrap();
        
        assert_eq!(path1, path2);
        assert_ne!(path1, path3);
    }
}

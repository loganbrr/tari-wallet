//! Macros for reducing field extraction boilerplate in Python bindings
//!
//! This module provides macros to eliminate the repetitive field extraction patterns
//! found throughout storage.rs and transaction.rs modules.

/// Macro to extract required fields from PyDict with consistent error handling
/// 
/// Usage:
/// ```rust
/// extract_required_field!(dict, "field_name", String)
/// extract_required_field!(dict, "field_name", u32, "custom error message")
/// ```
#[macro_export]
macro_rules! extract_required_field {
    ($dict:expr, $field:literal, $type:ty) => {
        match $dict.get_item($field)? {
            Some(v) => v.extract::<$type>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                concat!("Missing required field: ", $field)
            )),
        }
    };
    ($dict:expr, $field:literal, $type:ty, $custom_error:literal) => {
        match $dict.get_item($field)? {
            Some(v) => v.extract::<$type>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>($custom_error)),
        }
    };
}

/// Macro to extract optional fields from PyDict with None handling
/// 
/// Usage:
/// ```rust
/// extract_optional_field!(dict, "field_name", String)
/// extract_optional_field!(dict, "field_name", u64, Some(default_value))
/// ```
#[macro_export]
macro_rules! extract_optional_field {
    ($dict:expr, $field:literal, $type:ty) => {
        match $dict.get_item($field)? {
            Some(v) if !v.is_none() => Some(v.extract::<$type>()?),
            _ => None,
        }
    };
    ($dict:expr, $field:literal, $type:ty, $default:expr) => {
        match $dict.get_item($field)? {
            Some(v) if !v.is_none() => Some(v.extract::<$type>()?),
            _ => $default,
        }
    };
}

/// Macro to extract hex strings and validate byte length
/// 
/// Usage:
/// ```rust
/// extract_hex_field!(dict, "commitment_hex", 32)
/// extract_hex_field!(dict, "key_hex", 32, "Invalid key")
/// ```
#[macro_export]
macro_rules! extract_hex_field {
    ($dict:expr, $field:literal, $expected_len:literal) => {{
        let hex_str = extract_required_field!($dict, $field, String);
        let bytes = hex::decode(&hex_str).map_err(|e| {
            lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                format!("Invalid {} hex: {}", $field, e)
            )
        })?;
        if bytes.len() != $expected_len {
            return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                argument: $field.into(),
                value: format!("{} bytes", bytes.len()),
                message: format!("{} must be {} bytes", $field, $expected_len),
            });
        }
        let mut array = [0u8; $expected_len];
        array.copy_from_slice(&bytes);
        array
    }};
    ($dict:expr, $field:literal, $expected_len:literal, $error_prefix:literal) => {{
        let hex_str = extract_required_field!($dict, $field, String);
        let bytes = hex::decode(&hex_str).map_err(|e| {
            lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                format!("{}: {}", $error_prefix, e)
            )
        })?;
        if bytes.len() != $expected_len {
            return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                argument: $field.into(),
                value: format!("{} bytes", bytes.len()),
                message: format!("{} must be {} bytes", $error_prefix, $expected_len),
            });
        }
        let mut array = [0u8; $expected_len];
        array.copy_from_slice(&bytes);
        array
    }};
}

/// Macro for filter parameter extraction with unified error handling
/// 
/// Usage:
/// ```rust
/// if let Some(direction) = extract_filter_param!(dict, "direction", String)? {
///     let parsed = parse_transaction_direction(&direction)?;
///     filter = filter.with_direction(parsed);
/// }
/// ```
#[macro_export]
macro_rules! extract_filter_param {
    ($dict:expr, $field:literal, $type:ty) => {
        {
            let result: Result<Option<$type>, lightweight_wallet_libs::errors::LightweightWalletError> = 
                match $dict.get_item($field).map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        format!("Filter error: {}", e)
                    )
                })? {
                    Some(val) => {
                        let extracted: $type = val.extract().map_err(|e| {
                            lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                                format!("{} extraction error: {}", $field, e)
                            )
                        })?;
                        Ok(Some(extracted))
                    }
                    None => Ok(None),
                };
            result
        }
    };
}

/// Macro to create Python dictionary with multiple items
/// 
/// Usage:
/// ```rust
/// create_py_dict!(py, {
///     "field1" => value1,
///     "field2" => value2,
///     "field3" => &string_value
/// })
/// ```
#[macro_export]
macro_rules! create_py_dict {
    ($py:expr, { $($key:literal => $value:expr),* $(,)? }) => {{
        let dict = pyo3::types::PyDict::new($py);
        $(
            dict.set_item($key, $value)?;
        )*
        dict
    }};
}

/// Macro for storage guard acquisition with consistent error handling
#[macro_export]
macro_rules! get_storage_guard {
    ($storage_arc:expr) => {{
        let guard = $storage_arc.lock().map_err(|_| {
            lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                "Failed to lock storage".into()
            )
        })?;
        
        guard.as_ref().ok_or_else(|| {
            lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                "Storage not initialized - call initialize() first".into()
            )
        })?
    }};
}

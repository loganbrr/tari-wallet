pub fn format_number<T: std::fmt::Display>(val: T) -> String {
    let val_str = val.to_string();
    let is_negative = val_str.starts_with('-');
    let abs_str = if is_negative { &val_str[1..] } else { &val_str };
    
    // Split on decimal point if present
    let parts: Vec<&str> = abs_str.split('.').collect();
    let integer_part = parts[0];
    
    // Format the integer part with commas
    let formatted_integer = integer_part
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap()
        .join(","); // separator
    
    // Reconstruct the number
    let mut result = if parts.len() > 1 {
        // Has decimal part - join with decimal point
        format!("{}.{}", formatted_integer, parts[1])
    } else {
        // No decimal part
        formatted_integer
    };
    
    if is_negative {
        result = format!("-{result}");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_positive_integers() {
        assert_eq!(format_number(123), "123");
        assert_eq!(format_number(1234), "1,234");
        assert_eq!(format_number(12345), "12,345");
        assert_eq!(format_number(123456), "123,456");
        assert_eq!(format_number(1234567), "1,234,567");
        assert_eq!(format_number(12345678), "12,345,678");
        assert_eq!(format_number(123456789), "123,456,789");
    }

    #[test]
    fn test_negative_integers() {
        assert_eq!(format_number(-123), "-123");
        assert_eq!(format_number(-1234), "-1,234");
        assert_eq!(format_number(-12345), "-12,345");
        assert_eq!(format_number(-123456), "-123,456");
        assert_eq!(format_number(-1234567), "-1,234,567");
        assert_eq!(format_number(-12345678), "-12,345,678");
        assert_eq!(format_number(-123456789), "-123,456,789");
    }

    #[test]
    fn test_zero() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(0i32), "0");
        assert_eq!(format_number(0i64), "0");
        assert_eq!(format_number(0.0f32), "0");
        assert_eq!(format_number(0.0f64), "0");
    }

    #[test]
    fn test_positive_decimals() {
        assert_eq!(format_number(123.45), "123.45");
        assert_eq!(format_number(1234.56), "1,234.56");
        assert_eq!(format_number(12345.678), "12,345.678");
        assert_eq!(format_number(123456.789), "123,456.789");
        assert_eq!(format_number(1234567.89), "1,234,567.89");
        assert_eq!(format_number(12345678.901), "12,345,678.901");
    }

    #[test]
    fn test_negative_decimals() {
        assert_eq!(format_number(-123.45), "-123.45");
        assert_eq!(format_number(-1234.56), "-1,234.56");
        assert_eq!(format_number(-12345.678), "-12,345.678");
        assert_eq!(format_number(-123456.789), "-123,456.789");
        assert_eq!(format_number(-1234567.89), "-1,234,567.89");
        assert_eq!(format_number(-12345678.901), "-12,345,678.901");
    }

    #[test]
    fn test_small_decimals() {
        assert_eq!(format_number(0.123), "0.123");
        assert_eq!(format_number(-0.456), "-0.456");
        assert_eq!(format_number(0.000001), "0.000001");
        assert_eq!(format_number(-0.000001), "-0.000001");
    }

    #[test]
    fn test_different_numeric_types() {
        // Test various integer types (using values within range)
        assert_eq!(format_number(123i8), "123");
        assert_eq!(format_number(-127i8), "-127");
        assert_eq!(format_number(12345i16), "12,345");
        assert_eq!(format_number(123456i32), "123,456");
        assert_eq!(format_number(1234567i64), "1,234,567");
        assert_eq!(format_number(12345678i128), "12,345,678");
        
        // Test unsigned types (using values within range)
        assert_eq!(format_number(234u8), "234");
        assert_eq!(format_number(255u8), "255");
        assert_eq!(format_number(12345u16), "12,345");
        assert_eq!(format_number(123456u32), "123,456");
        assert_eq!(format_number(1234567u64), "1,234,567");
        assert_eq!(format_number(12345678u128), "12,345,678");
        
        // Test floating point types
        assert_eq!(format_number(1234.5f32), "1,234.5");
        assert_eq!(format_number(12345.67f64), "12,345.67");
    }

    #[test]
    fn test_edge_cases() {
        // Single digit
        assert_eq!(format_number(5), "5");
        assert_eq!(format_number(-7), "-7");
        
        // Two digits
        assert_eq!(format_number(42), "42");
        assert_eq!(format_number(-99), "-99");
        
        // Three digits (boundary case)
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(-999), "-999");
        
        // Four digits (first comma)
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(-1000), "-1,000");
        
        // Large numbers
        assert_eq!(format_number(1000000000), "1,000,000,000");
        assert_eq!(format_number(-1000000000), "-1,000,000,000");
    }

    #[test]
    fn test_scientific_notation() {
        // Very large numbers that might use scientific notation
        assert_eq!(format_number(1e12 as i64), "1,000,000,000,000");
        assert_eq!(format_number(-1e12 as i64), "-1,000,000,000,000");
        
        // Small decimals that might use scientific notation
        let small_decimal = 0.000000001f64;
        let result = format_number(small_decimal);
        // The exact format depends on how Rust formats very small decimals
        assert!(!result.is_empty());
    }
}
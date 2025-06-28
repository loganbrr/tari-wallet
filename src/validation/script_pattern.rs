use tari_script::{TariScript, Opcode};
use tari_crypto::ristretto::RistrettoPublicKey;

/// Represents the different types of script patterns we can detect
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptPattern {
    /// Standard output with single Nop instruction
    Standard,
    /// Simple one-sided output: PushPubKey(scanned_pk)
    SimpleOneSided,
    /// Stealth one-sided output: PushPubKey(nonce), Drop, PushPubKey(scanned_pk)
    StealthOneSided,
    /// Unknown or unsupported pattern
    Unknown,
}

/// Check if a script matches the standard output pattern (single Nop instruction)
pub fn is_standard_output(script: &TariScript) -> bool {
    if script.size() != 1 {
        return false;
    }
    
    matches!(script.opcode(0), Some(Opcode::Nop))
}

/// Check if a script matches the simple one-sided pattern: PushPubKey(scanned_pk)
pub fn is_simple_one_sided_output(script: &TariScript, _derived_keys: &[RistrettoPublicKey]) -> bool {
    if script.size() != 1 {
        return false;
    }
    
    matches!(script.opcode(0), Some(Opcode::PushPubKey(_)))
}

/// Check if a script matches the stealth one-sided pattern: PushPubKey(nonce), Drop, PushPubKey(scanned_pk)
pub fn is_stealth_one_sided_output(script: &TariScript, _derived_keys: &[RistrettoPublicKey]) -> bool {
    if script.size() != 3 {
        return false;
    }
    
    // Check pattern: PushPubKey(nonce), Drop, PushPubKey(scanned_pk)
    matches!(script.opcode(0), Some(Opcode::PushPubKey(_))) &&
    matches!(script.opcode(1), Some(Opcode::Drop)) &&
    matches!(script.opcode(2), Some(Opcode::PushPubKey(_)))
}

/// Analyze a script and determine which pattern it matches
pub fn analyze_script_pattern(script: &TariScript, derived_keys: &[RistrettoPublicKey]) -> ScriptPattern {
    // Check for standard output pattern first
    if is_standard_output(script) {
        return ScriptPattern::Standard;
    }
    
    // Check for simple one-sided pattern
    if is_simple_one_sided_output(script, derived_keys) {
        return ScriptPattern::SimpleOneSided;
    }
    
    // Check for stealth one-sided pattern
    if is_stealth_one_sided_output(script, derived_keys) {
        return ScriptPattern::StealthOneSided;
    }
    
    ScriptPattern::Unknown
}

/// Check if any of the script patterns indicate this output belongs to our wallet
/// For now, this detects patterns but doesn't verify key ownership
pub fn is_wallet_output(script: &TariScript, derived_keys: &[RistrettoPublicKey]) -> bool {
    match analyze_script_pattern(script, derived_keys) {
        ScriptPattern::Standard => true, // All standard outputs are potential wallet outputs
        ScriptPattern::SimpleOneSided => true, // TODO: Actually verify key match
        ScriptPattern::StealthOneSided => true, // TODO: Actually verify key match
        ScriptPattern::Unknown => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_script::script;
    
    #[test]
    fn test_standard_output_pattern() {
        let script = script!(Nop);
        assert!(is_standard_output(&script));
        
        let script = script!(Nop Nop);
        assert!(!is_standard_output(&script));
    }
    
    #[test] 
    fn test_script_pattern_analysis() {
        let derived_keys = vec![];
        
        let script = script!(Nop);
        assert_eq!(analyze_script_pattern(&script, &derived_keys), ScriptPattern::Standard);
        
        let script = script!(PushZero);
        assert_eq!(analyze_script_pattern(&script, &derived_keys), ScriptPattern::Unknown);
    }
} 
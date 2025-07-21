//! Tari Message Signing CLI Tool
//!
//! A command-line utility for signing and verifying messages using Tari-compatible
//! Schnorr signatures with domain separation.

use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use std::fs;
use tari_crypto::keys::{PublicKey, SecretKey};
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_utilities::hex::Hex;

use lightweight_wallet_libs::crypto::signing::{
    sign_message_with_hex_output, verify_message_from_hex,
};

#[derive(Parser)]
#[command(name = "signing")]
#[command(about = "Tari-compatible message signing and verification tool")]
#[command(long_about = "A CLI tool for signing and verifying messages using Schnorr signatures with Tari wallet-compatible domain separation")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair
    #[command(about = "Generate a new Ed25519 keypair")]
    Generate {
        /// Output file for the secret key (hex format)
        #[arg(long, short)]
        secret_key_file: Option<String>,
        
        /// Output file for the public key (hex format)
        #[arg(long, short)]
        public_key_file: Option<String>,
        
        /// Print keys to stdout instead of files
        #[arg(long)]
        stdout: bool,
    },
    
    /// Sign a message
    #[command(about = "Sign a message using a secret key")]
    Sign {
        /// Secret key in hex format
        #[arg(long, short, group = "key_input")]
        secret_key: Option<String>,
        
        /// File containing secret key in hex format
        #[arg(long, group = "key_input")]
        secret_key_file: Option<String>,
        
        /// Message to sign
        #[arg(long, short, group = "message_input")]
        message: Option<String>,
        
        /// File containing message to sign
        #[arg(long, group = "message_input")]
        message_file: Option<String>,
        
        /// Output signature to file
        #[arg(long)]
        output_file: Option<String>,
        
        /// Output format: 'compact' (signature:nonce) or 'json' (structured)
        #[arg(long, default_value = "compact")]
        format: String,
    },
    
    /// Verify a message signature
    #[command(about = "Verify a message signature using a public key")]
    Verify {
        /// Public key in hex format
        #[arg(long, short, group = "key_input")]
        public_key: Option<String>,
        
        /// File containing public key in hex format
        #[arg(long, group = "key_input")]
        public_key_file: Option<String>,
        
        /// Message that was signed
        #[arg(long, short, group = "message_input")]
        message: Option<String>,
        
        /// File containing message that was signed
        #[arg(long, group = "message_input")]
        message_file: Option<String>,
        
        /// Signature in hex format
        #[arg(long, short, requires = "nonce")]
        signature: Option<String>,
        
        /// Public nonce in hex format
        #[arg(long, short, requires = "signature")]
        nonce: Option<String>,
        
        /// File containing signature in compact format (signature:nonce)
        #[arg(long, conflicts_with_all = ["signature", "nonce"])]
        signature_file: Option<String>,
        
        /// Verbose output
        #[arg(long, short)]
        verbose: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            secret_key_file,
            public_key_file,
            stdout,
        } => {
            let secret_key = RistrettoSecretKey::random(&mut OsRng);
            let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
            
            let secret_hex = secret_key.to_hex();
            let public_hex = public_key.to_hex();
            
            if stdout {
                println!("Secret Key: {}", secret_hex);
                println!("Public Key: {}", public_hex);
            } else {
                if let Some(sk_file) = secret_key_file {
                    fs::write(&sk_file, &secret_hex)?;
                    println!("Secret key written to: {}", sk_file);
                } else {
                    println!("Secret Key: {}", secret_hex);
                }
                
                if let Some(pk_file) = public_key_file {
                    fs::write(&pk_file, &public_hex)?;
                    println!("Public key written to: {}", pk_file);
                } else {
                    println!("Public Key: {}", public_hex);
                }
            }
        }
        
        Commands::Sign {
            secret_key,
            secret_key_file,
            message,
            message_file,
            output_file,
            format,
        } => {
            // Get secret key
            let secret_key_hex = match (secret_key, secret_key_file) {
                (Some(key), None) => key,
                (None, Some(file)) => fs::read_to_string(&file)?.trim().to_string(),
                _ => return Err("Must provide either --secret-key or --secret-key-file".into()),
            };
            
            let secret_key = RistrettoSecretKey::from_hex(&secret_key_hex)
                .map_err(|e| format!("Invalid secret key hex: {}", e))?;
            
            // Get message
            let message_text = match (message, message_file) {
                (Some(msg), None) => msg,
                (None, Some(file)) => fs::read_to_string(&file)?,
                _ => return Err("Must provide either --message or --message-file".into()),
            };
            
            // Sign the message
            let (signature_hex, nonce_hex) = sign_message_with_hex_output(&secret_key, &message_text)?;
            
            let output = match format.as_str() {
                "compact" => format!("{}:{}", signature_hex, nonce_hex),
                "json" => serde_json::to_string_pretty(&serde_json::json!({
                    "signature": signature_hex,
                    "nonce": nonce_hex,
                    "message": message_text
                }))?,
                _ => return Err("Invalid format. Use 'compact' or 'json'".into()),
            };
            
            if let Some(file) = output_file {
                fs::write(&file, &output)?;
                println!("Signature written to: {}", file);
            } else {
                println!("{}", output);
            }
        }
        
        Commands::Verify {
            public_key,
            public_key_file,
            message,
            message_file,
            signature,
            nonce,
            signature_file,
            verbose,
        } => {
            // Get public key
            let public_key_hex = match (public_key, public_key_file) {
                (Some(key), None) => key,
                (None, Some(file)) => fs::read_to_string(&file)?.trim().to_string(),
                _ => return Err("Must provide either --public-key or --public-key-file".into()),
            };
            
            let public_key = RistrettoPublicKey::from_hex(&public_key_hex)
                .map_err(|e| format!("Invalid public key hex: {}", e))?;
            
            // Get message
            let message_text = match (message, message_file) {
                (Some(msg), None) => msg,
                (None, Some(file)) => fs::read_to_string(&file)?,
                _ => return Err("Must provide either --message or --message-file".into()),
            };
            
            // Get signature components
            let (sig_hex, nonce_hex) = match (signature, nonce, signature_file) {
                (Some(sig), Some(n), None) => (sig, n),
                (None, None, Some(file)) => {
                    let content = fs::read_to_string(&file)?.trim().to_string();
                    
                    // Try to parse as compact format first
                    if let Some((sig, n)) = content.split_once(':') {
                        (sig.to_string(), n.to_string())
                    } else {
                        // Try to parse as JSON
                        let parsed: serde_json::Value = serde_json::from_str(&content)?;
                        let sig = parsed["signature"].as_str()
                            .ok_or("Missing 'signature' field in JSON")?
                            .trim();
                        let n = parsed["nonce"].as_str()
                            .ok_or("Missing 'nonce' field in JSON")?
                            .trim();
                        (sig.to_string(), n.to_string())
                    }
                },
                _ => return Err("Must provide either (--signature and --nonce) or --signature-file".into()),
            };
            
            // Verify the signature
            let is_valid = verify_message_from_hex(&public_key, &message_text, &sig_hex, &nonce_hex)?;
            
            if verbose {
                println!("Message: \"{}\"", message_text);
                println!("Public Key: {}", public_key_hex);
                println!("Signature: {}", sig_hex);
                println!("Nonce: {}", nonce_hex);
                println!("Valid: {}", is_valid);
            } else {
                println!("{}", if is_valid { "VALID" } else { "INVALID" });
            }
            
            if !is_valid {
                std::process::exit(1);
            }
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        // This test verifies the keypair generation functionality
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        
        assert_eq!(secret_key.to_hex().len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(public_key.to_hex().len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_sign_and_verify_workflow() -> Result<(), Box<dyn std::error::Error>> {
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "Test message for CLI";

        // Test signing
        let (signature_hex, nonce_hex) = sign_message_with_hex_output(&secret_key, message)?;
        
        // Test verification
        let is_valid = verify_message_from_hex(&public_key, message, &signature_hex, &nonce_hex)?;
        
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_compact_format_parsing() {
        let signature = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let nonce = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let compact = format!("{}:{}", signature, nonce);
        
        let (parsed_sig, parsed_nonce) = compact.split_once(':').unwrap();
        assert_eq!(parsed_sig, signature);
        assert_eq!(parsed_nonce, nonce);
    }
}

use std::env;

use lightweight_wallet_libs::data_structures::address::TariAddressFeatures;
use lightweight_wallet_libs::wallet::Wallet;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return;
    }
    
    match args[1].as_str() {
        "new-wallet" => handle_new_wallet(&args[2..]),
        "new-address" => handle_new_address(&args[2..]),
        _ => {
            eprintln!("Error: Unknown command '{}'", args[1]);
            print_usage();
        }
    }
}

fn print_usage() {
    println!("Tari Wallet CLI");
    println!();
    println!("Usage:");
    println!("  cargo run --example wallet_cli new-wallet [--network <network>] [--payment-id <string>] [--passphrase <passphrase>]");
    println!("  cargo run --example wallet_cli new-address <seed_phrase> [--network <network>] [--payment-id <string>] [--passphrase <passphrase>]");
    println!();
    println!("Commands:");
    println!("  new-wallet     Generate a new wallet with seed phrase and one-sided address");
    println!("  new-address    Generate a one-sided address from existing seed phrase");
    println!();
    println!("Options:");
    println!("  --network      Network to use (mainnet, esmeralda, stagenet) [default: mainnet]");
    println!("  --payment-id   Payment ID as UTF-8 string (e.g., \"my-payment-123\")");
    println!("  --passphrase   Optional passphrase for CipherSeed encryption/decryption");
    println!();
    println!("Examples:");
    println!("  cargo run --example wallet_cli new-wallet");
    println!("  cargo run --example wallet_cli new-wallet --network esmeralda");
    println!("  cargo run --example wallet_cli new-wallet --payment-id \"my-payment-123\"");
    println!("  cargo run --example wallet_cli new-wallet --passphrase \"my-secret-passphrase\"");
    println!("  cargo run --example wallet_cli new-address \"word1 word2 ... word24\"");
    println!("  cargo run --example wallet_cli new-address \"word1 word2 ... word24\" --network stagenet --payment-id \"order-456\"");
    println!("  cargo run --example wallet_cli new-address \"word1 word2 ... word24\" --passphrase \"my-secret-passphrase\"");
}

fn handle_new_wallet(args: &[String]) {
    let mut network = "mainnet".to_string();
    let mut payment_id: Option<Vec<u8>> = None;
    let mut passphrase: Option<&str> = None;
    
    // Parse arguments
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--network" => {
                if i + 1 < args.len() {
                    network = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --network requires a value");
                    print_usage();
                    return;
                }
            }
            "--payment-id" => {
                if i + 1 < args.len() {
                    payment_id = Some(args[i + 1].as_bytes().to_vec());
                    i += 2;
                } else {
                    eprintln!("Error: --payment-id requires a value");
                    print_usage();
                    return;
                }
            }
            "--passphrase" => {
                if i + 1 < args.len() {
                    passphrase = Some(&args[i + 1]);
                    i += 2;
                } else {
                    eprintln!("Error: --passphrase requires a value");
                    print_usage();
                    return;
                }
            }
            _ => {
                eprintln!("Error: Unknown argument: {}", args[i]);
                print_usage();
                return;
            }
        }
    }
    
    // Validate network
    if !is_valid_network(&network) {
        eprintln!("Error: Invalid network '{}'. Valid networks: mainnet, esmeralda, stagenet", network);
        return;
    }
    
    // Generate new wallet
    match Wallet::generate_new_with_seed_phrase(passphrase) {
        Ok(mut wallet) => {
            wallet.set_network(network.clone());
            
            // Get seed phrase
            match wallet.export_seed_phrase() {
                Ok(seed) => {
                    println!("Seed: {}", seed);
                    
                    // Generate one-sided address using dual address method to support payment ID
                    match wallet.get_dual_address(TariAddressFeatures::create_one_sided_only(), payment_id) {
                        Ok(address) => {
                            println!("Base58: {}", address.to_base58());
                            println!("Emoji: {}", address.to_emoji_string());
                            
                            // Print additional info if payment ID was provided
                            if address.features().contains(TariAddressFeatures::PAYMENT_ID) {
                                println!("Payment ID included: Yes");
                            }
                        }
                        Err(e) => eprintln!("Error generating address: {}", e),
                    }
                }
                Err(e) => eprintln!("Error exporting seed: {}", e),
            }
        }
        Err(e) => eprintln!("Error creating wallet: {}", e),
    }
}

fn handle_new_address(args: &[String]) {
    if args.is_empty() {
        eprintln!("Error: seed phrase is required");
        print_usage();
        return;
    }
    
    let seed = &args[0];
    let mut network = "mainnet".to_string();
    let mut payment_id: Option<Vec<u8>> = None;
    let mut passphrase: Option<&str> = None;
    
    // Parse remaining arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--network" => {
                if i + 1 < args.len() {
                    network = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --network requires a value");
                    print_usage();
                    return;
                }
            }
            "--payment-id" => {
                if i + 1 < args.len() {
                    payment_id = Some(args[i + 1].as_bytes().to_vec());
                    i += 2;
                } else {
                    eprintln!("Error: --payment-id requires a value");
                    print_usage();
                    return;
                }
            }
            "--passphrase" => {
                if i + 1 < args.len() {
                    passphrase = Some(&args[i + 1]);
                    i += 2;
                } else {
                    eprintln!("Error: --passphrase requires a value");
                    print_usage();
                    return;
                }
            }
            _ => {
                eprintln!("Error: Unknown argument: {}", args[i]);
                print_usage();
                return;
            }
        }
    }
    
    // Validate network
    if !is_valid_network(&network) {
        eprintln!("Error: Invalid network '{}'. Valid networks: mainnet, esmeralda, stagenet", network);
        return;
    }
    
    // Create wallet from seed
    match Wallet::new_from_seed_phrase(seed, passphrase) {
        Ok(mut wallet) => {
            wallet.set_network(network.clone());
            
            // Generate one-sided address using dual address method to support payment ID
            match wallet.get_dual_address(TariAddressFeatures::create_one_sided_only(), payment_id) {
                Ok(address) => {
                    println!("Base58: {}", address.to_base58());
                    println!("Emoji: {}", address.to_emoji_string());
                    
                    // Print additional info if payment ID was provided
                    if address.features().contains(TariAddressFeatures::PAYMENT_ID) {
                        println!("Payment ID included: Yes");
                    }
                }
                Err(e) => eprintln!("Error generating address: {}", e),
            }
        }
        Err(e) => eprintln!("Error creating wallet from seed: {}", e),
    }
}

fn is_valid_network(network: &str) -> bool {
    matches!(network, "mainnet" | "esmeralda" | "stagenet")
} 
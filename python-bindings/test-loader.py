#!/usr/bin/env python3
from loader import Wallet
import sys
import os

def test_wallet_functionality():
    """Test basic wallet operations"""
    
    # Path to your WASM file
    wasm_path = os.path.join(os.path.dirname(__file__), 'pkg', 'lightweight_wallet_libs.wasm')
    
    if not os.path.exists(wasm_path):
        print(f"❌ WASM file not found: {wasm_path}")
        print("Run: cargo build --target wasm32-unknown-unknown --release --features wasm")
        print("Then: cp target/wasm32-unknown-unknown/release/lightweight_wallet_libs.wasm python-bindings/pkg/")
        return False
    
    try:
        # Initialize wallet
        print("🔄 Loading wallet...")
        wallet = Wallet(wasm_path)
        if not wallet:
            print('wallet not initializing. fix dat')
        
        # Test version
        print("🔄 Testing get_version()...")
        version = wallet.get_version()
        print(f"✅ Version: {version}")
        
        # Test public key derivation  
        print("🔄 Testing derive_public_key_hex()...")
        test_key = b'\x01' * 32  # Simple test key
        try:
            pub_key = wallet.derive_public_key_hex(test_key)
            print(f"✅ Public key: {pub_key}")
        except Exception as e:
            print(f"⚠️  derive_public_key_hex failed: {e}")
        
        # Test scanner creation
        print("🔄 Testing scanner creation...")
        test_seed_phrase = 'word' * 25
        try:
            scanner = wallet.new_scanner(test_seed_phrase)
            print("✅ Scanner created successfully")
            
            # Test scanner methods
            print("🔄 Testing scanner.get_scanner_state()...")
            state = scanner.get_scanner_state()
            print(f"✅ Scanner state: {state}")
            
            # Clean up
            scanner.drop()
            print("✅ Scanner cleaned up")
            
        except Exception as e:
            print(f"⚠️  Scanner test failed: {e}")
        
        print("\n🎉 Basic tests completed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_wallet_functionality()
    sys.exit(0 if success else 1)

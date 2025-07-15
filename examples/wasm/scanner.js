#!/usr/bin/env node

/**
 * Tari WASM Scanner - Node.js Example
 * 
 * This example demonstrates how to use the Tari WASM scanner in a Node.js environment
 * to scan blockchain data for wallet transactions.
 * 
 * Usage:
 *   node examples/wasm/scanner.js [seed_phrase|view_key] [data] [base_node_url]
 * 
 * Examples:
 *   node examples/wasm/scanner.js view_key
 *   node examples/wasm/scanner.js seed_phrase "your 24 word seed phrase here"
 *   node examples/wasm/scanner.js view_key "your_hex_key" "http://192.168.1.100:9000"
 * 
 * Requirements:
 *   - Build the WASM package first: wasm-pack build --target nodejs --out-dir pkg --example wasm_scanner
 *   - Install dependencies: npm install
 *   - (Optional) Tari base node running with API enabled for real blockchain data
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');

/**
 * HTTP Client for communicating with Tari base node
 */
class HttpClient {
    constructor(baseUrl = 'http://127.0.0.1:9000') {
        this.baseUrl = baseUrl;
    }

    /**
     * Make HTTP GET request
     */
    async request(endpoint, params = {}) {
        const url = new URL(endpoint, this.baseUrl);
        
        // Add query parameters
        Object.keys(params).forEach(key => {
            if (params[key] !== undefined && params[key] !== null) {
                url.searchParams.append(key, params[key]);
            }
        });

        return new Promise((resolve, reject) => {
            const client = url.protocol === 'https:' ? https : http;
            
            const req = client.get(url.toString(), (res) => {
                let data = '';
                
                res.on('data', (chunk) => {
                    data += chunk;
                });
                
                res.on('end', () => {
                    try {
                        if (res.statusCode >= 200 && res.statusCode < 300) {
                            const jsonData = JSON.parse(data);
                            resolve(jsonData);
                        } else {
                            reject(new Error(`HTTP ${res.statusCode}: ${data}`));
                        }
                    } catch (error) {
                        reject(new Error(`Failed to parse JSON: ${error.message}`));
                    }
                });
            });
            
            req.on('error', (error) => {
                reject(new Error(`Request failed: ${error.message}`));
            });
            
            req.setTimeout(10000, () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
        });
    }

    /**
     * Get tip info
     * @returns {Promise<Object>} Tip info
     */
    async getTipInfo() {
        /**
         * {"metadata":{"best_block_height":50508,"best_block_hash":[159,218,81,52,13,209,72,199,53,213,102,125,30,254,101,1,70,142,17,178,243,154,113,172,7,73,192,145,150,113,241,113],"pruning_horizon":0,"pruned_height":0,"accumulated_difficulty":"0x94560572e1ddb58cf053d87dbb080ba026bed840f90f","timestamp":1752579195},"is_synced":true}
         */
        const response = await this.request('/get_tip_info');
        return response;
    }

    /**
     * Get block header by height
     * @param {number} blockHeight - The height of the block
     * @returns {Promise<Object>} Block header information
     */
    async getHeaderByHeight(blockHeight) {
        console.log(`📡 Fetching header for block ${blockHeight}...`);
        try {
            const response = await this.request('/get_header_by_height', { height: blockHeight });
            console.log(`✅ Header fetched for block ${blockHeight}`);
            return response;
        } catch (error) {
            console.error(`❌ Failed to fetch header for block ${blockHeight}:`, error.message);
            throw error;
        }
    }

    /**
     * Sync UTXOs by block range
     * @param {string} startHeaderHash - Starting block hash (hex)
     * @param {string} endHeaderHash - Ending block hash (hex)
     * @param {number} limit - Number of blocks to fetch
     * @param {number} page - Page number for pagination
     * @returns {Promise<Object>} UTXO sync response
     */
    async syncUtxosByBlock(startHeaderHash, endHeaderHash, limit = 200, page = 0) {
        console.log(`📡 Syncing UTXOs from ${startHeaderHash.substring(0, 16)}... to ${endHeaderHash.substring(0, 16)}...`);
        try {
            const response = await this.request('/sync_utxos_by_block', {
                start_header_hash: startHeaderHash,
                end_header_hash: endHeaderHash,
                limit: limit,
                page: page
            });
            console.log(`✅ Synced ${response.blocks?.length || 0} blocks, has_next_page: ${response.has_next_page}`);
            return response;
        } catch (error) {
            console.error(`❌ Failed to sync UTXOs:`, error.message);
            throw error;
        }
    }

    /**
     * Convert block UTXO info to scanner format
     * @param {Object} blockUtxoInfo - Block UTXO info from base node
     * @returns {Object} Block data in scanner format
     */
    convertToScannerFormat(blockUtxoInfo) {
        return {
            height: blockUtxoInfo.height,
            hash: Buffer.from(blockUtxoInfo.header_hash).toString('hex'),
            timestamp: blockUtxoInfo.mined_timestamp,
            outputs: blockUtxoInfo.outputs.map(output => ({
                commitment: Buffer.from(output.commitment).toString('hex'),
                sender_offset_public_key: Buffer.from(output.sender_offset_public_key).toString('hex'),
                encrypted_data: Buffer.from(output.encrypted_data).toString('hex'),
                minimum_value_promise: 0, // Not provided in minimal sync
                features: null,
                script: null,
                metadata_signature: null,
                covenant: null
            })),
            inputs: [] // Inputs not included in UTXO sync
        };
    }

    /**
     * Fetch multiple blocks by height range (async iterator for streaming)
     * @param {number} startHeight - Starting block height
     * @param {number} endHeight - Ending block height
     * @returns {AsyncIterator<Object>} Async iterator that yields block data in scanner format
     */
    async* fetchBlockRange(startHeight, endHeight) {
        console.log(`📡 Fetching block range ${startHeight} to ${endHeight}...`);
        
        try {
            // Get headers for start and end blocks
            const startHeader = await this.getHeaderByHeight(startHeight);
            const endHeader = await this.getHeaderByHeight(endHeight);
            
            const startHash = Buffer.from(startHeader.hash).toString('hex');
            const endHash = Buffer.from(endHeader.hash).toString('hex');
            
            let page = 0;
            let hasNextPage = true;
            let totalBlocks = 0;
            
            // Sync UTXOs for the range
            while (hasNextPage) {
                const syncResponse = await this.syncUtxosByBlock(startHash, endHash, 200, page);
                hasNextPage = syncResponse.has_next_page;
                
                // Convert and yield each block from this page
                if (syncResponse.blocks) {
                    for (const blockInfo of syncResponse.blocks) {
                        const block = this.convertToScannerFormat(blockInfo);
                        totalBlocks++;
                        yield block;
                    }
                }
                
                page++;
            }
            
            console.log(`✅ Streamed ${totalBlocks} blocks from base node`);
            
        } catch (error) {
            console.error(`❌ Failed to fetch block range:`, error.message);
            throw error;
        }
    }
}

class WasmScanner {
    constructor(baseNodeUrl = 'http://127.0.0.1:9000') {
        this.wasm = null;
        this.scanner = null;
        this.httpClient = new HttpClient(baseNodeUrl);
    }

    /**
     * Initialize the WASM module
     */
    async init() {
        try {
            console.log("🚀 Initializing Tari WASM Scanner...");
            
            // Try to load the WASM module
            // Note: Path may need adjustment based on where the WASM package is built
            const wasmPath = path.join(__dirname, 'pkg/lightweight_wallet_libs.js');
            
            if (!fs.existsSync(wasmPath)) {
                throw new Error(`WASM module not found at ${wasmPath}. Please build it first with: wasm-pack build --target nodejs --out-dir pkg --example wasm_scanner`);
            }

            this.wasm = require(wasmPath);
            
            console.log("✅ WASM module loaded successfully");
            console.log("📊 Features enabled:", this.wasm.get_features());
            console.log("🏷️  Version:", this.wasm.get_version());
            
        } catch (error) {
            console.error("❌ Failed to initialize WASM module:", error.message);
            console.log("\n💡 To fix this:");
            console.log("   1. Install wasm-pack: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh");
            console.log("   2. Add WASM target: rustup target add wasm32-unknown-unknown");
            console.log("   3. Build the package: wasm-pack build --target nodejs --out-dir pkg --example wasm_scanner");
            process.exit(1);
        }
    }

    /**
     * Create a scanner instance
     */
    createScanner(type = "view_key", data = null) {
        try {
            console.log(`\n🔧 Creating scanner with ${type}...`, data);
            
            let scannerData;
            if (type === "seed_phrase") {
                scannerData = data ;
                console.log("   Using seed phrase:", scannerData.substring(0, 20) + "...");
            } else if (type === "view_key") {
                scannerData = data;
                console.log("   Using view key:", scannerData.substring(0, 20) + "...");
            } else {
                throw new Error("Invalid scanner type. Use 'seed_phrase' or 'view_key'");
            }

            this.scanner = this.wasm.create_wasm_scanner(type, scannerData);
            console.log("✅ Scanner created successfully");
            
            return this.scanner;
            
        } catch (error) {
            console.error("❌ Failed to create scanner:", error.message);
            throw error;
        }
    }

    /**
     * Test the scanner functionality
     */
    async testScanner() {
        try {
            console.log("\n🧪 Running scanner test...");
            const testResult = this.wasm.test_scanner();
            const result = JSON.parse(testResult);
            
            console.log("✅ Test completed successfully");
            console.log("📊 Test result:", result);
            
            return result;
            
        } catch (error) {
            console.error("❌ Scanner test failed:", error.message);
            throw error;
        }
    }


    async getTipHeight() {
        const tipInfo = await this.httpClient.getTipInfo();
        return tipInfo.metadata.best_block_height;
    }

    /**
     * Scan a single block
     */
    scanBlock(blockData) {
        try {
        
            const blockDataJson = JSON.stringify(blockData, null, 2);
            const resultJson = this.wasm.scan_block_data(this.scanner, blockDataJson);
            const result = JSON.parse(resultJson);
            
            if (result.success) {
                console.log(`✅ Block ${blockData.height} scanned successfully`);
                console.log(`   Transactions found: ${result.transactions.length}`);
                console.log(`   Current balance: ${result.current_balance} μT`);
            } else {
                console.log(`⚠️  Block ${blockData.height} scan completed with error: ${result.error}`);
            }
            
            return result;
            
        } catch (error) {
            console.error(`❌ Failed to scan block ${blockData.height}:`, error.message);
            throw error;
        }
    }

    /**
     * Scan multiple blocks
     */
    scanBlocks(blocks) {
        console.log(`\n📊 Scanning ${blocks.length} blocks...`);
        const results = [];
        let totalOutputs = 0;
        let totalValue = 0;

        for (const block of blocks) {
            const result = this.scanBlock(block);
            results.push(result);
            
            if (result.success) {
                totalOutputs += result.transactions.length;
                totalValue = result.total_value; // Latest total value
            }
        }

        console.log("\n📈 SCAN SUMMARY");
        console.log("================");
        console.log(`Blocks processed: ${blocks.length}`);
        console.log(`Total transactions: ${totalOutputs}`);
        console.log(`Total value found: ${totalValue} μT (${(totalValue / 1000000).toFixed(6)} T)`);
        
        return results;
    }

    /**
     * Reset scanner state
     */
    resetScanner() {
        try {
            console.log("\n🔄 Resetting scanner state...");
            this.wasm.reset_scanner(this.scanner);
            console.log("✅ Scanner state reset successfully");
        } catch (error) {
            console.error("❌ Failed to reset scanner:", error.message);
            throw error;
        }
    }

   
    /**
     * Test connection to base node
     */
    async testBaseNodeConnection() {
        console.log("\n📡 TESTING BASE NODE CONNECTION");
        console.log("===============================");
        
        try {
            console.log(`🔗 Connecting to ${this.httpClient.baseUrl}...`);
            
            // Try to fetch a recent block header
            const header = await this.httpClient.getHeaderByHeight(1);
            console.log(`✅ Successfully connected to base node`);
            console.log(`   Genesis block hash: ${Buffer.from(header.hash).toString('hex').substring(0, 16)}...`);
            console.log(`   Timestamp: ${new Date(header.timestamp * 1000).toISOString()}`);
            
            return true;
        } catch (error) {
            console.log(`❌ Failed to connect to base node: ${error.message}`);
            console.log(`   Make sure the Tari base node is running on ${this.httpClient.baseUrl}`);
            return false;
        }
    }

    /**
     * Scan real blocks from the base node
     * @param {number} startHeight - Starting block height
     * @param {number} endHeight - Ending block height (optional, defaults to startHeight)
     */
    async scanRealBlocks(startHeight, endHeight = null) {
        if (!endHeight) {
            endHeight = startHeight;
        }

        console.log(`\n🔍 SCANNING REAL BLOCKCHAIN DATA`);
        console.log("=================================");
        console.log(`Block range: ${startHeight} to ${endHeight}`);

        try {
            // Stream and scan blocks from base node
            let blockCount = 0;
            let totalOutputs = 0;
            let totalValue = 0;

            console.log(`\n📊 Streaming and scanning blocks...`);
            
            for await (const block of this.httpClient.fetchBlockRange(startHeight, endHeight)) {
                blockCount++;
                const result = this.scanBlock(block);
                
                if (result.success) {
                    totalOutputs += result.transactions.length;
                    totalValue = result.total_value; // Latest total value
                }
            }
            
            if (blockCount === 0) {
                console.log("⚠️  No blocks found in range");
                return [];
            }

            console.log("\n📈 STREAMING SCAN SUMMARY");
            console.log("=========================");
            console.log(`Blocks processed: ${blockCount}`);
            console.log(`Total transactions: ${totalOutputs}`);
            console.log(`Total value found: ${totalValue} μT (${(totalValue / 1000000).toFixed(6)} T)`);


        } catch (error) {
            console.error(`❌ Failed to scan real blocks: ${error.message}`);
            console.log(`   Make sure the Tari base node is running and accessible`);
            throw error;
        }
    }

    /**
     * Demonstrate real blockchain scanning
     */
    async scan(fromHeight, toHeight) {
        // Test connection first
        const connected = await this.testBaseNodeConnection();
        if (!connected) {
            console.log("⚠️  Skipping real blockchain demo - base node not available");
            console.log("   To enable this feature:");
            console.log("   1. Start a Tari base node");
            console.log("   2. Ensure it's accessible at http://127.0.0.1:9000");
            console.log("   3. Run this demo again");
            return;
        }

        try {
            await this.scanRealBlocks(fromHeight, toHeight);
        } catch (error) {
            console.error(`❌ Real blockchain demo failed: ${error.message}`);
        }
    }
}

/**
 * Parse command line arguments
 */
function parseArgs() {
    const args = process.argv.slice(2);
    const scannerType = args[0] || "view_key";
    const data = args[1] || null;
    const baseNodeUrl = args[2] || "http://127.0.0.1:9000";

    if (!["seed_phrase", "view_key"].includes(scannerType)) {
        console.error("❌ Invalid scanner type. Use 'seed_phrase' or 'view_key'");
        console.error("Usage: node scanner.js [seed_phrase|view_key] [data] [base_node_url]");
        process.exit(1);
    }

    return { scannerType, data, baseNodeUrl };
}

/**
 * Main execution function
 */
async function main() {
    console.log("🌟 Tari WASM Scanner - Node.js Example");
    console.log("=======================================");

    const { scannerType, data, baseNodeUrl } = parseArgs();
    const wasmScanner = new WasmScanner(baseNodeUrl);

    try {
        // Initialize WASM module
        await wasmScanner.init();

        // Create scanner
        wasmScanner.createScanner(scannerType, data);

        // Demonstrate real blockchain scanning (if base node is available)
        const fromHeight = 14500;
        const toHeight = await wasmScanner.getTipHeight();
        await wasmScanner.scan(fromHeight, toHeight);

        console.log("\n🎉 Example completed successfully!");

    } catch (error) {
        console.error("\n💥 Example failed:", error.message);
        console.error(error.stack);
        process.exit(1);
    }
}

/**
 * Handle unhandled errors
 */
process.on('unhandledRejection', (error) => {
    console.error('💥 Unhandled promise rejection:', error);
    process.exit(1);
});

process.on('uncaughtException', (error) => {
    console.error('💥 Uncaught exception:', error);
    process.exit(1);
});

// Run the example if this file is executed directly
if (require.main === module) {
    main();
}

// Export for use as a module
module.exports = {
    WasmScannerExample: WasmScanner,
};

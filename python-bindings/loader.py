from wasmer import engine, Store, Module
from wasmer_compiler_cranelift import Compiler
from bindings.bindings import Interface, WasmScanner, Ok, Err
import os

class Wallet:
    def __init__(self, wasm_path: str):
        with open(wasm_path, 'rb') as f:
            wasm_bytes = f.read()
        store = Store(engine.Universal())
        module = Module(store, wasm_bytes)
        self._iface = Interface(store, {}, module)

    def derive_public_key_hex(self, master_key: bytes):
        result = self._iface.derive_public_key_hex(master_key)
        if isinstance(result, Ok):
            return result.value
        else:
            raise RuntimeError(f"derive failed: {result.value}")

    def get_version(self):
        return self._iface.get_version()

    def new_scanner(self, data: str) -> WasmScanner:
        result = WasmScanner.create(self._iface, data)
        if isinstance(result, Ok):
            return result.value
        else:
            raise RuntimeError(f"scanner creation failed: {result.value}")
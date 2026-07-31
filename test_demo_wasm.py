"""Static contract tests for the offline browser/WASM demo."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

DEMO = Path(__file__).resolve().parent / "site" / "demo.html"


class BrowserWasmDemoContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = DEMO.read_text(encoding="utf-8")
        cls.compact = re.sub(r"\s+", " ", cls.source)

    def test_single_file_demo_exists_with_inline_runtime(self) -> None:
        self.assertTrue(DEMO.is_file())
        self.assertIn("<style>", self.source)
        self.assertIn("<script>", self.source)
        self.assertNotRegex(
            self.source,
            r"""<(?:script|link)\b[^>]+(?:src|href)=["']https?://""",
        )

    def test_network_is_disabled_and_no_transport_api_is_used(self) -> None:
        self.assertIn("connect-src 'none'", self.source)
        for transport in (
            "fetch(",
            "XMLHttpRequest",
            "WebSocket",
            "EventSource",
            "sendBeacon",
        ):
            self.assertNotIn(transport, self.source)
        self.assertIn("Offline. No network requests.", self.source)

    def test_webcrypto_ed25519_contract_is_present(self) -> None:
        self.assertIn('crypto.subtle.generateKey(', self.source)
        self.assertIn('crypto.subtle.sign("Ed25519"', self.source)
        self.assertIn('crypto.subtle.verify(', self.source)
        self.assertIn('{ name: "Ed25519" }', self.source)
        self.assertIn('crypto.subtle.digest("SHA-256"', self.source)

    def test_indexeddb_vault_contract_is_present(self) -> None:
        self.assertIn("indexedDB.open(DB_NAME, DB_VERSION)", self.source)
        self.assertIn('const RECEIPT_STORE = "receipts"', self.source)
        self.assertIn('const META_STORE = "metadata"', self.source)
        self.assertIn("createObjectStore(RECEIPT_STORE", self.source)
        self.assertIn("tx.objectStore(RECEIPT_STORE).put(receipt)", self.source)
        self.assertNotIn(
            "transaction.objectStore(RECEIPT_STORE).put(receipt)",
            self.source,
        )

    def test_mock_provider_and_chain_verification_are_local(self) -> None:
        self.assertIn("async function mockProvider(prompt, model)", self.source)
        self.assertIn("function canonicalPayload(receipt)", self.source)
        self.assertIn("async function verifyReceipt(receipt, expectedParentHash)", self.source)
        self.assertIn("receipt.parentHash === expectedParentHash", self.source)
        self.assertIn("[modified after signing]", self.source)

    def test_wasm_module_is_instantiated_from_inline_bytes(self) -> None:
        self.assertIn("const moduleBytes = new Uint8Array([", self.source)
        self.assertIn("WebAssembly.instantiate(moduleBytes)", self.source)
        self.assertIn("instance.exports.ready()", self.source)
        self.assertNotRegex(self.source, r"""["'][^"']+\.wasm(?:\?[^"']*)?["']""")

    def test_required_controls_and_status_regions_exist(self) -> None:
        for control in (
            "Run mock call",
            "Verify vault",
            "Tamper receipt",
            "Reset demo",
            "WebCrypto Ed25519",
            "IndexedDB vault",
            "Mock provider",
        ):
            self.assertIn(control, self.source)
        self.assertIn('aria-live="polite"', self.source)
        self.assertIn('role="status"', self.source)


if __name__ == "__main__":
    unittest.main()

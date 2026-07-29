"""Focused tests for the groundtruth (proof-of-route) lane.

These tests are stdlib-only and exercise the new BlindProbe/RouteAttestation
API without depending on a real network provider.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Type alias matching the cryptography library's Ed25519 key types.
_Key = Ed25519PrivateKey

import dontlie.groundtruth as gt
from dontlie import sign as signing
from dontlie import storage

_TMP = tempfile.mkdtemp(prefix="dontlie-groundtruth-test-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"


def _fresh_state(name: str) -> None:
    signing.KEY_DIR.mkdir(parents=True, exist_ok=True)
    for path in (signing.PRIVATE_FILE, signing.PUBLIC_FILE, signing.KEY_ID_FILE):
        path.unlink(missing_ok=True)
    signing.generate()
    storage.DB_PATH = Path(_TMP) / name
    with sqlite3.connect(storage.DB_PATH) as connection:
        connection.executescript(storage.SCHEMA)
        connection.execute("DELETE FROM receipts")
        connection.execute("DELETE FROM key_history")
        connection.execute("DELETE FROM sqlite_sequence WHERE name='receipts'")


def _make_receipt(provider: str = "openai", model: str = "gpt-4o-mini") -> dict:
    receipt = storage.append(
        model=model,
        prompt="hello",
        response="world",
        extra={"status": 200, "endpoint": "/v1/chat/completions", "provider": provider},
    )
    return {
        "id": receipt.id,
        "payload_sha256": receipt.payload_sha256,
        "model": receipt.model,
        "key_id": receipt.key_id,
        "extra": receipt.extra,
        "timestamp": receipt.timestamp,
    }


def _key_pair() -> object:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return type(
        "Key",
        (),
        {
            "key_id": raw[:8].hex(),
            "public": pub,
            "private": priv,
        },
    )()


class TestBlindProbe(unittest.TestCase):
    def setUp(self) -> None:
        _fresh_state("vault-blinding.db")
        gt.reset_runner()

    def tearDown(self) -> None:
        gt.reset_runner()

    def test_offline_default_rejects(self) -> None:
        probe = gt.BlindProbe()
        with self.assertRaises(gt.BlindProbeUnavailable):
            probe.run("ping")

    def test_short_nonce_is_at_least_8_chars(self) -> None:
        for _ in range(10):
            self.assertGreaterEqual(len(gt.short_nonce()), 8)
            self.assertLessEqual(len(gt.short_nonce()), 64)

    def test_digest_payload_is_deterministic(self) -> None:
        self.assertEqual(gt.digest_payload("hello"), gt.digest_payload("hello"))
        self.assertNotEqual(gt.digest_payload("hello"), gt.digest_payload("world"))

    def test_attach_runner_routes_to_runner(self) -> None:
        sentinel = gt.BlindProbeResult(
            provider="openai",
            model="gpt-4o-mini",
            response_sha256="a" * 64,
            response_digest=gt.digest_payload("ok"),
            elapsed_ms=12,
            correlation_id="c-1",
        )

        class _Stub:
            def run(self, prompt):  # type: ignore[no-untyped-def]
                return sentinel

        gt.attach_runner(_Stub())
        try:
            probe = gt.BlindProbe()
            result = probe.run("ping")
            self.assertIs(result, sentinel)
        finally:
            gt.reset_runner()

    def test_invalid_mode_raises(self) -> None:
        with self.assertRaises(ValueError):
            gt.BlindProbe(mode="bogus")


class TestRouteAttestation(unittest.TestCase):
    def setUp(self) -> None:
        _fresh_state("vault-attestation.db")

    def test_attest_and_verify_round_trip(self) -> None:
        receipt = _make_receipt(provider="openai", model="gpt-4o-mini")
        probe = gt.BlindProbeResult(
            provider="openai",
            model="gpt-4o-mini",
            response_sha256=gt.digest_payload("ok"),
            response_digest=gt.digest_payload("ok"),
            elapsed_ms=42,
            correlation_id="r-1",
        )
        key = _key_pair()
        attestation = gt.attest_receipt(receipt, probe, operator_key_pair=key)
        self.assertEqual(attestation.receipt_id, receipt["id"])
        self.assertEqual(attestation.provider, "openai")
        self.assertEqual(attestation.model, "gpt-4o-mini")
        self.assertTrue(
            gt.verify_route_attestation(
                attestation,
                receipt,
                probe,
                operator_public_key=key.public,
            )
        )

    def test_mismatched_provider_raises(self) -> None:
        receipt = _make_receipt(provider="openai", model="gpt-4o-mini")
        probe = gt.BlindProbeResult(
            provider="openai",
            model="gpt-4o-mini",
            response_sha256=gt.digest_payload("ok"),
            response_digest=gt.digest_payload("ok"),
            elapsed_ms=42,
            correlation_id="r-2",
        )
        key = _key_pair()
        attestation = gt.attest_receipt(receipt, probe, operator_key_pair=key)
        # Tamper with the attestation's recorded provider *after* signing
        # so signature no longer covers the (provider, model) pair.
        from dataclasses import replace
        tampered_att = replace(attestation, provider="anthropic")
        with self.assertRaises(gt.RouteMismatchError):
            gt.verify_route_attestation(
                tampered_att,
                receipt,
                probe,
                operator_public_key=key.public,
            )

    def test_tampered_signature_raises(self) -> None:
        receipt = _make_receipt()
        probe = gt.BlindProbeResult(
            provider="openai",
            model="gpt-4o-mini",
            response_sha256=gt.digest_payload("ok"),
            response_digest=gt.digest_payload("ok"),
            elapsed_ms=42,
            correlation_id="r-3",
        )
        key = _key_pair()
        attestation = gt.attest_receipt(receipt, probe, operator_key_pair=key)
        from dataclasses import replace
        # Replace a single character in the body that is signed. Pick a
        # different receipt_id to force a different payload hash.
        tampered_att = replace(attestation, receipt_id=attestation.receipt_id + 999)
        with self.assertRaises(gt.RouteMismatchError):
            gt.verify_route_attestation(
                tampered_att,
                receipt,
                probe,
                operator_public_key=key.public,
            )

    def test_mismatched_receipt_payload_raises(self) -> None:
        receipt_a = _make_receipt()
        receipt_b = _make_receipt()
        # receipt_b has different payload hash
        probe = gt.BlindProbeResult(
            provider="openai",
            model="gpt-4o-mini",
            response_sha256=gt.digest_payload("ok"),
            response_digest=gt.digest_payload("ok"),
            elapsed_ms=42,
            correlation_id="r-4",
        )
        key = _key_pair()
        attestation = gt.attest_receipt(receipt_a, probe, operator_key_pair=key)
        with self.assertRaises(gt.RouteMismatchError):
            gt.verify_route_attestation(
                attestation,
                receipt_b,
                probe,
                operator_public_key=key.public,
            )


# ---------------------------------------------------------------------------
# Hostile-actor tests: witness protocol
# ---------------------------------------------------------------------------


def _witness_keypair() -> gt.WitnessKey:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return gt.WitnessKey(
        key_id="witness-" + raw[:4].hex(),
        public_key=pub,
        private_key=priv,
    )


def _operator_keypair() -> _Key:
    """Local helper to match the style of _key_pair() in this file."""
    return _key_pair()


class TestWitnessRoundTrip(unittest.TestCase):
    """Conformance: in-process witness can attest and verifier accepts it."""

    def setUp(self) -> None:
        _fresh_state("vault-witness-rt.db")
        gt.reset_runner()

    def test_witness_attest_and_verify_round_trip(self) -> None:
        receipt = _make_receipt()
        operator = _operator_keypair()
        witness = _witness_keypair()
        witness_obj = gt.InProcessWitness(witness, verify_requester=True)
        request = gt.build_signed_request(
            receipt_payload_sha256=receipt["payload_sha256"],
            provider=receipt["extra"]["provider"],
            model=receipt["model"],
            correlation_id=receipt["timestamp"],
            requester_key_id=operator.key_id,
            requester_private_key=operator.private,
        )
        attestation = witness_obj.attest(request)
        verifier = gt.WitnessVerifier({witness.key_id: witness})
        result = verifier.verify(attestation)
        self.assertTrue(result)
        self.assertEqual(result.witness_key_id, witness.key_id)

    def test_witness_attestation_is_serializable(self) -> None:
        """Round-trip through JSON: deserialize, then verify."""
        receipt = _make_receipt()
        operator = _operator_keypair()
        witness = _witness_keypair()
        witness_obj = gt.InProcessWitness(witness, verify_requester=False)
        request = gt.build_signed_request(
            receipt_payload_sha256=receipt["payload_sha256"],
            provider=receipt["extra"]["provider"],
            model=receipt["model"],
            correlation_id=receipt["timestamp"],
            requester_key_id=operator.key_id,
            requester_private_key=operator.private,
        )
        attestation = witness_obj.attest(request)
        # Canonicalize via the public wire format and round-trip.
        wire = gt.serialize_attestation(attestation)
        restored = gt.deserialize_attestation(wire)
        self.assertEqual(restored.witness_key_id, attestation.witness_key_id)
        self.assertEqual(restored.signature, attestation.signature)
        verifier = gt.WitnessVerifier({witness.key_id: witness})
        self.assertTrue(verifier.verify(restored))


class TestOfflineWitnessDefault(unittest.TestCase):
    def setUp(self) -> None:
        _fresh_state("vault-witness-off.db")
        gt.reset_runner()

    def test_offline_witness_fails_closed(self) -> None:
        offline = gt.OfflineWitness()
        receipt = _make_receipt()
        operator = _operator_keypair()
        request = gt.build_signed_request(
            receipt_payload_sha256=receipt["payload_sha256"],
            provider=receipt["extra"]["provider"],
            model=receipt["model"],
            correlation_id=receipt["timestamp"],
            requester_key_id=operator.key_id,
            requester_private_key=operator.private,
        )
        with self.assertRaises(gt.WitnessError):
            offline.attest(request)


class TestRemoteHTTPWitnessStub(unittest.TestCase):
    def test_remote_witness_rejects_plain_http(self) -> None:
        witness = _witness_keypair()
        with self.assertRaises(ValueError):
            gt.RemoteHTTPWitness("http://peer.local/witness", witness)

    def test_remote_witness_stub_fails_closed(self) -> None:
        witness = _witness_keypair()
        remote = gt.RemoteHTTPWitness("https://peer.local/witness", witness)
        with self.assertRaises(gt.WitnessError):
            remote.attest(
                gt.build_signed_request(
                    receipt_payload_sha256="a" * 64,
                    provider="openai",
                    model="gpt-4o-mini",
                    correlation_id="c-1",
                    requester_key_id="op-1",
                    requester_private_key=Ed25519PrivateKey.generate(),
                )
            )


class TestHostileWitness(unittest.TestCase):
    """Adversarial: attacker tampers with attestations to slip past verify."""

    def setUp(self) -> None:
        _fresh_state("vault-witness-hostile.db")
        gt.reset_runner()

    def test_unknown_witness_key_id_rejected(self) -> None:
        # Honest operator, honest witness, but verifier does not know this
        # witness's key. Should reject.
        receipt = _make_receipt()
        operator = _operator_keypair()
        witness = _witness_keypair()
        witness_obj = gt.InProcessWitness(witness, verify_requester=False)
        request = gt.build_signed_request(
            receipt_payload_sha256=receipt["payload_sha256"],
            provider=receipt["extra"]["provider"],
            model=receipt["model"],
            correlation_id=receipt["timestamp"],
            requester_key_id=operator.key_id,
            requester_private_key=operator.private,
        )
        att = witness_obj.attest(request)
        # Build a verifier with a *different* key db; should fail closed.
        other = _witness_keypair()
        verifier = gt.WitnessVerifier({other.key_id: other})
        result = verifier.verify(att)
        self.assertFalse(result)
        self.assertIn("unknown witness key id", result.reason)

    def test_tampered_witness_signature_rejected(self) -> None:
        # Honest witness, but attacker edits the attestation post-signing.
        receipt = _make_receipt()
        operator = _operator_keypair()
        witness = _witness_keypair()
        witness_obj = gt.InProcessWitness(witness, verify_requester=False)
        request = gt.build_signed_request(
            receipt_payload_sha256=receipt["payload_sha256"],
            provider=receipt["extra"]["provider"],
            model=receipt["model"],
            correlation_id=receipt["timestamp"],
            requester_key_id=operator.key_id,
            requester_private_key=operator.private,
        )
        att = witness_obj.attest(request)
        # Flip a hex digit in the signature.
        original = att.signature
        tampered = ("f" if original[0] != "f" else "0") + original[1:]
        from dataclasses import replace

        bad = replace(att, signature=tampered)
        verifier = gt.WitnessVerifier({witness.key_id: witness})
        result = verifier.verify(bad)
        self.assertFalse(result)
        self.assertEqual(result.reason, "witness signature failed")

    def test_swapped_witness_payload_rejected(self) -> None:
        # Honest witness for receipt A, attacker substitutes receipt B's
        # digest into the attestation while keeping the original signature.
        receipt_a = _make_receipt()
        receipt_b = _make_receipt()
        operator = _operator_keypair()
        witness = _witness_keypair()
        witness_obj = gt.InProcessWitness(witness, verify_requester=False)
        request_a = gt.build_signed_request(
            receipt_payload_sha256=receipt_a["payload_sha256"],
            provider=receipt_a["extra"]["provider"],
            model=receipt_a["model"],
            correlation_id=receipt_a["timestamp"],
            requester_key_id=operator.key_id,
            requester_private_key=operator.private,
        )
        att = witness_obj.attest(request_a)
        from dataclasses import replace

        bad = replace(att, receipt_payload_sha256=receipt_b["payload_sha256"])
        verifier = gt.WitnessVerifier({witness.key_id: witness})
        result = verifier.verify(bad)
        self.assertFalse(result)
        self.assertEqual(result.reason, "witness signature failed")

    def test_replay_after_expiry_rejected(self) -> None:
        # A request from far in the past cannot be attested against
        # current verifier state because expiry is in the signed payload.
        receipt = _make_receipt()
        operator = _operator_keypair()
        witness = _witness_keypair()
        witness_obj = gt.InProcessWitness(witness, verify_requester=False)
        long_ago = 1_000_000  # ~11 days past epoch
        request = gt.build_signed_request(
            receipt_payload_sha256=receipt["payload_sha256"],
            provider=receipt["extra"]["provider"],
            model=receipt["model"],
            correlation_id=receipt["timestamp"],
            ttl_seconds=60,
            requester_key_id=operator.key_id,
            requester_private_key=operator.private,
            now=long_ago,
        )
        # Constructing the request is fine; the witness attests
        # without checking expiry (offline default). The verifier is
        # the one that catches it.
        att = witness_obj.attest(request)
        verifier = gt.WitnessVerifier({witness.key_id: witness})
        result = verifier.verify(att)
        self.assertFalse(result)
        self.assertEqual(result.reason, "request expired")

    def test_in_process_witness_rejects_missing_signature(self) -> None:
        receipt = _make_receipt()
        operator = _operator_keypair()
        witness = _witness_keypair()
        witness_obj = gt.InProcessWitness(witness, verify_requester=True)
        from dataclasses import replace

        request = gt.build_signed_request(
            receipt_payload_sha256=receipt["payload_sha256"],
            provider=receipt["extra"]["provider"],
            model=receipt["model"],
            correlation_id=receipt["timestamp"],
            requester_key_id=operator.key_id,
            requester_private_key=operator.private,
        )
        broken = replace(request, signature="")
        with self.assertRaises(gt.WitnessError):
            witness_obj.attest(broken)

    def test_in_process_witness_rejects_expired_request(self) -> None:
        receipt = _make_receipt()
        operator = _operator_keypair()
        witness = _witness_keypair()
        witness_obj = gt.InProcessWitness(witness, verify_requester=True)
        request = gt.build_signed_request(
            receipt_payload_sha256=receipt["payload_sha256"],
            provider=receipt["extra"]["provider"],
            model=receipt["model"],
            correlation_id=receipt["timestamp"],
            ttl_seconds=60,
            requester_key_id=operator.key_id,
            requester_private_key=operator.private,
            now=1_000_000,
        )
        with self.assertRaises(gt.WitnessError):
            witness_obj.attest(request)


if __name__ == "__main__":
    unittest.main(verbosity=2)

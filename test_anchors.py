"""Tests for dontlie.anchors — manifest format, attestation, and verification.

Run: python -m unittest test_anchors.py
"""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="dontlie-anchor-test-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"

from dontlie import anchors


def _receipt(receipt_id: int, payload: str) -> dict[str, object]:
    """Build a minimal receipt mapping for the manifest tests."""
    return {
        "id": receipt_id,
        "payload_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    }


class CheckpointDigestTest(unittest.TestCase):
    def test_canonical_json_is_stable(self) -> None:
        a = anchors.Checkpoint(receipt_id=1, receipt_sha256="a" * 64)
        b = anchors.Checkpoint(receipt_id=1, receipt_sha256="a" * 64)
        self.assertEqual(
            anchors.checkpoint_digest([a, a]),
            anchors.checkpoint_digest([b, b]),
        )

    def test_checkpoints_outside_attestation_block_change_digest(self) -> None:
        c1 = anchors.Checkpoint(receipt_id=1, receipt_sha256="a" * 64)
        c2 = anchors.Checkpoint(receipt_id=2, receipt_sha256="a" * 64)
        self.assertNotEqual(
            anchors.checkpoint_digest([c1]), anchors.checkpoint_digest([c2])
        )

    def test_attestation_metadata_changes_digest(self) -> None:
        # Two attestations that differ only in their metadata
        # must produce different manifest digests, so attackers
        # cannot swap metadata without breaking the chain.
        att1 = anchors.Attestation(
            attestor="rfc3161:test",
            status="confirmed",
            format="rfc3161",
            received_at="1970-01-01T00:00:00+00:00",
            checkpoint_digest="x" * 64,
            proof="p",
            metadata={"a": 1},
        )
        att2 = anchors.Attestation(
            attestor="rfc3161:test",
            status="confirmed",
            format="rfc3161",
            received_at="1970-01-01T00:00:00+00:00",
            checkpoint_digest="x" * 64,
            proof="p",
            metadata={"a": 2},
        )
        c1 = anchors.Checkpoint(receipt_id=1, receipt_sha256="r", attestations=(att1,))
        c2 = anchors.Checkpoint(receipt_id=1, receipt_sha256="r", attestations=(att2,))
        self.assertNotEqual(
            anchors.checkpoint_digest([c1]), anchors.checkpoint_digest([c2])
        )

    def test_dict_input_is_normalized(self) -> None:
        att = {
            "attestor": "rfc3161:test",
            "status": "confirmed",
            "format": "rfc3161",
            "received_at": "1970-01-01T00:00:00+00:00",
            "checkpoint_digest": "x" * 64,
            "proof": "p",
            "metadata": {"k": "v"},
        }
        from_dict = anchors.checkpoint_digest(
            [{"receipt_id": 1, "receipt_sha256": "r", "attestations": [att]}]
        )
        c = anchors.Checkpoint(
            receipt_id=1,
            receipt_sha256="r",
            attestations=(
                anchors.Attestation(
                    attestor="rfc3161:test",
                    status="confirmed",
                    format="rfc3161",
                    received_at="1970-01-01T00:00:00+00:00",
                    checkpoint_digest="x" * 64,
                    proof="p",
                    metadata={"k": "v"},
                ),
            ),
        )
        from_dataclass = anchors.checkpoint_digest([c])
        self.assertEqual(from_dict, from_dataclass)

    def test_invalid_checkpoint_raises(self) -> None:
        with self.assertRaises(anchors.AnchorError):
            anchors.checkpoint_digest(["not a checkpoint"])  # type: ignore[list-item]


class OfflineRFC3161Test(unittest.TestCase):
    def test_request_yields_confirmed_attestation(self) -> None:
        attestor = anchors.OfflineRFC3161Attestor()
        attestation = attestor.request("d" * 64)
        self.assertEqual(attestation.status, "confirmed")
        self.assertEqual(attestation.format, "rfc3161")
        self.assertEqual(attestation.attestor, "rfc3161:offline")
        self.assertEqual(attestation.checkpoint_digest, "d" * 64)

    def test_verify_confirms_when_proof_matches(self) -> None:
        attestor = anchors.OfflineRFC3161Attestor(identifier="rfc3161:lab")
        attestation = attestor.request("d" * 64)
        self.assertEqual(
            attestor.verify(attestation, "d" * 64), "confirmed"
        )

    def test_verify_rejects_wrong_digest(self) -> None:
        attestor = anchors.OfflineRFC3161Attestor(identifier="rfc3161:lab")
        attestation = attestor.request("d" * 64)
        self.assertEqual(
            attestor.verify(attestation, "e" * 64), "inconclusive"
        )


class OfflineOpenTimestampsTest(unittest.TestCase):
    def test_pending_then_upgrade(self) -> None:
        attestor = anchors.OfflineOpenTimestampsAttestor(pending=True)
        attestation = attestor.request("d" * 64)
        self.assertEqual(attestation.status, "pending")
        upgraded = attestor.upgrade(attestation)
        self.assertEqual(upgraded.status, "confirmed")
        self.assertTrue(upgraded.metadata.get("upgraded"))

    def test_upgrade_is_idempotent_on_confirmed(self) -> None:
        attestor = anchors.OfflineOpenTimestampsAttestor(pending=False)
        attestation = attestor.request("d" * 64)
        # Already confirmed; upgrade returns the same attestation.
        upgraded = attestor.upgrade(attestation)
        self.assertEqual(upgraded.status, "confirmed")
        self.assertFalse(upgraded.metadata.get("upgraded"))

    def test_upgrade_rejects_wrong_attestor(self) -> None:
        attestor = anchors.OfflineOpenTimestampsAttestor()
        foreign = anchors.Attestation(
            attestor="rfc3161:other",
            status="pending",
            format="rfc3161",
            received_at="1970-01-01T00:00:00+00:00",
            checkpoint_digest="d" * 64,
            proof="p",
        )
        with self.assertRaises(anchors.AnchorError):
            attestor.upgrade(foreign)

    def test_verify_rejects_wrong_digest(self) -> None:
        attestor = anchors.OfflineOpenTimestampsAttestor()
        attestation = attestor.request("d" * 64)
        self.assertEqual(
            attestor.verify(attestation, "wrong"), "inconclusive"
        )


class BuildManifestTest(unittest.TestCase):
    def test_build_manifest_from_receipts(self) -> None:
        receipts = [_receipt(1, "first"), _receipt(2, "second"), _receipt(3, "third")]
        manifest = anchors.build_manifest_from_receipts(
            receipts, vault_key_id="abcd1234"
        )
        self.assertEqual(manifest.format, anchors.ANCHOR_FORMAT)
        self.assertEqual(manifest.version, anchors.ANCHOR_VERSION)
        self.assertEqual(len(manifest.checkpoints), 3)
        self.assertEqual(
            manifest.checkpoint_digest, anchors.checkpoint_digest(manifest.checkpoints)
        )

    def test_attestors_added_to_every_checkpoint(self) -> None:
        receipts = [_receipt(1, "first"), _receipt(2, "second")]
        attestor = anchors.OfflineRFC3161Attestor(identifier="rfc3161:test")
        manifest = anchors.build_manifest_from_receipts(
            receipts, vault_key_id="abcd1234", attestors=[attestor]
        )
        for checkpoint in manifest.checkpoints:
            self.assertEqual(len(checkpoint.attestations), 1)
            self.assertEqual(checkpoint.attestations[0].status, "confirmed")

    def test_empty_checkpoints_rejected(self) -> None:
        with self.assertRaises(anchors.AnchorError):
            anchors.build_manifest([], vault_key_id="abcd1234")

    def test_invalid_receipt_mapping_rejected(self) -> None:
        with self.assertRaises(anchors.AnchorError):
            anchors.build_manifest_from_receipts(
                [{"id": 1}],  # type: ignore[list-item]
                vault_key_id="abcd1234",
            )

    def test_manifest_to_json_is_deterministic(self) -> None:
        receipts = [_receipt(1, "first"), _receipt(2, "second")]
        attestor = anchors.OfflineRFC3161Attestor(identifier="rfc3161:test")
        a = anchors.build_manifest_from_receipts(
            receipts, vault_key_id="abcd1234", attestors=[attestor]
        )
        b = anchors.build_manifest_from_receipts(
            receipts, vault_key_id="abcd1234", attestors=[attestor]
        )
        self.assertEqual(a.to_json(), b.to_json())


class VerifyManifestTest(unittest.TestCase):
    def _build(self):
        receipts = [_receipt(1, "first"), _receipt(2, "second")]
        attestor = anchors.OfflineRFC3161Attestor(identifier="rfc3161:test")
        return (
            anchors.build_manifest_from_receipts(
                receipts, vault_key_id="abcd1234", attestors=[attestor]
            ),
            attestor,
        )

    def test_verify_confirms_with_client(self) -> None:
        manifest, attestor = self._build()
        result = anchors.verify_manifest(
            manifest, attestors={attestor.identifier: attestor}
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.ok_count, 2)
        self.assertEqual(result.bad_count, 0)
        self.assertEqual(result.as_tuple(), (2, 0))

    def test_verify_flags_inconclusive_without_client(self) -> None:
        manifest, _ = self._build()
        result = anchors.verify_manifest(manifest, attestors={})
        self.assertEqual(result.bad_count, 0)
        self.assertEqual(result.inconclusive_count, 2)

    def test_verify_detects_digest_tampering(self) -> None:
        manifest, attestor = self._build()
        # Forge a manifest dict with the same checkpoints but a
        # different digest; the verifier must flag it.
        forged_dict = manifest.as_dict()
        forged_dict["checkpoint_digest"] = "f" * 64
        forged = anchors.AnchorManifest(
            format=forged_dict["format"],
            version=forged_dict["version"],
            created_at=forged_dict["created_at"],
            vault_key_id=forged_dict["vault_key_id"],
            checkpoints=manifest.checkpoints,
            checkpoint_digest="f" * 64,
            note=forged_dict["note"],
        )
        result = anchors.verify_manifest(
            forged, attestors={attestor.identifier: attestor}
        )
        self.assertFalse(result.valid)
        self.assertTrue(any("digest mismatch" in i for i in result.issues))

    def test_verify_rejects_wrong_format(self) -> None:
        manifest, attestor = self._build()
        bad = anchors.AnchorManifest(
            format="not-dontlie",
            version=1,
            created_at=manifest.created_at,
            vault_key_id=manifest.vault_key_id,
            checkpoints=manifest.checkpoints,
            checkpoint_digest=manifest.checkpoint_digest,
            note="",
        )
        result = anchors.verify_manifest(
            bad, attestors={attestor.identifier: attestor}
        )
        self.assertFalse(result.valid)

    def test_pending_attestations_count_as_pending(self) -> None:
        receipts = [_receipt(1, "first")]
        attestor = anchors.OfflineOpenTimestampsAttestor(pending=True)
        manifest = anchors.build_manifest_from_receipts(
            receipts, vault_key_id="abcd1234", attestors=[attestor]
        )
        result = anchors.verify_manifest(
            manifest, attestors={attestor.identifier: attestor}
        )
        # No checkpoint is "confirmed" yet, so ok_count=0 and
        # pending_count reflects the in-flight state.
        self.assertEqual(result.ok_count, 0)
        self.assertEqual(result.pending_count, 1)
        self.assertEqual(result.bad_count, 0)

    def test_no_attestations_reports_inconclusive(self) -> None:
        receipts = [_receipt(1, "first")]
        manifest = anchors.build_manifest_from_receipts(
            receipts, vault_key_id="abcd1234"
        )
        result = anchors.verify_manifest(manifest, attestors={})
        self.assertEqual(result.bad_count, 0)
        self.assertEqual(result.inconclusive_count, 1)


class UpgradeManifestTest(unittest.TestCase):
    def test_upgrade_moves_pending_to_confirmed(self) -> None:
        receipts = [_receipt(1, "first"), _receipt(2, "second")]
        attestor = anchors.OfflineOpenTimestampsAttestor(pending=True)
        manifest = anchors.build_manifest_from_receipts(
            receipts, vault_key_id="abcd1234", attestors=[attestor]
        )
        upgraded = anchors.upgrade_manifest(manifest, attestor)
        for checkpoint in upgraded.checkpoints:
            self.assertEqual(checkpoint.attestations[0].status, "confirmed")

    def test_upgrade_preserves_unrelated_attestations(self) -> None:
        # A checkpoint that already has a confirmed RFC 3161
        # attestation should keep it untouched after a separate
        # OTS upgrade pass.
        ots = anchors.OfflineOpenTimestampsAttestor(pending=True)
        rfc = anchors.OfflineRFC3161Attestor(identifier="rfc3161:sidecar")
        manifest = anchors.build_manifest_from_receipts(
            [_receipt(1, "first")],
            vault_key_id="abcd1234",
            attestors=[rfc, ots],
        )
        upgraded = anchors.upgrade_manifest(manifest, ots)
        checkpoint = upgraded.checkpoints[0]
        statuses = {a.attestor: a.status for a in checkpoint.attestations}
        self.assertEqual(statuses["rfc3161:sidecar"], "confirmed")
        self.assertEqual(statuses["opentimestamps:offline"], "confirmed")

    def test_upgrade_rejects_non_offline_upgrader(self) -> None:
        receipts = [_receipt(1, "first")]
        attestor = anchors.OfflineOpenTimestampsAttestor(pending=True)
        manifest = anchors.build_manifest_from_receipts(
            receipts, vault_key_id="abcd1234", attestors=[attestor]
        )
        with self.assertRaises(anchors.AnchorError):
            anchors.upgrade_manifest(manifest, "not an upgrader")  # type: ignore[arg-type]


class ParseManifestTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        receipts = [_receipt(1, "first"), _receipt(2, "second")]
        attestor = anchors.OfflineRFC3161Attestor(identifier="rfc3161:test")
        manifest = anchors.build_manifest_from_receipts(
            receipts, vault_key_id="abcd1234", attestors=[attestor]
        )
        payload = manifest.to_json()
        parsed = anchors.parse_manifest(payload)
        self.assertEqual(parsed.format, manifest.format)
        self.assertEqual(parsed.version, manifest.version)
        self.assertEqual(
            len(parsed.checkpoints), len(manifest.checkpoints)
        )
        self.assertEqual(
            parsed.checkpoint_digest, manifest.checkpoint_digest
        )

    def test_rejects_invalid_json(self) -> None:
        with self.assertRaises(anchors.AnchorError):
            anchors.parse_manifest("not json")

    def test_rejects_wrong_format(self) -> None:
        with self.assertRaises(anchors.AnchorError):
            anchors.parse_manifest(json.dumps({"format": "other", "version": 1}))

    def test_rejects_empty_checkpoints(self) -> None:
        payload = json.dumps(
            {
                "format": anchors.ANCHOR_FORMAT,
                "version": anchors.ANCHOR_VERSION,
                "checkpoints": [],
            }
        )
        with self.assertRaises(anchors.AnchorError):
            anchors.parse_manifest(payload)


class LiveIntegrationPointTest(unittest.TestCase):
    def test_rfc3161_factory_creates_attestor(self) -> None:
        attestor = anchors.RFC3161Attestor(tsa_url="https://tsa.example/test")
        self.assertEqual(attestor.identifier, "rfc3161:https://tsa.example/test")
        # The integration point is documented; calling request
        # without a wired implementation must fail loudly.
        with self.assertRaises(anchors.AnchorError):
            attestor.request("d" * 64)

    def test_ots_factory_creates_attestor(self) -> None:
        attestor = anchors.OpenTimestampsAttestor()
        self.assertTrue(attestor.identifier.startswith("opentimestamps:"))
        with self.assertRaises(anchors.AnchorError):
            attestor.request("d" * 64)

    def test_rfc3161_factory_rejects_empty_url(self) -> None:
        with self.assertRaises(anchors.AnchorError):
            anchors.RFC3161Attestor(tsa_url="")

    def test_rfc3161_verify_treats_unknown_as_inconclusive(self) -> None:
        attestor = anchors.RFC3161Attestor(tsa_url="https://tsa.example")
        foreign = anchors.Attestation(
            attestor="someone-else",
            status="confirmed",
            format="rfc3161",
            received_at="1970-01-01T00:00:00+00:00",
            checkpoint_digest="d" * 64,
            proof="p",
        )
        self.assertEqual(
            attestor.verify(foreign, "d" * 64), "inconclusive"
        )


class AttestCheckpointTest(unittest.TestCase):
    def test_attest_checkpoint_appends(self) -> None:
        checkpoint = anchors.Checkpoint(receipt_id=1, receipt_sha256="d" * 64)
        attestor = anchors.OfflineRFC3161Attestor(identifier="rfc3161:test")
        updated = anchors.attest_checkpoint(checkpoint, attestor)
        self.assertEqual(len(updated.attestations), 1)
        self.assertEqual(
            updated.attestations[0].attestor, "rfc3161:test"
        )
        # Original checkpoint is unchanged.
        self.assertEqual(len(checkpoint.attestations), 0)


if __name__ == "__main__":
    unittest.main()

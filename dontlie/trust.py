"""dontlie trust-score — a 0-100 score that summarizes vault health.

The score is intentionally simple, transparent, and reproducible. It is
not a security certification; it is a one-number "how much should I
trust the receipts in this vault right now" signal that a non-engineer
can read at a glance.

Five weighted components (total = 100):

    chain_integrity     (40)  — every receipt's hash + signature verify
    key_rotation        (15)  — age of the most recent signing key
    coverage            (20)  — fraction of receipts with witness coverage
    provider_attestation(15)  — fraction of receipts from a known provider
    freshness           (10)  — most recent receipt within expected window

A breakdown is included in the output so a CI gate can fail on a
specific component rather than the aggregate.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from . import storage


# Optional witness module — present in v0.2+ but treat absence as 0 coverage
try:
    from . import groundtruth as _groundtruth  # noqa: F401
    _HAS_GROUNDTRUTH = True
except Exception:
    _HAS_GROUNDTRUTH = False


@dataclass
class TrustScore:
    value: int
    label: str
    components: dict = field(default_factory=dict)
    summary: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "label": self.label,
            "components": self.components,
            "summary": self.summary,
        }


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _age_seconds(ts: str) -> float | None:
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (_now() - dt).total_seconds()
    except Exception:
        return None


def _label_for(value: int) -> str:
    if value >= 90:
        return "excellent"
    if value >= 75:
        return "good"
    if value >= 50:
        return "fair"
    if value >= 25:
        return "weak"
    return "untrusted"


def compute() -> TrustScore:
    storage.init()
    conn = storage._connect()
    try:
        # chain integrity
        report = storage.verify_chain_report()
        total = report.ok_count + report.bad_count
        if total == 0:
            chain_value = 0
            chain_note = "no receipts to verify"
        elif report.bad_count == 0:
            chain_value = 40
            chain_note = f"all {total} receipts verified"
        else:
            chain_value = max(0, int(40 * (report.ok_count / total)))
            chain_note = f"{report.bad_count} of {total} receipts failed verification"

        # key rotation age
        cur = conn.execute("SELECT MAX(created_at) FROM key_history")
        row = cur.fetchone()
        last_key_activated = row[0] if row else None
        if last_key_activated is None:
            cur = conn.execute("SELECT MIN(timestamp) FROM receipts")
            last_key_activated = cur.fetchone()[0]
        key_age = _age_seconds(last_key_activated) if last_key_activated else None
        if key_age is None:
            key_value = 0
            key_note = "no key history found"
        elif key_age < 30 * 86400:
            key_value = 15
            key_note = f"signing key rotated {int(key_age // 86400)}d ago"
        elif key_age < 180 * 86400:
            key_value = 10
            key_note = f"signing key {int(key_age // 86400)}d old — consider rotating"
        else:
            key_value = 3
            key_note = f"signing key {int(key_age // 86400)}d old — rotation overdue"

        # coverage — fraction of receipts with at least one witness signature.
        # If groundtruth is unavailable, coverage is unknown → 0 contribution.
        coverage_value = 0
        coverage_note = "witness coverage not available (groundtruth module missing)"
        if _HAS_GROUNDTRUTH:
            cur = conn.execute("SELECT COUNT(*) FROM receipts")
            rcount = cur.fetchone()[0]
            try:
                # Only count attestations whose receipt_id still exists in
                # the receipts table. Otherwise an attacker (or a botched
                # migration / test) can leave the witness_attestations
                # table full of rows that point to nothing, and the
                # coverage ratio would skew to >100% (which is exactly
                # what happened in the v0.3.0 test-isolation incident).
                cur = conn.execute(
                    "SELECT COUNT(DISTINCT wa.receipt_id) "
                    "FROM witness_attestations wa "
                    "INNER JOIN receipts r ON r.id = wa.receipt_id"
                )
                wcount = cur.fetchone()[0]
            except sqlite3.OperationalError:
                # witness table does not exist in this vault — coverage is 0
                wcount = 0
            if rcount == 0:
                coverage_note = "no receipts to score"
            else:
                ratio = min(1.0, wcount / rcount)  # clamp to [0, 1]
                coverage_value = int(20 * ratio)
                coverage_note = f"{wcount}/{rcount} receipts have witness coverage"

        # provider attestation — fraction of receipts from a known provider set
        cur = conn.execute("SELECT COUNT(*) FROM receipts")
        rcount = cur.fetchone()[0]
        cur = conn.execute("SELECT DISTINCT model FROM receipts WHERE model IS NOT NULL")
        models = [row[0] for row in cur.fetchall()]
        known_providers = {"gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "claude-3-5-sonnet",
                           "claude-3-opus", "claude-3-haiku", "MiniMax-M3", "MiniMax-M2",
                           "gemini-1.5-pro", "gemini-1.5-flash", "llama3.1-70b"}
        if rcount == 0:
            provider_value = 0
            provider_note = "no receipts to score"
        else:
            known = sum(1 for m in models if m in known_providers)
            if not models:
                provider_value = 0
                provider_note = "no model recorded on receipts"
            else:
                ratio = known / len(models)
                provider_value = int(15 * ratio)
                provider_note = f"{known}/{len(models)} distinct models from known providers"

        # freshness — most recent receipt within window
        cur = conn.execute("SELECT MAX(timestamp) FROM receipts")
        last_receipt = cur.fetchone()[0]
        if last_receipt is None:
            freshness_value = 0
            freshness_note = "no receipts yet"
        else:
            age = _age_seconds(last_receipt)
            if age is None:
                freshness_value = 0
                freshness_note = "could not parse last receipt timestamp"
            elif age < 86400:
                freshness_value = 10
                freshness_note = f"last receipt {int(age // 3600)}h ago"
            elif age < 7 * 86400:
                freshness_value = 7
                freshness_note = f"last receipt {int(age // 86400)}d ago"
            elif age < 30 * 86400:
                freshness_value = 3
                freshness_note = f"last receipt {int(age // 86400)}d ago — vault may be stale"
            else:
                freshness_value = 0
                freshness_note = f"last receipt {int(age // 86400)}d ago — vault likely inactive"
    finally:
        conn.close()

    value = chain_value + key_value + coverage_value + provider_value + freshness_value
    value = max(0, min(100, value))
    return TrustScore(
        value=value,
        label=_label_for(value),
        components={
            "chain_integrity": {"value": chain_value, "max": 40, "note": chain_note},
            "key_rotation": {"value": key_value, "max": 15, "note": key_note},
            "coverage": {"value": coverage_value, "max": 20, "note": coverage_note},
            "provider_attestation": {"value": provider_value, "max": 15, "note": provider_note},
            "freshness": {"value": freshness_value, "max": 10, "note": freshness_note},
        },
        summary=[
            f"chain integrity:   {chain_value}/40  — {chain_note}",
            f"key rotation:      {key_value}/15  — {key_note}",
            f"coverage:          {coverage_value}/20  — {coverage_note}",
            f"provider attestation: {provider_value}/15  — {provider_note}",
            f"freshness:         {freshness_value}/10  — {freshness_note}",
        ],
    )


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="dontlie trust-score", description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    score = compute()
    if args.json:
        print(json.dumps(score.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"trust-score: {score.value}/100  ({score.label})")
        for line in score.summary:
            print(f"  - {line}")
    return 0


# ---- per-receipt score ---------------------------------------------------------

def score_receipt(receipt) -> dict:
    """Compute a 0-100 trust score for a single receipt.

    A receipt earns points for each of the following that it possesses:
        signature_valid    40 — the Ed25519 signature verifies against the
                                 documented public key
        hash_matches       25 — the recomputed SHA-256 matches the stored hash
        chain_linked       15 — the parent link is present and unbroken
        key_known          10 — the signing key is in the active key set
        metadata_complete  10 — model, prompt, response, timestamp all present
                                and non-empty

    Returns a dict with 'value', 'label', and a 'components' breakdown.
    """
    components = {}
    # 1. hash matches — recompute SHA-256 and compare
    try:
        from . import storage
        from .storage import _canonical_payload
        canonical = _canonical_payload(receipt)
        actual = __import__("hashlib").sha256(canonical).hexdigest()
        hash_ok = (actual == receipt.payload_sha256)
    except Exception:
        hash_ok = False
    components["hash_matches"] = {"value": 25 if hash_ok else 0, "max": 25,
                                  "note": "SHA-256 matches the canonical payload" if hash_ok else
                                          "SHA-256 mismatch — receipt tampered"}
    # 2. signature valid — verify Ed25519
    try:
        from . import sign as signing
        from .storage import _canonical_payload
        canonical = _canonical_payload(receipt)
        # Look up public key from active or key_history
        pub = None
        try:
            active = signing.load()
            if active.key_id == receipt.key_id:
                pub = active.public
        except Exception:
            pass
        if pub is None:
            try:
                conn = storage._connect()
                cur = conn.execute(
                    "SELECT public_key_pem FROM key_history WHERE key_id = ?",
                    (receipt.key_id,),
                )
                row = cur.fetchone()
                conn.close()
                if row and row[0]:
                    pub = signing.load_public_key(row[0])
            except Exception:
                pass
        sig_ok = signing.verify_bytes(pub, canonical, receipt.signature) if pub else False
    except Exception:
        sig_ok = False
    components["signature_valid"] = {"value": 40 if sig_ok else 0, "max": 40,
                                     "note": "Ed25519 signature verifies" if sig_ok else
                                             "signature verification failed"}
    # 3. chain linked — parent link present
    if receipt.parent_id is None:
        components["chain_linked"] = {"value": 5, "max": 15,
                                      "note": "first receipt in chain (no parent)"}
    else:
        # parent exists in vault?
        from . import storage
        parent = storage.get_receipt(receipt.parent_id)
        if parent is None:
            components["chain_linked"] = {"value": 0, "max": 15,
                                          "note": f"parent #{receipt.parent_id} not in vault — chain broken"}
        else:
            # check that parent.payload_sha256 is referenced via extra
            parent_sha = parent.payload_sha256
            extra_parent = (receipt.extra or {}).get("_dontlie_parent_sha256")
            if extra_parent and extra_parent == parent_sha:
                components["chain_linked"] = {"value": 15, "max": 15,
                                              "note": f"parent link to #{receipt.parent_id} verified"}
            else:
                components["chain_linked"] = {"value": 8, "max": 15,
                                              "note": f"parent link present but unverified"}
    # 4. key known — the signing key is in the active key set
    try:
        from . import sign as signing
        pub_path = signing.PUBLIC_FILE
        if pub_path.exists():
            pub_pem = pub_path.read_text()
            # simple check: is this key_id the active one?
            active_id = (signing.KEY_ID_FILE.read_text().strip()
                         if signing.KEY_ID_FILE.exists() else None)
            components["key_known"] = {"value": 10 if active_id == receipt.key_id else 5, "max": 10,
                                       "note": "signing key is the active key" if active_id == receipt.key_id
                                               else "signing key is rotated — still valid"}
        else:
            components["key_known"] = {"value": 0, "max": 10, "note": "no active public key on disk"}
    except Exception:
        components["key_known"] = {"value": 0, "max": 10, "note": "could not read active key"}
    # 5. metadata complete
    complete = bool(receipt.model and receipt.prompt and receipt.response and receipt.timestamp)
    components["metadata_complete"] = {"value": 10 if complete else 0, "max": 10,
                                       "note": "model, prompt, response, timestamp all present" if complete
                                               else "metadata fields missing"}
    value = sum(c["value"] for c in components.values())
    return {
        "value": value,
        "label": _label_for(value),
        "components": components,
    }


if __name__ == "__main__":
    raise SystemExit(main())

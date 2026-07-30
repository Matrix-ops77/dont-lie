"""SQLite-backed append-only receipt log.

Schema is fixed by docs/schema.md. We expose one Receipt dataclass and
helpers: append, list, search, export, verify_chain.

The log is append-only in practice — updates/deletes are not part of the
API. Each row carries an Ed25519 signature over a canonical payload so
the chain can be verified offline.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import sign as signing

CHAIN_VERSION_KEY = "_dontlie_chain_version"
PARENT_HASH_KEY = "_dontlie_parent_sha256"
CHAIN_VERSION = 3  # v3 adds operator_id, deployer_id, system_id (Article 12(3))

# New v3 reserved metadata keys (EU AI Act Art. 12(3) mandatory fields)
OPERATOR_ID_KEY = "_dontlie_operator_id"
DEPLOYER_ID_KEY = "_dontlie_deployer_id"
SYSTEM_ID_KEY = "_dontlie_system_id"
# Reserved chain metadata keys that cannot be set by user-supplied extra
RESERVED_CHAIN_KEYS = frozenset({
    CHAIN_VERSION_KEY,
    PARENT_HASH_KEY,
    OPERATOR_ID_KEY,
    DEPLOYER_ID_KEY,
    SYSTEM_ID_KEY,
})

DB_PATH = Path(
    os.environ.get(
        "DONTLIE_DB",
        str(Path.home() / ".local" / "share" / "dontlie" / "vault.db"),
    )
)


SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    model           TEXT    NOT NULL,
    prompt          TEXT    NOT NULL,
    response        TEXT    NOT NULL,
    parent_id       INTEGER,
    key_id          TEXT    NOT NULL,
    payload_sha256  TEXT    NOT NULL,
    signature       TEXT    NOT NULL,
    tags            TEXT    NOT NULL DEFAULT '[]',
    extra           TEXT    NOT NULL DEFAULT '{}',
    namespace       TEXT    NOT NULL DEFAULT 'default',
    operator_id     TEXT,
    deployer_id     TEXT,
    system_id       TEXT
);

CREATE INDEX IF NOT EXISTS idx_receipts_ts     ON receipts(timestamp);
CREATE INDEX IF NOT EXISTS idx_receipts_model   ON receipts(model);
CREATE INDEX IF NOT EXISTS idx_receipts_parent  ON receipts(parent_id);
CREATE INDEX IF NOT EXISTS idx_receipts_ns      ON receipts(namespace);

CREATE TABLE IF NOT EXISTS key_history (
    key_id      TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT,
    public_key_pem TEXT
);
"""


@dataclass
class Receipt:
    id: int
    timestamp: str
    model: str
    prompt: str
    response: str
    parent_id: int | None
    key_id: str
    payload_sha256: str
    signature: str
    tags: list[str] = field(default_factory=list)
    extra: dict[str, object] = field(default_factory=dict)
    # v3: Article 12(3) mandatory identity fields. None for v2 receipts.
    operator_id: str | None = None
    deployer_id: str | None = None
    system_id: str | None = None


@dataclass(frozen=True)
class VerificationIssue:
    """One reason a receipt (or export line) failed verification."""

    receipt_id: int | None
    reason: str


@dataclass(frozen=True)
class VerificationReport:
    """Detailed verification result while preserving the legacy tuple API."""

    ok_count: int
    bad_count: int
    issues: tuple[VerificationIssue, ...] = ()

    @property
    def valid(self) -> bool:
        return self.bad_count == 0


def _canonical_payload(r: Receipt) -> bytes:
    """Stable JSON for hashing/signing. Field order is fixed.

    Versioned: receipts whose ``extra`` declares ``_dontlie_chain_version >= 3``
    include the Article 12(3) identity fields (operator_id, deployer_id,
    system_id). v2 receipts continue to use the original 9-field encoding
    so their existing signatures keep verifying.
    """
    chain_version = (r.extra or {}).get(CHAIN_VERSION_KEY)
    obj = {
        "id": r.id,
        "timestamp": r.timestamp,
        "model": r.model,
        "prompt": r.prompt,
        "response": r.response,
        "parent_id": r.parent_id,
        "key_id": r.key_id,
        "tags": r.tags,
        "extra": r.extra,
    }
    if chain_version is not None and chain_version >= 3:
        obj["operator_id"] = r.operator_id
        obj["deployer_id"] = r.deployer_id
        obj["system_id"] = r.system_id
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    if db_path is None:
        db_path = DB_PATH
    # Defensive: callers in dontlie/cli.py and dontlie/web.py assign
    # `storage.DB_PATH = args.vault` where args.vault is a string from
    # argparse. The legacy module-level DB_PATH is a Path, but
    # anything that overrides it post-import may not be. Accept
    # both; sqlite3.connect will accept either.
    if not isinstance(db_path, Path):
        db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, isolation_level=None)
    if os.environ.get("DONTLIE_NO_WAL"):
        conn.execute("PRAGMA journal_mode = DELETE;")
    else:
        conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Apply additive, idempotent migrations to pre-existing vaults.

    Each migration is a (table, column) tuple. We check for the column's
    existence before issuing the ALTER TABLE so this is safe to run on
    every connection open. SQLite ALTER TABLE only supports ADD COLUMN,
    so this is the canonical way to evolve the receipts table forward.

    This runs BEFORE the SCHEMA executescript in ``db()`` because the
    SCHEMA contains CREATE INDEX statements that reference columns
    added here. For fresh databases where the tables don't exist yet,
    the ``_table_exists`` guard makes this a no-op.
    """
    def _table_exists(name: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?",
            (name,),
        ).fetchone()
        return row is not None

    def _add_column_if_missing(table: str, column: str, decl: str) -> None:
        if not _table_exists(table):
            return
        cols = {
            str(row["name"])
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    _add_column_if_missing(
        "key_history", "public_key_pem", "TEXT"
    )
    # receipts additions — each must use a default so existing rows
    # don't violate NOT NULL constraints.
    _add_column_if_missing(
        "receipts", "namespace", "TEXT NOT NULL DEFAULT 'default'"
    )
    _add_column_if_missing(
        "receipts", "observed_at", "TEXT"
    )
    # v3 Article 12(3) identity columns. NULL means "not set"; v2 receipts
    # are grandfathered as NULL and use the v2 canonical payload encoding.
    _add_column_if_missing("receipts", "operator_id", "TEXT")
    _add_column_if_missing("receipts", "deployer_id", "TEXT")
    _add_column_if_missing("receipts", "system_id", "TEXT")

    # Receipts indexes — only create on tables that exist.
    if _table_exists("receipts"):
        existing_indexes = {
            str(row["name"])
            for row in conn.execute("PRAGMA index_list(receipts)").fetchall()
        }
        if "idx_receipts_ns" not in existing_indexes:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_receipts_ns ON receipts(namespace)")


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        # Run migrations BEFORE the full schema. The SCHEMA contains
        # CREATE INDEX statements that reference columns added by
        # _migrate, so existing vaults need the column added first.
        _migrate(conn)
        conn.executescript(SCHEMA)
        yield conn
    finally:
        conn.close()


def init() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)


def _row_to_receipt(row: sqlite3.Row) -> Receipt:
    # v3 columns: present in the SELECT *, may be None for v2 receipts.
    # sqlite3.Row has no .get(); we use a small helper that mimics dict.get
    # against a fixed column list, so older v2 rows don't KeyError.
    def _opt(name: str):
        try:
            return row[name]
        except IndexError:  # pragma: no cover — column not in SELECT
            return None

    return Receipt(
        id=row["id"],
        timestamp=row["timestamp"],
        model=row["model"],
        prompt=row["prompt"],
        response=row["response"],
        parent_id=row["parent_id"],
        key_id=row["key_id"],
        payload_sha256=row["payload_sha256"],
        signature=row["signature"],
        tags=json.loads(row["tags"]),
        extra=json.loads(row["extra"]),
        operator_id=_opt("operator_id"),
        deployer_id=_opt("deployer_id"),
        system_id=_opt("system_id"),
    )


def _redaction_policy():
    """Resolve the active policy from env, or None when redaction is off."""
    import os

    from .redaction import RedactionPolicy

    config = os.environ.get("DONTLIE_REDACTION_POLICY", "default").strip()
    if not config or config.lower() in {"off", "none", "disable", "disabled"}:
        return None
    return RedactionPolicy()


def _apply_redaction(prompt: str, response: str, *, extra: dict) -> tuple[str, str]:
    policy = _redaction_policy()
    if policy is None:
        return prompt, response
    prompt_report = policy.apply(prompt)
    response_report = policy.apply(response)
    extra.setdefault("redaction", {})
    if "rules" not in extra["redaction"]:
        extra["redaction"] = {
            "redacted": prompt_report.redacted or response_report.redacted,
            "rules": sorted(
                {d.rule for d in (*prompt_report.detections, *response_report.detections)}
            ),
            "count": len(prompt_report.detections) + len(response_report.detections),
        }
    return prompt_report.text, response_report.text


def append(
    model: str,
    prompt: str,
    response: str,
    parent_id: int | None = None,
    tags: list[str] | None = None,
    extra: dict[str, object] | None = None,
    namespace: str | None = None,
) -> Receipt:
    """Create and sign a new receipt, enforcing a single continuous chain
    per-namespace.

    The chain head is the most recent receipt in the same namespace.
    """
    from . import namespace as _ns
    try:
        key = signing.load()
    except (FileNotFoundError, ValueError):
        # First-run UX: a fresh install has no signing key yet, OR
        # the keychain has a stale/corrupt entry. Generate one on the
        # spot so `dontlie proxy --mock` and friends work without
        # an explicit `dontlie gen-key` step.
        # (ValueError covers MalformedFraming from a bad keychain.)
        key = signing.generate()
        try:
            record_key(key.key_id)
        except Exception:
            pass  # key_history is best-effort; signing is what matters
    ns = namespace or os.environ.get("DONTLIE_NAMESPACE", "default")
    _ns.init()  # make sure the namespaces table exists and 'default' is present
    tags = list(tags or [])
    extra = dict(extra or {})
    if RESERVED_CHAIN_KEYS & set(extra):
        raise ValueError(
            "extra contains reserved Don't-Lie chain metadata: "
            f"{sorted(RESERVED_CHAIN_KEYS & set(extra))}"
        )
    prompt, response = _apply_redaction(prompt, response, extra=extra)

    # v3 Article 12(3) identity fields — auto-populated from env vars if not
    # supplied explicitly. None means "not asserted" (allowed for backward
    # compatibility with the proxy path that doesn't know its operator).
    operator_id = os.environ.get("DONTLIE_OPERATOR_ID") or None
    deployer_id = os.environ.get("DONTLIE_DEPLOYER_ID") or None
    system_id = os.environ.get("DONTLIE_SYSTEM_ID") or None

    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            last = conn.execute(
                "SELECT id, payload_sha256 FROM receipts WHERE namespace = ? "
                "ORDER BY id DESC LIMIT 1",
                (ns,),
            ).fetchone()
            expected_parent = int(last["id"]) if last is not None else None
            if parent_id is not None and parent_id != expected_parent:
                raise ValueError(
                    f"parent_id must be the current chain head "
                    f"({expected_parent!r}), got {parent_id!r}"
                )
            parent = expected_parent
            extra[CHAIN_VERSION_KEY] = CHAIN_VERSION
            extra[PARENT_HASH_KEY] = (
                str(last["payload_sha256"]) if last is not None else None
            )

            sequence = conn.execute(
                "SELECT seq FROM sqlite_sequence WHERE name = 'receipts'"
            ).fetchone()
            sequence_id = int(sequence["seq"]) if sequence is not None else 0
            next_id = max(expected_parent or 0, sequence_id) + 1

            r = Receipt(
                id=next_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                model=model,
                prompt=prompt,
                response=response,
                parent_id=parent,
                key_id=key.key_id,
                payload_sha256="",
                signature="",
                tags=tags,
                extra=extra,
                operator_id=operator_id,
                deployer_id=deployer_id,
                system_id=system_id,
            )
            payload = _canonical_payload(r)
            r.payload_sha256 = hashlib.sha256(payload).hexdigest()
            r.signature = signing.sign_bytes(key, payload)

            _record_key(
                conn,
                key.key_id,
                signing.public_key_to_pem(key.public),
            )
            conn.execute(
                """
                INSERT INTO receipts
                    (id, timestamp, model, prompt, response, parent_id, key_id,
                     payload_sha256, signature, tags, extra, namespace,
                     operator_id, deployer_id, system_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    r.id, r.timestamp, r.model, r.prompt, r.response,
                    r.parent_id, r.key_id, r.payload_sha256, r.signature,
                    json.dumps(r.tags), json.dumps(r.extra), ns,
                    r.operator_id, r.deployer_id, r.system_id,
                ),
            )
            conn.execute("COMMIT")
            return r
        except BaseException:
            conn.execute("ROLLBACK")
            raise


def get_receipt(receipt_id: int) -> Receipt | None:
    """Return one receipt by ID, or ``None`` when it is absent."""
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM receipts WHERE id = ?", (receipt_id,)
        ).fetchone()
        return _row_to_receipt(row) if row is not None else None


def list_receipts(limit: int = 50, offset: int = 0, namespace: str | None = None) -> list[Receipt]:
    """Return the most recent receipts in the current namespace."""
    ns = namespace or os.environ.get("DONTLIE_NAMESPACE", "default")
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM receipts WHERE namespace = ? ORDER BY id DESC LIMIT ? OFFSET ?",
            (ns, limit, offset),
        ).fetchall()
        return [_row_to_receipt(r) for r in rows]


def search(query: str, limit: int = 50, namespace: str | None = None) -> list[Receipt]:
    like = f"%{query}%"
    ns = namespace or os.environ.get("DONTLIE_NAMESPACE", "default")
    with db() as conn:
        rows = conn.execute(
            """
            SELECT * FROM receipts
            WHERE namespace = ? AND (prompt LIKE ? OR response LIKE ? OR tags LIKE ?)
            ORDER BY id DESC LIMIT ?
            """,
            (ns, like, like, like, limit),
        ).fetchall()
        return [_row_to_receipt(r) for r in rows]


def export(path: Path | None = None) -> int:
    """Stream all receipts as JSONL. Returns row count written."""
    with db() as conn:
        rows = conn.execute("SELECT * FROM receipts ORDER BY id ASC").fetchall()
        out_path = path or Path("dontlie_export.jsonl")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            for row in rows:
                rec = _row_to_receipt(row)
                f.write(json.dumps(asdict(rec)) + "\n")
        return len(rows)


def _key_material(
    conn: sqlite3.Connection,
) -> tuple[dict[str, str], set[str]]:
    keys: dict[str, str] = {}
    revoked: set[str] = set()
    for row in conn.execute(
        "SELECT key_id, revoked_at, public_key_pem FROM key_history"
    ).fetchall():
        if row["public_key_pem"]:
            keys[str(row["key_id"])] = str(row["public_key_pem"])
        if row["revoked_at"] is not None:
            revoked.add(str(row["key_id"]))

    # Legacy vaults did not persist public keys in key_history.
    try:
        current = signing.load()
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
        pass
    else:
        keys.setdefault(
            current.key_id,
            signing.public_key_to_pem(current.public),
        )
    return keys, revoked


def verify_receipts(
    receipts: Iterable[Receipt],
    public_keys: Mapping[str, str | bytes | Path],
    revoked_key_ids: Iterable[str] = (),
    *,
    require_genesis: bool = True,
) -> VerificationReport:
    """Verify signatures, hashes, ordering, and parent continuity.

    Receipts are checked in the order supplied. Full-vault and full-export
    verification should keep ``require_genesis=True`` so a missing prefix is
    detected. A partial export may opt out, though its first parent cannot be
    authenticated without an external anchor.
    """
    loaded_keys = {}
    key_errors: dict[str, str] = {}
    for key_id, value in public_keys.items():
        try:
            public_key = signing.load_public_key(value)
            derived_key_id = signing.key_id_for_public_key(public_key)
            if derived_key_id != key_id:
                raise ValueError(
                    f"key id mismatch (public key identifies as "
                    f"{derived_key_id})"
                )
            loaded_keys[key_id] = public_key
        except (OSError, ValueError, TypeError) as exc:
            key_errors[key_id] = f"invalid public key: {exc}"

    revoked = set(revoked_key_ids)
    issues: list[VerificationIssue] = []
    ok_count = 0
    bad_count = 0
    previous: Receipt | None = None

    for rec in receipts:
        reasons: list[str] = []
        if previous is None:
            if require_genesis and rec.id != 1:
                reasons.append(f"missing chain prefix before receipt {rec.id}")
            if require_genesis and rec.parent_id is not None:
                reasons.append("genesis receipt must have parent_id null")
        else:
            if rec.id <= previous.id:
                reasons.append(
                    f"receipt id {rec.id} is not after {previous.id}"
                )
            elif rec.id != previous.id + 1:
                reasons.append(
                    f"missing intermediate receipt(s) between "
                    f"{previous.id} and {rec.id}"
                )
            if rec.parent_id != previous.id:
                reasons.append(
                    f"parent_id {rec.parent_id!r} does not match "
                    f"previous receipt {previous.id}"
                )

        chain_version = rec.extra.get(CHAIN_VERSION_KEY)
        if chain_version is not None:
            if chain_version > CHAIN_VERSION:
                # Receipts from a future schema version are unsupported;
                # receipts from older versions are grandfathered and still
                # verify against their own canonical encoding.
                reasons.append(f"unsupported chain version {chain_version!r}")
            elif previous is None and not require_genesis and rec.parent_id is not None:
                # A partial export has no previous receipt against which to
                # authenticate its first parent hash. The caller opted out of
                # genesis validation, so leave this first link unverified.
                pass
            else:
                expected_parent_hash = (
                    previous.payload_sha256 if previous is not None else None
                )
                actual_parent_hash = rec.extra.get(PARENT_HASH_KEY)
                if actual_parent_hash != expected_parent_hash:
                    reasons.append(
                        "parent sha256 does not match previous receipt "
                        f"({actual_parent_hash!r} != {expected_parent_hash!r})"
                    )

        payload = _canonical_payload(rec)
        if hashlib.sha256(payload).hexdigest() != rec.payload_sha256:
            reasons.append("payload sha256 mismatch")
        if rec.key_id in revoked:
            reasons.append(f"signing key {rec.key_id} is revoked")
        elif rec.key_id in key_errors:
            reasons.append(key_errors[rec.key_id])
        elif rec.key_id not in loaded_keys:
            reasons.append(f"missing public key for {rec.key_id}")
        elif not signing.verify_bytes(
            loaded_keys[rec.key_id], payload, rec.signature
        ):
            reasons.append("signature verification failed")

        if reasons:
            bad_count += 1
            issues.extend(
                VerificationIssue(receipt_id=rec.id, reason=reason)
                for reason in reasons
            )
        else:
            ok_count += 1
        previous = rec

    return VerificationReport(
        ok_count=ok_count,
        bad_count=bad_count,
        issues=tuple(issues),
    )


def verify_chain_report() -> VerificationReport:
    """Verify the complete local vault and return detailed failure reasons."""
    with db() as conn:
        keys, revoked = _key_material(conn)
        rows = conn.execute("SELECT * FROM receipts ORDER BY id ASC").fetchall()
        return verify_receipts(
            (_row_to_receipt(row) for row in rows),
            keys,
            revoked,
        )


def verify_chain() -> tuple[int, int]:
    """Backward-compatible ``(ok_count, bad_count)`` local verification."""
    report = verify_chain_report()
    return report.ok_count, report.bad_count


def export_bundle(path: Path) -> int:
    """Write a self-contained JSON bundle with receipts and public keys."""
    with db() as conn:
        keys, revoked = _key_material(conn)
        rows = conn.execute("SELECT * FROM receipts ORDER BY id ASC").fetchall()
        receipts = [asdict(_row_to_receipt(row)) for row in rows]
    bundle = {
        "format": "dontlie-verification-bundle",
        "version": 1,
        "public_keys": keys,
        "revoked_key_ids": sorted(revoked),
        "receipts": receipts,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return len(receipts)


def _export_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise TypeError(f"{field_name} must be an integer")
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an integer") from exc


def _receipt_from_mapping(value: Mapping[str, object]) -> Receipt:
    tags = value.get("tags", [])
    extra = value.get("extra", {})
    if not isinstance(tags, list) or not all(
        isinstance(tag, str) for tag in tags
    ):
        raise TypeError("tags must be a list of strings")
    if not isinstance(extra, dict) or not all(
        isinstance(key, str) for key in extra
    ):
        raise TypeError("extra must be an object with string keys")
    parent_id = value.get("parent_id")
    return Receipt(
        id=_export_int(value["id"], "id"),
        timestamp=str(value["timestamp"]),
        model=str(value["model"]),
        prompt=str(value["prompt"]),
        response=str(value["response"]),
        parent_id=(
            None
            if parent_id is None
            else _export_int(parent_id, "parent_id")
        ),
        key_id=str(value["key_id"]),
        payload_sha256=str(value["payload_sha256"]),
        signature=str(value["signature"]),
        tags=tags,
        extra=dict(extra),
    )


def verify_export(
    path: Path,
    public_keys: Mapping[str, str | bytes | Path] | None = None,
    revoked_key_ids: Iterable[str] = (),
) -> VerificationReport:
    """Verify a bundle, or legacy JSONL when public keys are supplied."""
    raw = path.read_text(encoding="utf-8")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        document = None

    try:
        if isinstance(document, dict) and document.get(
            "format"
        ) == "dontlie-verification-bundle":
            if document.get("version") != 1:
                raise ValueError(
                    f"unsupported bundle version {document.get('version')!r}"
                )
            raw_receipts = document.get("receipts")
            raw_keys = document.get("public_keys")
            raw_revoked = document.get("revoked_key_ids", [])
            if not isinstance(raw_receipts, list):
                raise ValueError("bundle receipts must be an array")
            if not isinstance(raw_keys, dict):
                raise ValueError("bundle public_keys must be an object")
            if not isinstance(raw_revoked, list):
                raise ValueError("bundle revoked_key_ids must be an array")
            receipts = [_receipt_from_mapping(item) for item in raw_receipts]
            embedded_keys = {str(k): str(v) for k, v in raw_keys.items()}
            # Supplying keys pins verification to an external trust source.
            # Embedded keys make a bundle portable, but cannot by themselves
            # prove who created an artifact received from an untrusted party.
            keys = dict(public_keys) if public_keys is not None else embedded_keys
            revoked = list({*map(str, raw_revoked), *revoked_key_ids})
        else:
            records = [
                json.loads(line)
                for line in raw.splitlines()
                if line.strip()
            ]
            receipts = [_receipt_from_mapping(item) for item in records]
            keys = dict(public_keys or {})
            revoked = list(revoked_key_ids)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return VerificationReport(
            ok_count=0,
            bad_count=1,
            issues=(VerificationIssue(None, f"invalid export: {exc}"),),
        )
    return verify_receipts(receipts, keys, revoked)


def count(namespace: str | None = None) -> int:
    ns = namespace or os.environ.get("DONTLIE_NAMESPACE", "default")
    with db() as conn:
        return int(conn.execute(
            "SELECT COUNT(*) AS n FROM receipts WHERE namespace = ?", (ns,)
        ).fetchone()["n"])


def revoke_key(key_id: str, revoked_at: str | None = None) -> None:
    """Mark ``key_id`` as revoked. Subsequent ``verify_chain`` calls will
    treat any receipt signed by this key as invalid. Idempotent.
    """
    if revoked_at is None:
        revoked_at = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute(
            "INSERT INTO key_history(key_id, created_at, revoked_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key_id) DO UPDATE SET revoked_at = excluded.revoked_at",
            (key_id, "1970-01-01T00:00:00+00:00", revoked_at),
        )


def record_key(key_id: str) -> None:
    """Record a key's creation in ``key_history`` if not already present.
    Receipts only become revocable once the key is recorded here.
    """
    with db() as conn:
        _record_key(conn, key_id)


def _record_key(
    conn: sqlite3.Connection,
    key_id: str,
    public_key_pem: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO key_history(key_id, created_at, public_key_pem)
        VALUES (?, ?, ?)
        ON CONFLICT(key_id) DO UPDATE SET public_key_pem =
            COALESCE(key_history.public_key_pem, excluded.public_key_pem)
        """,
        (key_id, datetime.now(timezone.utc).isoformat(), public_key_pem),
    )

# Don't-Lie v2 storage and verification

This document describes the schema implemented by `dontlie.storage`, not a
future cloud schema. The current product is a local SQLite vault with signed,
parent-linked receipts.

## Files

- Database: `~/.local/share/dontlie/vault.db`
- Override: `DONTLIE_DB=/path/to/vault.db`
- Signing directory: `~/.config/dontlie/keys`
- Override: `DONTLIE_KEY_DIR=/path/to/keys`

SQLite uses WAL mode by default. Tests and the offline demo can set
`DONTLIE_NO_WAL=1` for easier copying.

## `receipts`

| Column | Type | Meaning |
|---|---|---|
| `id` | INTEGER PRIMARY KEY | Monotonic receipt sequence. |
| `timestamp` | TEXT | UTC ISO-8601 timestamp written by the recorder. |
| `model` | TEXT | Model value in the upstream request. |
| `prompt` | TEXT | Canonical JSON of the complete request body. Historical rows may contain only the messages representation. |
| `response` | TEXT | Extracted assistant text, or the upstream error/non-JSON body. |
| `parent_id` | INTEGER | Previous receipt ID; `NULL` for the genesis receipt. |
| `key_id` | TEXT | Identifier of the Ed25519 signing key. |
| `payload_sha256` | TEXT | SHA-256 of the canonical fields signed for this row. |
| `signature` | TEXT | Base64 Ed25519 signature over the canonical fields. |
| `tags` | TEXT | JSON array, for example `['stream', 'tools']`. |
| `extra` | TEXT | JSON object containing status, endpoint, byte count, timing, content type, raw response SHA-256, optional base64 raw response, and chain-v2 metadata. |

Response metadata always includes `response_sha256`. By default it also
includes `response_raw_b64`, the exact upstream response bytes (including SSE
framing for streamed calls). Set `DONTLIE_STORE_RAW_RESPONSE=0` when policy
requires storing only the extracted response text and its digest. The raw copy
is capped at 16 MiB by default; larger responses retain their SHA-256 and set
`response_raw_omitted: true`.

The signed canonical payload contains `id`, `timestamp`, `model`, `prompt`,
`response`, `parent_id`, `key_id`, `tags`, and `extra`. It intentionally does
not contain `payload_sha256` or `signature`, because those are derived from the
payload.

### Chain-v2 metadata

New receipts contain reserved keys in `extra`:

- `_dontlie_chain_version: 2`
- `_dontlie_parent_sha256`: the previous receipt's `payload_sha256`, or `null`
  for genesis

This prevents a valid receipt from another chain being spliced into the middle
of a chain. Legacy receipts without these keys remain verifiable under their
original canonical format. User-supplied `extra` cannot override the reserved
keys.

## `key_history`

| Column | Type | Meaning |
|---|---|---|
| `key_id` | TEXT PRIMARY KEY | Ed25519 public-key identifier. |
| `created_at` | TEXT | First observed time for the key. |
| `revoked_at` | TEXT nullable | Local revocation marker. |
| `public_key_pem` | TEXT nullable | Public key needed for rotation and portable verification. |

The `public_key_pem` column is added idempotently when an older vault is opened.
Existing databases are not rewritten destructively.

## Verification

`dontlie verify` checks:

1. Canonical payload SHA-256.
2. Signature against the receipt's recorded public key.
3. Key revocation status.
4. Monotonic IDs and missing intermediate rows.
5. `parent_id` continuity.
6. Chain-v2 previous-payload hash links.
7. Genesis rules when verifying a complete local vault.

Use `dontlie verify --verbose` for receipt-level failure reasons. The Python
API exposes `verify_chain_report()` for structured reports while the historical
`verify_chain()` tuple `(ok_count, bad_count)` remains available.

## Portable verification bundles

```sh
dontlie export receipts.bundle.json --bundle
dontlie verify --export receipts.bundle.json --verbose
```

A bundle contains receipt records, embedded public keys, revoked key IDs, and a
format version. It can be verified without the private key or the original
SQLite database. An embedded key establishes mathematical validity, not who
should be trusted; pin an external key when provenance matters:

```sh
dontlie verify --export receipts.bundle.json \
  --public-key KEY_ID=/trusted/issuer/dontlie.pub
```

Legacy JSONL exports can also be verified when the caller supplies the public
key mapping through the Python API.

## Security boundaries

A valid receipt proves that the local signing key signed this canonical record
and that its internal chain checks pass. It does not prove that the model's
answer is true, that a remote provider generated it without an intermediary,
or that a compromised host did not alter the response before signing.

The current MVP writes the private key under `DONTLIE_KEY_DIR` with mode
`0600` and makes a best-effort OS-keychain backup. The public key is stored in
PEM form for local and portable verification.

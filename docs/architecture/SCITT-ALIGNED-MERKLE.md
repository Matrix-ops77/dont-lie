# SCITT-aligned Merkle tree + transparency log

**Status:** design only · **Tier 3** (ship 4–8 weeks after `anchor daily` is stable) · **Date:** 2026-07-29
**Closes:** `tech_edge_2026.md` §4.3, §5.1; SYNTHESIS_2026 §7 #9.

---

## 1. Why SCITT now

IETF SCITT is now **RFC 9943, Proposed Standard, June 2026**
([datatracker.ietf.org/doc/rfc9943](https://datatracker.ietf.org/doc/rfc9943/)).
SCITT is the architectural spec for what Don't-Lie does — signed
statements about artifacts in an append-only transparency log —
but uses COSE / CBOR framing rather than v1 JSON-canonical.
Related drafts: `draft-ietf-scitt-scrapi-11` (Reference APIs, May
2026), `draft-ietf-cose-merkle-tree-proofs-17` (COSE Receipts).

The cost of adopting SCITT framing in v2 is **mostly naming**. The
underlying cryptography (Ed25519 + SHA-256 + Merkle tree) is
unchanged. The win is interop: third-party SCITT verifiers can
validate Don't-Lie receipts without a custom verifier; receipts
can be re-anchored in any SCITT-compatible log (Rekor, Sigsum,
custom); the format aligns with the IETF supply-chain-transparency
ecosystem.

The most important new construct is the **COSE_Sign1 envelope**
(RFC 9052) — it binds the operator key, the Merkle root hash, and
a timestamp into one signed CBOR structure any SCITT verifier
library can parse.

## 2. The COSE_Sign1 envelope

```text
COSE_Sign1 = [
  protected: {                          ; signed headers
    "alg":     1,                        ; EdDSA
    "content_type": "application/dontlie-signed-statement+json",
    "dontlie_version": 2,
    "iss":     "did:key:z6Mk...",        ; operator's DID
    "kid":     "ed25519:abcdef1234567890",
    "iat":     "2026-07-29T00:00:00Z"
  },
  unprotected: {},
  payload:     <bytes>,                  ; canonical JSON receipt
  signature:   <64 bytes Ed25519>        ; over protected || payload
]
```

The `payload` IS the v1 canonical JSON receipt (no on-the-wire
change). The `signature` IS the existing Ed25519 signature. SCITT
framing is a wrapper any IETF `cose-cli` can produce and verify.

## 3. Merkle tree structure

**Binary, sorted by receipt id, last-leaf duplication for odd
levels** (Bitcoin-style). This is what `dontlie/batch.py` already
implements:

- `batch.merkle_root(leaf_hashes)` — Bitcoin-style last-leaf dup.
- `batch.merkle_path(leaf_hashes, index)` — sibling path to root.
- `batch.verify_merkle_path(leaf_hash, index, path, root)` —
  inclusion proof verifier.

The construction matches RFC 9162 §2.1 (Merkle Tree Hash, MTH):
`MTH(D_n) = SHA256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`. v2 keeps
`batch.py` verbatim and adds an `mth()` alias for verifier interop.

**Why not MMR?** MMR is O(1) append and log-structured. Don't-Lie
is single-writer, single-machine, batch-anchored daily. The
simpler binary tree is correct. MMR is a v3 revisit if cloud-sync
multi-machine ships.

## 4. Merkle inclusion proof

`batch.merkle_path` already produces the SCITT-compatible form:

```json
{
  "leaf_index": 512,
  "leaf_count": 1024,
  "siblings":   ["f3a4...", "9c12...", "77bd..."],
  "root":       "0a1b..."
}
```

A verifier rebuilds the path and checks the result equals `root`.
SCITT draft `draft-ietf-cose-merkle-tree-proofs-17` defines this
format exactly; the existing `verify_merkle_path` is already a
valid SCITT verifier.

## 5. The transparency log entry

A daily anchor is a SCITT log entry — a COSE_Sign1 envelope whose
payload is a `TransparencyLogEntry`:

```json
{
  "log_id":          "did:web:dontlie.local:logs:daily",
  "log_version":     1,
  "merkle_root":     "0a1b...",
  "merkle_root_alg": "SHA-256",
  "tree_size":       1024,
  "first_leaf":      { "receipt_id": 500,  "payload_sha256": "..." },
  "last_leaf":       { "receipt_id": 1523, "payload_sha256": "..." },
  "day":             "2026-07-28",
  "issuer":          "did:key:z6Mk...",
  "issued_at":       "2026-07-29T00:00:00Z"
}
```

An auditor verifying this entry can: verify the Ed25519 signature
against the operator's public key; verify the Merkle root by
recomputing the tree from any receipt whose inclusion proof they
hold; trust monotonicity because the envelope is signed and
chained via the existing receipt hash chain.

## 6. The optional public log

Local-first is sufficient for the buyer's main use case ("prove
the chain did not break to an auditor on a clean machine"). For
users who want **public, third-party-monitored** anchoring — the
SCITT-typical deployment — the optional public log is **Sigstore
Rekor v2** (see [SIGSTORE-REKOR.md](SIGSTORE-REKOR.md)). Opt-in
for two reasons:

- **Privacy.** Publishing the Merkle root leaks the **count** of
  receipts per day. Publishing individual receipt hashes leaks
  **when** calls were made. The daily root is the smallest
  public footprint that still gives chain-integrity.
- **Commitment.** Rekor v2 is free (Sigstore is a CNCF public
  good), but every public entry is a public commitment. A user
  who signs 1,000 prompts/day probably does not want 1,000
  public timestamps.

**The local-only path** (current `anchor daily`): local Merkle
root + OTS + witness is already the design. It gives
bounded-tampering-detection without any public commitment.

## 7. Migration from current `anchor daily`

Current `dontlie/anchor_daily.py` already produces the building
blocks. Four steps to SCITT-align:

| Step | Change | Effort |
|---|---|---|
| 1. Wrap daily batch in COSE_Sign1 | Add `_cose_envelope.py` (~80 LOC). Reuses existing canonical JSON as payload. | 1–2 days |
| 2. Add `TransparencyLogEntry` payload | Add `_scitt_payload.py` (~60 LOC). Schema per §5. | 1 day |
| 3. Extend `batch.py` with `mth()` alias | Internal-only; preserves back-compat. | 0.5 day |
| 4. Add `dontlie export --format scitt` | New export format; existing `verify` works because payload is the existing canonical JSON. | 2–3 days |

**Total: ~5 days** for one engineer. No receipt format breakage.
The verify path is unchanged. The only user-visible change is a
new `--format scitt` export option and the COSE envelope wrapper
around the daily anchor.

**Backwards compatibility:** receipts without a COSE wrapper
verify exactly as before. Existing `dontlie verify`, portable
bundles, and HTML reports continue to work. The COSE envelope is
**additive metadata at the daily-anchor level**, not a per-receipt
wrapper.

## 8. References

- [RFC 9943 — SCITT Architecture](https://datatracker.ietf.org/doc/rfc9943/)
- [IETF SCITT working group](https://datatracker.ietf.org/wg/scitt/about/)
- [draft-ietf-cose-merkle-tree-proofs-17](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/) — COSE Receipts
- [draft-ietf-scitt-scrapi-11](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/) — SCITT Reference APIs
- [RFC 9052 — COSE_Sign1](https://datatracker.ietf.org/doc/html/rfc9052)
- [RFC 9162 — Certificate Transparency v2.0](https://datatracker.ietf.org/doc/rfc9162/) (MTH reference)
- `tech_edge_2026.md` §4.3, §5.1; `SYNTHESIS_2026.md` §5.1

# RFC 3161 free-TSA timestamp anchoring — plan

**Scope:** Add an optional, third-party-anchored timestamp to the export
bundle so a verifier can later confirm "this digest existed by time T"
without trusting Don't-Lie.

## Why

Today `verify_export` only proves the chain is internally consistent and
signed by the keys in the bundle. It does not prove the bundle existed at
any specific point in time. An RFC 3161 timestamp from an independent TSA
adds exactly that. The brand language is preserved: this anchors *the
signed receipt bundle*, not the truth of the underlying model output.

## Free-TSA choice

Use a free, no-account public TSA. Pick at runtime, configurable:

| TSA | URL | Notes |
|---|---|---|
| FreeTSA (default) | `https://freetsa.org/tsr` | No auth, rate-limited |
| DigiStamp | `https://timestamp.digicert.com` | Comodo-backed |
| Sectigo | `https://timestamp.sectigo.com` | Comodo-backed |

Operator sets `DONTLIE_TSA_URL` to override. Default fingerprints are
pinned in the bundle so a MitM cannot swap a TSA.

## Wire format (additive to bundle)

Embed one `attestations[]` entry per TSA response:

```
{
  "type": "rfc3161",
  "tsa_url": "https://freetsa.org/tsr",
  "tsa_cert_sha256": "<pin>",
  "digest_algorithm": "sha256",
  "message_imprint": "<hex sha256 of bundle.canonical>",
  "serial_number": "<hex from TSResp>",
  "gen_time": "<ISO8601 from TSResp>",
  "policy_oid": "1.2.3.4.5",          # optional
  "nonce": "<hex>",                   # optional, included if request had one
  "tsa_signature": "<base64 DER TimeStampResp>"
}
```

`tsa_signature` is the full DER-encoded `TimeStampResp` so the verifier
can re-parse it with `cryptography` and independently check the TSA's
certificate chain against the pinned public key.

## Pipeline (export-time)

```
def anchor_with_rfc3161(bundle: dict, tsa_url: str) -> dict:
    canonical = canonical_json(bundle["receipts"] + bundle["pubkeys"])
    imprint = sha256(canonical).digest()
    nonce = secrets.token_bytes(8)
    req = build_tsr_request(imprint, hash_oid=SHA256_OID, nonce=nonce)
    resp = post_tsr(tsa_url, req, timeout=10.0)
    verify_tsr_response(resp, expected_imprint=imprint, nonce=nonce)
    bundle.setdefault("attestations", []).append({
        "type": "rfc3161",
        "tsa_url": tsa_url,
        "tsa_cert_sha256": pin_for(tsa_url),
        "digest_algorithm": "sha256",
        "message_imprint": imprint.hex(),
        "serial_number": resp.serial_number.hex(),
        "gen_time": resp.gen_time.isoformat(),
        "nonce": nonce.hex(),
        "tsa_signature": b64(resp.der),
    })
    return bundle
```

## Pipeline (verify-time)

```
def verify_rfc3161_attestation(att: dict, canonical: bytes) -> bool:
    if att["type"] != "rfc3161": return False
    imprint = sha256(canonical).digest()
    if imprint.hex() != att["message_imprint"]: return False
    resp = TimeStampResp.from_der(b64d(att["tsa_signature"]))
    if resp.status != PKIStatus.granted: return False
    if sha256(resp.tst_info.message_imprint).hex() != imprint.hex(): return False
    cert = resp.signer_cert
    if sha256(cert.der).hex() != att["tsa_cert_sha256"]: return False
    if not verify_chain(cert, trust_store=TSAs[att["tsa_url"]]): return False
    if att.get("nonce") and resp.tst_info.nonce.hex() != att["nonce"]: return False
    return True
```

## Failure & trust model

- **No network = no attestation.** Skip silently; never fail export.
- **TSR request fails / 5xx / timeout** → log to stderr, retry once with
  backoff, otherwise skip. Bundle remains valid; attestation is
  best-effort.
- **TSR granted but cert doesn't pin** → drop that attestation, log a
  warning. The bundle is still valid; only the anchor is missing.
- **Replay at verify time** is detectable via the nonce + the
  imprint match; the verifier must reject any attestation whose
  `message_imprint` does not hash the canonical bundle.

## Files to add

- `dontlie/anchor/rfc3161.py` — `request_attestation(tsa_url, digest)`,
  `parse_response(der)`, `verify_attestation(att, canonical)`.
- `dontlie/anchor/pins.py` — `FreeTSA` pin table, overridable by env.
- `dontlie/anchor/__init__.py` — re-exports.
- `dontlie/test_anchor_rfc3161.py` — offline tests using a recorded TSR
  fixture (no live network); one happy-path + three failure-path tests.

## Out of scope

- Bitcoin / OpenTimestamps anchors (already tracked elsewhere).
- Multi-TSA quorum. Single TSA per bundle is sufficient for v1.
- Paid TSAs (e.g., DigiCert PKI). Operator can swap via env.

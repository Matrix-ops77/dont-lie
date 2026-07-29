# Public reputation attestations

Don't-Lie's receipt vault is private evidence. The reputation layer turns one
receipt into a public, pseudonymous claim that can be copied, pinned to an
Ed25519 identity, checked offline, and later revoked by the same identity. It
does not upload anything and has no server, account, or global registry.

## Commands

Run the standalone command from the project directory:

```sh
python -m reputation publish 42 \
  --witness-count 2 \
  --last-corroboration 2026-07-24T14:10:00Z

python -m reputation link '#dl/v1/2nc6t4x6kgc4xscjryfj'
python -m reputation check '#dl/v1/2nc6t4x6kgc4xscjryfj'
python -m reputation revoke '#dl/v1/2nc6t4x6kgc4xscjryfj'
```

`publish` reads only the requested receipt ID and current chain-tip digest from
the local SQLite vault. It writes the portable JSON artifact into the local
content-addressed store and prints its full SHA-256 address, short share
fragment, and path. `link` accepts the full address, existing link, or artifact
path. `check` resolves the same references and prints signature/trust state,
witness count, age, and last corroboration. A valid revoked result exits 2.

The defaults follow the existing `DONTLIE_DB` and `DONTLIE_KEY_DIR`
configuration. Set `DONTLIE_REPUTATION_DIR` or pass `--store` to select a
different local store. A recipient can copy the printed JSON artifact into
their store or pass its path directly to `check`; no network lookup occurs.

## Portable format

The canonical signed payload has exactly five fields:

```json
{
  "receipt_id": 42,
  "chain_tip_hash": "64 lowercase hex characters",
  "public_key": "base64url raw Ed25519 public key",
  "witness_count": 2,
  "truncated_promise": "v1.<issued-unix>.<corroborated-unix>.<32 hex>"
}
```

The portable envelope is `{"payload": <above>, "signature": "<base64url>"}`.
The signature covers canonical UTF-8 JSON for the complete five-field payload.
The public key is pseudonymous attribution, not a person's name.

The truncated promise is a 128-bit SHA-256 prefix over a domain separator, the
other four public fields, publication time, and last-corroboration time. It
lets an offline verifier detect altered counts or times without exposing
prompt, response, model, provider, tags, or the receipt payload hash. A zero
last-corroboration value is required for zero witnesses; a nonzero witness
count requires a corroboration time.

The artifact address is SHA-256 over the canonical envelope. Short links use
the first 100 address bits as lower-case base32:
`#dl/v1/<20 characters>`. Resolution checks for ambiguity and then recomputes
the full content address, so the shortened fragment is a locator rather than a
weakened integrity check.

## Signer trust

Signature validity and signer trust are separate:

* `self`: the public key matches the local private key.
* `pinned`: the fingerprint matches a key supplied with `--trusted-key`.
* `unknown`: the signature is valid but no local trust decision exists.

Use `--trusted-key /path/to/public.pem` or pass the raw base64url public key.
Trust is deliberately local. Copying an attestation does not silently trust its
signer.

## Revocation

Revocation creates a second immutable, content-addressed artifact signed by the
attestation's key. It contains the full attestation address, signer public key,
revocation time, and Ed25519 signature. `check` ignores malformed, foreign, or
misaddressed revocation files and reports `REVOKED` only for a valid matching
signature. Revocation is discoverable only where the revocation artifact has
also been copied; there is no central revocation oracle.

## Threat model and honest boundaries

| Threat | Handling |
|---|---|
| Public artifact leaks conversation content | The five-field payload excludes prompt, response, model, provider, tags, and receipt payload digest. |
| Attacker edits receipt ID, tip, count, or timestamps | Promise commitment and Ed25519 signature verification fail. |
| Attacker substitutes a public key | The signature no longer verifies. |
| Attacker forges a revocation | Revocation must verify under the attestation's exact public key. |
| Short-link collision | Resolver rejects ambiguous prefixes and verifies the full content hash after resolution. |
| Store file is replaced or renamed | Filename/full-address mismatch is rejected. |
| Unknown signer presents a valid artifact | Cryptographic validity is shown as `unknown`, never promoted to trust. |
| Signer backdates publication or overstates witnesses | The signer can lie when creating its own claim. The format proves who signed which claim, not that the claim is true. |
| Witnesses collude or are duplicated | `witness_count` is an asserted aggregate. Verifying individual witness identities remains the ground-truth lane's responsibility. |
| Revocation is withheld from a verifier | Offline verification can only see locally available revocations. Share the revocation artifact wherever the attestation was shared. |
| 128-bit promise prefix is attacked | The prefix gives 128-bit second-preimage resistance for this disclosure format; the envelope additionally has a full Ed25519 signature and 256-bit content address. |

This layer does not prove model truth, provider provenance, human identity, or
receipt-chain validity by itself. To audit the underlying receipt, obtain a
separate verification bundle and confirm that the published receipt ID exists
under the published chain tip. Public attribution is key-pinned, scoped to one
receipt and one chain tip, and pseudonymous by design.

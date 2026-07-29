# Don't-Lie privacy & anchoring

This document describes the privacy/trust lane of Don't-Lie:
how receipts can be exported with an explicit evidence posture
(`fingerprint`, `redacted`, or `forensic`) and how external
attestation manifests are produced and verified. It is a
companion to `security.md`; that file describes what the local
chain proves, and this file describes what the artifacts you share
prove (or deliberately do not prove).

## What this layer is for

A signed receipt proves that *the bytes a host recorded* were not
later altered. It does not, by itself, prove that a recipient is
seeing the *whole story*: the host could have redacted a prompt
before signing, the original conversation could have been cut in
half, or the timestamps could have been back-dated. The privacy
lane in this module exists to make that boundary explicit on
both sides — the producer's evidence envelope and the consumer's
verification report.

There are two halves:

1. **Evidence modes** (`dontlie/privacy.py`) — the unit of trust
   on the receipt side. A producer picks one of three explicit
   modes when exporting a piece of text. Each mode produces a
   self-describing JSON envelope that names the detector bundle,
   the detection scope, the redactions applied, and (always) a
   warning that detection is heuristic.
2. **Anchor manifests** (`dontlie/anchors.py`) — the unit of
   trust on the timeline side. A manifest binds a set of receipt
   checkpoints to one or more external attestations (RFC 3161
   timestamps, OpenTimestamps upgrade proofs, or custom attestors)
   and is itself a portable, deterministic JSON document.

Both halves share the same design discipline: every artifact is
self-describing, deterministic in its digest, and refuses to claim
more than its inputs can prove.

## Evidence modes

### `fingerprint`

```text
mode: fingerprint
text: <not present>
fingerprint: sha256:<hex>
```

The text is omitted entirely. Only a content digest is shipped.
Useful for sharing "this is what the receipt says, in a way that
cannot leak" without revealing the prompt or response.

### `redacted`

```text
mode: redacted
text: "the [PARTIAL:openai_api_key:sha256=…] was rotated"
redactions: [{detector: openai_api_key, start: 4, end: 35, …}]
warnings: ["detection is heuristic; redacted output may be incomplete"]
```

A locally-redacted view of the text. Each redacted span is
replaced with a stable token that includes the detector id and the
sha-256 digest of the original bytes, so a downstream auditor can
verify "this span was detected, redacted, and untouched in
transit" without ever seeing the secret.

**The warning is mandatory.** Heuristic detection cannot
enumerate every secret or PII pattern. False negatives are
expected. Callers must treat `redacted` output as "best-effort
removal of *known* patterns", never as "all sensitive data is
gone". For any high-stakes exchange, prefer `forensic` and redact
out-of-band.

### `forensic`

```text
mode: forensic
text: "the sk-abc...xyz was rotated"
redactions: [{detector: openai_api_key, start: 4, end: 35, …}]
fingerprint: sha256:<hex>
warnings: ["detection is heuristic; redacted output may be incomplete"]
```

The full original text plus the detection index. This is the mode
to use when the recipient needs to (a) see the source, (b)
re-verify the redactions, and (c) confirm the text the producer
signed has not drifted from what the consumer is reading. The
redaction index in a `forensic` envelope is identical to the
redaction index a `redacted` envelope would emit; the only
difference is the text is kept.

### What the envelope always carries

| Field | Purpose |
|---|---|
| `format` / `format_version` | Reader refuses unknown formats. |
| `mode` | Which of the three modes produced this artifact. |
| `detector_bundle` | Version of the regex/keyword bundle that ran. |
| `generated_at` | ISO-8601 timestamp. Deterministic across runs unless the caller supplies one. |
| `text_digest_sha256` | SHA-256 of the source text. Stable across modes. |
| `redactions` | Per-span detection index (detector id, label, offsets, original digest). |
| `text` | Present for `redacted` and `forensic`; absent for `fingerprint`. |
| `fingerprint` | Present for `fingerprint` and `forensic`; absent for `redacted`. |
| `warnings` | At minimum, the heuristic-warning string. |

### Determinism

Every artifact produced here is a pure function of its inputs.
The default timestamp is the Unix epoch; the detector bundle is
named in the envelope; the JSON is serialized with sorted keys
and no whitespace. Two runs over the same input produce identical
bytes. If you need a real timestamp on the artifact, pass
`generated_at=` explicitly.

### Extending the detector set

`DetectorRegistry` is a small public surface. `register(id,
label, pattern)` adds a detector at runtime. Patterns must
declare exactly one named group; that group is the captured
span. The default registry in the module is the only
out-of-the-box set, and is documented as "conservative, not
exhaustive". If you wire a richer detector (e.g. local NER),
add it last; earlier registrations win on overlap.

## Anchor manifests

### What a manifest is

A `AnchorManifest` is a JSON document that lists:

- A set of checkpoints, each binding a receipt id to its
  payload sha-256 plus any attestations the vault has gathered.
- A `checkpoint_digest` that fingerprints the ordered set of
  checkpoints. Tampering with the checkpoints invalidates the
  digest.
- A `format` / `version` pair so a future reader can refuse
  unknown schemas.
- A `vault_key_id` so a reader can tell which local key was
  authoritative when the manifest was produced.
- A `note` field for free-form operator context.

The manifest is deliberately not signed by the local Ed25519 key.
Its integrity comes from the attestations it carries; the
`checkpoint_digest` is a structural check, not a signature. To
get a signed local assertion of the manifest, the producer can
record a separate receipt whose `extra` field embeds the
manifest's digest. That pattern keeps the manifest
format-agnostic while still tying it to the vault.

### Attestation lifecycle

Every attestation goes through a state machine:

```text
        request
   (no attestations)
          |
          v
     pending  --upgrade-->  confirmed
          |
          v
     failed  (attestor rejected the imprint)
          |
          v
     inconclusive (reader cannot re-validate; e.g. attestor
                   client is not available, or TSA key was
                   revoked since the request was made)
```

`verify_manifest` reports counts for each of these states, plus
a list of human-readable `issues` for the audit log. A manifest
is `valid` only when `bad_count == 0`; `inconclusive` is a
separate signal (the reader couldn't tell, not that the
attestation is wrong).

### RFC 3161 integration

`RFC3161Attestor(tsa_url=...)` is a documented integration point
for an RFC 3161 TSA client. The class satisfies the
`Attestor` protocol, but the request and verify methods raise
`AnchorError` until a real HTTP/ASN.1 client is wired in. The
minimal protocol steps (DER-encoded `TimeStampReq`, imprint sha-256,
cert-chain verification) are listed inline so the integration is
unambiguous.

The offline `OfflineRFC3161Attestor` is the test fixture: it
accepts any digest, returns a deterministic `proof`, and verifies
its own proof. It is the only RFC 3161 implementation that is
imported by default; real TSA clients should be added behind a
flag or an entry point that the operator opts into.

### OpenTimestamps integration

`OpenTimestampsAttestor(...)` is the integration point for a
real OTS calendar+upgrader. The two-phase flow is preserved: a
calendar returns a `pending` attestation, an upgrade step
moves it to `confirmed` once a Bitcoin-anchored proof is
available. The offline `OfflineOpenTimestampsAttestor(pending=True)`
exposes the same state machine, plus a `upgrade()` method, so
the upgrade code path can be tested without network access.

`upgrade_manifest(manifest, upgrader)` walks a manifest and asks
`upgrader` to upgrade every pending OTS attestation. Attestations
from other attestors are passed through unchanged. The result is
a new manifest with an updated `checkpoint_digest`.

### Determinism

Manifests follow the same discipline as evidence: the digest is
a function of the canonical JSON of the checkpoints, full stop.
The `created_at` field is the Unix epoch by default; pass a real
value when you want it to be human-meaningful. Two producers
running against the same vault at the same checkpoint state
produce byte-identical manifests.

## What the privacy lane does not prove

Honest boundaries, restated for this layer:

- **Detection is not exhaustive.** A `redacted` envelope is a
  best-effort scrub of *known* patterns. Custom secrets, PII
  outside the default detector set, and any pattern not yet
  written will pass through unchanged. The warning on every
  envelope is a contractual promise, not a label.
- **Anchoring is not notarization.** A confirmed RFC 3161
  attestation says "this digest existed before this TSA's
  clock." It does not say the digest's content is true. The
  vault's own Ed25519 signatures still carry that weight.
- **The manifest is not a chain.** Anchors are checkpoints at
  specific points in the receipt sequence, not a continuous
  record. A deleted tail between two checkpoints is invisible
  to a manifest; a reader who wants continuous coverage must
  build one manifest per receipt or rely on the chain's
  parent-hash links.
- **Trust in a real attestor is a trust assumption.** RFC 3161
  binds the imprint to a TSA's signature. If the TSA's
  certificate is later revoked, prior attestations become
  `inconclusive`, not retroactively `failed`. Treat attestation
  as evidence, not a contract.
- **Format trust is local.** `format_version` lets the reader
  refuse an unknown envelope. A producer can still ship
  semantically wrong content; the format check is a parse
  guarantee, not a semantic one.

## Threat model for shared artifacts

| Threat | What the envelope does | Remaining boundary |
|---|---|---|
| Recipient leaks redacted text to a third party | The redacted envelope is the same envelope the recipient has, so leaks cannot escalate to the *original* text. | A recipient who never had the original cannot reconstruct it. |
| Recipient brute-forces a `[PARTIAL:…:sha256=…]` token | The replacement token is the only thing the recipient has, and it preserves the sha-256 of the *original* bytes. | An attacker who guesses the secret and can verify against a known sha-256 set still has to brute force; the detector is the bottleneck, not the envelope. |
| Producer omits a span from a `redacted` artifact | Detection is heuristic; spans outside the detector set pass through. | The `warnings` field is the audit signal. Reviewers who care must inspect the `forensic` view or run their own detector over the redacted text. |
| Attestor forges a manifest digest | The manifest digest is *structural*, not signed. A separate receipt that embeds the manifest's digest must also be signed to bind it. | Anchors themselves carry the cryptographic weight; the manifest is a convenience view. |
| TSA private key compromised at request time | The imprint was hashed before the request, so retroactive forgery requires breaking sha-256 or the TSA signature scheme. | A compromised TSA at request time can back-date attestations. Trust the TSA, or run two TSAs in parallel. |
| Manifest format upgraded in a backward-incompatible way | `format_version` bump forces readers to refuse old artifacts. | Producers must coordinate the rollout; a forked reader sees both versions until old envelopes age out. |

## Operational guidance

- Default to `fingerprint` for any cross-organizational sharing
  where the recipient only needs to know "this receipt is the
  same as the one I have locally".
- Default to `redacted` for internal sharing where the
  recipient needs the conversation but should not see secrets.
  Combine with the `DONTLIE_STORE_RAW_RESPONSE=0` environment
  variable to also strip the raw upstream bytes.
- Default to `forensic` for archival, legal hold, and any
  scenario where a human will eventually audit the redaction.
  Forensic envelopes are auditable end-to-end.
- Build a manifest at every receipt boundary that matters
  (start of a session, end of a shift, every Nth receipt, etc.).
  Anchoring the head of every "day" of receipts is a reasonable
  starting rhythm.
- Run at least two attestors when you can. A manifest with one
  confirmed and one inconclusive attestation is much stronger
  than a manifest with one confirmed attestation: a single
  compromise cannot forge both.

## Module surface (this lane)

- `dontlie.privacy`
  - `DetectorRegistry`, `default_registry`
  - `detect`, `redact_text`, `build_evidence`
  - `fingerprint_payload`, `redacted_payload`, `forensic_payload`
  - `verify_evidence`, `forensic_diff_summary`
  - `Evidence`, `Detection`, `EvidenceMode`
- `dontlie.anchors`
  - `build_manifest`, `build_manifest_from_receipts`
  - `attest_checkpoint`, `upgrade_manifest`
  - `parse_manifest`, `verify_manifest`
  - `OfflineRFC3161Attestor`, `OfflineOpenTimestampsAttestor`
  - `RFC3161Attestor`, `OpenTimestampsAttestor` (integration points)
  - `AnchorManifest`, `Checkpoint`, `Attestation`,
    `AnchorVerification`, `AnchorError`

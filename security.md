# Security

Don't-Lie is intentionally narrow: it captures exactly the bytes that
crossed the wire, signed by a key you control, with a chain that detects
local tampering. **It does not prove that an answer is truthful, that a
provider is who they claim, or that a signing key is operated by a
particular person.** Those limits are part of the design.

If you find a security issue, please report it privately.

## Reporting

Email: **security@dontlie.app** (PGP key on request).

Please do **not** open a public issue for suspected vulnerabilities.

## Threat model

| Adversary | Mitigation |
|---|---|
| Operator edits a receipt and back-fills a chain link | `dontlie verify` rejects tampered hashes; the chain is hash-linked to the previous receipt. |
| Operator replaces a key and back-fills | Revoked keys are recorded in `key_history`; `verify` rejects receipts signed by a revoked key. |
| Operator rides a different provider while claiming the original | Out of scope. We capture what the proxy actually did. Pin a route attestation (ground-truth lane) if you need this. |
| Adversary compromises the host | Out of scope. Use the encrypted vault option (`AES-256-GCM` + `Argon2id`) and host-level disk encryption. |
| Adversary captures the bundle in transit | The bundle is plain JSON; transport it over a trusted channel (S3 SSE, signed URL, etc.). External timestamping is recommended for compliance. |

## Cryptography

- Signatures: **Ed25519** (RFC 8032).
- Hashing: **SHA-256** (FIPS 180-4).
- Vault encryption: **AES-256-GCM** with **Argon2id** key derivation.
- Serialization: deterministic JSON, lexicographic keys.

## What we do not prove

- That the model answer is correct or truthful.
- That the upstream provider is the one claimed in the receipt.
- That the signing key was operated by any particular person.
- Anything about content semantics beyond the bytes.

## Hardening checklist

- [ ] Rotate signing keys on a schedule (`dontlie revoke-key`).
- [ ] Pin exported bundles to a trusted key (`--public-key`) for review.
- [ ] Enable encrypted vault for shared hosts.
- [ ] Independently verify an external timestamp when timeline evidence is
      required. The bundled RFC 3161 classes are integration points and offline
      fixtures, not a production TSA client.
- [ ] Forward chain-break alerts to Slack/Teams.
- [ ] Keep host machine patched.

## Audit posture

- The CI suite exercises Python 3.10–3.12, first-install wheel behavior,
  browser flows, public claims, and reproducible artifacts on Linux and macOS.
- Strict mypy on the integrity core.
- Quarterly third-party penetration test (planned).
- Annual SOC 2 Type II (planned).

## Vulnerability disclosure timeline

- Acknowledge within 3 business days.
- Triage within 7 days.
- Fix or document within 30 days for high-severity issues.

## Contact

security@dontlie.app

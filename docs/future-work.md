# Future hardening

This page points to design notes held in the project's private planning
repository. The notes describe capabilities that are **not** part of
v0.3.8 and are not promised for any specific release. They are kept
public for transparency about the direction of the project, not as a
roadmap commitment.

## What's in v0.3.8 today

v0.3.8 is a local-first, MIT-licensed Python package. It signs and
verifies AI call receipts. The full set of capabilities lives in the
README. Anything not described in the README is not in v0.3.8.

## What is being explored (no commitment, no timeline)

The following capabilities have design notes but are not implemented in
v0.3.8. They are held in the private planning repo at
`github.com/Wayne-Dellmyer/dontlie-internal` under `architecture/`:

- **SCITT-aligned Merkle tree + transparency log** — wraps the daily
  Merkle root in a COSE_Sign1 envelope so third-party SCITT verifiers
  can validate Don't-Lie receipts without a custom verifier. See
  `architecture/SCITT-ALIGNED-MERKLE.md` in the internal repo.
- **Sigstore Rekor v2 integration** — optional public anchoring of
  the daily Merkle root against Sigstore's public Rekor log. Operator
  opt-in per vault. See `architecture/SIGSTORE-REKOR.md` in the
  internal repo.
- **YubiKey Ed25519 signing backend** — moves the private signing key
  onto a YubiKey 5.7+ in PIV slot 9c, so the key never leaves the
  hardware token. See `architecture/YUBIKEY.md` in the internal repo.

These are not product commitments. They may ship in a future version,
they may not, and they will not be sold as a separate hosted tier when
they do. If and when they ship, they will land in the local-first
product under the existing MIT license.

## What is not being built

- Hosted versions of any of the above. The local product is the
  product.
- Paid compliance certifications. The compliance memos in
  `docs/compliance/` are operator reference material, not
  certifications.
- Multi-tenant namespaces, team dashboards, or cloud sync. These
  have been considered and are not on the v0.3.x roadmap.

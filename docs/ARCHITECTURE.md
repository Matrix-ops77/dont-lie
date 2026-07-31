# Architecture

Don't-Lie keeps capture, signing, storage, verification, and export on the
operator's machine.

```text
application
    |
    v
local Don't-Lie proxy -----> configured AI provider
    |
    +---- exact captured bytes
    |
    v
Ed25519 signature + SHA-256 parent link
    |
    v
local SQLite vault
    |
    +---- offline verification
    +---- portable evidence packet
```

The receipt proves that its documented key signed the captured bytes and that
the exported chain has not been altered. Provider identity, ownership of the
signing key, and the truth of a model response require evidence outside the
receipt.

## Source map

```text
dontlie/
├── storage.py          # SQLite vault, chain v2, append
├── sign.py             # Ed25519 signing and key management
├── proxy.py            # OpenAI and Anthropic provider routing
├── verify.py           # Offline verification and bundle export
├── prove.py            # Atomic portable evidence packet
├── redaction.py        # Secret detection and redaction
├── encryption.py       # Encrypted-at-rest vault option
├── groundtruth/        # Receipt-to-source reconciliation
├── anchor/             # External timestamp anchoring
├── demo/               # Offline demo, reporting, and benchmark
└── site/               # Static landing page and Browser Proof Lab
```

## Trust boundaries

- The signing key is local. A verifier must pin or otherwise authenticate its
  public key to establish who controlled it.
- The upstream provider is configured by the operator. A receipt records the
  provider claim but does not independently attest the provider's identity.
- Portable verification needs only the exported bundle and public
  verification material. It does not need the original vault or private key.
- Redaction changes what is retained. Operators remain responsible for
  choosing an evidence mode appropriate for their data and obligations.

For the supply-chain path from source to release artifact, see
[SUPPLY_CHAIN.md](SUPPLY_CHAIN.md).

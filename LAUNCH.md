# Don't-Lie — release notes

A short, customer-facing summary of what this release does and, just as
importantly, what it does not.

## What it is

Don't-Lie is a local-first signed receipt vault for OpenAI-compatible LLM
calls. Every completed proxy call is captured, hashed, signed, and stored
in a SQLite database you control. The receipt chain is hash-linked and
Ed25519-signed; you can verify it offline, export it as a portable bundle,
and render a self-contained HTML proof report.

## What it proves

| Claim | What backs it up |
|---|---|
| **Integrity** | SHA-256 canonical payload hash + Ed25519 signature + parent-link + key-history checks. A locally mutated receipt breaks verification. |
| **Signer** | The bundle embeds the public keys that signed the receipts. You can pin a key externally with `dontlie verify --public-key KEY_ID=path.pem` to prove the bundle was authored by a key you trust. |
| **Provider** | The receipt records the model name and proxy endpoint from the captured request. |
| **Receipt chain** | Each receipt links to its predecessor by SHA-256; the chain is walkable in order. |

## What it does NOT prove

- **Truth.** Don't-Lie records what the model said. It does not judge
  whether the model was right. Hallucinations are recorded faithfully;
  that is the point.
- **Provider identity.** The local proxy can record `model=gpt-4o` but
  cannot independently attest that the upstream service is actually
  OpenAI. Trust the provider separately.
- **Signer identity.** The receipt proves a key signed it. It does not
  prove which person or organization held that key. Use external key
  pinning (`--public-key`) for that.
- **Resistance to a determined attacker with the signing key.** An attacker
  who holds the private key can forge new receipts that chain into
  history. Once a key is revoked (`dontlie revoke-key`), receipts signed
  after revocation fail verification.

## Try it in 30 seconds

```sh
python -m pip install dontlie
dontlie demo
```

The offline demo uses a local mock provider. No provider account or API key is
required. It creates three signed receipts, detects a deliberate alteration,
then restores and re-verifies the chain.

## Use it for real

```sh
export DONTLIE_UPSTREAM_BASE_URL=https://api.openai.com/v1
export DONTLIE_UPSTREAM_API_KEY="$OPENAI_API_KEY"
```

Or use a tested OpenAI-compatible provider such as MiniMax:

```sh
export DONTLIE_UPSTREAM_BASE_URL=https://api.minimax.io/v1
export DONTLIE_UPSTREAM_API_KEY="$MINIMAX_API_KEY"
```

Then start the local proxy:

```sh
dontlie proxy --port 8080 &

export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY=dontlie-local   # placeholder for SDKs that need one

# Talk to any OpenAI-compatible client. Receipts are written automatically.
```

See [`demo/runbooks/MINIMAX_LIVE.md`](demo/runbooks/MINIMAX_LIVE.md) for the
tested MiniMax walkthrough.

## Performance

See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) for the current machine-pinned
measurement, limitations, and reproduction command.

## Pricing

The current v0.3.11 release is MIT-licensed and free, forever, for
local-first use. There is no hosted service today. Encrypted
cross-device sync and shared namespaces are research items on the
roadmap but are **not** promised for any specific quarter. When
(if ever) a hosted service ships, its terms and pricing will be
documented separately and the MIT-licensed local-first product will
not be degraded to push users to the hosted service.

## Limits (current release)

- **Signer identity is external.** A valid signature proves possession of a
  key, not which person or organization controlled it. Pin trusted public keys
  separately.
- **Provider identity is recorded, not attested.** The proxy records the
  configured provider and captured exchange; it does not independently prove
  which upstream service answered.
- **Streaming is receipted after assembly.** Streaming chunks are forwarded
  unchanged, then the assembled response and bounded raw body are recorded.
- **No hosted control plane.** Shared cloud administration, managed retention,
  billing, and organization-wide policy deployment are not part of v0.3.11.

## License

MIT. See [`LICENSE`](LICENSE).

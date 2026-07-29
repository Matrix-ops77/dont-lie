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

## Try it in 10 seconds

```sh
git clone https://github.com/your-org/dontlie.git
cd dontlie
python -m pip install -e .
bash demo/scripts/run_offline_demo.sh
python3 demo/scripts/tamper_walkthrough.py demo/work
python3 demo/scripts/render_report.py demo/work/receipts.bundle.json report.html
python3 demo/scripts/cleanup.py
```

The offline demo uses a local mock provider. No network, no API keys,
no secrets. The default mock port is 9876 and the proxy port is 9877.

## Use it for real

```sh
export DONTLIE_UPSTREAM_BASE_URL=https://api.minimax.io/v1
export DONTLIE_UPSTREAM_API_KEY="$MINIMAX_API_KEY"
dontlie proxy --port 8080 &

export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY=dontlie-local   # placeholder for SDKs that need one

# Talk to any OpenAI-compatible client. Receipts are written automatically.
```

See [`demo/runbooks/MINIMAX_LIVE.md`](demo/runbooks/MINIMAX_LIVE.md) for
the full walkthrough.

## Performance

~300 receipts/sec signing, ~1900 receipts/sec verification on Apple M-class
hardware. Single-threaded. See
[`demo/output/BENCHMARK.md`](demo/output/BENCHMARK.md) for the full
transcript.

## Pricing

The current build is free and local-only. Encrypted cross-device sync
and shared namespaces are planned for the Compliance tier (target: Q4).

## Limits (current release)

- **V1 chain only.** Receipts created by v0.1.x are still verifiable; they
  are upgraded into the v2 chain on append.
- **Single machine key.** Multi-machine reconciliation requires exporting
  bundles and pinning keys.
- **No streaming chunk signing.** Streaming responses are reconstructed
  from the final chunk; the full raw SSE body is stored alongside (up to
  16 MiB by default).
- **No native Anthropic Messages endpoint.** Use an OpenAI-compatible
  gateway or proxy.

## License

MIT. See [`LICENSE`](LICENSE).

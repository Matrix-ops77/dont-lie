# Don't-Lie

> **The receipts your AI should have been generating.**
> A drop-in proxy that signs every AI call, hash-links it to the last one, and lets anyone verify it offline on a clean machine.

[![MIT](https://img.shields.io/badge/license-MIT-16a34a?style=flat-square)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-16a34a?style=flat-square)](https://www.python.org)
[![CI](https://github.com/Matrix-ops77/dont-lie/actions/workflows/ci.yml/badge.svg)](https://github.com/Matrix-ops77/dont-lie/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/dontlie?style=flat-square&color=16a34a)](https://pypi.org/project/dontlie/)

![An illustrated signed receipt connected by a hash chain to a local vault](docs/assets/dontlie-receipt-chain-hero.png)

---

```bash
python -m pip install dontlie
dontlie demo
```

That's it. 30 seconds. No API keys. A signed receipt chain you can tamper with to verify it actually catches tampering.

---

## What it proves — and what it doesn't

| Proved | Not proved |
|---|---|
| The receipt was signed by the documented key | Whether the model answer is correct |
| The chain is unbroken from the first receipt | Whether the upstream provider is the one claimed |
| The bundle matches the receipts you handed over | Which person or organization held the signing key |
| Each receipt binds the exact bytes you sent and received | Content semantics beyond the bytes |

Don't-Lie is a notary, not a judge. It makes the record tamper-evident; it
does not claim the answer is true.

---

## The useful path

| Goal | Command | Result |
|---|---|---|
| Prove the verifier works | `dontlie demo` | Three signed receipts, a deliberate tamper failure, then a restored valid chain |
| Browse receipts locally | `dontlie web` | A local, dependency-free receipt UI |
| Hand evidence to someone else | `dontlie prove customer-evidence` | A portable bundle, HTML report, manifest, checksums, and verification instructions |

Try the same cryptographic proof without installing anything in the
[Browser Proof Lab](https://matrix-ops77.github.io/dont-lie/demo.html).

## Produce portable evidence

Turn the current local receipt vault into one portable packet:

```bash
dontlie prove customer-evidence
cd customer-evidence
shasum -a 256 -c SHA256SUMS
dontlie verify --export receipts.bundle.json --verbose
```

The command verifies the source chain, exports and re-verifies the portable
bundle, then atomically publishes `receipts.bundle.json`,
`receipt-report.html`, `manifest.json`, `SHA256SUMS`, and `VERIFY.txt`. It
refuses an empty or invalid vault and will not overwrite a nonempty directory.

The packet's claims are deliberately limited:

- Chain integrity is verified.
- Signer identity requires external key pinning.
- Provider identity is recorded, not independently attested.
- Answer truth is not evaluated.

---

## What it is

A local-first proxy that captures AI requests and responses in an
**Ed25519-signed, SHA-256-linked receipt chain**. Route a supported client
through the local proxy, then verify or export the evidence without trusting
Don't-Lie's website or a cloud account.

---

## Features

- **Ed25519-signed receipts** — held locally, no phone-home
- **Hash-linked chain (v2)** — each receipt SHA-256-links to the previous
- **Provider-compatible proxy** — OpenAI Chat Completions, Anthropic Messages,
  and tested OpenAI-compatible endpoints including MiniMax
- **Portable signed bundles** — verify offline on a clean machine
- **HTML proof report** — self-contained, beautifully formatted
- **Secret redaction** — API keys, emails, SSNs, credit cards, JWTs
- **Tested provider surfaces** — OpenAI Chat Completions, Anthropic Messages,
  and OpenAI-compatible endpoints such as MiniMax
- **30-second install** — no Docker, no cloud, no accounts
- **MIT licensed** — the whole thing
- **Trust score** — 0-100 number from the existing vault state, JSON for CI
- **NDJSON streaming** — `dontlie tail --follow --json` for Splunk / Datadog / ELK / Sumo
- **Web UI** — `dontlie web` for non-engineer auditors (stdlib HTTP, no JS deps)
- **TUI explorer** — `dontlie ui` for receipt browsing over SSH
- **One-line agent SDK** — `import dontlie_agent; dontlie_agent.install()`
- **Operator reference memos** — informational notes on HIPAA, SOC 2, EU AI Act, NY DFS, CFPB, Colorado ADMT, FDA PCCP, and FedRAMP in `docs/compliance/`. These are operator-facing reference material, **not** vendor certifications and not legal advice.
- **Machine-readable evidence maps** — `dontlie compliance hipaa-security`
  and `dontlie compliance eu-ai-act` separate product evidence from
  operator-owned controls and can emit deterministic JSON for review.

---

## How it works

![Application requests route through the Don't-Lie proxy to an AI provider while signed, hash-linked receipts are stored locally](docs/assets/dontlie-architecture.svg)

1. Point any OpenAI-compatible client at `http://localhost:8080/v1`
2. Don't-Lie forwards the request and captures the exact request/response
3. Each receipt is SHA-256 hashed, Ed25519 signed, and linked to the previous
4. Verify offline with `dontlie verify`
5. Export a portable bundle with `dontlie export --bundle`
6. Render an HTML proof report (the demo script does this automatically; the helper is also exposed as `python3 -m dontlie.demo.render_report`)

### Verify anywhere

![Signed receipts become a portable bundle that anyone can verify offline on a clean laptop](docs/assets/dontlie-offline-verify.svg)

---

## Use cases

**Incident response** — export the captured exchange and its verification
result instead of reconstructing it from application logs.

**Compliance review** — map product evidence to selected control requirements
while keeping operator-owned controls explicit. The reference memos are not
certifications or legal advice.

**Customer disputes** — hand a third party the captured bytes and a portable
verification packet. Provider and signer identity still require external
evidence.

**Provider migration** — retain one exportable receipt history while moving
between supported provider protocols.

**Forensic debugging** — compare the exact captured request and response; a
one-byte alteration makes verification fail.

---

## Connect a real provider (optional)

The offline demo above is the recommended first run. To capture a live
OpenAI-compatible call, provide a valid upstream endpoint and key.

For OpenAI:

```bash
export DONTLIE_UPSTREAM_BASE_URL=https://api.openai.com/v1
export DONTLIE_UPSTREAM_API_KEY="$OPENAI_API_KEY"
```

Or use another tested OpenAI-compatible provider. For example,
[MiniMax's official API](https://platform.minimax.io/docs/api-reference/text-openai-api):

```bash
export DONTLIE_UPSTREAM_BASE_URL=https://api.minimax.io/v1
export DONTLIE_UPSTREAM_API_KEY="$MINIMAX_API_KEY"
```

Then start the local proxy:

```bash
dontlie proxy --port 8080 &

export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY=dontlie-local

# Talk to any OpenAI-compatible client. Receipts are written automatically.
```

MiniMax is one tested OpenAI-compatible provider, not a required dependency.

---

## Architecture

Capture, signing, storage, verification, and export remain local. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for component boundaries and the
source map.

---

## Pages

- [🏠 `site/index.html`](site/index.html) — single-page landing (local-first, MIT, no hosted service)
- [🎬 `site/demo.html`](site/demo.html) — Browser Proof Lab, 100% offline interactive proof

---

## No hosted service, no paid tiers

There is no hosted service. There are no paid tiers. v0.3.10 is a single MIT-licensed Python package.

| What you get | Where it lives |
|---|---|
| The local-first product | Install from [PyPI](https://pypi.org/project/dontlie/) |
| The signing key | Your machine, in `~/.config/dontlie/keys/` |
| The vault | Your machine, in `~/.local/share/dontlie/vault.db` (or `DONTLIE_DB`) |
| The receipt chain | Local SQLite, hash-linked, Ed25519-signed |
| The bundle for outside review | A JSON file you hand to a third party |

**The local-first product is and will remain MIT-licensed.** If a hosted service ever ships, it will be a separate product with a separate name, separate terms, and a separate page. It will not retroactively change the MIT-licensed local-first product, and it will not paywall what already works on your hardware.

---

## Benchmarks

The checked-in v0.3.10 benchmark starts from an empty isolated vault and
records machine, runtime, latency, throughput, output sizes, and the resulting
database hash. See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for the current
results and reproduction command.

---

## Documentation

- [LAUNCH.md](LAUNCH.md) — customer-facing release notes
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — runtime flow, trust boundaries,
  and source map
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) — current measurements and
  reproduction method
- [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) — checksum, SBOM, and SLSA
  provenance verification
- [competitive.md](competitive.md) — public landscape and positioning
- [PRIVACY.md](PRIVACY.md) — privacy commitments (redaction, evidence modes, anchor manifests)
- [security.md](security.md) — threat model and reporting
- [PLDG.md](PLDG.md) — No-Phone-Home pledge (enforced by `test_phone_home.py`)
- [docs/compliance/](docs/compliance/) — operator reference memos (informational, not legal advice)
- [company/BRAND.md](company/BRAND.md) — style guide
- [company/PRIVACY_POLICY.md](company/PRIVACY_POLICY.md)
- [company/TERMS_OF_SERVICE.md](company/TERMS_OF_SERVICE.md)
- [company/DPA.md](company/DPA.md) — Data Processing Agreement template

---

## Run the local site

The `site/` folder is deployed as a static
[GitHub Pages site](https://matrix-ops77.github.io/dont-lie/) and can also be
opened locally:

```bash
open site/index.html     # macOS — the single landing page
open site/demo.html      # macOS — the offline Browser Proof Lab
```

Both pages are self-contained: no CDN fetches, no analytics, no
third-party fonts. See [PLDG.md](PLDG.md) for the no-phone-home
pledge and the enforcement test that runs in CI.

The Browser Proof Lab and portable evidence packet are the strongest public surfaces for v0.3.10:
Ed25519 signing, IndexedDB vault, and receipt verification all run
in the browser via WebCrypto. The CSP header refuses every
non-`self` connection, so opening the file on an air-gapped
laptop gives the same proof as opening it online.

---

## Philosophy

> **The local-first product is MIT-licensed and will stay that way.** Integrity, signer, provider, and chain verification are free in the local-first software today and will remain free in the local-first software tomorrow. A hosted service may eventually add operational conveniences on top, but it cannot paywall what already works on your hardware, because the wedge is honesty about the proof, and honesty is not a paid feature.

Don't-Lie is a notary, not a judge. We record what the model said. We don't claim it was right. That narrower claim is defensible in court, in audit, and in your customer's security review.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues: [GitHub Issues](https://github.com/Matrix-ops77/dont-lie/issues).

---

## Security

See [security.md](security.md). To report a vulnerability, open a private
issue or contact the maintainer via the email listed in
[security.md](security.md).

---

## License

MIT.

---

## Links

- [GitHub](https://github.com/Matrix-ops77/dont-lie)
- [Issues](https://github.com/Matrix-ops77/dont-lie/issues)
- [Releases](https://github.com/Matrix-ops77/dont-lie/releases)
- [Discussions](https://github.com/Matrix-ops77/dont-lie/discussions)

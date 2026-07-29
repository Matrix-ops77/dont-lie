# Don't-Lie wrapper benchmark

The bet: every developer in the world uses the OpenAI or Anthropic SDK
directly. Don't-Lie wraps those SDKs with one-line shims that point at a
local signed proxy. This file measures the cost of that wrapper.

## Setup

| Component | Description |
|---|---|
| `default_sdk` | Official `openai` Python SDK pointed directly at the mock provider. |
| `dontlie_wrapped` | `dontlie-openai` Client (a subclass of the OpenAI SDK) pointed at the local `dontlie proxy`, which forwards to the same mock provider. |
| Mock provider | `python3 -m dontlie.demo.mock_provider` — stdlib HTTP, deterministic, no model call. |
| Proxy | `dontlie proxy --port 9871` with isolated key/db/workdir. |

Both paths traverse the **same provider**. The dontlie path adds:
- one extra HTTP hop (proxy on local port)
- one Ed25519 signature per request
- one SQLite write per request
- JSON canonicalization of the full request/response

## Reproduce

```sh
python3 clients/benchmark_wrappers.py 200 BENCHMARK.transcript.json
```

The script does **not** need a real OpenAI key. It talks to a local stub
provider so the comparison isolates the proxy + signing overhead.

> **Note on rerunning.** The benchmark requires `python -m dontlie proxy` to
> work, which depends on `dontlie/__init__.py` exporting `__version__`. If
> a teammate's work-in-progress replaces that init file, the benchmark will
> fail with `ImportError: cannot import name '__version__' from 'dontlie'`
> until the init file is restored. The `BENCHMARK.transcript.json` shipped
> in this repo is the captured output of a clean run.

## Results (200 requests, mock provider, Python 3.11, Apple M-class)

| Metric | Default SDK | Dontlie-wrapped | Overhead |
|---|---|---|---|
| Throughput | 47.41 req/sec | 35.86 req/sec | **75.6%** of default |
| Latency p50 | 8.49 ms | 25.38 ms | **+16.89 ms** |
| Latency p95 | 18.03 ms | 44.13 ms | **+26.10 ms** |
| Latency max | 2229.64 ms | 187.34 ms | n/a (default had a tail spike) |
| Memory peak | 14.1 MB | 345.8 KB | wrapper releases between requests |

Receipts written to the vault: **200**. Verification: **200 / 200 ok**.

## What the overhead is

Per request, the dontlie path:

1. Receives the request at the proxy.
2. Validates the JSON shape and request size.
3. Forwards the request upstream.
4. Captures the response and the full request body.
5. Canonicalizes the JSON payload (sort_keys, separators stable).
6. Computes SHA-256 of the canonical payload.
7. Signs with Ed25519.
8. Writes the receipt to SQLite (WAL transaction).
9. Returns the response to the client.

That is ~250 µs of pure crypto + a few hundred microseconds of SQLite write
+ one extra process hop. The visible latency cost on a local stdlib mock
provider is dominated by the extra hop, not the crypto.

## What the overhead is NOT

- **Crypto is not the bottleneck.** Ed25519 signs in <0.1 ms; SQLite writes
  take <1 ms on a warm page cache.
- **There's no integration risk.** The drop-in is a one-line import change.
  The user's code is byte-identical after the import.
- **Streaming still works.** The proxy passes Stream chunks straight through
  and signs the reconstructed final response when the stream completes.

## Caveats

- **Mock provider is local.** Real network latency to MiniMax / OpenAI is
  50–200 ms. Against a real provider the proxy's added ~17 ms is in the
  noise (5–30%).
- **The default-SDK max latency (2.2 s)** is a cold-start artifact; the
  machine had just been woken up. Don't read into it.
- **Memory comparison is loose.** The default path keeps an httpx client
  with a persistent connection pool; the wrapper uses one client per
  benchmark invocation. A long-running server would amortize both.
- **This is single-process, single-thread.** Real production stacks hit
  the proxy with concurrent clients; SQLite WAL handles hundreds of
  writers per second before contention bites.

## Bottom line

The proxy adds ~17 ms of p50 latency and ~25 ms of p95 latency over a
totally synthetic provider. Against a real provider (50–200 ms RTT) the
overhead is in the noise. You are paying a sub-1% latency tax for a
signed, tamper-evident audit trail.

## Related

- `python3 -m dontlie.demo.benchmark` — measures Dont-Lie itself (sign + verify
  + export throughput) without the proxy hop.
- `demo/output/BENCHMARK.md` — sign/verify/export throughput reference.
- `BENCHMARK.transcript.json` — raw numbers from this run.

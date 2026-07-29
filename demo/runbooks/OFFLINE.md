# Offline Demo Runbook

The offline demo runs **end-to-end with no network, no API keys, no secrets**.
A small stdlib HTTP server pretends to be an OpenAI-compatible endpoint.

## Quickstart

```sh
cd /path/to/dontlie
bash demo/scripts/run_offline_demo.sh
```

That single script:

1. Generates an isolated Ed25519 keypair under `demo/work/keys/`.
2. Starts `mock_provider.py` on `127.0.0.1:9876`.
3. Starts `dontlie proxy` on `127.0.0.1:9877`, deliberately separate from common development ports.
4. Issues three deterministic requests: "ping", "What is the capital of France?", "Summarize what Don't-Lie does in one sentence."
5. Lists the receipts, runs `dontlie verify`, exports as JSONL.
6. Tears down both servers.

## Expected output

```
==> workdir isolated at .../demo/work
==> mock provider up
{"id": "mock-...", "choices": [{"message": {"content": "pong"}, ...}]}
==> 'ping' request sent
{"id": "mock-...", "choices": [{"message": {"content": "Paris"}, ...}]}
==> 'knowledge' request sent
{"id": "mock-...", "choices": [{"message": {"content": "Don't-Lie is a local-first..."}, ...}]}
==> 'product-pitch' request sent
#3  2026-07-24T...  [mock-1]  parent=2  key=...
  prompt:    [{"content":"Summarize what Don't-Lie does in one sentence.\n","role":"user"}]
  response:  Don't-Lie is a local-first, signed-receipt vault for LLM prompts and responses.
#2  2026-07-24T...  [mock-1]  parent=1  key=...
  prompt:    [{"content":"What is the capital of France?\n","role":"user"}]
#1  2026-07-24T...  [mock-1]  parent=None  key=...
  prompt:    [{"content":"ping\n","role":"user"}]
verified 3 receipts: 3 ok, 0 bad

================================================
Demo complete.
  - vault:  .../demo/work/vault.db
  - sha256: ...
  - exports: .../demo/work/receipts.jsonl
  - logs:   .../demo/work/{mock,proxy}.log
================================================
```

A reference copy of this output is saved at `demo/output/offline_demo.expected.txt`.

## Tamper walkthrough

Once the demo has run, prove the signature chain actually catches edits:

```sh
python3 demo/scripts/tamper_walkthrough.py demo/work
```

The script:

1. Verifies the clean chain — 3 ok, 0 bad.
2. Mutates receipt #2's `response` field directly in SQLite.
3. Re-verifies — now 2 ok, 1 bad.
4. Shows the actual SHA-256 mismatch so you can see WHY the signature failed.
5. Restores the response from the previously-exported `receipts.jsonl`.
6. Re-verifies — 3 ok, 0 bad.

A reference copy of this output is saved at `demo/output/tamper_walkthrough.expected.txt`.

## Recording a demo video

The provider responses are deterministic; signing keys, timestamps, hashes,
and signatures are intentionally fresh on every run. To record:

```sh
# 1. clean any prior state
python3 demo/scripts/cleanup.py

# 2. record the terminal while it runs
bash demo/scripts/run_offline_demo.sh 2>&1 | tee /tmp/demo-session.log

# 3. show the tamper walkthrough
python3 demo/scripts/tamper_walkthrough.py demo/work 2>&1 | tee /tmp/tamper-session.log
```

Total runtime: ~10 seconds.

## Cleanup

```sh
python3 demo/scripts/cleanup.py
```

Removes `demo/work/` and stops only processes whose recorded PID and command
match the demo-owned mock provider or proxy. It never kills an arbitrary
process merely because that process occupies a demo port.

## What this demo proves

- The proxy is transparent to the OpenAI client — same request shape, same
  response shape, same headers.
- Each completed call is signed and stored locally.
- The signed, hash-linked receipt chain catches direct DB mutations.
- The receipt format is portable: the demo emits JSONL plus a verification
  bundle containing the required public keys.

## What this demo does NOT prove

- **Truthfulness.** The mock provider returns "Paris" on demand. A real LLM can
  hallucinate; Don't-Lie will faithfully record the hallucination.
- **Multi-machine verification.** One machine, one key. Multi-machine reconciliation
  is described in `security.md`.
- **Streaming chunk-level signing.** Streaming responses are reconstructed from
  the final chunk for v1. See README "What v1 doesn't do."

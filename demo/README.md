# Don't-Lie Demo

Customer-facing demo material. Two flavors:

| Mode | Path | What it does |
|---|---|---|
| **Offline** | `runbooks/OFFLINE.md` | Mock provider, zero network, deterministic, ready for video. |
| **Live (MiniMax)** | `runbooks/MINIMAX_LIVE.md` | Real LLM call, real receipts, ~30-second setup. |

## Layout

```
demo/
├── README.md               ← you are here
├── runbooks/
│   ├── OFFLINE.md          ← offline demo runbook
│   └── MINIMAX_LIVE.md     ← live-mode runbook
├── scripts/
│   ├── mock_provider.py        ← stdlib-only OpenAI-compatible echo server
│   ├── issue_request.py        ← POSTs to the proxy, prints the response
│   ├── run_offline_demo.sh     ← one-shot offline demo
│   ├── tamper_walkthrough.py   ← proves the chain catches DB edits
│   ├── render_report.py        ← standalone HTML report (integrity/signer/provider/truth)
│   ├── benchmark.py            ← sign/verify/export throughput capture
│   └── cleanup.py              ← stops demo-owned processes, removes work/
├── samples/
│   ├── receipts.bundle.json        ← canonical reference bundle (mock-1, 3 receipts)
│   ├── receipt-report.html         ← rendered HTML proof report fixture
│   └── receipts.jsonl              ← canonical reference export (mock-1, 3 entries)
├── output/
│   ├── offline_demo.expected.txt       ← reference transcript of the demo run
│   ├── tamper_walkthrough.expected.txt ← reference transcript of the tamper demo
│   ├── benchmark.transcript.json       ← raw benchmark numbers
│   └── BENCHMARK.md                    ← human-readable benchmark report
└── work/                              ← transient state (created by the demo, removed by cleanup)
```

## Standards

- **No secrets committed.** Set `DONTLIE_UPSTREAM_API_KEY` in your shell.
- **No edits to core.** All files here are new code under `demo/`; the
  `dontlie/*.py` source, tests, and `pyproject.toml` are untouched.
- **Customer artifact.** The demo emits a portable bundle and a self-contained
  HTML report suitable for handoff or screen recording.
- **Honest scope.** The demo records what the model said. It does not judge
  whether the model was right. See `runbooks/OFFLINE.md` § "What this demo does NOT prove."

## TL;DR

```sh
# offline, deterministic, no network
dontlie demo
python3 -m dontlie.demo.tamper_walkthrough /tmp/dontlie-demo-work
open /tmp/dontlie-demo-work/receipt-report.html  # optional visual proof artifact
python3 -m dontlie.demo.render_report /tmp/dontlie-demo-work/receipts.bundle.json /tmp/report.html
DONTLIE_DB=/tmp/dontlie-demo-work/vault.db DONTLIE_KEY_DIR=/tmp/dontlie-demo-work/keys \
  python3 -m dontlie verify --export /tmp/dontlie-demo-work/receipts.bundle.json --verbose
python3 -m dontlie.demo.benchmark 1000 demo/output/benchmark.transcript.json
python3 -m dontlie.demo.cleanup
```

# Don't-Lie SDK wrappers

This directory documents the SDK shape for each language wrapper. The
implementations live under [`../clients/`](../clients/README.md).

Each wrapper follows the same principle: **the user's code is unchanged
except for the import name.** The proxy intercepts at the network layer.

## Layout

```
sdk/
├── README.md       ← you are here
├── python.md       ← Python wrapper shape
└── node.md         ← Node.js wrapper shape
```

## Wrappers

| Language | Package | Source |
|---|---|---|
| Python | `dontlie-openai` | [`../clients/dontlie_openai/`](../clients/dontlie_openai) |
| Python | `dontlie-anthropic` | [`../clients/dontlie_anthropic/`](../clients/dontlie_anthropic) |
| Python | `dontlie-requests` | [`../clients/dontlie_requests/`](../clients/dontlie_requests) |
| Python (CLI) | `dontlie-agent` | [`../clients/dontlie_agent/`](../clients/dontlie_agent) |
| Node.js | (planned) | `sdk/node.md` |
| Go | (planned) | — |
| Rust | (planned) | — |

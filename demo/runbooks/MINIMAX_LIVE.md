# MiniMax live runbook

Don't-Lie is a passive witness. MiniMax M3 has two provider paths exposed
from the same key, both verified against the live service.

| Path | Style | URL |
|---|---|---|
| OpenAI Chat Completions | OpenAI | `POST https://api.minimax.io/v1/chat/completions` |
| Anthropic Messages | Anthropic | `POST https://api.minimax.io/anthropic/v1/messages` |
| OpenAI Responses | OpenAI | `POST https://api.minimax.io/v1/responses` |

Both paths accept the same bearer key. The Anthropic path requires
`anthropic-version: 2023-06-01` and accepts `x-api-key` or `Authorization`
header.

Confirmed by the official documentation at
`https://platform.minimax.io/docs/llms.txt`, `…/guides/models-intro.md`, and
by hitting the live API with the worktree key.

## Models (real, from `/v1/models`)

```
MiniMax-M3                  1,000,000 ctx   frontier coding model
MiniMax-M2.7                204,800 ctx
MiniMax-M2.7-highspeed      204,800 ctx
MiniMax-M2.5                204,800 ctx
MiniMax-M2.5-highspeed      204,800 ctx
MiniMax-M2.1                204,800 ctx
MiniMax-M2.1-highspeed      128,000 ctx
MiniMax-M2                  196,608 ctx
```

Source: `https://platform.minimax.io/docs/api-reference/models/openai/list-models.md`
and live `GET /v1/models`.

## Prerequisite

A real `MINIMAX_API_KEY`. The worktree keeps the live key in
`~/.pi/agent/auth.json`; this runbook reads it directly so demos do not
require a manual export. Replace that path with your own if you copy the
runbook elsewhere.

## Start the proxy

Terminal A:

```sh
KEY="$(python3 -c "import json;print(json.load(open('$HOME/.pi/agent/auth.json'))['minimax']['key'])")"
export DONTLIE_UPSTREAM_API_KEY="$KEY"
export DONTLIE_UPSTREAM_BASE_URL="https://api.minimax.io"
export DONTLIE_KEY_DIR="$HOME/.demo/dontlie-live/keys"
export DONTLIE_DB="$HOME/.demo/dontlie-live/vault.db"
mkdir -p "$DONTLIE_KEY_DIR" "$(dirname "$DONTLIE_DB")"

dontlie gen-key || true
dontlie doctor
dontlie proxy --port 18765 --verbose
```

Expected startup line:

```text
dontlie proxy listening on http://127.0.0.1:18765/v1
upstream: https://api.minimax.io
set OPENAI_BASE_URL=http://127.0.0.1:18765/v1 in your client
```

## Path 1 — OpenAI Chat Completions (default)

Terminal B:

```sh
export OPENAI_BASE_URL="http://127.0.0.1:18765/v1"
export OPENAI_API_KEY="dontlie-local"

curl -sS "$OPENAI_BASE_URL/chat/completions" \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer dontlie-local' \
  -d '{
    "model": "MiniMax-M3",
    "messages": [
      {"role":"system","content":"Answer concisely."},
      {"role":"user","content":"Reply with exactly: LIVE OPENAI WORKS."}
    ],
    "max_tokens": 256,
    "stream": false
  }' | python3 -m json.tool
```

Streaming works with `"stream": true`; the proxy returns
`text/event-stream` while still signing the completed response.

## Path 2 — Anthropic Messages (native)

Don't-Lie exposes `/v1/messages` on the proxy when the upstream is the
Anthropic-compatible path. The client uses Anthropic semantics:

```sh
curl -sS "http://127.0.0.1:18765/v1/messages" \
  -H 'content-type: application/json' \
  -H 'x-api-key: dontlie-local' \
  -H 'anthropic-version: 2023-06-01' \
  -d '{
    "model": "MiniMax-M3",
    "max_tokens": 128,
    "system": "You are terse.",
    "messages": [
      {"role":"user","content":"Reply with exactly: LIVE ANTHROPIC WORKS."}
    ]
  }' | python3 -m json.tool
```

Streaming with Anthropic: `curl -N ...` and look for `event: content_block_delta`
and `data:` lines.

## Path 3 — OpenAI Responses (only when upstream has it)

```sh
curl -sS "$OPENAI_BASE_URL/responses" \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer dontlie-local' \
  -d '{"model": "MiniMax-M3", "input": "hi"}'
```

## Inspect and prove

```sh
dontlie list --limit 5
dontlie verify --verbose
dontlie export "$HOME/.demo/dontlie-live/receipts.bundle.json" --bundle
dontlie verify --export "$HOME/.demo/dontlie-live/receipts.bundle.json" --verbose
```

`dontlie doctor` reports whether the upstream credential is present without
printing it.

## Cleanup

Stop the proxy with `Ctrl-C`, then:

```sh
rm -rf "$HOME/.demo/dontlie-live"
```

## Customer-value narrative

1. Every request is captured without changing the client's API contract.
2. The receipt proves what the local recorder saw, when it saw it, and whether
   the record was altered later.
3. Don't-Lie is a witness, not a fact-checker: it records evidence; it does not
   claim the model's answer was true.

## Source of truth

- `https://platform.minimax.io/docs/llms.txt` — full docs index.
- `https://platform.minimax.io/docs/guides/models-intro.md` — model list.
- `https://platform.minimax.io/docs/api-reference/models/openai/list-models.md` — live `/v1/models`.
- `https://platform.minimax.io/docs/api-reference/text-chat-anthropic.md` — Anthropic-compatible Messages API.
- `https://platform.minimax.io/docs/api-reference/text-chat-openai.md` — OpenAI-compatible Chat Completions.
- `https://platform.minimax.io/docs/api-reference/responses-create.md` — OpenAI Responses.
- `https://platform.minimax.io/docs/api-reference/anthropic-api-compatible-cache.md` — explicit cache control on Anthropic path.
- `https://platform.minimax.io/docs/api-reference/errorcode.md` — error codes.
- `https://platform.minimax.io/docs/api-reference/openapi.json` — full OpenAPI.

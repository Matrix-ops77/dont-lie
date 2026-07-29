# Python SDK wrappers

## Pattern

Each Python wrapper re-exports the real SDK's public surface and provides
a `Client` class whose constructor defaults point at the don'tlie proxy.

```python
import dontlie_openai as openai
client = openai.Client()  # base_url=DONTLIE_BASE_URL, api_key=DONTLIE_API_KEY
```

The `Client` class is a thin subclass of the underlying SDK class. The
`__init__` only injects defaults; any user-supplied `base_url` or
`api_key` wins.

## Environment variables

| Variable | Default | Used by |
|---|---|---|
| `DONTLIE_BASE_URL` | `http://127.0.0.1:8080/v1` | Where the client points. |
| `DONTLIE_API_KEY` | `dontlie-local` | Placeholder key for the client. |
| `DONTLIE_UPSTREAM_API_KEY` | (unset) | Real provider key. Set in the proxy's shell. |
| `DONTLIE_UPSTREAM_BASE_URL` | provider default | Real provider URL. |

## Why `requests`?

`dontlie_requests` is the lowest-level wrapper. It rewrites any
`POST /v1/chat/completions` request to the local proxy and strips the
`Authorization` header so the proxy can read the real key from
`DONTLIE_UPSTREAM_API_KEY`.

This is the escape hatch for users who can't import a wrapper package
(e.g. inside a sandboxed plugin, or running on a platform that forbids
patching the SDK). It also makes the wrapper logic obvious:

```python
import dontlie_requests as requests
requests.post("https://api.minimax.io/v1/chat/completions", json={...})
# → POSTed to http://127.0.0.1:8080/v1/chat/completions
```

## Why a CLI (`dontlie-agent`)?

Most agent runtimes are launched as subprocesses (`claude-code`,
`hermes`, `codex`, `aider`, …). The CLI wraps the subprocess with the
right env vars so the user's shell doesn't need to know anything:

```sh
dontlie-agent run --port 8080 -- claude-code
```

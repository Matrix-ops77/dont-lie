# dontlie-openai

A one-line drop-in for the [OpenAI Python SDK](https://github.com/openai/openai-python)
that routes every call through a [Don't-Lie](../..) signed proxy.

## Install

```sh
pip install dontlie-openai
```

## Use

```python
# before:                  # after:
import openai              import dontlie_openai as openai
client = openai.OpenAI(    client = openai.OpenAI()
    api_key="sk-...")      # (DONTLIE_BASE_URL / DONTLIE_API_KEY env vars
                           #  default to the local don'tlie proxy)
resp = client.chat.completions.create(
    model="MiniMax-M3",
    messages=[{"role": "user", "content": "hello"}],
)
```

Everything else in your codebase stays the same. The `OpenAI` class
returned by `dontlie_openai` is the real OpenAI SDK class — only the
defaults are swapped.

## How it works

The don'tlie proxy is just an OpenAI-compatible HTTP server. By pointing
the OpenAI SDK at `http://127.0.0.1:8080/v1`, every request is captured,
canonicalized, signed, and written to a local SQLite vault.

You don't have to do anything else. The proxy is transparent to the SDK.

## Environment

| Variable | Default | Used by |
|---|---|---|
| `DONTLIE_BASE_URL` | `http://127.0.0.1:8080/v1` | Where the client points. |
| `DONTLIE_API_KEY` | `dontlie-local` | Placeholder key for the client. |
| `DONTLIE_UPSTREAM_API_KEY` | (unset) | Forwarded to the proxy. Set in the proxy's shell. |
| `DONTLIE_UPSTREAM_BASE_URL` | `https://api.openai.com` | Forwarded to the proxy. |

## Verify the receipts

After a session:

```sh
dontlie list --limit 5
dontlie verify
dontlie export receipts.bundle.json --bundle
dontlie verify --export receipts.bundle.json --verbose
```

## License

MIT.

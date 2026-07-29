# dontlie-anthropic

A one-line drop-in for the [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python)
that routes every call through a Don't-Lie signed proxy.

## Install

```sh
pip install dontlie-anthropic
```

## Use

```python
# before:                              # after:
import anthropic                       import dontlie_anthropic as anthropic
client = anthropic.Anthropic(          client = anthropic.Anthropic()
    api_key="sk-ant-...")              # (DONTLIE_BASE_URL / DONTLIE_API_KEY env vars
                                       #  default to the local don'tlie proxy)
resp = client.messages.create(
    model="claude-3-5-sonnet-20240620",
    max_tokens=256,
    messages=[{"role": "user", "content": "hello"}],
)
```

## How it works

The don'tlie proxy speaks the Anthropic Messages wire format via the
`anthropic-messages@1` protocol adapter. Point the Anthropic SDK at the
proxy and every request is captured, canonicalized, signed, and written to
a local SQLite vault.

## Environment

| Variable | Default | Used by |
|---|---|---|
| `DONTLIE_BASE_URL` | `http://127.0.0.1:8080/v1` | Where the client points. |
| `DONTLIE_API_KEY` | `dontlie-local` | Placeholder key for the client. |
| `DONTLIE_UPSTREAM_API_KEY` | (unset) | Forwarded to the proxy. Set in the proxy's shell. |
| `DONTLIE_UPSTREAM_BASE_URL` | `https://api.anthropic.com` | Forwarded to the proxy. |

## Anthropic protocol adapter

The proxy's `anthropic-messages@1` adapter preserves native wire
semantics: `/v1/messages`, raw `x-api-key`, `anthropic-version` header,
and Anthropic content blocks. See [`../../interop/README.md`](../../interop/README.md)
for exact conversion limits.

## License

MIT.

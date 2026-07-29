# dontlie-requests

A drop-in for the [requests](https://requests.readthedocs.io/) library that
routes every `chat/completions` call through a Don't-Lie signed proxy.

## Install

```sh
pip install dontlie-requests
```

## Use

```python
# before:                          # after:
import requests                    import dontlie_requests as requests
resp = requests.post(              resp = requests.post(
    "https://api.minimax.io/v1/chat/completions",  # URL is rewritten
    json={"model": "MiniMax-M3", ...},             # to local proxy
    headers={"authorization": "Bearer sk-..."},    # auth is stripped
)                                               )  # proxy forwards
                                                    # the real key
```

## What gets rewritten

Only `POST /v1/chat/completions` requests — every other URL is passed through
unchanged. This is the safety net for "I just want signed receipts for my
LLM calls; everything else should keep working."

## Why strip `Authorization`?

The proxy reads the real provider key from `DONTLIE_UPSTREAM_API_KEY`,
which is set in the proxy's shell, not the client's. Sending the client
key to the proxy would be harmless (the proxy ignores it for chat
completions) but misleading: a future audit might wonder why the key
in the receipt trail doesn't match the key in the local config.

## Session

```python
import dontlie_requests as requests
s = requests.session()
s.post("https://api.openai.com/v1/chat/completions", json={...})
```

## Environment

| Variable | Default | Used by |
|---|---|---|
| `DONTLIE_BASE_URL` | `http://127.0.0.1:8080` | Where the client routes. |
| `DONTLIE_UPSTREAM_API_KEY` | (unset) | Forwarded to the proxy. |

## License

MIT.

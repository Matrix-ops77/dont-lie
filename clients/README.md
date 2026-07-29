# Don't-Lie clients

Drop-in client packages that route every LLM call through a Don't-Lie
signed proxy. The user's application code does not change.

## Packages

| Package | What it does | Install |
|---|---|---|
| `dontlie-openai` | Drop-in for the official OpenAI Python SDK. `import dontlie_openai as openai` and you're done. | `pip install dontlie-openai` |
| `dontlie-anthropic` | Drop-in for the official Anthropic Python SDK. `import dontlie_anthropic as anthropic`. | `pip install dontlie-anthropic` |
| `dontlie-requests` | Drop-in for `requests`. Routes `POST /v1/chat/completions` to the proxy; everything else passes through. | `pip install dontlie-requests` |
| `dontlie-agent` | `dontlie-agent run -- CMD...` wraps any agent runtime (Claude Code, Hermes, Codex, Aider, …) in a signed proxy. | `pip install dontlie-agent` |

## Common pattern

In every case, the user's code is:

```python
import dontlie_openai as openai
client = openai.OpenAI()
client.chat.completions.create(model="...", messages=[...])
```

The proxy is the network-level hook. The client does not have to know
about signatures, vaults, or receipts.

## Setup

```sh
# 1. install the don'tlie core
pip install dontlie

# 2. install the wrappers you need
pip install dontlie-openai      # and/or dontlie-anthropic, dontlie-requests, dontlie-agent

# 3. start the proxy (one terminal)
export DONTLIE_UPSTREAM_API_KEY=sk-...
export DONTLIE_UPSTREAM_BASE_URL=https://api.minimax.io/v1
dontlie proxy --port 8080

# 4. use any client (no change to your code)
python my_app.py
```

## Examples

See [`../examples/`](../examples/README.md) for end-to-end examples in
each language.

## Testing

Each package has its own smoke test:

```sh
python3 -m unittest clients/dontlie_openai/tests/test_smoke.py
python3 -m unittest clients/dontlie_anthropic/tests/test_smoke.py
python3 -m unittest clients/dontlie_requests/tests/test_smoke.py
python3 -m unittest clients/dontlie_agent/tests/test_smoke.py
```

## License

MIT.

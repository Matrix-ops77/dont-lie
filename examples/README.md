# Don't-Lie examples

One example per supported language/path. Each is self-contained and
runs against a local don'tlie proxy plus a real OpenAI-compatible
provider (e.g. MiniMax).

## Files

| File | Language | SDK | What it shows |
|---|---|---|---|
| `python_openai.py` | Python | OpenAI | The drop-in API. `import dontlie_openai as openai`. |
| `python_anthropic.py` | Python | Anthropic | The drop-in API. `import dontlie_anthropic as anthropic`. |
| `python_requests.py` | Python | requests | Raw HTTP transport. Chat-completions requests are rewritten. |
| `node_openai.js` | Node.js | openai | JS/TS drop-in via a small wrapper module. |

## Run

```sh
# 1. start the proxy
export DONTLIE_UPSTREAM_API_KEY=sk-...
export DONTLIE_UPSTREAM_BASE_URL=https://api.minimax.io/v1
dontlie proxy --port 8080 &

# 2. (in another terminal) run an example
python3 examples/python_openai.py
python3 examples/python_anthropic.py
python3 examples/python_requests.py
node examples/node_openai.js

# 3. inspect the receipts
dontlie list --limit 5
dontlie verify
```

## What each example does

Each example:

1. Issues a single chat-completion call.
2. Prints the assistant's reply.
3. Exits.

The local don'tlie proxy intercepts the call, captures the
canonical request and response, signs the receipt, and writes it
to the SQLite vault. After the example runs, `dontlie list` shows
the new receipt.

## License

MIT.

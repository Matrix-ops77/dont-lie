# Don't-Lie passive onboarding

No provider plugin installation is required. The existing Don't-Lie runtime
(including its `cryptography` signing dependency) must be importable; `status`
reports this separately. From this checkout:

```sh
./onboard/dontlie-passive
```

The zero-argument command prints exactly one shell line. Add that line to the
project's `.envrc` or to `.bashrc` / `.zshrc`, then start a new shell. The line
adds this checkout and its `sitecustomize` bootstrap to `PYTHONPATH` and adds the
onboarding command to `PATH`. Python imports `sitecustomize` automatically at
process start.

The explicit form is equivalent:

```sh
dontlie-passive init
```

Useful commands:

```sh
dontlie-passive status  # hook, vault, receipt count, and SDK availability
dontlie-passive show    # five newest receipts; no flags required
```

Set an explicit per-project vault if desired:

```sh
export DONTLIE_PROJECT_VAULT="$PWD/.evidence/model-calls.db"
```

Set `DONTLIE_PASSIVE=0` for a process that must not be instrumented.

## Supported Python SDK surfaces

| Provider | Wrapped methods |
|---|---|
| OpenAI | `Completions.create`, `Completions.stream`, and async variants |
| Anthropic | `Messages.create`, `Messages.stream`, and async variants |
| Google Gemini | legacy `GenerativeModel.generate_content` / async and current `Models` / `AsyncModels` generate and stream methods |

The import hook does not import provider SDKs itself. It patches supported
classes after their modules load, so absent SDKs have zero import cost.

See [PRIVACY.md](PRIVACY.md) before enabling capture. The short version:
requests and responses are plaintext in local SQLite; credentials and transport
headers are excluded; all instrumentation errors fail open; and an abandoned,
unclosed stream may not create a receipt.

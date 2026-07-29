# dontlie-agent

Wrap any agent runtime — Claude Code, Hermes, Codex, Aider, anything — in
a Don't-Lie signed proxy using one command.

## Install

```sh
pip install dontlie-agent
```

## Use

The simplest form: spawn the proxy and your agent under it, in one shot.

```sh
# Wrap Claude Code
dontlie-agent run --port 8080 -- claude-code

# Wrap Hermes
dontlie-agent run --port 8080 -- hermes chat

# Wrap Codex
dontlie-agent run --port 8080 -- codex --prompt "..."
```

The proxy is started in the background. When the agent process exits,
the proxy is stopped automatically.

## Environment

```sh
export DONTLIE_UPSTREAM_API_KEY=sk-...      # real provider key
dontlie-agent run --port 8080 -- claude-code
```

The agent subprocess sees `DONTLIE_BASE_URL=http://127.0.0.1:8080/v1` and
`DONTLIE_API_KEY=dontlie-local`, so any OpenAI/Anthropic-compatible
client inside the agent picks up the proxy automatically.

## Subcommands

| Command | Purpose |
|---|---|
| `dontlie-agent run -- CMD...` | Start proxy + exec agent under it |
| `dontlie-agent wrap -- CMD...` | Exec agent with proxy URL already exported (you start the proxy separately) |
| `dontlie-agent env --port 8080` | Print the env vars a shell needs to inject |
| `dontlie-agent start-proxy --port 8080` | Just start the proxy in the foreground |

## Multiple agents

Run multiple agents under the same proxy in separate terminals:

```sh
# terminal 1
dontlie-agent start-proxy --port 8080 &

# terminal 2
dontlie-agent wrap -- claude-code

# terminal 3
dontlie-agent wrap -- hermes chat

# terminal 4
dontlie list --limit 20
```

## Inspect

```sh
dontlie list --limit 10
dontlie verify
dontlie export receipts.bundle.json --bundle
```

## License

MIT.

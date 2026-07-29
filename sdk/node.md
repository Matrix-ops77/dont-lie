# Node.js SDK wrappers

A separate `dontlie-node` package is **not yet published**. The pattern
is identical to the Python wrappers — point your existing SDK at the
proxy — and the example below shows the minimal change.

## Example

```js
// examples/node_openai.js
const OpenAI = require('openai');
const client = new OpenAI({
  baseURL: `http://127.0.0.1:${process.env.DONTLIE_PORT || 8080}/v1`,
  apiKey: 'dontlie-local',
});
await client.chat.completions.create({
  model: 'MiniMax-M3',
  messages: [{ role: 'user', content: 'hello' }],
});
```

That's it. The OpenAI Node SDK respects `baseURL` natively, so no
shim is needed.

## Wrapping an agent runtime

The same trick works for any Node-based agent:

```sh
DONTLIE_BASE_URL=http://127.0.0.1:8080/v1 \
DONTLIE_API_KEY=dontlie-local \
  node my_agent.js
```

## Future package

When a real `dontlie-node` package is published, it will:

1. Re-export `openai` and `anthropic` from their respective npm packages.
2. Provide an `OpenAI` / `Anthropic` constructor that defaults
   `baseURL` and `apiKey` to the proxy.
3. Provide a `dontlie-agent` shim that copies the env vars before
   spawning a Node agent subprocess.

Track progress in [issues](https://github.com/anomalyco/dontlie/issues).

## License

MIT.

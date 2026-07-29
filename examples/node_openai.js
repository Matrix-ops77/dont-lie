/* Example: Don't-Lie drop-in for the Node.js OpenAI client.
 *
 * Run:
 *   npm install openai dontlie-node
 *   export DONTLIE_UPSTREAM_API_KEY=sk-...
 *   dontlie proxy --port 8080 &
 *   node examples/node_openai.js
 *
 * dontlie-node is not a separate npm package; here we show the
 * minimal pattern a JavaScript port would use. Set the SDK's
 * baseURL + apiKey to the proxy.
 */

const OpenAI = require('openai').OpenAI
  || require('openai').default
  || require('openai');

const PORT = process.env.DONTLIE_PORT || 8080;

const client = new OpenAI({
  baseURL: `http://127.0.0.1:${PORT}/v1`,
  apiKey: 'dontlie-local',  // placeholder; the proxy carries the real key
});

(async () => {
  const resp = await client.chat.completions.create({
    model: 'MiniMax-M3',
    messages: [{ role: 'user', content: "Say 'hello from don\\'tlie' and nothing else." }],
    max_tokens: 32,
  });
  console.log(resp.choices[0].message.content);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});

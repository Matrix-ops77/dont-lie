# Don't-Lie end-to-end flow

This describes the current local MVP from client request to independently
verifiable receipt.

## 1. Configure the two hops

```sh
# Proxy -> provider
export DONTLIE_UPSTREAM_BASE_URL=https://api.minimax.io/v1
export DONTLIE_UPSTREAM_API_KEY="$MINIMAX_API_KEY"
dontlie gen-key
dontlie doctor
dontlie proxy --port 18765

# Client -> proxy (in the client shell)
export OPENAI_BASE_URL=http://127.0.0.1:18765/v1
export OPENAI_API_KEY=dontlie-local
```

`OPENAI_BASE_URL` is never used as the outbound provider URL. This separation
prevents loops and keeps a client placeholder credential away from the provider
hop.

## 2. A chat request travels through the proxy

```http
POST /v1/chat/completions
Content-Type: application/json

{
  "model": "MiniMax-M3",
  "messages": [
    {"role": "system", "content": "Answer concisely."},
    {"role": "user", "content": "What is the code word?"}
  ],
  "stream": false
}
```

The proxy:

1. Limits and validates the JSON body.
2. Builds the provider URL from `DONTLIE_UPSTREAM_BASE_URL`.
3. Adds the provider credential without forwarding the client's secret channel.
4. Forwards the request to the configured OpenAI-compatible provider.
5. Returns the provider status, content type, body, and streaming chunks.
6. Canonicalizes the complete request body and extracts the response text.
7. Appends a receipt containing status, endpoint, byte count, timing, and tags.
8. Computes the payload SHA-256 and Ed25519 signature.
9. Links the receipt to the previous ID and chain-v2 previous payload hash.

For streaming calls, chunks are flushed to the client as they arrive while a
complete copy is collected for the final receipt. The receipt is written after
the upstream stream completes.

## 3. Inspect and verify

```sh
dontlie list --limit 5
dontlie search "code word"
dontlie verify --verbose
dontlie export receipts.bundle.json --bundle
dontlie verify --export receipts.bundle.json --verbose
```

The local verifier checks hashes, signatures, key status, receipt ordering,
parent IDs, and chain-v2 parent payload hashes. Portable verification does not
need the private key or the original database.

## 4. What a receipt proves

It proves that the local signing key signed the canonical record and that the
record still passes verification. It does not prove that the answer is true or
that the remote provider was not replaced before the local recorder received
the response.

## 5. Failure behavior

- Malformed JSON or missing model: HTTP 400, no upstream call.
- Upstream HTTP error: original status/body are returned and the attempt is
  recorded when a response exists.
- Upstream connection failure before a response: HTTP 502 to the client; no
  fabricated successful receipt is written.
- Client disconnect during streaming: the stream terminates; partial-response
  retention is a future enhancement.

# Protocol and receipt interoperability

The runtime adapters in `dontlie/protocols.py` preserve provider-native wire
semantics. `openai-chat-completions@1` uses `/v1/chat/completions`,
`Authorization: Bearer`, OpenAI response choices, and `data: ...` SSE deltas.
`anthropic-messages@1` uses `/v1/messages`, raw `x-api-key`,
`anthropic-version: 2023-06-01`, Anthropic content blocks, and named Anthropic
SSE events. Paths, auth headers/schemes, and Anthropic's version header can be
overridden for compatible gateways.

## Exact conversion limits

- Request converters preserve text system/user/assistant turns, common sampling
  fields, stop sequences, streaming flags, and JSON-schema function tools.
- OpenAI tool-call/result messages and Anthropic `tool_use`/`tool_result`,
  image, document, thinking, and other non-text blocks are rejected. They are
  never silently flattened.
- Provider-specific token accounting, finish/stop reasons, cache controls,
  service tiers, log probabilities, citations, and safety metadata are not
  normalized. Native proxy responses remain unchanged.
- OpenAI-to-Anthropic conversion requires an explicit `max_tokens` value or an
  explicitly supplied default because Anthropic requires that field.

## Obsigna / Agent Receipts compatibility

`to_obsigna_compat` emits a `dontlie-obsigna-compat@1.0` envelope. It retains the
complete source receipt, including its original signature, and projects common
fields into an Agent Receipts 0.5.0 draft.

The projection is **not a signed Agent Receipt**. A Don't-Lie Ed25519 signature
covers the Don't-Lie canonical payload, while Agent Receipts signs RFC 8785
canonical JSON; copying the signature into `proof` would be invalid. The draft
therefore has no `proof`, says `agent_receipt_draft_signed: false`, and lists
missing semantics. In particular, Don't-Lie's `parent_id` does not provide the
previous receipt's Agent Receipt hash, so `previous_receipt_hash` remains
unknown. A conforming Obsigna signer/daemon must enrich and sign the draft
before any consumer treats it as a Verifiable Credential.

PBOM conversion is not implemented because no stable, authoritative Prompt Bill
of Materials exchange schema was identified. Guessing a schema would create
false interoperability.

Fixtures in `fixtures/` are deterministic and exercise native responses and SSE
framing, including arbitrary chunk boundaries.

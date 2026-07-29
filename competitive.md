# Competitive position

The signed-AI-evidence category is active. Don't-Lie should not claim that it
invented signed receipts or that no competitor exists. The detailed, dated scan
is in [`COMPETITOR_RESEARCH.md`](COMPETITOR_RESEARCH.md).

## Direct categories

- **Evidence primitives:** halo-record, Provedex, PBOM, Obsigna, Tesserae.
- **Agent governance/firewalls:** OrgKernel, Pipelock, HELM AI Kernel, Asqav.
- **Compliance/PII evidence:** Aulite, CloakLLM.
- **Local/provider proxies:** llm.log and the gateway projects.
- **Observability platforms:** Langfuse, Phoenix, Helicone, OpenLLMetry,
  OpenLIT, LiteLLM, and Portkey.

## Our position

Don't-Lie should be the easiest way for a developer to turn a real AI call into
a portable, independently verifiable evidence artifact:

1. Change one local base URL; keep the existing client and provider contract.
2. Capture the complete request contract and bounded raw response, with explicit
   fingerprint/redacted/forensic privacy modes.
3. Sign and hash-link model calls, tool calls, approvals, denials, and human
   review events in one receipt format.
4. Export a bundle that a clean machine can verify without the recorder, cloud,
   or private key.
5. Render a customer-friendly report that clearly separates record integrity,
   signer trust, provider route, and answer truth.
6. Interoperate with open formats such as PBOM and Obsigna rather than creating
   another isolated vendor schema.

## What we must not promise yet

- Native Anthropic Messages support until its adapter and conformance tests ship.
- Regulatory compliance without external checkpoints, retention controls, and a
  regulation-specific implementation review.
- Truthfulness or provider provenance from a local signature alone.
- Team sync, encryption, redaction, or policy enforcement before those features
  are implemented and independently tested.

The moat is not the word “cryptographic.” The moat must be an open protocol,
interoperability, independent verification, privacy controls, and the fastest
credible proof workflow for a customer incident.

# Don't-Lie compliance memos

> **Operator reference, not vendor certification.**
> These memos are informational material for people evaluating Don't-Lie
> against a regulatory regime. They tell an operator what a Don't-Lie
> receipt does and does not cover. They are **not** a compliance
> certification, **not** a SOC 2 report, **not** a BAA, and **not**
> legal advice. Confirm any compliance position with your own counsel.
> Don't-Lie v0.3.5 is a local-first Python package; there is no
> hosted service, no hosted witness, and no compliance product behind
> these memos.

Per-regime guides for our primary buyers: regulated-industry AI engineers in healthcare, legal, financial services, and the EU. Each memo is **2 pages** and answers three questions in plain language:

1. What does the regime require?
2. What does a Don't-Lie receipt prove or not prove?
3. What does the operator still need to do?

| Regime | Memo | One-line answer |
|---|---|---|
| Healthcare PHI | [`HIPAA.md`](./HIPAA.md) | The receipt is the audit control (§164.312(b)) and the integrity control (§164.312(c)) for AI calls. Sign a BAA with your AI provider, restrict key access, run the trust score in CI. |
| SaaS audit | [`SOC2.md`](./SOC2.md) | The receipt is monitoring evidence (CC7.2) and vendor-risk evidence (CC9.2). Include the vault in audit scope, document key rotation, export the bundle for each audit period. |
| EU AI Act | [`EUAIAct.md`](./EUAIAct.md) | The receipt directly implements Article 12 logging for AI systems. Use it as the data source for your FRIA and post-market monitoring. |
| NY financial | [`NYDFS.md`](./NYDFS.md) | The receipt is the §500.06 audit trail and the §500.14 incident-response evidence. Wire it into your SIEM and use it for the 72-hour reporting rule. |

## The common pattern

Every memo says the same three things, because every regime needs the same three things from a tool like Don't-Lie:

1. **The tool provides the receipt.** It's a tamper-evident, hash-linked, signed audit trail of every LLM call.
2. **The receipt does not, on its own, prove the harder things** — that the key was held by an authorized person, that the call was authorized, that the response was correct, that the timestamp is anchored. The Reasonable Doubt panel in every bundle is the honest short list.
3. **The operator layers additional controls** — BAA, key access policy, retention rules, change management, incident response — and documents how those controls close the gaps.

The Don't-Lie part of the program is one to three days of integration work. The rest of the program is the operator's job and is the same work they'd be doing without Don't-Lie. The difference is that with Don't-Lie, that work is grounded in byte-exact, tamper-evident evidence instead of "we trust our logs."

## What the memos do not do

These are informational, not legal advice. Confirm any compliance position with counsel. A Don't-Lie compliance memo does not:

- Constitute a legal opinion
- Substitute for the operator's own counsel
- Guarantee pass on any audit
- Bind any third party (auditor, regulator, customer)

The memos are designed to be the document the operator's counsel works from — they identify the questions, point at the relevant receipt capabilities, and flag the gaps. Counsel then writes the operator's own compliance position.

## How to use them

- **For a sales conversation:** hand the relevant memo to the buyer's compliance team. "This is what we cover, this is what you still own."
- **For a pilot design:** read the "what you need to do additionally" section. That is the operator's work plan.
- **For an audit response:** export the relevant bundle, point the auditor at the Reasonable Doubt panel, walk through the 5 gaps and the controls that close them.
- **For product roadmap:** the memos name the controls Don't-Lie does not yet provide (e.g., HSM-backed keys, multi-region witnesses, RFC 3161 timestamps). Those are operator-side workarounds today, not paid features.

## A note on the four regimes we picked

We chose HIPAA, SOC 2, EU AI Act, and NY DFS Part 500 because together they cover most of the regulated-industry AI engineer population in the US and EU:

- **HIPAA** for healthcare (US)
- **SOC 2** for SaaS / B2B / cloud services (US, and globally via customer demand)
- **EU AI Act** for any AI system deployed in the EU, regardless of where the deployer is headquartered
- **NY DFS Part 500** for financial services (US, with comparable regimes in MA, NJ, CT, and other states following Part 500's lead)

If you operate in a different regime (FISMA for federal contracts, PCI DSS for card data, FedRAMP, CMMC for defense, the UK AI Bill, Singapore's MAS guidance, etc.), the structure of the memo is the same. We're happy to draft additional ones on request.

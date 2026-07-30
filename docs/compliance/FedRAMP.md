# Don't-Lie & FedRAMP 20x — compliance memo

**Date:** 2026-07-28
**Audience:** Federal agency program offices, FedRAMP-authorized cloud teams, CMMC / FISMA program managers, AI governance leads at federal contractors
**Scope:** How Don't-Lie receipts map to the FedRAMP 20x baseline and the 2025 AI Prioritization Initiative, and what the boundary question looks like for local-first AI observability.

> This memo is informational and is not legal advice. FedRAMP authorization is issued by the FedRAMP Program Management Office (PMO) at GSA, by agency authorizers, or by 3PAOs; Don't-Lie is one input to that authorization process, not a substitute for it.

---

## What FedRAMP 20x actually requires (the relevant subset)

| Source | Requirement | Applies to AI call receipts? |
|---|---|---|
| **FedRAMP 20x** (announced 24 Mar 2025; https://www.fedramp.gov/20x/) | Replaces the ~325-control Rev 5 narrative baseline with ~56 Key Security Indicators (Low) / ~61 (Moderate), delivered as machine-readable OSCAL | Partial — Receipts are machine-readable signed JSON, OSCAL-fragment-exportable |
| **FedRAMP AI Prioritization Initiative** (Aug 2025 – Apr 2026; https://www.fedramp.gov/ai/) | Prioritized authorization of AI-based cloud services; certified in early 2026 included OpenAI, Google Gemini for Government, Perplexity Enterprise | Indirect — if the AI service is in a FedRAMP authorization boundary, Receipts are the audit evidence inside that boundary |
| **NIST AI 600-1** (Jul 2024; GenAI Profile under NIST AI RMF 1.0) | Content provenance, audit trail, incident disclosure, stop-build authority | **Directly** — Receipts are the content-provenance + audit-trail artifacts |
| **OMB M-25-21** | "High-Impact" AI at federal agencies requires model version + prompts + outputs preserved per 44 U.S.C. §3101 | **Directly** — every Receipt carries model, prompt, response, timestamp, and signing key id |
| **FISMA / 44 U.S.C. §3554** | Federal agency information security programs must include audit logging | Yes — Receipts are the audit-log layer for the AI system |

## What a Don't-Lie receipt proves (in a FedRAMP context)

- That a specific call to an AI model was made from inside the federal authorization boundary, with a specific model, prompt, and response, at a specific time, signed by the operator's key
- That the receipt is tamper-evident (Ed25519 + SHA-256 chain) and can be machine-verified by a 3PAO or agency auditor without Don't-Lie's cooperation
- That the chain is unbroken back to the first receipt in the vault, providing the "review and audit trail" (NIST AI 600-1 cross-cutting) over the lifetime of the AI deployment
- That a model change (model version drift, swap from GPT-4o to a new model) is visible in the time-series of Receipts — the operator can show the auditor "this is when we changed models, this is what the new model was called with, this is what it said"

## What a Don't-Lie receipt does **not** prove

- That the AI service itself is FedRAMP authorized (the AI provider carries that authorization; the Receipt is evidence *inside* the boundary, not authorization of the boundary)
- That the AI service is operating correctly (that's the AI provider's authorization; don't conflate)
- That the federal agency's other FedRAMP controls (encryption at rest in the federal cloud boundary, access provisioning, vulnerability scanning, etc.) are working — those are separate KSIs
- That the model output is unbiased, accurate, or appropriate for the use case — that's NIST AI 600-1 §MEASURE and OMB M-25-21 "High-Impact" testing, separate from logging

## What you need to do additionally

1. **Ask the right boundary question.** Per https://truvisory.com/federal/verify-ai-contractor-cmmc-fedramp/, the first question to an AI vendor is not "are you FedRAMP authorized?" but **"is the specific generative-AI or inference component my users will call inside your authorization boundary?"** If prompts, outputs, or context windows leave the boundary, the authorization doesn't cover them. Run the AI call through Don't-Lie *inside* the boundary, and the Receipt is itself inside the boundary.
2. **Don't-Lie is not a FedRAMP service.** Don't-Lie is a local-first Python package the operator runs on their own hardware, inside the enclave. The Receipt does not introduce a FedRAMP authorization boundary of its own; the operator's enclave boundary governs it. The vault file lives in the operator's storage; the witness is a process the operator runs (or contracts for) on their own infrastructure.
3. **Export Receipts as OSCAL fragments for KSI collection.** FedRAMP 20x wants machine-readable evidence. The vault can be exported and mapped to KSIs in the `monitoring` and `audit-logging` families; that mapping is the operator's work.
4. **Anchor the chain via a witness notary the operator runs for cross-agency admissibility.** The witness notary's co-signature is the strongest available evidence that the timestamp was not backdated. For a federal record subject to NARA's General Records Schedule 6.5 (electronic records), an RFC 3161 timestamp from a witness the operator vets is the artifact a federal records officer will accept. Don't-Lie ships a `dontlie witness-service` subcommand so the operator can run the witness themselves.
5. **For "High-Impact" AI per OMB M-25-21:** ensure every Receipt carries the model version (in `model` field), the full prompt (`prompt`), and the full response (`response`). Don't-Lie's schema already does this; do not redact prompts/responses before signing — the value of the Receipt is byte-exactness.
6. **Document the Reasonable Doubt panel for the 3PAO.** The 3PAO's standard question is "what does the receipt not prove?" Have a written answer ready. The five RD items are: (1) who held the key, (2) whether the proxy process was compromised, (3) whether the call was authorized, (4) whether the upstream provider is itself authorized, (5) whether the timestamp is anchored. Each has a separate control.
7. **For 20x KSI automation, integrate `dontlie verify` into the continuous-monitoring pipeline.** 20x's 80% automation target means control evidence must be machine-checkable. The Receipt's signed JSON is already machine-checkable. The `dontlie trust-score --json` exit code is a candidate for a KSI "audit-log-integrity" check.

## What Don't-Lie does **not** do for FedRAMP

- It is **not** a FedRAMP authorization. The customer cannot hand the customer a "FedRAMP receipt." Only GSA / an agency AO / a 3PAO can issue a FedRAMP authorization.
- It is **not** a FedRAMP-authorized cloud service offering. Don't-Lie does not host customer data on its own infrastructure in the local-first tier.
- It does **not** substitute for the AI provider's authorization. The AI provider (OpenAI, Google, Anthropic) carries the AI-component authorization; Don't-Lie receipts are evidence inside that boundary.
- It does **not** satisfy 20x KSIs by itself. Receipts address the monitoring / audit-logging KSIs; the customer still has the other ~50 KSIs to satisfy.

## Where Don't-Lie fits in a typical FedRAMP 20x AI deployment

| 20x KSI family (representative) | Don't-Lie contribution |
|---|---|
| Audit logging (KSI-MNT) | **Strong** — Receipt chain is the audit log |
| Monitoring (KSI-MNT) | Strong — `dontlie tail --follow --json` is the continuous-monitoring event source |
| Configuration management (KSI-CMT) | Partial — Receipts log model-name changes; the customer still does CM of the AI service |
| Access control (KSI-IAM) | None — filesystem / IAM is the customer's control |
| Incident response (KSI-IR) | Strong — Receipt chain is the incident-response forensic record |
| Supply chain (KSI-SCM) | Strong — Receipts are the artifact for "is the AI component behaving as authorized?" |

## A practical example

A federal agency operating a FedRAMP-Moderate enclave wants to deploy an LLM-backed caseworker assistant. They:

1. Confirm the AI service is FedRAMP-authorized at Moderate (or higher) — that's the AI provider's authorization
2. Run the Don't-Lie proxy on a node inside the enclave
3. Point the caseworker application at the proxy
4. Configure the witness notary to co-sign the receipt chain (timestamp anchoring)
5. Export the bundle to a customer-controlled S3 bucket in the enclave with Object Lock retention
6. Hand the 3PAO a portable bundle, run `dontlie verify` on a clean 3PAO laptop, get a 30-second yes/no on chain integrity
7. The 3PAO maps the Receipt to KSIs in the audit-logging and monitoring families

Total integration: 1 day. Total operator cost: software is free under MIT; the storage, the witness, the enclave deployment, and the 3PAO engagement are not.

## Where to get help

- `docs/integrations/SIEM.md` — wire the receipts into the agency's existing SIEM
- `docs/groundtruth.md` — vendor-independent route attestation (opt-in lane)
- GitHub Issues: open a question at `github.com/Matrix-ops77/dont-lie/issues`
- For EU/UK cross-border deployments under FISMA + the EU AI Act, run your own witness notary in the relevant jurisdiction

## Sources

- FedRAMP 20x (primary): https://www.fedramp.gov/20x/
- FedRAMP AI page (primary): https://www.fedramp.gov/ai/
- GSA news release on AI Prioritization (Aug 2025): https://www.gsa.gov/about-gsa/newsroom/news-releases/gsa-fedramp-prioritize-20x-authorizations-for-ai-08252025
- OpenAI FedRAMP 20x Moderate announcement: https://openai.com/index/openai-available-at-fedramp-moderate/
- NIST AI RMF 1.0 (NIST AI 100-1, Jan 2023): https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 600-1 GenAI Profile (Jul 2024, primary): https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- OMB M-25-21 (referenced via Censinet + IAPP): https://www.whitehouse.gov/omb/
- Truvisory buyer-side boundary question: https://truvisory.com/federal/verify-ai-contractor-cmmc-fedramp/
- 44 U.S.C. §3101 (Records management by federal agencies): https://www.govinfo.gov/app/details/USCODE-2023-title44/USCODE-2023-title44-chap31-subchapI-sec3101
- 44 U.S.C. §3554 (FISMA): https://www.govinfo.gov/app/details/USCODE-2023-title44/USCODE-2023-title44-chap35-subchapII-sec3554

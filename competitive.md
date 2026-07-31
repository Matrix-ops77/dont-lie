# Competitive position

**Reviewed:** 2026-07-30
**Method:** primary project documentation and public repositories
**Scope:** runtime evidence, agent receipts, compliance proxies, and agent
security—not a security audit of those projects.

Don't-Lie did not invent signed receipts, hash chains, independent
verification, evidence reports, or AI gateways. The category is active and
capable. Product claims must describe a tested combination and never imply
that competitors do not exist.

## Closest projects

| Project | Demonstrated strength | Lesson for Don't-Lie |
|---|---|---|
| [halo-record](https://github.com/bkuan001/halo-record) | Runtime action records, explicit integrity-vs-completeness model, witness checkpoints, date-bounded GRC exports, report serving, OTel ingestion, and Python/TypeScript support | Add externally committed history, scope-aware exports, capture-coverage evidence, and cross-language verification |
| [Obsigna](https://github.com/agent-receipts/obsigna) | Open agent-receipt protocol, Go/TypeScript/Python SDKs, cross-SDK vectors, MCP proxy, and encrypted forensic disclosure | Publish frozen conformance vectors and add privacy-preserving encrypted disclosure without conflating signing and encryption keys |
| [Pipelock](https://github.com/luckyPipewrench/pipelock) | External mediator signing, egress enforcement, DLP, injection defenses, sandboxing, deployment recipes, SIEM mappings, and supply-chain attestations | Do not pretend a local recorder is a firewall; integrate with enforcement boundaries and prove where capture occurred |
| [Aulite](https://github.com/el1ght/aulite) | EU AI Act-focused proxy, policy rules, risk monitoring, dashboard, and report generation | Win on independently verifiable evidence and honest legal boundaries; do not imitate unsupported “legal-grade” language |
| [Provedex](https://github.com/provedex/provedex) | Rust signing core, offline verification, SDK bindings, and portable evidence | Keep first-install simplicity while moving verification toward an implementation independent from the recorder |

Large observability and gateway platforms—Langfuse, Helicone, Phoenix,
OpenLLMetry, OpenLIT, LiteLLM, and Portkey—compete for adjacent budget and
distribution. Don't-Lie should integrate with their telemetry rather than
rebuild their dashboards, routing, evaluation, or cost-management products.

## Current scorecard

| Capability | Don't-Lie | Stronger reference today | Required response |
|---|---|---|---|
| Real provider-call capture | Strong Python-first proxy and wrappers | Large gateways have broader protocols | Preserve as the initial wedge; test every claimed protocol path |
| Portable buyer packet | Strong `dontlie prove` flow | Halo has broader report-serving and scoped exports | Add scope manifests, date filters, and capture-boundary disclosure |
| Honest proof boundary | Strong manifest/report wording | Halo also documents integrity vs completeness rigorously | Make capture completeness a first-class verdict, not prose alone |
| External history commitment | Integration points and fixtures; production status varies by command | Halo has explicit witness/checkpoint workflows | Ship one production-verified external checkpoint path before claiming historical commitment |
| Privacy | Fingerprint, redacted, and forensic evidence modes; redaction is heuristic | Obsigna has encrypted asymmetric disclosure | Add recipient-key encrypted forensic disclosure and key-custody documentation |
| Cross-language conformance | Limited | Obsigna and Halo | Publish canonical vectors and an independent verifier |
| Policy enforcement and DLP | Partial local policy/redaction | Pipelock | Integrate; do not become a firewall without a buyer requirement |
| Agent/tool-action coverage | Partial | Halo, Obsigna, Pipelock | Define a versioned action envelope only after capture semantics are tested |
| Compliance evidence mapping | Machine-readable HIPAA and EU AI Act support maps | Competitors publish framework mappings of varying depth | Keep sources official, dates explicit, and gaps executable with `--only-gaps` |
| Supply-chain assurance | Reproducible wheel/sdist and SHA-pinned Actions | Pipelock publishes SLSA provenance and SBOM verification | Add release attestations and an SBOM before regulated pilots depend on the package |

## Position to win

> Don't-Lie is the shortest tested path from one real AI provider call to a
> portable evidence packet that a different person can verify, with explicit
> limits and a machine-readable map of the controls the packet does and does
> not support.

That position is defensible only while all five parts remain true:

1. The call is real, not a fabricated demo record.
2. The packet verifies independently.
3. The signing key can be pinned outside the packet.
4. The report separates integrity, signer trust, provider route, time, answer
   truth, and capture completeness.
5. Every regulatory mapping points to an official source and labels
   operator-owned controls.

## Priority order

1. Paid-pilot evidence from the current provider-call packet.
2. Capture-completeness and packet-scope manifest.
3. Production external checkpoint with independent verification.
4. Recipient-key encrypted forensic disclosure.
5. Frozen cross-language test vectors and independent verifier.
6. Release SBOM and provenance attestation.

UI, hosted retention, broad policy engines, and more SDKs move forward only
when a qualified buyer makes them part of a paid workflow.

## Claims we do not make

- That Don't-Lie is the only signed-receipt project.
- That a valid receipt proves every action was captured.
- That route metadata establishes provider identity.
- That timestamps are trustworthy without an independently verified source.
- That redaction removes all PHI or personal data.
- That a receipt establishes HIPAA compliance or EU AI Act conformity.
- That a compliance map is legal advice, certification, or an audit result.

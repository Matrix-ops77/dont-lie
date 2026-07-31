# Don't-Lie compliance memos

> **Operator reference, not vendor certification.**
> These memos are informational material for people evaluating Don't-Lie
> against a regulatory regime. They tell an operator what a Don't-Lie
> receipt does and does not cover. They are **not** a compliance
> certification, **not** a SOC 2 report, **not** a BAA, **not** legal
> advice, and **not** the work of counsel. Confirm any compliance
> position with your own counsel. Don't-Lie v0.3.7 is a local-first
> Python package; there is no hosted service, no hosted witness, no
> hosted vault, and no compliance product behind these memos. All
> retention, S3 Object Lock, KMS, witness, and operator-side controls
> named in these memos are **your** work, not Don't-Lie's.

Per-regime guides for the operator of a Don't-Lie vault. Each memo is **operator reference** and answers three questions in plain language:

1. What does the regime require?
2. What does a Don't-Lie receipt prove or not prove?
3. What does the **operator** still need to do? (Don't-Lie is one control in your program; the rest is yours.)

| Regime | Memo | One-line answer |
|---|---|---|
| Healthcare PHI | [`HIPAA.md`](./HIPAA.md) | Receipts support review of audit controls (§164.312(b)) and detect alteration of recorded evidence for integrity review (§164.312(c)); the operator supplies the rest of the HIPAA program. |
| BAA template | [`BAA-TEMPLATE.md`](./BAA-TEMPLATE.md) | A short Business Associate Agreement template. The template is short because the local-first product never receives PHI. Counsel adapts and completes. |
| SaaS audit | [`SOC2.md`](./SOC2.md) | The receipt is monitoring evidence (CC7.2) and vendor-risk evidence (CC9.2). Include the vault in your audit scope, document key rotation, export the bundle for each audit period. |
| EU AI Act | [`EUAIAct.md`](./EUAIAct.md) | Receipts provide supporting runtime evidence for configured model calls; they do not establish Article 12 coverage or conformity. |
| NY financial | [`NYDFS.md`](./NYDFS.md) | The receipt is the §500.06 audit trail and the §500.14 incident-response evidence. Wire it into your SIEM and use it for the 72-hour reporting rule. |
| CFPB / ECOA | [`CFPB.md`](./CFPB.md) | For creditors using LLMs to draft adverse-action narratives. The receipt is the byte-exact record behind the disclosure. |
| Colorado ADMT | [`ColoradoADMT.md`](./ColoradoADMT.md) | For Colorado SB 24-205 / SB 26-189 high-risk AI. The receipt is the deployer's evidence for the 90-day disclosure rule. |
| FDA PCCP | [`FDAPCCP.md`](./FDAPCCP.md) | For SaMD manufacturers using the FDA PCCP. The receipt chain is the audit trail for each pre-authorized modification. |
| FedRAMP 20x | [`FedRAMP.md`](./FedRAMP.md) | For federal agency AI deployments. The receipt is operator-side audit evidence inside the enclave; it is not a FedRAMP service. |

## The common pattern

Every memo says the same three things, because every regime needs the same three things from a tool like Don't-Lie:

1. **The tool provides a receipt for calls that cross a configured capture
   boundary.** It is a signed, hash-linked record. The chain cannot prove that
   every real-world event passed through the recorder.
2. **The receipt does not, on its own, prove the harder things** — that the key was held by an authorized person, that the call was authorized, that the response was correct, that the timestamp is anchored. The Reasonable Doubt panel in every bundle is the honest short list.
3. **The operator layers additional controls** — BAA, key access policy, retention rules, change management, incident response — and documents how those controls close the gaps.

Integration time depends on the application, capture boundary, privacy
requirements, and required coverage. Do not quote a universal implementation
time. The rest of the program remains the operator's responsibility.

## Machine-readable control maps

The maintained HIPAA Security Rule and EU AI Act maps can be reviewed in text
or deterministic JSON:

```bash
dontlie compliance hipaa-security --only-gaps
dontlie compliance eu-ai-act --json
```

The JSON is suitable for review or import into a GRC workflow. Its statuses are
limited to `supported`, `supporting_evidence`, `operator_required`, and
`out_of_scope`; none means compliant.

## What the memos do not do

These are informational, not legal advice. Confirm any compliance position with counsel. A Don't-Lie compliance memo does not:

- Constitute a legal opinion
- Substitute for the operator's own counsel
- Guarantee pass on any audit
- Bind any third party (auditor, regulator, customer)
- Replace the operator's HSM, key-management service, witness notary, retention storage, or any other control named in the memo
- Provide designated support staff, a hosted product, a hosted witness, or a hosted vault

The memos are designed to be the document the operator's counsel works from — they identify the questions, point at the relevant receipt capabilities, and flag the gaps. Counsel then writes the operator's own compliance position.

## How to use them

- **For an audit response:** export the relevant bundle, point the auditor at the Reasonable Doubt panel, walk through the 5 gaps and the controls that close them.
- **For a compliance program design:** read the "What the operator needs to do" section. That is the operator's work plan.
- **For an HSM / KMS / witness decision:** the memos name the controls Don't-Lie does not provide. Those are operator-side workarounds today — run your own HSM, your own witness, your own S3 Object Lock.

## A note on the regimes covered

We chose HIPAA, SOC 2, EU AI Act, NY DFS Part 500, CFPB / ECOA, Colorado ADMT, FDA PCCP, and FedRAMP 20x because together they cover the most common regulated-industry AI deployments we hear about:

- **HIPAA** for healthcare (US)
- **SOC 2** for SaaS / B2B / cloud services (US, and globally via customer demand)
- **EU AI Act** for any AI system deployed in the EU, regardless of where the deployer is headquartered
- **NY DFS Part 500** for financial services (US, with comparable regimes in MA, NJ, CT, and other states following Part 500's lead)
- **CFPB / ECOA** for creditors using LLMs in adverse-action decisions
- **Colorado ADMT** for Colorado high-risk AI deployments
- **FDA PCCP** for SaMD manufacturers with pre-authorized AI modifications
- **FedRAMP 20x** for federal agency AI deployments

If you operate in a different regime (FISMA for federal contracts, PCI DSS for card data, CMMC for defense, the UK AI Bill, Singapore's MAS guidance, etc.), the structure of the memo is the same. Open a GitHub issue with the regime name; the maintainer can draft additional memos on request.

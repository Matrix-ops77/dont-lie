# Don't-Lie & SOC 2 — compliance memo

**Date:** 2026-07-28
**Audience:** SOC 2 audit lead, security officer, ITGC reviewer
**Scope:** How Don't-Lie receipts help meet the SOC 2 Trust Services Criteria relevant to AI systems, and what the operator still has to do.

> This memo is informational. A SOC 2 report is issued by an independent CPA firm on the operator's own control environment; Don't-Lie is one component in that environment, not a substitute for it.

---

## What SOC 2 actually requires (the relevant TSCs)

| TSC | Requirement | Applies to AI call receipts? |
|---|---|---|
| CC6.1 | Logical access controls | Yes — vault is operator-local; key access controls matter |
| CC6.6 | Logical access to systems outside the entity | Yes — controls on the AI provider relationship |
| CC7.1 | Detection of new vulnerabilities | Partial — witness notary detects chain anomalies |
| **CC7.2** | **Monitoring of system components** | **Directly** — every LLM call is a monitored event |
| CC7.3 | Evaluation of security events | Yes — `dontlie trust-score` is the daily evaluation |
| CC7.4 | Incident response | Yes — receipts are the forensic record of an incident |
| CC8.1 | Change management | Partial — receipt captures the change event |
| **CC9.2** | **Vendor and business partner risk** | **Directly** — receipts are evidence of vendor risk controls |
| A1.1 | Capacity planning | Indirect — vault size trends inform capacity |
| C1.1 | Confidentiality of information | Yes — secret redaction in the receipt chain |

## What a Don't-Lie receipt proves

- That a specific call to an AI model was made at a specific time (CC7.2 monitoring event)
- That the exact prompt and response bytes were preserved, byte-for-byte (CC7.4 forensic record)
- That no operator has silently edited the call record afterward (CC7.3 evaluation input)
- That the chain is unbroken back to the first receipt in the vault (CC7.1 detection baseline)
- That the same key that signed the receipt was held continuously by the operator (CC6.1 access control)

## What a Don't-Lie receipt does **not** prove

- That the operator's SOC 2 controls are themselves operating effectively (that's the audit's job)
- That the AI provider is also SOC 2 compliant (request their report separately; many are)
- That the operator's own logging of who-ran-what is correct (Don't-Lie signs the AI call, not the operator's access log — though the Team tier does sign the audit log too)
- That the response was correct or appropriate

## What you need to do additionally

1. **Include the receipt vault in your audit scope.** The vault is in-scope for SOC 2 if you process customer data through it. The Compliance tier ships a SOC 2-relevant control matrix you can hand to your auditor.
2. **Document the change-management policy for the signing key.** When the key is rotated, that rotation event is itself logged in `key_history` and should be tied to your change ticket.
3. **Run `dontlie trust-score` daily.** The score is a leading indicator of vault health. A drop in `chain_integrity` from 40 → 0 is the kind of thing an auditor wants to know about before they find it.
4. **Export the bundle to immutable storage for the audit period.** The Compliance tier uses S3 Object Lock in COMPLIANCE mode — even the bucket owner cannot delete a receipt in retention.
5. **Map receipts to your monitoring systems.** Pipe `dontlie tail --follow --json` into your SIEM (see `docs/integrations/SIEM.md`). The receipt is then a first-class event in your existing monitoring, not a new silo.
6. **Add the receipt chain to your evidence locker.** For each control test that says "the system logged event X," the receipt is the evidence. Bundle the relevant receipts and attach to the test.
7. **Address the gaps from the Reasonable Doubt panel.** Specifically: publish your public key (RD #1), separate the proxy process (RD #2), tag authorized calls (RD #3), and anchor the chain (RD #5).

## What Don't-Lie does **not** do for SOC 2

- It is **not** a SOC 2 report itself. The report comes from a CPA firm auditing your controls.
- It does **not** cover the operator's own identity, change management, or HR controls. Those are your job.
- It does **not** certify the AI provider. (Get theirs.)

## Where this fits in a typical audit

| Audit section | What the auditor typically asks for | What Don't-Lie provides |
|---|---|---|
| Monitoring (CC7.2) | "Show me an audit log of AI calls" | The vault, exported as a portable bundle |
| Vendor risk (CC9.2) | "How do you know your AI provider did what you asked?" | The receipt, showing the exact prompt + response bytes |
| Incident response (CC7.4) | "If a bad response goes out, how do you reconstruct what happened?" | `dontlie search` + the receipt chain |
| Confidentiality (C1.1) | "How do you ensure secrets don't leak into logs?" | `dontlie redact` rules on the receipt chain |
| Change management (CC8.1) | "When did the AI behavior change?" | Time-series of receipts by model name |

## The most useful artifact for an auditor

`dontlie export audit-2026Q3.bundle.json --bundle` produces a single JSON file. Your auditor can:

1. Open it in any text editor
2. Run `dontlie verify --export audit-2026Q3.bundle.json --verbose` to confirm the chain
3. Run `dontlie trust-score --export audit-2026Q3.bundle.json` for the numeric verdict
4. Read the Reasonable Doubt panel in the rendered HTML report to see what the bundle does and does not prove

This is the entire evidence package for one quarter, in one file, verifiable in 30 seconds.

## Where to get help

- `docs/integrations/SIEM.md` — wire the receipts into your existing SIEM
- `docs/integrations/SIEM.md#s3-long-term-archive` — S3 with Object Lock for audit retention
- The Compliance tier (see `site/pricing.html`) includes a SOC 2-relevant control matrix and designated success engineer

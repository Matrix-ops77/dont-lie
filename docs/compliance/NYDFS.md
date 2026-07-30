# Don't-Lie & NY DFS 23 NYCRR Part 500 — operator reference

**Date:** 2026-07-30
**Audience:** CISO, cybersecurity officer, covered-entity compliance lead
**Scope:** How a Don't-Lie receipt vault, run by the operator on their own hardware, supports NY DFS cybersecurity event logging, audit trail, and incident response requirements for AI systems at financial services institutions.

> This memo is informational and is not legal advice. The final cybersecurity program is the responsibility of the covered entity's CISO and board. Don't-Lie is a local-first Python package. There is no hosted service, no hosted witness, no hosted vault, and no compliance product behind this memo.

---

## What 23 NYCRR Part 500 actually requires (the relevant sections)

| Section | Requirement | Applies to a locally-run AI call vault? |
|---|---|---|
| **§500.02** | Cybersecurity program | Partial — vault is one control in the program |
| §500.03 | Cybersecurity policy | Partial — vault ops is one policy element |
| §500.06 | **Audit trail** for cybersecurity events | **Directly** — every LLM call is an auditable event |
| §500.07 | Access privileges | Yes — vault is operator-local; key access controls matter |
| §500.10 | Cybersecurity personnel | Indirect — vault enables personnel to do their job |
| §500.11 | Third-party service provider security policy | Partial — AI provider is a third-party service provider |
| §500.14 | **Incident response plan** | Yes — receipts are forensic evidence for the IR plan |
| §500.16 | Incident reporting to superintendent (72-hour rule) | Yes — `dontlie search` finds the affected receipts fast |

## What a Don't-Lie receipt proves

- That the AI system generated a specific event (audit trail, §500.06)
- That the event log cannot be silently rewritten (audit integrity, §500.06)
- That the response to a reported incident is grounded in byte-exact evidence (incident response, §500.14)
- That a cybersecurity event affecting the AI system can be reconstructed (incident reporting, §500.16)

## What a Don't-Lie receipt does **not** prove

- That the covered entity's overall cybersecurity program is operating effectively (that's the annual certification, §500.17)
- That the AI provider is itself a covered third party with a compliant program (covered entity is responsible for assessing the third party, §500.11)
- That the AI system was free of vulnerabilities (pen testing, §500.05, is separate)
- That the response was correct

## What the operator needs to do

1. **Classify AI calls as cybersecurity events.** Under §500.02(a), you must identify and assess material cybersecurity risks. AI-driven decisions about a customer (credit decision, fraud flag, KYC outcome) qualify as material. The receipt vault is the audit trail for those events.
2. **Include the receipt vault in the cybersecurity policy.** §500.03 requires written policies. The vault's role, retention period, and access controls should be one section.
3. **Configure 5-year retention.** §500.06(b) requires retention for 5 years. Don't-Lie produces a portable bundle; you choose the storage backend and retention policy. A common pattern is S3 Object Lock in COMPLIANCE mode (or equivalent on Azure Blob immutable storage / GCS bucket lock) on infrastructure you operate.
4. **Wire `dontlie tail --follow --json` into your SIEM.** See `docs/integrations/SIEM.md`. The receipt becomes a first-class event in Splunk / Datadog / ELK, alongside your existing cybersecurity telemetry.
5. **Use the receipt chain for the 72-hour rule.** §500.17(a) requires reporting a cybersecurity event to the superintendent within 72 hours. The receipt chain lets you reconstruct the affected time window in seconds:
   ```bash
   dontlie search "fraud_decision:true" --limit 1000
   ```
6. **Tag the third-party provider.** Add `provider:` tags to every receipt so the audit trail makes clear which upstream was involved. This supports the §500.11 third-party risk assessment.
7. **Address the Reasonable Doubt panel.** RD #5 (timestamp anchoring) is especially important for §500.16 — the 72-hour rule is timestamp-sensitive, and a witness co-signature (from a witness you operate) is the strongest available evidence the timestamp was not backdated.
8. **Document the limitations.** Add a one-page addendum to your cybersecurity policy acknowledging the 5 things receipts do not prove on their own. This shows the regulator you've thought about the gaps.

## What Don't-Lie does **not** do for Part 500

- It is **not** a substitute for your CISO, your annual certification (§500.17), or your pen test (§500.05).
- It does **not** cover identity, MFA, training, or any of the other 17 sections. Don't-Lie is one control in the program.
- It does **not** certify your AI provider. Get theirs.
- It does **not** host your storage. The 5-year retention is your S3 bucket, your Azure blob, or whatever you operate.

## A practical example

A covered entity's fraud-detection AI flags a customer transaction as suspicious. The customer disputes the flag, claiming the AI was wrong. The covered entity's incident response team needs to:

1. Reconstruct the AI's reasoning for the flag (the receipt)
2. Show the byte-exact prompt and response (the receipt chain)
3. Demonstrate the chain has not been edited (the verifier)
4. Hand the bundle to outside counsel (the portable bundle)

Total time: minutes, not days. The receipt is the forensic record that turns "the AI said so" into evidence.

For the 72-hour rule, if the AI is implicated in a covered cybersecurity event, the receipt chain lets the CISO identify every affected customer in seconds:
```bash
dontlie search "decision_actor:ai-fraud-detector AND timestamp:>2026-07-25" --json | jq '.receipts[].extra.patient_id'
```

## Where this fits in a typical Part 500 program

| Section | Don't-Lie contribution |
|---|---|
| §500.02 cybersecurity program | One control in the program |
| §500.03 cybersecurity policy | One section on receipt vault operations |
| §500.06 audit trail | **Strong** — direct implementation |
| §500.07 access privileges | Vault is operator-local; key access controls matter |
| §500.10 personnel | Enables the CISO and IR team |
| §500.11 third-party | Receipts support the AI provider assessment |
| §500.14 incident response | Strong — receipts are forensic evidence |
| §500.16 incident reporting | Strong — fast search across affected receipts |
| §500.17 annual certification | The receipt vault is one control the board attests to |

## Where to get help

- `docs/integrations/SIEM.md` — wire the receipts into your existing SIEM
- `docs/groundtruth.md` — vendor-independent route attestation (opt-in lane)
- GitHub Issues: open a question at `github.com/Matrix-ops77/dont-lie/issues`

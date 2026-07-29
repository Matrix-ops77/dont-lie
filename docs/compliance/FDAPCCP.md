# Don't-Lie & FDA PCCP for AI/ML-Enabled Devices — compliance memo

**Date:** 2026-07-28
**Audience:** SaMD (Software as a Medical Device) regulatory affairs lead, quality manager at an AI/ML-enabled medical device manufacturer, FDA submission lead
**Scope:** How Don't-Lie receipts help satisfy the audit-trail and evidence portions of the FDA's Predetermined Change Control Plan (PCCP) for AI-enabled device software functions, per the **final guidance issued 4 December 2024**.

> This memo is informational and is not legal advice. FDA submissions are the responsibility of the device manufacturer's regulatory affairs team and external regulatory counsel. Don't-Lie is not a SaMD and is not in the FDA submission path; this memo describes how Don't-Lie receipts support the evidence the manufacturer presents to FDA.

---

## What the FDA actually requires (the relevant subset)

| Source | Requirement | Applies to AI call receipts? |
|---|---|---|
| **FDA Final Guidance, "Marketing Submission Recommendations for a Predetermined Change Control Plan for Artificial Intelligence-Enabled Device Software Functions"** (issued 4 Dec 2024; finalized; docket FDA-2024-D-2338; primary at https://www.fda.gov/media/185050/download) | PCCP is optional; if used, manufacturer pre-authorizes specific modifications; each modification does not require a new 510(k) or PMA supplement | **Directly** — Receipts are the evidence that modifications were implemented as pre-authorized |
| **PCCP three components**: (1) Description of Modifications, (2) Modification Protocol, (3) Impact Assessment | Documentation + protocols + assessment | Strong — Receipt chain is the per-modification evidence base |
| **FDA / Health Canada / MHRA Joint Guiding Principles** for Good Machine Learning Practice for Medical Device Development (2021) and PCCP (2023) — five principles: focused, risk-based, traceability, transparency, data integrity | **Directly** — Receipts implement "traceability" + "data integrity" + "transparency" | **Directly** — Receipts are the strongest available implementation of these principles |
| **FDA 21 CFR Part 820** (Quality System Regulation; transitioning to QMSR aligned with ISO 13485:2016) | Design controls, document controls, change control | Partial — Receipts are design-history evidence |
| **21 CFR Part 11** | Electronic records and electronic signatures | Yes — Ed25519 signature is a Part 11-compatible electronic signature for the audit trail |
| **Predetermined Change Control Plan — final guidance scope**: broadened from "ML-enabled" to "AI-enabled" devices | Receipts cover both | **Directly** — Receipts are AI-call-level evidence regardless of whether the device is ML or rule-based |
| **FDA-Health Canada-MHRA PCCP Guiding Principles (2023)**: focused, risk-based, traceability, transparency, data integrity | Receipts are the per-call evidence for traceability and data integrity | **Directly** |

## What a Don't-Lie receipt proves (in an FDA PCCP context)

- That a specific AI call was made by the SaMD, with a specific prompt and response, at a specific time, signed by the manufacturer's key — byte-exact evidence of the AI's behavior on a given date
- That the chain of AI calls over time is unbroken, supporting the "traceability" principle in the joint FDA-Health Canada-MHRA guiding principles
- That the data fed into the model at inference time is preserved (the `prompt` field) — supports the "data integrity" principle
- That a model version change (e.g., v3.2 → v3.3) is visible in the receipt time-series as a clean cutover — the manufacturer can show the FDA reviewer "we deployed v3.3 on 2026-04-15 at 14:32 UTC; here are the receipts before and after"
- That the modification was implemented as described in the pre-authorized Modification Protocol (the receipt timestamps show the modification was implemented within the window the manufacturer told FDA to expect)
- That labeling updates required by the final guidance ("should be updated as modifications are implemented to include relevant information such as a description of which modifications were implemented; how the modifications were implemented; and how users will be informed of implemented modifications") have a corresponding receipt event
- That an incident or adverse event traceable to an AI modification can be reconstructed — the receipt chain shows the full sequence of inputs that produced the failure

## What a Don't-Lie receipt does **not** prove

- That the SaMD is itself safe and effective (the FDA's determination; the 510(k) / De Novo / PMA pathway; the manufacturer's clinical performance data)
- That the modification was *correct* in the clinical sense (validation is a separate QMS / SaMD validation problem)
- That the manufacturer's overall QMS is operating effectively (FDA inspection / MDSAP audit)
- That the upstream model is itself FDA-cleared (the model provider's clearance, if applicable)
- That the device's clinical performance has not regressed (separate performance-monitoring workstream; the receipt is the *data*, not the *metric*)

## What you need to do additionally

1. **Include Don't-Lie receipts in the PCCP submission as the "ongoing performance monitoring" evidence base.** The PCCP's Impact Assessment asks the manufacturer to describe how modifications will be monitored. Don't-Lie receipts are the byte-exact, hash-chained, signed evidence the manufacturer points the FDA reviewer to when a modification is implemented.
2. **For each pre-authorized modification in the PCCP, tag the corresponding receipts.** When v3.3 is deployed, the first receipt signed by v3.3 should carry `pccp_modification_id:M-001 model_version:v3.3 deployed_at:<ts>`. The FDA reviewer can then search the receipt chain for every receipt under v3.3 and validate the modification was implemented as described.
3. **Log modification deployment as a separate receipt.** When the modification goes live, log a `type:pccp_modification` receipt that records the modification ID, the model version, the deployer, the timestamp, and the configuration delta. This is the artifact the FDA reviewer uses to confirm the modification was implemented.
4. **Use the witness notary for Part 11-compliant timestamp anchoring.** The witness notary's co-signature provides the timestamp the FDA expects for "when was this modification implemented?" — important when the modification has a clinical-safety window. The witness notary is the strongest available evidence the timestamp is genuine.
5. **Bundle the receipts into the Design History File (DHF).** For each PCCP modification, the manufacturer's DHF should include a portable bundle of the receipts over the modification's life. The bundle is verifiable on a clean FDA reviewer laptop with `dontlie verify --export <bundle>`.
6. **For 21 CFR Part 11 compliance:** document the Ed25519 signing key in the manufacturer's Part 11 signature manifest. The receipt's signature is non-repudiable; the manufacturer's quality system is responsible for the key lifecycle (generation, rotation, revocation). The Compliance tier ($999/mo) supports HSM-backed key isolation for Part 11-grade key management.
7. **For the labeling-update requirement (final guidance):** when the manufacturer updates the Instructions for Use (IFU) to reflect a PCCP modification, log a `type:labeling_update` receipt that captures the IFU version before and after. This proves the manufacturer updated the labeling "as modifications are implemented" as the guidance requires.
8. **For the joint FDA-Health Canada-MHRA principles:** document how the receipt chain satisfies "traceability" and "data integrity" in the PCCP's Modification Protocol. A one-page addendum is sufficient; the FDA reviewer expects to see this.
9. **Document the gaps from the Reasonable Doubt panel in the PCCP's Impact Assessment.** Specifically RD #2 (was the proxy process compromised?) and RD #3 (was the call authorized?) — these are the questions an FDA inspector is most likely to press. The manufacturer's QMS should have a written answer.

## What Don't-Lie does **not** do for FDA

- It is **not** a SaMD. Don't-Lie is a receipt-vault library, not a medical device.
- It does **not** perform clinical validation. That is the manufacturer's responsibility, under the manufacturer's QMS, with the manufacturer's clinical evidence.
- It does **not** substitute for the 510(k) / De Novo / PMA pathway. The PCCP is a supplement, not a replacement.
- It does **not** issue FDA clearance or approval. Only FDA does.
- It does **not** provide the model's performance metrics (accuracy, sensitivity, specificity, etc.). The receipt is the *audit trail*; the metrics are the *clinical performance* — separate workstream.

## Where Don't-Lie fits in a typical FDA AI/ML SaMD PCCP

| PCCP component | Don't-Lie contribution |
|---|---|
| Description of Modifications | None directly — the manufacturer's description |
| Modification Protocol | **Strong** — receipts prove the modification was implemented as pre-authorized |
| Impact Assessment (data) | **Strong** — receipt chain is the per-call evidence base |
| Impact Assessment (analysis) | None — the manufacturer's analysis |
| Ongoing performance monitoring | **Strong** — receipts are the per-call data the monitoring is built on |
| Labeling updates | Enabling — receipt of the labeling-update event |
| Incident response | **Strong** — receipts are the incident-response forensic record |

## A practical example

A manufacturer of an AI-enabled cardiac arrhythmia detector submits a 510(k) with a PCCP covering four pre-authorized model modifications over the next 18 months. The FDA clears the device. Over the life of the PCCP, the manufacturer:

1. Runs the SaMD inference through the Don't-Lie proxy (the proxy is inside the manufacturer's infrastructure; the receipt is in the manufacturer's vault)
2. For each modification, logs a `pccp_modification_id:M-00X` receipt on the day the modification goes live
3. Tags every receipt with `model_version` so the time-series splits cleanly across versions
4. Uses the witness notary to co-sign the chain (Part 11-grade timestamp)
5. Quarterly, exports the bundle and attaches it to the DHF entry for the PCCP
6. On the FDA's annual inspection, the inspector asks "show me the evidence that modification M-002 was implemented as pre-authorized" — the manufacturer hands over the portable bundle, the inspector runs `dontlie verify` on a clean FDA laptop, gets a 30-second yes/no
7. Six months later, an adverse event report traces back to a specific AI call on a specific date. The manufacturer's recall team reconstructs the failure from the receipt chain.

Total integration: 1 day per SaMD. Total operator cost: $999/mo for the Compliance tier (HSM keys, witness notary, S3 Object Lock).

## Where to get help

- The Compliance tier includes a designated success engineer familiar with FDA QMS / Part 11 / PCCP submissions
- The witness notary (`docs/WITNESS_PROTOCOL.md` v0.4) is the strongest available timestamp evidence for Part 11-grade recordkeeping
- For SaMD manufacturers in the EU, the same receipt chain supports the EU AI Act (high-risk AI logging under Article 12) — one set of receipts, FDA PCCP + EU AI Act

## Sources

- FDA Final Guidance, "Marketing Submission Recommendations for a Predetermined Change Control Plan for Artificial Intelligence-Enabled Device Software Functions" (4 Dec 2024, primary): https://www.fda.gov/media/185050/download
- FDA guidance landing page: https://www.fda.gov/regulatory-information/search-fda-guidance-documents/predetermined-change-control-plans-medical-devices
- FDA CDRH webinar transcript (Dec 2024): https://www.fda.gov/media/187905/download
- FDA / Health Canada / MHRA Joint Guiding Principles for PCCP (2023): https://www.fda.gov/medical-devices/software-medical-device-samd/predetermined-change-control-plans-machine-learning-enabled-medical-devices-guiding-principles
- FDA / Health Canada / MHRA Good Machine Learning Practice for Medical Device Development (2021): https://www.fda.gov/medical-devices/software-medical-device-samd/good-machine-learning-practice-machine-learning-enabled-medical-devices
- Ropes & Gray analysis: https://www.ropesgray.com/en/insights/alerts/2024/12/fda-finalizes-guidance-on-predetermined-change-control-plans-for-ai-enabled-device
- McDermott Will & Emery: https://www.mcdermottlaw.com/insights/fda-issues-final-guidance-on-predetermined-change-control-plans-for-ai-enabled-devices/
- King & Spalding: https://www.kslaw.com/news-and-insights/fda-publishes-final-predetermined-change-control-plan-guidance-for-ai-enabled-device-software-functions
- 21 CFR Part 11 (Electronic Records; Electronic Signatures): https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11
- 21 CFR Part 820 (Quality System Regulation; transitioning to QMSR): https://www.ecfr.gov/current/title-21/chapter-I/subchapter-H/part-820

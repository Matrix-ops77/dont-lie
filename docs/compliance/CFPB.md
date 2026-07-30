# Don't-Lie & CFPB — adverse action notices with AI (compliance memo)

**Date:** 2026-07-28
**Audience:** Compliance officer at a creditor or lender, model risk management lead, fair-lending counsel
**Scope:** How Don't-Lie receipts help meet CFPB Circulars 2022-03 and 2023-03 and the underlying ECOA / Regulation B requirements when AI is used in adverse action decisions.

> This memo is informational and is not legal advice. The creditor's compliance and fair-lending counsel must adapt any compliance position. CFPB enforcement actions and supervisory findings turn on facts the creditor's counsel is best positioned to evaluate.

---

## What ECOA / Regulation B actually requires (the relevant subset)

| Citation | Requirement | Applies to AI call receipts? |
|---|---|---|
| **Equal Credit Opportunity Act (ECOA), 15 U.S.C. §1691 et seq.** | Prohibits discrimination in credit; requires specific reasons for adverse action | Yes — the receipt is the byte-exact evidence of what the AI said |
| **12 CFR Part 1002 (Regulation B), §1002.9** | Adverse action notice within 30 days, with up to four principal reasons specific and accurate | Partial — Receipt proves the model said X; it does not produce the reason codes |
| **CFPB Circular 2022-03** (May 2022; https://www.consumerfinance.gov/compliance/circulars/circular-2022-03-adverse-action-notification-requirements-in-connection-with-credit-decisions-based-on-complex-algorithms/) | "ECOA and Regulation B do not permit creditors to use complex algorithms when doing so means they cannot provide the specific and accurate reasons for adverse actions" | **Directly** — Receipts are the artifact that proves the creditor can provide specific and accurate reasons |
| **CFPB Circular 2023-09** (19 Sep 2023; https://files.consumerfinance.gov/f/documents/cfpb_adverse_action_notice_circular_2023-09.pdf) | Reaffirms 2022-03; addresses the "black box" problem; emphasizes accuracy of disclosed reasons over completeness | **Directly** — the Receipt is the byte-exact evidence of the model's actual reasoning as expressed in the response |
| **SCAN review** (per Seiright's creditor guide) | Specific, Causal, Accurate, Non-discriminatory review of the four reasons on every adverse action notice | Partial — Receipt provides the artifact; creditor's compliance team produces the SCAN finding |

## What a Don't-Lie receipt proves (in an adverse-action context)

- That on a specific date, for a specific applicant, the creditor's AI was called with a specific prompt and produced a specific response (e.g., "recommend denial — debt-to-income ratio 0.52, no recent revolving installment credit, length of credit history 14 months")
- That the response bytes have not been altered (Ed25519 + SHA-256 chain) — the four reasons the creditor disclosed in the adverse action notice can be traced to the model output that produced them
- That the model version is recorded (in the receipt's `model` field) — so when the creditor updates the model from v3.2 to v3.3, the time-series of decisions is split cleanly across versions, and the creditor can show the examiner "v3.2 made this decision; v3.3 was deployed later"
- That the call was logged at the moment it was made (timestamp) and not reconstructed after the fact — closes the "you made up the reasons after the consumer complained" risk
- That the same signing key signed every receipt (a Reasonable Doubt flag if the key was rotated mid-period; the credential supports "we did not edit the history because we did not have the key")

## What a Don't-Lie receipt does **not** prove

- That the four reasons disclosed in the adverse action notice are the **right** four reasons. The creditor must select the four principal reasons; the receipt shows what the model said; the creditor's compliance team decides what to disclose.
- That the model output is **non-discriminatory**. The receipt captures what the model said; fair-lending testing (disparate impact analysis, ECOA Special Purpose Credit Programs, etc.) is a separate workstream.
- That the model itself complies with §1002.6 (rules against discrimination) or with the creditor's model risk management policy. The receipt is an evidence substrate, not a model validation.
- That the upstream LLM provider (OpenAI, Anthropic, etc.) is not itself logging the call. The receipt proves the creditor's side; the creditor's data processing agreement with the AI provider is what governs the provider's side.

## What you need to do additionally

1. **Use the receipt as the byte-exact record of the model's reasoning.** When the LLM is used to generate the narrative for an adverse action notice ("Dear applicant, the principal reason for our decision is…"), the receipt is the artifact that proves what the model actually said. The compliance team can then verify the disclosed reasons match the model output.
2. **Maintain a reason-code dictionary with version history.** CFPB examiners expect "the model card and validation report, the reason-code dictionary with version history, **a CSV of every adverse action issued in the period with the model version, top features, reasons given, language, and timestamp**" (per https://www.seiright.com/blog/adverse-action-notices-ai-credit-decisions-ecoa-reg-b). Don't-Lie receipts cover the last four fields. The reason-code dictionary and top features are the model's, not the receipt's — but the receipt is the join key.
3. **Tag every receipt with the application ID and the decision outcome.** Pattern:
   ```python
   with dontlie_agent.installed() as h:
       client.chat.completions.create(
           model="...",
           messages=[...],
           extra_tags={
               "application_id": app_id,
               "decision_outcome": "adverse",
               "model_version": "credit-narrative-v3.2",
               "principal_reasons": "debt_to_income,credit_history_length,no_revolving_credit",
           },
       )
   ```
4. **Run `dontlie search "decision_outcome:adverse AND timestamp:[start] TO [end]"` to produce the SCAN review set.** The search returns every receipt in the period; the compliance team maps each to the disclosed reason codes and runs the SCAN rubric.
5. **For the 30-day notice deadline (12 CFR §1002.9):** the receipt is the timestamp of when the decision was made. The 30-day clock starts at `created_at`. This is the strongest available evidence the creditor met the 30-day window.
6. **Anchor the chain via the witness notary.** A consumer disputes the adverse action two years later. The creditor's evidence is the receipt. The witness notary's co-signature is the strongest evidence the timestamp is genuine. Without the witness notary, a consumer's forensic expert can argue the timestamp was backdated.
7. **For creditors using on-device LLMs (no third-party API), the receipt is even more important.** If the model runs locally, the upstream provider logging risk goes away — but the creditor still has to prove what the model said to whom and when. Don't-Lie is the evidence.
8. **Document the gaps from the Reasonable Doubt panel.** In particular, RD #3 (was the call authorized?) is the question a CFPB examiner is most likely to press. The creditor's intake workflow must tag authorized calls (e.g., the call was triggered by the underwriting engine, not a rogue employee experiment).

## What Don't-Lie does **not** do for CFPB / ECOA

- It does **not** generate the four principal reasons. The creditor's compliance team selects the four reasons; the model output informs the selection.
- It does **not** perform fair-lending testing (disparate impact, ECOA §1002.6). The receipt captures what the model said; whether the model is discriminatory is a separate model-risk workstream.
- It does **not** issue the adverse action notice. The creditor's notice generation system issues the notice; the receipt is the underlying evidence.
- It does **not** substitute for the creditor's compliance program, model risk management, or fair-lending testing. It is one control in the program.

## Where Don't-Lie fits in a typical CFPB examination

| Exam request | Don't-Lie contribution |
|---|---|
| "Show me every adverse action you issued last quarter" | `dontlie search "decision_outcome:adverse" --bundle` |
| "Show me the model version that made this decision" | `model_version` tag in every receipt |
| "Show me the actual prompt and response for this applicant" | `dontlie search "application_id:X"` — single receipt, byte-exact |
| "Show me that the disclosed reasons match the model output" | Join receipt's `response` field to the notice's `principal_reasons` field |
| "Show me the integrity of your audit trail" | `dontlie verify --export <bundle>` — 30 seconds, signed verdict |
| "How do you know your AI didn't make this decision based on a prohibited basis?" | Receipt is the *audit trail*, not the *fair-lending test* — point the examiner to your separate disparate-impact analysis |

## A practical example

A regional bank uses an LLM to generate the narrative portion of adverse action notices. CFPB examiners arrive for a fair-lending examination and ask for "every adverse action issued in the period with the model version, top features, reasons given, language, and timestamp" (per the SCAN review framework). The bank's compliance team:

1. Runs `dontlie search "decision_outcome:adverse AND timestamp:[2026Q1]"` — gets a JSON manifest of every adverse action the AI helped draft
2. Exports to CSV with `model_version`, `principal_reasons`, `language`, `created_at` columns
3. Joins to the bank's own reason-code dictionary
4. Runs the SCAN rubric (Specific, Causal, Accurate, Non-discriminatory) on a sample
5. Hands the examiner a portable bundle (`audit-2026Q1.bundle.json`), verifies in 30 seconds on a clean examiner laptop
6. The examiner's report cites the bank's audit trail as "machine-verifiable, tamper-evident, and complete"

Total time: 1 day of integration. Total operator cost: software is free under MIT; the storage, the witness, the deployment, the SCAN review work, and the SCAN rubric scoring are not.

## Where to get help

- `docs/groundtruth.md` — vendor-independent route attestation (opt-in lane)
- GitHub Issues: open a question at `github.com/Matrix-ops77/dont-lie/issues`
- The Reasonable Doubt panel in every bundle names the 5 gaps the receipts do not close. Your SCAN response should explicitly address each one.

## Sources

- CFPB Circular 2022-03 (primary): https://www.consumerfinance.gov/compliance/circulars/circular-2022-03-adverse-action-notification-requirements-in-connection-with-credit-decisions-based-on-complex-algorithms/
- CFPB Circular 2023-09 (PDF, primary): https://files.consumerfinance.gov/f/documents/cfpb_adverse_action_notice_circular_2023-09.pdf
- 15 U.S.C. §1691 et seq. (ECOA): https://www.govinfo.gov/app/details/USCODE-2023-title15/USCODE-2023-title15-chap41-subchapIV
- 12 CFR Part 1002 (Regulation B): https://www.consumerfinance.gov/rules-policy/regulations/1002/
- 12 CFR §1002.9 (adverse action notice content and timing): https://www.consumerfinance.gov/rules-policy/regulations/1002/9/
- Skadden analysis: https://www.skadden.com/insights/publications/2024/01/cfpb-applies-adverse-action-notification-requirement
- Venable analysis: https://www.venable.com/insights/publications/2023/09/cfpb-weighs-in-on-credit-denials-by-lenders
- Seiright SCAN rubric: https://www.seiright.com/blog/adverse-action-notices-ai-credit-decisions-ecoa-reg-b

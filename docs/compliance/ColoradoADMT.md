# Don't-Lie & Colorado ADMT Act (SB 24-205 + SB 26-189) — compliance memo

**Date:** 2026-07-28
**Audience:** Compliance officer at a Colorado-deploying AI developer or deployer, in-house counsel, product lead for high-risk AI
**Scope:** How Don't-Lie receipts help meet Colorado's AI regime, with attention to the **1 January 2027 effective date** of the new ADMT Act (SB 26-189) and the 30 June 2026 effective date of SB 24-205 (as pushed by SB 25B-004).

> This memo is informational and is not legal advice. Colorado's AI regime is evolving rapidly; confirm the latest effective dates, the AG's rulemaking, and the specific classification of your system with Colorado-licensed counsel.

---

## What Colorado law actually requires (the relevant subset)

| Source | Requirement | Applies to AI call receipts? |
|---|---|---|
| **SB 24-205** — Consumer Protections for Artificial Intelligence (signed 17 May 2024; effective 30 June 2026 per SB 25B-004) | Risk management, impact assessment, annual review, consumer notice, consumer right to correct and appeal, AI disclosure | **Directly** — Receipts are the impact-assessment evidence base |
| **SB 26-189** — "Automated Decision-Making Technology Act" (ADMT Act, signed May 2026; effective 1 Jan 2027) | Re-enacts and expands SB 24-205; broader scope of "high-risk" ADMT; new developer + deployer duties | **Directly** — Receipts are the audit trail for the new ADMT regime |
| **Colorado AG AI page** (https://coag.gov/ai/) | AG rulemaking, guidance, enforcement priorities | Partial — Receipts support the AG's evidence request under the 90-day disclosure rule |
| **"Consequential decision"** (SB 24-205 §6-1-1701 et seq., as amended) | Education, employment, financial services, healthcare, housing, insurance, legal services, essential government services | All consequential decisions — the Receipt is the byte-exact record |
| **Developer 90-day disclosure** to AG and known deployers of discovered algorithmic discrimination risk | Receipt chain is the discovery record | **Directly** — the Receipt timestamps when the developer became aware |
| **Deployer annual impact assessment + annual review** | Receipts are the per-call evidence | **Directly** — Receipt chain over the year is the impact-assessment data |
| **Consumer notice + right to correct + right to appeal** | Receipts prove the consumer was notified, what was decided, and the underlying AI call | Partial — Receipt proves the call; notice is the deployer's workflow |
| **AI disclosure to consumer** when AI is intended to interact with a consumer | Receipts log the interaction | Partial — Receipt is the audit trail; the disclosure is the deployer's UX |

## What a Don't-Lie receipt proves (in a Colorado ADMT context)

- That a specific consumer was subject to a specific consequential decision by an AI, at a specific time, with a specific prompt and response — byte-exact
- That the deployer did not silently alter the call record after the fact (Ed25519 + SHA-256 chain)
- That the model version is recorded, so the deployer can show "v3.2 made this decision; we switched to v3.3 in March after the AG's guidance update" — a clean cutover line
- That the consumer notice obligation was met: a Receipt tagged `notice_sent:true timestamp:<notice_datetime>` proves the deployer notified the consumer within whatever window the AG's rules require
- That the consumer's appeal was logged: a Receipt of `type:appeal decision_id:<id> actor:human-reviewer` proves the right-to-appeal was honored
- That the 90-day developer disclosure clock started at a specific time: a Receipt tagged `type:incident discovery:algorithmic_discrimination` is the strongest available evidence the developer met the 90-day AG disclosure window

## What a Don't-Lie receipt does **not** prove

- That the deployer actually performed the impact assessment (the deployer must produce the assessment; the Receipts are the underlying evidence, not the assessment itself)
- That the AI system is "high-risk" within the meaning of the ADMT Act (the deployer's classification; the Receipt is the call log, not the classification)
- That the model is non-discriminatory (separate testing, separate workstream)
- That the consumer was correctly notified (the deployer's notice workflow; the Receipt proves the workflow ran, not that the content of the notice was correct)

## What you need to do additionally

1. **Classify your system as in-scope or out-of-scope for "consequential decision" ADMT.** If your system makes or substantially influences a decision in education, employment, financial services, healthcare, housing, insurance, legal services, or essential government services, the ADMT Act applies. The Receipt is in-scope from day one; the Receipt does not tell you whether the AI is in-scope.
2. **Run the receipt vault inside the consumer's data jurisdiction.** The Receipt contains the consumer's personal data (potentially). The ADMT Act interacts with the Colorado Privacy Act (CPA) and (if the consumer is in the EU/UK) GDPR. Local-first is the cleanest answer; the Solo tier keeps the vault on the deployer's machine. The Compliance tier offers a customer-controlled S3 bucket in the deployer's chosen region.
3. **Tag every receipt that supports a consequential decision.** Pattern:
   ```python
   with dontlie_agent.installed() as h:
       client.chat.completions.create(
           model="...",
           messages=[...],
           extra_tags={
               "consumer_id": c_id,
               "decision_type": "employment_screening",  # or healthcare_allocation, etc.
               "notice_sent": True,
               "appeal_window_open": True,
               "model_version": "screen-v2.1",
           },
       )
   ```
4. **Maintain the impact assessment alongside the receipts.** The deployer's annual impact assessment should be a separate document (per AG guidance). Append the relevant receipt bundle as an exhibit. The AG's enforcement priority will be the deployer who can produce *both* the assessment and the underlying call evidence — Don't-Lie gives you the second half for free.
5. **Log the human-appeal event as a receipt.** When the consumer appeals, create a receipt of `type:appeal_actor:human-reviewer decision_id:<id> outcome:<upheld|reversed>`. This proves the right-to-appeal was honored. Pattern:
   ```python
   storage.append(
       model="human-review",
       prompt=f"appeal of decision {decision_id}",
       response=appeal_outcome,
       tags=[f"decision_id:{decision_id}", "actor:human", "type:appeal"],
   )
   ```
6. **For developer-side 90-day disclosure: log the discovery event.** The moment the developer becomes aware of algorithmic discrimination risk, log a receipt of `type:incident discovery:algorithmic_discrimination`. The 90-day clock starts at `created_at`. This is the strongest available evidence the developer met the 90-day AG disclosure window.
7. **Anchor the chain via the witness notary for the AG's enforcement record.** The AG's enforcement actions are timestamp-sensitive (the 90-day disclosure window is one example). The witness notary's co-signature is the strongest available evidence the timestamp is genuine. Without it, the deployer is exposed to a "you backdated the discovery record" argument.
8. **Document the gaps from the Reasonable Doubt panel.** Specifically RD #1 (who held the key), RD #3 (was the call authorized), and RD #5 (timestamp anchoring) — these are the three the AG is most likely to press in an enforcement action.

## What Don't-Lie does **not** do for Colorado ADMT

- It does **not** classify your system as "high-risk ADMT" (the deployer does that)
- It does **not** perform the impact assessment (the deployer does that; the receipts are the data)
- It does **not** satisfy the consumer notice obligation (the deployer's UX does that; the receipt is the audit trail)
- It does **not** submit the AG disclosure (the developer does that; the receipt of the discovery event is the timestamp)

## Where Don't-Lie fits in a typical Colorado ADMT program

| ADMT workstream | Don't-Lie contribution |
|---|---|
| Risk management policy + program | None directly — the deployer's policy |
| Impact assessment | **Strong** — receipt chain is the per-call evidence |
| Annual review for discrimination | Strong — receipt chain over the year, tagged with consumer_id |
| Consumer notice | Enabling — receipt proves the notice was sent |
| Consumer right to correct | Enabling — receipt of the correction event |
| Consumer right to appeal | **Strong** — receipt of the human-review event |
| AI disclosure to consumer | Enabling — receipt of the disclosure event |
| Developer 90-day AG disclosure | **Strong** — receipt of the discovery event is the timestamp |
| Recordkeeping (deployer) | **Strong** — receipt chain is the record |

## A practical example

A Colorado-based employer uses an AI-assisted resume screener that filters applicants for a high-volume role. The screener is a "high-risk ADMT" because employment decisions are a "consequential decision" under SB 24-205 / SB 26-189. The employer:

1. Confirms classification with counsel (the Receipt doesn't classify)
2. Runs the screener through the Don't-Lie proxy
3. Tags every receipt with `consumer_id`, `decision_type:employment_screening`, `model_version`, `notice_sent`
4. Logs the consumer notice event as a separate receipt when the rejection email goes out
5. Logs the human-review event as a receipt when an applicant appeals
6. Once a year, exports the bundle (`audit-2026.bundle.json`), attaches it to the impact assessment
7. The AG, if asked, runs `dontlie verify --export <bundle>` on a clean laptop and gets a 30-second yes/no

If, mid-year, the developer (a third-party AI vendor) discovers a discrimination risk in the screener model, the developer logs a receipt of `type:incident discovery:algorithmic_discrimination` and the 90-day AG disclosure clock starts at that timestamp. The deployer can then point to the receipt and say "we knew on day X and disclosed to the AG on day X+72, within the 90-day window."

Total time: 1 day of integration. Total operator cost: $0 Solo, $19/seat/mo Pro, $999/mo Compliance (with HSM keys + witness notary for timestamp anchoring).

## Where to get help

- The Compliance tier includes a designated success engineer familiar with the Colorado AG's ADMT rulemaking
- The witness notary (`docs/WITNESS_PROTOCOL.md` v0.4) is the strongest available timestamp evidence — especially important for the 90-day developer disclosure window
- The Team tier ($199/mo) includes multi-user signing keys, which is the right tier for an employment-ops team where multiple reviewers need to sign the chain
- For multi-state deployers, the same receipt chain satisfies California AB 2013 (training-data provenance) and the Colorado ADMT Act simultaneously — one set of receipts, multiple regimes

## Sources

- Colorado AG AI page (primary): https://coag.gov/ai/
- SB 24-205 bill page (primary): https://leg.colorado.gov/bills/sb24-205
- Brownstein Hyatt Farber Schreck analysis: https://www.bhfs.com/insight/colorados-landmark-ai-law-coming-online-what-developers-and-deployers-should-know/
- TrustArc compliance guide: https://trustarc.com/resource/colorado-ai-law-sb24-205-compliance-guide/
- NAAG deep dive: https://www.naag.org/attorney-general-journal/a-deep-dive-into-colorados-artificial-intelligence-act/
- SB 25B-004 (effective date push to 30 June 2026) — see Colorado General Assembly bill page
- SB 26-189 (ADMT Act) — see https://coag.gov/ai/ and Colorado General Assembly bill page
- California AB 2013 (Generative AI Transparency Act, signed 28 Sept 2024): https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202320240AB2013

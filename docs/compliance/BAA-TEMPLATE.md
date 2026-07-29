# Business Associate Agreement — Don't-Lie (template)

**Version:** 1.0 — 2026-07-28
**For adaptation by:** Covered Entity (healthcare provider, plan, clearinghouse, or business associate of any of the above)
**Counterparty:** Don't-Lie (the Business Associate)
**Modeled on:** HHS Sample Business Associate Agreement, https://www.hhs.gov/sites/default/files/model-business-associate-agreement.pdf
**Statutory basis:** 45 CFR §164.504(e) and the HIPAA Rules at 45 CFR Parts 160, 162, and 164.

> This is a **template**. It is not legal advice. The Covered Entity's counsel must adapt, complete the bracketed fields, and confirm the final language before execution. Don't-Lie provides this template as a starting point for the conversation.

---

## Why this BAA is short (read this first)

Most Business Associate Agreements run 25 to 35 pages because the Business Associate is hosting Protected Health Information ("PHI") on the BA's servers, in the BA's database, behind the BA's perimeter. The BAA has to spell out how the BA will protect, retain, return, and destroy that hosted PHI. The size of the document is roughly proportional to the amount of PHI the BA holds.

Don't-Lie is a **local-first signed-receipt vault**. The Customer's Covered Entity runs the Don't-Lie software **inside the Covered Entity's own infrastructure**. Don't-Lie does not receive, store, transmit, or process the Covered Entity's PHI on Don't-Lie-controlled systems. The only data Don't-Lie ever holds is the signing keypair (which is not PHI) and, for the hosted Compliance tier, the customer-uploaded vault bundle (which is the customer's data, stored under the customer's S3 Object Lock retention, in a customer-controlled bucket).

That is why this BAA is 5 to 6 pages instead of 30. The clauses that most BAAs use to govern "what the BA does with our hosted PHI" shrink to "there is no hosted PHI," and the obligations the BAA does retain are the ones the Covered Entity's regulator (HHS OCR) will still want to see: notice of breaches that affect the BA's handling of the keychain, the right to terminate, and the absence of subcontractor risk for the local-first tier.

If the Covered Entity is purchasing the **Compliance tier** (the only tier in which any data leaves the customer's machine), the hosted-vault subsection [bracketed as §7 below] must be selected and completed. If the Covered Entity is using the **Solo or Pro tier** (local-only), §7 may be struck in its entirety.

---

## 1. Definitions

Capitalized terms have the meaning given in the HIPAA Rules (45 CFR §160.103, §164.501). For convenience:

- **"Business Associate"** ("BA") means **Don't-Lie** (the party signing this agreement), including its employees, contractors, and agents. In the local-first tier, Don't-Lie is a Business Associate only in the technical sense of §164.504(e) because the Don't-Lie software runs inside the Covered Entity's environment; Don't-Lie does not receive PHI on its own systems.
- **"Covered Entity"** ("CE") means [name of healthcare provider, plan, clearinghouse, or business associate] identified in the signature block.
- **"Protected Health Information"** ("PHI") has the meaning given at 45 CFR §160.103, limited to the PHI that the Covered Entity routes through the Don't-Lie proxy for signed-receipt purposes.
- **"Designated Record Set"** has the meaning given at 45 CFR §164.501. **For the local-first tier, the Covered Entity's Don't-Lie vault is *not* a Designated Record Set of the Business Associate — it is a Designated Record Set of the Covered Entity**, because the vault file resides on the Covered Entity's systems and is controlled by the Covered Entity.
- **"Individual"** has the meaning given at 45 CFR §160.103 and includes a person who is the subject of PHI.
- **"HIPAA Rules"** means the Privacy, Security, Breach Notification, and Enforcement Rules at 45 CFR Parts 160 and 164.
- **"Receipt"** means a single signed record produced by the Don't-Lie proxy: a SHA-256 hash, an Ed25519 signature, the original prompt and response bytes, a timestamp, the model identifier, and a chain pointer to the previous receipt. A Receipt may contain PHI to the extent the underlying LLM call contained PHI.
- **"Vault"** means the file (SQLite database or encrypted bundle) holding the Covered Entity's chain of Receipts, residing on the Covered Entity's machine.
- **"Hosted Vault"** means, only if the Covered Entity purchases the Compliance tier, the encrypted copy of the Vault uploaded to the Covered Entity's customer-controlled S3 bucket with Object Lock retention.

## 2. Permitted Uses and Disclosures by the Business Associate

2.1 The Business Associate may use or disclose PHI **only as follows**:

(a) To **sign and verify Receipts** at the direction of the Covered Entity. Signing consists of computing a SHA-256 hash of the prompt and response bytes and signing the hash with the Ed25519 key generated on the Covered Entity's machine. Verification consists of recomputing the hash chain and validating the Ed25519 signature against the Covered Entity's published public key.

(b) To **provide the Don't-Lie software** (proxy, CLI, libraries) to the Covered Entity under the license terms in effect between the parties.

(c) To **make Receipts available to the Covered Entity** through the standard APIs (CLI: `dontlie verify`, `dontlie export`, `dontlie trust-score`; UI: the local web console).

(d) As otherwise **required by law**, subject to §2.2.

2.2 If the Business Associate is required by law to disclose PHI (e.g., a court order), the Business Associate shall, to the extent permitted by law and reasonably practicable, provide the Covered Entity with prompt written notice of the requirement so that the Covered Entity may seek a protective order or other appropriate remedy.

2.3 The Business Associate shall **not use or disclose PHI in a manner that would violate Subpart E of 45 CFR Part 164 if done by the Covered Entity**, except for the specific uses and disclosures expressly permitted under §2.1.

## 3. Safeguards

3.1 The Business Associate agrees to use appropriate safeguards, and comply, where applicable, with Subpart C of 45 CFR Part 164, to prevent the use or disclosure of PHI other than as provided for by this Agreement. In the local-first tier, the relevant safeguards are those in the Don't-Lie software as deployed by the Covered Entity:

- **Hashing:** SHA-256 over the canonicalized prompt and response bytes.
- **Signing:** Ed25519 (RFC 8032) using a key generated on the Covered Entity's machine.
- **Key storage:** the Ed25519 private key is stored in the Covered Entity's OS keychain (macOS Keychain, Windows Credential Manager, or Linux Secret Service) by default; the public key is published by the Covered Entity.
- **Chain integrity:** every receipt includes a `parent_hash` pointer to the previous receipt, forming a tamper-evident chain. Any modification to a historical receipt invalidates every subsequent receipt's signature.
- **No telemetry:** the local-first tier does not phone home. The Don't-Lie proxy makes no outbound calls except to the upstream AI provider the Covered Entity has configured.
- **At-rest encryption (optional, Compliance tier):** the Vault may be exported as an age-encrypted bundle; the Compliance tier additionally supports AES-256-GCM at rest in the Hosted Vault bucket.

3.2 The Business Associate shall, where applicable and to the extent it holds PHI on its own systems (only in the Compliance tier), comply with the applicable provisions of the Security Rule with respect to electronic PHI, including §164.308 (administrative safeguards), §164.310 (physical safeguards), §164.312 (technical safeguards), and §164.316 (policies, procedures, and documentation).

3.3 The Business Associate shall report to the Covered Entity any security incident of which it becomes aware affecting the signing keychain or the Hosted Vault, in accordance with §5 below.

## 4. Subcontractors

4.1 The Business Associate shall, in accordance with 45 CFR §164.502(e)(1)(ii) and §164.308(b)(2), ensure that any subcontractor that creates, receives, maintains, or transmits PHI on behalf of the Business Associate agrees in writing to substantially the same restrictions, conditions, and requirements that apply to the Business Associate under this Agreement.

4.2 **For the local-first tier (Solo and Pro):** the Business Associate has **no subcontractors** that receive PHI. The Don't-Lie proxy runs on the Covered Entity's machine and does not transmit PHI to Don't-Lie. No subcontractor agreement is required for this tier.

4.3 **For the Compliance (hosted) tier:** the Business Associate may engage the following categories of subcontractor to provide cloud storage and infrastructure for the Hosted Vault only:

- **Cloud object storage provider** (currently Amazon Web Services S3, customer-controlled bucket).
- **Key management service** (the customer controls the bucket-level KMS key; the BA does not hold the customer KMS key).
- **Witness notary** (third-party timestamp-anchoring co-signer, listed at https://dontlie.example/legal/subprocessors).

The current list of subcontractors, with the country in which each is located and a description of the service provided, is published at the URL above. The Business Associate shall provide the Covered Entity with at least **30 days' written notice** of any new subcontractor, and the Covered Entity may terminate this Agreement if the Covered Entity reasonably objects to the new subcontractor on the basis of PHI handling.

## 5. Reporting

5.1 **Breach notification.** The Business Associate shall report to the Covered Entity any breach of unsecured PHI of which the Business Associate becomes aware, in accordance with 45 CFR §164.410. The Business Associate shall provide such notification **without unreasonable delay and in no case later than 60 calendar days** after discovery of the breach, except as permitted by §164.412 for law enforcement delay. The notification shall include, to the extent possible: (a) the identification of each Individual whose unsecured PHI has been, or is reasonably believed to have been, accessed, acquired, used, or disclosed; (b) a description of what occurred; (c) the types of PHI involved; (d) the steps the Business Associate is taking to mitigate and protect against further breaches; and (e) the steps the Covered Entity should take to mitigate potential harm.

5.2 **Reasonableness of the 60-day window.** For the local-first tier, the Business Associate typically has no PHI and therefore no breach to report under this section. The 60-day window is selected (rather than HHS's "without unreasonable delay" standard) because the Business Associate may first need to ascertain whether the signing keychain was compromised (which would constitute a reportable event under HHS guidance), and that investigation may take time. The Covered Entity is not precluded from reporting the breach to HHS OCR sooner if the Covered Entity's own investigation is faster.

5.3 **Security incidents that are not breaches.** The Business Associate shall report to the Covered Entity any attempted or successful unauthorized access, use, disclosure, modification, or destruction of the signing keychain or the Hosted Vault, and any interference with the Business Associate's information system activities, in accordance with 45 CFR §164.314(a)(2)(i)(C) and §164.314(b)(2)(i)(C). Such report shall be made within 30 calendar days of discovery.

5.4 The Business Associate's reporting obligations under this §5 are not a substitute for the Covered Entity's own reporting obligations under 45 CFR §164.402, §164.404, §164.406, and §164.408.

## 6. Access, Amendment, and Accounting

6.1 **Access by Individuals.** In the local-first tier, the Business Associate does not hold the Vault and cannot provide direct access to the Vault; the Covered Entity, as the custodian of the Vault, is responsible for responding to Individuals' requests for access to their own PHI under 45 CFR §164.524. The Business Associate shall, on the Covered Entity's reasonable request, provide documentation, verification tools, and reasonable assistance to enable the Covered Entity to fulfill the Individual's access request. The standard Don't-Lie CLI command for producing an Individual's records is `dontlie search "patient_id:<id>" --bundle --output individual-<id>.bundle.json`.

6.2 **Amendment.** The Covered Entity is responsible for responding to amendment requests under 45 CFR §164.526. The Business Associate shall not amend a Receipt (and cannot, as the Vault is append-only by cryptographic design — any amendment is a new Receipt referencing the original). If the Covered Entity determines that a Receipt must be amended, the Covered Entity shall create an amendment Receipt that references the original by hash and includes the correct information. The Business Associate's CLI supports this via `dontlie append --parent <hash> --type amendment`.

6.3 **Accounting of disclosures.** The Covered Entity is responsible for responding to requests for an accounting under 45 CFR §164.528. The Business Associate shall, on the Covered Entity's request, export the relevant Receipts as a portable bundle so the Covered Entity can compile the accounting. The Business Associate's standard `dontlie search` and `dontlie export --bundle` commands produce the audit-quality CSV-equivalent the Covered Entity needs.

6.4 **Independent verification — the wedge.** The Covered Entity and its regulators (HHS OCR, a state medical board, a court in a malpractice action) may verify any Receipt **on a clean laptop without the Business Associate's assistance**. The Business Associate publishes the verifier (`dontlie verify --export <bundle>`) under an open-source license; the verification operation takes under one second per 1,000 Receipts; and the verifier does not require network connectivity, the Business Associate's cooperation, or any Business Associate-held key material. This is the design intent of the local-first architecture: third-party verifiability is a property of the Receipt itself, not a service the Business Associate provides.

## 7. [Optional — Compliance tier only] Hosted Vault provisions

> Include this section only if the Covered Entity is purchasing the Compliance tier and a Hosted Vault exists.

7.1 The Business Associate shall store the Hosted Vault in the Covered Entity's customer-controlled S3 bucket under the Covered Entity's KMS key, with S3 Object Lock in COMPLIANCE mode set to the Covered Entity's chosen retention period (default 7 years; configurable up to the maximum supported by S3 Object Lock).

7.2 The Business Associate shall not access the contents of the Hosted Vault except (a) at the Covered Entity's written direction, (b) to provide the witness notary's co-signature, or (c) to perform integrity verification in response to a Covered Entity ticket.

7.3 On termination of this Agreement, the Hosted Vault remains in the Covered Entity's S3 bucket under the Covered Entity's Object Lock retention. The Business Associate's right to access the Hosted Vault terminates; the Business Associate does not hold the KMS key and therefore cannot decrypt the Hosted Vault. Return and destruction of PHI is governed by §8 below.

## 8. Return or Destruction of PHI

8.1 **Local-first tier.** On termination of this Agreement, the Business Associate has no PHI to return or destroy because the Business Associate never received PHI. The Vault resides on the Covered Entity's machine. The Covered Entity retains the Vault per its own retention obligations (45 CFR §164.530(j) — 6 years minimum). The Receipt itself is the "return" of the underlying call: the Covered Entity already has the byte-exact record of every LLM call the Covered Entity made.

8.2 **Hosted Vault tier.** On termination, the Business Associate shall, at the Covered Entity's election:

(a) **Return.** Provide the Covered Entity with a portable, encrypted bundle of the Hosted Vault and a copy of the signing key in a format the Covered Entity can load into a new installation of the Don't-Lie software. The Business Associate's `dontlie export --bundle` command produces this artifact.

(b) **Destroy.** Delete the Hosted Vault and the Business Associate's copy of the signing key. Because the Hosted Vault is under the Covered Entity's S3 Object Lock in COMPLIANCE mode, the Business Associate cannot delete the Covered Entity's copy; the Business Associate's destruction obligation is limited to the Business Associate's own working copies (if any).

8.3 If it is infeasible to return or destroy the PHI (e.g., the Hosted Vault is subject to legal hold), the Business Associate shall continue to extend the protections of this Agreement to the PHI for so long as the Business Associate maintains the PHI.

## 9. Term and Termination

9.1 **Term.** This Agreement is effective on the Effective Date and continues until terminated by either party.

9.2 **Termination by the Covered Entity.** The Covered Entity may terminate this Agreement upon 30 days' written notice to the Business Associate if the Covered Entity determines, in its reasonable discretion, that the Business Associate has violated a material term of this Agreement and the violation has not been cured. If cure is not feasible, the Covered Entity may terminate immediately on written notice.

9.3 **Termination by the Business Associate.** The Business Associate may terminate this Agreement upon 90 days' written notice to the Covered Entity. The Business Associate's principal termination right arises from a change in applicable law that materially affects the Business Associate's ability to perform under this Agreement, or from the Covered Entity's failure to pay fees owed under the parties' underlying license agreement.

9.4 **Effect of termination.** On termination, the Business Associate has no PHI to return or destroy in the local-first tier (§8.1). In the hosted tier, the Business Associate shall comply with §8.2. The provisions of this Agreement that by their nature should survive termination — including §3 (Safeguards) with respect to any residual keychain, §5 (Reporting) for incidents discovered after termination, §6 (Access, Amendment, and Accounting) with respect to records the Business Associate continues to hold, and §10 (Indemnification and Limitation of Liability) — shall survive.

## 10. Indemnification and Limitation of Liability

10.1 Each party shall indemnify the other against losses arising from the indemnifying party's gross negligence or willful misconduct in the performance of this Agreement, subject to the limitation of liability in the parties' underlying license agreement.

10.2 The Business Associate is not liable for the actions or omissions of the Covered Entity, the Covered Entity's employees, contractors, or agents, the upstream AI provider, or any third party who obtains access to the Vault through the Covered Entity's systems.

10.3 The Business Associate's total liability under this Agreement is limited to the cap set forth in the parties' underlying license agreement, except for liability arising from the Business Associate's gross negligence or willful misconduct.

## 11. General Provisions

11.1 **Amendment.** The parties shall amend this Agreement as required by changes in applicable law, including changes in the HIPAA Rules.

11.2 **Survival.** The provisions of this Agreement that by their nature should survive termination shall survive.

11.3 **Interpretation.** Any ambiguity in this Agreement shall be resolved to permit the parties to comply with the HIPAA Rules.

11.4 **Regulatory references.** A reference in this Agreement to a section of the HIPAA Rules means the section as in effect or as amended, and for which a corresponding transition provision may apply.

11.5 **Governing law.** This Agreement is governed by the laws of the State of [Delaware], without regard to its conflict-of-laws principles.

11.6 **Order of precedence.** In the event of a conflict between this Agreement and the parties' underlying license agreement, the terms of this Agreement control with respect to the handling of PHI.

---

## Signature block

**Covered Entity:**

By: ______________________________
Name: ____________________________
Title: ____________________________
Date: _____________________________

**Business Associate — Don't-Lie:**

By: ______________________________
Name: ____________________________
Title: ____________________________
Date: _____________________________

---

## Appendix A — Statutory citations referenced in this template

- **45 CFR §164.504(e)** — Uses and disclosures of protected health information: organizational requirements (the BAA requirement).
- **45 CFR §164.502(a)** — Permitted uses and disclosures: general rules (the "minimum necessary" standard).
- **45 CFR §164.502(e)** — Business associate contracts.
- **45 CFR §164.308** — Administrative safeguards (incl. §164.308(a)(1)(ii)(D) information system activity review; §164.308(b)(1) business associate contracts).
- **45 CFR §164.310** — Physical safeguards.
- **45 CFR §164.312** — Technical safeguards (incl. (a) access control, (b) audit controls, (c) integrity, (d) person or entity authentication, (e) transmission security).
- **45 CFR §164.314** — Organizational requirements (BAA subcontractor obligations).
- **45 CFR §164.316** — Policies, procedures, and documentation.
- **45 CFR §164.402** — Definitions (breach notification rule).
- **45 CFR §164.404** — Notification to individuals.
- **45 CFR §164.406** — Notification to the media.
- **45 CFR §164.408** — Notification to the Secretary of HHS.
- **45 CFR §164.410** — Notification by a business associate.
- **45 CFR §164.412** — Law enforcement delay.
- **45 CFR §164.414** — Administrative requirements and burden of proof.
- **45 CFR §164.524** — Access of individuals to protected health information.
- **45 CFR §164.526** — Amendment of protected health information.
- **45 CFR §164.528** — Accounting of disclosures of protected health information.
- **45 CFR §164.530(j)** — Documentation retention (6 years).

## Appendix B — Source documents

- HHS Sample Business Associate Agreement (PDF): https://www.hhs.gov/sites/default/files/model-business-associate-agreement.pdf
- HHS Sample Business Associate Agreement Provisions (web): https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html
- HIPAA Journal — "Business Associate Agreement Requirements Explained": https://www.hipaajournal.com/hipaa-business-associate-agreement/
- 45 CFR Part 164 (full text): https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164
- OCR HIPAA Security Rule Guidance: https://www.hhs.gov/hipaa/for-professionals/security/

---

## Disclaimer

This template is informational and is **not legal advice**. The Covered Entity's counsel must adapt, complete the bracketed fields, and confirm that the final language satisfies the Covered Entity's specific circumstances, applicable state law, and the Covered Entity's existing compliance program. Don't-Lie does not warrant that use of this template will satisfy any particular Covered Entity's regulatory obligations.

Template version 1.0 — 2026-07-28.

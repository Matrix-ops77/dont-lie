# Don't-Lie & HIPAA — compliance memo

**Date:** 2026-07-28
**Audience:** Privacy officer, compliance counsel, BAA reviewer
**Scope:** How Don't-Lie receipts help meet HIPAA Security Rule requirements for AI systems that process Protected Health Information (PHI).

> This memo is informational and is not legal advice. Confirm any compliance position with counsel.

---

## What HIPAA actually requires (the relevant subset)

| Citation | Requirement | Applies to AI call receipts? |
|---|---|---|
| 45 CFR §164.312(a)(1) | Access control for ePHI | Yes — vault is operator-local; access via filesystem perms |
| 45 CFR §164.312(b) | Audit controls | **Directly** — every LLM call leaves a signed audit record |
| 45 CFR §164.312(c) | Integrity controls for ePHI | **Directly** — Ed25519 + SHA-256 chain prove no silent rewrite |
| 45 CFR §164.312(d) | Person or entity authentication | Partial — receipt captures the key, not the person |
| 45 CFR §164.316(b) | Retention for 6 years (or longer per state) | Yes — append-only chain supports it |
| 45 CFR §164.308(a)(1)(ii)(D) | Information system activity review | Yes — `dontlie search` and the web UI enable review |
| 45 CFR §164.530(c) | Documentation retention | Yes — portable bundle + HTML report is the documentation |
| 45 CFR §164.502(a) | Minimum necessary | **Not addressed** — redaction is the operator's job |

## What a Don't-Lie receipt proves

- That a specific call to an AI model was made at a specific time
- That the exact prompt and response bytes were preserved, byte-for-byte
- That no operator has silently edited the call record afterward
- That the chain is unbroken back to the first receipt in the vault
- That the signing key is the one the operator published

## What a Don't-Lie receipt does **not** prove

- That the patient authorized the call (consent is captured separately, e.g., in a consent-management system; tag the consent ID into the receipt's `tags` field)
- That the model gave a clinically correct answer
- That the signing key was held by a specific authorized person (see "Reasonable Doubt" in every report)
- That the upstream AI provider did not log the call on its side

## What you need to do additionally (the don't-lie checklist)

1. **Sign a BAA with your AI provider.** Don't-Lie is a local proxy, not a service provider, so no Don't-Lie BAA is needed. Your AI provider (OpenAI, Anthropic, MiniMax) may need one.
2. **Map receipts to patients.** Add a `patient_id` or `case_id` tag to every receipt before it lands. Pattern:
   ```python
   with dontlie_agent.installed() as h:
       client.chat.completions.create(
           model="...",
           messages=[...],
           extra_tags={"patient_id": "P-12345"},
       )
   ```
3. **Restrict key access.** The signing key at `~/.config/dontlie/keys/dontlie.key` should be readable only by the service account that runs the proxy. Use filesystem permissions (chmod 600) and consider storing it in macOS Keychain or an HSM.
4. **Configure object-locked S3 retention.** The Compliance tier ships a 7-year retention guarantee using AWS S3 Object Lock in COMPLIANCE mode. The operator cannot delete the bundle, even with root keys, before the retention date.
5. **Add to your annual risk assessment.** Document the receipt vault in your §164.308(a)(1)(ii)(A) risk analysis. The vault is one of the controls in the "audit controls" section.
6. **Run `dontlie trust-score` in your CI.** The trust score fails the build if a receipt fails verification. Wire it into your pipeline:
   ```bash
   dontlie trust-score --json | jq -e '.value >= 80' || (echo "trust-score below threshold"; exit 1)
   ```
7. **Document the gaps.** The "Reasonable Doubt" panel in every bundle shows the 5 things receipts do not prove on their own. Your compliance team should write a one-page addendum acknowledging those gaps and naming the controls that close them.

## What Don't-Lie does **not** do for HIPAA

- It is **not** a BAA-eligible service on its own (it is a local library; the BAA, if any, is between you and the AI provider)
- It does **not** de-identify PHI before transmission — use your existing de-identification layer
- It does **not** perform access control on the vault (use filesystem perms, an HSM, or a key-management service)
- It does **not** enforce minimum necessary — that is a workflow problem, not a tool problem

## Recommended controls layered on top

| Control | Where it lives | What Don't-Lie provides |
|---|---|---|
| Encryption at rest | Your machine + S3 | TDE-style via age-encrypted vault export (`dontlie encrypt`) |
| Access control | Filesystem + IAM | Audit log of who exported what (`/api/audit` in Team tier) |
| Tamper evidence | Don't-Lie | Ed25519 + SHA-256 chain |
| Retention | S3 Object Lock in COMPLIANCE mode | 7-year guarantee in Compliance tier |
| Activity review | Compliance team + `dontlie search` | Full-text search across all receipts |
| Documentation | HTML report | The bundle is the documentation |

## When you would actually need this

- A patient files a complaint with HHS OCR about an AI-assisted decision
- A state medical board audits your use of AI in clinical workflows
- A plaintiff in a malpractice case subpoenas "the AI's reasoning"
- An internal QA review needs to verify that the AI did not hallucinate a drug interaction

In each of these, the receipt is the byte-exact record. The verifier (`dontlie verify --export <bundle>`) runs in 0.24 seconds for 1,000 receipts and on a clean laptop. The bundle is the response you hand to the auditor.

## Where to get help

- `docs/integrations/SIEM.md` — Splunk / Datadog / ELK shipping
- The Compliance tier (see `site/pricing.html`) includes a designated success engineer for the 30-day pilot
- The witness notary (see `docs/WITNESS_PROTOCOL.md` — v0.4) provides the timestamp-anchoring that closes Reasonable Doubt #5

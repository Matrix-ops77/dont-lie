# Don't-Lie & HIPAA — operator reference

**Date:** 2026-07-30
**Audience:** Privacy officer, compliance counsel, BAA reviewer
**Scope:** How a Don't-Lie receipt vault, run by the operator on their own hardware, supports HIPAA Security Rule requirements for AI systems that process Protected Health Information (PHI).

> This memo is informational and is not legal advice. Confirm any compliance position with counsel. Don't-Lie is a local-first Python package. There is no hosted service, no hosted witness, no hosted vault, and no compliance product behind this memo.

---

## What HIPAA actually requires (the relevant subset)

| Citation | Requirement | Applies to a locally-run AI call vault? |
|---|---|---|
| 45 CFR §164.312(a)(1) | Access control for ePHI | Yes — vault is operator-local; access via filesystem permissions |
| 45 CFR §164.312(b) | Audit controls | **Directly** — every LLM call leaves a signed audit record |
| 45 CFR §164.312(c) | Integrity controls for ePHI | **Directly** — Ed25519 + SHA-256 chain prove no silent rewrite |
| 45 CFR §164.312(d) | Person or entity authentication | Partial — the receipt captures the key, not the person |
| 45 CFR §164.316(b) | Retention for 6 years (or longer per state) | The chain supports arbitrary retention. The operator chooses the storage backend and retention policy. |
| 45 CFR §164.308(a)(1)(ii)(D) | Information system activity review | Yes — `dontlie search` and the local `dontlie web` UI enable review |
| 45 CFR §164.530(c) | Documentation retention | Yes — the portable bundle + HTML proof report is the documentation |
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
- That the signing key was held by a specific authorized person (see the "Reasonable Doubt" panel in every bundle)
- That the upstream AI provider did not log the call on its side

## What the operator needs to do

The receipt is the integrity evidence. The remaining controls are the operator's job — and were always going to be, with or without Don't-Lie.

1. **Sign a BAA with your AI provider.** Don't-Lie is a local proxy, not a service provider, so no Don't-Lie BAA is needed. Your AI provider (OpenAI, Anthropic, MiniMax, etc.) is the one you sign a BAA with.
2. **Map receipts to patients.** Add a `patient_id` or `case_id` tag to every receipt before it lands. Pattern:
   ```python
   with dontlie_agent.installed() as h:
       client.chat.completions.create(
           model="...",
           messages=[...],
           extra_tags={"patient_id": "P-12345"},
       )
   ```
3. **Restrict key access.** The signing key at `~/.config/dontlie/keys/dontlie.key` should be readable only by the service account that runs the proxy. Use filesystem permissions (chmod 600) and consider storing it in macOS Keychain, an HSM, or a key-management service you operate.
4. **Configure your own retention storage.** HIPAA requires 6 years minimum. Don't-Lie does not host the storage; you do. A common pattern is to export the daily bundle and copy it into an S3 bucket you control with Object Lock in COMPLIANCE mode (or equivalent on Azure Blob immutable storage / GCS bucket lock). Example:
   ```bash
   python3 -m dontlie export /tmp/daily.bundle.json --bundle
   aws s3 cp /tmp/daily.bundle.json s3://your-audit-vault/dontlie/$(date +%Y-%m-%d).bundle.json \
     --object-lock-mode COMPLIANCE \
     --object-lock-retain-until-date 2033-07-30T00:00:00Z
   ```
   The retention date, the bucket, the KMS key, and the access policy are all yours. Don't-Lie only signs the bundle; it does not store it.
5. **Add the vault to your annual risk assessment.** Document the receipt vault in your §164.308(a)(1)(ii)(A) risk analysis. The vault is one of the controls in the "audit controls" section.
6. **Run `dontlie trust-score` in CI.** The trust score fails the build if a receipt fails verification. Wire it into your pipeline:
   ```bash
   dontlie trust-score --json | jq -e '.value >= 80' || (echo "trust-score below threshold"; exit 1)
   ```
7. **Document the gaps.** The "Reasonable Doubt" panel in every bundle shows the 5 things receipts do not prove on their own. Your compliance team should write a one-page addendum acknowledging those gaps and naming the controls that close them.

## What Don't-Lie does **not** do for HIPAA

- It is **not** a BAA-eligible service. It is a local library. The BAA, if any, is between you and your AI provider.
- It does **not** de-identify PHI before transmission. Use your existing de-identification layer.
- It does **not** perform access control on the vault. Use filesystem permissions, an HSM, or a key-management service you operate.
- It does **not** enforce minimum necessary. That is a workflow problem, not a tool problem.
- It does **not** host a copy of your receipts. The vault lives on your hardware; backups live in storage you control.
- It does **not** provide designated support staff. The author (Wayne Dellmyer) and the open-source community answer questions in the issue tracker; no SLA, no on-call, no support contract.

## Recommended controls layered on top

| Control | Where it lives | What Don't-Lie provides |
|---|---|---|
| Encryption at rest | Your machine + your storage backend | TDE-style via age-encrypted vault export (`dontlie encrypt`) and per-receipt key derivation |
| Access control | Filesystem + your IAM | The receipt chain detects tampering; your filesystem permissions and storage IAM enforce who can read the vault |
| Tamper evidence | Don't-Lie (local) | Ed25519 + SHA-256 chain; verifiable offline on a clean laptop |
| Retention | Your storage backend (S3, Azure, GCS, NAS, tape) | Don't-Lie produces a portable bundle; the operator chooses where it lives and for how long |
| Activity review | Your compliance team + `dontlie search` | Full-text search across all receipts; operator-side automation (Splunk, ELK) covered in `docs/integrations/SIEM.md` |
| Documentation | Your HTML report | The bundle is the documentation; render with `dontlie render` or `python3 -m dontlie.demo.render_report` |

## When you would actually need this

- A patient files a complaint with HHS OCR about an AI-assisted decision
- A state medical board audits your use of AI in clinical workflows
- A plaintiff in a malpractice case subpoenas "the AI's reasoning"
- An internal QA review needs to verify that the AI did not hallucinate a drug interaction

In each of these, the receipt is the byte-exact record. The verifier (`dontlie verify --export <bundle>`) runs in under a second on a clean laptop, with no Don't-Lie install and no network. The bundle is the response you hand to the auditor.

## Where to get help

- `docs/integrations/SIEM.md` — Splunk / Datadog / ELK shipping (you operate the SIEM)
- `docs/groundtruth.md` — vendor-independent route attestation (opt-in lane)
- GitHub Issues: open a question at `github.com/Matrix-ops77/dont-lie/issues`
- Security issues: see `security.md`

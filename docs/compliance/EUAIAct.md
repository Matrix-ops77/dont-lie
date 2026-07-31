# Don't-Lie and EU AI Act evidence

**Reviewed:** 2026-07-30
**Audience:** Providers, deployers, AI governance leads, counsel, and assessors

> This is an evidence-support map, not legal advice, certification, a
> conformity assessment, or a CE declaration. Duties depend on the system's
> classification and the organization's role. Application dates are phased
> and have changed; verify the current timeline before relying on a deadline.

Authoritative sources:

- [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)
- [European Commission AI Act overview and timeline](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)

## The accurate product claim

Don't-Lie can produce supporting evidence for runtime logging and
record-keeping. It automatically records configured model calls and can export
signed, hash-linked receipts for independent verification.

That does not, by itself, satisfy Article 12. The operator must demonstrate
that the high-risk system's logging capabilities cover the events required for
traceability, risk identification, post-market monitoring, and operational
monitoring over the system lifetime. A recorder placed at one model boundary
cannot prove that every system event passed through it.

## Control coverage

Run the maintained, machine-readable map:

```bash
dontlie compliance eu-ai-act
dontlie compliance eu-ai-act --only-gaps
dontlie compliance eu-ai-act --json > eu-ai-act-evidence-map.json
```

The map includes:

- AI literacy and prohibited practices;
- risk management, data governance, and technical documentation;
- logging, deployer transparency, human oversight, accuracy, robustness, and
  cybersecurity;
- provider and deployer obligations, quality management, corrective action,
  and record retention;
- fundamental-rights impact assessments;
- conformity assessment, declarations, and registration;
- Article 50 transparency;
- post-market monitoring and serious-incident reporting;
- GDPR and other applicable Union or national law.

## Where receipt evidence helps

| Workstream | Evidence contribution |
|---|---|
| Article 11 / Annex IV technical documentation | Recorded runtime exchanges and verification results |
| Article 12 logging | Signed records of configured model calls |
| Article 13 deployer information | Recorded model, request, response, and proof limitations |
| Article 14 human oversight | Signed annotations or decision events, when the operator records them |
| Article 15 security | Detection of receipt alteration, not whole-system cybersecurity |
| Article 26 deployer monitoring | Searchable and exportable runtime evidence |
| Articles 72–73 monitoring and incidents | Forensic input for investigation and reporting |

Every row is supporting evidence. None is a standalone conformity result.

## Controls the operator must still supply

- Correct role and risk classification.
- Continuous risk management and documented testing.
- Data governance, lawful processing, quality, provenance, bias, and
  representativeness controls.
- Complete technical documentation and instructions for use.
- Effective human authority, intervention, override, and stop mechanisms.
- Accuracy, robustness, resilience, and cybersecurity evaluation.
- A documented quality-management system and accountability framework.
- Required log retention, access, interpretation, and capture coverage.
- Fundamental-rights impact assessment where applicable.
- Conformity assessment, declarations, registration, and notified-body work.
- User disclosures and machine-readable or visible labels under Article 50.
- Post-market monitoring, corrective action, and serious-incident reporting.
- GDPR, sector-specific, employment, consumer, and national-law obligations.

## Evidence workflow

1. Classify the system and the organization's role with qualified counsel.
2. Define the system events the applicable controls require.
3. Place capture at boundaries that can observe those events.
4. Test success, failure, stream, retry, bypass, and recorder-failure paths.
5. Produce a date- and scope-specific packet:

   ```bash
   dontlie prove evidence-packet
   ```

6. Pin the operator's trusted public key and verify independently.
7. Record packet scope and known omissions in the technical file.
8. Feed verified evidence into monitoring, risk, oversight, and incident
   processes owned by accountable people.

## Personal data and erasure

An append-only receipt containing personal data can create a serious retention
and data-subject-rights problem. Prefer pseudonymous identifiers, externalize
the identity mapping, and choose fingerprint evidence when raw content is not
required. Heuristic redaction is not anonymization.

The operator must reconcile traceability needs with GDPR purpose limitation,
data minimization, retention, security, access, transfer, and data-subject
rights. Don't-Lie does not make that legal decision.

## What the packet proves

- Integrity of the included recorded receipts.
- Internal continuity of the included chain.
- Trust in a signer when a reviewer pins the signer externally.
- Changes to exported packet files through checksums.

## What it does not prove

- That all required system events were captured.
- That a system is high-risk, low-risk, prohibited, or correctly classified.
- Effective human oversight or accurate, robust, secure model behavior.
- Provider identity from a route string.
- Compliance with the AI Act, GDPR, or another law.
- Completion of a conformity assessment, declaration, registration, FRIA, or
  incident report.

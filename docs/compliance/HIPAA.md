# Don't-Lie and HIPAA Security Rule evidence

**Reviewed:** 2026-07-30
**Audience:** Security and privacy officers, counsel, auditors, and operators

> This is an evidence-support map, not legal advice or a compliance
> determination. The current HIPAA Security Rule remains in effect. HHS
> describes its December 2024 cybersecurity update as a proposed rule, not a
> final rule.

Authoritative sources:

- [HHS Security Rule summary](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/)
- [HHS risk-analysis guidance](https://www.hhs.gov/hipaa/for-professionals/security/guidance/guidance-risk-analysis/)
- [HHS proposed Security Rule update](https://www.hhs.gov/hipaa/for-professionals/security/hipaa-security-rule-nprm/)

## The accurate product claim

Don't-Lie can support two technical-control reviews for AI calls:

- **Audit controls (§164.312(b)):** it records configured AI calls and supports
  search, export, and independent verification.
- **Integrity (§164.312(c)):** Ed25519 signatures and a hash-linked chain detect
  alteration of recorded receipts.

That is evidence for part of a HIPAA security program. It is not the program.
A valid chain does not prove that every in-scope event was captured, that the
signing key belongs to an authorized identity, or that ePHI elsewhere is
protected.

## Control coverage

Run the maintained, machine-readable map:

```bash
dontlie compliance hipaa-security
dontlie compliance hipaa-security --only-gaps
dontlie compliance hipaa-security --json > hipaa-evidence-map.json
```

The map covers:

- administrative safeguards, including risk analysis, activity review,
  workforce controls, incidents, contingency planning, and evaluation;
- physical safeguards;
- technical safeguards: access, audit, integrity, authentication, and
  transmission security;
- organizational arrangements, policies, and documentation;
- the Privacy and Breach Notification Rules as explicitly out of scope;
- the proposed cybersecurity amendments as future-readiness material only.

## Evidence workflow

For an in-scope AI workflow:

1. Configure capture at the actual provider or application boundary.
2. Confirm capture of successful calls, failures, streams, and retries.
3. Create the packet:

   ```bash
   dontlie prove evidence-packet
   ```

4. Give the packet and the trusted public-key pin to an independent reviewer.
5. Have the reviewer verify:

   ```bash
   shasum -a 256 -c evidence-packet/SHA256SUMS
   dontlie verify \
     --export evidence-packet/receipts.bundle.json \
     --public-key KEY_ID=/trusted/path/public.pem \
     --verbose
   ```

6. Retain the review result inside the operator's documented activity-review
   and incident-response process.

## Controls the operator must still supply

- Complete risk analysis and risk management.
- Authoritative identity, access control, workforce lifecycle, and training.
- Transport security and protection of ePHI outside the vault.
- Physical safeguards, backup, recovery, availability, and emergency access.
- Key ownership, custody, rotation, recovery, and revocation procedures.
- Capture-completeness testing and response to missing receipts.
- Lawful use, disclosure, minimum-necessary, patient rights, and breach
  assessment.
- Applicable business-associate agreements and other contracts.
- Written policies, review cadence, retention decisions, and proof that those
  procedures operate.

The HIPAA documentation-retention rule is not a universal command to retain
every ePHI log for six years. Counsel should determine which documentation and
records must be retained, for how long, and whether other federal or state
rules impose different periods.

## PHI handling

Full prompts and responses may contain PHI. The safest default for
cross-organizational sharing is a fingerprint-only evidence view. Heuristic
redaction is defense in depth; it is not de-identification and can miss names,
addresses, free text, and other identifiers.

Do not place a direct patient identifier in receipt tags merely to simplify
search. Prefer a pseudonymous case reference whose identifying mapping lives
in an access-controlled system with its own retention and deletion policy.

Encrypting an exported vault does not secure a running plaintext database,
authorize its users, secure the host, or replace encrypted transport.

## What the packet proves

- The included receipts verify against their included keys.
- The included receipt chain is internally intact.
- A pinned external public key can establish trust in a signing key.
- Packet checksums detect changes to the exported files.

## What it does not prove

- Complete capture of every real-world action.
- The clinical correctness or lawfulness of an AI response.
- Patient consent or minimum-necessary use.
- Provider identity from a recorded route string.
- A trustworthy event time without an independently verified time source.
- HIPAA compliance by the operator, provider, or any other party.

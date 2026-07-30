# Don't-Lie — Terms of Service

**Last updated:** 2026-07-30

**Scope:** These terms apply to Don't-Lie as it ships today — the
open-source local-first software published under the MIT license at
`github.com/Matrix-ops77/dont-lie`. They do not yet describe a hosted
service. If and when Don't-Lie offers a hosted service, those terms
will be updated and the hosted service will be governed by a separate
agreement.

By using the software you agree to these terms.

## 1. The software is yours

The software is MIT-licensed (see `LICENSE`). You may use it, modify
it, fork it, and ship it. We make no warranty as to its fitness for
any particular purpose. To the maximum extent permitted by law, the
software is provided "as is" without warranty of any kind.

## 2. What Don't-Lie proves

Don't-Lie makes one specific claim: **the local record of an AI
exchange was not silently modified after the fact.** Verification is
cryptographic (Ed25519 signature, SHA-256 payload hash, parent-chain
link) and can be reproduced offline on a clean machine using only
the receipt bundle and the public key.

We do **not** claim that:

- the model answer is correct, truthful, or non-hallucinated;
- the upstream provider is the one your receipt claims;
- the signing key was operated by any particular person or
  organization;
- the receipt proves a contract, agreement, or legal commitment by
  any party.

Don't-Lie receipts are evidence of integrity, not evidence of
correctness, identity, or intent.

## 3. Your responsibilities

You are responsible for:

- the legality of the prompts and responses you capture;
- access control to your signing key and your local vault;
- compliance with applicable laws (GDPR, EU AI Act, HIPAA, NY DFS,
  sector-specific regulations) in your jurisdiction;
- verifying that the public key you trust as a "signer" is actually
  the key you intended to trust (the receipt itself records which
  key signed it, but the trust decision is yours).

## 4. No hosted service today

The released v0.3.x versions are local-first only. We do not operate
a hosted service, we do not collect telemetry, we do not have a
billing system, and we do not have customer support. The terms in
this document apply to the software you run on your own hardware.

If you found a hosted signup page, a Stripe checkout, or a support
inbox for Don't-Lie, it is a future plan, not a current offering. We
will update these terms and the README when a hosted service ships.

## 5. Limitation of liability

To the maximum extent permitted by law, in no event will the Don't-Lie
contributors be liable for any claim, damages, or other liability
arising from, out of, or in connection with the software or the use
or other dealings in the software. This includes but is not limited
to direct, indirect, incidental, special, consequential, or punitive
damages, even if advised of the possibility of such damages.

## 6. No professional advice

Nothing in this repository — code, documentation, compliance memos,
or comparison material — constitutes legal, regulatory, or compliance
advice. Compliance buyers should consult qualified counsel before
relying on Don't-Lie receipts in a regulated workflow.

## 7. Disputes

These terms are governed by the laws of the State of Delaware, USA.
Disputes resolved in Delaware courts to the maximum extent permitted
by applicable consumer-protection law in your jurisdiction.

## 8. Contact

Open an issue at `github.com/Matrix-ops77/dont-lie/issues` for
public, accountable contact. There is no private support channel
today.

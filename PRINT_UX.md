# Demo Proof Report — 60-Second Design Spec

## Goal

In one minute, a skeptical viewer should understand:

1. what interaction was recorded;
2. whether its receipt and chain verify;
3. exactly what that verification proves;
4. exactly what it does not prove; and
5. that changing a recorded field produces a visible verification failure.

The report is evidence, not marketing. Never use “truth verified,” “AI output is
true,” or “tamper-proof.” Preferred language: **signature valid**, **chain
intact**, **record changed**, and **not established by this receipt**.

## Format

- Two screens or two printed pages, both readable without scrolling.
- Canvas: 16:9 at 1440 × 810; print fallback: US Letter landscape.
- Minimum type: 18 px screen / 11 pt print. Verdict: 56–72 px / 36–44 pt.
- White background, near-black text, one status color:
  - verified: dark green `#166534`;
  - failed: dark red `#B91C1C`;
  - neutral/not proven: slate `#475569`.
- Monospace only for IDs, hashes, signatures, and changed values.
- No charts, gauges, gradients, animations, or dashboard chrome.
- Every truncated value has a visible label such as `first 16 of 64 hex`.

## Screen 1 — Proof Summary

### Header strip

Left:

> DON’T-LIE · RECEIPT PROOF

Right:

> Generated `<ISO-8601 UTC>` · Local verification

### Big verdict

The top third contains one dominant verdict:

> **VERIFIED**
>
> Signature valid · Chain intact · 3 of 3 receipts checked

If verification fails, replace the entire verdict—not just the color:

> **FAILED**
>
> Receipt #3 changed · Payload hash mismatch

Never show green status when any checked receipt fails.

### Exchange identity

Directly beneath the verdict, show one compact row:

| Receipt | Recorded at | Model | Parent | Signing key |
|---|---|---|---|---|
| `#3` | `2026-07-24 14:32:08Z` | `claude-sonnet-4` | `#2` | `a31f…92c0` |

Then show the captured exchange in two equal columns:

- **Model input** — first 240 characters of the canonical request.
- **Model response** — first 240 characters of the recorded response.

Label these as recorded values, not live provider data.

### Proven / not proven

Use two equal-width boxes with literal headings.

**PROVEN BY THIS REPORT**

- The displayed receipt fields reproduce the stored payload hash.
- The stored Ed25519 signature verifies with the displayed public key.
- Each displayed receipt points to the preceding receipt in this export.
- The checked database/export contained the stated receipt count at verification time.

**NOT PROVEN BY THIS REPORT**

- That the model’s answer is factually correct.
- That the provider actually ran the named model.
- That omitted client, SDK, gateway, or server transformations did not occur.
- That no receipts were removed before the first or after the last available chain record.
- Who controlled the signing key, unless key custody is established separately.

Footer:

> Privacy: this report may contain what the model received, including hidden
> system instructions and tool context. Review before sharing.

## Screen 2 — Tamper Demonstration

### Title and verdict

> TAMPER CHECK · SAME RECEIPT, ONE FIELD CHANGED

Dominant verdict:

> **TAMPER DETECTED**
>
> Receipt #3 · Payload hash mismatch · Signature invalid

### One-screen before/after

Use a two-column diff with no scrolling:

**ORIGINAL — verifies**

```text
response: "Approve refund up to $50."
payload:  64d1c8a4…9e72
signature: valid
```

**CHANGED — fails**

```text
response: "Approve refund up to $500."
payload:  b02971ef…c443
signature: invalid
```

Highlight only the changed substring (`$50` → `$500`) and the resulting status.
Do not animate the change; the printed report must communicate the same proof.

### Explanation

One sentence beneath the diff:

> The response changed, so its canonical payload hash changed; the original
> signature no longer verifies against the modified receipt.

Show the verifier result as a compact evidence block:

```text
checked: 3
valid:   2
failed:  1
first failure: receipt #3 — payload sha256 mismatch
```

Footer limitation:

> This demonstrates detection of modification to the available signed record.
> It does not prove the response is true or that the available record set is complete.

## 60-Second Presenter Path

- **0–10 seconds:** Point to the big verdict and say what was checked: receipt
  hash, Ed25519 signature, and parent continuity.
- **10–25 seconds:** Identify the recorded model input/response and signing key.
- **25–40 seconds:** Read one item from **Proven** and two from **Not proven**.
- **40–55 seconds:** Switch to the tamper screen; point to `$50` → `$500`, then
  the failed hash and signature.
- **55–60 seconds:** Close with: “It proves this signed record changed; it does
  not prove the model was correct.”

## Acceptance Checklist

- Both screens fit at 100% zoom and on Letter landscape without clipping.
- Verdict remains understandable in grayscale and without icons.
- Verified and failed states use different words, not color alone.
- All timestamps include UTC; all IDs identify their truncation.
- The displayed counts and failure reason come from verifier output, never mock copy.
- The tamper demo modifies a copy; the original vault remains untouched.
- No claim exceeds the **Proven by this report** list.

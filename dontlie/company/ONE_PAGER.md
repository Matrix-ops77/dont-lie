# Don't-Lie — One-Pager

**Last updated:** 2026-07-24

## What it is
A local-first, signed-receipt vault for OpenAI-compatible LLM calls. Drop-in SDK.
Every call is captured, hashed, signed (Ed25519), and stored in a SQLite file you
control. The receipt chain is hash-linked, verifiable offline, and exportable as
a portable bundle + self-contained HTML proof report.

## Why now
2024–2026: 1,796+ AI-hallucination cases in legal sector (Charlotin database).
Texas AG v. Pieces Technologies (Sept 2024). FTC v. Rytr (Sept 2024). §1557
final rule (May 2025) requires "identification and mitigation of risk" in
patient-care AI. TRAIGA / HB 149 (Jan 1, 2026) requires AI disclosure with
$10K–$200K civil penalties per violation. The audit ask is real and monthly.

## ICP (Ideal Customer Profile)
Regulated-industry AI engineer in healthcare, legal, or financial services.
Building internal agents. Spends ≥ $5K/mo on OpenAI/Anthropic/MiniMax. Has
already had a "bad AI moment" and is now in procurement. Budget: $200–$2K/mo
for SDK, $10K+ for compliance-grade. Sales cycle: 2–4 weeks.

## Wedge
One-line drop-in for OpenAI / Anthropic Python SDK. Point the client at a
local signed proxy. Get portable, verifiable, tamper-evident receipts. Show
your auditor next week. The report explicitly says what it proves (integrity,
signer, provider) and what it does not (truth).

## Trajectory
| Month | MRR target | Notes |
|---|---|---|
| M1 | $1k | 5 design partners, 1 paying |
| M2 | $2k | 10 paying Pro + 1 Team |
| M3 | $4k | 25 Pro + 3 Team |
| M4 | $6k | 40 Pro + 6 Team |
| M5 | $8k | 60 Pro + 10 Team |
| **M6** | **$10k** | **80 Pro + 15 Team + 1 Enterprise pilot** |

## Moat
- Drop-in UX (one-line import; user's code unchanged)
- Honest scope (explicitly does NOT claim truth — auditors trust it more)
- Portable artifacts (HTML + JSON bundle, verifiable offline, no lock-in)
- Pre-built wrappers for OpenAI, Anthropic, requests, and agent runtimes

## Pricing
Free / $19 Pro / $199 Team / Enterprise. Free is permanent and full-featured
locally; paid is sync + multi-user + dashboard + enterprise plumbing.

## Team
Don't-Lie contributors: Goose, Kilo, OC, Gemini, Hermes, Claude, Destro.

## Contact
[contact channel TBD]

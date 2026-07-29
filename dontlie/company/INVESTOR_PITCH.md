# Don't-Lie — Investor Pitch (5-slide outline)

**Last updated:** 2026-07-24

## Slide 1 — Problem
**Your AI lied and you can't prove what it said.**
- 1,796+ AI-hallucination cases in legal sector (Charlotin database).
- Texas AG v. Pieces Technologies (Sept 2024); FTC v. Rytr (Sept 2024).
- §1557 final rule (May 2025) + TRAIGA / HB 149 (Jan 2026) require AI
  disclosure with $10K–$200K civil penalties per violation in healthcare.
- The audit ask is real, monthly, and "show me the receipt" is the answer
  nobody can give today.

## Slide 2 — Solution
**Don't-Lie = one-line SDK + signed receipt vault.**
- Drop-in for OpenAI, Anthropic, requests, and agent runtimes.
- Every call is captured, hashed (SHA-256), signed (Ed25519), and stored
  in a SQLite file you control.
- Chain is hash-linked; portable bundle + self-contained HTML proof report;
  verifiable offline, no trust in us or the model vendor.
- Honest boundary: the report says what it proves (integrity, signer,
  provider) and what it does not (truth).

## Slide 3 — Why now
- 2024–2026 enforcement: AI hallucination is now a legal category, not a
  Twitter joke.
- Regulated buyers (healthcare, legal, finance) are in active procurement
  for "AI governance" tooling.
- Existing alternatives (Langfuse, Helicone, LangSmith) are LLM
  *observability*; none of them produce a portable, signed, auditor-
  verifiable artifact.

## Slide 4 — Market & traction
- ICP: regulated-industry AI engineer, $200–$2K/mo SDK, $10K+ enterprise.
- Sales cycle: 2–4 weeks (not 18 months).
- 6-month goal: $10K MRR. Path: 80 Pro + 15 Team + 1 Enterprise.
- Pre-revenue today; design-partner pilots kicking off.
- Free tier is permanent and full-featured locally; paid is sync +
  multi-user + dashboard + enterprise plumbing.

## Slide 5 — Ask
- **Pre-seed / Seed: $500K–$1.5M.**
- Use of funds: 1 founder-type eng + 1 designer + 1 GTM, 12-month runway.
- Milestones: 5 design partners → 25 paying → 1 enterprise pilot → $10K MRR.
- Open questions: do we monetize sync first, or the audit report itself?

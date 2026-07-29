# The receipts your AI should have been generating.

*Don't-Lie is a local-first proxy that signs every AI request and response, hash-links it to the last one, and lets anyone verify it offline on a clean machine. It is MIT-licensed, fits in one line of code, and is the only major option that says out loud what it doesn't prove.*

---

## What this is, in one sentence

Point any OpenAI-compatible client at `http://127.0.0.1:8080/v1` and every call lands as a tamper-evident, Ed25519-signed, hash-linked receipt you can hand an auditor and walk away.

## What it proves

- The receipt was signed by the documented key.
- The chain is unbroken from the first receipt.
- The bundle matches the receipts you handed over.
- Each receipt binds the exact bytes you sent and received.

## What it does not prove

- That the model was truthful.
- That the upstream provider is the one claimed.
- Which person or organization held the signing key.
- Content semantics beyond the bytes.

**This narrower claim is the wedge.** It lets us ship to a buyer who has been burned by "we use AI" sales pitches that overclaim.

## The five reasonable doubts

Every bundle ships with a Reasonable Doubt panel — five challenges an auditor might raise, and a concrete instruction to close each one. No other product in the space does this.

1. **"How do I know the key was held by you?"** → publish the public key on a timestamped external channel.
2. **"Couldn't the LLM or upstream tamper before signing?"** → run the proxy as a separate process; don't co-locate the key with code that constructs prompts.
3. **"The call was recorded, but was it authorized?"** → tag `authorized_by:user_42` before the call; the tag itself becomes part of the signed payload.
4. **"The model response is recorded. That doesn't mean it was correct."** → use a separate evaluation layer; receipts give bytes, not truth.
5. **"How do I know the timestamp wasn't backdated?"** → witness notary with RFC 3161 anchored timestamp.

## Why this matters now

- 2024-2026 enforcement: Texas AG v. Pieces Technologies (Sept 2024), FTC v. Rytr (Sept 2024), 1,796+ AI-hallucination cases in legal sector.
- §1557 final rule (effective May 1, 2025) requires "identification and mitigation of risk" in patient-care decision-support tools.
- TRAIGA / HB 149 (effective Jan 1, 2026) requires Texas healthcare providers to give patients "clear and conspicuous" disclosure of AI use, with civil penalties $10K-$200K per violation.
- EU AI Act Article 12 (logging) is in effect for high-risk systems.

## What's new in v0.3

- **Web UI for non-engineers** (`dontlie web`) — auditors, GC, regulators get a URL.
- **TUI for engineers** (`dontlie ui`) — receipt browsing over SSH.
- **Trust score** (`dontlie trust-score`) — 0-100 number from the vault state, JSON for CI.
- **NDJSON streaming** (`dontlie tail --follow --json`) — Splunk, Datadog, ELK, Sumo, S3.
- **One-line agent SDK** (`import dontlie_agent; dontlie_agent.install()`) — every detected SDK now signs.
- **Reasonable Doubt panel** in every report.
- **Per-regime compliance memos** — HIPAA, SOC 2, EU AI Act, NY DFS — at `docs/compliance/`.
- **Real pricing** at $19 / $199 / $999 — at `site/pricing.html`.

## What you can do in 5 minutes

```bash
# 1. Install
pip install dontlie

# 2. The 30-second offline demo (no API key)
dontlie demo

# 3. The receipt report (open in browser)
open demo/work/receipt-report.html
```

You will see: 3 receipts signed, the verifier catch a tampered row, and the chain restored from a signed export. The whole thing is 30 seconds and proves the wedge.

## What you can do in 30 minutes

```bash
# 1. Run the proxy on a real upstream
export DONTLIE_UPSTREAM_BASE_URL="https://api.minimax.io/v1"
export DONTLIE_UPSTREAM_API_KEY="sk-..."
dontlie proxy --port 8080

# 2. Point your SDK at it
export OPENAI_BASE_URL="http://127.0.0.1:8080/v1"
export OPENAI_API_KEY="dontlie-local"
# any openai / anthropic / langchain / requests call is now signed

# 3. Verify the chain
dontlie verify --verbose
dontlie trust-score
```

## What you can do in 30 days

- Run a 30-day pilot with one design partner. We provide the witness notary, the compliance memos, and a designated success engineer. $0 for 30 days, then $99/mo or $999/mo depending on tier.
- Get a reference call. The compliance officer you hand the bundle to becomes the person who can answer the next buyer's "show me what you shipped" question.

## Who this is for

- Regulated-industry AI engineers shipping agents in healthcare, legal, financial services.
- Anyone who has had (or narrowly avoided) the moment where a clinician asks "what did the AI actually tell the patient?" and the team can't answer.
- Anyone whose general counsel wants a defensible audit trail and is tired of "we trust our logs."

## Who this is not for

- Hobbyists who don't have auditors.
- Frontier-lab researchers (they build their own).
- Big-bank CISOs (the 18-month sales cycle isn't ready for v0.3).

## The one-line pitch

> Don't-Lie is the receipts layer for AI calls. Local-first. MIT. Honest about what it doesn't prove. The auditor can verify on a clean laptop without you in the room.

## The one-line anti-pitch (use this if a competitor tries to FUD it)

> Aulite does the same thing in BUSL and is tied to a vendor dashboard. Pipelock does it for agent firewalls, not LLM calls. Asqav is Elastic-licensed. Don't-Lie is the only MIT option with portable verification on a clean laptop and a Reasonable Doubt panel that names the gaps.

## Who built this

A small team. MIT-licensed. No VC. No board. No exit timeline. We sell to the buyer who needs audit-grade evidence, not the buyer who's been told they need it.

## Where to go next

- Install: `pip install dontlie`
- Demo: `dontlie demo`
- Docs: `README.md`
- Compliance: `docs/compliance/`
- Pricing: `site/pricing.html`
- Honest contact: `founders@dontlie.dev`

The wedge is honesty. The wedge is portable. The wedge is MIT. We are not for everyone. We are for the buyer who has been burned.

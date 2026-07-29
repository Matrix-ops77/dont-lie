# Show HN: Don't-Lie — verifiable AI receipts, MIT-licensed, and the only one that says out loud what it doesn't prove

I'm shipping a v0.3 today and I'd like to show you what changed. The TL;DR: a drop-in local proxy that signs every AI call with Ed25519, hash-links it to the last one, lets you hand an auditor a portable JSON bundle, and they verify it on a clean laptop. MIT-licensed. 246 tests passing. The interesting part is not the cryptography — it's the honesty panel in the report.

**Demo (30 seconds, no API key):**
```bash
pip install dontlie
dontlie demo
open /tmp/dontlie-demo-work/receipt-report.html
```

You will see: 3 receipts signed, a SQLite row edited directly with the sqlite3 CLI, the verifier catching it ("1 ok / 1 bad"), the chain restored from a signed export, and the chain back to clean. The whole loop runs in 30 seconds and proves the wedge: **the receipt is tamper-evident, and you can prove it without trusting us**.

**What it proves, in the report itself:**

| Proves | Does not prove |
|---|---|
| The receipt was signed by the documented key | The model was correct or truthful |
| The chain is unbroken from the first receipt | The upstream provider is the one claimed |
| The bundle matches the receipts you handed over | Which person or organization held the signing key |
| Each receipt binds the exact bytes you sent and received | Content semantics beyond the bytes |

**The Reasonable Doubt panel** in every bundle names the 5 hard challenges an auditor might raise, and a concrete instruction to close each one. We have not seen another product in this space put the gaps in the report itself.

1. "How do I know the key was held by you?" → publish the public key on a timestamped external channel
2. "Couldn't the LLM or upstream tamper before signing?" → run the proxy as a separate process
3. "The call was recorded, but was it authorized?" → tag `authorized_by:user_42` before the call
4. "The model response is recorded. That doesn't mean it was correct." → use a separate evaluation layer
5. "How do I know the timestamp wasn't backdated?" → witness notary with RFC 3161 anchored timestamp

**What we built in this release:**

- `dontlie web` — stdlib HTTP UI for non-engineer auditors (9 endpoints, dark mode, no JS deps, works on an air-gapped laptop)
- `dontlie ui` — TUI receipt explorer for engineers (works over SSH)
- `dontlie trust-score` — 0-100 number from the vault state, JSON output for CI gates
- `dontlie tail --follow --json` — NDJSON streaming for Splunk / Datadog / ELK / Sumo
- `dontlie-agent` — one-line drop-in for any agent (`import dontlie_agent; dontlie_agent.install()`)
- `docs/compliance/{HIPAA,SOC2,EUAIAct,NYDFS}.md` — per-regime compliance memos
- 4 per-regime memos that tell a buyer's compliance officer what receipts do and don't cover
- `site/pricing.html` — actual numbers: $19 / $199 / $999 (we shipped the placeholder for 6 months, that's gone now)
- `MANIFESTO.md` — the 1-page version of this post

**The honest comparison.** There are now ~10 public projects that implement signed AI receipts (Aulite, Asqav, Pipelock, halo-record, HELM AI Kernel, Obsigna, Provedex, Tesserae, CloakLLM, llm.log, plus a few). The crypto isn't the differentiator. The differentiators, in our view:

- **MIT licensed.** Aulite is BUSL-1.1. Asqav is Elastic-2.0. We're MIT. You can fork us, audit us, embed us in a regulated product.
- **Portable verification on a clean laptop.** No Dont-Lie install, no account, no trust in us. Hand the bundle to outside counsel; they run `dontlie verify --export <bundle>` in 0.24 seconds for 1,000 receipts.
- **The Reasonable Doubt panel.** Telling buyers "here's what we don't prove" before they buy. The honesty IS the feature.
- **The drop-in agent SDK.** One line of code, every detected SDK patched, env round-tripped. We are not aware of another product with this UX.

**What it doesn't do.** It does not catch hallucinations. It does not verify the upstream provider is honest. It does not tell you which person held the signing key. It is not a SOC 2 report itself. We are very clear about this in the report, in the manifest, in the compliance memos, and in every sales conversation we have.

**Who this is for.** Regulated-industry AI engineers shipping agents in healthcare, legal, financial services, and the EU — anyone who has had (or narrowly avoided) the moment where a clinician, a lawyer, or a regulator asks "what did the AI actually do?" and the team can't answer. Time-to-decision for the buyer is 2-4 weeks; we sell on the portable verification story and the compliance memos, not on dashboards.

**Who this is not for.** Hobbyists who don't have auditors. Frontier-lab researchers. Big-bank CISOs (the 18-month sales cycle isn't ready for v0.3).

**What's next.** We're running 30-day design-partner pilots in legal and healthcare ($0 for 30 days, $99/mo or $999/mo after). If you're a regulated-industry AI engineer who wants to be one of the first 5, the email is at the bottom of the manifesto. The next public release is the witness notary as a free, no-signup public service — anyone can POST a receipt hash to it and get a co-signature, which closes Reasonable Doubt #5.

Thanks for reading. Run the demo. Tell me what breaks.

— Wayne Dellmyer, solo, `founders@dontlie.dev`

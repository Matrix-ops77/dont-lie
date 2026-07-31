"""Render a self-contained customer-facing HTML evidence report.

Usage:
    python3 -m dontlie.demo.render_report demo/work/receipts.bundle.json \
        demo/work/receipt-report.html

The report contains no external assets, scripts, keys, or network calls.
It explicitly distinguishes four claims Don't-Lie receipts imply:

  - Integrity:  the canonical payload hashes, signatures, parent links, and
                key-history rows are internally consistent.
  - Signer:     the receipt was signed by whichever key produced the public
                key PEM in the bundle. It does not assert that the key was
                operated by any particular person or organization.
  - Provider:   the receipt records the model name and proxy endpoint from
                the captured request. It does not independently attest the
                remote provider's identity or behavior.
  - Truth:      the receipt does not claim the model answer is correct.
                Hallucinations are recorded faithfully; that is the point.
"""
from __future__ import annotations

import hashlib
import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dontlie import storage


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _key_fingerprint(pem: str) -> str:
    """Stable short fingerprint for a public-key PEM (sha256, first 16 hex)."""
    return hashlib.sha256(pem.encode("utf-8")).hexdigest()[:16]


def render(
    bundle: Path,
    *,
    title: str = "Don't-Lie receipt report",
    packet: bool = False,
) -> str:
    report = storage.verify_export(bundle)
    document = json.loads(bundle.read_text(encoding="utf-8"))
    receipts = document.get("receipts", [])
    public_keys: dict[str, str] = document.get("public_keys", {}) or {}

    # --- signer summary ------------------------------------------------------
    key_rows: list[str] = []
    for key_id, pem in sorted(public_keys.items()):
        key_rows.append(
            "<tr>"
            f"<td><code>{_esc(key_id)}</code></td>"
            f"<td><code>{_esc(_key_fingerprint(pem))}…</code></td>"
            f"<td><code>{_esc(pem.strip())[:80]}…</code></td>"
            "</tr>"
        )
    key_rows_html = "".join(key_rows) or "<tr><td colspan=\"3\"><em>no public keys embedded</em></td></tr>"

    # --- provider summary ----------------------------------------------------
    models: dict[str, int] = {}
    endpoints: dict[str, int] = {}
    for r in receipts:
        m = r.get("model") or "unknown"
        ep = ((r.get("extra") or {}).get("endpoint")) or "unknown"
        models[m] = models.get(m, 0) + 1
        endpoints[ep] = endpoints.get(ep, 0) + 1
    model_rows = "".join(
        f"<tr><td><code>{_esc(m)}</code></td><td>{c}</td></tr>"
        for m, c in sorted(models.items())
    ) or "<tr><td colspan=\"2\"><em>none</em></td></tr>"
    endpoint_rows = "".join(
        f"<tr><td><code>{_esc(e)}</code></td><td>{c}</td></tr>"
        for e, c in sorted(endpoints.items())
    ) or "<tr><td colspan=\"2\"><em>none</em></td></tr>"

    # --- integrity table -----------------------------------------------------
    status = "VERIFIED" if report.valid else "FAILED"
    status_class = "good" if report.valid else "bad"
    rows: list[str] = []
    for receipt in receipts:
        rows.append(
            "<tr>"
            f"<td>#{_esc(receipt.get('id'))}</td>"
            f"<td>{_esc(receipt.get('timestamp'))}</td>"
            f"<td><code>{_esc(receipt.get('model'))}</code></td>"
            f"<td>{_esc(receipt.get('parent_id'))}</td>"
            f"<td><code>{_esc(str(receipt.get('payload_sha256', ''))[:16])}…</code></td>"
            f"<td><code>{_esc(str(receipt.get('signature', ''))[:16])}…</code></td>"
            "</tr>"
        )
    issue_html = "".join(
        f"<li>receipt {_esc(issue.receipt_id)}: {_esc(issue.reason)}</li>"
        for issue in report.issues
    ) or "<li>none</li>"

    if packet:
        workflow_html = """
<section>
<h2>How to verify and reproduce this report</h2>
<p>From inside this packet directory:</p>
<ol>
  <li>Check artifact hashes: <code>shasum -a 256 -c SHA256SUMS</code></li>
  <li>Verify the portable bundle: <code>dontlie verify --export receipts.bundle.json --verbose</code></li>
  <li>Re-render the report: <code>python -m dontlie.demo.render_report receipts.bundle.json receipt-report.reproduced.html</code></li>
</ol>
</section>
"""
    else:
        bundle_name = _esc(bundle.name)
        workflow_html = f"""
<section>
<h2>How to verify and reproduce this report</h2>
<p>From the directory containing this bundle:</p>
<ol>
  <li>Verify the portable bundle: <code>dontlie verify --export {bundle_name} --verbose</code></li>
  <li>Re-render the report: <code>python -m dontlie.demo.render_report {bundle_name} receipt-report.reproduced.html</code></li>
</ol>
</section>
"""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<style>
:root {{ color-scheme: light dark; font-family: ui-sans-serif,system-ui,sans-serif; }}
body {{ max-width: 1100px; margin: 0 auto; padding: 2rem; line-height: 1.45; }}
h1 {{ margin-bottom: .25rem; }}
h2 {{ margin-top: 2.4rem; border-bottom: 1px solid #8885; padding-bottom: .35rem; }}
.subtle {{ opacity: .72; }}
.badge {{ display:inline-block; padding:.45rem .8rem; border-radius:999px; font-weight:700; letter-spacing:.04em; }}
.good {{ color:#075e2b; background:#b9f6cf; }}
.bad  {{ color:#8b1020; background:#ffc2c9; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:.8rem; margin:1.5rem 0; }}
.card {{ border:1px solid #8885; border-radius:.7rem; padding:1rem; }}
.card strong {{ display:block; font-size:1.5rem; }}
table {{ width:100%; border-collapse:collapse; font-size:.9rem; }}
th,td {{ text-align:left; border-bottom:1px solid #8885; padding:.65rem .4rem; vertical-align: top; }}
code {{ font-family:ui-monospace,SFMono-Regular,monospace; font-size:.85em; }}
.fourup {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:.65rem; margin: 1rem 0 1.5rem; }}
.fourup > div {{ border:1px solid #8885; border-radius:.55rem; padding:.8rem .9rem; }}
.fourup h3 {{ margin: 0 0 .35rem; font-size: 1rem; letter-spacing:.02em; }}
.fourup p  {{ margin: 0; font-size: .9rem; opacity:.85; }}
/* Light mode (default) — saturated colors with strong contrast */
.legend-integrity {{ background: #dbeafe; color: #0c2a5e; border-left: 4px solid #2563eb; }}
.legend-signer    {{ background: #ede4ff; color: #2e1065; border-left: 4px solid #7c3aed; }}
.legend-provider  {{ background: #d3f9d8; color: #064e3b; border-left: 4px solid #15803d; }}
.legend-truth     {{ background: #ffe2e2; color: #5b1010; border-left: 4px solid #b91c1c; }}
.legend-integrity h3, .legend-signer h3, .legend-provider h3, .legend-truth h3 {{ color: inherit; opacity: 1; }}
.legend-integrity p,  .legend-signer p,  .legend-provider p,  .legend-truth p  {{ color: inherit; opacity: 0.92; }}
/* Dark mode — auto-invert with deeper saturated backgrounds + light text */
@media (prefers-color-scheme: dark) {{
  :root {{ color-scheme: dark; }}
  body {{ background: #0a0a0a; color: #e5e5e5; }}
  h2 {{ border-bottom-color: #444; }}
  th, td, .card, .fourup > div {{ border-color: #333; }}
  .subtle {{ opacity: .8; }}
  .legend-integrity {{ background: #1e3a8a; color: #dbeafe; border-left-color: #60a5fa; }}
  .legend-signer    {{ background: #4c1d95; color: #ede4ff; border-left-color: #a78bfa; }}
  .legend-provider  {{ background: #14532d; color: #d3f9d8; border-left-color: #4ade80; }}
  .legend-truth     {{ background: #7f1d1d; color: #ffe2e2; border-left-color: #f87171; }}
}}
/* Reasonable-doubt panel */
.doubt {{ margin: 1.4rem 0 1.8rem; border: 1px solid #8885; border-radius: 0.55rem; padding: 1rem 1.1rem; background: #1a1a1a0a; }}
.doubt h2 {{ margin-top: 0; font-size: 1.05rem; }}
.doubt .item {{ margin: 0.65rem 0; padding: 0.55rem 0.7rem; border-left: 3px solid #f59e0b; background: #fff8e8; color: #3a2a05; border-radius: 0 0.4rem 0.4rem 0; }}
.doubt .item b {{ display: block; font-size: 0.95rem; margin-bottom: 0.2rem; }}
.doubt .item p {{ margin: 0 0 0.3rem; font-size: 0.88rem; }}
.doubt .item .close {{ font-size: 0.82rem; color: #15803d; font-weight: 600; }}
@media (prefers-color-scheme: dark) {{
  .doubt {{ border-color: #333; background: #141414; }}
  .doubt .item {{ background: #2a1f04; color: #fde8c2; border-left-color: #fbbf24; }}
  .doubt .item .close {{ color: #4ade80; }}
}}
</style>
</head>
<body>
<h1>{_esc(title)}</h1>
<p class="subtle">Portable verification artifact · no network required · self-contained HTML</p>
<p><span class="badge {status_class}">{status}</span></p>

<div class="cards">
  <div class="card"><strong>{report.ok_count}</strong>valid receipts</div>
  <div class="card"><strong>{report.bad_count}</strong>invalid receipts</div>
  <div class="card"><strong>{len(receipts)}</strong>total records</div>
  <div class="card"><strong>Ed25519</strong>signature scheme</div>
</div>

<section>
<h2>Executive summary</h2>
<p class="subtle">One-line verdict:
{ "All receipts are intact and were signed by the documented key." if report.valid else "One or more receipts failed integrity verification." }</p>
</section>

<section>
<div class="doubt">
<h2>Reasonable doubt — 5 challenges an auditor might raise, and how to close each</h2>
<p class="subtle" style="margin: 0 0 0.6rem; font-size: 0.88rem;">
Receipts answer the integrity question. They do not, on their own, answer the
custody, authorization, or truth questions. Here is the honest short list.
</p>
<div class="item">
  <b>1. "The receipt was signed, but how do I know the signing key was held by you and not an attacker?"</b>
  <p>A receipt proves that <em>some</em> key with the documented fingerprint produced the signature. It does not prove that a specific person or organization held the key at the time of signing.</p>
  <p class="close">To close this gap: publish your public key on a timestamped, externally-mirrored channel (e.g., your website, a public git repo, an SSL transparency log). The earliest signature timestamp on a receipt is the latest moment at which an attacker could have started forging receipts under that key.</p>
</div>
<div class="item">
  <b>2. "The signing key is on the same machine as the LLM. Couldn't the LLM or the upstream provider have tampered with the prompt before signing?"</b>
  <p>The receipt is signed at the network boundary of the local proxy, on the operator's machine. A compromised upstream provider cannot tamper with a signed receipt after the fact; but a compromised local proxy that re-writes the prompt before signing could.</p>
  <p class="close">To close this gap: run <code>dontlie proxy</code> as a separate process from your agent runtime, on a separate user account if possible, and audit the proxy source. Don't co-locate the signing key with code that can construct prompts. For higher assurance, hold the key in an HSM, macOS Keychain, or another key-management service you operate — Don't-Lie signs with whatever key backend the operator configures.</p>
</div>
<div class="item">
  <b>3. "The receipt records that this model was called. It does not record whether the call was authorized."</b>
  <p>The receipt captures the bytes of the request and response. It does not capture who triggered the call, whether they had permission, or whether a policy gate approved it.</p>
  <p class="close">To close this gap: wrap the call in your own authorization layer and add a tag (e.g. <code>tags: ["authorized_by:user_42", "policy_gate:passed"]</code>) before the call hits the proxy. The tag itself becomes part of the signed payload, so the audit trail of authorization is also tamper-evident.</p>
</div>
<div class="item">
  <b>4. "The model response is recorded. That does not mean the model was correct."</b>
  <p>Hallucinations are recorded faithfully. A receipt proves what the model said, not whether what the model said was right. A signed receipt for a wrong answer is still a valid receipt.</p>
  <p class="close">To close this gap: don't rely on receipts to prove correctness. Use them to prove that the recorded answer is what the model produced, and use a separate evaluation layer (human review, eval suite, second model) to assess correctness. The receipt gives you the exact bytes to evaluate against.</p>
</div>
<div class="item">
  <b>5. "The receipt is dated 2026-07-28. How do I know the date wasn't backdated?"</b>
  <p>The timestamp is part of the signed payload. The receipt itself does not anchor that timestamp to external time.</p>
  <p class="close">To close this gap: anchor the chain to an external timestamping authority. Run a witness notary yourself (the CLI ships <code>dontlie witness-service</code>) and configure it to optionally fetch an RFC 3161 timestamp from a TSA you trust. Any third-party witness you point <code>dontlie witness-attest</code> at is a co-signature on the receipt hash; that witness's key fingerprint is the auditor's anchor.</p>
</div>
</div>
</section>

<section>
<h2>What this report proves (and what it does not)</h2>
<div class="fourup">
  <div class="legend-integrity">
    <h3>Integrity</h3>
    <p>Canonical payload hashes, signatures, parent links, and key-history rows
    are internally consistent. Receipts cannot be silently altered after the
    fact without breaking verification.</p>
  </div>
  <div class="legend-signer">
    <h3>Signer</h3>
    <p>The receipt was signed by whichever key produced the public-key PEM
    embedded in this bundle. The report does <em>not</em> assert that a
    particular person or organization operated that key.</p>
  </div>
  <div class="legend-provider">
    <h3>Provider</h3>
    <p>The receipt records the model name and the local proxy endpoint that
    forwarded the request. It does <em>not</em> independently attest the
    remote provider's identity or behavior.</p>
  </div>
  <div class="legend-truth">
    <h3>Truth</h3>
    <p>The receipt does <em>not</em> claim the model answer is correct.
    Hallucinations are recorded faithfully; that is the whole point. Use the
    receipts as evidence of <em>what</em>, not as a fact-checker of
    <em>whether</em>.</p>
  </div>
</div>
</section>

{workflow_html}

<section>
<h2>Verifier findings</h2>
<ul>{issue_html}</ul>
</section>

<section>
<h2>Signer — public keys embedded in this bundle</h2>
<table>
<thead><tr><th>Key ID</th><th>SHA-256 fingerprint</th><th>Public key (PEM, first 80 chars)</th></tr></thead>
<tbody>{key_rows_html}</tbody>
</table>
<p class="subtle">Re-pin these keys with
<code>dontlie verify --public-key KEY_ID=path/to/pub.pem</code> to prove the
bundle was authored by a key you trust.</p>
</section>

<section>
<h2>Provider — distinct models and endpoints</h2>
<h3 style="margin-bottom:.2rem">Models</h3>
<table><thead><tr><th>Model</th><th>Receipts</th></tr></thead><tbody>{model_rows}</tbody></table>
<h3 style="margin-bottom:.2rem; margin-top:1rem">Endpoints</h3>
<table><thead><tr><th>Endpoint</th><th>Receipts</th></tr></thead><tbody>{endpoint_rows}</tbody></table>
</section>

<section>
<h2>Integrity — receipt chain</h2>
<table>
<thead><tr><th>ID</th><th>Timestamp</th><th>Model</th><th>Parent</th><th>SHA-256</th><th>Signature</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
</section>

</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 2:
        print(f"usage: {Path(sys.argv[0]).name} BUNDLE.json OUTPUT.html", file=sys.stderr)
        return 2
    bundle, output = Path(args[0]), Path(args[1])
    if not bundle.exists():
        print(f"missing bundle: {bundle}", file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(bundle), encoding="utf-8")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

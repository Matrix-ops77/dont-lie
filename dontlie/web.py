"""dontlie web — stdlib-only HTTP UI for non-engineers.

Run with:
    python3 -m dontlie web
    python3 -m dontlie web --port 8080 --host 127.0.0.1

Then open http://127.0.0.1:8080 in any browser. The pages are
intentionally dependency-free (no JS frameworks, no CDN) so they
work on an air-gapped forensic workstation.

Endpoints:
    GET  /                           dashboard (counts, last 50 receipts, search, verify)
    GET  /receipt/<id>               full detail of one receipt
    GET  /search?q=<term>            search results page
    GET  /verify                     run verify, render result page
    GET  /export                     download portable verification bundle
    GET  /api/receipts?limit=N       JSON list of recent receipts
    GET  /api/receipts/<id>          JSON detail of one receipt
    GET  /api/verify                 JSON verify result
    GET  /api/stats                  JSON aggregate stats
    GET  /static/<file>              served from dontlie/web_static/ (none yet)
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import storage
from .storage import Receipt

# ---- helpers ----------------------------------------------------------------

def _shorten(value: str | None, n: int = 16) -> str:
    if not value:
        return "-"
    return value if len(value) <= n else value[:n] + "…"


def _fmt_ts(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts


def _esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _json(payload, status: int = 200) -> tuple[bytes, str, int]:
    body = json.dumps(payload, sort_keys=True, indent=2, default=str).encode("utf-8")
    return body, "application/json; charset=utf-8", status


# ---- HTML (all inline so the server is truly stdlib) ------------------------

_PAGE_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", ui-sans-serif, system-ui, sans-serif; max-width: 1200px; margin: 0 auto; padding: 1.5rem; line-height: 1.5; }
header { display: flex; align-items: center; gap: 1rem; border-bottom: 1px solid #8885; padding-bottom: 1rem; margin-bottom: 1.5rem; }
header h1 { margin: 0; font-size: 1.4rem; }
header nav a { margin-right: 1rem; color: inherit; text-decoration: none; opacity: .75; border-bottom: 1px dotted; }
header nav a:hover { opacity: 1; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0.8rem; margin: 1rem 0 1.5rem; }
.card { border: 1px solid #8885; border-radius: 0.6rem; padding: 0.9rem 1rem; }
.card strong { display: block; font-size: 1.6rem; }
.card.ok strong { color: #15803d; }
.card.bad strong { color: #b91c1c; }
.card .muted { font-size: 0.78rem; opacity: 0.7; display: block; margin-top: 0.1rem; }
.trust-card strong small { font-size: 0.6em; opacity: 0.6; font-weight: 400; }
.trust-breakdown { margin-top: 0.6rem; font-size: 0.78rem; line-height: 1.4; }
.trust-row { display: flex; justify-content: space-between; padding: 0.1rem 0; border-top: 1px solid #8883; }
.trust-row:first-child { border-top: none; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { text-align: left; border-bottom: 1px solid #8885; padding: 0.55rem 0.4rem; vertical-align: top; }
th { opacity: .75; font-weight: 600; }
tr:hover { background: #8882; }
a { color: #2563eb; }
.badge { display: inline-block; padding: 0.2rem 0.55rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.04em; }
.badge.ok { background: #d3f9d8; color: #064e3b; }
.badge.bad { background: #ffe2e2; color: #5b1010; }
.searchbox { display: flex; gap: 0.5rem; margin: 1rem 0; }
.searchbox input { flex: 1; padding: 0.5rem 0.7rem; font-size: 1rem; border: 1px solid #8885; border-radius: 0.4rem; background: inherit; color: inherit; }
.searchbox button, .btn { padding: 0.5rem 1rem; border: 1px solid #8885; border-radius: 0.4rem; background: #8881; color: inherit; cursor: pointer; font: inherit; }
.searchbox button:hover, .btn:hover { background: #8883; }
.btn-primary { background: #2563eb; color: #fff; border-color: #2563eb; }
.btn-primary:hover { background: #1d4ed8; }
pre { background: #8882; padding: 0.7rem; border-radius: 0.4rem; overflow-x: auto; font-size: 0.85rem; }
.muted { opacity: .6; font-size: 0.85rem; }
.kv { display: grid; grid-template-columns: max-content 1fr; gap: 0.3rem 0.8rem; font-size: 0.9rem; }
.kv b { opacity: .75; }
.legend { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.5rem; margin: 0.7rem 0 1.4rem; }
.legend > div { padding: 0.6rem 0.8rem; border-radius: 0.5rem; border-left: 4px solid; }
.legend h4 { margin: 0 0 0.2rem; font-size: 0.85rem; }
.legend p { margin: 0; font-size: 0.8rem; opacity: 0.92; }
.legend.integrity { background: #dbeafe; color: #0c2a5e; border-left-color: #2563eb; }
.legend.signer    { background: #ede4ff; color: #2e1065; border-left-color: #7c3aed; }
.legend.provider  { background: #d3f9d8; color: #064e3b; border-left-color: #15803d; }
.legend.truth     { background: #ffe2e2; color: #5b1010; border-left-color: #b91c1c; }
@media (prefers-color-scheme: dark) {
  body { background: #0a0a0a; color: #e5e5e5; }
  th, td, .card, pre { border-color: #333; }
  .legend.integrity { background: #1e3a8a; color: #dbeafe; border-left-color: #60a5fa; }
  .legend.signer    { background: #4c1d95; color: #ede4ff; border-left-color: #a78bfa; }
  .legend.provider  { background: #14532d; color: #d3f9d8; border-left-color: #4ade80; }
  .legend.truth     { background: #7f1d1d; color: #ffe2e2; border-left-color: #f87171; }
  a { color: #60a5fa; }
}
"""

_PAGE_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Don't-Lie vault</title>
<style>{css}</style>
</head>
<body>
<header>
  <h1>Don't-Lie</h1>
  <nav>
    <a href="/">Dashboard</a>
    <a href="/search">Search</a>
    <a href="/verify">Verify</a>
    <a href="/export">Export bundle</a>
    <a href="/api/stats">JSON</a>
  </nav>
</header>
<main>
"""

_PAGE_TAIL = "</main></body></html>"


def _wrap(title: str, body: str) -> str:
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{_esc(title)} — Don't-Lie</title>"
        f"<style>{_PAGE_CSS}</style></head><body>"
        '<header>'
        '  <h1>Don\'t-Lie</h1>'
        '  <nav>'
        '    <a href="/">Dashboard</a>'
        '    <a href="/search">Search</a>'
        '    <a href="/verify">Verify</a>'
        '    <a href="/export">Export bundle</a>'
        '    <a href="/api/stats">JSON</a>'
        '  </nav>'
        '</header>'
        "<main>"
        + body
        + "</main></body></html>"
    )


def _render_dashboard(limit: int = 50) -> str:
    storage.init()
    receipts = storage.list_receipts(limit=limit)
    total = storage.count()
    report = storage.verify_chain_report()
    status_class = "ok" if report.bad_count == 0 and report.ok_count else "bad" if report.bad_count else ""
    status_label = (
        f"{report.ok_count} ok / {report.bad_count} bad"
        if (report.ok_count + report.bad_count)
        else "empty"
    )
    # Trust score
    trust_html = ""
    try:
        from . import trust as _trust
        ts = _trust.compute()
        ts_class = (
            "ok" if ts.value >= 75 else "bad" if ts.value < 50 else ""
        )
        breakdown = "".join(
            f'<div class="trust-row"><span>{name.replace("_", " ")}</span>'
            f'<span class="muted">{c["value"]}/{c["max"]}</span></div>'
            for name, c in ts.components.items()
        )
        trust_html = (
            f'<div class="card {ts_class} trust-card">'
            f'<strong>{ts.value}<small>/100</small></strong>'
            f'<span class="muted">trust score ({ts.label})</span>'
            f'<div class="trust-breakdown">{breakdown}</div>'
            f'</div>'
        )
    except Exception:
        trust_html = ""
    cards = (
        f'<div class="cards">'
        f'<div class="card ok"><strong>{total}</strong>total receipts</div>'
        f'<div class="card {status_class}"><strong>{status_label}</strong>chain status</div>'
        f'{trust_html}'
        f'<div class="card"><strong>Ed25519</strong>signature scheme</div>'
        f"</div>"
    )
    legend = (
        '<div class="legend">'
        '<div class="legend integrity"><h4>Integrity</h4><p>Hashes and signatures form a verifiable chain.</p></div>'
        '<div class="legend signer"><h4>Signer</h4><p>Receipts are signed by the documented local key.</p></div>'
        '<div class="legend provider"><h4>Provider</h4><p>Model name and proxy endpoint are recorded.</p></div>'
        '<div class="legend truth"><h4>Truth</h4><p>Receipts do <em>not</em> claim model answers are correct.</p></div>'
        "</div>"
    )
    search = (
        '<form class="searchbox" action="/search" method="get">'
        '<input name="q" placeholder="search prompt / response / tags" autofocus>'
        '<button type="submit">Search</button>'
        "</form>"
    )
    rows = []
    for r in receipts:
        prompt_preview = (r.prompt or "").replace("\n", " ")[:80]
        if len(r.prompt or "") > 80:
            prompt_preview += "…"
        rows.append(
            "<tr>"
            f'<td><a href="/receipt/{r.id}">#{r.id}</a></td>'
            f"<td>{_esc(_fmt_ts(r.timestamp))}</td>"
            f"<td>{_esc(r.model or '?')}</td>"
            f"<td>{_esc(_shorten(r.key_id, 8))}</td>"
            f"<td>{_esc(prompt_preview)}</td>"
            "</tr>"
        )
    table = (
        "<table><thead><tr>"
        "<th>#</th><th>timestamp</th><th>model</th><th>key</th><th>prompt</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    if not receipts:
        table = '<p class="muted">No receipts yet. Start the proxy and make a call, or run <code>dontlie demo</code>.</p>'
    return _wrap("Dashboard", cards + legend + search + table)


def _render_receipt(rid: int) -> str:
    storage.init()
    r = storage.get_receipt(rid)
    if r is None:
        return _wrap("Not found", f'<p class="muted">Receipt #{rid} not found.</p><p><a href="/">← back to dashboard</a></p>')
    kv = (
        '<div class="kv">'
        f"<b>id</b><span>{r.id}</span>"
        f"<b>timestamp</b><span>{_esc(r.timestamp)}</span>"
        f"<b>model</b><span>{_esc(r.model or '?')}</span>"
        f"<b>parent</b><span>{r.parent_id if r.parent_id is not None else '—'}</span>"
        f"<b>key_id</b><span>{_esc(r.key_id)}</span>"
        f"<b>tags</b><span>{_esc(', '.join(r.tags)) if r.tags else '—'}</span>"
        f"<b>payload_sha256</b><span><code>{_esc(r.payload_sha256)}</code></span>"
        f"<b>signature</b><span><code>{_esc(r.signature)}</code></span>"
        "</div>"
    )
    if r.extra:
        kv += f'<h3>Extra</h3><pre>{_esc(json.dumps(r.extra, indent=2, sort_keys=True))}</pre>'
    body = (
        f'<h2>Receipt #{r.id}</h2>'
        + kv
        + f'<h3>Prompt</h3><pre>{_esc(r.prompt or "(empty)")}</pre>'
        + f'<h3>Response</h3><pre>{_esc(r.response or "(empty)")}</pre>'
        + f'<p><a class="btn" href="/api/receipts/{r.id}">view as JSON</a> '
        + '<a class="btn" href="/">← dashboard</a></p>'
    )
    return _wrap(f"Receipt #{r.id}", body)


def _render_search(query: str, limit: int = 100) -> str:
    storage.init()
    hits = storage.search(query, limit=limit) if query else []
    body = (
        '<h2>Search</h2>'
        f'<form class="searchbox" action="/search" method="get">'
        f'<input name="q" value="{_esc(query)}" placeholder="search prompt / response / tags" autofocus>'
        f'<button type="submit">Search</button></form>'
    )
    if not query:
        body += '<p class="muted">Type a query above and press Enter.</p>'
        return _wrap("Search", body)
    if not hits:
        body += f'<p class="muted">No matches for <code>{_esc(query)}</code>.</p>'
        return _wrap("Search", body)
    rows = []
    for r in hits:
        prompt_preview = (r.prompt or "").replace("\n", " ")[:100]
        if len(r.prompt or "") > 100:
            prompt_preview += "…"
        rows.append(
            "<tr>"
            f'<td><a href="/receipt/{r.id}">#{r.id}</a></td>'
            f"<td>{_esc(_fmt_ts(r.timestamp))}</td>"
            f"<td>{_esc(r.model or '?')}</td>"
            f"<td>{_esc(prompt_preview)}</td>"
            "</tr>"
        )
    body += (
        f'<p>{len(hits)} match{"es" if len(hits) != 1 else ""} for <code>{_esc(query)}</code>.</p>'
        '<table><thead><tr><th>#</th><th>timestamp</th><th>model</th><th>prompt</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table>"
    )
    return _wrap(f"Search: {query}", body)


def _render_verify() -> str:
    storage.init()
    report = storage.verify_chain_report()
    total = report.ok_count + report.bad_count
    if report.bad_count:
        status = "TAMPERED"
        klass = "bad"
    elif report.ok_count:
        status = "VERIFIED"
        klass = "ok"
    else:
        status = "EMPTY"
        klass = ""
    body = (
        '<h2>Chain verification</h2>'
        f'<div class="cards">'
        f'<div class="card"><strong>{total}</strong>total receipts</div>'
        f'<div class="card ok"><strong>{report.ok_count}</strong>valid</div>'
        f'<div class="card bad"><strong>{report.bad_count}</strong>invalid</div>'
        f'<div class="card {klass}"><strong>{status}</strong>status</div>'
        f'</div>'
        '<h3>Findings</h3>'
    )
    if report.issues:
        issues_html = "<ul>" + "".join(
            f"<li><b>receipt {i.receipt_id}</b>: {_esc(i.reason)}</li>"
            for i in report.issues
        ) + "</ul>"
        body += issues_html
    else:
        body += '<p class="muted">No issues found. Chain is intact.</p>'
    body += (
        '<p style="margin-top:1.5rem">'
        '<a class="btn btn-primary" href="/export">Download portable bundle</a> '
        '<a class="btn" href="/api/verify">view as JSON</a></p>'
    )
    return _wrap("Verify", body)


def _stats() -> dict:
    storage.init()
    conn = storage._connect()
    try:
        cur = conn.execute("SELECT COUNT(*) FROM receipts")
        total = cur.fetchone()[0]
        cur = conn.execute("SELECT DISTINCT model FROM receipts WHERE model IS NOT NULL ORDER BY model")
        models = [row[0] for row in cur.fetchall()]
        cur = conn.execute("SELECT COUNT(DISTINCT key_id) FROM receipts")
        distinct_keys = cur.fetchone()[0]
        cur = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM receipts")
        first, last = cur.fetchone()
    finally:
        conn.close()
    report = storage.verify_chain_report()
    return {
        "total_receipts": total,
        "ok": report.ok_count,
        "bad": report.bad_count,
        "distinct_models": models,
        "distinct_signing_keys": distinct_keys,
        "first_receipt_at": first,
        "last_receipt_at": last,
        "vault_path": str(storage.DB_PATH),
    }


# ---- HTTP handler -----------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    server_version = "dontlie-web/1.0"

    def log_message(self, fmt: str, *args) -> None:  # quiet by default
        sys.stderr.write(f"[dontlie-web] {self.address_string()} {fmt % args}\n")

    def _send(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        url = urlparse(self.path)
        path = url.path
        qs = parse_qs(url.query)

        try:
            if path == "/" or path == "/index.html":
                self._send(_render_dashboard().encode("utf-8"), "text/html; charset=utf-8")
            elif path.startswith("/receipt/"):
                rid_s = path[len("/receipt/"):].rstrip("/")
                try:
                    rid = int(rid_s)
                except ValueError:
                    self._send(b"invalid receipt id", "text/plain", 400)
                    return
                self._send(_render_receipt(rid).encode("utf-8"), "text/html; charset=utf-8")
            elif path == "/search":
                q = (qs.get("q") or [""])[0]
                self._send(_render_search(q).encode("utf-8"), "text/html; charset=utf-8")
            elif path == "/verify":
                self._send(_render_verify().encode("utf-8"), "text/html; charset=utf-8")
            elif path == "/export":
                self._handle_export()
            elif path == "/api/receipts":
                limit = int((qs.get("limit") or ["50"])[0])
                offset = int((qs.get("offset") or ["0"])[0])
                storage.init()
                receipts = storage.list_receipts(limit=limit, offset=offset)
                body, ct, status = _json({
                    "total": storage.count(),
                    "limit": limit,
                    "offset": offset,
                    "receipts": [_receipt_to_dict(r) for r in receipts],
                })
                self._send(body, ct, status)
            elif path.startswith("/api/receipts/"):
                rid_s = path[len("/api/receipts/"):].rstrip("/")
                try:
                    rid = int(rid_s)
                except ValueError:
                    self._send(b'{"error":"invalid id"}', "application/json", 400)
                    return
                storage.init()
                r = storage.get_receipt(rid)
                if r is None:
                    self._send(b'{"error":"not found"}', "application/json", 404)
                    return
                body, ct, status = _json(_receipt_to_dict(r))
                self._send(body, ct, status)
            elif path == "/api/verify":
                storage.init()
                report = storage.verify_chain_report()
                body, ct, status = _json({
                    "ok_count": report.ok_count,
                    "bad_count": report.bad_count,
                    "total": report.ok_count + report.bad_count,
                    "issues": [
                        {"receipt_id": i.receipt_id, "reason": i.reason}
                        for i in report.issues
                    ],
                })
                self._send(body, ct, status)
            elif path == "/api/stats":
                body, ct, status = _json(_stats())
                self._send(body, ct, status)
            else:
                self._send(b"not found", "text/plain", HTTPStatus.NOT_FOUND)
        except Exception as exc:  # pragma: no cover - defensive
            self._send(
                json.dumps({"error": str(exc)}).encode("utf-8"),
                "application/json",
                500,
            )

    def _handle_export(self) -> None:
        # Build a portable bundle in-memory and stream it as a download.
        storage.init()
        receipts = storage.list_receipts(limit=10_000)
        bundle = {
            "version": 1,
            "format": "dontlie-bundle/1",
            "public_keys": [],
            "revoked_key_ids": [],
            "receipts": [_receipt_to_dict(r) for r in receipts],
        }
        body = json.dumps(bundle, indent=2, sort_keys=True, default=str).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", 'attachment; filename="receipts.bundle.json"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _receipt_to_dict(r: Receipt) -> dict:
    d = asdict(r)
    return d


# ---- entry point ------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dontlie web", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="bind port (default: 8080)")
    parser.add_argument(
        "--vault",
        type=Path,
        default=None,
        help="path to vault.db (default: $DONTLIE_DB or ~/.local/share/dontlie/vault.db)",
    )
    args = parser.parse_args(argv)
    import os
    if args.vault is not None:
        storage.DB_PATH = args.vault
    elif "DONTLIE_DB" in os.environ:
        storage.DB_PATH = Path(os.environ["DONTLIE_DB"])
    storage.init()
    server = ThreadingHTTPServer((args.host, args.port), _Handler)
    print(f"dontlie web — http://{args.host}:{args.port}/")
    print(f"  vault: {storage.DB_PATH}")
    print("  press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down…")
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())

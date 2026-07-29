"""Stripe Checkout session creator for Don't-Lie.

Stdlib-only HTTP server. The static checkout page POSTs to
``/api/create-checkout-session`` with a JSON body
``{"tier": "local|pro|team", "email": "..."}``. This handler maps the
tier to a Stripe price ID, creates a Checkout Session, and returns the
session URL. The page then redirects the browser to Stripe.

Env vars (required):
    STRIPE_SECRET_KEY                — sk_live_... or sk_test_...
    STRIPE_PRICE_PRO                 — price_...
    STRIPE_PRICE_TEAM                — price_...

Env vars (optional):
    STRIPE_SUCCESS_URL               — defaults to /thanks.html
    STRIPE_CANCEL_URL                — defaults to /CHECKOUT.html

If STRIPE_SECRET_KEY is not set, the endpoint returns 503 with a
payload that the page renders as a /pricing-not-configured screen.

Run:
    python3 site/checkout_server.py --port 8081
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STRIPE_API = "https://api.stripe.com/v1/checkout/sessions"

TIER_TO_PRICE_ENV = {
    "pro": "STRIPE_PRICE_PRO",
    "team": "STRIPE_PRICE_TEAM",
}

TIER_TO_AMOUNT_FALLBACK = {
    # Fallback amount table when price IDs are not set. We use
    # amount-only mode (line_items.price_data) in that case. Local is
    # free and never billed — it returns a 200 with a redirect to
    # /thanks.html?free=1 instead of touching Stripe.
    # NOTE: pricing here is 10x lower than the published site tiers
    # ($49 Pro / $299 Team). This table is intentionally inert. The
    # code path that uses it is unreachable; we only keep the values
    # documented for reference. Real prices must be set via the
    # STRIPE_PRICE_PRO and STRIPE_PRICE_TEAM env vars.
    "pro": 4900,   # $49.00 (canonical Pro tier; fallback disabled)
    "team": 29900, # $299.00 (canonical Team tier; fallback disabled)
}

TIER_NAME = {"pro": "Pro", "team": "Team"}


def _not_configured_response(reason: str) -> dict:
    return {
        "ok": False,
        "configured": False,
        "error": "pricing-not-configured",
        "reason": reason,
        "fallback_url": "/pricing.html",
    }


def _create_session(tier: str, email: str | None) -> dict:
    if tier == "local":
        # Local is free; just bounce to thanks page. No Stripe needed.
        return {
            "ok": True,
            "url": "/thanks.html?free=1",
            "free": True,
        }

    secret = os.environ.get("STRIPE_SECRET_KEY", "")
    if not secret:
        return _not_configured_response(
            "STRIPE_SECRET_KEY is not set. Set it in the server's environment."
        )

    if tier not in TIER_TO_PRICE_ENV:
        return {"ok": False, "error": f"unknown tier: {tier}"}

    price_id = os.environ.get(TIER_TO_PRICE_ENV[tier], "")
    success_url = os.environ.get(
        "STRIPE_SUCCESS_URL", "https://dontlie.local/thanks.html"
    )
    cancel_url = os.environ.get(
        "STRIPE_CANCEL_URL", "https://dontlie.local/CHECKOUT.html"
    )

    form = [
        ("mode", "subscription"),
        ("line_items[0][quantity]", "1"),
        ("success_url", success_url + "?session_id={CHECKOUT_SESSION_ID}"),
        ("cancel_url", cancel_url),
        ("allow_promotion_codes", "true"),
    ]

    if price_id:
        form.append(("line_items[0][price]", price_id))
    else:
        # Fail closed: do NOT bill at a fallback price. The published
        # tier prices are $49/mo Pro and $299/mo Team. If the operator
        # has not configured STRIPE_PRICE_PRO / STRIPE_PRICE_TEAM yet,
        # we'd rather bounce them to the pricing-not-configured screen
        # than silently bill them the wrong amount. The fallback
        # amount table is preserved above for documentation only.
        return _not_configured_response(
            f"STRIPE_PRICE_{tier.upper()} is not set. "
            "Configure Stripe price IDs in the server's environment."
        )

    if email:
        form.append(("customer_email", email))

    body = urllib.parse.urlencode(form).encode("utf-8") if hasattr(urllib, "parse") else \
        "&".join(f"{k}={urllib.parse.quote_plus(v)}" for k, v in form).encode("utf-8")

    req = urllib.request.Request(
        STRIPE_API,
        data=body,
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8")
        except Exception:
            body = ""
        return {"ok": False, "error": "stripe_http_error", "status": e.code, "body": body[:500]}
    except Exception as e:
        return {"ok": False, "error": "stripe_request_failed", "reason": str(e)[:200]}

    url = payload.get("url")
    if not url:
        return {"ok": False, "error": "stripe_missing_url", "payload": payload}

    return {"ok": True, "url": url, "session_id": payload.get("id")}


class CheckoutHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:  # noqa: D401
        pass

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/create-checkout-session":
            self.send_error(404, "not found")
            return
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "invalid JSON"})
            return
        tier = (body.get("tier") or "").strip().lower()
        email = body.get("email")
        result = _create_session(tier, email)
        status = 200 if result.get("ok") else (
            503 if result.get("configured") is False else 500
        )
        self._send_json(status, result)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_json(200, {
                "ok": True,
                "stripe_configured": bool(os.environ.get("STRIPE_SECRET_KEY")),
                "price_pro": bool(os.environ.get("STRIPE_PRICE_PRO")),
                "price_team": bool(os.environ.get("STRIPE_PRICE_TEAM")),
            })
            return
        self.send_error(404, "not found")

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("access-control-allow-origin", "*")
        self.end_headers()
        self.wfile.write(body)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Don't-Lie Stripe Checkout backend")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args(argv)

    # Import here for the urlencoding helper.
    import urllib.parse  # noqa: F401

    httpd = ThreadingHTTPServer((args.host, args.port), CheckoutHandler)
    print(f"checkout backend listening on http://{args.host}:{args.port}", file=sys.stderr)
    print(f"  POST /api/create-checkout-session", file=sys.stderr)
    print(f"  GET  /health", file=sys.stderr)
    print(f"  stripe_configured: {bool(os.environ.get('STRIPE_SECRET_KEY'))}", file=sys.stderr)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

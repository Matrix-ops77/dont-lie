"""Stripe self-serve checkout.

This module is a thin wrapper around the Stripe REST API. It exposes
two helpers:

* ``create_checkout_session`` — returns a hosted Stripe Checkout URL for
  one of the three plans (Local is free and never billed; Team is $299/mo;
  Enterprise opens a sales contact).
* ``handle_webhook`` — validates a Stripe webhook signature and returns
  the parsed event. The caller is responsible for acting on it.

The module is optional: if ``stripe`` is not installed, it raises
``StripeUnavailable``. The host application is responsible for
bootstrapping a Stripe API key via ``DONTLIE_STRIPE_SECRET_KEY`` and the
webhook signing secret via ``DONTLIE_STRIPE_WEBHOOK_SECRET``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    import stripe  # type: ignore


class StripeUnavailable(ImportError):
    """Raised when the optional ``stripe`` dependency is not installed."""


class StripeError(RuntimeError):
    """Raised for any Stripe-related failure (network, auth, signature)."""


@dataclass(frozen=True)
class Plan:
    key: str
    name: str
    price_cents: int
    interval: str
    description: str


PLANS = {
    "team": Plan(
        key="team",
        name="Don't-Lie Team",
        price_cents=29900,
        interval="month",
        description="Hosted vault with encrypted retention, shared namespaces, alerts.",
    ),
    "team-annual": Plan(
        key="team-annual",
        name="Don't-Lie Team (Annual)",
        price_cents=299000,
        interval="year",
        description="Hosted vault with encrypted retention, shared namespaces, alerts.",
    ),
    "enterprise": Plan(
        key="enterprise",
        name="Don't-Lie Enterprise",
        price_cents=0,
        interval="custom",
        description="SSO, RBAC, anchored timestamps, compliance templates. Contact sales.",
    ),
}


def _client():
    try:
        import stripe  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dep
        raise StripeUnavailable(
            "install the `stripe` package to enable billing"
        ) from exc
    key = os.environ.get("DONTLIE_STRIPE_SECRET_KEY")
    if not key:
        raise StripeError("DONTLIE_STRIPE_SECRET_KEY is not set")
    stripe.api_key = key
    return stripe


def _has_secret_key() -> bool:
    return bool(os.environ.get("DONTLIE_STRIPE_SECRET_KEY"))


def create_checkout_session(
    plan: str,
    *,
    customer_email: str,
    success_url: str,
    cancel_url: str,
    origin: str | None = None,
) -> str:
    """Create a Stripe Checkout session and return its URL."""
    if plan not in PLANS:
        raise StripeError(f"unknown plan: {plan!r}")
    if PLANS[plan].price_cents == 0:
        # Enterprise: redirect to a contact form.
        return f"{origin or success_url.rsplit('/', 1)[0]}/contact?reason=enterprise"
    if not _has_secret_key():
        raise StripeError("DONTLIE_STRIPE_SECRET_KEY is not set")
    stripe = _client()
    payload: dict[str, Any] = {
        "mode": "subscription",
        "line_items": [
            {
                "price_data": {
                    "currency": "usd",
                    "unit_amount": PLANS[plan].price_cents,
                    "recurring": {"interval": PLANS[plan].interval},
                    "product_data": {
                        "name": PLANS[plan].name,
                        "description": PLANS[plan].description,
                    },
                },
                "quantity": 1,
            }
        ],
        "success_url": success_url,
        "cancel_url": cancel_url,
        "customer_email": customer_email,
        "allow_promotion_codes": True,
    }
    session = stripe.checkout.Session.create(**payload)
    return str(session.url)


def verify_webhook_signature(payload: bytes, signature: str) -> dict[str, Any]:
    """Verify a Stripe webhook signature and return the parsed event."""
    secret = os.environ.get("DONTLIE_STRIPE_WEBHOOK_SECRET")
    if not secret:
        raise StripeError("DONTLIE_STRIPE_WEBHOOK_SECRET is not set")
    try:
        import stripe  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise StripeUnavailable("install the `stripe` package") from exc
    try:
        event = stripe.Webhook.construct_event(payload, signature, secret)
    except Exception as exc:
        raise StripeError(f"invalid webhook signature: {exc}") from exc
    return dict(event)


def quick_checkout_url(
    plan: str,
    email: str,
    origin: str = "https://dontlie.app",
) -> str:
    """Build a deterministic checkout URL stub for tests and demos.

    Does not contact Stripe. The real implementation is
    ``create_checkout_session`` and requires the ``stripe`` package.
    """
    if plan not in PLANS:
        raise StripeError(f"unknown plan: {plan!r}")
    digest = hashlib.sha256(f"{plan}|{email}|{time.time_ns()}".encode("utf-8")).hexdigest()[:16]
    return f"{origin}/billing/checkout?session={digest}"


def plans() -> dict[str, Plan]:
    return dict(PLANS)


__all__ = [
    "Plan",
    "PLANS",
    "StripeError",
    "StripeUnavailable",
    "create_checkout_session",
    "verify_webhook_signature",
    "quick_checkout_url",
    "plans",
]

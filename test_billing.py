"""Tests for the billing helpers."""

from __future__ import annotations

import unittest

from dontlie.billing import (
    PLANS,
    StripeError,
    plans,
    quick_checkout_url,
)


class BillingPlanTest(unittest.TestCase):
    def test_plans_catalog(self) -> None:
        p = plans()
        self.assertEqual(p["team"].price_cents, 29900)
        self.assertEqual(p["team"].interval, "month")
        self.assertEqual(p["enterprise"].price_cents, 0)

    def test_plans_dict_matches_constant(self) -> None:
        self.assertEqual(set(plans()), set(PLANS))

    def test_quick_checkout_url_contains_plan(self) -> None:
        url = quick_checkout_url("team", "user@example.com")
        self.assertIn("checkout", url)
        self.assertIn("session=", url)
        self.assertIn("dontlie.app", url)

    def test_unknown_plan_raises(self) -> None:
        with self.assertRaises(StripeError):
            quick_checkout_url("not-a-real-plan", "user@example.com")

    def test_checkout_session_requires_stripe_key(self) -> None:
        from dontlie.billing import create_checkout_session
        import os

        os.environ.pop("DONTLIE_STRIPE_SECRET_KEY", None)
        with self.assertRaises(StripeError):
            create_checkout_session(
                "team",
                customer_email="user@example.com",
                success_url="https://dontlie.app/success",
                cancel_url="https://dontlie.app/cancel",
            )


if __name__ == "__main__":
    unittest.main()

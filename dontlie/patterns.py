"""Compiled regex patterns for RedactionPolicy."""

from __future__ import annotations

import re


def luhn_check(card: str) -> bool:
    """Luhn check for credit-card-like digit strings."""
    digits = [int(c) for c in card if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def build_default_patterns() -> dict[str, re.Pattern]:
    return {
        "PRIVATE_KEY_BLOCK": re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "BASIC_AUTH": re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{8,}\b"),
        "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "OPENAI_API_KEY": re.compile(r"\bsk-(?!ant-|proj-)[A-Za-z0-9_-]{20,}\b"),
        "OPENAI_PROJECT_KEY": re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"),
        "ANTHROPIC_API_KEY": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        "AWS_ACCESS_KEY_ID": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "GOOGLE_API_KEY": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "GITHUB_TOKEN": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        "SLACK_TOKEN": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        "STRIPE_API_KEY": re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "CREDIT_CARD": re.compile(
            r"(?<![\d-])((?:\d[ -]?){12,18}\d)(?![\d-])", re.MULTILINE
        ),
        "PHONE": re.compile(
            r"\b(?:\+?\d{1,3}[\s-]?)?(?:\(\d{3}\)|\d{3})[\s-]?\d{3}[\s-]?\d{4}\b"
        ),
    }


__all__ = ["build_default_patterns", "luhn_check"]

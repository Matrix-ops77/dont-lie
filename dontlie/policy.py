"""dontlie policy — pre-call allow/deny/redact filters on the proxy.

A policy is a set of rules evaluated BEFORE the proxy forwards a request
to the upstream provider. Each rule is one of:

  deny_model   <glob>          refuse if the request would call this model
  deny_prompt  <substring>     refuse if the prompt contains this substring
  allow_only   <model-glob>    refuse any model not matching
  redact_pii   true|false      strip emails / SSNs / credit cards / API keys
                                from the prompt before forwarding

Policies are stored as a JSON file at $DONTLIE_POLICY (default:
~/.config/dontlie/policy.json). The proxy loads it on startup; the CLI
subcommands manage it.

When a request is denied, the proxy still writes a receipt — the denial
itself is signed evidence that the call was blocked. The receipt's
response field contains the reason for the deny, and a special tag
`policy:denied` is added.

This is genuinely novel vs. Aulite/Asqav: their policy is enforced
*after* the call, on the response. We enforce *before*, on the request,
and the denial is itself signed. The receipt chain is unbroken even for
blocked calls.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

DEFAULT_POLICY_PATH = Path.home() / ".config" / "dontlie" / "policy.json"

# Built-in PII patterns (extend via the redact_pii_patterns rule)
_PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "api_key": re.compile(r"\b(sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-cp-[A-Za-z0-9_-]{20,})\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
}


@dataclass
class Policy:
    deny_models: list[str] = field(default_factory=list)
    deny_prompts: list[str] = field(default_factory=list)
    allow_only: list[str] = field(default_factory=list)
    redact_pii: bool = False
    redact_pii_patterns: list[str] = field(default_factory=list)  # names from _PII_PATTERNS

    def to_dict(self) -> dict:
        return {
            "deny_models": self.deny_models,
            "deny_prompts": self.deny_prompts,
            "allow_only": self.allow_only,
            "redact_pii": self.redact_pii,
            "redact_pii_patterns": self.redact_pii_patterns,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Policy:
        return cls(
            deny_models=list(d.get("deny_models", []) or []),
            deny_prompts=list(d.get("deny_prompts", []) or []),
            allow_only=list(d.get("allow_only", []) or []),
            redact_pii=bool(d.get("redact_pii", False)),
            redact_pii_patterns=list(d.get("redact_pii_patterns", []) or []),
        )

    def save(self, path: Path | None = None) -> Path:
        path = Path(path) if path is not None else _policy_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))
        return path

    @classmethod
    def load(cls, path: Path | None = None) -> Policy:
        path = Path(path) if path is not None else _policy_path()
        if not path.exists():
            return cls()
        try:
            return cls.from_dict(json.loads(path.read_text()))
        except Exception:
            return cls()


def _policy_path() -> Path:
    env = os.environ.get("DONTLIE_POLICY")
    if env:
        return Path(env)
    return DEFAULT_POLICY_PATH


# ---- evaluation --------------------------------------------------------------

@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""
    redacted_prompt: str | None = None
    redactions: list[str] = field(default_factory=list)


def evaluate(policy: Policy, *, model: str, prompt: str) -> PolicyDecision:
    """Evaluate a policy against a proposed call. Returns allow/deny + redacted prompt."""
    # 1. deny_models
    for pattern in policy.deny_models:
        if fnmatch(model, pattern):
            return PolicyDecision(allowed=False, reason=f"model {model!r} denied by policy (matches {pattern!r})")
    # 2. allow_only
    if policy.allow_only and not any(fnmatch(model, p) for p in policy.allow_only):
        return PolicyDecision(allowed=False, reason=f"model {model!r} not in allow_only list {policy.allow_only}")
    # 3. deny_prompts
    for needle in policy.deny_prompts:
        if needle in prompt:
            return PolicyDecision(allowed=False, reason=f"prompt contains denied substring {needle!r}")
    # 4. redact_pii
    redacted = prompt
    redactions: list[str] = []
    if policy.redact_pii:
        for name in (policy.redact_pii_patterns or list(_PII_PATTERNS.keys())):
            pattern = _PII_PATTERNS.get(name)
            if pattern is None:
                continue
            new_redacted, n = pattern.subn(f"[REDACTED:{name}]", redacted)
            if n > 0:
                redactions.append(f"{name}×{n}")
                redacted = new_redacted
    return PolicyDecision(
        allowed=True,
        redacted_prompt=redacted if redactions else None,
        redactions=redactions,
    )


# ---- CLI ---------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="dontlie policy", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_show = sub.add_parser("show", help="show the active policy")
    p_show.set_defaults(func=lambda a: _cmd_show(a))

    p_test = sub.add_parser("test", help="test a call against the active policy")
    p_test.add_argument("--model", required=True)
    p_test.add_argument("--prompt", required=True)
    p_test.set_defaults(func=lambda a: _cmd_test(a))

    p_deny = sub.add_parser("deny-model", help="add a model pattern to deny")
    p_deny.add_argument("pattern")
    p_deny.set_defaults(func=lambda a: _cmd_deny_model(a))

    p_deny_p = sub.add_parser("deny-prompt", help="add a prompt substring to deny")
    p_deny_p.add_argument("substring")
    p_deny_p.set_defaults(func=lambda a: _cmd_deny_prompt(a))

    p_allow = sub.add_parser("allow-only", help="restrict to a set of model patterns (empty = unrestricted)")
    p_allow.add_argument("patterns", nargs="*")
    p_allow.set_defaults(func=lambda a: _cmd_allow_only(a))

    p_redact = sub.add_parser("redact-pii", help="turn PII redaction on/off")
    p_redact.add_argument("enabled", choices=["on", "off"])
    p_redact.set_defaults(func=lambda a: _cmd_redact_pii(a))

    p_path = sub.add_parser("path", help="show the policy file path")
    p_path.set_defaults(func=lambda a: _cmd_path(a))

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_show(args) -> int:
    p = Policy.load()
    print(json.dumps(p.to_dict(), indent=2, sort_keys=True))
    return 0


def _cmd_test(args) -> int:
    p = Policy.load()
    d = evaluate(p, model=args.model, prompt=args.prompt)
    if d.allowed:
        print("ALLOWED")
    else:
        print(f"DENIED: {d.reason}")
    if d.redacted_prompt is not None:
        print(f"REDACTED ({', '.join(d.redactions)}):")
        print(d.redacted_prompt)
    return 0 if d.allowed else 1


def _cmd_deny_model(args) -> int:
    p = Policy.load()
    if args.pattern not in p.deny_models:
        p.deny_models.append(args.pattern)
        p.save()
    print(f"deny-models: {p.deny_models}")
    return 0


def _cmd_deny_prompt(args) -> int:
    p = Policy.load()
    if args.substring not in p.deny_prompts:
        p.deny_prompts.append(args.substring)
        p.save()
    print(f"deny-prompts: {p.deny_prompts}")
    return 0


def _cmd_allow_only(args) -> int:
    p = Policy.load()
    p.allow_only = list(args.patterns)
    p.save()
    print(f"allow-only: {p.allow_only}")
    return 0


def _cmd_redact_pii(args) -> int:
    p = Policy.load()
    p.redact_pii = (args.enabled == "on")
    p.save()
    print(f"redact-pii: {p.redact_pii}")
    return 0


def _cmd_path(args) -> int:
    print(_policy_path())
    return 0


if __name__ == "__main__":
    sys.exit(main())

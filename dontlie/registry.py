"""dontlie registry — known provider attestation registry.

A provider attestation says: "this receipt was made by a call to
<provider>'s API, and we have a way to verify that." The registry is
a JSON file at $DONTLIE_REGISTRY (default:
~/.config/dontlie/registry.json) that maps provider names to a
verification recipe.

What it proves (and what it doesn't):

  Proves       — the receipt's model field matches a known provider
                 AND the operator is willing to attest that their
                 traffic to that provider is what the receipt says
  Does NOT    — that the provider actually responded (only the
                 provider can sign for that)

The registry is the operator's word, not the provider's. To get
a provider's signature on a receipt, you need the witness protocol
or a provider-side integration (out of scope for v0.3).

The registry lets the operator add a `provider_attested:true` tag
to receipts by matching them against a known list. This is the
input to the `provider_attestation` component of the trust score.

CLI:
    dontlie registry list
    dontlie registry show openai
    dontlie registry add <name> --model-pattern <glob> --base-url <url>
    dontlie registry attest <receipt_id>            # check & tag if matches
    dontlie registry verify <receipt_id>            # just check
"""
from __future__ import annotations

import fnmatch
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import storage

DEFAULT_REGISTRY_PATH = Path.home() / ".config" / "dontlie" / "registry.json"


@dataclass
class Provider:
    name: str
    model_pattern: str       # glob; the receipt's model must match
    base_url: str
    attestable: bool = True  # if false, the registry is informational only
    notes: str = ""
    extra: dict = field(default_factory=dict)


def _registry_path() -> Path:
    env = os.environ.get("DONTLIE_REGISTRY")
    if env:
        return Path(env)
    return DEFAULT_REGISTRY_PATH


def load(path: Path | None = None) -> dict[str, Provider]:
    """Load the registry from disk. Returns an empty dict if the file doesn't exist.

    Supports both a list form (order-preserving) and a dict form (older).
    """
    path = Path(path) if path is not None else _registry_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    out: dict[str, Provider] = {}
    providers = data.get("providers")
    if isinstance(providers, list):
        for p in providers:
            name = p.get("name") or p.get("model_pattern", "?")
            out[name] = Provider(
                name=name,
                model_pattern=p.get("model_pattern", "*"),
                base_url=p.get("base_url", ""),
                attestable=bool(p.get("attestable", True)),
                notes=p.get("notes", ""),
                extra=p.get("extra", {}),
            )
    elif isinstance(providers, dict):
        for name, p in providers.items():
            out[name] = Provider(
                name=name,
                model_pattern=p.get("model_pattern", "*"),
                base_url=p.get("base_url", ""),
                attestable=bool(p.get("attestable", True)),
                notes=p.get("notes", ""),
                extra=p.get("extra", {}),
            )
    return out


def save(registry: dict[str, Provider], path: Path | None = None) -> Path:
    path = Path(path) if path is not None else _registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Store providers as a LIST to preserve insertion order — JSON object
    # keys sort alphabetically, which would lose the order we rely on for
    # "more specific patterns first".
    data = {
        "version": 1,
        "providers": [
            {
                "name": p.name,
                "model_pattern": p.model_pattern,
                "base_url": p.base_url,
                "attestable": p.attestable,
                "notes": p.notes,
                "extra": p.extra,
            }
            for p in registry.values()
        ],
    }
    path.write_text(json.dumps(data, indent=2))
    return path


def default_registry() -> dict[str, Provider]:
    """Return the curated default registry (12 known providers)."""
    return {
        "openai": Provider(
            name="openai",
            model_pattern="gpt-*",
            base_url="https://api.openai.com/v1",
            notes="OpenAI chat-completions endpoint. Includes gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-3.5-turbo, o1, o1-mini, o3, o3-mini.",
        ),
        "anthropic": Provider(
            name="anthropic",
            model_pattern="claude-*",
            base_url="https://api.anthropic.com",
            notes="Anthropic Messages API. Includes claude-3-5-sonnet, claude-3-opus, claude-3-haiku, claude-3-5-haiku.",
        ),
        "MiniMax": Provider(
            name="MiniMax",
            model_pattern="MiniMax-*",
            base_url="https://api.minimax.io/v1",
            notes="MiniMax Open Platform. OpenAI-compatible. Includes MiniMax-M2, MiniMax-M3.",
        ),
        "google": Provider(
            name="google",
            model_pattern="gemini-*",
            base_url="https://generativelanguage.googleapis.com",
            notes="Google AI / Gemini API. Includes gemini-1.5-pro, gemini-1.5-flash, gemini-2.0-flash.",
        ),
        "mistral": Provider(
            name="mistral",
            model_pattern="mistral-*",
            base_url="https://api.mistral.ai/v1",
            notes="Mistral AI. Includes mistral-large, mistral-small, mixtral, codestral.",
        ),
        "meta": Provider(
            name="meta",
            model_pattern="llama*",
            base_url="https://api.meta.ai/v1",
            notes="Meta Llama. Includes llama3.1-70b, llama3.1-8b, llama3.2-90b-vision.",
        ),
        "cohere": Provider(
            name="cohere",
            model_pattern="command-*",
            base_url="https://api.cohere.com/v1",
            notes="Cohere Command. Includes command-r-plus, command-r, command-light.",
        ),
        "deepseek": Provider(
            name="deepseek",
            model_pattern="deepseek-*",
            base_url="https://api.deepseek.com/v1",
            notes="DeepSeek. Includes deepseek-chat, deepseek-coder, deepseek-reasoner.",
        ),
        "groq": Provider(
            name="groq",
            model_pattern="*",
            base_url="https://api.groq.com/openai/v1",
            notes="Groq. OpenAI-compatible. Wildcard because Groq hosts many models.",
        ),
        "together": Provider(
            name="together",
            model_pattern="*",
            base_url="https://api.together.xyz/v1",
            notes="Together AI. OpenAI-compatible. Wildcard for the same reason.",
        ),
        "openrouter": Provider(
            name="openrouter",
            model_pattern="*",
            base_url="https://openrouter.ai/api/v1",
            notes="OpenRouter. OpenAI-compatible. Wildcard.",
        ),
        "local": Provider(
            name="local",
            model_pattern="*",
            base_url="http://localhost:*",
            notes="Local model servers (Ollama, vLLM, llama.cpp, etc.).",
            attestable=False,  # the operator can't attest to upstream behavior
        ),
    }


def install_default(path: Path | None = None) -> Path:
    """Write the curated default registry if no registry exists yet."""
    path = Path(path) if path is not None else _registry_path()
    if not path.exists():
        save(default_registry(), path)
    return path


def match(receipt, registry: dict[str, Provider]) -> tuple[str, Provider] | None:
    """Return (provider_name, provider) if the receipt's model matches any registered provider."""
    for name, p in registry.items():
        if fnmatch.fnmatch(receipt.model or "", p.model_pattern):
            return name, p
    return None


def attest(receipt) -> tuple[str, Provider] | None:
    """Convenience: load the registry, check if the receipt matches, return the match."""
    reg = load()
    return match(receipt, reg)


def add_to_receipt_tags(receipt, tag: str) -> None:
    """Add a tag to a receipt (preserves the rest)."""
    if tag in receipt.tags:
        return
    new_tags = list(receipt.tags) + [tag]
    conn = storage._connect()
    try:
        conn.execute(
            "UPDATE receipts SET tags = ? WHERE id = ?",
            (json.dumps(new_tags), receipt.id),
        )
        conn.commit()
    finally:
        conn.close()


# ---- CLI -------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="dontlie registry", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="list registered providers")
    p_list.set_defaults(func=lambda a: _cmd_list(a))

    p_show = sub.add_parser("show", help="show one provider")
    p_show.add_argument("name")
    p_show.set_defaults(func=lambda a: _cmd_show(a))

    p_add = sub.add_parser("add", help="add a custom provider")
    p_add.add_argument("name")
    p_add.add_argument("--model-pattern", default="*")
    p_add.add_argument("--base-url", default="")
    p_add.add_argument("--notes", default="")
    p_add.set_defaults(func=lambda a: _cmd_add(a))

    p_install = sub.add_parser("install-default", help="install the curated 12-provider default registry")
    p_install.set_defaults(func=lambda a: _cmd_install_default(a))

    p_attest = sub.add_parser("attest", help="check a receipt against the registry and add the provider tag")
    p_attest.add_argument("receipt_id", type=int)
    p_attest.set_defaults(func=lambda a: _cmd_attest(a))

    p_verify = sub.add_parser("verify", help="check a receipt against the registry (no tag added)")
    p_verify.add_argument("receipt_id", type=int)
    p_verify.set_defaults(func=lambda a: _cmd_verify(a))

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_list(args) -> int:
    reg = load()
    if not reg:
        print("no providers registered. run `dontlie registry install-default` to seed.")
        return 0
    for name, p in reg.items():
        marker = "✓" if p.attestable else " "
        print(f"  [{marker}] {name:12s}  {p.model_pattern:20s}  {p.base_url}")
    return 0


def _cmd_show(args) -> int:
    reg = load()
    if args.name not in reg:
        print(f"provider {args.name!r} not found", file=sys.stderr)
        return 1
    p = reg[args.name]
    print(f"Provider {p.name!r}")
    print(f"  model_pattern: {p.model_pattern}")
    print(f"  base_url:      {p.base_url}")
    print(f"  attestable:    {p.attestable}")
    if p.notes:
        print(f"  notes:         {p.notes}")
    return 0


def _cmd_add(args) -> int:
    reg = load()
    reg[args.name] = Provider(
        name=args.name,
        model_pattern=args.model_pattern,
        base_url=args.base_url,
        notes=args.notes,
    )
    save(reg)
    print(f"added {args.name!r}")
    return 0


def _cmd_install_default(args) -> int:
    path = install_default()
    print(f"installed default registry at {path}")
    print(f"  {len(default_registry())} providers")
    return 0


def _cmd_attest(args) -> int:
    r = storage.get_receipt(args.receipt_id)
    if r is None:
        print(f"receipt {args.receipt_id} not found", file=sys.stderr)
        return 1
    m = attest(r)
    if m is None:
        print(f"receipt #{r.id} (model={r.model!r}) does not match any registered provider")
        return 1
    name, p = m
    if not p.attestable:
        print(f"matched {name!r} but it is marked attestable=false; not tagging")
        return 0
    add_to_receipt_tags(r, f"provider_attested:{name}")
    print(f"receipt #{r.id} (model={r.model!r}) attested by {name!r}")
    return 0


def _cmd_verify(args) -> int:
    r = storage.get_receipt(args.receipt_id)
    if r is None:
        print(f"receipt {args.receipt_id} not found", file=sys.stderr)
        return 1
    m = attest(r)
    if m is None:
        print(f"no provider match for model={r.model!r}")
        return 1
    name, p = m
    print(f"matched: {name!r}  model={r.model!r}  attestable={p.attestable}  base_url={p.base_url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Dependency-free onboarding CLI for passive instrumentation."""

from __future__ import annotations

import argparse
import importlib.util
import os
import shlex
import sqlite3
import sys
from pathlib import Path

from .runtime import discover_vault


def shell_line() -> str:
    project_root = Path(__file__).resolve().parent.parent
    onboard_dir = project_root / "onboard"
    bootstrap_dir = onboard_dir / "bootstrap"
    python_path = shlex.quote(f"{project_root}:{bootstrap_dir}")
    command_path = shlex.quote(str(onboard_dir))
    return (
        f"export PYTHONPATH={python_path}${{PYTHONPATH:+:$PYTHONPATH}}; "
        f"export PATH={command_path}${{PATH:+:$PATH}}"
    )


def cmd_init(_args: argparse.Namespace) -> int:
    print(shell_line())
    return 0


def _receipt_count(vault: Path) -> int:
    if not vault.exists():
        return 0
    try:
        with sqlite3.connect(f"file:{vault}?mode=ro", uri=True) as connection:
            row = connection.execute("SELECT COUNT(*) FROM receipts").fetchone()
        return int(row[0]) if row else 0
    except (sqlite3.Error, OSError, ValueError):
        return 0


def cmd_status(_args: argparse.Namespace) -> int:
    vault = discover_vault()
    active = os.environ.get("DONTLIE_PASSIVE_ACTIVE") == "1"
    signing_available = _module_available("cryptography")
    providers = {
        "openai": _module_available("openai"),
        "anthropic": _module_available("anthropic"),
        "gemini": _module_available("google.genai", "google.generativeai"),
    }
    print(f"passive hook: {'active' if active else 'inactive'}")
    print(
        "signing backend: "
        f"{'available' if signing_available else 'unavailable (calls still fail open)'}"
    )
    print(f"vault: {vault}")
    print(f"receipts: {_receipt_count(vault)}")
    for provider, available in providers.items():
        print(f"{provider} SDK: {'available' if available else 'not installed (okay)'}")
    print("failure mode: fail-open (signing/storage errors never break SDK calls)")
    return 0 if active and signing_available else 1


def _module_available(*names: str) -> bool:
    for name in names:
        try:
            if importlib.util.find_spec(name) is not None:
                return True
        except (ImportError, ModuleNotFoundError, AttributeError, ValueError):
            continue
    return False


def cmd_show(_args: argparse.Namespace) -> int:
    vault = discover_vault()
    if not vault.exists():
        print(f"no receipts yet ({vault})")
        return 0
    try:
        with sqlite3.connect(f"file:{vault}?mode=ro", uri=True) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT id, timestamp, model, response, tags
                FROM receipts ORDER BY id DESC LIMIT 5
                """
            ).fetchall()
    except (sqlite3.Error, OSError) as error:
        print(f"vault unavailable: {error}", file=sys.stderr)
        return 1
    if not rows:
        print(f"no receipts yet ({vault})")
        return 0
    for row in rows:
        response = str(row["response"]).replace("\n", " ")
        if len(response) > 100:
            response = response[:100] + "…"
        print(
            f"#{row['id']} {row['timestamp']} [{row['model']}] "
            f"{response} tags={row['tags']}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dontlie-passive",
        description="No-install, fail-open provider SDK receipt capture.",
    )
    subcommands = parser.add_subparsers(dest="command")
    subcommands.add_parser(
        "init",
        help="print the one shell line to add to .envrc/.bashrc/.zshrc",
    ).set_defaults(func=cmd_init)
    subcommands.add_parser(
        "show",
        help="show the five most recent project receipts",
    ).set_defaults(func=cmd_show)
    subcommands.add_parser(
        "status",
        help="show passive-hook and project-vault health",
    ).set_defaults(func=cmd_status)
    parser.set_defaults(func=cmd_init)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

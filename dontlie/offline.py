"""dontlie/offline.py — No-Phone-Home enforcement.

The PLDG.md pledge is enforced here. When the environment variable
DONTLIE_OFFLINE=1 is set, opt-in network commands (witness,
anchor --remote, proxy, import --from-url) must refuse to make
network calls. The core commands (list, show, verify, trust-score,
doctor, etc.) are already network-free by construction; see
test_phone_home.py for the enforcement test.

This module is intentionally tiny — the goal is auditable behavior,
not a complex policy engine.

Note: this is separate from dontlie/privacy.py, which handles
PII redaction / evidence modes. Different concept, same word.
"""
from __future__ import annotations

import os
from typing import NoReturn


class OfflineRefused(RuntimeError):
    """Raised when an opt-in command is asked to make a network call
    while DONTLIE_OFFLINE=1 is set.

    The error message is what the user sees; the command's main() must
    catch this and exit with a non-zero status. The message should
    explain what the user can do:

        - Unset DONTLIE_OFFLINE (or set it to 0) to allow network
        - Run on a machine with network access and a witness configured
    """


def is_offline_mode() -> bool:
    """Return True if the user has explicitly opted into offline mode."""
    val = os.environ.get("DONTLIE_OFFLINE", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def require_network(command_name: str) -> None:
    """Raise OfflineRefused if the user has set DONTLIE_OFFLINE=1.

    Call this at the top of any opt-in command (witness-coverage,
    witness-attest, anchor --remote, proxy, import --from-url)
    before the first network request.

    Args:
        command_name: the human-readable name of the command, used
            in the error message so the user knows what to retry.
    """
    if is_offline_mode():
        raise OfflineRefused(
            f"'{command_name}' refused to make a network call because "
            f"DONTLIE_OFFLINE=1 is set. Unset it (or set DONTLIE_OFFLINE=0) "
            f"and re-run if you want this command to phone home."
        )


def assert_not_offline(command_name: str) -> None:
    """Convenience alias for require_network; same behavior."""
    require_network(command_name)

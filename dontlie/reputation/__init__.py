"""Public, privacy-preserving attestations for Don't-Lie receipts.

The package is deliberately separate from the main CLI so the reputation
format can evolve without changing the receipt vault. Run it with
``python -m reputation`` from the project directory.
"""

from .core import (
    Attestation,
    AttestationError,
    CheckResult,
    ReputationStore,
    Revocation,
    build_attestation,
    build_revocation,
    check,
)

__all__ = [
    "Attestation",
    "AttestationError",
    "CheckResult",
    "ReputationStore",
    "Revocation",
    "build_attestation",
    "build_revocation",
    "check",
]


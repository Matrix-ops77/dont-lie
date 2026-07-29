"""Public API for the anchor module.

There are two layers here:

* The legacy ``dontlie/anchor.py`` (the file alongside this directory)
  ships the simple ``anchor()`` + CLI used by ``dontlie anchor add``.
  Python 3 picks this directory (the package) over the same-named
  file when both exist, so we expose the file's ``main()`` and
  ``anchor()`` via :func:`importlib` to keep the CLI working.

* The newer subpackage (this directory) provides the manifest format,
  the RFC 3161 attestor, the OpenTimestamps attestor, and the pinned
  TSA registry. Use these for new code.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from . import pins, rfc3161
from .pins import TSAEntry, default_tsa, get_entry, set_pin
from .rfc3161 import (
    TimestampError,
    anchor_bundle,
    build_timestamp_request,
    canonical_bundle_bytes,
    parse_response,
    request_attestation,
    verify_attestation,
)

# Re-expose the legacy file's CLI so the ``dontlie anchor`` subcommand
# keeps working. The file lives at ``dontlie/anchor.py`` and is shadowed
# by this package, so we load it by path. The module is registered in
# ``sys.modules`` under a private name so dataclass introspection
# (which looks up ``sys.modules[cls.__module__]``) succeeds.
_LEGACY_PATH = Path(__file__).resolve().parent.parent / "anchor.py"
_LEGACY_NAME = "dontlie._anchor_legacy_cli"
_spec = importlib.util.spec_from_file_location(_LEGACY_NAME, _LEGACY_PATH)
if _spec is not None and _spec.loader is not None:  # pragma: no cover
    _legacy = importlib.util.module_from_spec(_spec)
    sys.modules[_LEGACY_NAME] = _legacy
    _spec.loader.exec_module(_legacy)
    Anchor = _legacy.Anchor
    anchor = _legacy.anchor
    main = _legacy.main
else:  # pragma: no cover
    Anchor = None
    anchor = None
    main = None


__all__ = [
    "Anchor",
    "anchor",
    "anchor_bundle",
    "build_timestamp_request",
    "canonical_bundle_bytes",
    "default_tsa",
    "get_entry",
    "main",
    "parse_response",
    "pins",
    "request_attestation",
    "rfc3161",
    "set_pin",
    "TimestampError",
    "TSAEntry",
    "verify_attestation",
]

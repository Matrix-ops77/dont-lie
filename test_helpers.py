"""test_helpers.py — shared utilities for the dontlie test suite.

Provides two helpers used by tests that drive the `dontlie` CLI through
subprocesses (or shell scripts that ultimately do):

  * `dontlie_cmd(*args)` — build a command list that runs
    `dontlie <args>` under the test runner's Python interpreter.
    Use this instead of hard-coding `["dontlie", ...]` in a subprocess
    call: the bare form assumes a `dontlie` binary on PATH, which is
    not reliable across checkouts, venvs, and CI.

  * `with_dontlie_env(base=None)` — return an env dict (copy of `base`
    or the current process env) with `PYTHON` set so that both direct
    `python -m dontlie` calls and shell scripts using
    `PY="${PYTHON:-python3}"` resolve to the right interpreter.

Both helpers are deliberately tiny so tests can stay readable.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# The test runner's Python. Use this in subprocess commands so tests
# don't depend on a particular `python3` being on PATH.
PYTHON = sys.executable

# The repo root, computed from this file's location. Used by callers
# that need to cwd into it.
REPO_ROOT = Path(__file__).resolve().parent


def _dontlie_is_installed() -> bool:
    """True if `dontlie` is already importable from the test runner's
    site-packages (editable install, wheel, or sdist). When True, we
    must NOT prepend REPO_ROOT to PYTHONPATH in subprocesses, because
    doing so makes Python replace the venv's site-packages with the
    repo dir, which hides deps like `httpx` from the subprocess.
    """
    try:
        import dontlie  # noqa: F401

        return True
    except ImportError:
        return False


# Cached at import time. Tests are short-lived; the cost of recomputing
# per test is trivial but the cache keeps things explicit.
DONTLIE_INSTALLED = _dontlie_is_installed()


def dontlie_cmd(*args: str) -> list[str]:
    """Return a subprocess-ready command list that runs
    `dontlie <args>` under the current Python interpreter.

    Example:
        subprocess.run(dontlie_cmd("version"), capture_output=True)
        subprocess.run(dontlie_cmd("anchor", "list"), cwd=...)
    """
    return [PYTHON, "-m", "dontlie", *args]


def with_dontlie_env(base: dict | None = None) -> dict:
    """Return a copy of `base` (or os.environ) suitable for a subprocess
    that needs to invoke `dontlie`.

    - `PYTHON=sys.executable` so shell scripts that use
      `PY="${PYTHON:-python3}"` pick up the test runner's interpreter.
    - PYTHONPATH is only set if `dontlie` is NOT importable from the
      test runner's site-packages. If the package is already installed
      (editable install or wheel), prepending REPO_ROOT to PYTHONPATH
      breaks the venv: Python replaces its site-packages with REPO_ROOT,
      which hides third-party deps like `httpx` from the subprocess.
      When `dontlie` is installed, the subprocess can find it via the
      venv's site-packages — no PYTHONPATH override needed.
    """
    env = (base if base is not None else os.environ).copy()
    env["PYTHON"] = PYTHON
    if not DONTLIE_INSTALLED:
        # Fall back to PYTHONPATH only when there's no installed copy.
        existing_pp = env.get("PYTHONPATH", "")
        parts = [p for p in existing_pp.split(os.pathsep) if p]
        if str(REPO_ROOT) not in parts:
            env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + existing_pp
    return env

"""test_helpers.py — shared utilities for the dontlie test suite.

Provides two helpers used by tests that drive the `dontlie` CLI through
subprocesses (or shell scripts that ultimately do):

  * `dontlie_cmd(*args)` — build a command list that runs
    `dontlie <args>` under the test runner's Python interpreter.
    Use this instead of hard-coding `["dontlie", ...]` in a subprocess
    call: the bare form assumes a `dontlie` binary on PATH, which is
    not reliable across checkouts, venvs, and CI.

  * `with_dontlie_env(base=None)` — return an env dict (copy of `base`
    or the current process env) with `PYTHON` and `PYTHONPATH` set so
    that both direct `python -m dontlie` calls and shell scripts using
    `PY="${PYTHON:-python3}"` resolve to the right interpreter and can
    import the `dontlie` package regardless of cwd.

Both helpers are deliberately tiny so tests can stay readable.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# The test runner's Python. Use this in subprocess commands so tests
# don't depend on a particular `python3` being on PATH.
PYTHON = sys.executable

# The repo root, computed from this file's location. Used to put the
# `dontlie` package on PYTHONPATH for subprocess invocations.
REPO_ROOT = Path(__file__).resolve().parent


def dontlie_cmd(*args: str) -> list[str]:
    """Return a subprocess-ready command list that runs
    `dontlie <args>` under the current Python interpreter.

    Example:
        subprocess.run(dontlie_cmd("version"), capture_output=True)
        subprocess.run(dontlie_cmd("anchor", "list"), cwd=...)
    """
    return [PYTHON, "-m", "dontlie", *args]


def with_dontlie_env(base: dict | None = None) -> dict:
    """Return a copy of `base` (or os.environ) with PYTHON and PYTHONPATH
    set so that subprocess invocations of `dontlie` work, regardless of
    the parent's env or the subprocess's cwd.

    - `PYTHON=sys.executable` so shell scripts that use
      `PY="${PYTHON:-python3}"` pick up the test runner's interpreter.
    - `PYTHONPATH=<repo_root>` so `python -m dontlie` and direct
      `import dontlie` work even when the subprocess cwd is somewhere
      other than the repo root.
    """
    env = (base if base is not None else os.environ).copy()
    env["PYTHON"] = PYTHON
    existing_pp = env.get("PYTHONPATH", "")
    parts = [p for p in existing_pp.split(os.pathsep) if p]
    if str(REPO_ROOT) not in parts:
        env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + existing_pp
    return env

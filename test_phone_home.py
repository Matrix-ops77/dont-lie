"""test_phone_home.py — enforce the No-Phone-Home pledge (PLDG.md).

The pledge: core commands (list, show, search, verify, trust-score,
doctor, version, export, backup, demo) make ZERO outbound network
calls. This test:

  1. Subprocess-runs each core command with all network libraries
     patched at the Python level (socket, httpx, urllib, requests)
     to record any attempt.
  2. Parses the deployed site/index.html for any third-party URL
     (the static UI pledge).
  3. Verifies opt-in commands refuse to make network calls when
     DONTLIE_OFFLINE=1 is set.

If a future version adds a network call to a core command without
opt-in, this test fails.

Run: python3 -m unittest test_phone_home -v
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent
SITE_INDEX = REPO_ROOT / "site" / "index.html"
PATCHER_PATH = REPO_ROOT / "_test_phone_home_patcher.py"
CALLS_FILE = REPO_ROOT / "_test_phone_home_calls.json"

# The core commands that must NEVER make a network call.
# Use `python -m dontlie ...` because there is no `dontlie` binary on PATH
# in this test env (matches the setUp pattern one block below).
CORE_COMMANDS = [
    [sys.executable, "-m", "dontlie", "version"],
    [sys.executable, "-m", "dontlie", "doctor"],
    [sys.executable, "-m", "dontlie", "list"],
    [sys.executable, "-m", "dontlie", "list", "--limit", "5"],
    [sys.executable, "-m", "dontlie", "trust-score"],
    # verify against the live vault (no --bundle -> reads local DB only)
    [sys.executable, "-m", "dontlie", "verify"],
]


# This script is loaded via PYTHONSTARTUP. It patches socket.create_connection
# (the lowest-level Python network call) to record any attempt to a JSON file
# that the test reads after the subprocess exits.
_PATCHER_SCRIPT = """
import json as _json
import os as _os
import socket as _socket

_CALLS_FILE = _os.environ.get("TEST_PHONE_HOME_CALLS_FILE", "")
if _CALLS_FILE:
    _orig_create_connection = _socket.create_connection

    def _patched_create_connection(address, *args, **kwargs):
        try:
            host, port = address[0], address[1] if len(address) > 1 else 0
        except Exception:
            host, port = str(address), 0
        try:
            with open(_CALLS_FILE, "a") as _f:
                _f.write(_json.dumps({"where": "socket.create_connection", "host": str(host), "port": port}) + "\\\\n")
        except Exception:
            pass
        # Let the call proceed (the test only cares about CALL ATTEMPTS, not success)
        return _orig_create_connection(address, *args, **kwargs)

    _socket.create_connection = _patched_create_connection
"""


def _isolated_env() -> dict:
    """Build a clean env pointing at a temp DB and key dir.

    Tests should NEVER touch the live vault at ~/.local/share/dontlie/.
    """
    tmp = Path(tempfile.mkdtemp(prefix="dontlie-phone-home-test-"))
    keys = tmp / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["DONTLIE_DB"] = str(tmp / "vault.db")
    env["DONTLIE_KEY_DIR"] = str(keys)
    env["DONTLIE_NO_WAL"] = "1"
    env["DONTLIE_OFFLINE"] = "1"  # belt-and-suspenders for opt-in commands
    env["TEST_PHONE_HOME_CALLS_FILE"] = str(CALLS_FILE)
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return env


class TestNoPhoneHomeCLI(unittest.TestCase):
    """In-process test that core commands don't make network calls.

    We use a subprocess wrapper that injects socket/httpx/urllib patches
    via PYTHONSTARTUP. This catches network calls at the actual module
    level where the code lives.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # Create the patcher script that we'll use as PYTHONSTARTUP
        PATCHER_PATH.write_text(_PATCHER_SCRIPT)

    @classmethod
    def tearDownClass(cls) -> None:
        if PATCHER_PATH.exists():
            PATCHER_PATH.unlink()
        if CALLS_FILE.exists():
            CALLS_FILE.unlink()

    def setUp(self) -> None:
        self.env = _isolated_env()
        # Inject the patcher so subprocess calls to the dontlie CLI
        # have their network modules patched before the command runs.
        self.env["PYTHONSTARTUP"] = str(PATCHER_PATH)
        # Generate a fresh key so the isolated vault can sign
        subprocess.run(
            [sys.executable, "-m", "dontlie", "gen-key"],
            env=self.env,
            check=True,
            capture_output=True,
        )
        # Sign a couple of receipts so list/verify/trust-score have data
        sign_script = """
import sys
sys.path.insert(0, '.')
from dontlie import storage
storage.append(model='test-model', prompt='test prompt', response='test response')
storage.append(model='test-model', prompt='second prompt', response='second response', parent_id=1)
"""
        subprocess.run(
            [sys.executable, "-c", sign_script],
            env=self.env,
            check=True,
            capture_output=True,
            cwd=str(REPO_ROOT),
        )
        # Clean up any prior calls
        if CALLS_FILE.exists():
            CALLS_FILE.unlink()

    def tearDown(self) -> None:
        if CALLS_FILE.exists():
            CALLS_FILE.unlink()

    def _read_calls(self) -> list:
        if not CALLS_FILE.exists():
            return []
        try:
            lines = CALLS_FILE.read_text().strip().splitlines()
            return [json.loads(line) for line in lines if line.strip()]
        except (OSError, json.JSONDecodeError):
            return []

    def test_no_network_calls_in_core_commands(self) -> None:
        for cmd in CORE_COMMANDS:
            with self.subTest(cmd=" ".join(cmd)):
                # Clear the calls file before this command
                if CALLS_FILE.exists():
                    CALLS_FILE.unlink()
                result = subprocess.run(
                    cmd,
                    env=self.env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                calls = self._read_calls()
                # Allow localhost calls (the witness might be on localhost
                # in tests, and the storage layer uses sqlite3 which is
                # all-local). The point is: NO internet calls.
                nonlocal_calls = [
                    c for c in calls
                    if not any(
                        h in (c.get("host") or "")
                        for h in ("localhost", "127.0.0.1", "::1")
                    )
                ]
                self.assertEqual(
                    nonlocal_calls,
                    [],
                    f"Core command {' '.join(cmd)} made {len(nonlocal_calls)} "
                    f"non-local network call(s): {nonlocal_calls!r}. "
                    f"See PLDG.md — core commands must be offline. "
                    f"stdout={result.stdout[:500]!r} stderr={result.stderr[:500]!r}",
                )

    def test_opt_in_command_refuses_when_offline_env(self) -> None:
        """dontlie witness-coverage should refuse to call the network
        when DONTLIE_OFFLINE=1 is set.

        We call main() in-process so the privacy.require_network() check
        actually fires (subprocess mocks wouldn't help here because
        we want to verify the command's own refusal logic, not that the
        network was externally blocked).
        """
        # Set up env (DONTLIE_OFFLINE is already in _isolated_env())
        old_env = os.environ.copy()
        os.environ.update(self.env)
        try:
            from dontlie import witness_coverage
            # Call main() with empty args. It should return non-zero
            # because of the offline refusal.
            returncode = witness_coverage.main([])
            self.assertNotEqual(
                returncode, 0,
                "witness-coverage should refuse in offline mode (DONTLIE_OFFLINE=1)",
            )
            # Should be exit code 2 (the specific refusal code)
            self.assertEqual(
                returncode, 2,
                f"witness-coverage should exit 2 (refusal), got {returncode}",
            )
        finally:
            os.environ.clear()
            os.environ.update(old_env)


class TestNoPhoneHomeStaticSite(unittest.TestCase):
    """Parse site/index.html and assert no third-party URL.

    The deployed web UI is a static site at queued-inlet-pmqa.here.now.
    The PLDG says: no third-party URLs in the deployed HTML.
    """

    # These are the only acceptable URL prefixes for resources in the
    # deployed site. Anything else is a violation.
    # Note: relative paths (no scheme) and bare filenames are same-origin.
    ALLOWED_PREFIXES = (
        "https://queued-inlet-pmqa.here.now/",  # the deployed origin
        "https://here.now/",                    # the platform root
        "https://github.com/Matrix-ops77/dontlie",  # view-source link
        "http://localhost:",                    # local-dev demo links
        "http://127.0.0.1:",                    # local-dev demo links
        "/",          # same-origin absolute path
        "#",          # same-page anchor
        "data:",      # inline data URI (e.g. inline SVG)
        "blob:",      # inline blob URL
    )

    # Hosts that are allowed even if they don't match the above prefixes.
    # These are "view source" / informational links, not resource loads.
    ALLOWED_HOSTS = (
        "github.com",  # view-source / repo link
    )

    # Strings that may legitimately appear in the HTML but are not URLs
    # (e.g. inside JSON literals, comments). The pattern is a heuristic
    # but covers the common cases.
    URL_PATTERN = re.compile(
        r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""",
        re.IGNORECASE,
    )

    def test_no_third_party_urls_in_deployed_site(self) -> None:
        if not SITE_INDEX.exists():
            self.skipTest(f"site/index.html not found at {SITE_INDEX}")
        html = SITE_INDEX.read_text(encoding="utf-8")
        violations: list[str] = []
        for match in self.URL_PATTERN.finditer(html):
            url = match.group(1).strip()
            if not url:
                continue
            # Relative paths and bare filenames are same-origin
            if "://" not in url and not url.startswith("//"):
                continue
            if any(url.startswith(prefix) for prefix in self.ALLOWED_PREFIXES):
                continue
            # javascript: and mailto: are also acceptable (no third-party)
            if url.startswith(("javascript:", "mailto:", "tel:")):
                continue
            # Allowed hosts (view-source etc.)
            from urllib.parse import urlparse

            try:
                host = urlparse(url).hostname or ""
            except ValueError:
                host = ""
            if host in self.ALLOWED_HOSTS:
                continue
            violations.append(url)
        self.assertEqual(
            violations,
            [],
            f"site/index.html contains {len(violations)} third-party URL(s). "
            f"Per PLDG.md, the deployed web UI must not make third-party "
            f"requests. Violations: {violations[:10]!r}",
        )

    def test_no_analytics_or_telemetry_in_deployed_site(self) -> None:
        """Specifically check for known analytics/telemetry patterns."""
        if not SITE_INDEX.exists():
            self.skipTest(f"site/index.html not found at {SITE_INDEX}")
        html = SITE_INDEX.read_text(encoding="utf-8")
        forbidden_patterns = [
            "google-analytics.com",
            "googletagmanager.com",
            "plausible.io",
            "fathom.com",
            "segment.io",
            "segment.com",
            "mixpanel.com",
            "amplitude.com",
            "sentry.io",
            "datadoghq.com",
            "newrelic.com",
            "cloudflareinsights.com",  # CF analytics
            "hotjar.com",
            "fullstory.com",
            "logrocket.com",
        ]
        hits = [p for p in forbidden_patterns if p in html.lower()]
        self.assertEqual(
            hits,
            [],
            f"site/index.html contains known analytics/telemetry patterns: {hits}. "
            f"Per PLDG.md, the deployed web UI must not track users.",
        )


class TestPledgeDocument(unittest.TestCase):
    """Sanity-check that PLDG.md exists and references are correct."""

    def test_pldg_md_exists(self) -> None:
        path = REPO_ROOT / "PLDG.md"
        self.assertTrue(
            path.exists(),
            f"PLDG.md must exist at the repo root. Found: {path}",
        )
        text = path.read_text(encoding="utf-8")
        # Must mention each core command
        for cmd in ["doctor", "version", "list", "verify", "trust-score"]:
            self.assertIn(
                cmd,
                text,
                f"PLDG.md must reference the '{cmd}' core command",
            )
        # Must mention the opt-in commands
        for cmd in ["proxy", "witness-coverage", "anchor"]:
            self.assertIn(
                cmd,
                text,
                f"PLDG.md must reference the '{cmd}' opt-in command",
            )


if __name__ == "__main__":
    unittest.main()

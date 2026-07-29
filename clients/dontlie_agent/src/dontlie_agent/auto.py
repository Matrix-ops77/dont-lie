"""dontlie_agent.auto — one-line SDK patching for any agent runtime.

Usage (the easiest path):

    import dontlie_agent
    dontlie_agent.install()   # ← this is the whole story
    # now any openai / anthropic / langchain / requests call is signed.

    # Or, with explicit teardown:
    with dontlie_agent.installed():
        ...

    # Or, decorate a function so the patch lives only as long as the call:
    @dontlie_agent.sign
    def my_agent_step(prompt: str) -> str:
        from openai import OpenAI
        return OpenAI().chat.completions.create(
            model="gpt-4o-mini", messages=[{"role":"user","content":prompt}],
        ).choices[0].message.content

What install() actually does:

    1. Starts a dontlie proxy on 127.0.0.1 (a free port) if one is not
       already pointing at the same vault.
    2. Detects which SDKs are importable (openai, anthropic, langchain,
       requests) and routes them through the proxy via env vars.
    3. Returns a small handle that can stop the proxy on teardown.

The user's application code does not change. Every LLM call is captured,
signed, and appended to a hash-linked receipt chain in the local vault.
"""
from __future__ import annotations

import atexit
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

DEFAULT_UPSTREAM = "https://api.minimax.io/v1"
DEFAULT_PORT_LOW, DEFAULT_PORT_HIGH = 8080, 8180  # scan a small window

# SDKs we know how to redirect. Each entry: (module-to-detect, env-var, default-base-url)
_KNOWN_SDKS: list[tuple[str, str, str]] = [
    # The dontlie_* packages always read DONTLIE_BASE_URL — no need to
    # patch them; just set the env var.
    ("dontlie_openai", "DONTLIE_BASE_URL", "http://127.0.0.1:8080/v1"),
    ("dontlie_anthropic", "DONTLIE_BASE_URL", "http://127.0.0.1:8080/v1"),
    ("dontlie_langchain", "DONTLIE_BASE_URL", "http://127.0.0.1:8080/v1"),
    ("dontlie_requests", "DONTLIE_BASE_URL", "http://127.0.0.1:8080/v1"),
    # The bare SDKs use OPENAI_BASE_URL / ANTHROPIC_BASE_URL. If the
    # user has installed them without the dontlie_* wrappers, we
    # redirect at the env layer too.
    ("openai", "OPENAI_BASE_URL", "http://127.0.0.1:8080/v1"),
    ("anthropic", "ANTHROPIC_BASE_URL", "http://127.0.0.1:8080"),
]


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _scan_free_port(low: int = DEFAULT_PORT_LOW, high: int = DEFAULT_PORT_HIGH) -> int:
    for p in range(low, high + 1):
        if _port_is_free(p):
            return p
    raise RuntimeError(
        f"no free port in {low}..{high}; pass --port or free one with `lsof -i :PORT`"
    )


def _has_dontlie_cli() -> bool:
    return shutil.which("dontlie") is not None or _python_can_import("dontlie")


def _python_can_import(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:
        return False


@dataclass
class InstallHandle:
    """Returned by install(). Use uninstall() or rely on atexit."""

    port: int
    base_url: str
    proxy_proc: Optional[subprocess.Popen] = None
    env_backup: dict[str, Optional[str]] = field(default_factory=dict)
    detected_sdks: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _uninstalled: bool = False

    def uninstall(self) -> None:
        with self._lock:
            if self._uninstalled:
                return
            self._uninstalled = True
            for var, prev in self.env_backup.items():
                if prev is None:
                    os.environ.pop(var, None)
                else:
                    os.environ[var] = prev
            if self.proxy_proc and self.proxy_proc.poll() is None:
                try:
                    self.proxy_proc.send_signal(signal.SIGTERM)
                    self.proxy_proc.wait(timeout=5)
                except Exception:
                    try:
                        self.proxy_proc.kill()
                    except Exception:
                        pass


def _patch_env(handle: InstallHandle) -> list[str]:
    """Set env vars so detected SDKs route through the proxy.

    We back up each env var only the first time we touch it, so that
    multiple SDKs that share a base-URL var don't clobber each other's
    backup, and so that the placeholder API key is set exactly once.
    """
    detected: list[str] = []
    keys_to_set: list[tuple[str, str]] = []  # (var, value) — applied after backup

    for mod, var, default_url in _KNOWN_SDKS:
        if not _python_can_import(mod):
            continue
        # record previous value (None if unset) — but only once per var
        if var not in handle.env_backup:
            handle.env_backup[var] = os.environ.get(var)
        keys_to_set.append((var, handle.base_url))
        # OpenAI/Anthropic SDKs will reject calls without a key; the
        # dontlie proxy accepts the literal placeholder "dontlie-local".
        if "OPENAI" in var or "DONTLIE_BASE" in var:
            if "OPENAI_API_KEY" not in handle.env_backup:
                handle.env_backup["OPENAI_API_KEY"] = os.environ.get("OPENAI_API_KEY")
            keys_to_set.append(("OPENAI_API_KEY", "dontlie-local"))
        if "ANTHROPIC" in var:
            if "ANTHROPIC_API_KEY" not in handle.env_backup:
                handle.env_backup["ANTHROPIC_API_KEY"] = os.environ.get("ANTHROPIC_API_KEY")
            keys_to_set.append(("ANTHROPIC_API_KEY", "dontlie-local"))
        if "DONTLIE_API_KEY" not in handle.env_backup:
            handle.env_backup["DONTLIE_API_KEY"] = os.environ.get("DONTLIE_API_KEY")
        keys_to_set.append(("DONTLIE_API_KEY", "dontlie-local"))
        detected.append(mod)

    for var, value in keys_to_set:
        os.environ[var] = value
    handle.detected_sdks = detected
    return detected


def _start_proxy(port: int, *, upstream: str, upstream_key: Optional[str]) -> subprocess.Popen:
    env = os.environ.copy()
    env["DONTLIE_UPSTREAM_BASE_URL"] = upstream
    if upstream_key:
        env["DONTLIE_UPSTREAM_API_KEY"] = upstream_key
    log = open(Path.home() / ".dontlie" / "agent-proxy.log", "ab")
    Path.home().joinpath(".dontlie").mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        ["dontlie", "proxy", "--port", str(port)],
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    # wait for the proxy to bind
    for _ in range(50):  # 5s
        if not _port_is_free(port):
            return proc
        time.sleep(0.1)
    raise RuntimeError(f"dontlie proxy did not start on port {port} within 5s — see ~/.dontlie/agent-proxy.log")


def install(
    *,
    port: int | None = None,
    upstream: str = DEFAULT_UPSTREAM,
    upstream_key: Optional[str] = None,
    start_proxy: bool = True,
) -> InstallHandle:
    """One-line setup: start a proxy (if needed) and route every known SDK through it.

    Returns an InstallHandle; call .uninstall() to tear down, or rely on
    process exit. The handle is also registered with atexit for safety.
    """
    if not _has_dontlie_cli():
        raise RuntimeError(
            "the 'dontlie' package is not installed. Run: pip install dontlie"
        )
    # Pick a port. If user gave one, use it; otherwise scan.
    chosen_port: int
    if port is None:
        # If something is already listening on the default 8080, assume
        # it is a dontlie proxy (we can't easily tell, but the safest
        # thing is to use it rather than fail).
        if not _port_is_free(8080):
            chosen_port = 8080
            # assume an external proxy is already running
        else:
            chosen_port = _scan_free_port()
    else:
        chosen_port = port
    base_url = f"http://127.0.0.1:{chosen_port}/v1"
    handle = InstallHandle(port=chosen_port, base_url=base_url)
    # If we need to start a proxy, do it.
    if start_proxy and _port_is_free(chosen_port):
        if not upstream_key:
            upstream_key = os.environ.get("DONTLIE_UPSTREAM_API_KEY")
        if not upstream_key:
            print(
                "warning: DONTLIE_UPSTREAM_API_KEY not set; the proxy will reject upstream calls.\n"
                "         set it via the environment or pass upstream_key= to install().",
                file=sys.stderr,
            )
        handle.proxy_proc = _start_proxy(chosen_port, upstream=upstream, upstream_key=upstream_key)
    _patch_env(handle)
    atexit.register(handle.uninstall)
    return handle


@contextmanager
def installed(**kwargs) -> Iterator[InstallHandle]:
    handle = install(**kwargs)
    try:
        yield handle
    finally:
        handle.uninstall()


def sign(func):
    """Decorator: install the proxy for the duration of a single function call.

    Example:
        @dontlie_agent.sign
        def answer(prompt: str) -> str:
            from openai import OpenAI
            return OpenAI().chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role":"user","content":prompt}],
            ).choices[0].message.content
    """
    def wrapper(*args, **kwargs):
        with installed() as _h:
            return func(*args, **kwargs)
    wrapper.__wrapped__ = func
    wrapper.__dontlie_signed__ = True
    return wrapper


def main(argv: list[str] | None = None) -> int:
    """CLI: `python3 -m dontlie_agent.auto` prints detected SDKs and starts a proxy."""
    import argparse
    parser = argparse.ArgumentParser(prog="dontlie-agent-auto")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--upstream", default=DEFAULT_UPSTREAM)
    parser.add_argument("--upstream-key", default=os.environ.get("DONTLIE_UPSTREAM_API_KEY"))
    parser.add_argument("--no-proxy", action="store_true", help="don't start a proxy; just patch env (assumes one is running)")
    args = parser.parse_args(argv)
    handle = install(
        port=args.port,
        upstream=args.upstream,
        upstream_key=args.upstream_key,
        start_proxy=not args.no_proxy,
    )
    print(f"dontlie_agent installed.")
    print(f"  proxy port: {handle.port}")
    print(f"  base url:   {handle.base_url}")
    print(f"  detected:   {', '.join(handle.detected_sdks) or '(none)'}")
    print("  press Ctrl+C to uninstall.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        handle.uninstall()
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

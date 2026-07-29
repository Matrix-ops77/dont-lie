"""dontlie-agent CLI: spawn a signed proxy and run any agent tool under it.

Subcommands:
    run        start a proxy and exec an agent tool under it
    wrap       exec an agent tool with the proxy URL already exported (you
               start the proxy separately)
    env        print the env vars a shell needs to inject for the agent
    start-proxy  start just the proxy (no agent)
"""
from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

DEFAULT_PORT = 8080
DEFAULT_KEY_DIR = Path.home() / ".config" / "dontlie" / "keys"
DEFAULT_DB = Path.home() / ".local" / "share" / "dontlie" / "vault.db"


def _check_python_pkg() -> bool:
    """The `dontlie` package must be installed."""
    try:
        import dontlie  # noqa: F401
        return True
    except ImportError:
        return False


def _check_proxy_bin() -> bool:
    return shutil.which("dontlie") is not None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


@contextmanager
def _managed_proxy(args):
    """Start the proxy in the background, yield its env, stop on exit."""
    if not _check_python_pkg():
        raise SystemExit("error: the 'dontlie' package is not installed. pip install dontlie.")
    if not _check_proxy_bin():
        raise SystemExit("error: 'dontlie' CLI not on PATH. pip install dontlie.")

    env = os.environ.copy()
    env["DONTLIE_KEY_DIR"] = args.key_dir
    env["DONTLIE_DB"] = args.db
    env["DONTLIE_UPSTREAM_BASE_URL"] = args.upstream_url
    if args.upstream_key:
        env["DONTLIE_UPSTREAM_API_KEY"] = args.upstream_key

    log = open(args.log, "ab") if args.log else subprocess.DEVNULL  # noqa: SIM115
    proc = subprocess.Popen(
        ["dontlie", "proxy", "--port", str(args.port)],
        env=env, stdout=log, stderr=log,
    )
    try:
        # give the proxy a moment to bind
        import time
        time.sleep(0.5)
        yield {"DONTLIE_BASE_URL": f"http://127.0.0.1:{args.port}/v1",
               "DONTLIE_API_KEY": "dontlie-local"}
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def cmd_run(args) -> int:
    """Start a proxy, then exec the agent command."""
    if not args.cmd:
        raise SystemExit("error: pass the agent command after `--`, e.g.\n"
                         "  dontlie-agent run --port 8080 -- claude-code")
    with _managed_proxy(args) as extra_env:
        env = os.environ.copy()
        env.update(extra_env)
        try:
            return subprocess.call(args.cmd, env=env)
        except FileNotFoundError:
            print(f"error: command not found: {args.cmd[0]}", file=sys.stderr)
            return 127


def cmd_wrap(args) -> int:
    """Exec the agent command after exporting DON'T LIE env vars.

    Assumes the proxy is already running on --port.
    """
    if not args.cmd:
        raise SystemExit("error: pass the agent command after `--`, e.g.\n"
                         "  dontlie-agent wrap --port 8080 -- claude-code")
    env = os.environ.copy()
    env["DONTLIE_BASE_URL"] = f"http://127.0.0.1:{args.port}/v1"
    env["DONTLIE_API_KEY"] = "dontlie-local"
    try:
        return subprocess.call(args.cmd, env=env)
    except FileNotFoundError:
        print(f"error: command not found: {args.cmd[0]}", file=sys.stderr)
        return 127


def cmd_env(args) -> int:
    """Print the env vars a shell needs to inject."""
    print(f"export DONTLIE_BASE_URL=http://127.0.0.1:{args.port}/v1")
    print("export DONTLIE_API_KEY=dontlie-local")
    return 0


def cmd_start_proxy(args) -> int:
    """Just start the proxy in the foreground."""
    if not _check_python_pkg():
        raise SystemExit("error: the 'dontlie' package is not installed. pip install dontlie.")
    env = os.environ.copy()
    env["DONTLIE_KEY_DIR"] = args.key_dir
    env["DONTLIE_DB"] = args.db
    if args.upstream_url:
        env["DONTLIE_UPSTREAM_BASE_URL"] = args.upstream_url
    if args.upstream_key:
        env["DONTLIE_UPSTREAM_API_KEY"] = args.upstream_key
    return subprocess.call(["dontlie", "proxy", "--port", str(args.port)], env=env)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dontlie-agent",
        description="Wrap any agent runtime in a Don't-Lie signed proxy.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="start a proxy and exec an agent tool under it")
    p_run.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_run.add_argument("--key-dir", default=str(DEFAULT_KEY_DIR))
    p_run.add_argument("--db", default=str(DEFAULT_DB))
    p_run.add_argument("--upstream-url", default=os.environ.get("DONTLIE_UPSTREAM_BASE_URL", "https://api.minimax.io/v1"))
    p_run.add_argument("--upstream-key", default=os.environ.get("DONTLIE_UPSTREAM_API_KEY"))
    p_run.add_argument("--log", default=None)
    p_run.add_argument("cmd", nargs=argparse.REMAINDER, help="agent command after `--`")
    p_run.set_defaults(func=cmd_run)

    p_wrap = sub.add_parser("wrap", help="exec an agent command with the proxy URL exported")
    p_wrap.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_wrap.add_argument("cmd", nargs=argparse.REMAINDER)
    p_wrap.set_defaults(func=cmd_wrap)

    p_env = sub.add_parser("env", help="print the env vars a shell needs to inject")
    p_env.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_env.set_defaults(func=cmd_env)

    p_sp = sub.add_parser("start-proxy", help="just start the proxy in the foreground")
    p_sp.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_sp.add_argument("--key-dir", default=str(DEFAULT_KEY_DIR))
    p_sp.add_argument("--db", default=str(DEFAULT_DB))
    p_sp.add_argument("--upstream-url",
                      default=os.environ.get("DONTLIE_UPSTREAM_BASE_URL", "https://api.minimax.io/v1"))
    p_sp.add_argument("--upstream-key", default=os.environ.get("DONTLIE_UPSTREAM_API_KEY"))
    p_sp.set_defaults(func=cmd_start_proxy)

    p_auto = sub.add_parser(
        "auto",
        help="one-line: start a proxy and patch every detected SDK in this process",
    )
    p_auto.add_argument("--port", type=int, default=None)
    p_auto.add_argument("--upstream", default=os.environ.get("DONTLIE_UPSTREAM_BASE_URL", "https://api.minimax.io/v1"))
    p_auto.add_argument("--upstream-key", default=os.environ.get("DONTLIE_UPSTREAM_API_KEY"))
    p_auto.add_argument("--no-proxy", action="store_true", help="don't start a proxy (assume one is running)")
    p_auto.set_defaults(func=cmd_auto)

    return p


def cmd_auto(args) -> int:
    """`dontlie-agent auto` — start a proxy, patch env, run until Ctrl+C."""
    from . import auto as _auto
    handle = _auto.install(
        port=args.port,
        upstream=args.upstream,
        upstream_key=args.upstream_key,
        start_proxy=not args.no_proxy,
    )
    print("dontlie_agent installed.")
    print(f"  proxy port: {handle.port}")
    print(f"  base url:   {handle.base_url}")
    print(f"  detected:   {', '.join(handle.detected_sdks) or '(none)'}")
    print("  press Ctrl+C to uninstall.")
    try:
        import time as _time
        while True:
            _time.sleep(3600)
    except KeyboardInterrupt:
        handle.uninstall()
        return 0
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # strip a leading `--` from REMAINDER, if present
    if getattr(args, "cmd", None) and args.cmd and args.cmd[0] == "--":
        args.cmd = args.cmd[1:]
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

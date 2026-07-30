"""dontlie CLI.

Commands:

    dontlie gen-key                   create the local Ed25519 keypair
    dontlie proxy [--port 8765]       start the OpenAI-compatible HTTP proxy
    dontlie show ID [--json]        show one complete receipt
    dontlie list [--limit N]          show recent receipts
    dontlie search QUERY              full-text search prompt/response/tags
    dontlie export [PATH] [--bundle] write JSONL or a portable verification bundle
    dontlie verify [--export PATH] verify the local chain or an export
    dontlie doctor                    run environment diagnostics
    dontlie demo                      run the offline proof experience
"""

from __future__ import annotations

import argparse
import asyncio
import http.server
import json
import os
import re
import secrets
import socket
import socketserver
import sys
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse

import httpx

from . import __version__, encryption, protocols, proxy, storage
from . import sign as signing


def _print_receipt(r) -> None:
    ts = r.timestamp
    model = r.model
    print(f"#{r.id}  {ts}  [{model}]  parent={r.parent_id}  key={r.key_id[:8]}")
    print(f"  prompt:    {r.prompt[:120]}{'...' if len(r.prompt) > 120 else ''}")
    print(f"  response:  {r.response[:120]}{'...' if len(r.response) > 120 else ''}")
    if r.tags:
        print(f"  tags:      {', '.join(r.tags)}")
    print(f"  sha256:    {r.payload_sha256[:16]}...")
    print(f"  signature: {r.signature[:16]}...")
    print()


def cmd_gen_key(args) -> int:
    _ = args
    if signing.PRIVATE_FILE.exists():
        print(f"key already exists at {signing.PRIVATE_FILE}", file=sys.stderr)
        return 1
    kp = signing.generate()
    print("generated Ed25519 keypair")
    print(f"  key_id:    {kp.key_id}")
    print(f"  private:   {signing.PRIVATE_FILE}")
    print(f"  public:    {signing.PUBLIC_FILE}")
    return 0


def cmd_show(args) -> int:
    storage.init()
    try:
        receipt_id = int(args.receipt_id)
    except (TypeError, ValueError):
        print(f"invalid receipt id: {args.receipt_id}", file=sys.stderr)
        return 2
    receipt = storage.get_receipt(receipt_id)
    if receipt is None:
        print(f"receipt {receipt_id} not found", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(asdict(receipt), sort_keys=True, indent=2))
    else:
        print(f"#{receipt.id}  {receipt.timestamp}  [{receipt.model}]")
        print(f"parent:       {receipt.parent_id}")
        print(f"key_id:       {receipt.key_id}")
        print(f"payload_sha256: {receipt.payload_sha256}")
        print(f"signature:    {receipt.signature}")
        print(f"tags:         {json.dumps(receipt.tags)}")
        print(f"extra:        {json.dumps(receipt.extra, sort_keys=True)}")
        print(f"prompt:       {receipt.prompt}")
        print(f"response:     {receipt.response}")
    return 0


def cmd_list(args) -> int:
    storage.init()
    for r in storage.list_receipts(limit=args.limit, offset=args.offset):
        _print_receipt(r)
    print(f"total receipts in vault: {storage.count()}")
    return 0


def cmd_search(args) -> int:
    storage.init()
    hits = storage.search(args.query, limit=args.limit)
    if not hits:
        print(f"no matches for {args.query!r}")
        return 0
    for r in hits:
        _print_receipt(r)
    return 0


def cmd_export(args) -> int:
    storage.init()
    fmt = str(getattr(args, "format", "jsonl") or "jsonl")
    out: Path | None
    # --bundle is the legacy v1 flag; keep it as an alias for --format bundle
    # so existing scripts and muscle memory continue to work.
    if getattr(args, "bundle", False) and fmt == "jsonl":
        fmt = "bundle"
    if fmt == "bundle":
        path_value = getattr(args, "path", None)
        out = Path(path_value or "dontlie_bundle.json")
        n = storage.export_bundle(out)
        kind = "portable verification bundle"
    elif fmt == "scitt":
        from . import scitt as _scitt
        receipt_id = getattr(args, "receipt_id", None)
        if receipt_id is None:
            print(
                "--format scitt requires a receipt id (--id <int>)",
                file=sys.stderr,
            )
            return 2
        try:
            path_value = getattr(args, "path", None)
            out = Path(path_value) if path_value else None
            written = _scitt.write_scitt_envelope(int(receipt_id), out)
        except LookupError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except (OSError, ValueError) as exc:
            print(f"scitt export failed: {exc}", file=sys.stderr)
            return 1
        n = 1
        kind = "SCITT COSE_Sign1 envelope"
        out = written
    elif fmt == "scitt-bundle":
        from . import scitt as _scitt
        path_value = getattr(args, "path", None)
        out = Path(path_value) if path_value else Path("dontlie_scitt_bundle.json")
        try:
            n = _scitt.write_scitt_bundle(out)
        except (OSError, ValueError) as exc:
            print(f"scitt bundle export failed: {exc}", file=sys.stderr)
            return 1
        kind = "SCITT bundle (COSE_Sign1 envelopes + receipt bodies)"
    else:
        path_value = getattr(args, "path", None)
        out = Path(path_value) if path_value else None
        n = storage.export(out)
        kind = "JSONL export"
    print(f"exported {n} receipts as {kind} -> {out or 'dontlie_export.jsonl'}")
    return 0


def _public_key_pins(values: list[str]) -> dict[str, Path]:
    pins: dict[str, Path] = {}
    for value in values:
        key_id, separator, path = value.partition("=")
        if not separator or not key_id or not path:
            raise ValueError(
                "--public-key must use KEY_ID=/path/to/public-key.pem"
            )
        pins[key_id] = Path(path)
    return pins


def cmd_verify(args) -> int:
    if getattr(args, "export_path", None):
        try:
            pins = _public_key_pins(getattr(args, "public_key", []))
            report = storage.verify_export(
                Path(args.export_path),
                pins or None,
                getattr(args, "revoked_key_id", []),
            )
        except (OSError, ValueError) as exc:
            print(f"verification error: {exc}", file=sys.stderr)
            return 1
        source = args.export_path
    else:
        storage.init()
        report = storage.verify_chain_report()
        source = str(storage.DB_PATH)

    total = report.ok_count + report.bad_count
    print(
        f"verified {total} receipts: {report.ok_count} ok, "
        f"{report.bad_count} bad ({source})"
    )
    if getattr(args, "verbose", False) or report.bad_count:
        for issue in report.issues:
            receipt = issue.receipt_id if issue.receipt_id is not None else "export"
            print(f"  receipt {receipt}: {issue.reason}")
    return 0 if report.valid else 2


def cmd_revoke_key(args) -> int:
    storage.init()
    storage.revoke_key(args.key_id)
    print(f"revoked signing key {args.key_id}")
    return 0


def _port_open(host: str, port: int) -> bool:
    """Return True if we can bind to ``(host, port)`` right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def cmd_doctor(args) -> int:
    """Print a quick environment report; return non-zero if key is missing."""
    _ = args
    storage.init()
    print("dontlie doctor")
    print(f"  version:          {__version__}")
    print(f"  db:               {storage.DB_PATH}")
    print(f"  receipts stored:  {storage.count()}")
    print(f"  key dir:          {signing.KEY_DIR}")
    has_key = signing.PRIVATE_FILE.exists() and signing.PUBLIC_FILE.exists()
    print(f"  signing key:      {'present' if has_key else 'MISSING (run `dontlie gen-key`)'}")

    dedicated_key = os.environ.get("DONTLIE_UPSTREAM_API_KEY")
    legacy_key = os.environ.get("OPENAI_API_KEY")
    if dedicated_key:
        key_status = "set (DONTLIE_UPSTREAM_API_KEY)"
    elif legacy_key:
        key_status = "set via legacy OPENAI_API_KEY (verify it is the provider key)"
    else:
        key_status = "MISSING (set DONTLIE_UPSTREAM_API_KEY)"
    print(f"  upstream key:     {key_status}")
    print(f"  upstream base:    {proxy.resolve_upstream_base_url()}")
    print(f"  max request size: {proxy.MAX_REQUEST_BYTES} bytes")
    print(f"  max raw response: {proxy.MAX_RAW_RESPONSE_BYTES} bytes")

    # Live port check is informative; the proxy can still fail later
    # if the port is grabbed between this check and serve_forever().
    default_port = 8765
    if _port_open("127.0.0.1", default_port):
        print("  port 8765:        free")
    else:
        print("  port 8765:        IN USE (--port to override)")

    if not has_key or not (dedicated_key or legacy_key):
        return 1
    return 0


def cmd_proxy(args) -> int:
    storage.init()
    try:
        adapter = protocols.get_adapter(getattr(args, "protocol", "openai"))
    except protocols.ProtocolError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    extra_headers: dict[str, str] = {}
    anthropic_version = getattr(args, "anthropic_version", None)
    if anthropic_version and adapter is protocols.ANTHROPIC_MESSAGES:
        extra_headers["anthropic-version"] = anthropic_version
    auth_config = protocols.AuthConfig(
        header_name=getattr(args, "auth_header", None),
        scheme=getattr(args, "auth_scheme", None),
        path=getattr(args, "upstream_path", None),
        extra_headers=extra_headers,
    )
    use_legacy_openai = (
        adapter is protocols.OPENAI_CHAT
        and auth_config.header_name is None
        and auth_config.scheme is None
        and auth_config.path is None
        and not auth_config.extra_headers
    )
    upstream_key = (
        os.environ.get("DONTLIE_UPSTREAM_API_KEY")
        or (
            os.environ.get("ANTHROPIC_API_KEY")
            if adapter is protocols.ANTHROPIC_MESSAGES
            else None
        )
        or os.environ.get("OPENAI_API_KEY")  # backward compatibility
        or ""
    ).strip()
    # --mock mode: spin up an in-process mock OpenAI-compatible
    # provider on a free localhost port and route the proxy at it.
    # No API key required. Perfect for trying dontlie without
    # burning a real provider key. The mock supplies canned
    # responses to /v1/chat/completions and signs nothing itself —
    # dontlie still signs the receipt on the way back to the
    # client, so this exercises the full chain end-to-end.
    mock_server = None
    if getattr(args, "mock", False):
        from . import mock_provider
        mock_port = int(getattr(args, "mock_port", 0) or 0)
        mock_server = mock_provider.start_mock_server(port=mock_port)
        # Override the upstream so the proxy points at the mock.
        args.upstream_base_url = mock_server.base_url
        # The mock accepts any value in the Authorization header, so
        # set a placeholder to satisfy the proxy's pre-flight checks.
        if not upstream_key:
            upstream_key = "mock-placeholder-not-validated"
    if not upstream_key:
        print(
            "DONTLIE_UPSTREAM_API_KEY must be set "
            "(ANTHROPIC_API_KEY is accepted for the Anthropic protocol; "
            "OPENAI_API_KEY is accepted for backward compatibility). "
            "Or pass --mock to run an in-process fake provider with no key.",
            file=sys.stderr,
        )
        if mock_server is not None:
            mock_server.stop()
        return 1
    upstream_base_url = proxy.resolve_upstream_base_url(args.upstream_base_url)

    class Handler(http.server.BaseHTTPRequestHandler):
        # Per-request logger. We swallow BaseHTTPRequestHandler's
        # built-in stderr noise; an opt-in verbose flag is exposed
        # through ``--verbose`` so operators can audit traffic.
        verbose = bool(getattr(args, "verbose", False))

        def log_message(self, format, *fargs):
            _ = (format, fargs)  # suppress unused-arg warnings; BaseHTTPRequestHandler signature

        def _log(self, msg: str) -> None:
            if self.verbose:
                sys.stderr.write(f"[{self.log_date_time_string()}] {msg}\n")
                sys.stderr.flush()

        def _send_json(self, status: int, payload: dict | list) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            parsed = urlparse(self.path)
            if parsed.path != adapter.default_path:
                self.send_response(404)
                self.end_headers()
                return

            # Cap inbound body to MAX_REQUEST_BYTES. A malicious local
            # client could otherwise OOM the proxy by streaming a huge
            # content-length and never finishing the body.
            length_hdr = self.headers.get("content-length", "0")
            try:
                length = int(length_hdr)
            except ValueError:
                self._send_json(400, {"error": "invalid content-length"})
                return
            if length < 0 or length > proxy.MAX_REQUEST_BYTES:
                self._send_json(
                    413,
                    {"error": f"request body too large (max {proxy.MAX_REQUEST_BYTES} bytes)"},
                )
                return
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid json"})
                return

            # Validate shape before doing any upstream work. We bind
            # ``model`` + ``messages`` into the receipt, so a request
            # with neither cannot produce a meaningful receipt anyway.
            _parsed, err = adapter.validate_request(body)
            _ = _parsed  # validation side-effect: shape check only
            if err is not None:
                self._send_json(400, {"error": err})
                return

            self._log(f"POST {self.path} model={body.get('model')!r} stream={bool(body.get('stream'))}")

            # Streaming path: write SSE chunks straight to the client
            # so users see the first token immediately, while still
            # capturing the full body for the signed receipt.
            if body.get("stream"):
                loop = asyncio.new_event_loop()
                response_started = False

                async def _start(
                    status: int, response_headers: dict[str, str]
                ) -> None:
                    nonlocal response_started
                    content_type = response_headers.get(
                        "content-type",
                        "text/event-stream" if 200 <= status < 300 else "application/json",
                    )
                    self.send_response(status)
                    self.send_header("content-type", content_type)
                    if 200 <= status < 300:
                        self.send_header(
                            "cache-control",
                            response_headers.get("cache-control", "no-cache"),
                        )
                    self.send_header("connection", "close")
                    self.end_headers()
                    response_started = True

                async def _write(chunk: bytes) -> None:
                    self.wfile.write(chunk)

                async def _flush() -> None:
                    self.wfile.flush()

                try:
                    if use_legacy_openai:
                        operation = proxy.stream_chat_completion_to_client(
                            body,
                            upstream_key,
                            _write,
                            _flush,
                            upstream_base_url=upstream_base_url,
                            on_start=_start,
                        )
                    else:
                        operation = proxy.stream_protocol_to_client(
                            body,
                            upstream_key,
                            adapter,
                            _write,
                            _flush,
                            upstream_base_url=upstream_base_url,
                            auth_config=auth_config,
                            on_start=_start,
                        )
                    info = loop.run_until_complete(operation)
                    self._log(f"  -> {info}")
                except (
                    httpx.HTTPError,
                    RuntimeError,
                    OSError,
                    BrokenPipeError,
                    ConnectionResetError,
                ) as exc:
                    self._log(f"  -> upstream error: {exc!r}")
                    if not response_started:
                        self._send_json(502, {"error": "upstream connection failed"})
                finally:
                    loop.close()
                return

            # Non-streaming path: use the synchronous helper. It already
            # writes the receipt and returns either a parsed dict or a
            # passthrough envelope.
            try:
                if use_legacy_openai:
                    resp = proxy.handle_chat_completion(
                        body,
                        upstream_key,
                        upstream_base_url=upstream_base_url,
                    )
                else:
                    resp = proxy.handle_protocol_completion(
                        body,
                        upstream_key,
                        adapter,
                        upstream_base_url=upstream_base_url,
                        auth_config=auth_config,
                    )
            except (
                httpx.HTTPError,
                RuntimeError,
                OSError,
            ) as exc:
                self._log(f"  -> upstream error: {exc!r}")
                self._send_json(502, {"error": "upstream connection failed"})
                return
            if isinstance(resp, dict) and "_dontlie_passthrough_body" in resp:
                payload = resp["_dontlie_passthrough_body_bytes"]
                self.send_response(resp["_dontlie_passthrough_status"])
                self.send_header(
                    "content-type",
                    resp.get("_dontlie_passthrough_content_type", "application/json"),
                )
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            else:
                payload = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        def do_GET(self):
            if urlparse(self.path).path == "/v1/models":
                payload = json.dumps({"object": "list", "data": []}).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if urlparse(self.path).path in ("/healthz", "/_dontlie/health"):
                payload = json.dumps({"status": "ok", "version": __version__}).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.end_headers()

    class ThreadedServer(socketserver.ThreadingTCPServer):
        # Allow quick rebinds during restarts without TIME_WAIT noise.
        allow_reuse_address = True
        daemon_threads = True

    try:
        with ThreadedServer(("127.0.0.1", args.port), Handler) as srv:
            print(
                f"dontlie proxy listening on http://127.0.0.1:{args.port}/v1",
                file=sys.stderr,
            )
            print(f"upstream: {upstream_base_url}", file=sys.stderr)
            if mock_server is not None:
                print(
                    "mode: MOCK (in-process, no real provider key needed)",
                    file=sys.stderr,
                )
            print(
                f"protocol: {adapter.identifier} "
                f"(local {adapter.default_path}, "
                f"upstream {adapter.request_path(auth_config)})",
                file=sys.stderr,
            )
            if adapter is protocols.OPENAI_CHAT:
                print(
                    f"set OPENAI_BASE_URL=http://127.0.0.1:{args.port}/v1 "
                    "in your client",
                    file=sys.stderr,
                )
            else:
                print(
                    "send native Anthropic Messages requests to "
                    f"http://127.0.0.1:{args.port}{adapter.default_path}",
                    file=sys.stderr,
                )
            print(
                f"health check: http://127.0.0.1:{args.port}/_dontlie/health",
                file=sys.stderr,
            )
            if getattr(args, "verbose", False):
                print("verbose request logging: ON", file=sys.stderr)
            if mock_server is not None:
                print(
                    f"mock provider: {mock_server.base_url}/v1 "
                    "(--mock, in-process, no API key)",
                    file=sys.stderr,
                )
            try:
                srv.serve_forever()
            except KeyboardInterrupt:
                print("shutting down...", file=sys.stderr)
                srv.shutdown()
                srv.server_close()
            finally:
                if mock_server is not None:
                    mock_server.stop()
    except OSError as exc:
        print(f"cannot start dontlie proxy on port {args.port}: {exc}", file=sys.stderr)
        if mock_server is not None:
            mock_server.stop()
        return 1
    return 0


def cmd_version(args) -> int:
    _ = args
    print(f"dontlie {__version__}")
    return 0


def cmd_demo(args) -> int:
    """Run the deterministic offline demo (no API key, no network).

    The demo shell script is shipped inside the installed package at
    ``dontlie/demo/run_offline_demo.sh`` and its sibling Python helpers
    run as ``python -m dontlie.demo.<name>`` so this works after
    ``pip install dontlie``, not just from a source checkout.

    --port and --mock-port propagate to the script via MOCK_PORT and
    PROXY_PORT environment variables.
    """
    import subprocess

    try:
        import dontlie.demo as _demo_pkg
    except ImportError as exc:  # pragma: no cover - the sub-package is shipped
        print(f"demo sub-package is not available: {exc}", file=sys.stderr)
        return 2

    script = Path(_demo_pkg.__file__).resolve().parent / "run_offline_demo.sh"
    if not script.exists():
        print(f"demo script not found at {script}", file=sys.stderr)
        return 2

    env = os.environ.copy()
    # Always pin PYTHON to the interpreter running this CLI so the demo's
    # helper scripts (`python -m dontlie ...`, `python -m dontlie.demo.X`)
    # resolve to a Python that actually has `dontlie` installed. Without
    # this, a stray `PYTHON` in the parent env (e.g. a system Python or
    # another venv) would silently route the demo to the wrong
    # interpreter and the helpers would fail with "No module named
    # 'dontlie'".
    env["PYTHON"] = sys.executable
    if getattr(args, "port", None):
        env["PROXY_PORT"] = str(args.port)
    if getattr(args, "mock_port", None):
        env["MOCK_PORT"] = str(args.mock_port)
    return subprocess.run(
        ["bash", str(script)],
        cwd=str(script.parent),
        env=env,
    ).returncode


def _read_passphrase(prompt: str, confirm: bool = False) -> bytearray:
    """Read a passphrase from stdin without echoing it.

    Honors ``DONTLIE_ENCRYPTION_PASSPHRASE`` (and ``DONTLIE_PASSPHRASE``)
    from the environment for non-interactive use; otherwise falls back to
    :mod:`getpass`. A mutable ``bytearray`` is returned so callers can
    zeroize it.
    """
    import getpass
    import os

    env_pw = os.environ.get("DONTLIE_ENCRYPTION_PASSPHRASE") or os.environ.get("DONTLIE_PASSPHRASE")
    if env_pw:
        return bytearray(env_pw.encode("utf-8"))

    try:
        pw = getpass.getpass(prompt)
    except (EOFError, OSError):
        # Non-interactive stdin (e.g. CI). The only safe non-interactive
        # path is the env var above; refuse anything else loudly so
        # callers don't accidentally store a blank passphrase.
        raise RuntimeError(
            "no terminal available and DONTLIE_ENCRYPTION_PASSPHRASE is not set"
        )
    if confirm:
        try:
            pw2 = getpass.getpass("confirm passphrase: ")
        except (EOFError, OSError):
            raise RuntimeError(
                "no terminal available and DONTLIE_ENCRYPTION_PASSPHRASE is not set"
            )
        if pw != pw2:
            raise RuntimeError("passphrases do not match")
    return bytearray(pw.encode("utf-8"))


def _zeroize(buf: bytearray) -> None:
    """Best-effort overwrite of a mutable byte buffer with zeros."""
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except Exception:
        pass


def cmd_encrypt(args) -> int:
    """Encrypt the local vault in place (or to a new path)."""
    source = Path(args.vault) if args.vault else storage.DB_PATH
    if not source.exists():
        print(f"FAIL: vault not found at {source}", file=sys.stderr)
        return 2
    target = Path(args.output) if args.output else source.with_suffix(
        source.suffix + ".enc"
    )
    if target.exists() and not args.force:
        print(f"FAIL: {target} already exists; pass --force to overwrite", file=sys.stderr)
        return 2
    try:
        passphrase = _read_passphrase("passphrase: ", confirm=True)
    except RuntimeError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    try:
        encryption.encrypt_file(source, target, bytes(passphrase))
    finally:
        _zeroize(passphrase)
    print(f"encrypted vault -> {target}")
    print("passphrase is not stored; you must remember it to unlock")
    return 0


def cmd_unlock(args) -> int:
    """Decrypt a previously encrypted vault."""
    source = Path(args.input) if args.input else (
        Path(args.vault) if args.vault else storage.DB_PATH.with_suffix(
            storage.DB_PATH.suffix + ".enc"
        )
    )
    if not source.exists():
        print(f"FAIL: encrypted vault not found at {source}", file=sys.stderr)
        return 2
    target = Path(args.output) if args.output else storage.DB_PATH
    if target.exists() and not args.force:
        print(f"FAIL: {target} already exists; pass --force to overwrite", file=sys.stderr)
        return 2
    try:
        passphrase = _read_passphrase("passphrase: ")
    except (RuntimeError, EOFError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    try:
        try:
            encryption.decrypt_file(source, target, bytes(passphrase))
        except encryption.EncryptionError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 3
    finally:
        _zeroize(passphrase)
    print(f"unlocked vault -> {target}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dontlie", description="Verifiable local-first LLM receipt vault.")
    # Top-level --version flag so `dontlie --version` works without a subcommand.
    # This is what most CLI users try first; the `version` subcommand is still
    # available for parity.
    p.add_argument(
        "--version",
        action="version",
        version=f"dontlie {__version__}",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("gen-key", help="generate Ed25519 keypair").set_defaults(func=cmd_gen_key)
    sub.add_parser("version", help="print version").set_defaults(func=cmd_version)
    sub.add_parser("doctor", help="show environment diagnostics").set_defaults(func=cmd_doctor)
    p_demo = sub.add_parser("demo", help="run the offline proof experience (no API key required)")
    p_demo.add_argument(
        "--port",
        type=int,
        default=None,
        help="proxy port (default: 9877)",
    )
    p_demo.add_argument(
        "--mock-port",
        type=int,
        default=None,
        help="mock provider port (default: 9876)",
    )
    p_demo.set_defaults(func=cmd_demo)

    p_encrypt = sub.add_parser("encrypt", help="encrypt the local vault with a passphrase")
    p_encrypt.add_argument("vault", nargs="?",
                           help="vault path to encrypt (default: $DONTLIE_DB or ~/.local/share/dontlie/vault.db)")
    p_encrypt.add_argument("--output", help="output path (default: <vault>.enc)")
    p_encrypt.add_argument("--force", action="store_true", help="overwrite existing output")
    p_encrypt.set_defaults(func=cmd_encrypt)

    p_unlock = sub.add_parser("unlock", help="decrypt an encrypted vault")
    p_unlock.add_argument("vault", nargs="?",
                          help="encrypted vault file (default: ~/.local/share/dontlie/vault.db.enc)")
    p_unlock.add_argument("--input", help=argparse.SUPPRESS)  # legacy alias
    p_unlock.add_argument("--output", help="output path (default: standard vault path)")
    p_unlock.add_argument("--force", action="store_true", help="overwrite existing output")
    p_unlock.set_defaults(func=cmd_unlock)

    p_show = sub.add_parser("show", help="show one complete receipt")
    p_show.add_argument("receipt_id")
    p_show.add_argument("--json", action="store_true", help="emit the receipt as JSON")
    p_show.set_defaults(func=cmd_show)

    p_list = sub.add_parser("list", help="list recent receipts")
    p_list.add_argument("--limit", type=int, default=20)
    p_list.add_argument("--offset", type=int, default=0)
    p_list.set_defaults(func=cmd_list)

    p_search = sub.add_parser("search", help="search prompt/response/tags")
    p_search.add_argument("query")
    p_search.add_argument("--limit", type=int, default=20)
    p_search.set_defaults(func=cmd_search)

    p_export = sub.add_parser("export", help="export receipts")
    p_export.add_argument("path", nargs="?")
    p_export.add_argument(
        "--bundle",
        action="store_true",
        help="alias for --format bundle (portable JSON with public keys)",
    )
    p_export.add_argument(
        "--format",
        choices=("jsonl", "bundle", "scitt", "scitt-bundle"),
        default="jsonl",
        help="output shape: jsonl (default), bundle (portable with public keys), "
             "scitt (single COSE_Sign1 envelope, needs --id), "
             "scitt-bundle (all receipts as SCITT envelopes with manifest)",
    )
    p_export.add_argument(
        "--id",
        dest="receipt_id",
        type=int,
        default=None,
        help="receipt id (required for --format scitt)",
    )
    p_export.set_defaults(func=cmd_export)

    p_verify = sub.add_parser("verify", help="verify the receipt chain or export")
    p_verify.add_argument(
        "--export",
        dest="export_path",
        help="verify a portable bundle or JSONL export instead of the local vault",
    )
    p_verify.add_argument(
        "--public-key",
        action="append",
        default=[],
        metavar="KEY_ID=PATH",
        help="pin an export key to a trusted PEM file (repeatable)",
    )
    p_verify.add_argument(
        "--revoked-key-id",
        action="append",
        default=[],
        help="treat this signing key as revoked during export verification",
    )
    p_verify.add_argument(
        "--verbose",
        action="store_true",
        help="print receipt-level verification issues",
    )
    p_verify.set_defaults(func=cmd_verify)

    p_revoke = sub.add_parser(
        "revoke-key", help="revoke a signing key for future verification"
    )
    p_revoke.add_argument("key_id")
    p_revoke.set_defaults(func=cmd_revoke_key)

    p_proxy = sub.add_parser("proxy", help="run a provider-native receipt proxy")
    p_proxy.add_argument("--port", type=int, default=8765)
    p_proxy.add_argument(
        "--upstream-base-url",
        help="provider API base (env: DONTLIE_UPSTREAM_BASE_URL)",
    )
    p_proxy.add_argument(
        "--protocol",
        choices=("openai", "anthropic"),
        default="openai",
        help="provider-native wire protocol (default: openai)",
    )
    p_proxy.add_argument(
        "--upstream-path",
        help="override the adapter's upstream request path",
    )
    p_proxy.add_argument(
        "--auth-header",
        help="override the adapter's upstream authentication header",
    )
    p_proxy.add_argument(
        "--auth-scheme",
        help="override the auth value scheme, e.g. Bearer; pass an empty value for raw",
    )
    p_proxy.add_argument(
        "--anthropic-version",
        help="override Anthropic's default 2023-06-01 API version header",
    )
    p_proxy.add_argument(
        "--verbose",
        action="store_true",
        help="log each request/response to stderr (operator audit only)",
    )
    p_proxy.add_argument(
        "--mock",
        action="store_true",
        help="start an in-process mock OpenAI-compatible provider and route "
             "the proxy at it. No API key required. Perfect for trying "
             "dontlie without burning a real provider key.",
    )
    p_proxy.add_argument(
        "--mock-port", type=int, default=0,
        help="port for the in-process mock (0 = OS picks; default: 0)",
    )
    p_proxy.set_defaults(func=cmd_proxy)

    p_ui = sub.add_parser("ui", help="launch the interactive receipt explorer (TUI)")
    p_ui.add_argument("--limit", type=int, default=200, help="max receipts to load (default: 200)")
    p_ui.add_argument("--vault", type=Path, default=None, help="path to vault.db (default: $DONTLIE_DB or ~/.local/share/dontlie/vault.db)")
    p_ui.set_defaults(func=cmd_ui)

    p_web = sub.add_parser("web", help="launch the web UI (stdlib HTTP server)")
    p_web.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    p_web.add_argument("--port", type=int, default=8080, help="bind port (default: 8080)")
    p_web.add_argument("--vault", type=Path, default=None, help="path to vault.db (default: $DONTLIE_DB or ~/.local/share/dontlie/vault.db)")
    p_web.set_defaults(func=cmd_web)

    p_trust = sub.add_parser("trust-score", help="compute a 0-100 trust score for the local vault")
    p_trust.add_argument("--json", action="store_true", help="emit JSON for CI")
    p_trust.add_argument("receipt_id", nargs="?", type=int, default=None,
                         help="optional: score a single receipt (e.g. `dontlie trust-score 42`)")
    p_trust.set_defaults(func=cmd_trust_score)

    # Safety net: snapshot the live vault before any risky operation.
    # The v0.3.0/v0.3.1 test-isolation bug wiped the production vault
    # because no snapshot existed. ``dontlie backup`` is the cheap
    # insurance policy against that class of bug.
    p_backup = sub.add_parser(
        "backup",
        help="snapshot the live vault to a safe copy (use before "
             "upgrades, migrations, or any test work)",
    )
    p_backup.add_argument("--src", dest="src", type=Path, default=None)
    p_backup.add_argument("--dst", dest="dst", type=Path, default=None)
    p_backup.add_argument("--list", dest="list_only", action="store_true",
                          help="list existing snapshots and exit")
    p_backup.set_defaults(func=cmd_backup)

    p_tail = sub.add_parser("tail", help="stream new receipts (NDJSON for SIEM)")
    p_tail.add_argument("--follow", "-f", action="store_true", help="poll for new receipts")
    p_tail.add_argument("--last", type=int, default=20, help="show the last N (default: 20)")
    p_tail.add_argument("--interval", type=float, default=2.0, help="poll interval in seconds (default: 2)")
    p_tail.add_argument("--json", action="store_true", help="emit JSONL (one receipt per line)")
    p_tail.set_defaults(func=cmd_tail)

    # Capability 2: decision-level evidence
    p_decision = sub.add_parser("decision", help="wrap multiple receipts into a signed decision")
    p_decision.add_argument("--json", action="store_true")
    p_decision.add_argument("decision_action", nargs="?",
                            choices=["create", "list", "show"], default="list",
                            help="action to perform (default: list)")
    p_decision.add_argument("--name", help="decision name (for create)")
    p_decision.add_argument("--actor", help="who made the decision (for create)")
    p_decision.add_argument("--notes", default="", help="decision notes (for create)")
    p_decision.add_argument("--tag", action="append", default=[], help="add a tag")
    p_decision.add_argument("--limit", type=int, default=20, help="list limit")
    p_decision.add_argument("decision_id_or_receipts", nargs="*", type=int, default=[],
                            help="for create: receipt IDs; for show: decision ID")
    p_decision.set_defaults(func=cmd_decision)

    # Capability 3: policy gates
    p_policy = sub.add_parser("policy", help="manage pre-call allow/deny/redact policy")
    p_policy.add_argument("policy_action", nargs="?",
                          choices=["show", "test", "deny-model", "deny-prompt", "allow-only", "redact-pii", "path"],
                          default="show")
    p_policy.add_argument("--model", help="for `policy test`")
    p_policy.add_argument("--prompt", help="for `policy test`")
    p_policy.add_argument("policy_args", nargs="*")
    p_policy.set_defaults(func=cmd_policy)

    # Capability 4: annotations
    p_annotate = sub.add_parser("annotate", help="attach signed reviewer notes to receipts")
    p_annotate.add_argument("annotate_action", nargs="?",
                            choices=["add", "show", "list"], default="list")
    p_annotate.add_argument("--actor", help="for `annotate add`")
    p_annotate.add_argument("--note", help="for `annotate add`")
    p_annotate.add_argument("--tag", action="append", default=[])
    p_annotate.add_argument("--json", action="store_true")
    p_annotate.add_argument("annotate_ids", nargs="*", type=int, default=[])
    p_annotate.set_defaults(func=cmd_annotate)

    # Capability 5: RFC 3161 timestamp anchor
    p_anchor = sub.add_parser("anchor", help="anchor a receipt to an external TSA (closes RD #5)")
    p_anchor.add_argument("anchor_action", nargs="?", choices=["add", "list", "verify", "daily"], default="list")
    p_anchor.add_argument("--tsa", choices=["freetsa", "digicert"], default="freetsa")
    p_anchor.add_argument("receipt_id", nargs="?", type=int, default=None)
    p_anchor.add_argument("--day", dest="anchor_day", default=None,
                          help="for `anchor daily`: UTC day to anchor (YYYY-MM-DD, default: today UTC)")
    p_anchor.add_argument("--url", dest="anchor_url", default=None,
                          help="for `anchor daily`: witness service URL")
    p_anchor.add_argument("--dry-run", dest="anchor_dry_run", action="store_true",
                          help="for `anchor daily`: show what would be anchored without making any requests")
    p_anchor.set_defaults(func=cmd_anchor)

    # Capability 6: bulk import from competitor formats
    p_import = sub.add_parser("import", help="import receipts from a competitor's export")
    p_import.add_argument("path", type=Path)
    p_import.add_argument("--format", default=None,
                          choices=["obsigna", "halo-record", "aulite", "generic-jsonl"])
    p_import.set_defaults(func=cmd_import)

    # Capability 7: public witness service
    p_witness = sub.add_parser("witness-service", help="run the public witness notary (stdin/stdout)")
    p_witness.add_argument("--host", default="127.0.0.1")
    p_witness.add_argument("--port", type=int, default=9099)
    p_witness.add_argument("--key-dir", type=Path, default=None,
                           help="where to store the service's signing key "
                                "(default: $DONTLIE_KEY_DIR/../witness or "
                                "~/.config/dontlie/witness)")
    p_witness.set_defaults(func=cmd_witness_service)

    # Capability 7b: ask the hosted witness to co-sign a receipt hash.
    # This is the "Bitcoin moment" — anyone with a receipt can get a
    # public, no-permission co-signature from a notary that's not
    # under their control. Defaults to the hosted dontlie witness;
    # override with --url for a self-hosted one.
    p_witness_attest = sub.add_parser(
        "witness-attest",
        help="co-sign a receipt hash with the hosted witness notary",
    )
    p_witness_attest.add_argument(
        "receipt",
        nargs="?",
        help="a receipt id (e.g. 1026) or a 64-char SHA-256 hex digest",
    )
    p_witness_attest.add_argument(
        "--url",
        default=os.environ.get(
            "DONTLIE_WITNESS_URL",
            "https://dontlie-witness.buxmont-floodassist.workers.dev",
        ),
        help="witness service URL (default: hosted dontlie witness)",
    )
    p_witness_attest.add_argument(
        "--parent-sha256",
        default=None,
        help="optional: include the receipt's parent sha256 in the request",
    )
    p_witness_attest.add_argument(
        "--nonce", default=None,
        help="optional: a caller-chosen nonce (default: random 16 bytes hex)",
    )
    p_witness_attest.add_argument(
        "--no-verify", action="store_true",
        help="skip the local signature verification (faster, but you must "
             "trust the network)",
    )
    p_witness_attest.set_defaults(func=cmd_witness_attest)

    # Capability 7c: co-sign every receipt in the current namespace with the
    # witness notary. Improves the `dontlie trust-score` coverage component
    # from 0/20 to 20/20, and converts "the chain did not break" from an
    # operator claim into a third-party-witnessed claim.
    p_witness_cov = sub.add_parser(
        "witness-coverage",
        help="co-sign every receipt in the current namespace with the witness",
    )
    p_witness_cov.add_argument(
        "--url",
        default=os.environ.get(
            "DONTLIE_WITNESS_URL",
            "https://dontlie-witness.buxmont-floodassist.workers.dev",
        ),
        help="witness service URL (default: hosted dontlie witness)",
    )
    p_witness_cov.add_argument("--limit", type=int, default=None)
    p_witness_cov.add_argument("--since", default=None)
    p_witness_cov.add_argument("--resume", action="store_true")
    p_witness_cov.add_argument("--dry-run", action="store_true")
    p_witness_cov.add_argument("--quiet", action="store_true")
    p_witness_cov.set_defaults(func=cmd_witness_coverage)

    # Capability 8: OCSF / Splunk ECS streaming output
    p_siem = sub.add_parser("siem", help="emit receipts in OCSF or Splunk ECS field format")
    p_siem.add_argument("siem_action", nargs="?", choices=["tail", "convert"], default="tail")
    p_siem.add_argument("--format", choices=["ocsf", "ecs"], required=True)
    p_siem.add_argument("--last", type=int, default=20)
    p_siem.add_argument("receipt_id", nargs="?", type=int, default=None)
    p_siem.set_defaults(func=cmd_siem)

    # Merkle-root batch signatures
    p_batch = sub.add_parser("batch", help="create a Merkle-root signature over a range of receipts")
    p_batch.add_argument("batch_action", nargs="?", choices=["create", "list", "show", "prove"], default="list")
    p_batch.add_argument("--from", dest="from_id", type=int)
    p_batch.add_argument("--to", dest="to_id", type=int)
    p_batch.add_argument("--tag", action="append", default=[])
    p_batch.add_argument("batch_or_receipt_id", nargs="?", type=int, default=None,
                          help="for `show`: batch id; for `prove`: receipt id")
    p_batch.set_defaults(func=cmd_batch)

    # Multi-namespace vaults
    p_namespace = sub.add_parser("namespace", help="manage multi-tenant namespaces")
    p_namespace.add_argument("ns_action", nargs="?",
                              choices=["list", "create", "use", "show", "delete", "stats"], default="list")
    p_namespace.add_argument("name", nargs="?", default=None)
    p_namespace.add_argument("--description", default="")
    p_namespace.add_argument("--force", action="store_true")
    p_namespace.set_defaults(func=cmd_namespace)

    # Provider attestation registry
    p_registry = sub.add_parser("registry", help="manage the known provider attestation registry")
    p_registry.add_argument("reg_action", nargs="?",
                             choices=["list", "show", "add", "install-default", "attest", "verify"],
                             default="list")
    p_registry.add_argument("name", nargs="?", default=None)
    p_registry.add_argument("--model-pattern", default="*")
    p_registry.add_argument("--base-url", default="")
    p_registry.add_argument("--notes", default="")
    p_registry.add_argument("receipt_id", nargs="?", type=int, default=None)
    p_registry.set_defaults(func=cmd_registry)

    # OTS-compatible pending attestations
    p_ots = sub.add_parser("ots", help="OpenTimestamps-compatible pending attestations (Bitcoin-anchorable)")
    p_ots.add_argument("ots_action", nargs="?", choices=["create", "list", "upgrade"], default="list")
    p_ots.add_argument("receipt_id_or_file", nargs="?", type=int, default=None)
    p_ots.set_defaults(func=cmd_ots)

    # Self-contained shareable verification URL
    p_verify_url = sub.add_parser(
        "verify-url",
        help="generate a self-contained, shareable verification URL for one receipt",
    )
    p_verify_url.add_argument("receipt_id", type=int, help="the receipt id to encode")
    p_verify_url.add_argument(
        "--base-url",
        default="https://queued-inlet-pmqa.here.now/",
        help="verifier URL to embed (default: the live deployed verifier)",
    )
    p_verify_url.add_argument(
        "--out",
        default=None,
        help="write the URL to this file instead of stdout",
    )
    p_verify_url.add_argument(
        "--verify",
        action="store_true",
        help="verify the generated URL locally before emitting (sanity check)",
    )
    p_verify_url.set_defaults(func=cmd_verify_url)

    return p


def cmd_ui(args) -> int:
    """Launch the interactive TUI."""
    import os

    from . import ui
    if args.vault is not None:
        storage.DB_PATH = args.vault
    elif "DONTLIE_DB" in os.environ:
        storage.DB_PATH = Path(os.environ["DONTLIE_DB"])
    storage.init()
    app = ui.DontlieApp(limit=args.limit)
    app.run()
    return 0


def cmd_web(args) -> int:
    """Launch the stdlib web UI."""
    import os

    from . import web as _web
    if args.vault is not None:
        storage.DB_PATH = args.vault
    elif "DONTLIE_DB" in os.environ:
        storage.DB_PATH = Path(os.environ["DONTLIE_DB"])
    return _web.main(["--host", args.host, "--port", str(args.port), "--vault", str(args.vault)] if args.vault else ["--host", args.host, "--port", str(args.port)])


def cmd_trust_score(args) -> int:
    """Compute and print a 0-100 trust score for the local vault."""

    from . import trust as _trust
    if getattr(args, "receipt_id", None) is not None:
        # per-receipt score
        r = storage.get_receipt(args.receipt_id)
        if r is None:
            print(f"receipt {args.receipt_id} not found", file=sys.stderr)
            return 1
        score = _trust.score_receipt(r)
        if args.json:
            print(json.dumps(score, indent=2, sort_keys=True, default=str))
        else:
            print(f"trust-score #{r.id}: {score['value']}/100  ({score['label']})")
            for name, c in score["components"].items():
                print(f"  {name:20s}  {c['value']:>3}/{c['max']}  {c['note']}")
        return 0
    score = _trust.compute()
    if args.json:
        print(json.dumps(score.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"trust-score: {score.value}/100  ({score.label})")
        for line in score.summary:
            print(f"  - {line}")
    return 0


def cmd_tail(args) -> int:
    """Stream new receipts (NDJSON for SIEM)."""
    from . import tail as _tail
    argv = []
    if args.follow:
        argv.append("--follow")
    if args.last != 20:
        argv.extend(["--last", str(args.last)])
    if args.interval != 2.0:
        argv.extend(["--interval", str(args.interval)])
    if args.json:
        argv.append("--json")
    return _tail.main(argv)


def cmd_decision(args) -> int:
    """Wrap multiple receipts into a signed decision."""
    import os

    from . import decision as _decision
    if os.environ.get("DONTLIE_DB"):
        storage.DB_PATH = Path(os.environ["DONTLIE_DB"])
    if os.environ.get("DONTLIE_KEY_DIR"):
        from . import sign as signing
        signing.KEY_DIR = Path(os.environ["DONTLIE_KEY_DIR"])
        signing.PRIVATE_FILE = signing.KEY_DIR / "dontlie.key"
        signing.PUBLIC_FILE = signing.KEY_DIR / "dontlie.pub"
        signing.KEY_ID_FILE = signing.KEY_DIR / "key_id"
    action = args.decision_action
    if action == "create":
        if not args.name or not args.actor or not args.decision_id_or_receipts:
            print("usage: dontlie decision create --name NAME --actor ACTOR RECEIPT_ID [RECEIPT_ID ...]",
                  file=sys.stderr)
            return 2
        try:
            d = _decision.create(
                name=args.name, actor=args.actor, receipt_ids=args.decision_id_or_receipts,
                notes=args.notes, tags=args.tag,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"decision #{d.id} created")
        print(f"  name:      {d.name}")
        print(f"  actor:     {d.actor}")
        print(f"  receipts:  {', '.join('#'+str(r) for r in d.receipt_ids)}")
        return 0
    if action == "show":
        if not args.decision_id_or_receipts:
            print("usage: dontlie decision show DECISION_ID", file=sys.stderr)
            return 2
        d = _decision.get(args.decision_id_or_receipts[0])
        if d is None:
            print("decision not found", file=sys.stderr)
            return 1
        ok = _decision.verify(d)
        if args.json:
            print(json.dumps({"decision": d.__dict__, "verified": ok}, indent=2, sort_keys=True, default=str))
        else:
            print(f"Decision #{d.id}  ({'VERIFIED' if ok else 'FAILED'})")
            print(f"  name:      {d.name}")
            print(f"  actor:     {d.actor}")
            print(f"  notes:     {d.notes or '(none)'}")
            print(f"  receipts:  {', '.join('#'+str(r) for r in d.receipt_ids)}")
        return 0 if ok else 2
    # list
    decisions = _decision.list_all(limit=args.limit)
    if not decisions:
        print("no decisions yet")
        return 0
    for d in decisions:
        print(f"#{d.id}  {d.timestamp}  [{d.actor}]  {d.name}")
    return 0


def cmd_policy(args) -> int:
    """Manage pre-call allow/deny/redact policy."""
    from . import policy as _policy
    # Re-route to the policy subcommand parser
    sub_argv = [args.policy_action]
    if args.policy_action == "test":
        sub_argv += ["--model", args.model or "", "--prompt", args.prompt or ""]
    elif args.policy_action in ("deny-model", "deny-prompt", "allow-only") or args.policy_action == "redact-pii":
        sub_argv += list(args.policy_args)
    return _policy.main(sub_argv)


def cmd_annotate(args) -> int:
    """Attach signed reviewer notes to receipts."""
    from . import annotate as _annotate
    sub_argv = [args.annotate_action]
    if args.annotate_action == "add":
        sub_argv += ["--actor", args.actor or "", "--note", args.note or ""]
        for t in args.tag:
            sub_argv += ["--tag", t]
        sub_argv += [str(r) for r in args.annotate_ids]
    elif args.annotate_action == "show":
        sub_argv += [str(args.annotate_ids[0])]
        if args.json:
            sub_argv += ["--json"]
    elif args.annotate_action == "list":
        sub_argv += [str(args.annotate_ids[0])]
    return _annotate.main(sub_argv)


def cmd_anchor(args) -> int:
    """Anchor a receipt to an external TSA, or anchor the daily Merkle root."""
    if args.anchor_action == "daily":
        from . import anchor_daily as _ad
        sub_argv = []
        if hasattr(args, "anchor_day") and args.anchor_day:
            sub_argv += ["--day", args.anchor_day]
        if hasattr(args, "anchor_url") and args.anchor_url:
            sub_argv += ["--url", args.anchor_url]
        if hasattr(args, "anchor_dry_run") and args.anchor_dry_run:
            sub_argv += ["--dry-run"]
        return _ad.main(sub_argv)
    from . import anchor as _anchor
    if args.anchor_action == "add":
        if args.receipt_id is None:
            print("usage: dontlie anchor add RECEIPT_ID", file=sys.stderr)
            return 2
        sub_argv = ["add", str(args.receipt_id), "--tsa", args.tsa]
        return _anchor.main(sub_argv)
    if args.anchor_action == "verify":
        if args.receipt_id is None:
            print("usage: dontlie anchor verify RECEIPT_ID", file=sys.stderr)
            return 2
        sub_argv = ["verify", str(args.receipt_id)]
        return _anchor.main(sub_argv)
    return _anchor.main(["list"])


def cmd_import(args) -> int:
    """Import receipts from a competitor's export."""
    from . import importers as _importers
    sub_argv = [str(args.path)]
    if args.format:
        sub_argv += ["--format", args.format]
    return _importers.main(sub_argv)


def cmd_witness_attest(args) -> int:
    """Co-sign a receipt hash with the hosted witness service.

    Two-phase: POST a JSON request to the witness /attest endpoint,
    then locally verify the returned signature against the witness's
    advertised public key. Default endpoint is the hosted dontlie
    witness at dontlie-witness.buxmont-floodassist.workers.dev.

    Closes Reasonable Doubt #5: the receipt's existence is now
    co-signed by a third party whose key the operator doesn't hold.
    """
    import base64
    storage.init()
    target = (args.receipt or "").strip()
    receipt_sha = ""
    parent_sha = args.parent_sha256
    receipt_id = None
    if not target:
        # Default: the most recent receipt
        latest = storage.list_receipts(limit=1)
        if not latest:
            print("no receipts in vault; provide a receipt id or sha256", file=sys.stderr)
            return 2
        target = str(latest[0].id)
    if re.fullmatch(r"[0-9a-fA-F]{64}", target):
        receipt_sha = target.lower()
    elif target.isdigit():
        receipt_id = int(target)
        r = storage.get_receipt(receipt_id)
        if r is None:
            print(f"receipt {receipt_id} not found", file=sys.stderr)
            return 2
        # Local integrity check: the receipt's stored payload_sha256
        # must match a fresh recompute of the canonical payload hash.
        # If they disagree, the receipt has been mutated (response,
        # tags, extra, etc.) without recomputing the hash — and the
        # witness signature we are about to request would attest the
        # OLD hash, not the receipt's current content. A downstream
        # verifier would reject the bundle as hash-mismatched, and
        # the operator would have paid for an attestation they can't
        # use. Refuse early with a clear error rather than producing
        # a useless signature.
        try:
            from . import storage as _storage
            recomputed = _storage._canonical_payload(r)
            import hashlib as _hashlib
            actual = _hashlib.sha256(recomputed).hexdigest()
            if actual != r.payload_sha256:
                print(
                    f"receipt {receipt_id} has been mutated: "
                    f"stored payload_sha256={r.payload_sha256[:16]}... "
                    f"does not match recomputed {actual[:16]}... "
                    "The witness can only attest a hash; attesting this "
                    "receipt would sign a hash that the (tampered) "
                    "content does not match. Run `dontlie verify` to "
                    "see the chain state. If you intended to remove a "
                    "tampered receipt, the right move is to keep this "
                    "receipt and the old hash, or to start a new "
                    "vault. Refusing to attest.",
                    file=sys.stderr,
                )
                return 2
        except Exception as e:
            print(f"could not verify local receipt integrity: {e}", file=sys.stderr)
            return 2
        receipt_sha = r.payload_sha256
        if parent_sha is None:
            parent_sha = r.extra.get("_dontlie_parent_sha256") if r.extra else None
    else:
        print(
            f"unrecognized receipt reference {target!r}; "
            "expected a receipt id (e.g. 1026) or a 64-char SHA-256 hex",
            file=sys.stderr,
        )
        return 2

    # Discover the operator's signing key id. The witness co-signs
    # (hash, operator_key_id, parent, nonce, now) so it needs to
    # know which operator is asking. Pull it from the local vault.
    operator_key_id = ""
    if receipt_id is not None:
        r = storage.get_receipt(receipt_id)
        if r is not None:
            operator_key_id = r.key_id
    if not operator_key_id:
        # Fall back to the active key
        try:
            from . import sign as signing
            kp = signing.load()
            operator_key_id = kp.key_id
        except Exception:
            pass

    nonce = args.nonce or secrets.token_hex(16)
    url = args.url.rstrip("/") + "/attest"
    payload = {
        "receipt_sha256": receipt_sha,
        "operator_key_id": operator_key_id or "unknown",
        "nonce": nonce,
    }
    if parent_sha:
        payload["parent_sha256"] = parent_sha

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"dontlie-cli/{__version__} (+https://dontlie.pages.dev)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            attestation = json.loads(raw)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"witness rejected the request: HTTP {e.code}: {body}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"could not reach witness at {url}: {e}", file=sys.stderr)
        return 1

    # Verify the witness signature locally against the public key it
    # advertises at /pubkey. This is the trust anchor — we do NOT
    # trust the response over the wire.
    if not args.no_verify:
        try:
            pkreq = urllib.request.Request(
                args.url.rstrip("/") + "/pubkey", method="GET",
                headers={"User-Agent": f"dontlie-cli/{__version__}"},
            )
            with urllib.request.urlopen(pkreq, timeout=10) as resp:
                pub = json.loads(resp.read())
        except Exception as e:
            print(f"could not fetch witness pubkey: {e}", file=sys.stderr)
            return 1
        # Reconstruct the canonical message the witness signed
        canonical = json.dumps({
            "receipt_sha256": receipt_sha,
            "operator_key_id": payload["operator_key_id"],
            "parent_sha256": parent_sha or "",
            "nonce": nonce,
            "service": attestation.get("service", ""),
            "service_version": attestation.get("service_version", ""),
            "service_key_id": attestation.get("service_key_id", ""),
            "issued_at": attestation.get("issued_at", ""),
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        from . import sign as signing
        try:
            witness_pub = signing.load_public_key(pub["public_key_pem"])
            sig = base64.b64decode(attestation["signature"])
            signing.verify_bytes(witness_pub, canonical, sig.hex())
        except Exception as e:
            print(
                f"FAIL: witness signature did not verify against "
                f"{pub.get('key_id', '?')}: {e}",
                file=sys.stderr,
            )
            return 2

    # Pretty output
    print(f"witness attestation for receipt {target}")
    print(f"  witness:     {attestation.get('service')} v{attestation.get('service_version')}")
    print(f"  witness key: {attestation.get('service_key_id')}")
    print(f"  operator:    {payload['operator_key_id']}")
    print(f"  receipt:     {receipt_sha}")
    if parent_sha:
        print(f"  parent:      {parent_sha}")
    print(f"  nonce:       {nonce}")
    print(f"  issued_at:   {attestation.get('issued_at')}")
    print(f"  signature:   {attestation.get('signature', '')[:48]}...")
    if not args.no_verify:
        print()
        print("  ✓ signature verified locally against witness public key")
    else:
        print()
        print("  ! verification skipped (--no-verify)")
    return 0


def cmd_witness_coverage(args) -> int:
    """Co-sign every receipt in the current namespace with the witness."""
    from . import witness_coverage as _wc
    sub_argv = ["--url", args.url]
    if args.limit is not None:
        sub_argv += ["--limit", str(args.limit)]
    if args.since:
        sub_argv += ["--since", args.since]
    if args.resume:
        sub_argv += ["--resume"]
    if args.dry_run:
        sub_argv += ["--dry-run"]
    if args.quiet:
        sub_argv += ["--quiet"]
    return _wc.main(sub_argv)


def cmd_witness_service(args) -> int:
    """Run the public witness notary service."""
    from . import witness_service as _ws
    sub_argv = ["--host", args.host, "--port", str(args.port)]
    if args.key_dir is not None:
        sub_argv += ["--key-dir", str(args.key_dir)]
    return _ws.main(sub_argv)


def cmd_siem(args) -> int:
    """Emit receipts in OCSF or Splunk ECS field format."""
    from . import siem as _siem
    if args.siem_action == "convert":
        if args.receipt_id is None:
            print("usage: dontlie siem convert RECEIPT_ID --format ocsf|ecs", file=sys.stderr)
            return 2
        sub_argv = ["convert", str(args.receipt_id), "--format", args.format]
    else:
        sub_argv = ["tail", "--format", args.format, "--last", str(args.last)]
    return _siem.main(sub_argv)


def cmd_batch(args) -> int:
    """Create a Merkle-root signature over a range of receipts."""
    from . import batch as _batch
    if args.batch_action == "create":
        if args.from_id is None or args.to_id is None:
            print("usage: dontlie batch create --from ID --to ID", file=sys.stderr)
            return 2
        sub_argv = ["create", "--from", str(args.from_id), "--to", str(args.to_id)]
        for t in args.tag:
            sub_argv += ["--tag", t]
        return _batch.main(sub_argv)
    if args.batch_action == "show":
        if args.batch_or_receipt_id is None:
            print("usage: dontlie batch show BATCH_ID", file=sys.stderr)
            return 2
        return _batch.main(["show", str(args.batch_or_receipt_id)])
    if args.batch_action == "prove":
        if args.batch_or_receipt_id is None:
            print("usage: dontlie batch prove RECEIPT_ID", file=sys.stderr)
            return 2
        return _batch.main(["prove", str(args.batch_or_receipt_id)])
    return _batch.main(["list"])


def cmd_namespace(args) -> int:
    """Manage multi-tenant namespaces."""
    from . import namespace as _ns
    sub_argv = [args.ns_action]
    if args.ns_action in ("create", "use", "show", "delete", "stats") and args.name:
        sub_argv.append(args.name)
    if args.ns_action == "create" and args.description:
        sub_argv += ["--description", args.description]
    if args.ns_action == "delete" and args.force:
        sub_argv += ["--force"]
    return _ns.main(sub_argv)


def cmd_registry(args) -> int:
    """Manage the known provider attestation registry."""
    from . import registry as _reg
    sub_argv = [args.reg_action]
    if args.reg_action == "show" and args.name:
        sub_argv.append(args.name)
    if args.reg_action == "add" and args.name:
        sub_argv.append(args.name)
        if args.model_pattern != "*":
            sub_argv += ["--model-pattern", args.model_pattern]
        if args.base_url:
            sub_argv += ["--base-url", args.base_url]
        if args.notes:
            sub_argv += ["--notes", args.notes]
    if args.reg_action in ("attest", "verify") and args.receipt_id is not None:
        sub_argv.append(str(args.receipt_id))
    return _reg.main(sub_argv)


def cmd_ots(args) -> int:
    """OTS-compatible pending attestations."""
    from . import ots as _ots
    if args.ots_action == "create" and args.receipt_id_or_file is not None:
        return _ots.main(["create", str(args.receipt_id_or_file)])
    if args.ots_action == "upgrade" and args.receipt_id_or_file is not None:
        return _ots.main(["upgrade", str(args.receipt_id_or_file)])
    return _ots.main(["list"])


def cmd_backup(args) -> int:
    """Snapshot the live vault to a safe copy."""
    from . import backup as _backup
    sub_argv = []
    if args.src is not None:
        sub_argv += ["--src", str(args.src)]
    if args.dst is not None:
        sub_argv += ["--dst", str(args.dst)]
    if getattr(args, "list_only", False):
        sub_argv += ["--list"]
    return _backup.main(sub_argv)


def cmd_verify_url(args) -> int:
    """Generate a self-contained, shareable verification URL for one receipt."""
    from . import verify_url as _vu
    sub_argv = [str(args.receipt_id)]
    if args.base_url:
        sub_argv += ["--base-url", args.base_url]
    if args.out:
        sub_argv += ["--out", args.out]
    if getattr(args, "verify", False):
        sub_argv += ["--verify"]
    return _vu.main(sub_argv)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

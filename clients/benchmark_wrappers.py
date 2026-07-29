"""Benchmark: default SDK vs dontlie-wrapped SDK.

Compares latency, throughput, and memory of:
  (a) the default OpenAI Python SDK pointing directly at the (mock) provider
  (b) the dontlie-openai wrapper pointing at a local dontlie proxy, which
      forwards to the same (mock) provider

This isolates the overhead of the proxy + signing + sqlite write — that's
the cost of the receipt, in numbers.

Usage:
    python3 BENCHMARK_SCRIPT.py [N=200] [output_path]
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import statistics
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent if "__file__" in globals() else Path.cwd().parent
DEMO = ROOT / "demo"
DEMO_SCRIPTS = DEMO / "scripts"
WORK = DEMO / "work" / "bench-cli"
MOCK_PORT = 9870
PROXY_PORT = 9871


def _free_port(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _wait_listening(port: int, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _free_port(port):
            return True
        time.sleep(0.05)
    return False


def _kill_pid(pid: int) -> None:
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        pass


def _run(cmd: list[str], **kwargs) -> subprocess.Popen:
    return subprocess.Popen(cmd, **kwargs)


def _chat_direct(client, model: str, prompt: str) -> str:
    """No dontlie: call the mock provider directly via OpenAI SDK."""
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=32,
    )
    return resp.choices[0].message.content or ""


def _chat_wrapped(client, model: str, prompt: str) -> str:
    """Routed through dontlie proxy."""
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=32,
    )
    return resp.choices[0].message.content or ""


def _measure(fn, n: int, **kwargs) -> dict:
    """Run fn() n times, return timings + memory."""
    tracemalloc.start()
    latencies = []
    t0 = time.perf_counter()
    for i in range(n):
        s = time.perf_counter()
        fn(prompt=f"ping {i}", **kwargs)
        latencies.append((time.perf_counter() - s) * 1000.0)
    elapsed = time.perf_counter() - t0
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "n": n,
        "elapsed_sec": round(elapsed, 4),
        "throughput_per_sec": round(n / elapsed, 2),
        "latency_ms_p50": round(statistics.median(latencies), 3),
        "latency_ms_p95": round(sorted(latencies)[int(0.95 * n) - 1], 3),
        "latency_ms_max": round(max(latencies), 3),
        "mem_current_kb": round(current / 1024, 1),
        "mem_peak_kb": round(peak / 1024, 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("n", nargs="?", type=int, default=200)
    ap.add_argument("output", nargs="?", type=Path,
                    default=Path("BENCHMARK.transcript.json"))
    args = ap.parse_args()

    # setup isolated workdir
    WORK.mkdir(parents=True, exist_ok=True)
    os.environ["DONTLIE_KEY_DIR"] = str(WORK / "keys")
    os.environ["DONTLIE_DB"] = str(WORK / "vault.db")
    os.environ["DONTLIE_NO_WAL"] = "1"
    os.environ["DONTLIE_UPSTREAM_BASE_URL"] = f"http://127.0.0.1:{MOCK_PORT}"
    os.environ["DONTLIE_UPSTREAM_API_KEY"] = "mock-no-key"
    os.environ["DONTLIE_BASE_URL"] = f"http://127.0.0.1:{PROXY_PORT}/v1"
    os.environ["DONTLIE_API_KEY"] = "dontlie-local"

    # generate signing key
    sys.path.insert(0, str(ROOT))
    from dontlie import sign as signing
    (WORK / "keys").mkdir(parents=True, exist_ok=True)
    signing.generate()

    # start mock + proxy
    if not _free_port(MOCK_PORT):
        print(f"port {MOCK_PORT} busy", file=sys.stderr); return 1
    if not _free_port(PROXY_PORT):
        print(f"port {PROXY_PORT} busy", file=sys.stderr); return 1

    mock_log = open(WORK / "mock.log", "wb")  # noqa: SIM115
    mock = _run(
        [sys.executable, str(DEMO_SCRIPTS / "mock_provider.py"), "--port", str(MOCK_PORT)],
        stdout=mock_log, stderr=mock_log,
    )
    try:
        if not _wait_listening(MOCK_PORT):
            print("mock did not start", file=sys.stderr)
            print("---mock log---", file=sys.stderr)
            with open(WORK / "mock.log") as f:
                print(f.read(), file=sys.stderr)
            return 1
        print(f"mock up on {MOCK_PORT}", file=sys.stderr)
    except Exception:
        _kill_pid(mock.pid)
        raise

    proxy_log = open(WORK / "proxy.log", "wb")  # noqa: SIM115
    proxy = _run(
        [sys.executable, "-m", "dontlie", "proxy", "--port", str(PROXY_PORT)],
        stdout=proxy_log, stderr=subprocess.STDOUT,
        env=os.environ,
    )
    try:
        if not _wait_listening(PROXY_PORT, timeout=10.0):
            print("proxy did not start", file=sys.stderr)
            print("---proxy log---", file=sys.stderr)
            with open(WORK / "proxy.log") as f:
                print(f.read(), file=sys.stderr)
            return 1
        print(f"proxy up on {PROXY_PORT}", file=sys.stderr)
        print(f"mock + proxy up on {MOCK_PORT}/{PROXY_PORT}", file=sys.stderr)

        # === measure: default SDK pointed directly at mock provider ===
        import openai
        direct_client = openai.OpenAI(
            base_url=f"http://127.0.0.1:{MOCK_PORT}/v1",
            api_key="mock-no-key",
        )
        print(f"running default-SDK benchmark ({args.n} reqs)", file=sys.stderr)
        direct = _measure(lambda **kw: _chat_direct(direct_client, "mock-1", **kw), args.n)

        # === measure: dontlie-wrapped SDK pointed at proxy ===
        import dontlie_openai
        wrapped_client = dontlie_openai.Client()
        print(f"running dontlie-wrapped benchmark ({args.n} reqs)", file=sys.stderr)
        wrapped = _measure(lambda **kw: _chat_wrapped(wrapped_client, "mock-1", **kw), args.n)

        # verify receipts were written
        from dontlie import storage
        ok, bad = storage.verify_chain()
        receipts_in_db = ok + bad

    finally:
        _kill_pid(mock.pid)
        _kill_pid(proxy.pid)
        mock.wait(timeout=5)
        proxy.wait(timeout=5)
        mock_log.close()

    overhead = {
        "latency_ms_p50_added": round(wrapped["latency_ms_p50"] - direct["latency_ms_p50"], 3),
        "latency_ms_p95_added": round(wrapped["latency_ms_p95"] - direct["latency_ms_p95"], 3),
        "throughput_pct": round((wrapped["throughput_per_sec"] / direct["throughput_per_sec"]) * 100, 1),
        "mem_peak_kb_added": round(wrapped["mem_peak_kb"] - direct["mem_peak_kb"], 1),
    }

    transcript = {
        "machine": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "configuration": {
            "n_requests": args.n,
            "mock_port": MOCK_PORT,
            "proxy_port": PROXY_PORT,
            "note": "Mock provider is local stdlib HTTP. Both paths traverse the same provider; the dontlie path adds an extra proxy hop + sqlite write + ed25519 sign.",
        },
        "default_sdk": direct,
        "dontlie_wrapped": wrapped,
        "overhead": overhead,
        "receipts_written": receipts_in_db,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(transcript, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output}", file=sys.stderr)
    print(json.dumps(transcript, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

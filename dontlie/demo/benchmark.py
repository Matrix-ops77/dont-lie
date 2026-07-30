"""Benchmark Don't-Lie: signing, verification, and proxy throughput.

Runs against an isolated workdir so it never touches the real vault.
Outputs a transcript file with timings, throughput, and machine info.

Usage:
    python3 -m dontlie.demo.benchmark [N=1000] [transcript_path]

Designed to be deterministic given the same Python/runtime/build.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# IMPORTANT: set env BEFORE importing dontlie so module-level DB_PATH / KEY_DIR
# resolve to the isolated workdir.
_default_work = ROOT / "demo" / "work" / "bench"
os.environ.setdefault("DONTLIE_KEY_DIR", str(_default_work / "keys"))
os.environ.setdefault("DONTLIE_DB", str(_default_work / "vault.db"))
os.environ.setdefault("DONTLIE_NO_WAL", "1")

sys.path.insert(0, str(ROOT))

from dontlie import sign as signing
from dontlie import storage


def _measure_sign(n: int) -> dict:
    """Append `n` receipts and time the appends."""
    # warm-up
    storage.append("bench-warmup", "warmup", "ok", tags=["benchmark"])
    latencies_ms: list[float] = []
    t0 = time.perf_counter()
    for i in range(n):
        s = time.perf_counter()
        storage.append(
            model=f"bench-{i % 4}",
            prompt=f"prompt #{i}",
            response=f"response payload #{i} " * 8,
            tags=["benchmark", f"batch-{i // 100}"],
        )
        latencies_ms.append((time.perf_counter() - s) * 1000.0)
    elapsed = time.perf_counter() - t0
    return {
        "n": n,
        "elapsed_sec": round(elapsed, 4),
        "throughput_per_sec": round(n / elapsed, 2),
        "latency_ms_p50": round(statistics.median(latencies_ms), 3),
        "latency_ms_p95": round(sorted(latencies_ms)[int(0.95 * n) - 1], 3),
        "latency_ms_p99": round(sorted(latencies_ms)[int(0.99 * n) - 1], 3),
        "latency_ms_max": round(max(latencies_ms), 3),
    }


def _measure_verify() -> dict:
    t0 = time.perf_counter()
    ok, bad = storage.verify_chain()
    elapsed = time.perf_counter() - t0
    return {
        "receipts": ok + bad,
        "elapsed_sec": round(elapsed, 4),
        "verify_per_sec": round((ok + bad) / elapsed, 2) if elapsed > 0 else None,
        "ok": ok,
        "bad": bad,
    }


def _measure_export() -> dict:
    out = Path(os.environ["DONTLIE_DB"]).with_suffix(".bench-export.jsonl")
    t0 = time.perf_counter()
    n = storage.export(out)
    elapsed = time.perf_counter() - t0
    size_bytes = out.stat().st_size
    return {
        "n": n,
        "elapsed_sec": round(elapsed, 4),
        "export_per_sec": round(n / elapsed, 2) if elapsed > 0 else None,
        "jsonl_bytes": size_bytes,
    }


def _measure_render() -> dict:
    """Time the HTML evidence report render on the captured chain.

    The render reads a portable bundle (not the live vault) and
    produces a self-contained HTML file with no external assets.
    """
    # Use the JSONL export we just wrote and wrap it in a single
    # bundle dict so render_report can read it. We don't need a
    # separate bundle export step here — the render tool accepts
    # JSONL-shaped bundles too, but the single-object bundle is
    # the canonical form. Build it in-process.
    import json
    from dontlie.demo.render_report import render as render_report

    jsonl_path = Path(os.environ["DONTLIE_DB"]).with_suffix(".bench-export.jsonl")
    rows = [json.loads(line) for line in jsonl_path.read_text().splitlines() if line.strip()]
    bundle_path = jsonl_path.with_suffix(".bench-bundle.json")
    bundle_path.write_text(json.dumps({"receipts": rows}) + "\n", encoding="utf-8")

    out = jsonl_path.with_suffix(".bench-report.html")
    t0 = time.perf_counter()
    html = render_report(bundle_path)
    out.write_text(html, encoding="utf-8")
    elapsed = time.perf_counter() - t0
    return {
        "n": len(rows),
        "elapsed_sec": round(elapsed, 4),
        "render_per_sec": round(len(rows) / elapsed, 2) if elapsed > 0 else None,
        "html_bytes": out.stat().st_size,
    }


def _machine_info() -> dict:
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "dontlie_pkg": _dontlie_version(),
    }


def _dontlie_version() -> str:
    try:
        from dontlie import __version__
        return __version__
    except (ImportError, AttributeError):
        return "unknown"


def _sha256_file(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("n", nargs="?", type=int, default=1000)
    ap.add_argument("transcript", nargs="?", type=Path,
                    default=Path("demo/output/benchmark.transcript.json"))
    args = ap.parse_args()

    # isolated workdir
    work = ROOT / "demo" / "work" / "bench"
    work.mkdir(parents=True, exist_ok=True)
    os.environ["DONTLIE_KEY_DIR"] = str(work / "keys")
    os.environ["DONTLIE_DB"] = str(work / "vault.db")
    os.environ["DONTLIE_NO_WAL"] = "1"

    # fresh keypair + db
    if (work / "keys").exists():
        shutil.rmtree(work / "keys")
    (work / "keys").mkdir(parents=True)
    signing.generate()

    machine = _machine_info()
    print(f"==> bench environment: {machine}", file=sys.stderr)
    print(f"==> workdir: {work}", file=sys.stderr)

    print(f"==> running {args.n} appends", file=sys.stderr)
    sign = _measure_sign(args.n)
    print(f"   {sign['throughput_per_sec']} receipts/sec, "
          f"p50={sign['latency_ms_p50']}ms p95={sign['latency_ms_p95']}ms", file=sys.stderr)

    print("==> verifying chain", file=sys.stderr)
    verify = _measure_verify()
    print(f"   {verify['verify_per_sec']} receipts/sec, ok={verify['ok']} bad={verify['bad']}", file=sys.stderr)

    print("==> exporting JSONL", file=sys.stderr)
    export = _measure_export()
    print(f"   {export['export_per_sec']} rows/sec, {export['jsonl_bytes']} bytes", file=sys.stderr)

    print("==> rendering HTML report", file=sys.stderr)
    render_meas = _measure_render()
    print(f"   {render_meas['render_per_sec']} receipts/sec, "
          f"{render_meas['html_bytes']} bytes", file=sys.stderr)

    transcript = {
        "machine": machine,
        "workdir": str(work),
        "sign": sign,
        "verify": verify,
        "export": export,
        "render": render_meas,
        "db_sha256": _sha256_file(Path(os.environ["DONTLIE_DB"])),
    }
    args.transcript.parent.mkdir(parents=True, exist_ok=True)
    args.transcript.write_text(json.dumps(transcript, indent=2) + "\n", encoding="utf-8")
    print(f"==> wrote {args.transcript}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

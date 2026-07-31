# Benchmarks

The benchmark is a local measurement, not a universal performance guarantee.
Hardware, filesystem, Python version, background load, and vault size all
affect the result.

## Current checked-in run

Command:

```bash
python3 -m dontlie.demo.benchmark 5000 demo/output/benchmark.transcript.json
```

Environment: Apple arm64 hardware, Python 3.10.20, Don't-Lie 0.3.11,
single-threaded.

| Operation | Measured throughput | Additional result |
|---|---:|---|
| Sign + store | 1,075.62 receipts/sec | p50 0.871 ms; p95 1.201 ms |
| Verify chain | 5,960.42 receipts/sec | 5,001 valid; 0 invalid |
| Export JSONL | 47,101.06 rows/sec | 4,172,376 bytes |
| Render HTML report | 96,707.14 receipts/sec | 949,117 bytes |

The extra receipt is the benchmark warm-up record. The complete machine-pinned
record, including timings and database SHA-256, is
[`demo/output/benchmark.transcript.json`](../demo/output/benchmark.transcript.json).

## Reproduction rules

The benchmark removes its isolated database, SQLite sidecars, keypair, and
generated exports before every run. It never intentionally touches the normal
Don't-Lie vault.

Run it several times on the target deployment hardware and use the distribution
of results for capacity planning. Do not compare a single laptop run directly
with a server workload without matching storage, concurrency, and receipt
sizes.

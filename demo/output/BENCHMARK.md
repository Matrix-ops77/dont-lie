# Benchmark transcript — reference fixture

Captured by `python3 demo/scripts/benchmark.py 5000` on:

| Item | Value |
|---|---|
| Python | 3.11.15 |
| Platform | macOS-27.0-arm64 |
| Machine | arm64 (Apple Silicon) |
| dontlie | 0.2.0 |

## Results (5000 receipts, isolated workdir, single-threaded)

| Phase | Throughput | Latency p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| Sign + append | **436 /sec** | 1.83 ms | 4.59 ms | n/a | n/a |
| Verify chain | **2,224 /sec** | n/a | n/a | n/a | n/a |
| Export JSONL | **30,650 /sec** | n/a | n/a | n/a | n/a |

- 5000 sign+append operations: ~11.5s total
- 5001 verify operations: ~2.25s total
- 5001 export rows: ~0.16s total, 3,572,256 bytes (~714 B/receipt)

## Reproduce

```sh
python3 demo/scripts/benchmark.py 5000 demo/output/benchmark.transcript.json
```

The benchmark is single-threaded, single-process. Numbers are wall-clock
on the host above. Multi-core scaling will be lower than linear because
the bottleneck is SQLite write locking.

## What this proves

- Local signing is fast enough for human-paced chat (>> 100 req/sec).
- Bulk verification is ~5× faster than signing; you can verify a day of
  receipts in under a second.
- Export is mostly JSON serialization — disk-bound, not crypto-bound.

## What this does NOT prove

- Streaming throughput. The proxy path includes a network round-trip; the
  benchmark only exercises the local sign+append path.
- Real concurrent client load. Run your own load test against `dontlie proxy`
  if you need production capacity numbers.
- Cross-process concurrent writers. SQLite locking is the limiter.

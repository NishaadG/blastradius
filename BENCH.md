# Concurrency benchmark

N concurrent agents share one graph for 5 seconds. Mix: 70% path traversal, 20% precedent lookup, 10% memory write.
Writes use a throwaway session id and are deleted afterwards. Reproduce with `python -m blastradius.bench boutique --report`.

Run: 2026-10-15 · Windows 11 · 8 logical CPUs · FalkorDB in Docker · tenant `boutique`. Numbers vary with hardware; treat them as shape, not a promise.

| Agents | Ops/sec | p50 ms | p95 ms | p99 ms | Read p95 ms | Write p95 ms | Errors | Backpressure retries |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 696 | 13.15 | 24.86 | 36.24 | 27.39 | 24.05 | 0 | 0 |
| 50 | 781 | 37.56 | 288.17 | 384.21 | 61.34 | 468.64 | 0 | 3 |
| 100 | 803 | 40.72 | 773.61 | 1057.18 | 86.14 | 1094.15 | 0 | 171 |

Reading it: reads stay fast because FalkorDB runs read queries on a thread pool. Writes are executed one at a time, so
write latency includes queueing and grows with the number of agents. When FalkorDB's bounded query queue fills it
answers `Max pending queries exceeded`; the client retries with jittered backoff (`db.py`) and the retries are counted
above, never hidden. In an earlier run without that retry, 100 agents saw ~2% of operations rejected: that is why it exists.

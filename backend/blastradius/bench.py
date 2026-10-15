"""Concurrency benchmark (Track 2: shared state, high-concurrency reads and writes).

N concurrent 'agents' each loop for a fixed time doing what real agents do against shared graph memory:
  70% read   path traversal (advisory -> services)
  20% read   precedent lookup in memory
  10% write  record a Case (episodic memory) linked into the graph
Writes use a throwaway session id that is deleted afterwards, so the benchmark leaves no trace.

    python -m blastradius.bench boutique --agents 50 --seconds 5
"""
import argparse
import random
import statistics
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from . import db, memory, queries as q

_one_at_a_time = threading.Lock()


def _pct(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(len(xs) * p))], 2)


def run_bench(tenant: str, agents: int = 50, seconds: float = 4.0) -> dict:
    agents = max(1, min(int(agents), 100))
    seconds = max(1.0, min(float(seconds), 8.0))
    if not _one_at_a_time.acquire(blocking=False):
        raise RuntimeError("a benchmark is already running")
    sid = f"bench-{uuid.uuid4().hex[:10]}"
    try:
        ids = [r[0] for r in db.read(tenant, "MATCH (a:Advisory) RETURN a.id LIMIT 200").result_set]
        if not ids:
            raise RuntimeError("tenant has no advisories")
        memory.ensure_playbooks(tenant)
        lat: dict[str, list[float]] = {"path": [], "precedent": [], "write": []}
        errors = 0
        err_types: dict[str, int] = {}
        lock = threading.Lock()
        stop = time.monotonic() + seconds

        def agent(_):
            nonlocal errors
            rng = random.Random()
            while time.monotonic() < stop:
                a = rng.choice(ids)
                roll = rng.random()
                t0 = time.perf_counter()
                try:
                    if roll < 0.7:
                        q.affected_paths(tenant, a)
                        kind = "path"
                    elif roll < 0.9:
                        memory.find_precedents(tenant, a, ["protobufjs"], sid)
                        kind = "precedent"
                    else:
                        db.write(tenant, """MATCH (adv:Advisory {id:$aid})
                            CREATE (c:Case {id:$cid, sid:$sid, decision:'patched', rationale:'bench', actor:'bench',
                                            ts:$ts, outcome:'success', reused:0})-[:ABOUT]->(adv)""",
                                 {"aid": a, "cid": f"case-{uuid.uuid4().hex[:8]}", "sid": sid, "ts": int(time.time() * 1000)})
                        kind = "write"
                    ms = (time.perf_counter() - t0) * 1000
                    with lock:
                        lat[kind].append(ms)
                except Exception as e:
                    with lock:
                        errors += 1
                        err_types[f"{type(e).__name__}: {str(e)[:80]}"] = err_types.get(f"{type(e).__name__}: {str(e)[:80]}", 0) + 1

        retries0 = db.backpressure_retries()
        t0 = time.monotonic()
        with ThreadPoolExecutor(agents) as ex:
            list(ex.map(agent, range(agents)))
        wall = time.monotonic() - t0
        retries = db.backpressure_retries() - retries0
        allms = [x for v in lat.values() for x in v]
        out = {
            "tenant": tenant, "agents": agents, "seconds": round(wall, 2), "errors": errors, "error_types": err_types,
            "backpressure_retries": retries,
            "operations": len(allms), "ops_per_sec": round(len(allms) / wall, 1) if wall else 0,
            "overall": {"p50_ms": _pct(allms, 0.5), "p95_ms": _pct(allms, 0.95), "p99_ms": _pct(allms, 0.99),
                        "mean_ms": round(statistics.fmean(allms), 2) if allms else 0},
            "by_op": {k: {"count": len(v), "p50_ms": _pct(v, 0.5), "p95_ms": _pct(v, 0.95)} for k, v in lat.items()},
        }
        return out
    finally:
        try:
            db.write(tenant, "MATCH (c:Case {sid:$sid}) DETACH DELETE c", {"sid": sid})
        finally:
            _one_at_a_time.release()


def report(tenant: str, path):
    """Run 10/50/100 agents and write a markdown report (BENCH.md) including the machine it ran on."""
    import datetime
    import os
    import platform

    rows = [run_bench(tenant, n, 5) for n in (10, 50, 100)]
    lines = [
        "# Concurrency benchmark",
        "",
        "N concurrent agents share one graph for 5 seconds. Mix: 70% path traversal, 20% precedent lookup, 10% memory write.",
        "Writes use a throwaway session id and are deleted afterwards. Reproduce with `python -m blastradius.bench "
        f"{tenant} --report`.",
        "",
        f"Run: {datetime.date.today().isoformat()} · {platform.system()} {platform.release()} · {os.cpu_count()} logical CPUs · "
        f"FalkorDB in Docker · tenant `{tenant}`. Numbers vary with hardware; treat them as shape, not a promise.",
        "",
        "| Agents | Ops/sec | p50 ms | p95 ms | p99 ms | Read p95 ms | Write p95 ms | Errors | Backpressure retries |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        rd = max(r["by_op"]["path"]["p95_ms"], r["by_op"]["precedent"]["p95_ms"])
        lines.append(f"| {r['agents']} | {r['ops_per_sec']:,.0f} | {r['overall']['p50_ms']} | {r['overall']['p95_ms']} | "
                     f"{r['overall']['p99_ms']} | {rd} | {r['by_op']['write']['p95_ms']} | {r['errors']} | {r['backpressure_retries']} |")
    lines += [
        "",
        "Reading it: reads stay fast because FalkorDB runs read queries on a thread pool. Writes are executed one at a time, so",
        "write latency includes queueing and grows with the number of agents. When FalkorDB's bounded query queue fills it",
        "answers `Max pending queries exceeded`; the client retries with jittered backoff (`db.py`) and the retries are counted",
        "above, never hidden. In an earlier run without that retry, 100 agents saw ~2% of operations rejected: that is why it exists.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rows


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("tenant")
    ap.add_argument("--agents", type=int, default=50)
    ap.add_argument("--seconds", type=float, default=5)
    ap.add_argument("--report", action="store_true", help="write BENCH.md at the repo root")
    a = ap.parse_args()
    import json
    from pathlib import Path

    if a.report:
        report(a.tenant, Path(__file__).resolve().parents[2] / "BENCH.md")
        print("wrote BENCH.md")
    else:
        print(json.dumps(run_bench(a.tenant, a.agents, a.seconds), indent=2))

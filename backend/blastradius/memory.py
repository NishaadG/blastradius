"""Agent memory, stored in the same per-tenant graph as the dependency data.

 episodic   (:Case)      one triage decision, linked to the advisory and services it concerned
 semantic   (:Advisory)-[:AFFECTS]->(:Package)  facts about the environment
 procedural (:Playbook)  remediation recipes, reinforced by outcomes
 shared     (:Run)-[:HAS_STEP]->(:Step)  agent handoff state: each agent reads the previous step from the graph
"""
import time
import uuid

from . import db

DECISIONS = {"patched", "not_affected", "accepted_risk"}

PLAYBOOKS = {
    "npm": ("npm:bump-direct-dependency",
            "Find the direct dependency that pulls the vulnerable package, bump it (or add an `overrides` entry), "
            "regenerate package-lock.json, run the test suite."),
    "Go": ("Go:go-get-upgrade", "go get module@fixed && go mod tidy, run tests, rebuild the image."),
    "PyPI": ("PyPI:pin-fixed-version", "Pin the fixed version in requirements.txt, re-lock hashes, run tests."),
}


def _now() -> int:
    return int(time.time() * 1000)


def ensure_playbooks(tenant):
    for eco, (key, steps) in PLAYBOOKS.items():
        db.write(tenant, "MERGE (p:Playbook {key:$k}) ON CREATE SET p.steps=$s, p.successes=0, p.failures=0, p.eco=$e",
                 {"k": key, "s": steps, "e": eco})


def record_decision(tenant, advisory_id, decision, rationale, actor, services, eco=None, outcome="success"):
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {sorted(DECISIONS)}")
    ensure_playbooks(tenant)
    cid = f"case-{uuid.uuid4().hex[:8]}"
    db.write(tenant, """MATCH (a:Advisory {id:$aid})
        CREATE (c:Case {id:$cid, decision:$d, rationale:$r, actor:$actor, ts:$ts, outcome:$o, reused:0})
        CREATE (c)-[:ABOUT]->(a)""",
             {"aid": advisory_id, "cid": cid, "d": decision, "r": rationale, "actor": actor, "ts": _now(), "o": outcome})
    if services:
        db.write(tenant, """MATCH (c:Case {id:$cid}) UNWIND $svcs AS sn MATCH (s:Service {name:sn}) MERGE (c)-[:IN]->(s)""",
                 {"cid": cid, "svcs": services})
    if decision == "patched" and eco in PLAYBOOKS:
        key = PLAYBOOKS[eco][0]
        field = "successes" if outcome == "success" else "failures"
        db.write(tenant, f"""MATCH (c:Case {{id:$cid}}), (p:Playbook {{key:$k}})
            MERGE (c)-[:USED]->(p) SET p.{field} = p.{field} + 1""", {"cid": cid, "k": key})
    return cid


Q_PRECEDENT = """
MATCH (c:Case)-[:ABOUT]->(a2:Advisory)
OPTIONAL MATCH (a2)-[:AFFECTS]->(p2:Package)
WITH c, a2, collect(DISTINCT p2.name) AS pkgs
WHERE a2.id = $aid OR any(n IN pkgs WHERE n IN $names)
OPTIONAL MATCH (c)-[:IN]->(s:Service)
OPTIONAL MATCH (c)-[:USED]->(pb:Playbook)
RETURN c.id, c.decision, c.rationale, c.actor, c.ts, a2.id, a2.cve, pkgs, collect(DISTINCT s.name),
       collect(DISTINCT pb.key), (a2.id = $aid) AS exact
ORDER BY exact DESC, c.ts DESC LIMIT 5
"""


def find_precedents(tenant, advisory_id, package_names):
    from .queries import _run
    rows, tr = _run(tenant, Q_PRECEDENT, {"aid": advisory_id, "names": list(package_names)})
    out = [{"id": r[0], "decision": r[1], "rationale": r[2], "actor": r[3], "ts": r[4], "advisory": r[5],
            "cve": r[6], "packages": r[7], "services": r[8], "playbooks": r[9], "exact": bool(r[10])} for r in rows]
    return out, tr


def mark_reused(tenant, case_ids):
    if case_ids:
        db.write(tenant, "MATCH (c:Case) WHERE c.id IN $ids SET c.reused = c.reused + 1", {"ids": case_ids})


def save_run(tenant, run_id, ident, verdict, steps):
    db.write(tenant, "CREATE (:Run {id:$id, ident:$i, verdict:$v, ts:$ts})",
             {"id": run_id, "i": ident, "v": verdict, "ts": _now()})
    prev = None
    for n, st in enumerate(steps):
        sid = f"{run_id}-{n}"
        db.write(tenant, """MATCH (r:Run {id:$rid}) CREATE (s:Step {id:$sid, n:$n, agent:$agent, tool:$tool, summary:$sum, ms:$ms})
            CREATE (r)-[:HAS_STEP]->(s)""",
                 {"rid": run_id, "sid": sid, "n": n, "agent": st["agent"], "tool": st["tool"],
                  "sum": st["summary"], "ms": st.get("ms", 0)})
        if prev:
            db.write(tenant, "MATCH (a:Step {id:$a}),(b:Step {id:$b}) CREATE (a)-[:HANDS_OFF_TO]->(b)",
                     {"a": prev, "b": sid})
        prev = sid


def brain_timeline(tenant):
    from .queries import _run
    rows, _ = _run(tenant, "MATCH (c:Case) RETURN c.id, c.decision, c.ts, c.reused, c.actor ORDER BY c.ts")
    runs, _ = _run(tenant, "MATCH (r:Run) RETURN count(r)")
    pbs, _ = _run(tenant, "MATCH (p:Playbook) RETURN p.key, p.successes, p.failures, p.steps ORDER BY p.successes DESC")
    return {"cases": [{"id": r[0], "decision": r[1], "ts": r[2], "reused": r[3], "actor": r[4]} for r in rows],
            "runs": runs[0][0] if runs else 0,
            "playbooks": [{"key": r[0], "successes": r[1], "failures": r[2], "steps": r[3]} for r in pbs]}

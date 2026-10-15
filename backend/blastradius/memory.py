"""Agent memory, stored in the same per-tenant graph as the dependency data.

 episodic   (:Case)      one triage decision, linked to the advisory and services it concerned
 semantic   (:Advisory)-[:AFFECTS]->(:Package)  facts about the environment
 procedural (:Playbook)  remediation recipes; success/failure counts are DERIVED from the cases that used them
 shared     (:Run)-[:HAS_STEP]->(:Step)  agent handoff state: each agent reads the previous step from the graph

Every memory node carries `sid`, the session it belongs to, so on a shared public server one visitor's memory is
invisible to (and cannot be wiped by) another. CLI/MCP/test use the default session "shared".
"""
import time
import uuid

from . import db

DECISIONS = {"patched", "not_affected", "accepted_risk"}
DEFAULT_SID = "shared"
MAX_CASES = 2000   # per tenant; oldest are pruned beyond this
MAX_RUNS = 4000

PLAYBOOKS = {
    "npm": ("npm:bump-direct-dependency",
            "Find the direct dependency that pulls the vulnerable package, bump it (or add an `overrides` entry), "
            "regenerate package-lock.json, run the test suite."),
    "Go": ("Go:go-get-upgrade", "go get module@fixed && go mod tidy, run tests, rebuild the image."),
    "PyPI": ("PyPI:pin-fixed-version", "Pin the fixed version in requirements.txt, re-lock hashes, run tests."),
    "Maven": ("Maven:bump-dependency-version", "Raise the version in pom.xml (or dependencyManagement), run `mvn verify`."),
    "crates.io": ("crates.io:cargo-update", "cargo update -p crate --precise <fixed>, run cargo test."),
}


def _now() -> int:
    return int(time.time() * 1000)


def ensure_playbooks(tenant):
    for key, steps in PLAYBOOKS.values():
        db.write(tenant, "MERGE (p:Playbook {key:$k}) ON CREATE SET p.steps=$s", {"k": key, "s": steps})


def record_decision(tenant, advisory_id, decision, rationale, actor, services, eco=None, outcome="success", sid=DEFAULT_SID):
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {sorted(DECISIONS)}")
    ensure_playbooks(tenant)
    cid = f"case-{uuid.uuid4().hex[:8]}"
    db.write(tenant, """MATCH (a:Advisory {id:$aid})
        CREATE (c:Case {id:$cid, sid:$sid, decision:$d, rationale:$r, actor:$actor, ts:$ts, outcome:$o, reused:0})
        CREATE (c)-[:ABOUT]->(a)""",
             {"aid": advisory_id, "cid": cid, "sid": sid, "d": decision, "r": rationale[:500], "actor": actor[:60],
              "ts": _now(), "o": outcome})
    if services:
        db.write(tenant, """MATCH (c:Case {id:$cid}) UNWIND $svcs AS sn MATCH (s:Service {name:sn}) MERGE (c)-[:IN]->(s)""",
                 {"cid": cid, "svcs": services})
    if decision == "patched" and eco in PLAYBOOKS:
        db.write(tenant, "MATCH (c:Case {id:$cid}), (p:Playbook {key:$k}) MERGE (c)-[:USED]->(p)",
                 {"cid": cid, "k": PLAYBOOKS[eco][0]})
    prune(tenant)
    return cid


def prune(tenant):
    """Retention: a shared server must not grow without bound."""
    n = db.read(tenant, "MATCH (c:Case) RETURN count(c)").result_set[0][0]
    if n > MAX_CASES:
        db.write(tenant, "MATCH (c:Case) WITH c ORDER BY c.ts ASC LIMIT $k DETACH DELETE c", {"k": n - MAX_CASES + 200})
    r = db.read(tenant, "MATCH (r:Run) RETURN count(r)").result_set[0][0]
    if r > MAX_RUNS:
        db.write(tenant, "MATCH (r:Run) WITH r ORDER BY r.ts ASC LIMIT $k OPTIONAL MATCH (r)-[:HAS_STEP]->(s:Step) DETACH DELETE s, r",
                 {"k": r - MAX_RUNS + 400})


Q_PRECEDENT = """
MATCH (c:Case)-[:ABOUT]->(a2:Advisory)
WHERE c.sid = $sid
OPTIONAL MATCH (a2)-[:AFFECTS]->(p2:Package)
WITH c, a2, collect(DISTINCT p2.name) AS pkgs
WHERE a2.id = $aid OR any(n IN pkgs WHERE n IN $names)
OPTIONAL MATCH (c)-[:IN]->(s:Service)
OPTIONAL MATCH (c)-[:USED]->(pb:Playbook)
RETURN c.id, c.decision, c.rationale, c.actor, c.ts, a2.id, a2.cve, pkgs, collect(DISTINCT s.name),
       collect(DISTINCT pb.key), (a2.id = $aid) AS exact
ORDER BY exact DESC, c.ts DESC LIMIT 5
"""


def find_precedents(tenant, advisory_id, package_names, sid=DEFAULT_SID):
    from .queries import _run
    rows, tr = _run(tenant, Q_PRECEDENT, {"aid": advisory_id, "names": list(package_names), "sid": sid})
    out = [{"id": r[0], "decision": r[1], "rationale": r[2], "actor": r[3], "ts": r[4], "advisory": r[5],
            "cve": r[6], "packages": r[7], "services": r[8], "playbooks": r[9], "exact": bool(r[10])} for r in rows]
    return out, tr


def mark_reused(tenant, case_ids):
    if case_ids:
        db.write(tenant, "MATCH (c:Case) WHERE c.id IN $ids SET c.reused = c.reused + 1", {"ids": case_ids})


def save_run(tenant, run_id, ident, verdict, steps, sid=DEFAULT_SID):
    db.write(tenant, "CREATE (:Run {id:$id, sid:$sid, ident:$i, verdict:$v, ts:$ts})",
             {"id": run_id, "sid": sid, "i": ident[:80], "v": verdict, "ts": _now()})
    prev = None
    for n, st in enumerate(steps):
        sid_ = f"{run_id}-{n}"
        db.write(tenant, """MATCH (r:Run {id:$rid}) CREATE (s:Step {id:$sid, n:$n, agent:$agent, tool:$tool, summary:$sum, ms:$ms})
            CREATE (r)-[:HAS_STEP]->(s)""",
                 {"rid": run_id, "sid": sid_, "n": n, "agent": st["agent"], "tool": st["tool"],
                  "sum": st["summary"][:300], "ms": st.get("ms", 0)})
        if prev:
            db.write(tenant, "MATCH (a:Step {id:$a}),(b:Step {id:$b}) CREATE (a)-[:HANDS_OFF_TO]->(b)",
                     {"a": prev, "b": sid_})
        prev = sid_


def reset_session(tenant, sid):
    """Delete only this session's memory. Other visitors are untouched."""
    db.write(tenant, "MATCH (c:Case {sid:$sid}) DETACH DELETE c", {"sid": sid})
    db.write(tenant, "MATCH (r:Run {sid:$sid}) OPTIONAL MATCH (r)-[:HAS_STEP]->(s:Step) DETACH DELETE s, r", {"sid": sid})


def brain_timeline(tenant, sid=DEFAULT_SID):
    from .queries import _run
    rows, _ = _run(tenant, "MATCH (c:Case {sid:$sid}) RETURN c.id, c.decision, c.ts, c.reused, c.actor ORDER BY c.ts", {"sid": sid})
    runs, _ = _run(tenant, "MATCH (r:Run {sid:$sid}) RETURN count(r)", {"sid": sid})
    pbs, _ = _run(tenant, """MATCH (p:Playbook)
        OPTIONAL MATCH (c:Case {sid:$sid})-[:USED]->(p)
        RETURN p.key, p.steps, sum(CASE WHEN c.outcome = 'success' THEN 1 ELSE 0 END),
               sum(CASE WHEN c.outcome = 'failure' THEN 1 ELSE 0 END)
        ORDER BY p.key""", {"sid": sid})
    playbooks = [{"key": r[0], "steps": r[1], "successes": r[2], "failures": r[3]} for r in pbs]
    if not playbooks:  # a fresh graph has not created its playbook nodes yet: show the built-in recipes at zero
        playbooks = [{"key": k, "steps": s, "successes": 0, "failures": 0} for k, s in PLAYBOOKS.values()]
    return {"cases": [{"id": r[0], "decision": r[1], "ts": r[2], "reused": r[3], "actor": r[4]} for r in rows],
            "runs": runs[0][0] if runs else 0, "playbooks": playbooks}

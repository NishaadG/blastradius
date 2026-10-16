"""Tests run against a tiny hand-built fixture graph so every expected answer is known."""
import pytest

from blastradius import db, memory, queries as q, triage
from blastradius.db import UnsafeQuery
from blastradius.parsers import parse_go_mod, parse_npm_lock, parse_requirements

T = "pytest_fixture"

# web(exposed) -> api -> db-svc ; web -> payments
# api -> libA -> libB(vuln X)         (prod path, 3 hops)
# payments -> libDev(vuln Y, dev)     (dev only)
# db-svc -> libC (no vuln)
SETUP = [
    "CREATE (:Service {name:'web', exposed:true}), (:Service {name:'api', exposed:false}), "
    "(:Service {name:'payments', exposed:false}), (:Service {name:'dbsvc', exposed:false}), (:Service {name:'island', exposed:false})",
    "MATCH (a:Service {name:'web'}),(b:Service {name:'api'}),(c:Service {name:'payments'}),(d:Service {name:'dbsvc'}) "
    "CREATE (a)-[:CALLS]->(b),(a)-[:CALLS]->(c),(b)-[:CALLS]->(d)",
    "CREATE (:Package {key:'npm:libA@1', name:'libA', version:'1', eco:'npm', dev:false}),"
    "(:Package {key:'npm:libB@1', name:'libB', version:'1', eco:'npm', dev:false}),"
    "(:Package {key:'npm:libDev@1', name:'libDev', version:'1', eco:'npm', dev:true}),"
    "(:Package {key:'npm:libC@1', name:'libC', version:'1', eco:'npm', dev:false}),"
    "(:Package {key:'npm:libB@2', name:'libB', version:'2', eco:'npm', dev:false})",
    "MATCH (s:Service {name:'api'}),(a:Package {key:'npm:libA@1'}),(b:Package {key:'npm:libB@1'}) "
    "CREATE (s)-[:DEPENDS_ON {direct:true}]->(a),(a)-[:DEPENDS_ON]->(b)",
    "MATCH (s:Service {name:'payments'}),(p:Package {key:'npm:libDev@1'}) CREATE (s)-[:DEPENDS_ON {dev:true}]->(p)",
    "MATCH (s:Service {name:'dbsvc'}),(p:Package {key:'npm:libC@1'}) CREATE (s)-[:DEPENDS_ON]->(p)",
    "CREATE (:Advisory {id:'GHSA-xxxx-xxxx-xxxx', cve:'CVE-2000-0001', severity:'CRITICAL', summary:'x', url:'u'}),"
    "(:Advisory {id:'GHSA-yyyy-yyyy-yyyy', cve:'CVE-2000-0002', severity:'HIGH', summary:'y', url:'u'})",
    "MATCH (a:Advisory {id:'GHSA-xxxx-xxxx-xxxx'}),(p:Package {key:'npm:libB@1'}) CREATE (a)-[:AFFECTS {fixed:'2'}]->(p)",
    "MATCH (a:Advisory {id:'GHSA-yyyy-yyyy-yyyy'}),(p:Package {key:'npm:libDev@1'}) CREATE (a)-[:AFFECTS {fixed:'2'}]->(p)",
    "MATCH (o:Service {name:'api'}) CREATE (:Owner {name:'org/api-team', kind:'team'})-[:OWNS]->(o)",
]


@pytest.fixture(scope="module", autouse=True)
def fixture_graph():
    g = db.graph(T)
    try:
        g.delete()
    except Exception:
        pass
    for s in SETUP:
        db.write(T, s)
    yield
    db.graph(T).delete()


def test_parse_npm_nested_resolution():
    lock = ('{"packages":{"":{"dependencies":{"a":"1"}},"node_modules/a":{"version":"1.0.0","dependencies":{"b":"2"}},'
            '"node_modules/b":{"version":"1.0.0"},"node_modules/a/node_modules/b":{"version":"2.0.0"}}}')
    pkgs, edges = parse_npm_lock(lock)
    assert ("npm:a@1.0.0", "npm:b@2.0.0", False) in edges  # nested copy wins over hoisted
    assert (None, "npm:a@1.0.0", False) in edges


def test_parse_go_and_requirements():
    gp, ge = parse_go_mod("module x\nrequire (\n\tgolang.org/x/net v0.1.0 // indirect\n\tgithub.com/a/b v1.2.3\n)\n")
    assert gp["Go:github.com/a/b@1.2.3"]["version"] == "1.2.3" and gp["Go:golang.org/x/net@0.1.0"]["indirect"]
    rp, _ = parse_requirements("Flask==2.0.1 \\\n    --hash=sha256:abc\nrequests[security]==2.31.0\n# c\n")
    assert "PyPI:flask@2.0.1" in rp and "PyPI:requests@2.31.0" in rp


def test_affected_path_found_with_hops():
    paths, tr = q.affected_paths(T, "GHSA-xxxx-xxxx-xxxx")
    assert [p["service"] for p in paths] == ["api"]
    assert paths[0]["path"] == ["api", "npm:libA@1", "npm:libB@1"] and paths[0]["fixed"] == "2"
    assert tr["cypher"].startswith("MATCH")


def test_blast_radius_and_exposure_path():
    callers, _ = q.upstream_callers(T, "dbsvc")
    assert {c["service"] for c in callers} == {"api", "web"}
    ep, _ = q.exposure_path(T, "dbsvc")
    assert ep == ["web", "api", "dbsvc"]
    assert q.exposure_path(T, "island")[0] is None  # nothing reaches it: no path = not exposed


def test_verdict_affected_p0_exposed():
    r = triage.run_triage(T, "CVE-2000-0001")
    assert r["verdict"] == "AFFECTED" and r["priority"] == "P0"
    assert r["services"][0]["owners"][0]["owner"] == "org/api-team"
    assert r["actions"] and r["actions"][0]["status"] == "pending_approval"


def test_verdict_dev_only_needs_human():
    r = triage.run_triage(T, "GHSA-yyyy-yyyy-yyyy")
    assert r["verdict"] == "NEEDS_HUMAN" and r["reason"] == "dev_only_dependency"


def test_precedent_is_found_and_reused():
    r = triage.run_triage(T, "CVE-2000-0001")
    cid = memory.record_decision(T, r["advisory"]["id"], "patched", "bumped libB", "alice", ["api"], eco="npm")
    again = triage.run_triage(T, "CVE-2000-0001")
    assert any(p["id"] == cid and p["exact"] for p in again["precedents"])
    b = memory.brain_timeline(T)
    npm = next(p for p in b["playbooks"] if p["key"].startswith("npm:"))
    assert b["cases"][0]["reused"] >= 1 and npm["successes"] >= 1


def test_vex_precedent_flips_verdict_to_not_affected():
    r = triage.run_triage(T, "GHSA-yyyy-yyyy-yyyy")
    memory.record_decision(T, r["advisory"]["id"], "not_affected", "dev tool only", "bob", ["payments"])
    r2 = triage.run_triage(T, "GHSA-yyyy-yyyy-yyyy")
    assert r2["verdict"] == "NOT_AFFECTED" and r2["reason"] == "vex_precedent"


def test_decisions_export_as_openvex():
    from blastradius import vex

    sid = "vex-session"
    memory.reset_session(T, sid)
    memory.record_decision(T, "GHSA-xxxx-xxxx-xxxx", "patched", "bumped libB", "alice", ["api"], eco="npm", sid=sid)
    memory.record_decision(T, "GHSA-yyyy-yyyy-yyyy", "not_affected", "dev tool only", "bob", ["payments"], sid=sid)
    memory.record_decision(T, "GHSA-yyyy-yyyy-yyyy", "accepted_risk", "no fix yet", "bob", [], sid=sid)
    doc = vex.build_vex(T, sid)
    assert doc["@context"].startswith("https://openvex.dev/ns") and doc["version"] == 1
    by_status = {s["status"]: s for s in doc["statements"]}
    assert set(by_status) == {"fixed", "not_affected", "affected"}
    assert by_status["not_affected"]["justification"] and by_status["not_affected"]["impact_statement"] == "dev tool only"
    assert by_status["affected"]["action_statement"].startswith("Risk accepted")
    assert by_status["fixed"]["vulnerability"]["name"] == "CVE-2000-0001"
    assert vex.build_vex(T, "someone-else")["statements"] == []           # another session exports nothing of ours
    memory.reset_session(T, sid)


def test_govulncheck_output_parses_into_reachability_levels():
    from blastradius import reach

    stream = "\n".join([
        '{"config": {"scanner_name": "govulncheck"}}',
        '{"osv": {"id": "GO-1", "aliases": ["CVE-1", "GHSA-a"]}}',
        '{"finding": {"osv": "GO-1", "fixed_version": "v1.2", "trace": ['
        '{"module": "m", "package": "m/p", "function": "Bad", "position": {"filename": "p.go", "line": 3}},'
        '{"module": "app", "package": "app", "function": "main", "position": {"filename": "main.go", "line": 9}}]}}',
        '{"finding": {"osv": "GO-2", "trace": [{"module": "m2", "package": "m2/q"}]}}',
        '{"finding": {"osv": "GO-3", "trace": [{"module": "m3"}]}}',
        '{"finding": {"osv": "GO-3", "trace": [{"module": "m3"}]}}',
    ])
    f = reach.parse(stream)
    assert f["GO-1"]["level"] == "called" and f["GO-1"]["ids"] == ["GO-1", "CVE-1", "GHSA-a"] and f["GO-1"]["fixed"] == "v1.2"
    assert f["GO-1"]["stack"][0].startswith("app.main") and "main.go:9" in f["GO-1"]["stack"][0]   # entry point first
    assert f["GO-2"]["level"] == "imported" and f["GO-2"]["stack"] == []
    assert f["GO-3"]["level"] == "required"


def test_function_level_reachability_demotes_or_confirms_priority():
    base = triage.run_triage(T, "CVE-2000-0001", record=False)
    assert base["priority"] == "P0" and base["services"][0]["reach"]["analyzed"] is False   # not analysed: no change
    db.write(T, "MATCH (s:Service {name:'api'}) SET s.reach_analyzed = true")
    db.write(T, """MATCH (s:Service {name:'api'}),(a:Advisory {id:'GHSA-xxxx-xxxx-xxxx'})
        MERGE (s)-[r:REACHES]->(a) SET r.level='imported', r.symbol='libB', r.stack=[]""")
    demoted = triage.run_triage(T, "CVE-2000-0001", record=False)
    assert demoted["verdict"] == "AFFECTED" and demoted["priority"] == "P2"            # verdict stays; urgency drops
    assert "no call path" in demoted["headline"]
    board = {a["id"]: a for a in triage.risk_board(T)["advisories"]}
    assert board["GHSA-xxxx-xxxx-xxxx"]["priority"] == "P2" and board["GHSA-xxxx-xxxx-xxxx"]["reach"] == "not_called"
    db.write(T, "MATCH (:Service {name:'api'})-[r:REACHES]->(:Advisory {id:'GHSA-xxxx-xxxx-xxxx'}) "
                "SET r.level='called', r.symbol='libB.Bad', r.stack=['api.main (main.go:1)', 'libB.Bad (b.go:2)']")
    called = triage.run_triage(T, "CVE-2000-0001", record=False)
    assert called["priority"] == "P0" and "actually called" in called["headline"]
    assert called["services"][0]["reach"]["stack"][0].startswith("api.main")
    db.write(T, "MATCH (:Service {name:'api'})-[r:REACHES]->() DELETE r")
    db.write(T, "MATCH (s:Service {name:'api'}) SET s.reach_analyzed = false")


def test_read_path_blocks_writes():
    for bad in ("MATCH (n) DETACH DELETE n", "CREATE (:X)", "MATCH (n) SET n.a=1"):
        with pytest.raises(UnsafeQuery):
            db.read(T, bad)
    # the same word inside a string literal is fine
    db.read(T, "MATCH (a:Advisory) WHERE a.summary = 'please DELETE me' RETURN a")


def test_tenant_isolation():
    other = "pytest_other"
    try:
        db.write(other, "CREATE (:Service {name:'secret'})")
        assert q.stats(T)["nodes"].get("Service") == 5
        names = {n["id"] for n in q.service_graph(T)[0]["nodes"]}
        assert "secret" not in names
    finally:
        db.graph(other).delete()

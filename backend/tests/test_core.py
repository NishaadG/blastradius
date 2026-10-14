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
    assert b["cases"][0]["reused"] >= 1 and b["playbooks"][0]["successes"] >= 1


def test_vex_precedent_flips_verdict_to_not_affected():
    r = triage.run_triage(T, "GHSA-yyyy-yyyy-yyyy")
    memory.record_decision(T, r["advisory"]["id"], "not_affected", "dev tool only", "bob", ["payments"])
    r2 = triage.run_triage(T, "GHSA-yyyy-yyyy-yyyy")
    assert r2["verdict"] == "NOT_AFFECTED" and r2["reason"] == "vex_precedent"


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

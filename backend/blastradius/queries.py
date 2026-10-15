"""Every query the product depends on. Each function returns (data, trace) where trace
records the exact Cypher + params + latency, so the UI can show 'the work'."""
import time

from . import db

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}


def _run(tenant, cypher, params=None):
    t0 = time.perf_counter()
    res = db.read(tenant, cypher, params)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    return res.result_set, {"cypher": " ".join(cypher.split()), "params": params or {}, "ms": ms,
                            "rows": len(res.result_set)}


def tenant_meta(tenant):
    """Title/repo and whether exposure could be determined (curated tenants discover it from deployment files)."""
    rows, _ = _run(tenant, "MATCH (m:Meta {k:'tenant'}) RETURN m.title, m.repo, m.exposure_known, m.kind, m.built_at")
    if not rows:
        return {"title": tenant, "repo": None, "exposure_known": True, "kind": "curated", "built_at": None}
    r = rows[0]
    return {"title": r[0], "repo": r[1], "exposure_known": bool(r[2]), "kind": r[3], "built_at": r[4]}


# ---------------------------------------------------------------- advisory lookup
Q_ADVISORY = """
MATCH (a:Advisory)
WHERE a.id = $ident OR a.cve = $ident
RETURN a.id, a.cve, a.summary, a.severity, a.published, a.url
UNION
MATCH (:Alias {name:$ident})-[:ALIAS_OF]->(a:Advisory)
RETURN a.id, a.cve, a.summary, a.severity, a.published, a.url
"""


def find_advisory(tenant, ident):
    rows, tr = _run(tenant, Q_ADVISORY, {"ident": ident.strip()})
    if not rows:
        return None, tr
    r = rows[0]
    return {"id": r[0], "cve": r[1], "summary": r[2], "severity": r[3], "published": r[4], "url": r[5]}, tr


# ---------------------------------------------------------------- core: path from service to vulnerable package
Q_PATHS = """
MATCH (a:Advisory {id:$id})-[e:AFFECTS]->(p:Package)
MATCH (s:Service)
WITH a, e, p, s, shortestPath((s)-[:DEPENDS_ON*1..15]->(p)) AS path
WHERE path IS NOT NULL
RETURN s.name, coalesce(s.exposed, false), p.key, p.name, p.version, coalesce(p.dev, false), e.fixed,
       length(path), [n IN nodes(path) | coalesce(n.key, n.name)]
ORDER BY length(path)
"""


def affected_paths(tenant, advisory_id):
    rows, tr = _run(tenant, Q_PATHS, {"id": advisory_id})
    out = [{"service": r[0], "exposed": r[1], "pkg_key": r[2], "pkg": r[3], "version": r[4], "dev": r[5],
            "fixed": r[6], "hops": r[7], "path": r[8]} for r in rows]
    return out, tr


# ---------------------------------------------------------------- blast radius via CALLS graph
Q_CALLERS = """
MATCH p = (c:Service)-[:CALLS*0..6]->(s:Service {name:$svc})
RETURN DISTINCT c.name, coalesce(c.exposed, false), min(length(p))
"""


def upstream_callers(tenant, service):
    rows, tr = _run(tenant, Q_CALLERS, {"svc": service})
    return [{"service": r[0], "exposed": r[1], "distance": r[2]} for r in rows if r[0] != service], tr


Q_CALL_PATH = """
MATCH (e:Service {exposed:true}), (s:Service {name:$svc})
WITH e, s, shortestPath((e)-[:CALLS*0..6]->(s)) AS path
WHERE path IS NOT NULL
RETURN e.name, [n IN nodes(path) | n.name]
ORDER BY length(path) LIMIT 1
"""


def exposure_path(tenant, service):
    rows, tr = _run(tenant, Q_CALL_PATH, {"svc": service})
    return (rows[0][1] if rows else None), tr


# ---------------------------------------------------------------- ownership (company brain)
Q_OWNERS = """
MATCH (o:Owner)-[:OWNS]->(s:Service {name:$svc})
RETURN o.name, coalesce(o.kind, 'person')
"""


def owners(tenant, service):
    rows, tr = _run(tenant, Q_OWNERS, {"svc": service})
    return [{"owner": r[0], "kind": r[1]} for r in rows], tr


Q_EXPERTS = """
MATCH (p:Owner)-[c:COMMITTED]->(s:Service {name:$svc})
RETURN p.name, coalesce(p.kind,'person'), c.count, c.last
ORDER BY c.count DESC LIMIT 8
"""


def experts(tenant, service):
    rows, tr = _run(tenant, Q_EXPERTS, {"svc": service})
    return [{"name": r[0], "kind": r[1], "commits": r[2], "last": r[3]} for r in rows], tr


Q_DECISIONS = """
MATCH (d:Decision)-[:DOCUMENTED_IN]->(k:Commit)
WHERE ($svc = '' OR d.service = $svc) AND ($term = '' OR toLower(d.text) CONTAINS toLower($term))
OPTIONAL MATCH (newer:Decision)-[:SUPERSEDES]->(d)
RETURN d.id, d.text, d.author, d.date, k.url, d.service, newer.id
ORDER BY d.date DESC LIMIT 8
"""


def decisions(tenant, service="", term=""):
    rows, tr = _run(tenant, Q_DECISIONS, {"svc": service or "", "term": term or ""})
    return [{"id": r[0], "text": r[1], "author": r[2], "date": r[3], "source": r[4], "service": r[5],
             "superseded_by": r[6]} for r in rows], tr


# ---------------------------------------------------------------- algorithms
Q_PAGERANK = """
CALL algo.pageRank('Service', 'CALLS') YIELD node, score
RETURN node.name, score ORDER BY score DESC
"""


def service_centrality(tenant):
    rows, tr = _run(tenant, Q_PAGERANK)
    return {r[0]: r[1] for r in rows}, tr


Q_FINDINGS = """
MATCH (a:Advisory)-[e:AFFECTS]->(p:Package)
MATCH (s:Service)
WITH a, e, p, s, shortestPath((s)-[:DEPENDS_ON*1..15]->(p)) AS path
WHERE path IS NOT NULL
RETURN a.id, a.cve, a.severity, a.summary, s.name, coalesce(s.exposed,false), p.name, p.version,
       coalesce(p.dev,false), e.fixed, length(path), a.first_seen
"""


def all_findings(tenant):
    rows, tr = _run(tenant, Q_FINDINGS)
    return [{"id": r[0], "cve": r[1], "severity": r[2], "summary": r[3], "service": r[4], "exposed": r[5],
             "pkg": r[6], "version": r[7], "dev": r[8], "fixed": r[9], "hops": r[10], "first_seen": r[11]} for r in rows], tr


# ---------------------------------------------------------------- package presence (for 'version outside range')
Q_PKG_PRESENT = """
MATCH (p:Package) WHERE toLower(p.name) = toLower($name) AND p.eco = $eco
OPTIONAL MATCH (s:Service)-[:DEPENDS_ON*1..15]->(p)
RETURN p.version, collect(DISTINCT s.name)
"""


def package_presence(tenant, eco, name):
    rows, tr = _run(tenant, Q_PKG_PRESENT, {"name": name, "eco": eco})
    return [{"version": r[0], "services": r[1]} for r in rows], tr


# ---------------------------------------------------------------- graph snapshot for the visualization
def service_graph(tenant):
    nodes, tr1 = _run(tenant, """MATCH (s:Service) RETURN s.name, coalesce(s.exposed,false), s.kind""")
    edges, tr2 = _run(tenant, """MATCH (a:Service)-[:CALLS]->(b:Service) RETURN a.name, b.name""")
    return ({"nodes": [{"id": r[0], "exposed": r[1], "kind": r[2]} for r in nodes],
             "edges": [{"source": r[0], "target": r[1]} for r in edges]}, [tr1, tr2])


def stats(tenant):
    rows, _ = _run(tenant, """MATCH (n) RETURN labels(n)[0], count(n)""")
    erows, _ = _run(tenant, """MATCH ()-[e]->() RETURN type(e), count(e)""")
    return {"nodes": {r[0]: r[1] for r in rows}, "edges": {r[0]: r[1] for r in erows}}

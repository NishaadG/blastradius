"""Build a tenant graph from real public lockfiles + OSV advisories.

    python -m blastradius.ingest otel boutique
"""
import sys
import time

import httpx

from . import db, osv
from .config import DATA_DIR
from .parsers import PARSERS
from .tenants import TENANTS

RAW = DATA_DIR / "raw"


def fetch(repo: str, branch: str, path: str) -> str | None:
    cache = RAW / repo.replace("/", "__") / path.replace("/", "__")
    if cache.exists():
        return cache.read_text(encoding="utf-8")
    r = httpx.get(f"https://raw.githubusercontent.com/{repo}/{branch}/{path}", timeout=60, follow_redirects=True)
    if r.status_code != 200:
        return None
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(r.text, encoding="utf-8")
    return r.text


def chunks(seq, n=1500):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def parse_codeowners(text: str, services: list[dict]):
    """-> [(owner, service_name)] ; owners 'org/team' become Team nodes, others Person handles."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        pattern, owners = parts[0], [o.lstrip("@") for o in parts[1:] if o.startswith("@")]
        for svc in services:
            sp = "/" + svc["path"]
            if pattern == "*" or sp.startswith(pattern.rstrip("/*")) or pattern.rstrip("/*").startswith(sp):
                out += [(o, svc["name"]) for o in owners]
    return out


def ingest(tenant: str):
    t = TENANTS[tenant]
    print(f"[{tenant}] fetching lockfiles from {t['repo']}")
    all_pkgs, svc_edges, pkg_edges = {}, [], []
    for svc in t["services"]:
        if svc["kind"] == "none":
            continue
        text = fetch(t["repo"], t["branch"], f"{svc['path']}/{svc['file']}")
        if not text:
            print(f"  ! missing {svc['path']}/{svc['file']}")
            continue
        pkgs, edges = PARSERS[svc["kind"]](text)
        all_pkgs.update(pkgs)
        for parent, child, dev in edges:
            if parent is None:
                svc_edges.append({"s": svc["name"], "b": child, "dev": dev,
                                  "indirect": bool(pkgs[child].get("indirect"))})
            else:
                pkg_edges.append({"a": parent, "b": child, "dev": dev})
        print(f"  {svc['name']}: {len(pkgs)} packages")
    print(f"[{tenant}] {len(all_pkgs)} unique packages -> OSV")
    hits = osv.query_packages(all_pkgs)
    vuln_ids = sorted({v for ids in hits.values() for v in ids})
    vulns = osv.fetch_vulns(vuln_ids)
    print(f"[{tenant}] {len(vulns)} advisories affect the dependency set")

    g = db.graph(tenant)
    try:
        g.delete()
    except Exception:
        pass
    for q in ("CREATE INDEX FOR (p:Package) ON (p.key)", "CREATE INDEX FOR (s:Service) ON (s.name)",
              "CREATE INDEX FOR (a:Advisory) ON (a.id)", "CREATE INDEX FOR (o:Owner) ON (o.name)",
              "CREATE INDEX FOR (c:Case) ON (c.id)"):
        try:
            db.write(tenant, q)
        except Exception as e:
            print("  index:", e)

    db.write(tenant, "MERGE (r:Repo {name:$n}) SET r.url=$u, r.title=$t",
             {"n": t["repo"], "u": f"https://github.com/{t['repo']}", "t": t["title"]})
    db.write(tenant, """UNWIND $rows AS r MERGE (s:Service {name:r.name})
        SET s.path=r.path, s.kind=r.kind, s.exposed=r.exposed
        WITH s MATCH (repo:Repo {name:$repo}) MERGE (repo)-[:CONTAINS]->(s)""",
             {"rows": [{"name": s["name"], "path": s["path"], "kind": s["kind"],
                        "exposed": bool(s.get("exposed"))} for s in t["services"]], "repo": t["repo"]})
    db.write(tenant, "UNWIND $rows AS r MATCH (a:Service {name:r.a}),(b:Service {name:r.b}) MERGE (a)-[:CALLS]->(b)",
             {"rows": [{"a": a, "b": b} for a, b in t["calls"]]})

    rows = [{"key": k, **{x: v for x, v in p.items() if x != "indirect"}} for k, p in all_pkgs.items()]
    for c in chunks(rows):
        db.write(tenant, """UNWIND $rows AS r MERGE (p:Package {key:r.key})
            SET p.eco=r.eco, p.name=r.name, p.version=r.version, p.dev=r.dev""", {"rows": c})
    for c in chunks(pkg_edges, 3000):
        db.write(tenant, """UNWIND $rows AS r MATCH (a:Package {key:r.a}),(b:Package {key:r.b})
            MERGE (a)-[e:DEPENDS_ON]->(b) SET e.dev=r.dev""", {"rows": c})
    for c in chunks(svc_edges):
        db.write(tenant, """UNWIND $rows AS r MATCH (s:Service {name:r.s}),(b:Package {key:r.b})
            MERGE (s)-[e:DEPENDS_ON]->(b) SET e.direct=true, e.dev=r.dev, e.indirect=r.indirect""", {"rows": c})

    adv_rows, aff_rows = [], []
    for vid, v in vulns.items():
        s = osv.summarize(v)
        adv_rows.append(s)
    for key, ids in hits.items():
        p = all_pkgs[key]
        for vid in ids:
            if vid in vulns:
                aff_rows.append({"id": vid, "key": key, "fixed": osv.fixed_version(vulns[vid], p["eco"], p["name"])})
    for c in chunks(adv_rows):
        db.write(tenant, """UNWIND $rows AS r MERGE (a:Advisory {id:r.id})
            SET a.cve=r.cve, a.summary=r.summary, a.severity=r.severity, a.published=r.published, a.url=r.url""",
                 {"rows": c})
    # alias lookup (CVE-xxxx / GHSA-xxxx -> OSV id) so users can query by any identifier
    alias_rows = [{"id": s["id"], "alias": al} for s in adv_rows for al in s["aliases"]]
    for c in chunks(alias_rows):
        db.write(tenant, "UNWIND $rows AS r MATCH (a:Advisory {id:r.id}) MERGE (x:Alias {name:r.alias}) MERGE (x)-[:ALIAS_OF]->(a)",
                 {"rows": c})
    for c in chunks(aff_rows):
        db.write(tenant, """UNWIND $rows AS r MATCH (a:Advisory {id:r.id}),(p:Package {key:r.key})
            MERGE (a)-[e:AFFECTS]->(p) SET e.fixed=r.fixed""", {"rows": c})

    co = fetch(t["repo"], t["branch"], t["codeowners"])
    if co:
        owned = parse_codeowners(co, t["services"])
        db.write(tenant, """UNWIND $rows AS r MATCH (s:Service {name:r.svc})
            MERGE (o:Owner {name:r.owner}) SET o.kind = CASE WHEN r.owner CONTAINS '/' THEN 'team' ELSE 'person' END
            MERGE (o)-[:OWNS]->(s)""", {"rows": [{"owner": o, "svc": s} for o, s in owned]})
        print(f"[{tenant}] {len(owned)} ownership edges from CODEOWNERS")
    n = db.read(tenant, "MATCH (n) RETURN count(n)").result_set[0][0]
    e = db.read(tenant, "MATCH ()-[e]->() RETURN count(e)").result_set[0][0]
    print(f"[{tenant}] graph ready: {n} nodes, {e} edges")


if __name__ == "__main__":
    t0 = time.time()
    for name in sys.argv[1:] or list(TENANTS):
        ingest(name)
    print(f"done in {time.time() - t0:.1f}s")

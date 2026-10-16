"""Build tenant graphs from public lockfiles + OSV advisories.

    python -m blastradius.ingest otel boutique          # curated tenants (reads the committed snapshot)
    python -m blastradius.ingest --repo owner/name      # any public GitHub repository
"""
import os
import re
import sys
import time
from typing import Callable

import httpx

from . import db, depsdev, discover, osv
from .config import cache_write_path, cached_path
from .parsers import LOCKFILES, PARSERS
from .tenants import TENANTS

Progress = Callable[[str], None]
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}$")
MAX_FILE_BYTES = 3_000_000
MAX_SERVICES = 15
MAX_PACKAGES = 20_000
SKIP_DIRS = ("node_modules/", "vendor/", "/test/", "/tests/", "testdata/", "/fixtures/", "/examples/", "/example/",
             "third_party/", ".git/", "/docs/")


class IngestError(Exception):
    """A user-facing failure (bad repo, rate limit, too large)."""


def _rel(repo: str, path: str) -> str:
    return f"raw/{repo.replace('/', '__')}/{path.replace('/', '__')}"


LOCAL_ROOT: dict[str, str] = {}  # pseudo-repo name -> checkout directory (CI mode reads the working tree, not GitHub)


def fetch(repo: str, ref: str, path: str) -> str | None:
    if repo in LOCAL_ROOT:
        root = os.path.realpath(LOCAL_ROOT[repo])
        f = os.path.realpath(os.path.join(root, path))
        if os.path.commonpath([root, f]) == root and os.path.isfile(f) and os.path.getsize(f) <= MAX_FILE_BYTES:
            with open(f, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        return None
    p = cached_path(_rel(repo, path))
    if p:
        return p.read_text(encoding="utf-8")
    r = httpx.get(f"https://raw.githubusercontent.com/{repo}/{ref}/{path}", timeout=30, follow_redirects=True)
    if r.status_code != 200 or len(r.content) > MAX_FILE_BYTES:
        return None
    cache_write_path(_rel(repo, path)).write_text(r.text, encoding="utf-8")
    return r.text


def chunks(seq, n=1500):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def parse_codeowners(text: str, services: list[dict]):
    """-> [(owner, service_name)] ; owners 'org/team' become team owners, others people."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        pattern, owners = parts[0], [o.lstrip("@") for o in parts[1:] if o.startswith("@")]
        for svc in services:
            sp = "/" + svc["path"].strip("/")
            if pattern == "*" or sp.startswith(pattern.rstrip("/*")) or pattern.rstrip("/*").startswith(sp):
                out += [(o, svc["name"]) for o in owners]
    return out


def _gh_headers():
    h = {"User-Agent": "blastradius", "Accept": "application/vnd.github+json"}
    if os.getenv("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    return h


def discover_repo(repo: str):
    """List a public repo's dependency manifests -> (services, truncated). Costs one GitHub API call."""
    if not REPO_RE.match(repo):
        raise IngestError("Use the form owner/name, for example open-telemetry/opentelemetry-demo.")
    r = httpx.get(f"https://api.github.com/repos/{repo}/git/trees/HEAD", params={"recursive": "1"},
                  headers=_gh_headers(), timeout=30)
    if r.status_code == 404:
        raise IngestError("Repository not found, or it is private. Only public repositories are supported.")
    if r.status_code in (403, 429):
        raise IngestError("GitHub rate limit reached for this server. Try again later, or run Blastradius locally.")
    r.raise_for_status()
    tree = r.json().get("tree", [])
    found = []
    for b in tree:
        if b.get("type") != "blob":
            continue
        base = b["path"].rsplit("/", 1)[-1]
        if base not in LOCKFILES or any(s in "/" + b["path"] for s in SKIP_DIRS):
            continue
        if b.get("size", 0) > MAX_FILE_BYTES:
            continue
        found.append(b["path"])
    found.sort(key=lambda p: (p.count("/"), p))
    services, used = [], set()
    for path in found[:MAX_SERVICES * 2]:
        d, _, base = path.rpartition("/")
        kind = LOCKFILES[base]
        name = d.rsplit("/", 1)[-1] if d else repo.split("/")[1]
        if name in used:
            name = f"{name}-{kind}"
        if name in used:
            continue
        used.add(name)
        services.append({"name": name, "path": d, "kind": kind, "file": base})
        if len(services) >= MAX_SERVICES:
            break
    if not services:
        raise IngestError("No supported dependency files found (package-lock.json, go.mod, requirements.txt, pom.xml, build.gradle, Cargo.lock).")
    return services, r.json().get("truncated", False)


def write_advisories(tenant: str, all_pkgs: dict, hits: dict, vulns: dict, first_seen: int | None = None):
    """Idempotently write advisories, their aliases and AFFECTS edges. `first_seen` marks advisories a later rescan found."""
    adv_rows, aff_rows, alias_rows = [], [], []
    for vid, v in vulns.items():
        s = osv.summarize(v)
        s["first_seen"] = first_seen
        adv_rows.append(s)
        alias_rows += [{"id": s["id"], "alias": al} for al in s["aliases"]]
    for key, ids in hits.items():
        p = all_pkgs[key]
        for vid in ids:
            if vid in vulns:
                aff_rows.append({"id": vid, "key": key, "fixed": osv.fixed_version(vulns[vid], p["eco"], p["name"])})
    for c in chunks(adv_rows):
        db.write(tenant, """UNWIND $rows AS r MERGE (a:Advisory {id:r.id})
            SET a.cve=r.cve, a.summary=r.summary, a.severity=r.severity, a.published=r.published, a.url=r.url,
                a.first_seen = coalesce(a.first_seen, r.first_seen)""", {"rows": c})
    for c in chunks(alias_rows):
        db.write(tenant, "UNWIND $rows AS r MATCH (a:Advisory {id:r.id}) MERGE (x:Alias {name:r.alias}) MERGE (x)-[:ALIAS_OF]->(a)",
                 {"rows": c})
    for c in chunks(aff_rows):
        db.write(tenant, """UNWIND $rows AS r MATCH (a:Advisory {id:r.id}),(p:Package {key:r.key})
            MERGE (a)-[e:AFFECTS]->(p) SET e.fixed=r.fixed""", {"rows": c})


def build_graph(tenant: str, meta: dict, services: list[dict], calls: set, exposed: set, exposure_known: bool,
                ref: str, say: Progress = print):
    repo = meta["repo"]
    all_pkgs, svc_edges, pkg_edges = {}, [], []
    for svc in services:
        if svc["kind"] == "none":
            continue
        text = fetch(repo, ref, f"{svc['path']}/{svc['file']}".lstrip("/"))
        if not text:
            say(f"missing {svc['path']}/{svc['file']}")
            continue
        pkgs, edges = PARSERS[svc["kind"]](text)
        if meta.get("kind") == "byo" and svc["kind"] in depsdev.EXPAND_KINDS and pkgs:
            n_direct = min(len(pkgs), depsdev.MAX_DIRECT)
            extra, new_edges, resolved = depsdev.expand(pkgs)
            pkgs = {**extra, **pkgs}
            edges = list(edges) + [(a, b, pkgs[b]["dev"]) for a, b in new_edges]
            say(f"{svc['name']}: resolved {resolved}/{n_direct} direct dependencies, +{len(extra)} transitive packages")
        all_pkgs.update(pkgs)
        for parent, child, dev in edges:
            if parent is None:
                svc_edges.append({"s": svc["name"], "b": child, "dev": dev, "indirect": bool(pkgs[child].get("indirect"))})
            else:
                pkg_edges.append({"a": parent, "b": child, "dev": dev})
        say(f"{svc['name']}: {len(pkgs)} packages")
        if len(all_pkgs) > MAX_PACKAGES:
            raise IngestError(f"Too many packages ({len(all_pkgs)}+). Limit is {MAX_PACKAGES} for a hosted demo; run locally for larger repos.")
    say(f"querying OSV for {len(all_pkgs)} packages")
    hits = osv.query_packages(all_pkgs)
    vuln_ids = sorted({v for ids in hits.values() for v in ids})
    vulns = osv.fetch_vulns(vuln_ids)
    say(f"{len(vulns)} advisories affect this dependency set")

    g = db.graph(tenant)
    try:
        g.delete()
    except Exception:
        pass
    for q in ("CREATE INDEX FOR (p:Package) ON (p.key)", "CREATE INDEX FOR (s:Service) ON (s.name)",
              "CREATE INDEX FOR (a:Advisory) ON (a.id)", "CREATE INDEX FOR (o:Owner) ON (o.name)",
              "CREATE INDEX FOR (c:Case) ON (c.id)", "CREATE INDEX FOR (x:Alias) ON (x.name)"):
        try:
            db.write(tenant, q)
        except Exception as e:  # an index failing must not fail the build, but must not be silent
            say(f"index warning: {e}")

    db.write(tenant, "MERGE (m:Meta {k:'tenant'}) SET m.title=$t, m.repo=$r, m.exposure_known=$ek, m.kind=$kind, m.built_at=$ts",
             {"t": meta["title"], "r": repo, "ek": exposure_known, "kind": meta.get("kind", "curated"), "ts": int(time.time() * 1000)})
    db.write(tenant, "MERGE (r:Repo {name:$n}) SET r.url=$u, r.title=$t",
             {"n": repo, "u": f"https://github.com/{repo}", "t": meta["title"]})
    db.write(tenant, """UNWIND $rows AS r MERGE (s:Service {name:r.name})
        SET s.path=r.path, s.kind=r.kind, s.exposed=r.exposed
        WITH s MATCH (repo:Repo {name:$repo}) MERGE (repo)-[:CONTAINS]->(s)""",
             {"rows": [{"name": s["name"], "path": s["path"], "kind": s["kind"], "exposed": s["name"] in exposed}
                       for s in services], "repo": repo})
    if calls:
        db.write(tenant, "UNWIND $rows AS r MATCH (a:Service {name:r.a}),(b:Service {name:r.b}) MERGE (a)-[:CALLS]->(b)",
                 {"rows": [{"a": a, "b": b} for a, b in sorted(calls)]})

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

    write_advisories(tenant, all_pkgs, hits, vulns)

    for path in (meta.get("codeowners"), ".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        co = fetch(repo, ref, path) if path else None
        if co:
            owned = parse_codeowners(co, services)
            if owned:
                db.write(tenant, """UNWIND $rows AS r MATCH (s:Service {name:r.svc})
                    MERGE (o:Owner {name:r.owner}) SET o.kind = CASE WHEN r.owner CONTAINS '/' THEN 'team' ELSE 'person' END
                    MERGE (o)-[:OWNS]->(s)""", {"rows": [{"owner": o, "svc": s} for o, s in owned]})
                say(f"{len(owned)} ownership edges from CODEOWNERS")
            break
    n = db.read(tenant, "MATCH (n) RETURN count(n)").result_set[0][0]
    e = db.read(tenant, "MATCH ()-[e]->() RETURN count(e)").result_set[0][0]
    say(f"graph ready: {n} nodes, {e} edges")


def curated_graph_inputs(tenant: str):
    """Read the discovery files and derive the call graph + exposure. -> (calls, exposed)."""
    t = TENANTS[tenant]
    names = {s["name"] for s in t["services"]}
    texts = [x for x in (fetch(t["repo"], t["branch"], f) for f in t["discover"]["files"]) if x]
    if t["discover"]["kind"] == "compose":
        dotenv = discover.parse_dotenv(fetch(t["repo"], t["branch"], t["discover"].get("dotenv", ".env")))
        calls, exposed = discover.compose(texts, names, dotenv)
    else:
        calls, exposed = discover.kubernetes(texts, names)
    calls |= set(map(tuple, t["supplement_calls"]))
    exposed |= set(t["supplement_exposed"])
    return calls, exposed


def ingest(tenant: str, say: Progress = print):
    t = TENANTS[tenant]
    calls, exposed = curated_graph_inputs(tenant)
    say(f"[{tenant}] discovered {len(calls)} service calls and {len(exposed)} exposed service(s) from deployment files")
    build_graph(tenant, {"title": t["title"], "repo": t["repo"], "codeowners": t["codeowners"], "kind": "curated"},
                t["services"], calls, exposed, True, t["branch"], say)


def tenant_id_for(repo: str) -> str:
    return "gh-" + re.sub(r"[^a-z0-9]+", "-", repo.lower()).strip("-")


def ingest_repo(repo: str, say: Progress = print) -> str:
    """Analyze any public repo into its own tenant graph. Exposure is unknown (no deployment topology)."""
    services, truncated = discover_repo(repo)
    if truncated:
        say("repository tree was truncated by GitHub; analyzing the manifests that were listed")
    say(f"found {len(services)} service(s): " + ", ".join(s["name"] for s in services))
    tenant = tenant_id_for(repo)
    build_graph(tenant, {"title": repo, "repo": repo, "kind": "byo"}, services, set(), set(), False, "HEAD", say)
    return tenant


if __name__ == "__main__":
    t0 = time.time()
    args = sys.argv[1:]
    if args[:1] == ["--repo"]:
        print(ingest_repo(args[1]))
    else:
        for name in args or list(TENANTS):
            ingest(name)
    print(f"done in {time.time() - t0:.1f}s")

"""Company-brain ingestion (Track 3): who knows what, and why things are the way they are.

Public GitHub commit history becomes:
  (:Owner{kind:'person'|'bot'})-[:COMMITTED {count,last}]->(:Service)   expertise (whole service directory)
  (:Commit)-[:TOUCHED]->(:Service)                                      source documents
  (:Decision)-[:DOCUMENTED_IN]->(:Commit), (:Decision)-[:CONCERNS]->(:Package|:Service)
  (:Decision)-[:SUPERSEDES]->(:Decision)                                knowledge currency
Only public repo metadata (handle, commit message, date, url) is used.

    GITHUB_TOKEN=... python -m blastradius.brain otel boutique     # token only lifts the 60 req/h anonymous limit
"""
import json
import os
import re
import sys
import time

import httpx

from . import db
from .config import cache_write_path, cached_path
from .tenants import TENANTS

DECISION_RE = re.compile(r"\b(pin|pinned|downgrade|revert|ignore|workaround|security|cve|vulnerab|fix|upgrade|bump|deprecat|remove|drop)\w*", re.I)
BOT_RE = re.compile(r"(\[bot\]|-bot$|^renovate|^dependabot|github-actions)", re.I)
STRONG_RE = re.compile(r"\b(pin|pinned|downgrade|revert|ignore|workaround|security|cve|vulnerab|deprecat|drop)\w*", re.I)


def gh_commits(repo: str, path: str, per_page: int = 100):
    rel = "commits/" + repo.replace("/", "__") + "__" + path.replace("/", "__") + ".json"
    p = cached_path(rel)
    if p:
        return json.loads(p.read_text(encoding="utf-8"))
    headers = {"User-Agent": "blastradius", "Accept": "application/vnd.github+json"}
    if os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    r = httpx.get(f"https://api.github.com/repos/{repo}/commits", params={"path": path, "per_page": per_page},
                  headers=headers, timeout=60)
    if r.status_code != 200:
        print(f"  ! {repo}:{path} -> HTTP {r.status_code} (rate limit? set GITHUB_TOKEN)")
        return None
    data = [{"sha": c["sha"], "msg": c["commit"]["message"].split("\n", 1)[0],
             "author": (c.get("author") or {}).get("login") or c["commit"]["author"]["name"],
             "date": c["commit"]["author"]["date"], "url": c["html_url"]} for c in r.json()]
    cache_write_path(rel).write_text(json.dumps(data), encoding="utf-8")
    return data


def _expertise(tenant: str, svc: dict, commits: list[dict]):
    counts: dict[str, list] = {}
    for c in commits:
        e = counts.setdefault(c["author"], [0, ""])
        e[0] += 1
        e[1] = max(e[1], c["date"])
    db.write(tenant, """MATCH (s:Service {name:$svc}) UNWIND $rows AS r
        MERGE (p:Owner {name:r.a}) ON CREATE SET p.kind = CASE WHEN r.bot THEN 'bot' ELSE 'person' END
        MERGE (p)-[e:COMMITTED]->(s) SET e.count=r.n, e.last=r.last""",
             {"svc": svc["name"], "rows": [{"a": a, "n": v[0], "last": v[1], "bot": bool(BOT_RE.search(a))}
                                           for a, v in counts.items()]})


def _decisions(tenant: str, svc: dict, commits: list[dict], pkg_names: dict[str, str]) -> int:
    db.write(tenant, """MATCH (s:Service {name:$svc}) UNWIND $rows AS c
        MERGE (k:Commit {sha:c.sha}) SET k.msg=c.msg, k.author=c.author, k.date=c.date, k.url=c.url
        MERGE (k)-[:TOUCHED]->(s)""", {"svc": svc["name"], "rows": commits})
    decs = []
    for c in commits:
        if DECISION_RE.search(c["msg"]) and (STRONG_RE.search(c["msg"]) or any(n in c["msg"].lower() for n in pkg_names if len(n) > 4)):
            words = set(re.findall(r"[@\w./-]+", c["msg"].lower()))
            about = sorted({pkg_names[w] for w in words if w in pkg_names and len(w) > 3})
            decs.append({"id": "dec-" + c["sha"][:10], "sha": c["sha"], "text": c["msg"], "date": c["date"],
                         "author": c["author"], "about": about})
    decs.sort(key=lambda d: d["date"])
    if not decs:
        return 0
    db.write(tenant, """MATCH (s:Service {name:$svc}) UNWIND $rows AS d
        MATCH (k:Commit {sha:d.sha})
        MERGE (x:Decision {id:d.id}) SET x.text=d.text, x.date=d.date, x.author=d.author, x.service=$svc
        MERGE (x)-[:DOCUMENTED_IN]->(k) MERGE (x)-[:CONCERNS]->(s)""", {"svc": svc["name"], "rows": decs})
    db.write(tenant, """UNWIND $rows AS d MATCH (x:Decision {id:d.id})
        UNWIND d.about AS n MATCH (p:Package {name:n}) MERGE (x)-[:CONCERNS]->(p)""", {"rows": decs})
    last_by_pkg: dict[str, str] = {}
    sup = []
    for d in decs:  # a newer decision supersedes the previous one about the same package in the same service
        for n in d["about"]:
            if n in last_by_pkg and last_by_pkg[n] != d["id"]:
                sup.append({"new": d["id"], "old": last_by_pkg[n]})
            last_by_pkg[n] = d["id"]
    if sup:
        db.write(tenant, "UNWIND $rows AS r MATCH (a:Decision {id:r.new}),(b:Decision {id:r.old}) MERGE (a)-[:SUPERSEDES]->(b)",
                 {"rows": sup})
    return len(decs)


def ingest(tenant: str):
    t = TENANTS[tenant]
    pkg_names = {r[0].lower(): r[0] for r in db.read(tenant, "MATCH (p:Package) RETURN DISTINCT p.name").result_set}
    n_commits = n_dec = 0
    for svc in t["services"]:
        # expertise: everyone who touched the service directory; decisions: changes to its dependency manifest
        dir_commits = gh_commits(t["repo"], svc["path"])
        if dir_commits:
            _expertise(tenant, svc, dir_commits)
            n_commits += len(dir_commits)
        if svc["kind"] != "none":
            man = gh_commits(t["repo"], f"{svc['path']}/{svc['file']}")
            if man:
                n_dec += _decisions(tenant, svc, man, pkg_names)
        time.sleep(0.1)
    print(f"[{tenant}] {n_commits} directory commits, {n_dec} dependency decisions")


if __name__ == "__main__":
    for name in sys.argv[1:] or list(TENANTS):
        ingest(name)

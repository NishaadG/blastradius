"""Function-level reachability for Go services, from the official `govulncheck` call-graph analysis.

A vulnerable *package* in a dependency tree is not the same as a vulnerable *function that your code can call*.
govulncheck answers the second question. We run it (in a Go container, so no local toolchain is needed), keep its raw
JSON in the committed snapshot, and bring the result into the graph:

  (Service)-[:REACHES {level, symbol, stack}]->(Advisory)      level: called | imported | required
  (Service {reach_analyzed: true})

    python -m blastradius.reach collect boutique otel    # needs Docker + network; writes snapshot/reach/
    python -m blastradius.reach ingest  boutique otel    # offline: snapshot -> graph (build.py calls this)

called   = govulncheck found a call path from your code to the vulnerable function
imported = your code imports the vulnerable package but no call path to the vulnerable function was found
required = the vulnerable module is only in your dependency graph
"""
import json
import subprocess
import sys
from pathlib import Path

from . import db
from .config import SNAPSHOT_DIR
from .tenants import TENANTS

RANK = {"required": 0, "imported": 1, "called": 2}
IMAGE = "golang:latest"

SCRIPT = r"""
set -u
go install golang.org/x/vuln/cmd/govulncheck@latest >/dev/null 2>&1
git clone --depth 1 https://github.com/$REPO /src >/dev/null 2>&1
govulncheck -version > /out/_version.txt 2>&1 || true
for d in $DIRS; do
  name=$(echo "$d" | tr / _)
  (cd /src/$d && govulncheck -format json ./... > /out/$name.json 2>/out/$name.err) || true
done
"""


def reach_dir(tenant: str) -> Path:
    return SNAPSHOT_DIR / "reach" / tenant


def go_services(tenant: str):
    return [s for s in TENANTS[tenant]["services"] if s["kind"] == "gomod"]


def collect(tenant: str):
    t = TENANTS[tenant]
    out = reach_dir(tenant)
    out.mkdir(parents=True, exist_ok=True)
    dirs = " ".join(s["path"] for s in go_services(tenant))
    print(f"[{tenant}] running govulncheck on: {dirs}")
    subprocess.run(["docker", "run", "--rm", "-e", f"REPO={t['repo']}", "-e", f"DIRS={dirs}",
                    "-v", f"{out}:/out", IMAGE, "sh", "-c", SCRIPT], check=True)
    compact(tenant)


def compact(tenant: str):
    """Keep only the findings (a few KB) instead of govulncheck's ~1 MB raw stream, so the snapshot stays small."""
    d = reach_dir(tenant)
    version = (d / "_version.txt").read_text(encoding="utf-8").strip() if (d / "_version.txt").exists() else ""
    n = 0
    for raw in sorted(d.glob("*.json")):
        if raw.name.endswith(".reach.json"):
            continue
        findings = parse(raw.read_text(encoding="utf-8"))
        (d / (raw.stem + ".reach.json")).write_text(json.dumps({"tool": version, "findings": findings}, indent=1), encoding="utf-8")
        raw.unlink()
        raw.with_suffix(".err").unlink(missing_ok=True)
        n += 1
    print(f"[{tenant}] compacted {n} govulncheck result file(s)")


def parse(text: str) -> dict[str, dict]:
    """govulncheck JSON stream -> {osv id: {level, symbol, stack, ids, fixed}} keeping the strongest finding per id."""
    dec, i, msgs = json.JSONDecoder(), 0, []
    text = text.strip()
    while i < len(text):
        obj, j = dec.raw_decode(text, i)
        msgs.append(obj)
        i = j
        while i < len(text) and text[i].isspace():
            i += 1
    aliases = {m["osv"]["id"]: [m["osv"]["id"]] + list(m["osv"].get("aliases", [])) for m in msgs if "osv" in m}
    out: dict[str, dict] = {}
    for m in msgs:
        f = m.get("finding")
        if not f or not f.get("trace"):
            continue
        tr = f["trace"]
        head = tr[0]
        level = "called" if head.get("function") else "imported" if head.get("package") else "required"

        def fmt(fr):
            where = fr.get("position") or {}
            name = ".".join(x for x in (fr.get("package", "").rsplit("/", 1)[-1], fr.get("receiver", "").lstrip("*").rsplit(".", 1)[-1], fr.get("function")) if x)
            loc = f" ({where['filename']}:{where['line']})" if where.get("filename") else ""
            return (name or fr.get("module", "?")) + loc

        stack = [fmt(fr) for fr in reversed(tr)] if level == "called" else []
        symbol = fmt(head) if level == "called" else (head.get("package") or head.get("module"))
        cur = out.get(f["osv"])
        if cur is None or RANK[level] > RANK[cur["level"]]:
            out[f["osv"]] = {"level": level, "symbol": symbol, "stack": stack[:12], "ids": aliases.get(f["osv"], [f["osv"]]),
                             "fixed": f.get("fixed_version")}
    return out


def ingest(tenant: str, say=print) -> int:
    d = reach_dir(tenant)
    n = 0
    for s in go_services(tenant):
        p = d / (s["path"].replace("/", "_") + ".reach.json")
        if not p.exists():
            continue
        findings = json.loads(p.read_text(encoding="utf-8"))["findings"]
        db.write(tenant, "MATCH (s:Service {name:$svc}) SET s.reach_analyzed = true", {"svc": s["name"]})
        for osv_id, f in findings.items():
            params = {"svc": s["name"], "ids": f["ids"], "level": f["level"], "symbol": f["symbol"],
                      "stack": f["stack"], "fixed": f["fixed"]}
            # an advisory in the graph can be known by its Go id, its CVE, or via an alias node
            link = "MERGE (s)-[r:REACHES]->(a) SET r.level=$level, r.symbol=$symbol, r.stack=$stack, r.fixed=$fixed"
            db.write(tenant, f"MATCH (s:Service {{name:$svc}}) MATCH (a:Advisory) WHERE a.id IN $ids OR a.cve IN $ids {link}", params)
            db.write(tenant, f"MATCH (s:Service {{name:$svc}}) MATCH (x:Alias)-[:ALIAS_OF]->(a:Advisory) WHERE x.name IN $ids {link}", params)
            n += 1
    say(f"[{tenant}] reachability: {n} govulncheck findings linked to advisories")
    return n


if __name__ == "__main__":
    mode, names = sys.argv[1], sys.argv[2:] or list(TENANTS)
    for t in names:
        (collect if mode == "collect" else ingest)(t)


"""CI gate: analyse the checkout you are standing in and fail the build on new serious findings.

    python -m blastradius.ci --path . --fail-on P0 --sarif blastradius.sarif
    python -m blastradius.ci --path . --baseline ../base-checkout     # only findings the change introduces

Same pipeline as the web app (manifests -> FalkorDB graph -> OSV -> deterministic judge), read from the local working
tree. Exposure is unknown in this mode, so serious advisories on production dependencies are ranked as exposed.
Exit code 1 when a finding at or above --fail-on is present (and, with --baseline, new relative to the baseline).
"""
import argparse
import json
import os
import sys

from . import ingest, triage
from .parsers import LOCKFILES

ORDER = {"P0": 0, "P1": 1, "P2": 2, "DEV": 3}


def discover_local(root: str, name: str):
    found = []
    for dirpath, dirs, files in os.walk(root):
        rel = os.path.relpath(dirpath, root).replace("\\", "/")
        rel = "" if rel == "." else rel
        dirs[:] = [d for d in dirs if d not in ("node_modules", "vendor", ".git", "testdata", "fixtures", "examples")]
        for f in files:
            if f in LOCKFILES and not any(x in "/" + rel + "/" for x in ("/test/", "/tests/", "/docs/", "/third_party/")):
                found.append((rel, f))
    found.sort(key=lambda t: (t[0].count("/"), t))
    services, used = [], set()
    for d, f in found[:ingest.MAX_SERVICES]:
        n = d.rsplit("/", 1)[-1] if d else name
        n = n if n not in used else f"{n}-{LOCKFILES[f]}"
        if n in used:
            continue
        used.add(n)
        services.append({"name": n, "path": d, "kind": LOCKFILES[f], "file": f})
    return services


def analyse(path: str, tenant: str, say=print) -> tuple[dict, list[dict]]:
    root = os.path.abspath(path)
    repo = f"local/{tenant}"
    ingest.LOCAL_ROOT[repo] = root
    services = discover_local(root, os.path.basename(root) or "app")
    if not services:
        raise SystemExit(f"no supported dependency files under {root}")
    say(f"{tenant}: {len(services)} manifest(s): " + ", ".join(f"{s['path'] or '.'}/{s['file']}" for s in services))
    ingest.build_graph(tenant, {"title": repo, "repo": repo, "kind": "byo"}, services, set(), set(), False, "HEAD", say)
    return triage.risk_board(tenant), services


def sarif(items: list[dict], services: list[dict]) -> dict:
    by_name = {s["name"]: s for s in services}
    rules, results = {}, []
    for a in items:
        rid = a["cve"] or a["id"]
        rules[rid] = {"id": rid, "shortDescription": {"text": a["summary"][:200] or rid},
                      "helpUri": f"https://osv.dev/vulnerability/{a['id']}",
                      "properties": {"severity": a["severity"], "priority": a["priority"]}}
        for svc in a["services"]:
            s = by_name.get(svc, {})
            uri = f"{s.get('path', '')}/{s.get('file', '')}".lstrip("/")
            fix = f" Fixed in {', '.join(a['fixed'])}." if a["fixed"] else ""
            results.append({"ruleId": rid, "level": "error" if a["priority"] in ("P0", "P1") else "warning",
                            "message": {"text": f"{a['priority']} {a['severity']}: {', '.join(a['packages'][:3])} in {svc}.{fix}"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri or "."},
                                                                "region": {"startLine": 1}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "Blastradius", "informationUri": "https://github.com/NishaadG/blastradius",
                                          "rules": list(rules.values())}}, "results": results}]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="blastradius.ci")
    ap.add_argument("--path", default=".")
    ap.add_argument("--baseline", help="checkout of the base branch; only advisories absent there can fail the build")
    ap.add_argument("--fail-on", default="P0", choices=["P0", "P1", "P2", "never"])
    ap.add_argument("--sarif")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--summary", help="write a markdown summary here (e.g. $GITHUB_STEP_SUMMARY)")
    a = ap.parse_args(argv)
    log = lambda m: print(m, file=sys.stderr)

    board, services = analyse(a.path, "ci-head", log)
    items = [x for x in board["advisories"] if x["priority"] != "DEV"]
    known = set()
    if a.baseline:
        base, _ = analyse(a.baseline, "ci-base", log)
        known = {x["id"] for x in base["advisories"]}
        for x in items:
            x["introduced"] = x["id"] not in known
    gating = [x for x in items if (not a.baseline or x["introduced"])]
    bad = [x for x in gating if a.fail_on != "never" and ORDER[x["priority"]] <= ORDER[a.fail_on]]

    if a.sarif:
        with open(a.sarif, "w", encoding="utf-8") as f:
            json.dump(sarif(items, services), f, indent=1)
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as f:
            json.dump({"summary": board["summary"], "advisories": items, "failing": [x["id"] for x in bad]}, f, indent=1)

    scope = "introduced by this change" if a.baseline else "found"
    lines = [f"Blastradius: {len(gating)} advisories {scope} ({', '.join(f'{k} {v}' for k, v in board['summary'].items() if k != 'DEV')})"]
    for x in gating[:15]:
        lines.append(f"  {x['priority']:>3} {x['severity']:<9} {x['cve'] or x['id']}  {', '.join(x['packages'][:2])}"
                     + (f"  fix: {', '.join(x['fixed'])}" if x["fixed"] else ""))
    print("\n".join(lines))
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as f:
            f.write("### Blastradius\n\n" + f"{len(bad)} blocking, {len(gating)} {scope}.\n\n| Priority | Advisory | Package | Fix |\n|---|---|---|---|\n")
            for x in gating[:25]:
                f.write(f"| {x['priority']} | [{x['cve'] or x['id']}](https://osv.dev/vulnerability/{x['id']}) | {x['packages'][0] if x['packages'] else ''} | {', '.join(x['fixed']) or '-'} |\n")
    if bad:
        print(f"FAIL: {len(bad)} finding(s) at or above {a.fail_on}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

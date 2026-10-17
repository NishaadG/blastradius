"""Evaluation: does the graph answer the same as an independent computation from raw data?

Ground truth is derived WITHOUT FalkorDB: lockfiles parsed from the cached raw files, OSV results from the
cache, the call graph and exposure discovered from the projects' deployment files, owners from CODEOWNERS. Each check
compares that to the answer the graph-backed product gives. One extra check compares *discovery itself* against the
hand-written call lists from the projects' docs.

    python -m evals.run            # writes EVALS.md at repo root, exit 1 on any failure
"""
import sys
from collections import deque
from pathlib import Path

from blastradius import config, db, depsdev, ingest as ing, memory, osv, queries as q, triage
from blastradius.parsers import PARSERS
from blastradius.tenants import TENANTS

results: list[tuple[str, str, bool, str]] = []


def check(group: str, name: str, ok: bool, detail: str = ""):
    results.append((group, name, bool(ok), detail))


def load_truth(tenant):
    t = TENANTS[tenant]
    svc_pkgs, svc_edges, dev_of = {}, {}, {}
    for s in t["services"]:
        if s["kind"] == "none":
            continue
        f = config.cached_path(ing._rel(t["repo"], f"{s['path']}/{s['file']}"))
        pk, ed = PARSERS[s["kind"]](f.read_text(encoding="utf-8"))
        if t.get("expand") and s["kind"] in depsdev.EXPAND_KINDS and pk:  # same transitive resolution the build applies (cached deps.dev data)
            extra, new_edges, _ = depsdev.expand(pk)
            pk = {**extra, **pk}
            ed = list(ed) + [(a, b, pk[b]["dev"]) for a, b in new_edges]
        svc_pkgs[s["name"]] = set(pk)
        svc_edges[s["name"]] = {(a, b) for a, b, _ in ed if a is not None} | {(s["name"], b) for a, b, _ in ed if a is None}
        dev_of[s["name"]] = {k for k, v in pk.items() if v["dev"]}
    cache = osv._load()
    tenant_pkgs = set().union(*svc_pkgs.values())  # the OSV cache is shared across tenants: scope to this one
    affected = {}  # advisory id -> set(pkg keys)
    for key, ids in cache["queries"].items():
        if key not in tenant_pkgs:
            continue
        for vid in ids:
            affected.setdefault(vid, set()).add(key)
    calls, exposed = ing.curated_graph_inputs(tenant)
    return t, svc_pkgs, svc_edges, dev_of, affected, calls, exposed


def exposure_truth(exposed, calls, service):
    adj = {}
    for a, b in calls:
        adj.setdefault(a, []).append(b)
    dist = {e: 0 for e in exposed}
    dq = deque(exposed)
    while dq:
        x = dq.popleft()
        for y in adj.get(x, []):
            if y not in dist:
                dist[y] = dist[x] + 1
                dq.append(y)
    return dist.get(service)


def eval_tenant(tenant):
    t, svc_pkgs, svc_edges, dev_of, affected, calls, exposed = load_truth(tenant)
    all_svcs = {s["name"] for s in t["services"]}
    adv_ids = [r[0] for r in db.read(tenant, "MATCH (a:Advisory) RETURN a.id").result_set]
    check(f"{tenant}/coverage", "every OSV advisory for this tenant's packages is in the graph",
          set(adv_ids) == set(affected), f"{len(adv_ids)} vs {len(affected)}")
    bad_services = bad_paths = bad_verdict = 0
    for vid in adv_ids:
        exp_svcs = {s for s, pk in svc_pkgs.items() if pk & affected[vid]}
        paths, _ = q.affected_paths(tenant, vid)
        got = {p["service"] for p in paths}
        if got != exp_svcs:
            bad_services += 1
        for p in paths:
            hops = list(zip(p["path"], p["path"][1:]))
            if p["path"][0] != p["service"] or not all(h in svc_edges[p["service"]] for h in hops) or p["path"][-1] not in affected[vid]:
                bad_paths += 1
        exp_prod = {s for s in exp_svcs if affected[vid] & (svc_pkgs[s] - dev_of[s])}
        res = triage.run_triage(tenant, vid, record=False)
        exp_verdict = "AFFECTED" if exp_prod else ("NEEDS_HUMAN" if exp_svcs else "NOT_AFFECTED")
        if res["verdict"] != exp_verdict:
            bad_verdict += 1
    n = len(adv_ids)
    check(f"{tenant}/affected-services", f"affected service set equals independent computation for {n} advisories", bad_services == 0, f"{bad_services} mismatches")
    check(f"{tenant}/path-validity", "every returned path is a real chain of lockfile edges ending at an affected package", bad_paths == 0, f"{bad_paths} invalid")
    check(f"{tenant}/verdicts", f"deterministic verdict equals independent rule for {n} advisories", bad_verdict == 0, f"{bad_verdict} mismatches")

    bad_exp = 0
    for s in all_svcs:
        ep, _ = q.exposure_path(tenant, s)
        truth = exposure_truth(exposed, calls, s)
        got = None if ep is None else len(ep) - 1
        if got != truth:
            bad_exp += 1
    check(f"{tenant}/exposure", f"internet-exposure distance matches BFS over discovered topology for {len(all_svcs)} services", bad_exp == 0, f"{bad_exp} mismatches")

    graph_calls = {(r[0], r[1]) for r in db.read(tenant, "MATCH (a:Service)-[:CALLS]->(b:Service) RETURN a.name, b.name").result_set}
    check(f"{tenant}/call-graph", f"graph stores exactly the {len(calls)} discovered service calls", graph_calls == set(calls), f"{len(graph_calls)} in graph")

    ref = set(map(tuple, t["reference_calls"]))
    found = ref & set(calls)
    recall = len(found) / len(ref)
    extra = len(set(calls) - ref)
    check(f"{tenant}/discovery-vs-docs", f"discovery recovers the hand-written call list from the project docs (recall {recall:.0%}); {extra} additional call(s) found only in deployment files",
          recall >= 0.85, f"missing: {sorted(ref - found)}")

    co = ing.fetch(t["repo"], t["branch"], t["codeowners"])
    truth_owned = {}
    for o, s in ing.parse_codeowners(co, t["services"]):
        truth_owned.setdefault(s, set()).add(o)
    bad_own = sum(1 for s in all_svcs if {o["owner"] for o in q.owners(tenant, s)[0]} != truth_owned.get(s, set()))
    check(f"{tenant}/ownership", f"owners equal CODEOWNERS for {len(all_svcs)} services", bad_own == 0, f"{bad_own} mismatches")

    rev = {}
    for a, b in calls:
        rev.setdefault(b, []).append(a)
    bad_callers = 0
    for s in all_svcs:
        callers = {c["service"] for c in q.upstream_callers(tenant, s)[0]}
        seen, dq = set(), deque([s])
        while dq:
            x = dq.popleft()
            for y in rev.get(x, []):
                if y not in seen:
                    seen.add(y)
                    dq.append(y)
        seen.discard(s)
        if callers != seen:
            bad_callers += 1
    check(f"{tenant}/blast-radius", f"transitive upstream callers equal reverse-BFS for {len(all_svcs)} services", bad_callers == 0, f"{bad_callers} mismatches")

    # function-level reachability: every govulncheck finding that matches an advisory in the graph is stored with the same level
    import json as _json
    from blastradius import reach as _reach
    checked = bad_reach = 0
    for s in _reach.go_services(tenant):
        p = _reach.reach_dir(tenant) / (s["path"].replace("/", "_") + ".reach.json")
        if not p.exists():
            continue
        for osv_id, f in _json.loads(p.read_text(encoding="utf-8"))["findings"].items():
            adv = db.read(tenant, "MATCH (a:Advisory) WHERE a.id IN $ids OR a.cve IN $ids RETURN a.id", {"ids": f["ids"]}).result_set
            for (aid,) in adv:
                checked += 1
                got = db.read(tenant, "MATCH (:Service {name:$s})-[r:REACHES]->(:Advisory {id:$a}) RETURN r.level",
                              {"s": s["name"], "a": aid}).result_set
                if not got or got[0][0] != f["level"]:
                    bad_reach += 1
    check(f"{tenant}/reachability", f"govulncheck findings stored with identical call-graph level ({checked} checked)",
          bad_reach == 0 and (checked > 0 or not _reach.go_services(tenant)), f"{bad_reach} mismatches")

    # PR-discussion reasoning: graph decisions equal the cached extractions, link to their PR, and name only packages the PR text mentions
    import json as _j
    from blastradius import discussions as _d
    from blastradius.config import cached_path as _cp
    stored = {r[0]: (r[1], r[2]) for r in db.read(tenant, "MATCH (x:Decision)-[:DISCUSSED_IN]->(d:Discussion) RETURN d.number, x.rationale, d.url").result_set}
    n_ext = bad_store = ungrounded = 0
    for num, c in _d.candidates(t).items():
        pe, ee = _cp(f"discussions/pr__{t['repo'].replace('/', '__')}__{num}.json"), _cp(f"discussions/ext__{t['repo'].replace('/', '__')}__{num}.json")
        if not (pe and ee):
            continue
        pr, ex = _j.loads(pe.read_text(encoding="utf-8")), _j.loads(ee.read_text(encoding="utf-8"))
        if not ex["is_decision"] or not ex["rationale"].strip():
            continue
        n_ext += 1
        if stored.get(int(num)) != (ex["rationale"], pr["url"]):
            bad_store += 1
        text = (pr["title"] + pr["body"] + " ".join(x["text"] for x in pr["comments"]) + c["msg"]).lower()
        linked = db.read(tenant, "MATCH (x:Decision {id:$id})-[:CONCERNS]->(p:Package) RETURN DISTINCT p.name", {"id": "dec-" + c["sha"][:10]}).result_set
        ungrounded += sum(1 for (nm,) in linked if nm.lower() not in text)
    check(f"{tenant}/pr-reasoning", f"{n_ext} decisions carry the reasoning and link of their PR exactly as extracted", n_ext > 0 and bad_store == 0, f"{bad_store} mismatches")
    check(f"{tenant}/pr-grounding", "every package a decision is linked to appears in its PR or commit text (no invented subjects)", ungrounded == 0, f"{ungrounded} ungrounded")

    humans = sum(1 for s in all_svcs for e in q.experts(tenant, s)[0] if e["kind"] == "person")
    check(f"{tenant}/company-brain", "expertise includes real human contributors, not only bots", humans > 0, f"{humans} person-service links")


def eval_scenarios():
    t = "boutique"
    r = triage.run_triage(t, "GHSA-jfh8-c2jp-5v3q", record=False)
    check("scenario", "Log4Shell (Maven) is NOT_AFFECTED by proof of absence", r["verdict"] == "NOT_AFFECTED" and r["reason"] == "no_path")
    r = triage.run_triage(t, "GHSA-h755-8qp9-cq85", record=False)
    check("scenario", "protobufjs advisory with a fixed version in use is NOT_AFFECTED (version outside range)",
          r["verdict"] == "NOT_AFFECTED" and r["reason"] == "version_outside_range", r["headline"])
    r = triage.run_triage(t, "CVE-2099-0000", record=False)
    check("scenario", "unknown identifier is NEEDS_HUMAN, never guessed", r["verdict"] == "NEEDS_HUMAN")
    top = triage.risk_board(t)["advisories"][0]
    r = triage.run_triage(t, top["id"], record=False)
    check("scenario", "top-ranked advisory is AFFECTED and every action is gated", r["verdict"] == "AFFECTED" and all(a["status"] == "pending_approval" for a in r["actions"]))

    sid = "eval-session"
    memory.reset_session(t, sid)
    a1 = triage.run_triage(t, "CVE-2026-41242", sid=sid)
    cid = memory.record_decision(t, a1["advisory"]["id"], "patched", "eval", "eval", [s["service"] for s in a1["services"]], eco="npm", sid=sid)
    a2 = triage.run_triage(t, "CVE-2026-48712", sid=sid)
    check("memory", "a decision on one protobufjs advisory is cited when triaging another", any(p["id"] == cid for p in a2["precedents"]))
    a1b = triage.run_triage(t, "CVE-2026-41242", sid=sid)
    check("memory", "the same advisory finds its exact precedent", any(p["id"] == cid and p["exact"] for p in a1b["precedents"]))
    other = triage.run_triage("otel", "CVE-2026-41242", sid=sid, record=False)
    check("memory", "tenant isolation: boutique memory is invisible to otel", not other["precedents"])
    stranger = triage.run_triage(t, "CVE-2026-41242", sid="someone-else", record=False)
    check("memory", "session isolation: another visitor never sees this memory", not stranger["precedents"])
    memory.reset_session(t, sid)

    for bad in ("MATCH (n) DETACH DELETE n", "CREATE (:X)", "MATCH (n) SET n.x = 1", "MERGE (:Y)"):
        try:
            db.read(t, bad)
            ok = False
        except db.UnsafeQuery:
            ok = True
        check("guardrails", f"read path rejects write query: {bad}", ok)
    try:
        db.graph(t).ro_query("CREATE (:Z)")
        ok = False
    except Exception:
        ok = True
    check("guardrails", "database itself rejects writes on the read-only path (defence in depth)", ok)
    check("guardrails", "query timeout and row cap configured", config.QUERY_TIMEOUT_MS <= 3000 and config.MAX_ROWS <= 100)
    check("guardrails", "advisory identifiers are validated before reaching any URL", not osv.valid_id("../../v1/query") and osv.valid_id("CVE-2021-44228"))


def main():
    for t in TENANTS:
        eval_tenant(t)
    eval_scenarios()
    passed = sum(1 for r in results if r[2])
    lines = ["# Evaluation", "",
             "Ground truth is computed **without the graph** (raw lockfiles, cached OSV data, topology discovered from deployment "
             "files, CODEOWNERS) and compared with what the FalkorDB-backed product returns.", "",
             f"**{passed}/{len(results)} checks passed.**", "", "| Group | Check | Result | Detail |", "|---|---|---|---|"]
    for g, n, ok, d in results:
        lines.append(f"| {g} | {n} | {'PASS' if ok else '**FAIL**'} | {d} |")
    out = Path(__file__).resolve().parents[2] / "EVALS.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[4:5]))
    for g, n, ok, d in results:
        print(("PASS " if ok else "FAIL ") + f"[{g}] {n} {d}")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()

"""The triage pipeline: three agents hand off through graph state; a deterministic judge decides.

 Triage agent      -> resolves the identifier to an advisory
 Investigator agent-> graph traversals: paths, blast radius, owners, precedents
 Judge (no LLM)    -> verdict from graph evidence only
 Remediator agent  -> gated action proposals (never executed without approval)

The LLM (agent.py) may choose which tool to call and phrase the summary, but it can not change a verdict.
"""
import time
import uuid

from . import memory, osv, queries as q

VERDICTS = ("AFFECTED", "NOT_AFFECTED", "NEEDS_HUMAN")
ECO_FROM_OSV = {"npm": "npm", "Go": "Go", "PyPI": "PyPI"}


def _step(steps, agent, tool, summary, trace=None):
    ms = round(sum(t["ms"] for t in trace), 1) if isinstance(trace, list) else (trace or {}).get("ms", 0)
    steps.append({"agent": agent, "tool": tool, "summary": summary, "ms": ms,
                  "traces": trace if isinstance(trace, list) else ([trace] if trace else [])})


def _priority(severity, exposed):
    sev = q.SEV_RANK.get((severity or "").upper(), 0)
    if sev >= 4 and exposed:
        return "P0"
    if sev >= 4 or (sev == 3 and exposed):
        return "P1"
    return "P2"


def _not_in_graph(tenant, ident, steps):
    """Advisory isn't affecting any package in the graph. Say *why*, from graph evidence."""
    vulns = osv.fetch_vulns([ident.strip()])
    v = vulns.get(ident.strip())
    if not v:
        _step(steps, "Triage", "osv_lookup", f"'{ident}' is not a known advisory id or alias.")
        return {"verdict": "NEEDS_HUMAN", "reason": "unknown_identifier",
                "headline": f"Could not resolve '{ident}' to any known advisory.",
                "evidence": []}
    s = osv.summarize(v)
    names = sorted({(a["package"]["ecosystem"].split(":")[0], a["package"]["name"])
                    for a in v.get("affected", []) if "package" in a})
    evidence, traces = [], []
    for eco, name in names:
        present, tr = q.package_presence(tenant, eco, name)
        traces.append(tr)
        evidence.append({"package": name, "eco": eco, "present": present})
    present_any = [e for e in evidence if e["present"]]
    _step(steps, "Investigator", "package_presence",
          f"Checked {len(names)} affected package(s) against the graph: "
          + (f"{len(present_any)} present, {len(names) - len(present_any)} absent" if names else "none listed"), traces[:3])
    tag = s["cve"] or s["id"]
    if present_any:
        e = present_any[0]
        vers = ", ".join(p["version"] for p in e["present"])
        return {"verdict": "NOT_AFFECTED", "reason": "version_outside_range", "advisory": s,
                "headline": f"{tag} targets {e['package']}, but you run {vers}: outside the affected range.",
                "evidence": evidence}
    shown = ", ".join(n.split(":")[-1] for _, n in names[:2]) + (f" +{len(names) - 2} more" if len(names) > 2 else "")
    return {"verdict": "NOT_AFFECTED", "reason": "no_path", "advisory": s,
            "headline": f"No path: {tag} affects {shown or 'n/a'}, and none of it exists anywhere in the dependency graph.",
            "evidence": evidence}


def _subgraph(tenant, paths, callpaths):
    nodes, edges, seq = {}, [], []

    def add(nid, label, typ):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "label": label, "type": typ}

    for p in paths:
        prev = None
        for i, nid in enumerate(p["path"]):
            typ = "service" if i == 0 else ("vuln" if nid == p["pkg_key"] else "package")
            label = nid if i == 0 else nid.split(":", 1)[1]
            add(nid, label, typ)
            if prev:
                edges.append({"source": prev, "target": nid, "type": "DEPENDS_ON"})
                seq.append({"source": prev, "target": nid})
            prev = nid
    for cp in callpaths:
        prev = None
        for nid in cp:
            add(nid, nid, "service")
            if prev:
                edges.append({"source": prev, "target": nid, "type": "CALLS"})
                seq.append({"source": prev, "target": nid})
            prev = nid
    uniq = {(e["source"], e["target"], e["type"]): e for e in edges}
    return {"nodes": list(nodes.values()), "edges": list(uniq.values()), "sequence": seq}


def risk_board(tenant: str) -> dict:
    """All advisories ranked by deterministic priority; one traversal sweep + cached exposure lookups."""
    findings, tr = q.all_findings(tenant)
    known = q.tenant_meta(tenant)["exposure_known"]
    exp_cache: dict[str, bool] = {}
    adv: dict[str, dict] = {}
    for f in findings:
        if f["service"] not in exp_cache:
            if known:
                ep, _ = q.exposure_path(tenant, f["service"])
                exp_cache[f["service"]] = bool(ep) or f["exposed"]
            else:
                exp_cache[f["service"]] = True  # unknown topology: assume the worst

        a = adv.setdefault(f["id"], {"id": f["id"], "cve": f["cve"], "severity": f["severity"], "summary": f["summary"],
                                     "services": {}, "packages": set(), "exposed": False, "prod": False, "fixed": set(),
                                     "new": f["first_seen"] is not None})
        a["services"][f["service"]] = a["services"].get(f["service"], False) or not f["dev"]
        a["packages"].add(f"{f['pkg']}@{f['version']}")
        if f["fixed"]:
            a["fixed"].add(f["fixed"])
        if not f["dev"]:
            a["prod"] = True
            a["exposed"] = a["exposed"] or exp_cache[f["service"]]
    out = []
    for a in adv.values():
        prio = _priority(a["severity"], a["exposed"]) if a["prod"] else "DEV"
        out.append({**a, "services": sorted(a["services"]), "packages": sorted(a["packages"]),
                    "fixed": sorted(a["fixed"]), "priority": prio})
    order = {"P0": 0, "P1": 1, "P2": 2, "DEV": 3}
    out.sort(key=lambda x: (order[x["priority"]], -q.SEV_RANK.get(x["severity"], 0), -len(x["services"])))
    summary = {p: sum(1 for x in out if x["priority"] == p) for p in order}
    return {"advisories": out, "summary": summary, "trace": tr}


def run_triage(tenant: str, ident: str, sid: str = memory.DEFAULT_SID, record: bool = True) -> dict:
    """record=False leaves no trace in the graph (read-only callers such as the public MCP endpoint)."""
    t0 = time.perf_counter()
    steps: list[dict] = []
    exposure_known = q.tenant_meta(tenant)["exposure_known"]
    adv, tr = q.find_advisory(tenant, ident)
    _step(steps, "Triage", "find_advisory",
          f"Resolved '{ident}' -> {adv['id']} ({adv['severity']})" if adv else f"'{ident}' not in graph", tr)

    result: dict
    if not adv:
        result = _not_in_graph(tenant, ident, steps)
        result.setdefault("advisory", None)
        result.update(paths=[], services=[], precedents=[], actions=[], subgraph={"nodes": [], "edges": [], "sequence": []})
    else:
        paths, tr = q.affected_paths(tenant, adv["id"])
        _step(steps, "Investigator", "affected_paths",
              f"{len(paths)} service->package path(s) reach a vulnerable package", tr)
        by_service: dict[str, dict] = {}
        callpaths = []
        for p in paths:
            sv = by_service.setdefault(p["service"], {"service": p["service"], "paths": [], "dev_only": True,
                                                       "exposed_direct": p["exposed"]})
            sv["paths"].append(p)
            if not p["dev"]:
                sv["dev_only"] = False
        for name, sv in by_service.items():
            callers, tr1 = q.upstream_callers(tenant, name)
            ep, tr2 = q.exposure_path(tenant, name)
            own, tr3 = q.owners(tenant, name)
            sv.update(callers=callers, exposure_path=ep, owners=own, exposure_unknown=not exposure_known,
                      exposed=bool(ep) or sv["exposed_direct"] or not exposure_known)
            if exposure_known:
                what = f"internet-exposed via {' -> '.join(ep)}" if ep else "not reachable from an exposed entry point"
            else:
                what = "exposure unknown (no deployment topology), assumed reachable"
            _step(steps, "Investigator", "blast_radius", f"{name}: {len(callers)} upstream caller(s); {what}", [tr1, tr2, tr3])
            if ep and len(ep) > 1:
                callpaths.append(ep)
        pkg_names = {p["pkg"] for p in paths}
        precedents, tr = memory.find_precedents(tenant, adv["id"], pkg_names, sid)
        _step(steps, "Investigator", "find_precedents",
              f"{len(precedents)} relevant prior case(s) in memory", tr)

        # ---- deterministic judge: graph evidence only
        services = list(by_service.values())
        prod = [s for s in services if not s["dev_only"]]
        exact_vex = next((c for c in precedents if c["exact"] and c["decision"] == "not_affected"), None)
        if not paths:
            verdict, reason, headline = "NOT_AFFECTED", "no_path", f"No service reaches a package affected by {adv['id']}."
        elif exact_vex and set(exact_vex["services"]) >= {s["service"] for s in services}:
            verdict, reason = "NOT_AFFECTED", "vex_precedent"
            headline = f"Previously assessed not affected ({exact_vex['id']}: {exact_vex['rationale']})."
        elif prod:
            exposed = any(s["exposed"] for s in prod)
            verdict, reason = "AFFECTED", "reachable_runtime_dependency"
            names = ", ".join(s["service"] for s in prod)
            if not exposure_known:
                tail = "Exposure is unknown for this repository, so it is assumed reachable."
            else:
                tail = "Reachable from an internet-exposed entry point." if exposed else "Not reachable from the internet."
            headline = f"Reaches {names} through a runtime dependency. {tail}"
        else:
            verdict, reason = "NEEDS_HUMAN", "dev_only_dependency"
            headline = "Only dev-time dependency paths exist; confirm it is not shipped to production."
        prio = _priority(adv["severity"], any(s["exposed"] for s in prod)) if verdict == "AFFECTED" else None
        _step(steps, "Judge", "deterministic_verdict", f"{verdict} ({reason})" + (f" priority {prio}" if prio else ""))

        # ---- remediator proposals (gated)
        actions = []
        if verdict == "AFFECTED":
            fixed_by_pkg: dict[str, set] = {}
            for p in paths:
                if not p["dev"]:
                    fixed_by_pkg.setdefault(f"{p['pkg']}@{p['version']}", set()).add(p["fixed"] or "?")
            for sv in prod:
                best = min(sv["paths"], key=lambda x: x["hops"])
                chain = [n.split(":", 1)[-1] for n in best["path"][1:]]
                via = chain[0] if chain else best["pkg"]
                eco = best["pkg_key"].split(":", 1)[0]
                pb = memory.PLAYBOOKS.get(eco, (None, ""))[0]
                owner = (sv["owners"][0]["owner"] if sv["owners"] else "unowned")
                actions.append({
                    "id": f"act-{uuid.uuid4().hex[:6]}", "kind": "open_issue", "service": sv["service"],
                    "title": f"[{prio}] {adv['cve'] or adv['id']}: upgrade {best['pkg']} in {sv['service']}",
                    "body": (f"{adv['summary']}\n\nPath: {' -> '.join(best['path'][:1] + chain)}\n"
                             f"Fix: {best['pkg']} >= {best['fixed'] or 'see advisory'} (currently {best['version']}).\n"
                             f"Bump `{via}` or override {best['pkg']}.\nOwner: @{owner}\nAdvisory: {adv['url']}"),
                    "playbook": pb, "status": "pending_approval"})
        elif verdict == "NEEDS_HUMAN":
            actions.append({"id": f"act-{uuid.uuid4().hex[:6]}", "kind": "request_review", "service": None,
                            "title": f"Review {adv['id']}: dev-only path", "body": headline,
                            "playbook": None, "status": "pending_approval"})
        _step(steps, "Remediator", "propose_actions", f"{len(actions)} action proposal(s), awaiting human approval")

        sub = _subgraph(tenant, [p for s in prod or services for p in s["paths"]], callpaths)
        result = {"verdict": verdict, "reason": reason, "priority": prio, "headline": headline, "advisory": adv,
                  "services": services, "precedents": precedents, "actions": actions, "subgraph": sub}
        if record:
            memory.mark_reused(tenant, [c["id"] for c in precedents])

    run_id = f"run-{uuid.uuid4().hex[:8]}"
    if record:
        memory.save_run(tenant, run_id, ident, result["verdict"], steps, sid)
    result.update(run_id=run_id, exposure_known=exposure_known, tenant=tenant, ident=ident, steps=steps,
                  total_ms=round((time.perf_counter() - t0) * 1000, 1))
    return result

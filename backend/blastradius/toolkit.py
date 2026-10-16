"""The agent-facing tool surface, shared by the LLM agent loop and the MCP server.

Every tool is read-only against the graph (triage can optionally log a run), takes validated arguments, and returns
compact JSON. The LLM never sees Cypher or database credentials: it can only call these.
"""
from . import db, memory, queries as q, triage
from .osv import valid_id
from .security import NAME_RE, TENANT_RE


class ToolError(ValueError):
    """Bad arguments from the caller (surfaced to the LLM / MCP client as a tool error)."""


def check_tenant(tenant: str) -> str:
    if not TENANT_RE.match(tenant or "") or tenant not in db.tenants_present():
        raise ToolError(f"unknown tenant '{tenant}'. Use list_tenants to see valid ones.")
    return tenant


def check_service(tenant: str, service: str) -> str:
    if not NAME_RE.match(service or ""):
        raise ToolError("invalid service name")
    names = {n["id"] for n in q.service_graph(tenant)[0]["nodes"]}
    if service not in names:
        raise ToolError(f"unknown service '{service}'. Known: {', '.join(sorted(names))}")
    return service


def list_tenants() -> list[dict]:
    out = []
    for t in db.tenants_present():
        m = q.tenant_meta(t)
        out.append({"tenant": t, "title": m["title"], "repo": m["repo"], "kind": m["kind"],
                    "exposure_known": m["exposure_known"]})
    return out


def risk_board(tenant: str, limit: int = 10) -> dict:
    check_tenant(tenant)
    b = triage.risk_board(tenant)
    return {"summary": b["summary"],
            "top": [{"id": a["id"], "cve": a["cve"], "severity": a["severity"], "priority": a["priority"],
                     "packages": a["packages"][:3], "services": a["services"], "fixed": a["fixed"][:2],
                     "summary": a["summary"][:160]} for a in b["advisories"][:max(1, min(limit, 25))]]}


def triage_advisory(tenant: str, identifier: str, sid: str = memory.DEFAULT_SID, record: bool = True) -> tuple[dict, dict]:
    """-> (compact dict for the LLM/MCP client, full result for the UI)."""
    check_tenant(tenant)
    if not valid_id(identifier):
        raise ToolError("identifier must look like CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx")
    r = triage.run_triage(tenant, identifier.strip(), sid=sid, record=record)
    compact = {
        "verdict": r["verdict"], "reason": r["reason"], "priority": r.get("priority"), "headline": r["headline"],
        "advisory": r["advisory"] and {k: r["advisory"][k] for k in ("id", "cve", "severity", "summary")},
        "exposure_known": r.get("exposure_known", True),
        "services": [{"service": s["service"], "internet_exposed": s["exposed"], "exposure_path": s.get("exposure_path"),
                      "dependency_chain": [p.split(":", 1)[-1] for p in min(s["paths"], key=lambda x: x["hops"])["path"]],
                      "fix": f"{s['paths'][0]['pkg']} >= {s['paths'][0]['fixed']}",
                      "function_reachability": (s.get("reach") or {}).get("level") or "not analysed",
                      "vulnerable_symbol": (s.get("reach") or {}).get("symbol"),
                      "owners": [o["owner"] for o in s.get("owners", [])]} for s in r["services"]],
        "precedents": [{"id": p["id"], "decision": p["decision"], "rationale": p["rationale"], "same_advisory": p["exact"]}
                       for p in r["precedents"]],
        "proposed_actions": [a["title"] for a in r["actions"]],
        "note": "Actions are proposals only. Nothing has been executed.",
    }
    return compact, r


def blast_radius(tenant: str, service: str) -> dict:
    check_tenant(tenant)
    check_service(tenant, service)
    callers, _ = q.upstream_callers(tenant, service)
    ep, _ = q.exposure_path(tenant, service)
    return {"service": service, "upstream_callers": callers, "exposure_path": ep,
            "internet_reachable": bool(ep), "exposure_known": q.tenant_meta(tenant)["exposure_known"]}


def who_owns(tenant: str, service: str) -> dict:
    check_tenant(tenant)
    check_service(tenant, service)
    owners, _ = q.owners(tenant, service)
    return {"service": service, "owners": owners}


def service_brain(tenant: str, service: str) -> dict:
    check_tenant(tenant)
    check_service(tenant, service)
    owners, _ = q.owners(tenant, service)
    experts, _ = q.experts(tenant, service)
    decisions, _ = q.decisions(tenant, service)
    return {"service": service, "owners": owners,
            "experts": [e for e in experts if e["kind"] != "bot"][:5],
            "automation": [e["name"] for e in experts if e["kind"] == "bot"],
            "recent_decisions": [_dec(d) for d in decisions[:5]]}


def _dec(d: dict) -> dict:
    out = {"text": d["text"], "by": d["author"], "date": d["date"][:10], "source": d["source"],
           "superseded": bool(d["superseded_by"])}
    if d.get("rationale"):
        out["why"] = d["rationale"]
        out["discussion"] = d["discussion"]
    return out


def why_decision(tenant: str, topic: str, service: str = "") -> dict:
    """Why was a dependency changed/pinned/upgraded? Answers from pull-request discussions, with links."""
    check_tenant(tenant)
    if service and service not in {n["id"] for n in q.service_graph(tenant)[0]["nodes"]}:
        service = ""  # a wrong service name widens the search instead of failing it
    topic = (topic or "").strip()
    if topic and not NAME_RE.match(topic):
        raise ToolError("invalid topic: use a package or service name")
    rows, _ = q.decisions(tenant, service, topic, limit=6)
    return {"topic": topic, "service": service or None, "decisions": [_dec(d) for d in rows]}


def record_decision(tenant: str, advisory_id: str, decision: str, rationale: str, services: list[str],
                    sid: str = memory.DEFAULT_SID) -> dict:
    """The only write tool. Disabled on public servers (see mcp_server / agent)."""
    check_tenant(tenant)
    if not valid_id(advisory_id):
        raise ToolError("invalid advisory id")
    if decision not in memory.DECISIONS:
        raise ToolError(f"decision must be one of {sorted(memory.DECISIONS)}")
    if not rationale.strip():
        raise ToolError("a rationale is required")
    adv, _ = q.find_advisory(tenant, advisory_id)
    if not adv:
        raise ToolError("advisory is not in this tenant's graph")
    for s in services:
        check_service(tenant, s)
    eco = None
    paths, _ = q.affected_paths(tenant, adv["id"])
    if paths:
        eco = paths[0]["pkg_key"].split(":", 1)[0]
    cid = memory.record_decision(tenant, adv["id"], decision, rationale, "mcp-client", services, eco=eco, sid=sid)
    return {"case_id": cid, "recorded": decision}

"""Conversational layer. The LLM only (a) picks tools and (b) phrases the answer.
All facts and verdicts come from graph tools; it never sees or writes Cypher.

Free-tier LLM: Gemini via REST (GEMINI_API_KEY). With no key (or on any error) a deterministic
router handles the same tools, so the app and the demo work at $0 with no network LLM.
"""
import json
import os
import re

import httpx

from . import queries as q, triage

ID_RE = re.compile(r"(CVE-\d{4}-\d{3,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+)", re.I)

TOOLS = [
    {"name": "triage_advisory",
     "description": "Full triage of a CVE/GHSA id: affected? which services? exposure, owners, precedents, proposed actions.",
     "parameters": {"type": "object", "properties": {"identifier": {"type": "string"}}, "required": ["identifier"]}},
    {"name": "who_owns",
     "description": "Owners/maintainers of a service, from CODEOWNERS ownership edges in the graph.",
     "parameters": {"type": "object", "properties": {"service": {"type": "string"}}, "required": ["service"]}},
    {"name": "blast_radius",
     "description": "Which services call a given service (upstream) and whether it is reachable from an internet-exposed entry point.",
     "parameters": {"type": "object", "properties": {"service": {"type": "string"}}, "required": ["service"]}},
    {"name": "risk_board",
     "description": "Top vulnerabilities in this environment ranked by priority (severity x exposure).",
     "parameters": {"type": "object", "properties": {}}},
]


def _tool_triage(tenant, identifier):
    r = triage.run_triage(tenant, identifier)
    return {"verdict": r["verdict"], "priority": r.get("priority"), "headline": r["headline"],
            "services": [{"service": s["service"], "exposure_path": s.get("exposure_path"),
                          "owners": [o["owner"] for o in s.get("owners", [])]} for s in r["services"]],
            "precedents": [{"id": p["id"], "decision": p["decision"], "rationale": p["rationale"]} for p in r["precedents"]],
            "actions": [a["title"] for a in r["actions"]]}, r


def _tool_owner(tenant, service):
    rows, _ = q.owners(tenant, service)
    return {"service": service, "owners": rows}, None


def _tool_blast(tenant, service):
    callers, _ = q.upstream_callers(tenant, service)
    ep, _ = q.exposure_path(tenant, service)
    return {"service": service, "callers": callers, "exposure_path": ep}, None


def _tool_board(tenant):
    b = triage.risk_board(tenant)
    return {"summary": b["summary"],
            "top": [{"id": a["id"], "cve": a["cve"], "severity": a["severity"], "priority": a["priority"],
                     "services": a["services"]} for a in b["advisories"][:8]]}, None


def call_tool(tenant, name, args):
    if name == "triage_advisory":
        return _tool_triage(tenant, args["identifier"])
    if name == "who_owns":
        return _tool_owner(tenant, args["service"])
    if name == "blast_radius":
        return _tool_blast(tenant, args["service"])
    if name == "risk_board":
        return _tool_board(tenant)
    raise ValueError(f"unknown tool {name}")


def _service_names(tenant):
    g, _ = q.service_graph(tenant)
    return [n["id"] for n in g["nodes"]]


def _offline(tenant, question):
    """Deterministic router: same tools, template phrasing."""
    calls, triage_result = [], None
    m = ID_RE.search(question)
    svc = next((s for s in sorted(_service_names(tenant), key=len, reverse=True) if s in question.lower()), None)
    low = question.lower()
    if m:
        res, triage_result = call_tool(tenant, "triage_advisory", {"identifier": m.group(1).upper()})
        calls.append({"tool": "triage_advisory", "args": {"identifier": m.group(1).upper()}})
        ans = res["headline"]
        for s in res["services"]:
            ans += f"\n- {s['service']}: " + (" -> ".join(s["exposure_path"]) if s["exposure_path"] else "not exposed") + \
                   (f" (owners: {', '.join(s['owners'])})" if s["owners"] else "")
        if res["precedents"]:
            ans += "\nPrecedent: " + "; ".join(f"{p['id']} ({p['decision']}: {p['rationale']})" for p in res["precedents"])
        return ans, calls, triage_result
    if svc and re.search(r"\b(own|owner|owns|maintain|who)\b", low):
        res, _ = call_tool(tenant, "who_owns", {"service": svc})
        calls.append({"tool": "who_owns", "args": {"service": svc}})
        return (f"{svc} is owned by " + (", ".join(o["owner"] for o in res["owners"]) or "nobody (no CODEOWNERS entry)")), calls, None
    if svc and re.search(r"blast|radius|impact|depend|call", low):
        res, _ = call_tool(tenant, "blast_radius", {"service": svc})
        calls.append({"tool": "blast_radius", "args": {"service": svc}})
        return (f"{svc} is called by {', '.join(c['service'] for c in res['callers']) or 'nobody'}; "
                + (f"exposed via {' -> '.join(res['exposure_path'])}." if res["exposure_path"] else "not internet-reachable.")), calls, None
    res, _ = call_tool(tenant, "risk_board", {})
    calls.append({"tool": "risk_board", "args": {}})
    s = res["summary"]
    ans = f"{s['P0']} P0, {s['P1']} P1, {s['P2']} P2 advisories. Top: " + "; ".join(
        f"{a['cve'] or a['id']} [{a['priority']}] in {', '.join(a['services'])}" for a in res["top"][:3])
    return ans, calls, None


def _gemini(tenant, question, key):
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    sys = (f"You are the Blastradius security triage assistant for tenant '{tenant}'. Use the tools for every fact; "
           "never invent CVEs, services or owners. Answer concisely (max 6 lines) and mention the exposure path.")
    contents = [{"role": "user", "parts": [{"text": question}]}]
    calls, triage_result = [], None
    with httpx.Client(timeout=40) as cli:
        for _ in range(4):
            r = cli.post(url, params={"key": key}, json={
                "systemInstruction": {"parts": [{"text": sys}]}, "contents": contents,
                "tools": [{"functionDeclarations": TOOLS}]})
            r.raise_for_status()
            parts = r.json()["candidates"][0]["content"]["parts"]
            fcs = [p["functionCall"] for p in parts if "functionCall" in p]
            if not fcs:
                return "".join(p.get("text", "") for p in parts).strip(), calls, triage_result
            contents.append({"role": "model", "parts": parts})
            resp_parts = []
            for fc in fcs:
                res, full = call_tool(tenant, fc["name"], fc.get("args", {}))
                triage_result = full or triage_result
                calls.append({"tool": fc["name"], "args": fc.get("args", {})})
                resp_parts.append({"functionResponse": {"name": fc["name"], "response": {"result": res}}})
            contents.append({"role": "user", "parts": resp_parts})
    return "I could not finish within the tool budget.", calls, triage_result


def ask(tenant: str, question: str) -> dict:
    key = os.getenv("GEMINI_API_KEY")
    mode = "offline-router"
    try:
        if key:
            answer, calls, tr = _gemini(tenant, question, key)
            mode = "gemini"
        else:
            raise RuntimeError("no key")
    except Exception:
        answer, calls, tr = _offline(tenant, question)
    return {"answer": answer, "tool_calls": calls, "triage": tr, "mode": mode}

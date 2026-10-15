"""Export a session's decisions as an OpenVEX document (https://openvex.dev), the standard way to say
"this vulnerability does / does not affect this product".

patched        -> status "fixed"
not_affected   -> status "not_affected" with a justification and the human's rationale as the impact statement
accepted_risk  -> status "affected" with an action statement recording that the risk was accepted, and why
"""
import datetime
import uuid

from . import queries as q
from .memory import DEFAULT_SID

CONTEXT = "https://openvex.dev/ns/v0.2.0"

Q_CASES = """
MATCH (c:Case {sid:$sid})-[:ABOUT]->(a:Advisory)
OPTIONAL MATCH (c)-[:IN]->(s:Service)
RETURN c.id, c.decision, c.rationale, c.actor, c.ts, a.id, a.cve, a.url, collect(DISTINCT s.name)
ORDER BY c.ts
"""


def _iso(ms: int) -> str:
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_vex(tenant: str, sid: str = DEFAULT_SID) -> dict:
    meta = q.tenant_meta(tenant)
    product = f"pkg:github/{meta['repo']}" if meta["repo"] else f"pkg:generic/{tenant}"
    rows, _ = q._run(tenant, Q_CASES, {"sid": sid})
    statements = []
    for cid, decision, rationale, actor, ts, adv_id, cve, url, services in rows:
        st = {
            "vulnerability": {"@id": url, "name": cve or adv_id, "aliases": [x for x in (adv_id, cve) if x and x != (cve or adv_id)]},
            "products": [{"@id": product, "subcomponents": [{"@id": f"{product}#{s}"} for s in services]}],
            "timestamp": _iso(ts),
            "supplier": f"Decided by {actor} via Blastradius case {cid}",
        }
        if decision == "patched":
            st["status"] = "fixed"
        elif decision == "not_affected":
            st["status"] = "not_affected"
            st["justification"] = "vulnerable_code_not_in_execute_path"
            st["impact_statement"] = rationale
        else:
            st["status"] = "affected"
            st["action_statement"] = f"Risk accepted: {rationale}"
        statements.append(st)
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        "@context": CONTEXT,
        "@id": f"https://openvex.dev/docs/blastradius/{uuid.uuid4()}",
        "author": "Blastradius",
        "role": "Automated triage with human approval",
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": 1,
        "statements": statements,
    }

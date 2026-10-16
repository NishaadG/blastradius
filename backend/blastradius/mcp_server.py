"""MCP server: lets any MCP client (Claude Desktop, Claude Code, IDEs) query the graph.

    python -m blastradius.mcp_server                      # stdio, for local clients
    claude mcp add blastradius -- python -m blastradius.mcp_server

The same server is mounted at /mcp on the API (streamable HTTP). On a public deployment (BR_PUBLIC=1) it is strictly
read-only: triage leaves no trace and the write tool is not registered.
"""
import os

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from . import config, toolkit
from .toolkit import ToolError

INSTRUCTIONS = (
    "Blastradius answers supply-chain vulnerability questions from a FalkorDB graph of real dependency, call and "
    "ownership data. Start with list_tenants, then risk_board for what matters most, then triage_advisory for a CVE or "
    "GHSA id. Verdicts are computed deterministically from graph traversals; 'NOT_AFFECTED / no_path' means the "
    "traversal found zero paths. Proposed actions are suggestions and are never executed."
)

def _transport_security() -> TransportSecuritySettings:
    """DNS-rebinding protection stays ON; allow the local hosts plus the public site address (SITE_ADDRESS)."""
    hosts = ["127.0.0.1:*", "localhost:*", "localhost", "[::1]:*"]
    origins = ["http://127.0.0.1:*", "http://localhost:*"]
    site = os.getenv("SITE_ADDRESS", "").strip()
    if site and not site.startswith(":"):
        hosts += [site, f"{site}:*"]
        origins += [f"https://{site}", f"http://{site}"]
    return TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins)


mcp = FastMCP("blastradius", instructions=INSTRUCTIONS, stateless_http=True, json_response=True, streamable_http_path="/",
              transport_security=_transport_security())


def _safe(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ToolError as e:
        return {"error": str(e)}


@mcp.tool()
def list_tenants() -> list[dict]:
    """List the analysed environments (tenants). Each is an isolated graph; use its `tenant` id in other tools."""
    return toolkit.list_tenants()


@mcp.tool()
def risk_board(tenant: str, limit: int = 10) -> dict:
    """Top vulnerabilities in a tenant ranked by priority (P0 = critical and reachable from the internet)."""
    return _safe(toolkit.risk_board, tenant, limit)


@mcp.tool()
def triage_advisory(tenant: str, identifier: str) -> dict:
    """Full triage of a CVE/GHSA id: is the tenant affected, via which dependency chain, which services and owners,
    internet exposure path, precedent decisions, proposed actions. 'No path' is a valid, proven answer."""
    try:
        compact, _ = toolkit.triage_advisory(tenant, identifier, sid="mcp", record=not config.PUBLIC)
        return compact
    except ToolError as e:
        return {"error": str(e)}


@mcp.tool()
def blast_radius(tenant: str, service: str) -> dict:
    """Which services call this service (transitively) and whether it is reachable from an internet-exposed entry point."""
    return _safe(toolkit.blast_radius, tenant, service)


@mcp.tool()
def who_owns(tenant: str, service: str) -> dict:
    """Owners of a service according to CODEOWNERS."""
    return _safe(toolkit.who_owns, tenant, service)


@mcp.tool()
def service_brain(tenant: str, service: str) -> dict:
    """Company knowledge about a service: owners, human experts from commit history, and recent dependency decisions
    traced to their source commit (with whether a later decision superseded them)."""
    return _safe(toolkit.service_brain, tenant, service)


@mcp.tool()
def why_decision(tenant: str, topic: str, service: str = "") -> dict:
    """Why was a dependency changed, pinned or upgraded? Reads the reasoning from the pull-request discussions behind
    the change, with links to the source. Empty when no discussion explains it."""
    return _safe(toolkit.why_decision, tenant, topic, service)


if not config.PUBLIC:

    @mcp.tool()
    def record_decision(tenant: str, advisory_id: str, decision: str, rationale: str, services: list[str]) -> dict:
        """WRITE: record a human decision (patched | not_affected | accepted_risk) as memory so later triages can cite
        it. Only call this after the user has explicitly approved the decision."""
        return _safe(toolkit.record_decision, tenant, advisory_id, decision, rationale, services, "mcp")


if __name__ == "__main__":
    mcp.run()

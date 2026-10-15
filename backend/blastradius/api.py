import logging
import os
import re
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from redis.exceptions import RedisError

from . import agent, bench, config, db, ingest, jobs, mcp_server, memory, queries as q, security, triage
from .osv import valid_id
from .security import ECOS, TENANT_RE, check_name, session_id

log = logging.getLogger("blastradius")


@asynccontextmanager
async def lifespan(_: FastAPI):
    async with mcp_server.mcp.session_manager.run():
        yield


app = FastAPI(title="Blastradius API", version="1.1", lifespan=lifespan, docs_url=None if config.PUBLIC else "/docs",
              redoc_url=None, openapi_url=None if config.PUBLIC else "/openapi.json")

_cors = [o.strip() for o in os.getenv("BR_CORS", "" if config.PUBLIC else "*").split(",") if o.strip()]
if _cors:
    app.add_middleware(CORSMiddleware, allow_origins=_cors, allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-Session"])


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    if path.startswith(("/api", "/mcp")):
        if int(request.headers.get("content-length") or 0) > 20_000:
            return JSONResponse(status_code=413, content={"detail": "request too large"})
        who = security.client_ip(request)
        cls = "heavy" if path.startswith("/mcp") else security.classify(request.method, path)
        for bucket in {cls, "general"}:
            limit, window = security.RULES[bucket]
            if not security.limiter.allow(bucket, who, limit, window):
                return JSONResponse(status_code=429, content={"detail": "Too many requests. Slow down and retry shortly."},
                                    headers={"Retry-After": str(window)})
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


@app.exception_handler(RedisError)
async def graph_down(_, exc: RedisError):
    # No fallback on purpose: every verdict is a graph traversal, so without FalkorDB there is nothing to say.
    log.warning("FalkorDB error: %s", exc)
    return JSONResponse(status_code=503, content={"detail": "FalkorDB unavailable"})


@app.exception_handler(Exception)
async def unexpected(_, exc: Exception):
    log.exception("unhandled error")
    return JSONResponse(status_code=500, content={"detail": "internal error"})


def tenant_dep(tenant: str) -> str:
    if not TENANT_RE.match(tenant) or tenant not in db.tenants_present():
        raise HTTPException(404, "unknown tenant")
    return tenant


def service_names(tenant: str) -> set[str]:
    return {n["id"] for n in q.service_graph(tenant)[0]["nodes"]}


@app.get("/api/health")
def health():
    return {"ok": True, "graphs": len(db.tenants_present())}  # raises RedisError -> 503 when the graph is down


@app.get("/api/config")
def public_config():
    return {"public": config.PUBLIC, "max_repo_services": ingest.MAX_SERVICES, "max_packages": ingest.MAX_PACKAGES}


@app.get("/api/evals")
def evals():
    """Latest result of `python -m evals.run`, read from the report it wrote (never hard-coded)."""
    from pathlib import Path

    p = Path(__file__).resolve().parents[2] / "EVALS.md"
    if not p.exists():
        return {"available": False}
    m = re.search(r"\*\*(\d+)/(\d+) checks passed", p.read_text(encoding="utf-8"))
    return {"available": bool(m), "passed": int(m.group(1)) if m else 0, "total": int(m.group(2)) if m else 0}


@app.get("/api/tenants")
def tenants():
    out = []
    for t in db.tenants_present():
        m = q.tenant_meta(t)
        out.append({"id": t, "title": m["title"], "repo": m["repo"], "kind": m["kind"], "exposure_known": m["exposure_known"],
                    **q.stats(t)})
    out.sort(key=lambda x: (x["kind"] != "curated", x["title"]))
    return out


@app.get("/api/{tenant}/graph")
def graph(tenant: str = Depends(tenant_dep)):
    data, trace = q.service_graph(tenant)
    pr, _ = q.service_centrality(tenant)
    for n in data["nodes"]:
        n["centrality"] = pr.get(n["id"], 0)
    return {**data, "trace": trace, "exposure_known": q.tenant_meta(tenant)["exposure_known"]}


@app.get("/api/{tenant}/risk")
def risk(tenant: str = Depends(tenant_dep)):
    return triage.risk_board(tenant)


class TriageIn(BaseModel):
    identifier: str = Field(min_length=3, max_length=64)


@app.post("/api/{tenant}/triage")
def do_triage(body: TriageIn, request: Request, tenant: str = Depends(tenant_dep)):
    if not valid_id(body.identifier.strip()):
        raise HTTPException(422, "identifier must look like CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx")
    return triage.run_triage(tenant, body.identifier.strip(), sid=session_id(request))


class DecideIn(BaseModel):
    advisory_id: str = Field(min_length=3, max_length=64)
    decision: Literal["patched", "not_affected", "accepted_risk"]
    rationale: str = Field(min_length=1, max_length=500)
    actor: str = Field(default="you", max_length=60)
    services: list[str] = Field(default_factory=list, max_length=25)
    eco: str | None = None


@app.post("/api/{tenant}/decide")
def decide(body: DecideIn, request: Request, tenant: str = Depends(tenant_dep)):
    if not valid_id(body.advisory_id):
        raise HTTPException(422, "invalid advisory id")
    if body.eco is not None and body.eco not in ECOS:
        raise HTTPException(422, "invalid ecosystem")
    known = service_names(tenant)
    if any(s not in known for s in body.services):
        raise HTTPException(422, "unknown service")
    adv, _ = q.find_advisory(tenant, body.advisory_id)
    if not adv:
        raise HTTPException(404, "advisory is not in this tenant's graph")
    cid = memory.record_decision(tenant, adv["id"], body.decision, body.rationale, body.actor, body.services, body.eco,
                                 sid=session_id(request))
    return {"case_id": cid}


@app.get("/api/{tenant}/brain")
def brain(request: Request, tenant: str = Depends(tenant_dep)):
    return memory.brain_timeline(tenant, session_id(request))


@app.post("/api/{tenant}/reset-memory")
def reset_memory(request: Request, tenant: str = Depends(tenant_dep)):
    memory.reset_session(tenant, session_id(request))  # only this browser session's memory
    return {"ok": True}


@app.get("/api/{tenant}/service/{service}")
def service_card(service: str, tenant: str = Depends(tenant_dep)):
    check_name(service, "service")
    if service not in service_names(tenant):
        raise HTTPException(404, "unknown service")
    own, t1 = q.owners(tenant, service)
    exp, t2 = q.experts(tenant, service)
    dec, t3 = q.decisions(tenant, service)
    callers, t4 = q.upstream_callers(tenant, service)
    ep, t5 = q.exposure_path(tenant, service)
    return {"service": service, "owners": own, "experts": exp, "decisions": dec, "callers": callers,
            "exposure_path": ep, "traces": [t1, t2, t3, t4, t5]}


@app.get("/api/{tenant}/decisions")
def decisions(service: str = Query("", max_length=80), term: str = Query("", max_length=80), tenant: str = Depends(tenant_dep)):
    if service:
        check_name(service, "service")
    rows, tr = q.decisions(tenant, service, term)
    return {"decisions": rows, "trace": tr}


class AskIn(BaseModel):
    question: str = Field(min_length=1, max_length=300)


@app.post("/api/{tenant}/ask")
def ask(body: AskIn, request: Request, tenant: str = Depends(tenant_dep)):
    return agent.ask(tenant, body.question, sid=session_id(request))


@app.get("/api/{tenant}/bench")
def run_bench(agents: int = 50, seconds: float = 4.0, tenant: str = Depends(tenant_dep)):
    try:
        return bench.run_bench(tenant, agents, seconds)
    except RuntimeError as e:
        raise HTTPException(409, str(e))


class IngestIn(BaseModel):
    repo: str = Field(min_length=3, max_length=140)


@app.post("/api/ingest")
def start_ingest(body: IngestIn):
    try:
        return {"job": jobs.start(body.repo.strip())}
    except ingest.IngestError as e:
        raise HTTPException(422, str(e))
    except jobs.Busy as e:
        raise HTTPException(409, str(e))


@app.get("/api/ingest/{job_id}")
def ingest_status(job_id: str):
    if not re.fullmatch(r"[a-f0-9]{12}", job_id):
        raise HTTPException(404, "unknown job")
    j = jobs.get(job_id)
    if not j:
        raise HTTPException(404, "unknown job")
    return {k: j[k] for k in ("id", "repo", "status", "log", "tenant", "error")}


app.mount("/mcp", mcp_server.mcp.streamable_http_app())

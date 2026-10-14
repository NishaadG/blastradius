from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from redis.exceptions import RedisError

from . import agent, db, memory, queries as q, triage
from .tenants import TENANTS

app = FastAPI(title="Blastradius API", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.exception_handler(RedisError)
async def graph_down(_, exc: RedisError):
    # No fallback on purpose: every verdict is a graph traversal, so without FalkorDB there is nothing to say.
    return JSONResponse(status_code=503, content={"detail": f"FalkorDB unavailable: {exc}"})


def _tenant(t: str) -> str:
    if t not in TENANTS or t not in db.tenants_present():
        raise HTTPException(404, f"unknown or un-built tenant '{t}'")
    return t


@app.get("/api/health")
def health():
    return {"ok": True, "graphs": db.tenants_present()}  # raises RedisError -> 503 when the graph is down


@app.get("/api/tenants")
def tenants():
    out = []
    for t in db.tenants_present():
        if t in TENANTS:
            out.append({"id": t, "title": TENANTS[t]["title"], "repo": TENANTS[t]["repo"], **q.stats(t)})
    return out


@app.get("/api/{tenant}/graph")
def graph(tenant: str):
    data, trace = q.service_graph(_tenant(tenant))
    pr, _ = q.service_centrality(tenant)
    for n in data["nodes"]:
        n["centrality"] = pr.get(n["id"], 0)
    return {**data, "trace": trace}


@app.get("/api/{tenant}/risk")
def risk(tenant: str):
    return triage.risk_board(_tenant(tenant))


class TriageIn(BaseModel):
    identifier: str


@app.post("/api/{tenant}/triage")
def do_triage(tenant: str, body: TriageIn):
    return triage.run_triage(_tenant(tenant), body.identifier)


class DecideIn(BaseModel):
    advisory_id: str
    decision: str
    rationale: str
    actor: str = "you"
    services: list[str] = []
    eco: str | None = None


@app.post("/api/{tenant}/decide")
def decide(tenant: str, body: DecideIn):
    try:
        cid = memory.record_decision(_tenant(tenant), body.advisory_id, body.decision, body.rationale,
                                     body.actor, body.services, body.eco)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"case_id": cid}


@app.get("/api/{tenant}/brain")
def brain(tenant: str):
    return memory.brain_timeline(_tenant(tenant))


@app.post("/api/{tenant}/reset-memory")
def reset_memory(tenant: str):
    t = _tenant(tenant)
    db.write(t, "MATCH (n) WHERE n:Case OR n:Run OR n:Step DETACH DELETE n")
    db.write(t, "MATCH (p:Playbook) SET p.successes = 0, p.failures = 0")
    return {"ok": True}


@app.get("/api/{tenant}/service/{service}")
def service_card(tenant: str, service: str):
    t = _tenant(tenant)
    own, t1 = q.owners(t, service)
    exp, t2 = q.experts(t, service)
    dec, t3 = q.decisions(t, service)
    callers, t4 = q.upstream_callers(t, service)
    ep, t5 = q.exposure_path(t, service)
    return {"service": service, "owners": own, "experts": exp, "decisions": dec, "callers": callers,
            "exposure_path": ep, "traces": [t1, t2, t3, t4, t5]}


@app.get("/api/{tenant}/decisions")
def decisions(tenant: str, service: str = "", term: str = ""):
    rows, tr = q.decisions(_tenant(tenant), service, term)
    return {"decisions": rows, "trace": tr}


class AskIn(BaseModel):
    question: str


@app.post("/api/{tenant}/ask")
def ask(tenant: str, body: AskIn):
    return agent.ask(_tenant(tenant), body.question)

"""Tests for discovery, new parsers, MCP, the LLM tool loop, public-server hardening and repo analysis."""
import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from blastradius import agent, config, db, discover, ingest, memory, osv, queries as q, security, triage
from blastradius.api import app
from blastradius.parsers import parse_cargo_lock, parse_pom

BACKEND = Path(__file__).resolve().parent.parent
HAVE_BOUTIQUE = "boutique" in db.tenants_present()
needs_boutique = pytest.mark.skipif(not HAVE_BOUTIQUE, reason="boutique graph not built (python -m blastradius.build)")


@pytest.fixture(autouse=True)
def _fresh_limiter():
    security.limiter.hits.clear()


# ------------------------------------------------------------------ discovery
def test_discover_compose_resolves_dotenv_and_ignores_bare_ports():
    compose = """
services:
  web:
    ports: ["8080:8080"]
    environment: ["API_ADDR", "OTEL_SERVICE_NAME=web", "OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317"]
  api:
    ports: ["${API_PORT}"]
    environment:
      - DB_ADDR=db:5432
  db: {}
"""
    calls, exposed = discover.compose([compose], {"web", "api", "db"}, discover.parse_dotenv("API_ADDR=api:${API_PORT}\n"))
    assert calls == {("web", "api"), ("api", "db")}
    assert exposed == {"web"}  # a bare container port is not a deliberate exposure


def test_discover_kubernetes_calls_and_loadbalancer_exposure():
    k8s = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: frontend}
spec:
  template:
    spec:
      containers:
        - name: s
          env:
            - {name: CART_SERVICE_ADDR, value: "cart:7070"}
            - {name: PORT, value: "8080"}
---
apiVersion: v1
kind: Service
metadata: {name: frontend-external}
spec: {type: LoadBalancer, selector: {app: frontend}}
"""
    calls, exposed = discover.kubernetes([k8s], {"frontend", "cart"})
    assert calls == {("frontend", "cart")} and exposed == {"frontend"}


def test_parse_pom_resolves_properties_and_managed_versions():
    pom = """<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><log4j.v>2.14.1</log4j.v></properties>
    <dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>managed</artifactId><version>1.2</version></dependency></dependencies></dependencyManagement>
    <dependencies>
      <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.v}</version></dependency>
      <dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency>
      <dependency><groupId>g</groupId><artifactId>junit</artifactId><version>4.13</version><scope>test</scope></dependency>
      <dependency><groupId>g</groupId><artifactId>unresolved</artifactId></dependency>
    </dependencies></project>"""
    pkgs, edges = parse_pom(pom)
    assert "Maven:org.apache.logging.log4j:log4j-core@2.14.1" in pkgs and "Maven:g:managed@1.2" in pkgs
    assert pkgs["Maven:g:junit@4.13"]["dev"] is True
    assert not any("unresolved" in k for k in pkgs)


def test_parse_gradle_literal_coordinates_only():
    from blastradius.parsers import parse_gradle
    g = """dependencies {
        implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
        implementation("com.google.guava:guava:31.0-jre")
        testImplementation 'junit:junit:4.13'
        implementation "org.x:y:${someVersion}"   // variable: cannot resolve, skipped
        // implementation 'old:commented:1.0'
        id 'java'
    }"""
    pkgs, edges = parse_gradle(g)
    assert set(pkgs) == {"Maven:org.apache.logging.log4j:log4j-core@2.14.1", "Maven:com.google.guava:guava@31.0-jre", "Maven:junit:junit@4.13"}
    assert pkgs["Maven:junit:junit@4.13"]["dev"] is True


def test_parse_cargo_lock_edges():
    lock = """
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde", "tokio 1.0.0"]
[[package]]
name = "serde"
version = "1.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "tokio"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["serde"]
"""
    pkgs, edges = parse_cargo_lock(lock)
    assert set(pkgs) == {"crates.io:serde@1.0.1", "crates.io:tokio@1.0.0"}
    assert (None, "crates.io:tokio@1.0.0", False) in edges and ("crates.io:tokio@1.0.0", "crates.io:serde@1.0.1", False) in edges


# ------------------------------------------------------------------ analyse any repo (network mocked)
FAKE_POM = """<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId>
<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>"""
LOG4J_VULN = {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"], "summary": "Remote code injection in Log4j",
              "database_specific": {"severity": "CRITICAL"}, "published": "2021-12-10T00:00:00Z",
              "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                            "ranges": [{"events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}]}]}


class _Resp:
    def __init__(self, status=200, js=None, text=""):
        self.status_code, self._js, self.text, self.content = status, js, text, text.encode()

    def json(self):
        return self._js

    def raise_for_status(self):
        pass


@pytest.fixture
def fake_repo(monkeypatch):
    def fake_get(url, **kw):
        if "api.github.com" in url and "git/trees" in url:
            if "missing/repo" in url:
                return _Resp(404)
            return _Resp(js={"tree": [{"type": "blob", "path": "pom.xml", "size": 300},
                                      {"type": "blob", "path": "node_modules/x/package-lock.json", "size": 10}], "truncated": False})
        if "raw.githubusercontent.com" in url:
            return _Resp(text=FAKE_POM) if url.endswith("pom.xml") else _Resp(404)
        raise AssertionError(f"unexpected network call: {url}")

    from blastradius import depsdev
    monkeypatch.setattr(ingest.httpx, "get", fake_get)
    monkeypatch.setattr(depsdev, "_get", lambda *a: None)  # default: transitive resolution unavailable
    monkeypatch.setattr(osv, "query_packages", lambda pkgs: {k: ["GHSA-jfh8-c2jp-5v3q"] if "log4j-core" in k else [] for k in pkgs})
    monkeypatch.setattr(osv, "fetch_vulns", lambda ids: {i: LOG4J_VULN for i in ids if i == "GHSA-jfh8-c2jp-5v3q"})
    yield
    shutil.rmtree(config.CACHE_DIR / "raw" / "acme__shop-test", ignore_errors=True)
    try:
        db.graph("gh-acme-shop-test").delete()
    except Exception:
        pass


def test_analyse_repo_finds_real_java_log4shell_and_assumes_exposure(fake_repo):
    tenant = ingest.ingest_repo("acme/shop-test", lambda m: None)
    assert tenant == "gh-acme-shop-test"
    meta = q.tenant_meta(tenant)
    assert meta["kind"] == "byo" and meta["exposure_known"] is False
    r = triage.run_triage(tenant, "CVE-2021-44228")
    assert r["verdict"] == "AFFECTED" and r["priority"] == "P0"  # critical + unknown exposure -> assume the worst
    assert "unknown" in r["headline"].lower()
    assert r["services"][0]["paths"][0]["fixed"] == "2.15.0"
    assert not [s for s in q.service_graph(tenant)[0]["nodes"] if "node_modules" in s["id"]]  # vendored dirs skipped


def test_transitive_expansion_finds_vulnerability_a_manifest_parser_cannot_see(monkeypatch, fake_repo):
    """A pom lists only spring-boot-starter-log4j2; log4j-core arrives transitively (as in the real Log4Shell app)."""
    from blastradius import depsdev

    pom = """<project><dependencies><dependency><groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-log4j2</artifactId><version>2.6.1</version></dependency></dependencies></project>"""
    monkeypatch.setattr(ingest, "fetch", lambda repo, ref, path: pom if path.endswith("pom.xml") else None)
    resolved = {"nodes": [
        {"versionKey": {"system": "MAVEN", "name": "org.springframework.boot:spring-boot-starter-log4j2", "version": "2.6.1"}, "relation": "SELF"},
        {"versionKey": {"system": "MAVEN", "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1"}, "relation": "INDIRECT"}],
        "edges": [{"fromNode": 0, "toNode": 1}]}
    monkeypatch.setattr(depsdev, "_get", lambda system, name, version: resolved)
    tenant = ingest.ingest_repo("acme/shop-test", lambda m: None)
    r = triage.run_triage(tenant, "CVE-2021-44228", record=False)
    chain = [p.split(":", 1)[-1] for p in min(r["services"][0]["paths"], key=lambda p: p["hops"])["path"]]
    assert r["verdict"] == "AFFECTED"
    assert chain[1].startswith("org.springframework.boot:spring-boot-starter-log4j2") and chain[-1].startswith("org.apache.logging.log4j:log4j-core@2.14.1")


def test_rescan_finds_only_new_advisories_and_triages_them(monkeypatch, fake_repo):
    from blastradius import watch

    tenant = ingest.ingest_repo("acme/shop-test", lambda m: None)
    before = {r[0] for r in db.read(tenant, "MATCH (a:Advisory) RETURN a.id").result_set}
    assert before == {"GHSA-jfh8-c2jp-5v3q"}
    newer = {"id": "GHSA-new0-new0-new0", "aliases": ["CVE-2030-0001"], "summary": "Brand new bug in log4j-core",
             "database_specific": {"severity": "HIGH"}, "published": "2030-01-01T00:00:00Z",
             "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                           "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.99"}]}]}]}
    monkeypatch.setattr(osv, "query_packages",
                        lambda pkgs, fresh=False: {k: ["GHSA-jfh8-c2jp-5v3q", "GHSA-new0-new0-new0"] if "log4j-core" in k else [] for k in pkgs})
    monkeypatch.setattr(osv, "fetch_vulns", lambda ids: {i: newer for i in ids if i == "GHSA-new0-new0-new0"})
    out = watch.rescan(tenant, say=lambda m: None)
    assert [n["id"] for n in out["new"]] == ["GHSA-new0-new0-new0"] and out["new"][0]["priority"] == "P1"
    board = triage.risk_board(tenant)["advisories"]
    flags = {a["id"]: a["new"] for a in board}
    assert flags == {"GHSA-jfh8-c2jp-5v3q": False, "GHSA-new0-new0-new0": True}   # only the later find is marked new
    assert watch.rescan(tenant, say=lambda m: None)["new"] == []                  # a second scan finds nothing new


def test_analyse_repo_rejects_bad_input_and_private_repos(fake_repo):
    with pytest.raises(ingest.IngestError):
        ingest.discover_repo("not a repo")
    with pytest.raises(ingest.IngestError):
        ingest.discover_repo("../../etc/passwd")
    with pytest.raises(ingest.IngestError, match="not found"):
        ingest.discover_repo("missing/repo")


# ------------------------------------------------------------------ public-server hardening
def test_input_validation_and_unknown_tenant():
    c = TestClient(app)
    assert c.get("/api/..%2f..%2fetc/graph").status_code in (404, 422)
    assert c.get("/api/Not_A_Tenant/risk").status_code == 404
    assert c.post("/api/nope/triage", json={"identifier": "CVE-2026-1"}).status_code == 404
    assert c.post("/api/ingest", json={"repo": "bad repo name"}).status_code == 422


@needs_boutique
def test_identifier_and_field_validation_on_real_tenant():
    c = TestClient(app)
    for bad in ("../../v1/query", "CVE-2026-1; MATCH (n) DETACH DELETE n", "a" * 80, "x y"):
        assert c.post("/api/boutique/triage", json={"identifier": bad}).status_code in (422,), bad
    assert c.post("/api/boutique/decide", json={"advisory_id": "CVE-2026-41242", "decision": "yolo", "rationale": "x"}).status_code == 422
    assert c.post("/api/boutique/decide", json={"advisory_id": "CVE-2026-41242", "decision": "patched", "rationale": "x",
                                                 "services": ["not-a-service"]}).status_code == 422
    assert c.post("/api/boutique/decide", json={"advisory_id": "CVE-2026-41242", "decision": "patched", "rationale": "x" * 501}).status_code == 422
    assert c.get("/api/boutique/service/..%2fx").status_code in (404, 422)


@needs_boutique
def test_sessions_cannot_see_or_wipe_each_other():
    c = TestClient(app)
    a, b = {"X-Session": "session-aaaaaaaa"}, {"X-Session": "session-bbbbbbbb"}
    for h in (a, b):
        c.post("/api/boutique/reset-memory", headers=h)
    r = c.post("/api/boutique/triage", json={"identifier": "CVE-2026-41242"}, headers=a).json()
    c.post("/api/boutique/decide", json={"advisory_id": "CVE-2026-41242", "decision": "patched", "rationale": "A did it",
                                          "services": [s["service"] for s in r["services"]], "eco": "npm"}, headers=a)
    assert len(c.get("/api/boutique/brain", headers=a).json()["cases"]) == 1
    assert c.get("/api/boutique/brain", headers=b).json()["cases"] == []        # B cannot see A's memory
    again_b = c.post("/api/boutique/triage", json={"identifier": "CVE-2026-41242"}, headers=b).json()
    assert again_b["precedents"] == []                                           # ...and it never becomes B's precedent
    c.post("/api/boutique/reset-memory", headers=b)                              # B resets
    assert len(c.get("/api/boutique/brain", headers=a).json()["cases"]) == 1    # A's memory survives
    c.post("/api/boutique/reset-memory", headers=a)


def test_rate_limiter_blocks_a_flood_but_not_normal_use():
    lim = security.Limiter()
    assert all(lim.allow("b", "1.2.3.4", 5, 60) for _ in range(5))
    assert not lim.allow("b", "1.2.3.4", 5, 60)
    assert lim.allow("b", "9.9.9.9", 5, 60)  # another client is unaffected


def test_ingest_endpoint_is_rate_limited():
    c = TestClient(app)
    codes = [c.post("/api/ingest", json={"repo": "bad repo"}).status_code for _ in range(5)]
    assert codes[:3] == [422, 422, 422] and codes[3:] == [429, 429]


def test_oversized_body_rejected():
    c = TestClient(app)
    r = c.post("/api/boutique/ask", content=b"x" * 30_000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_osv_id_validator():
    assert osv.valid_id("CVE-2021-44228") and osv.valid_id("GHSA-jfh8-c2jp-5v3q")
    for bad in ("../x", "a/b", "CVE 1", "", "x" * 100, "CVE-1?x=y"):
        assert not osv.valid_id(bad)


def test_database_backpressure_is_retried_not_surfaced():
    from redis.exceptions import ResponseError

    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ResponseError("Max pending queries exceeded")
        return "ok"

    before = db.backpressure_retries()
    assert db._with_backoff(flaky) == "ok" and calls["n"] == 3
    assert db.backpressure_retries() - before == 2


def test_other_database_errors_are_not_swallowed():
    from redis.exceptions import ResponseError

    def broken():
        raise ResponseError("Invalid input")

    with pytest.raises(ResponseError):
        db._with_backoff(broken)


# ------------------------------------------------------------------ LLM tool loop against a mock model
@needs_boutique
def test_gemini_tool_loop_calls_tools_and_feeds_results_back(monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        body = json.loads(request.content)
        seen["key_header"] = request.headers.get("x-goog-api-key")
        seen.setdefault("rounds", 0)
        seen["rounds"] += 1
        if seen["rounds"] == 1:
            return httpx.Response(200, json={"candidates": [{"content": {"parts": [
                {"functionCall": {"name": "who_owns", "args": {"service": "paymentservice"}}},
                {"functionCall": {"name": "blast_radius", "args": {"service": "../../etc/passwd"}}}]}}]})
        fr = [p["functionResponse"] for p in body["contents"][-1]["parts"]]
        seen["responses"] = fr
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "paymentservice is owned by the maintainers."}]}}]})

    monkeypatch.setattr(agent, "_http", lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    out = agent.ask("boutique", "who owns the payment service?")
    assert out["mode"] == "gemini" and out["answer"].startswith("paymentservice is owned")
    assert seen["key_header"] == "test-key"                      # key travels in a header, not the URL
    assert [c["tool"] for c in out["tool_calls"]] == ["who_owns", "blast_radius"]
    ok, bad = seen["responses"]
    assert ok["response"]["result"]["owners"]                    # real graph data reached the model
    assert "error" in bad["response"]["result"]                  # malformed argument rejected, not executed


@needs_boutique
def test_llm_failure_falls_back_to_deterministic_router(monkeypatch):
    monkeypatch.setattr(agent, "_http", lambda: httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500))))
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    out = agent.ask("boutique", "who owns paymentservice?")
    assert out["mode"] == "offline-router" and "paymentservice" in out["answer"]


# ------------------------------------------------------------------ MCP server over stdio
@needs_boutique
def test_mcp_server_public_mode_is_read_only_and_answers():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    def runs(sid):
        return q._run("boutique", "MATCH (r:Run {sid:$s}) RETURN count(r)", {"s": sid})[0][0][0]

    before = runs("mcp")

    async def go():
        params = StdioServerParameters(command=sys.executable, args=["-m", "blastradius.mcp_server"],
                                       env={**os.environ, "BR_PUBLIC": "1"}, cwd=str(BACKEND))
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                tools = {t.name for t in (await s.list_tools()).tools}
                res = await s.call_tool("triage_advisory", {"tenant": "boutique", "identifier": "CVE-2026-41242"})
                bad = await s.call_tool("triage_advisory", {"tenant": "boutique", "identifier": "../../x"})
                return tools, res, bad

    tools, res, bad = asyncio.run(go())
    assert {"list_tenants", "risk_board", "triage_advisory", "blast_radius", "who_owns", "service_brain"} <= tools
    assert "record_decision" not in tools                        # no write tool on a public server
    payload = json.loads(res.content[0].text)
    assert payload["verdict"] == "AFFECTED" and payload["services"]
    assert "error" in json.loads(bad.content[0].text)
    assert runs("mcp") == before                                  # read-only: the triage left no trace

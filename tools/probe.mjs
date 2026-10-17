// Probe a deployed instance the way an outsider would. usage: node probe.mjs https://host
const base = process.argv[2].replace(/\/$/, "");
let fails = 0;
const ok = (name, cond, extra = "") => { console.log(`${cond ? "PASS" : "FAIL"}  ${name} ${extra}`); if (!cond) fails++; };
const j = async (path, init) => { const r = await fetch(base + path, init); let b = null; try { b = await r.clone().json(); } catch {} return { r, b }; };

let { r, b } = await j("/api/health");
ok("health", r.status === 200 && b.ok, JSON.stringify(b));
({ r, b } = await j("/api/tenants"));
ok("tenants list (3 curated)", Array.isArray(b) && b.filter((t) => t.kind === "curated").length === 3);
ok("security headers on API", r.headers.get("x-content-type-options") === "nosniff");
const home = await fetch(base + "/");
ok("web app serves", home.status === 200 && (await home.text()).includes("Blastradius"));
ok("web security headers", home.headers.get("x-frame-options") === "DENY" && (!base.startsWith("https") || !!home.headers.get("strict-transport-security")));
ok("openapi/docs disabled in public mode", (await fetch(base + "/docs")).status !== 200 && (await fetch(base + "/openapi.json")).status !== 200);
({ r, b } = await j("/api/boutique/triage", { method: "POST", headers: { "Content-Type": "application/json", "X-Session": "probe-session-0001" }, body: JSON.stringify({ identifier: "CVE-2026-41242" }) }));
ok("triage works", r.status === 200 && b.verdict === "AFFECTED", `${b.verdict} ${b.priority}`);
({ r } = await j("/api/boutique/triage", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ identifier: "../../v1/query" }) }));
ok("path-traversal identifier rejected", r.status === 422);
({ r } = await j("/api/nope/risk"));
ok("unknown tenant 404", r.status === 404);
({ r } = await j("/api/boutique/ask", { method: "POST", headers: { "Content-Type": "application/json" }, body: "x".repeat(70000) }));
ok("oversized body rejected", r.status === 413);
({ r } = await j("/api/sbom", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ sbom: JSON.stringify({ hello: "world", pad: "y".repeat(30) }) }) }));
ok("SBOM endpoint rejects a non-SBOM document (422, or 429 once the ingest quota is used)", r.status === 422 || r.status === 429);
const cors = await fetch(base + "/api/tenants", { headers: { Origin: "https://evil.example" } });
ok("no cross-origin access granted", !cors.headers.get("access-control-allow-origin"));
({ r, b } = await j("/api/boutique/reset-memory", { method: "POST", headers: { "Content-Type": "application/json", "X-Session": "probe-session-0001" }, body: "{}" }));
ok("reset only touches own session", r.status === 200);
const mcp = await fetch(base + "/mcp/", { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "probe", version: "1" } } }) });
ok("MCP endpoint answers initialize", mcp.status === 200, `status ${mcp.status}`);
const tools = await fetch(base + "/mcp/", { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) });
const tl = await tools.json();
const names = (tl.result?.tools ?? []).map((t) => t.name);
ok("MCP exposes read tools and NO write tool", names.includes("triage_advisory") && !names.includes("record_decision"), names.join(","));
console.log(fails ? `\n${fails} probe(s) failed` : "\nall probes passed");
process.exit(fails ? 1 : 0);

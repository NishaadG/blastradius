# "No path found" is the most useful thing a security agent can say

*Building Blastradius for Graph Hacks with FalkorDB*

Every time a new CVE lands, someone asks the same four questions: **Are we affected? Through which dependency? Who owns that service? Did we already deal with something like this?** Most tools answer with a list. The honest answer is a *path*.

## The problem with "similar text"
Most agent demos retrieve context by embedding similarity. That is fine for "find the doc that sounds like this". It is the wrong tool for *"does this vulnerable package reach a service that faces the internet?"*, because that is a question about **connections**, and similarity can't prove a connection exists or doesn't.

A graph can. In Blastradius the question is one traversal:

```cypher
MATCH (a:Advisory {id:$id})-[e:AFFECTS]->(p:Package)
MATCH (s:Service)
WITH a, e, p, s, shortestPath((s)-[:DEPENDS_ON*1..15]->(p)) AS path
WHERE path IS NOT NULL
RETURN s.name, p.name, p.version, e.fixed, length(path), [n IN nodes(path) | coalesce(n.key, n.name)]
```

Run it on a real project (Google's Online Boutique, with real lockfiles and real OSV advisories) and a critical `protobufjs` RCE resolves, in tens of milliseconds, to:

`frontend → checkoutservice → paymentservice → @opentelemetry/exporter-otlp-grpc → @grpc/proto-loader → protobufjs@6.11.4`

with the internet-facing entry point, the owning team, and the fixed version, all from the same graph.

## Proof by absence
Ask about Log4Shell and the same query returns **zero rows**. That is not a failure; it is the answer. Nothing in the graph depends on a Maven package, so the verdict is `NOT_AFFECTED`, with the empty traversal on screen as the evidence. Ask about an advisory for a package you *do* run, but at a patched version, and the graph explains *why* it's safe: the package is present, the version is outside the affected range.

## The LLM doesn't get to decide
The verdict (`AFFECTED / NOT_AFFECTED / NEEDS_HUMAN`) comes from plain rules over graph evidence. The LLM, optional and free-tier, only chooses which tool to call and phrases the result. It never sees a database credential or writes Cypher; the read path is rejected for writes and enforced read-only by the database too. Remediation actions are proposals that wait for a human.

## Memory that is also a graph
When a human approves a fix, the decision is written back as a `Case` node linked to the advisory, the affected services and the playbook used. Days later a *different* `protobufjs` advisory arrives, and a three-hop traversal `(Case)-[:ABOUT]->(Advisory)-[:AFFECTS]->(Package)` finds the earlier case. The agent cites it and reuses the playbook; the playbook's success counter ticks up. Memory, dependency data and ownership live in one graph, so the agents' handoffs (`Step-[:HANDS_OFF_TO]->Step`) are queryable too.

Each tenant gets its **own FalkorDB graph**, so isolation is structural rather than a `WHERE tenant = …` you hope nobody forgets.

## A company brain with receipts
Ownership comes from `CODEOWNERS`, expertise from commit history, and dependency decisions link to the exact commit that made them. A `SUPERSEDES` edge marks decisions that were later overtaken, so the answer to "why do we pin this?" says whether the reasoning is still current.

Commits say what changed, not why, so a build step also reads the pull request behind each dependency change and has Gemini extract the decision and the stated reason. The model is boxed in: it may only restate what the PR says, an empty rationale stays empty, and a package is linked to a decision only if its name literally appears in the PR or commit text. Two evals enforce this, and the second one caught the model inventing a subject (`otlp-exporters`, a paraphrase, not a package) on the first run. Now "why did we upgrade golang.org/x/net?" is answered with the CVEs and the PR links.

## The topology is discovered, not typed in
Early on I hand-wrote which service calls which. That's the weakest part of any demo, so I replaced it: Blastradius now reads the project's own deployment files. In Online Boutique's Kubernetes manifests, `PRODUCT_CATALOG_SERVICE_ADDR=productcatalogservice:3550` is a call and a `LoadBalancer` Service is an internet exposure. In the OpenTelemetry demo's Compose file, bare env names resolve through `.env`, and only a real `host:container` port mapping counts as exposure. Checked against my old hand-written list, discovery recovered 100% of the OpenTelemetry edges (and found 7 the docs never mention), 100% of Bank of Anthos's (whose addresses hide inside ConfigMaps and `jdbc:` URLs) and 94% of Boutique's; the one it misses is in no deployment file at all, and the eval report says so.

## Any public repo, including the paths manifests hide
Paste `owner/name` and Blastradius finds the manifests, asks [deps.dev](https://deps.dev) for the resolved dependency tree when a manifest lists only direct dependencies, and builds a tenant graph. Pointed at a deliberately vulnerable Java app, it finds Log4Shell as `app → spring-boot-starter-log4j2 → log4j-core@2.14.1`. The build file never mentions log4j-core; a static parser sees nothing. A graph of resolved dependencies sees the whole chain.

## One graph, many AI clients
The same toolkit is exposed as an MCP server, so Claude Desktop, Claude Code or any MCP client can ask the graph directly, and as a tool-calling loop for the chat box. The model can only call validated, read-only tools; it never sees Cypher.

## How do we know it's right?
Ground truth is computed *without* the graph from the raw lockfiles, cached OSV data, the discovered topology and `CODEOWNERS`, then compared to the product: affected-service sets and verdicts for every advisory in three real projects, that every returned path is a real chain of lockfile edges, exposure distances, ownership, transitive callers, memory reuse, and tenant and session isolation. 54 of 54 pass, plus 38 unit tests and guardrail checks (write queries are rejected on the agent path).

## Under load, honestly
Track 2 mentions high-concurrency shared state, so I benchmarked it: 10, 50 and 100 agents hammering one graph. Reads stay fast; FalkorDB serialises writes, so write latency queues. At 100 agents my first run saw about 2% of operations rejected with `Max pending queries exceeded`. That's FalkorDB protecting itself, so the client now retries with jittered backoff and counts every retry in the results instead of hiding them.

## The "is the graph decoration?" test
Stop the FalkorDB container. The UI turns red and nothing answers: no cache, no fallback, by design. Start it, and everything resumes. If removing the database leaves the product working, the database was decoration. Here, it is the product.

## Reachable, not just present
For Go services, Blastradius runs Google's `govulncheck` and stores the call-graph result on the edge between service and advisory. A P0 whose vulnerable function is never called is demoted with the reason; one that is called shows the actual stack, from `main` down to the vulnerable function.

## It notices, and it blocks
A watcher re-queries OSV on a schedule and flags advisories published since the graph was built. A CLI and GitHub Action analyse a checkout, write SARIF and fail a pull request only for findings that change *introduces* compared to the base branch.

## What's next
Function-level reachability beyond Go, SBOM import, and building the `CALLS` edges from OpenTelemetry traces instead of reading them from deployment files.

*Built with FalkorDB, Cypher, FastAPI, Next.js and Cytoscape. Everything runs locally for $0. Developed with Claude Code as a coding assistant (disclosed per the hackathon rules).*

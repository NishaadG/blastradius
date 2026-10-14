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

## How do we know it's right?
Ground truth is computed *without* the graph from the raw lockfiles, cached OSV data, the call list and `CODEOWNERS`, then compared to the product: affected-service sets and verdicts for all 96 advisories, that every returned path is a real chain of lockfile edges, exposure distances, ownership, transitive callers, memory reuse and tenant isolation. 27 of 27 pass. There are also guardrail checks: write queries are rejected on the agent path.

## The "is the graph decoration?" test
Stop the FalkorDB container. The UI turns red and nothing answers: no cache, no fallback, by design. Start it, and everything resumes. If removing the database leaves the product working, the database was decoration. Here, it is the product.

## What's next
Function-level reachability, SBOM import, and building the `CALLS` edges from OpenTelemetry traces instead of curating them.

*Built with FalkorDB, Cypher, FastAPI, Next.js and Cytoscape. Everything runs locally for $0. Developed with Claude Code as a coding assistant (disclosed per the hackathon rules).*

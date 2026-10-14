# Demo video script (about 2:45)

Record at 1080p+. Run the app, open `http://localhost:3001`, and either click **Guided demo** or drive it by hand. `tools/demo.mjs` records the guided run to a `.webm` automatically; add the voiceover on top.

| Time | On screen | Voiceover |
|---|---|---|
| 0:00 | Landing: risk board + service graph | "Every time a CVE drops, someone has to answer: are we affected, through what, and who owns it? Blastradius answers with a graph." |
| 0:15 | Triage `CVE-2026-41242` → path animates hop by hop | "A critical protobufjs RCE. The agent follows the graph from the internet-exposed frontend, through checkout and payment, down the dependency chain to the vulnerable package." |
| 0:35 | Handoff timeline, expand a Cypher block | "Three agents hand off through the graph. Every step shows the exact Cypher and its latency. The verdict comes from a deterministic judge, not the LLM." |
| 0:55 | Click **Approve fix** → Memory tab | "A human approves. The decision is written back as memory: a case, linked to the advisory, the services, and the playbook." |
| 1:10 | Triage `CVE-2026-48712` → precedent card | "A different protobufjs advisory arrives. A three-hop traversal finds the earlier case. The agent cites it and reuses the playbook." |
| 1:35 | Triage `GHSA-jfh8-c2jp-5v3q` (Log4Shell) | "Log4Shell? Zero paths. In a graph, 'no path found' is proof, not a failure." |
| 1:55 | Company tab → paymentservice | "The company brain: owners from CODEOWNERS, expertise from commits, and decisions traced to the source commit, with staleness marked." |
| 2:15 | Switch tenant → Memory empty | "Each tenant is its own FalkorDB graph. Memory can't leak across them." |
| 2:30 | `docker stop` FalkorDB → red banner | "And the test that matters: stop FalkorDB and the product stops. The graph isn't decoration. It's the product." |
| 2:42 | Title card: repo, EVALS 27/27, $0 | "Open source, runs locally for free, 27 of 27 correctness checks against an independent computation." |

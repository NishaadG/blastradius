# Evaluation

Ground truth is computed **without the graph** (raw lockfiles, cached OSV data, topology discovered from deployment files, CODEOWNERS) and compared with what the FalkorDB-backed product returns.

**57/57 checks passed.**

| Group | Check | Result | Detail |
|---|---|---|---|
| otel/coverage | every OSV advisory for this tenant's packages is in the graph | PASS | 8 vs 8 |
| otel/affected-services | affected service set equals independent computation for 8 advisories | PASS | 0 mismatches |
| otel/path-validity | every returned path is a real chain of lockfile edges ending at an affected package | PASS | 0 invalid |
| otel/verdicts | deterministic verdict equals independent rule for 8 advisories | PASS | 0 mismatches |
| otel/exposure | internet-exposure distance matches BFS over discovered topology for 18 services | PASS | 0 mismatches |
| otel/call-graph | graph stores exactly the 21 discovered service calls | PASS | 21 in graph |
| otel/discovery-vs-docs | discovery recovers the hand-written call list from the project docs (recall 100%); 7 additional call(s) found only in deployment files | PASS | missing: [] |
| otel/ownership | owners equal CODEOWNERS for 18 services | PASS | 0 mismatches |
| otel/blast-radius | transitive upstream callers equal reverse-BFS for 18 services | PASS | 0 mismatches |
| otel/reachability | govulncheck findings stored with identical call-graph level (11 checked) | PASS | 0 mismatches |
| otel/pr-reasoning | 37 decisions carry the reasoning and link of their PR exactly as extracted | PASS | 0 mismatches |
| otel/pr-grounding | every package a decision is linked to appears in its PR or commit text (no invented subjects) | PASS | 0 ungrounded |
| otel/sbom | CycloneDX export round-trips: 1576 packages and 2591 dependency edges identical, 8 advisories attached | PASS | 0 package diffs, 0 edge diffs |
| otel/company-brain | expertise includes real human contributors, not only bots | PASS | 118 person-service links |
| boutique/coverage | every OSV advisory for this tenant's packages is in the graph | PASS | 88 vs 88 |
| boutique/affected-services | affected service set equals independent computation for 88 advisories | PASS | 0 mismatches |
| boutique/path-validity | every returned path is a real chain of lockfile edges ending at an affected package | PASS | 0 invalid |
| boutique/verdicts | deterministic verdict equals independent rule for 88 advisories | PASS | 0 mismatches |
| boutique/exposure | internet-exposure distance matches BFS over discovered topology for 12 services | PASS | 0 mismatches |
| boutique/call-graph | graph stores exactly the 16 discovered service calls | PASS | 16 in graph |
| boutique/discovery-vs-docs | discovery recovers the hand-written call list from the project docs (recall 94%); 0 additional call(s) found only in deployment files | PASS | missing: [('shoppingassistantservice', 'productcatalogservice')] |
| boutique/ownership | owners equal CODEOWNERS for 12 services | PASS | 0 mismatches |
| boutique/blast-radius | transitive upstream callers equal reverse-BFS for 12 services | PASS | 0 mismatches |
| boutique/reachability | govulncheck findings stored with identical call-graph level (30 checked) | PASS | 0 mismatches |
| boutique/pr-reasoning | 12 decisions carry the reasoning and link of their PR exactly as extracted | PASS | 0 mismatches |
| boutique/pr-grounding | every package a decision is linked to appears in its PR or commit text (no invented subjects) | PASS | 0 ungrounded |
| boutique/sbom | CycloneDX export round-trips: 476 packages and 504 dependency edges identical, 88 advisories attached | PASS | 0 package diffs, 0 edge diffs |
| boutique/company-brain | expertise includes real human contributors, not only bots | PASS | 50 person-service links |
| anthos/coverage | every OSV advisory for this tenant's packages is in the graph | PASS | 19 vs 19 |
| anthos/affected-services | affected service set equals independent computation for 19 advisories | PASS | 0 mismatches |
| anthos/path-validity | every returned path is a real chain of lockfile edges ending at an affected package | PASS | 0 invalid |
| anthos/verdicts | deterministic verdict equals independent rule for 19 advisories | PASS | 0 mismatches |
| anthos/exposure | internet-exposure distance matches BFS over discovered topology for 9 services | PASS | 0 mismatches |
| anthos/call-graph | graph stores exactly the 15 discovered service calls | PASS | 15 in graph |
| anthos/discovery-vs-docs | discovery recovers the hand-written call list from the project docs (recall 100%); 3 additional call(s) found only in deployment files | PASS | missing: [] |
| anthos/ownership | owners equal CODEOWNERS for 9 services | PASS | 0 mismatches |
| anthos/blast-radius | transitive upstream callers equal reverse-BFS for 9 services | PASS | 0 mismatches |
| anthos/reachability | govulncheck findings stored with identical call-graph level (0 checked) | PASS | 0 mismatches |
| anthos/pr-reasoning | 8 decisions carry the reasoning and link of their PR exactly as extracted | PASS | 0 mismatches |
| anthos/pr-grounding | every package a decision is linked to appears in its PR or commit text (no invented subjects) | PASS | 0 ungrounded |
| anthos/sbom | CycloneDX export round-trips: 136 packages and 194 dependency edges identical, 19 advisories attached | PASS | 0 package diffs, 0 edge diffs |
| anthos/company-brain | expertise includes real human contributors, not only bots | PASS | 26 person-service links |
| scenario | Log4Shell (Maven) is NOT_AFFECTED by proof of absence | PASS |  |
| scenario | protobufjs advisory with a fixed version in use is NOT_AFFECTED (version outside range) | PASS | CVE-2023-36665 targets protobufjs, but you run 6.11.4, 7.6.5, 7.6.6, 7.5.9: outside the affected range. |
| scenario | unknown identifier is NEEDS_HUMAN, never guessed | PASS |  |
| scenario | top-ranked advisory is AFFECTED and every action is gated | PASS |  |
| memory | a decision on one protobufjs advisory is cited when triaging another | PASS |  |
| memory | the same advisory finds its exact precedent | PASS |  |
| memory | tenant isolation: boutique memory is invisible to otel | PASS |  |
| memory | session isolation: another visitor never sees this memory | PASS |  |
| guardrails | read path rejects write query: MATCH (n) DETACH DELETE n | PASS |  |
| guardrails | read path rejects write query: CREATE (:X) | PASS |  |
| guardrails | read path rejects write query: MATCH (n) SET n.x = 1 | PASS |  |
| guardrails | read path rejects write query: MERGE (:Y) | PASS |  |
| guardrails | database itself rejects writes on the read-only path (defence in depth) | PASS |  |
| guardrails | query timeout and row cap configured | PASS |  |
| guardrails | advisory identifiers are validated before reaching any URL | PASS |  |

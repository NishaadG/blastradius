# Evaluation

Ground truth is computed **without the graph** (raw lockfiles, cached OSV data, curated call list, CODEOWNERS) and compared with what the FalkorDB-backed product returns.

**27/27 checks passed.**

| Group | Check | Result | Detail |
|---|---|---|---|
| otel/coverage | every OSV advisory in the cache is in the graph | PASS | 8 vs 8 |
| otel/affected-services | affected service set equals independent computation for 8 advisories | PASS | 0 mismatches |
| otel/path-validity | every returned path is a real chain of lockfile edges ending at an affected package | PASS | 0 invalid |
| otel/verdicts | deterministic verdict equals independent rule for 8 advisories | PASS | 0 mismatches |
| otel/exposure | internet-exposure distance matches BFS for 17 services | PASS | 0 mismatches |
| otel/ownership | owners equal CODEOWNERS for 17 services | PASS | 0 mismatches |
| otel/blast-radius | transitive upstream callers equal reverse-BFS for 17 services | PASS | 0 mismatches |
| boutique/coverage | every OSV advisory in the cache is in the graph | PASS | 88 vs 88 |
| boutique/affected-services | affected service set equals independent computation for 88 advisories | PASS | 0 mismatches |
| boutique/path-validity | every returned path is a real chain of lockfile edges ending at an affected package | PASS | 0 invalid |
| boutique/verdicts | deterministic verdict equals independent rule for 88 advisories | PASS | 0 mismatches |
| boutique/exposure | internet-exposure distance matches BFS for 12 services | PASS | 0 mismatches |
| boutique/ownership | owners equal CODEOWNERS for 12 services | PASS | 0 mismatches |
| boutique/blast-radius | transitive upstream callers equal reverse-BFS for 12 services | PASS | 0 mismatches |
| scenario | Log4Shell (Maven) is NOT_AFFECTED by proof of absence | PASS |  |
| scenario | protobufjs advisory with a fixed version in use is NOT_AFFECTED (version outside range) | PASS | CVE-2023-36665 targets protobufjs, but you run 6.11.4, 7.6.5, 7.6.6, 7.5.9: outside the affected range. |
| scenario | unknown identifier is NEEDS_HUMAN, never guessed | PASS |  |
| scenario | top-ranked advisory is AFFECTED and every action is gated | PASS |  |
| memory | a decision on one protobufjs advisory is cited when triaging another | PASS |  |
| memory | the same advisory finds its exact precedent | PASS |  |
| memory | tenant isolation: boutique memory is invisible to otel | PASS |  |
| guardrails | read path rejects write query: MATCH (n) DETACH DELETE n | PASS |  |
| guardrails | read path rejects write query: CREATE (:X) | PASS |  |
| guardrails | read path rejects write query: MATCH (n) SET n.x = 1 | PASS |  |
| guardrails | read path rejects write query: MERGE (:Y) | PASS |  |
| guardrails | database itself rejects writes on the read-only path (defence in depth) | PASS |  |
| guardrails | query timeout and row cap configured | PASS |  |

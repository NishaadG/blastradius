"""SBOM in, SBOM out.

Import: a CycloneDX (JSON) or SPDX (JSON) document becomes a tenant graph exactly like a repository does. Packages come
from each component's purl, edges from CycloneDX `dependencies` / SPDX `relationships` (a flat list when the SBOM carries
no graph). Export: a tenant's graph as CycloneDX 1.5 with the advisories that apply (`vulnerabilities[].affects`).

    python -m blastradius.sbom import bom.json        # -> tenant id
"""
import hashlib
import json
import sys
import urllib.parse

from .parsers import ECO_CARGO, ECO_GO, ECO_MAVEN, ECO_NPM, ECO_PYPI, pkey

PURL_ECO = {"npm": ECO_NPM, "pypi": ECO_PYPI, "golang": ECO_GO, "maven": ECO_MAVEN, "cargo": ECO_CARGO}
ECO_PURL = {v: k for k, v in PURL_ECO.items()}
MAX_BYTES = 3_000_000


class SbomError(ValueError):
    """A user-facing problem with the uploaded document."""


def parse_purl(purl: str):
    """pkg:type/namespace/name@version?qualifiers -> (eco, name, version), or None for unsupported types."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    typ, _, rest = body.partition("/")
    eco = PURL_ECO.get(typ.lower())
    if not eco or "@" not in rest:
        return None
    path, _, ver = rest.rpartition("@")
    ver = urllib.parse.unquote(ver)
    parts = [urllib.parse.unquote(p) for p in path.split("/") if p]
    if not parts or not ver:
        return None
    if eco == ECO_MAVEN:
        name = ":".join(parts)
    elif eco == ECO_PYPI:
        name = parts[-1].lower().replace("_", "-")
    else:
        name = "/".join(parts)
    if eco == ECO_GO:
        ver = ver.lstrip("v")
    return eco, name, ver


def _norm(doc):
    """-> (name, components [{ref,purl,dev}], dependency edges [(ref, ref)], root refs)."""
    if isinstance(doc, dict) and doc.get("bomFormat") == "CycloneDX":
        meta = (doc.get("metadata") or {}).get("component") or {}
        comps = [{"ref": c.get("bom-ref") or c.get("purl"), "purl": c.get("purl"), "dev": c.get("scope") == "excluded"}
                 for c in doc.get("components", [])]
        edges = [(d["ref"], t) for d in doc.get("dependencies", []) for t in d.get("dependsOn", [])]
        root = meta.get("bom-ref")
        roots = [t for d in doc.get("dependencies", []) if d.get("ref") == root for t in d.get("dependsOn", [])]
        return meta.get("name") or "sbom", comps, edges, roots
    if isinstance(doc, dict) and str(doc.get("spdxVersion", "")).startswith("SPDX"):
        comps = []
        for p in doc.get("packages", []):
            purl = next((r.get("referenceLocator") for r in p.get("externalRefs", []) if r.get("referenceType") == "purl"), None)
            comps.append({"ref": p.get("SPDXID"), "purl": purl, "dev": False})
        rels = doc.get("relationships", [])
        edges = [(r["spdxElementId"], r["relatedSpdxElement"]) for r in rels if r.get("relationshipType") == "DEPENDS_ON"]
        described = {r["relatedSpdxElement"] for r in rels
                     if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == "SPDXRef-DOCUMENT"}
        roots = [t for a, t in edges if a in described]
        return doc.get("name") or "sbom", comps, edges, roots
    raise SbomError("Not a CycloneDX or SPDX JSON document.")


def parse_sbom(text: str):
    """The PARSERS contract: -> (packages, edges). Components with unsupported purl types are skipped."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        raise SbomError("The file is not valid JSON. CycloneDX and SPDX JSON are supported.")
    _, comps, dep_edges, roots = _norm(doc)
    pkgs, key_of = {}, {}
    for c in comps:
        p = parse_purl(c["purl"] or "")
        if not p or not c["ref"]:
            continue
        k = pkey(*p)
        key_of[c["ref"]] = k
        pkgs[k] = {"eco": p[0], "name": p[1], "version": p[2], "dev": c["dev"]}
    if not pkgs:
        raise SbomError("No packages with a supported purl (npm, pypi, golang, maven, cargo) were found.")
    edges, has_parent = [], set()
    for a, b in dep_edges:
        if a in key_of and b in key_of:
            edges.append((key_of[a], key_of[b], pkgs[key_of[b]]["dev"]))
            has_parent.add(key_of[b])
    direct = {key_of[r] for r in roots if r in key_of} or {k for k in pkgs if k not in has_parent}
    edges += [(None, k, pkgs[k]["dev"]) for k in sorted(direct)]
    return pkgs, edges


def app_name(text: str) -> str:
    try:
        n = _norm(json.loads(text))[0]
    except Exception:
        n = "sbom"
    return "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in str(n))[:40].strip("-") or "sbom"


def tenant_id_for_sbom(text: str) -> str:
    return "sbom-" + hashlib.sha256(text.encode()).hexdigest()[:10]


def ingest_sbom(text: str, say=print) -> str:
    from . import ingest

    if len(text.encode()) > MAX_BYTES:
        raise SbomError("SBOM is larger than 3 MB; run Blastradius locally for files this size.")
    parse_sbom(text)  # validate before touching the graph
    tenant = tenant_id_for_sbom(text)
    repo = f"local/{tenant}"
    name = app_name(text)
    ingest.LOCAL_TEXT[repo] = {"sbom.json": text}
    try:
        say(f"SBOM: {name}")
        ingest.build_graph(tenant, {"title": f"{name} (SBOM)", "repo": repo, "kind": "byo"},
                           [{"name": name, "path": "", "kind": "sbom", "file": "sbom.json"}], set(), set(), False, "HEAD", say)
    finally:
        ingest.LOCAL_TEXT.pop(repo, None)
    return tenant


def export_cyclonedx(tenant: str) -> dict:
    from . import db, queries as q, triage

    meta = q.tenant_meta(tenant)
    rows = db.read(tenant, "MATCH (p:Package) RETURN p.key, p.eco, p.name, p.version, p.dev").result_set
    comps, ref = [], {}
    for key, eco, name, ver, dev in rows:
        typ = ECO_PURL.get(eco)
        if not typ:
            continue
        sep = ":" if eco == ECO_MAVEN else "/"
        ns, _, nm = name.rpartition(sep)
        prefix = "".join(urllib.parse.quote(s, safe="") + "/" for s in ns.split(sep)) if ns else ""
        purl = f"pkg:{typ}/{prefix}{urllib.parse.quote(nm, safe='')}@{urllib.parse.quote(ver, safe='')}"
        ref[key] = purl
        comps.append({"type": "library", "bom-ref": purl, "name": nm, "version": ver, "purl": purl,
                      **({"scope": "excluded"} if dev else {})})
    deps: dict[str, list[str]] = {}
    for a, b in db.read(tenant, "MATCH (a:Package)-[:DEPENDS_ON]->(b:Package) RETURN a.key, b.key").result_set:
        if a in ref and b in ref:
            deps.setdefault(ref[a], []).append(ref[b])
    affects: dict[str, list[dict]] = {}
    for aid, pk in db.read(tenant, "MATCH (a:Advisory)-[:AFFECTS]->(p:Package) RETURN a.id, p.key").result_set:
        if pk in ref:
            affects.setdefault(aid, []).append({"ref": ref[pk]})
    vulns = [{"id": a["cve"] or a["id"], "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{a['id']}"},
              "description": a["summary"], "ratings": [{"severity": a["severity"].lower()}],
              "properties": [{"name": "blastradius:priority", "value": a["priority"]}],
              "affects": affects[a["id"]]} for a in triage.risk_board(tenant)["advisories"] if a["id"] in affects]
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": meta.get("title") or tenant},
                         "tools": {"components": [{"type": "application", "name": "Blastradius"}]}},
            "components": comps, "dependencies": [{"ref": r, "dependsOn": sorted(v)} for r, v in deps.items()],
            "vulnerabilities": vulns}


if __name__ == "__main__":
    if sys.argv[1:2] == ["import"]:
        print(ingest_sbom(open(sys.argv[2], encoding="utf-8").read()))

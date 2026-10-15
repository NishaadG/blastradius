"""Resolve transitive dependencies with deps.dev (free, no auth) for manifests that only list direct dependencies.

Lockfiles (package-lock.json, Cargo.lock) already contain the full resolved graph. pom.xml, build.gradle,
requirements.txt and go.mod list only direct (or flat) dependencies, so a vulnerability pulled in through a BOM or a
transitive dependency is invisible to a static parser. deps.dev returns the resolved graph for a package version.
"""
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import httpx

from .config import cache_write_path, cached_path
from .parsers import pkey

BASE = "https://api.deps.dev/v3/systems"
SYSTEMS = {"npm": "npm", "Go": "go", "PyPI": "pypi", "Maven": "maven", "crates.io": "cargo"}
ECOS = {v.upper(): k for k, v in SYSTEMS.items()}
MAX_DIRECT = 60  # bounded work per service on a shared server
EXPAND_KINDS = {"maven", "gradle", "gomod", "requirements"}


def _rel(system: str, name: str, version: str) -> str:
    return "depsdev/" + urllib.parse.quote(f"{system}__{name}__{version}", safe="") + ".json"


def _get(system: str, name: str, version: str) -> dict | None:
    rel = _rel(system, name, version)
    p = cached_path(rel)
    if p:
        return json.loads(p.read_text(encoding="utf-8"))
    url = f"{BASE}/{system}/packages/{urllib.parse.quote(name, safe='')}/versions/{urllib.parse.quote(version, safe='')}:dependencies"
    try:
        r = httpx.get(url, timeout=15)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    cache_write_path(rel).write_text(r.text, encoding="utf-8")
    return r.json()


def _norm_version(eco: str, v: str) -> str:
    return v[1:] if eco == "Go" and v.startswith("v") else v


def expand(direct: dict[str, dict]):
    """direct: {key: {eco,name,version,dev}} -> (extra packages {key: pkg}, edges [(parent_key, child_key)], resolved_count)."""
    items = list(direct.items())[:MAX_DIRECT]

    def one(item):
        key, p = item
        system = SYSTEMS.get(p["eco"])
        if not system:
            return key, None
        ver = "v" + p["version"] if p["eco"] == "Go" and not p["version"].startswith("v") else p["version"]
        return key, _get(system, p["name"], ver)

    extra: dict[str, dict] = {}
    edges: set[tuple[str, str]] = set()
    dev_votes: dict[str, list[bool]] = {}
    resolved = 0
    with ThreadPoolExecutor(8) as ex:
        for key, doc in ex.map(one, items):
            if not doc:
                continue
            resolved += 1
            idx: dict[int, str] = {}
            for i, n in enumerate(doc.get("nodes", [])):
                vk = n.get("versionKey", {})
                eco = ECOS.get(str(vk.get("system", "")).upper())
                if not eco or not vk.get("name") or not vk.get("version"):
                    continue
                k = pkey(eco, vk["name"], _norm_version(eco, vk["version"]))
                idx[i] = k
                if n.get("relation") == "SELF":
                    idx[i] = key  # the queried package keeps the key the parser gave it
                elif k not in direct:
                    extra.setdefault(k, {"eco": eco, "name": vk["name"], "version": _norm_version(eco, vk["version"]), "dev": True})
                    dev_votes.setdefault(k, []).append(bool(direct[key]["dev"]))
            for e in doc.get("edges", []):
                a, b = idx.get(e.get("fromNode")), idx.get(e.get("toNode"))
                if a and b and a != b:
                    edges.add((a, b))
    for k, votes in dev_votes.items():
        extra[k]["dev"] = all(votes)  # a transitive package is dev-only only if every route to it is dev-only
    return extra, sorted(edges), resolved

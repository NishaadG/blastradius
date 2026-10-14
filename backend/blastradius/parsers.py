"""Lockfile parsers -> (packages, edges).

packages: {key: {"eco","name","version","dev"}}
edges:    [(parent_key | None, child_key, is_dev)]   parent None = direct dep of the service
"""
import json
import re

ECO_NPM, ECO_GO, ECO_PYPI = "npm", "Go", "PyPI"


def pkey(eco: str, name: str, version: str) -> str:
    return f"{eco}:{name}@{version}"


def _resolve_npm(packages: dict, from_path: str, dep: str):
    """Node's resolution: look in nested node_modules, then walk up."""
    base = from_path
    while True:
        cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if cand in packages:
            return cand
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx != -1 else ""


def parse_npm_lock(text: str):
    lock = json.loads(text)
    pk = lock.get("packages")
    if not pk:
        return {}, []
    pkgs, edges = {}, []
    path_key = {}
    for path, info in pk.items():
        if path == "" or not info.get("version") or info.get("link"):
            continue
        name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
        key = pkey(ECO_NPM, name, info["version"])
        path_key[path] = key
        pkgs[key] = {"eco": ECO_NPM, "name": name, "version": info["version"],
                     "dev": bool(info.get("dev") or info.get("devOptional"))}
    root = pk.get("", {})
    for dep in root.get("dependencies", {}):
        p = _resolve_npm(pk, "", dep)
        if p in path_key:
            edges.append((None, path_key[p], False))
    for dep in root.get("optionalDependencies", {}):
        p = _resolve_npm(pk, "", dep)
        if p in path_key:
            edges.append((None, path_key[p], False))
    for dep in root.get("devDependencies", {}):
        p = _resolve_npm(pk, "", dep)
        if p in path_key and not any(e[0] is None and e[1] == path_key[p] for e in edges):
            edges.append((None, path_key[p], True))
    for path, key in path_key.items():
        info = pk[path]
        for dep in {**info.get("dependencies", {}), **info.get("optionalDependencies", {})}:
            p = _resolve_npm(pk, path, dep)
            if p in path_key:
                edges.append((key, path_key[p], pkgs[path_key[p]]["dev"]))
    return pkgs, edges


_GO_REQ = re.compile(r"^\s*(?:require\s+)?([\w.\-/~]+\.[\w.\-/~]+)\s+(v[\w.\-+]+)(\s*//\s*indirect)?\s*$")


def parse_go_mod(text: str):
    pkgs, edges = {}, []
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if not (in_block or s.startswith("require ")):
            continue
        m = _GO_REQ.match(s)
        if not m:
            continue
        name, ver = m.group(1), m.group(2)
        key = pkey(ECO_GO, name, ver.lstrip("v"))
        pkgs[key] = {"eco": ECO_GO, "name": name, "version": ver.lstrip("v"), "dev": False,
                     "indirect": bool(m.group(3))}
        edges.append((None, key, False))
    return pkgs, edges


_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)(?:\[[^\]]*\])?==([A-Za-z0-9_.\-+!]+)")


def parse_requirements(text: str):
    pkgs, edges = {}, []
    for line in text.splitlines():
        m = _REQ.match(line.strip())
        if not m:
            continue
        name, ver = m.group(1).lower().replace("_", "-"), m.group(2)
        key = pkey(ECO_PYPI, name, ver)
        pkgs[key] = {"eco": ECO_PYPI, "name": name, "version": ver, "dev": False}
        edges.append((None, key, False))
    return pkgs, edges


PARSERS = {"npm": parse_npm_lock, "gomod": parse_go_mod, "requirements": parse_requirements}

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


def parse_uv_lock(text: str):
    """uv.lock: a fully resolved Python dependency graph. The project's own entry (virtual/editable source) lists the direct
    dependencies; every other [[package]] lists its own, so real transitive paths are available."""
    import tomllib

    data = tomllib.loads(text)
    pkgs, edges, root_deps, dev = {}, [], [], set()
    by_name = {}
    for p in data.get("package", []):
        src = p.get("source") or {}
        by_name[p["name"]] = p
        if "virtual" in src or "editable" in src:
            root_deps = [d["name"] for d in p.get("dependencies", [])]
            dev = {d["name"] for grp in (p.get("dev-dependencies") or {}).values() for d in grp}
            root_deps += sorted(dev)
        elif p.get("version"):
            key = pkey(ECO_PYPI, p["name"], p["version"])
            pkgs[key] = {"eco": ECO_PYPI, "name": p["name"], "version": p["version"], "dev": False}
    for p in data.get("package", []):
        src = p.get("source") or {}
        if "virtual" in src or "editable" in src or not p.get("version"):
            continue
        a = pkey(ECO_PYPI, p["name"], p["version"])
        for d in p.get("dependencies", []):
            q = by_name.get(d["name"])
            if q and q.get("version"):
                edges.append((a, pkey(ECO_PYPI, q["name"], q["version"]), False))
    for n in root_deps:
        q = by_name.get(n)
        if q and q.get("version"):
            k = pkey(ECO_PYPI, q["name"], q["version"])
            if n in dev:
                pkgs[k]["dev"] = True
            edges.append((None, k, n in dev))
    return pkgs, edges


ECO_MAVEN, ECO_CARGO = "Maven", "crates.io"


def parse_pom(text: str):
    """Direct dependencies with a resolvable version (explicit, ${property}, or dependencyManagement)."""
    import re
    import xml.etree.ElementTree as ET

    text = re.sub(r'\sxmlns="[^"]+"', "", text, count=1)  # drop the default namespace
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return {}, []
    props_el = root.find("properties")
    props = {el.tag: (el.text or "").strip() for el in (list(props_el) if props_el is not None else [])}
    props["project.version"] = (root.findtext("version") or root.findtext("parent/version") or "").strip()

    def resolve(v):
        if not v:
            return None
        v = v.strip()
        for _ in range(3):
            m = re.fullmatch(r"\$\{([^}]+)\}", v)
            if not m:
                break
            v = props.get(m.group(1), "")
        return v if v and "${" not in v else None

    managed = {}
    for d in root.findall("dependencyManagement/dependencies/dependency"):
        g, a = d.findtext("groupId"), d.findtext("artifactId")
        if g and a:
            managed[f"{g.strip()}:{a.strip()}"] = resolve(d.findtext("version"))
    pkgs, edges = {}, []
    for d in root.findall("dependencies/dependency"):
        g, a = (d.findtext("groupId") or "").strip(), (d.findtext("artifactId") or "").strip()
        if not g or not a or "${" in g or "${" in a:
            continue
        name = f"{g}:{a}"
        ver = resolve(d.findtext("version")) or managed.get(name)
        if not ver:
            continue
        key = pkey(ECO_MAVEN, name, ver)
        dev = (d.findtext("scope") or "").strip() == "test"
        pkgs[key] = {"eco": ECO_MAVEN, "name": name, "version": ver, "dev": dev}
        edges.append((None, key, dev))
    return pkgs, edges


def parse_cargo_lock(text: str):
    import tomllib

    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}, []
    packages = data.get("package", [])
    by_name: dict[str, list[dict]] = {}
    for p in packages:
        by_name.setdefault(p["name"], []).append(p)
    pkgs, edges = {}, []

    def key_of(p):
        return pkey(ECO_CARGO, p["name"], p["version"])

    def resolve(dep: str):
        parts = dep.split()
        cands = by_name.get(parts[0], [])
        if len(parts) > 1:
            cands = [c for c in cands if c["version"] == parts[1]] or cands
        return cands[0] if cands else None

    for p in packages:
        if "source" in p:  # registry/git packages only; local crates are the "service" itself
            pkgs[key_of(p)] = {"eco": ECO_CARGO, "name": p["name"], "version": p["version"], "dev": False}
    for p in packages:
        for dep in p.get("dependencies", []):
            c = resolve(dep)
            if not c or "source" not in c:
                continue
            if "source" in p:
                edges.append((key_of(p), key_of(c), False))
            else:
                edges.append((None, key_of(c), False))
    return pkgs, edges


_GRADLE_DEP = None


def parse_gradle(text: str):
    """Direct `group:artifact:version` coordinates in build.gradle / build.gradle.kts (literal versions only)."""
    import re

    global _GRADLE_DEP
    if _GRADLE_DEP is None:
        _GRADLE_DEP = re.compile(
            r"""(?P<cfg>\b[a-zA-Z]+)\s*\(?\s*['"](?P<g>[\w.\-]+):(?P<a>[\w.\-]+):(?P<v>[\w.\-+]+)['"]""")
    pkgs, edges = {}, []
    for m in _GRADLE_DEP.finditer(re.sub(r"//.*", "", text)):
        cfg = m.group("cfg")
        if cfg.lower() not in {"implementation", "api", "compile", "runtime", "runtimeonly", "compileonly",
                               "testimplementation", "testcompile", "testruntimeonly", "annotationprocessor", "kapt"}:
            continue
        ver = m.group("v")
        if "$" in ver:
            continue
        name = f"{m.group('g')}:{m.group('a')}"
        key = pkey(ECO_MAVEN, name, ver)
        dev = cfg.lower().startswith("test")
        pkgs[key] = {"eco": ECO_MAVEN, "name": name, "version": ver, "dev": dev}
        edges.append((None, key, dev))
    return pkgs, edges


def _parse_sbom(text: str):
    from .sbom import parse_sbom

    return parse_sbom(text)


PARSERS = {
    "sbom": _parse_sbom,
    "npm": parse_npm_lock, "gomod": parse_go_mod, "requirements": parse_requirements,
    "uv": parse_uv_lock, "maven": parse_pom, "cargo": parse_cargo_lock, "gradle": parse_gradle,
}

# file name -> parser kind, used to discover services in an arbitrary repository
LOCKFILES = {
    "package-lock.json": "npm", "go.mod": "gomod", "requirements.txt": "requirements",
    "pom.xml": "maven", "Cargo.lock": "cargo", "uv.lock": "uv", "build.gradle": "gradle", "build.gradle.kts": "gradle",
}

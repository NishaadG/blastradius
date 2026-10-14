"""OSV.dev client (free, no auth) with an on-disk cache."""
import json
from concurrent.futures import ThreadPoolExecutor

import httpx

from .config import DATA_DIR

OSV = "https://api.osv.dev/v1"
CACHE = DATA_DIR / "osv_cache.json"


def _load():
    if CACHE.exists():
        return json.loads(CACHE.read_text(encoding="utf-8"))
    return {"queries": {}, "vulns": {}}


def _save(c):
    CACHE.write_text(json.dumps(c), encoding="utf-8")


def query_packages(pkgs: dict) -> dict:
    """pkgs: {key: {eco,name,version}} -> {key: [vuln ids]} using querybatch."""
    cache = _load()
    todo = [k for k in pkgs if k not in cache["queries"]]
    with httpx.Client(timeout=60) as cli:
        for i in range(0, len(todo), 500):
            chunk = todo[i:i + 500]
            body = {"queries": [{"package": {"name": pkgs[k]["name"], "ecosystem": pkgs[k]["eco"]},
                                 "version": pkgs[k]["version"]} for k in chunk]}
            r = cli.post(f"{OSV}/querybatch", json=body)
            r.raise_for_status()
            for k, res in zip(chunk, r.json()["results"]):
                cache["queries"][k] = [v["id"] for v in res.get("vulns", [])]
    _save(cache)
    return {k: cache["queries"][k] for k in pkgs}


def fetch_vulns(ids) -> dict:
    cache = _load()
    todo = [i for i in set(ids) if i not in cache["vulns"]]

    def get(vid):
        with httpx.Client(timeout=60) as cli:
            r = cli.get(f"{OSV}/vulns/{vid}")
            return vid, (r.json() if r.status_code == 200 else None)

    with ThreadPoolExecutor(8) as ex:
        for vid, data in ex.map(get, todo):
            if data:
                cache["vulns"][vid] = data
    _save(cache)
    return {i: cache["vulns"][i] for i in ids if i in cache["vulns"]}


def summarize(v: dict) -> dict:
    sev = (v.get("database_specific") or {}).get("severity") or "UNKNOWN"
    cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
    return {
        "id": v["id"],
        "cve": cves[0] if cves else None,
        "aliases": v.get("aliases", []),
        "summary": (v.get("summary") or (v.get("details") or "")[:160]).strip(),
        "severity": str(sev).upper(),
        "published": (v.get("published") or "")[:10],
        "url": next((r["url"] for r in v.get("references", []) if r.get("type") == "ADVISORY"),
                    f"https://osv.dev/{v['id']}"),
    }


def fixed_version(v: dict, eco: str, name: str):
    for a in v.get("affected", []):
        p = a.get("package", {})
        if p.get("ecosystem", "").split(":")[0] == eco and p.get("name", "").lower() == name.lower():
            for r in a.get("ranges", []):
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        return ev["fixed"]
    return None

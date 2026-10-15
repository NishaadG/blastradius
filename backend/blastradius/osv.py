"""OSV.dev client (free, no auth). Results are cached: a committed snapshot (read-only) plus a writable cache."""
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

from .config import CACHE_DIR, SNAPSHOT_DIR

OSV = "https://api.osv.dev/v1"
REL = "osv_cache.json"
_lock = threading.Lock()
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$")


def valid_id(ident: str) -> bool:
    """Advisory identifiers only: anything else never reaches the OSV URL path."""
    return bool(_ID.match(ident or ""))


def _load():
    c = {"queries": {}, "vulns": {}}
    for base in (SNAPSHOT_DIR, CACHE_DIR):  # the writable cache overrides the snapshot
        p = base / REL
        if p.exists():
            d = json.loads(p.read_text(encoding="utf-8"))
            c["queries"].update(d.get("queries", {}))
            c["vulns"].update(d.get("vulns", {}))
    return c


def _save(c):
    (CACHE_DIR / REL).write_text(json.dumps(c), encoding="utf-8")


def _post(cli: httpx.Client, url: str, body: dict, tries: int = 3):
    for i in range(tries):
        r = cli.post(url, json=body)
        if r.status_code == 429 or r.status_code >= 500:
            time.sleep(1.5 * (i + 1))
            continue
        r.raise_for_status()
        return r.json()
    r.raise_for_status()


def query_packages(pkgs: dict) -> dict:
    """pkgs: {key: {eco,name,version}} -> {key: [vuln ids]} using querybatch."""
    with _lock:
        cache = _load()
    todo = [k for k in pkgs if k not in cache["queries"]]
    with httpx.Client(timeout=60) as cli:
        for i in range(0, len(todo), 500):
            chunk = todo[i:i + 500]
            body = {"queries": [{"package": {"name": pkgs[k]["name"], "ecosystem": pkgs[k]["eco"]},
                                 "version": pkgs[k]["version"]} for k in chunk]}
            data = _post(cli, f"{OSV}/querybatch", body)
            for k, res in zip(chunk, data["results"]):
                cache["queries"][k] = [v["id"] for v in res.get("vulns", [])]
    if todo:
        with _lock:
            _save(cache)
    return {k: cache["queries"][k] for k in pkgs}


def fetch_vulns(ids) -> dict:
    ids = [i for i in dict.fromkeys(ids) if valid_id(i)]
    with _lock:
        cache = _load()
    todo = [i for i in ids if i not in cache["vulns"]]

    def get(vid):
        with httpx.Client(timeout=30) as cli:
            r = cli.get(f"{OSV}/vulns/{vid}")
            return vid, (r.json() if r.status_code == 200 else None)

    if todo:
        with ThreadPoolExecutor(8) as ex:
            for vid, data in ex.map(get, todo):
                if data:
                    cache["vulns"][vid] = data
        with _lock:
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

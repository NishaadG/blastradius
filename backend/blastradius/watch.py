"""Watcher: rescan a tenant's packages against OSV and surface advisories published since the graph was built.

    python -m blastradius.watch boutique            # rescan one tenant
    python -m blastradius.watch --all               # every tenant (cron-friendly)

Anything new is written into the graph (marked with first_seen), triaged with the same deterministic judge, and
reported by priority. This is what turns a lookup tool into something that notices on its own.
"""
import sys
import threading
import time

from . import db, ingest, osv, triage

_lock = threading.Lock()


class Busy(Exception):
    pass


def rescan(tenant: str, say=print) -> dict:
    if not _lock.acquire(blocking=False):
        raise Busy("a rescan is already running")
    try:
        rows = db.read(tenant, "MATCH (p:Package) RETURN p.key, p.eco, p.name, p.version").result_set
        pkgs = {r[0]: {"eco": r[1], "name": r[2], "version": r[3]} for r in rows}
        known = {r[0] for r in db.read(tenant, "MATCH (a:Advisory) RETURN a.id").result_set}
        say(f"[{tenant}] re-querying OSV for {len(pkgs)} packages")
        hits = osv.query_packages(pkgs, fresh=True)
        found = {v for ids in hits.values() for v in ids}
        new_ids = sorted(found - known)
        say(f"[{tenant}] {len(found)} advisories apply now, {len(new_ids)} new since the last scan")
        out = {"tenant": tenant, "packages": len(pkgs), "applicable": len(found), "new": []}
        if new_ids:
            vulns = osv.fetch_vulns(new_ids)
            ingest.write_advisories(tenant, pkgs, {k: [v for v in ids if v in vulns] for k, ids in hits.items()}, vulns,
                                    first_seen=int(time.time() * 1000))
            board = {a["id"]: a for a in triage.risk_board(tenant)["advisories"]}
            for vid in new_ids:
                a = board.get(vid)
                if a:
                    out["new"].append({"id": vid, "cve": a["cve"], "severity": a["severity"], "priority": a["priority"],
                                       "services": a["services"], "summary": a["summary"]})
        db.write(tenant, "MATCH (m:Meta {k:'tenant'}) SET m.last_scan=$ts", {"ts": int(time.time() * 1000)})
        out["scanned_at"] = int(time.time() * 1000)
        return out
    finally:
        _lock.release()


if __name__ == "__main__":
    targets = db.tenants_present() if sys.argv[1:] == ["--all"] else sys.argv[1:]
    for t in targets:
        r = rescan(t)
        for n in r["new"]:
            print(f"  NEW {n['priority']:>3} {n['severity']:<9} {n['cve'] or n['id']}  {', '.join(n['services'])}  {n['summary'][:80]}")

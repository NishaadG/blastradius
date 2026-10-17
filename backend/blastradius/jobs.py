"""Background jobs for 'analyse a public GitHub repo'. One job at a time, a hard deadline, bounded retention."""
import logging
import threading
import time
import uuid

from . import db, ingest, queries as q

log = logging.getLogger("blastradius.jobs")
MAX_BYO_TENANTS = 8
DEADLINE_S = 150
_jobs: dict[str, dict] = {}
_lock = threading.Lock()
_busy = threading.Lock()


class Busy(Exception):
    pass


def _evict_if_needed(keep: str):
    byo = []
    for t in db.tenants_present():
        m = q.tenant_meta(t)
        if m["kind"] == "byo" and t != keep:
            byo.append((m["built_at"] or 0, t))
    byo.sort()
    while len(byo) >= MAX_BYO_TENANTS:
        _, old = byo.pop(0)
        try:
            db.graph(old).delete()
            log.info("evicted tenant %s", old)
        except Exception:
            log.exception("eviction failed for %s", old)


def _run(job_id: str, repo: str, sbom: str | None = None):
    job = _jobs[job_id]
    t0 = time.monotonic()

    def say(msg: str):
        if time.monotonic() - t0 > DEADLINE_S:
            raise ingest.IngestError("Analysis took too long for a hosted demo. Run Blastradius locally for repos this large.")
        job["log"].append(msg)

    try:
        if sbom is not None:
            from . import sbom as sbommod

            _evict_if_needed(sbommod.tenant_id_for_sbom(sbom))
            tenant = sbommod.ingest_sbom(sbom, say)
        else:
            _evict_if_needed(ingest.tenant_id_for(repo))
            tenant = ingest.ingest_repo(repo, say)
        job.update(status="done", tenant=tenant)
    except (ingest.IngestError, ValueError) as e:  # ValueError covers SbomError
        job.update(status="error", error=str(e))
    except Exception:
        log.exception("ingest failed for %s", repo)
        job.update(status="error", error="Analysis failed unexpectedly. Try another repository.")
    finally:
        job["finished"] = time.time()
        _busy.release()


def start(repo: str, sbom: str | None = None) -> str:
    if sbom is None and not ingest.REPO_RE.match(repo):
        raise ingest.IngestError("Use the form owner/name, for example open-telemetry/opentelemetry-demo.")
    if not _busy.acquire(blocking=False):
        raise Busy("Another repository is being analysed right now. Try again in a minute.")
    job_id = uuid.uuid4().hex[:12]
    with _lock:
        _jobs[job_id] = {"id": job_id, "repo": repo, "status": "running", "log": [], "tenant": None, "error": None,
                         "started": time.time()}
        for old in sorted(_jobs, key=lambda k: _jobs[k]["started"])[:-50]:
            _jobs.pop(old, None)
    threading.Thread(target=_run, args=(job_id, repo, sbom), daemon=True).start()
    return job_id


def get(job_id: str) -> dict | None:
    return _jobs.get(job_id)

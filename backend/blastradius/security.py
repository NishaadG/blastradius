"""Input validation, session identity and rate limiting for a shared public deployment."""
import re
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from . import config

TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
SID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@/:-]{0,120}$")  # service / package style names
ECOS = {"npm", "Go", "PyPI", "Maven", "crates.io"}


def session_id(request: Request) -> str:
    """Each browser gets its own memory namespace; header-less callers share 'anon'."""
    sid = request.headers.get("x-session", "")
    return sid if SID_RE.match(sid) else "anon"


def client_ip(request: Request) -> str:
    # Behind the reverse proxy the last X-Forwarded-For hop is the one the proxy itself observed.
    xff = request.headers.get("x-forwarded-for")
    if config.PUBLIC and xff:
        return xff.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def check_name(value: str, what: str = "name") -> str:
    if not NAME_RE.match(value or ""):
        raise HTTPException(422, f"invalid {what}")
    return value


class Limiter:
    """Sliding-window counters keyed by (bucket, client). In-memory is enough for one small instance."""

    def __init__(self):
        self.hits: dict[tuple[str, str], deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, bucket: str, who: str, limit: int, window_s: int) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[(bucket, who)]
            while q and now - q[0] > window_s:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self.hits) > 20_000:  # bound memory under a flood of distinct clients
                for k in [k for k, v in self.hits.items() if not v or now - v[-1] > 3600][:5000]:
                    self.hits.pop(k, None)
            return True


limiter = Limiter()

# (bucket, limit, window seconds) for each request class
RULES = {
    "general": (240, 60),
    "heavy": (40, 60),      # triage / ask / decide: each does several graph queries and writes
    "bench": (3, 60),
    "ingest": (3, 3600),    # analysing a repo is expensive: hard cap per client
}


def classify(method: str, path: str) -> str:
    if method == "POST" and (path.endswith("/ingest") or path.endswith("/rescan") or path == "/api/sbom"):
        return "ingest"
    if path.endswith("/bench"):
        return "bench"
    if method == "POST" and path.rsplit("/", 1)[-1] in ("triage", "ask", "decide"):
        return "heavy"
    return "general"

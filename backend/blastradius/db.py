import random
import re
import threading
import time
from functools import lru_cache

import falkordb
from redis.exceptions import ResponseError

from . import config

_WRITE = re.compile(r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|LOAD\s+CSV|CALL\s+db\.idx|CALL\s+dbms)\b", re.I)

# FalkorDB protects itself with a bounded query queue and answers "Max pending queries exceeded" when it is full.
# That is backpressure, not failure: well-behaved clients retry with jittered backoff.
_BUSY = "Max pending queries exceeded"
_retries = 0
_retries_lock = threading.Lock()


def backpressure_retries() -> int:
    return _retries


def _with_backoff(fn, attempts: int = 6):
    global _retries
    for i in range(attempts):
        try:
            return fn()
        except ResponseError as e:
            if _BUSY not in str(e) or i == attempts - 1:
                raise
            with _retries_lock:
                _retries += 1
            time.sleep(random.uniform(0.02, 0.06) * (2 ** i))


@lru_cache(maxsize=1)
def client() -> falkordb.FalkorDB:
    return falkordb.FalkorDB(host=config.FALKOR_HOST, port=config.FALKOR_PORT,
                             username=config.FALKOR_USERNAME, password=config.FALKOR_PASSWORD,
                             socket_connect_timeout=2)  # database down -> fail in seconds, not after a long hang


def graph(tenant: str):
    return client().select_graph(config.graph_name(tenant))


def tenants_present() -> list[str]:
    names = client().list_graphs()
    return sorted(n[3:] for n in names if n.startswith("br_"))


class UnsafeQuery(Exception):
    pass


def read(tenant: str, cypher: str, params: dict | None = None):
    """Agent-facing read path: write keywords rejected, DB-enforced read-only, timeout, row cap."""
    stripped = re.sub(r"'[^']*'|\"[^\"]*\"", "''", cypher)
    if _WRITE.search(stripped):
        raise UnsafeQuery("write operations are not allowed on the agent read path")
    return _with_backoff(lambda: graph(tenant).ro_query(cypher, params or {}, timeout=config.QUERY_TIMEOUT_MS))


def rows(res, limit: int = config.MAX_ROWS):
    return res.result_set[:limit]


def write(tenant: str, cypher: str, params: dict | None = None):
    """Internal write path (ingestion + memory). Never exposed to the LLM."""
    return _with_backoff(lambda: graph(tenant).query(cypher, params or {}))

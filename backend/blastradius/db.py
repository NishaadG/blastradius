import re
from functools import lru_cache

import falkordb

from . import config

_WRITE = re.compile(r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|LOAD\s+CSV|CALL\s+db\.idx|CALL\s+dbms)\b", re.I)


@lru_cache(maxsize=1)
def client() -> falkordb.FalkorDB:
    return falkordb.FalkorDB(host=config.FALKOR_HOST, port=config.FALKOR_PORT,
                             username=config.FALKOR_USERNAME, password=config.FALKOR_PASSWORD)


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
    res = graph(tenant).ro_query(cypher, params or {}, timeout=config.QUERY_TIMEOUT_MS)
    return res


def rows(res, limit: int = config.MAX_ROWS):
    return res.result_set[:limit]


def write(tenant: str, cypher: str, params: dict | None = None):
    """Internal write path (ingestion + memory). Never exposed to the LLM."""
    return graph(tenant).query(cypher, params or {})

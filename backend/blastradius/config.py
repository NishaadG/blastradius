import os
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

FALKOR_HOST = os.getenv("FALKOR_HOST", "localhost")
FALKOR_PORT = int(os.getenv("FALKOR_PORT", "6379"))
FALKOR_USERNAME = os.getenv("FALKOR_USERNAME") or None
FALKOR_PASSWORD = os.getenv("FALKOR_PASSWORD") or None

# SNAPSHOT_DIR: committed, read-only inputs (lockfiles, manifests, OSV results, commit metadata) so the demo
# graphs rebuild identically and offline. CACHE_DIR: writable cache for anything fetched at runtime.
SNAPSHOT_DIR = Path(os.getenv("BR_SNAPSHOT_DIR", _ROOT / "snapshot"))
CACHE_DIR = Path(os.getenv("BR_CACHE_DIR", _ROOT / ".cache"))
CACHE_DIR.mkdir(parents=True, exist_ok=True)

QUERY_TIMEOUT_MS = 3000
MAX_ROWS = 100

# Public-demo mode: stricter limits, no destructive endpoints, MCP is read-only.
PUBLIC = os.getenv("BR_PUBLIC", "") == "1"


def graph_name(tenant: str) -> str:
    """One FalkorDB graph per tenant: hard isolation between orgs."""
    return f"br_{tenant}"


def cached_path(rel: str) -> Path | None:
    """Existing file for `rel` from the writable cache or the committed snapshot."""
    for base in (CACHE_DIR, SNAPSHOT_DIR):
        p = base / rel
        if p.exists():
            return p
    return None


def cache_write_path(rel: str) -> Path:
    p = CACHE_DIR / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

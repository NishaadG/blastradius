"""One-shot: rebuild the curated tenant graphs (dependencies + advisories + ownership + call graph + company brain).

    python -m blastradius.build            # all tenants, from the committed snapshot (works offline)
    python -m blastradius.build boutique
    python -m blastradius.build --snapshot # after a networked build, copy the cache into the committed snapshot
"""
import shutil
import sys

from . import brain, ingest, reach
from .config import CACHE_DIR, SNAPSHOT_DIR
from .tenants import TENANTS


def snapshot():
    """Promote everything fetched into the writable cache to the committed snapshot."""
    n = 0
    for p in CACHE_DIR.rglob("*"):
        if p.is_file():
            dst = SNAPSHOT_DIR / p.relative_to(CACHE_DIR)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dst)
            n += 1
    print(f"snapshot updated: {n} files -> {SNAPSHOT_DIR}")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["--snapshot"]:
        snapshot()
    else:
        for name in args or list(TENANTS):
            ingest.ingest(name)
            brain.ingest(name)
            reach.ingest(name)

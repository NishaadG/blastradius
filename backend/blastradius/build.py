"""One-shot: rebuild tenant graphs (dependencies + advisories + ownership + company brain).

    python -m blastradius.build            # all tenants
    python -m blastradius.build boutique
"""
import sys

from . import brain, ingest
from .tenants import TENANTS

if __name__ == "__main__":
    for name in sys.argv[1:] or list(TENANTS):
        ingest.ingest(name)
        brain.ingest(name)

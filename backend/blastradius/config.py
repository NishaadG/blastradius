import os
from pathlib import Path

FALKOR_HOST = os.getenv("FALKOR_HOST", "localhost")
FALKOR_PORT = int(os.getenv("FALKOR_PORT", "6379"))
FALKOR_USERNAME = os.getenv("FALKOR_USERNAME") or None
FALKOR_PASSWORD = os.getenv("FALKOR_PASSWORD") or None

DATA_DIR = Path(os.getenv("BR_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

QUERY_TIMEOUT_MS = 3000
MAX_ROWS = 100

# One FalkorDB graph per tenant: hard isolation between orgs.
def graph_name(tenant: str) -> str:
    return f"br_{tenant}"

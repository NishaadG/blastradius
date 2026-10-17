"""Discover the service call graph and internet exposure from the project's own deployment files.

Instead of hand-curating edges we read what the deployment says:
  * Docker Compose: env vars like CART_ADDR=cart:8080 / FRONTEND_HOST=frontend are calls; a published `ports:` is exposure.
  * Kubernetes: Deployment env vars like PRODUCT_CATALOG_SERVICE_ADDR=productcatalogservice:3550 are calls;
    a Service of type LoadBalancer/NodePort is exposure.
"""
import re

import yaml

_ENV_KEY = re.compile(r"(_ADDR|_ADDRESS|_HOST|_URL|_ENDPOINT|_URI)$", re.I)


def _host(value: str) -> str | None:
    v = str(value).strip().strip("'\"")
    v = re.sub(r"^([a-z][a-z0-9+.-]*:)+//", "", v)  # scheme, incl. jdbc:postgresql://
    v = v.split("@")[-1].split("/")[0].split(":")[0]
    return v.lower() if re.fullmatch(r"[a-z][a-z0-9_-]*", v.lower()) else None


def _env_items(env) -> list[tuple[str, str]]:
    if isinstance(env, dict):
        return [(str(k), "" if v is None else str(v)) for k, v in env.items()]
    out = []
    for item in env or []:
        if isinstance(item, str) and "=" in item:
            k, v = item.split("=", 1)
            out.append((k, v))
        elif isinstance(item, dict) and "name" in item and "value" in item:
            out.append((str(item["name"]), str(item["value"])))
    return out


def parse_dotenv(text: str | None) -> dict[str, str]:
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.split(" #")[0].strip()
    return out


def _published(ports) -> bool:
    """host:container mapping bound to all interfaces. A bare container port is not a deliberate exposure,
    and an explicit 127.0.0.1 bind is not reachable from outside."""
    for p in ports or []:
        s = str(p.get("published", "") if isinstance(p, dict) else p)
        if isinstance(p, dict):
            if s:
                return True
        elif ":" in s and not s.startswith("127.0.0.1"):
            return True
    return False


def compose(texts: list[str], names: set[str], dotenv: dict[str, str] | None = None):
    """-> (calls {(a,b)}, exposed {name}) restricted to `names`. Bare env names resolve through `.env`."""
    calls, exposed = set(), set()
    dotenv = dotenv or {}
    for text in texts:
        doc = yaml.safe_load(text) or {}
        for svc, d in (doc.get("services") or {}).items():
            if svc not in names or not isinstance(d, dict):
                continue
            if _published(d.get("ports")):
                exposed.add(svc)
            env = d.get("environment")
            items = _env_items(env)
            if isinstance(env, list):  # bare `NAME` entries take their value from .env
                items += [(e, dotenv[e]) for e in env if isinstance(e, str) and "=" not in e and e in dotenv]
            for k, v in items:
                if _ENV_KEY.search(k):
                    h = _host(v)
                    if h and h in names and h != svc:
                        calls.add((svc, h))
    return calls, exposed


def kubernetes(texts: list[str], names: set[str]):
    """Calls come from container env (literal, or resolved through ConfigMaps: envFrom and configMapKeyRef)."""
    docs = [d for t in texts for d in yaml.safe_load_all(t) if isinstance(d, dict)]
    cms = {(d.get("metadata") or {}).get("name"): {str(k): str(v) for k, v in (d.get("data") or {}).items()}
           for d in docs if d.get("kind") == "ConfigMap"}
    calls, exposed = set(), set()
    for doc in docs:
        kind, meta, spec = doc.get("kind"), doc.get("metadata") or {}, doc.get("spec") or {}
        if kind == "Deployment":
            svc = meta.get("name")
            if svc not in names:
                continue
            for c in (((spec.get("template") or {}).get("spec") or {}).get("containers") or []):
                items = list(_env_items(c.get("env")))
                for ref in c.get("envFrom") or []:
                    items += list(cms.get(((ref or {}).get("configMapRef") or {}).get("name"), {}).items())
                for e in c.get("env") or []:
                    kr = ((e.get("valueFrom") or {}).get("configMapKeyRef") or {}) if isinstance(e, dict) else {}
                    if kr.get("key") in cms.get(kr.get("name"), {}):
                        items.append((e["name"], cms[kr["name"]][kr["key"]]))
                for k, v in items:
                    if _ENV_KEY.search(k):
                        h = _host(v)
                        if h and h in names and h != svc:
                            calls.add((svc, h))
        elif kind == "Service" and spec.get("type") in ("LoadBalancer", "NodePort"):
            target = (spec.get("selector") or {}).get("app")
            if target in names:
                exposed.add(target)
    return calls, exposed

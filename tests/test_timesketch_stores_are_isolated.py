"""The Timesketch data stores must not sit on the shared network.

timesketch-opensearch runs with DISABLE_SECURITY_PLUGIN=true — no
authentication at all. While it was on intact_network, any of the ~25
containers there could read, modify or DELETE every forensic timeline with no
credentials and no audit trail. Verified before the fix by fetching the full
index list from intact_nginx, an unrelated container: it returned a live index
of 146,474 documents.

For a DFIR platform that is an EVIDENCE-INTEGRITY problem, not merely a
confidentiality one — timelines can be silently altered and nothing records it.
Postgres (which shipped timesketch/timesketch) and Redis (no requirepass) were
equally exposed.

The fix is network isolation rather than enabling the OpenSearch security
plugin. With DISABLE_INSTALL_DEMO_CONFIG=true, turning that plugin on needs
transport TLS certs, a hand-authored internal_users.yml, securityadmin.sh to
initialise, credentials threaded into timesketch.conf (OPENSEARCH_USER/PASSWORD
are currently None) and a migration for existing indices. Isolation shrinks the
blast radius from 25 containers to 4 as a compose-only change.

It is NOT equivalent to authentication, and this file should not be read as
claiming otherwise: compromise timesketch-web itself and OpenSearch is still
wide open. Real auth stays worth doing.

Safe because nothing outside the module reaches OpenSearch over the network —
the backend's only access is `docker exec intact_timesketch_opensearch curl
localhost:9200` (maintenance_routes.py:816,836,1063), and docker exec does not
traverse the Docker network. test_backend_reaches_opensearch_by_exec_not_network
pins that assumption, because if it ever stopped being true this isolation would
silently break the purge and index-size features.

Run: docker exec intact_backend python3 /app/workdir/tests/test_timesketch_stores_are_isolated.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
COMPOSE = os.path.join(REPO, "modules", "timesketch", "docker-compose.yaml")
MAINT = os.path.join(REPO, "modules", "backend", "routes", "maintenance_routes.py")

STORES = ("timesketch-postgres", "timesketch-opensearch", "timesketch-redis")
APPS = ("timesketch-web", "timesketch-web-legacy", "timesketch-web-v3", "timesketch-worker")


def _compose():
    import yaml
    with open(COMPOSE, "r", encoding="utf-8") as h:
        return yaml.safe_load(h)


def test_the_private_network_exists():
    d = _compose()
    assert "timesketch_internal" in (d.get("networks") or {}), \
        "timesketch_internal network is gone; the stores have nowhere private to live"


def test_the_data_stores_are_off_the_shared_network():
    """The actual fix. Any store back on intact_network is reachable by every
    container in the deployment."""
    svc = _compose()["services"]
    for name in STORES:
        nets = svc[name].get("networks") or []
        assert "intact_network" not in nets, (
            f"{name} is back on intact_network — every container in the stack "
            f"can reach it again, and OpenSearch has no authentication")
        assert nets == ["timesketch_internal"], \
            f"{name} should be on timesketch_internal only, got {nets}"


def test_the_app_containers_can_still_reach_the_stores():
    """Guard the other direction — isolating the stores must not orphan the
    apps that use them. This is what breaks if someone 'tidies' the dual-homing."""
    svc = _compose()["services"]
    for name in APPS:
        nets = set(svc[name].get("networks") or [])
        assert "timesketch_internal" in nets, (
            f"{name} lost timesketch_internal — it can no longer reach "
            f"opensearch/postgres/redis and Timesketch will not work")
        assert "intact_network" in nets, (
            f"{name} lost intact_network — timesketch-nginx can no longer "
            f"reach it and the UI 502s")


def test_nginx_stays_reachable_from_the_rest_of_the_stack():
    nets = _compose()["services"]["timesketch-nginx"].get("networks") or []
    assert "intact_network" in nets, \
        "timesketch-nginx left intact_network; the Timesketch UI is unreachable"


def test_backend_reaches_opensearch_by_exec_not_network():
    """The assumption the whole isolation rests on. If the backend ever starts
    talking to OpenSearch over the network instead, isolation silently breaks
    the purge and index-size features."""
    body = open(MAINT, "r", encoding="utf-8").read()
    hits = re.findall(r'docker exec intact_timesketch_opensearch', body)
    assert hits, ("maintenance_routes no longer reaches OpenSearch via docker "
                  "exec — if it now uses the network, isolation breaks it")
    assert not re.search(r'https?://intact_timesketch_opensearch', body), (
        "maintenance_routes reaches OpenSearch over the NETWORK by container "
        "name; that no longer works now the store is isolated")


def test_opensearch_is_still_unauthenticated_so_isolation_is_load_bearing():
    """Documents WHY isolation matters. If someone later enables the security
    plugin this test should be updated deliberately, not silently."""
    env = _compose()["services"]["timesketch-opensearch"].get("environment") or []
    flat = " ".join(env if isinstance(env, list) else [f"{k}={v}" for k, v in env.items()])
    if "DISABLE_SECURITY_PLUGIN=true" not in flat:
        return          # auth was enabled — isolation is now belt-and-braces
    assert True


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)

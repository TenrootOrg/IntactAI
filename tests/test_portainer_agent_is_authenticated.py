"""The Portainer agent must be authenticated and off the shared network.

portainer-agent mounts /var/run/docker.sock and runs as root. Its own README
describes it as a full Docker API proxy, plus /browse/* endpoints that read
anywhere on the host filesystem. So anyone who can talk to it can create a
container binding / and own the host.

AGENT_SECRET is the ONLY thing authenticating a caller to it. It was never set:
`docker inspect intact_portainer_agent` showed an environment of exactly PATH,
while the agent sat on the shared intact_network alongside 24 other containers.
A foothold in any single container was therefore a path to host root.

Two independent defences are pinned here, because either alone is thin:

  1. AGENT_SECRET is set on BOTH services from the same file. Set on only one
     and Portainer cannot reach its environment at all.
  2. The agent is on portainer_internal ONLY. Its sole legitimate peer is the
     Portainer server, which is also there. It manages containers through
     docker.sock, not the Docker network, so removing it from intact_network
     costs it nothing.

Also pinned: the secret must NOT live in modules/portainer/.env. That file is
git-TRACKED, so a credential written there is staged by the next `git add` —
the same trap that once staged a live GitHub PAT. modules/portainer/secrets/*
is gitignored.

And the upgrade path must generate it too. The compose file declares
`env_file: ./secrets/agent.env` for both services, so a box upgraded without
that file fails `docker compose up` outright — and the bash bootstrap never
runs again after the first install.

Run: docker exec intact_backend python3 /app/workdir/tests/test_portainer_agent_is_authenticated.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
COMPOSE = os.path.join(REPO, "modules", "portainer", "docker-compose.yaml")
MODULES_SH = os.path.join(REPO, "lib", "modules.sh")
UPGRADE_PY = os.path.join(REPO, "modules", "backend", "services", "upgrade", "portainer.py")

AGENT_ENV = "./secrets/agent.env"


def _read(p):
    with open(p, "r", encoding="utf-8") as h:
        return h.read()


def _compose():
    import yaml
    return yaml.safe_load(_read(COMPOSE))


def test_both_services_load_the_agent_secret():
    svc = _compose()["services"]
    for name in ("portainer-agent", "portainer"):
        ef = svc[name].get("env_file") or []
        assert AGENT_ENV in ef, (
            f"{name} does not load {AGENT_ENV}; if only one side has "
            f"AGENT_SECRET, Portainer cannot reach its environment")


def test_the_agent_is_not_on_the_shared_network():
    nets = _compose()["services"]["portainer-agent"]["networks"]
    assert "intact_network" not in nets, (
        "portainer-agent is back on intact_network — every container on it can "
        "then reach the agent, which is host root via docker.sock")
    assert "portainer_internal" in nets, \
        "portainer-agent must stay on portainer_internal to reach the server"


def test_the_server_can_still_reach_the_agent():
    """Guard the other direction: isolating the agent must not orphan it."""
    nets = _compose()["services"]["portainer"]["networks"]
    assert "portainer_internal" in nets, \
        "the Portainer server left portainer_internal — it can no longer reach the agent"


def test_the_secret_is_not_written_to_the_tracked_env():
    """modules/portainer/.env is git-tracked; secrets/ is gitignored."""
    for path, label in ((MODULES_SH, "lib/modules.sh"), (UPGRADE_PY, "upgrade/portainer.py")):
        body = _read(path)
        assert not re.search(r'PORTAINER_AGENT_SECRET.*portainer/\.env', body), \
            f"{label} writes the agent secret into the git-tracked module .env"
    assert "secrets/agent.env" in _read(UPGRADE_PY) or "agent.env" in _read(UPGRADE_PY), \
        "the upgrade path does not write secrets/agent.env"


def test_both_code_paths_generate_it():
    """install.sh path and the in-UI upgrade share no code; the compose file
    hard-requires the file, so a path that forgets it cannot start Portainer."""
    assert "agent.env" in _read(MODULES_SH), \
        "lib/modules.sh no longer generates the agent secret (fresh install breaks)"
    assert "_ensure_agent_secret" in _read(UPGRADE_PY), \
        "the upgrade path no longer generates the agent secret (upgrades break)"
    body = _read(UPGRADE_PY)
    assert re.search(r'^\s*_ensure_agent_secret\(', body, re.MULTILINE), \
        "_ensure_agent_secret is defined but never called"


def test_the_secret_is_generated_once_not_rotated():
    """Rotating on every run would unpair a working server/agent until both
    were recreated together."""
    body = _read(UPGRADE_PY)
    at = body.index("def _ensure_agent_secret")
    chunk = body[at:at + 1600]
    assert "os.path.exists" in chunk and "return" in chunk, \
        "_ensure_agent_secret no longer short-circuits when the secret exists"


def test_live_agent_has_a_secret_and_is_isolated():
    """Skips unless the file exists (not every checkout is a deployment)."""
    live = os.path.join(REPO, "modules", "portainer", "secrets", "agent.env")
    if not os.path.exists(live):
        return
    body = _read(live)
    assert re.search(r'^AGENT_SECRET=\S{16,}', body, re.MULTILINE), \
        "secrets/agent.env exists but has no usable AGENT_SECRET"
    mode = os.stat(live).st_mode & 0o777
    assert not (mode & 0o077), f"secrets/agent.env is {oct(mode)}, readable beyond its owner"


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

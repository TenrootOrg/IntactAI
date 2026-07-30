"""The Velociraptor GUI must reach its own API from inside the container.

Symptom, on a live box: the whole Velociraptor UI was a blank page with

    connection error: desc = "transport: Error while dialing:
    dial tcp 192.168.120.11:8001: connect: connection refused"

and every /velociraptor/api/v1/* call returning HTTP 503 — while the API itself
was perfectly healthy. Verified from inside the container's own network
namespace: 127.0.0.1:8001 OPEN, intact_velociraptor:8001 OPEN,
192.168.120.11:8001 REFUSED. The only broken address was the one the GUI used.

Cause is an interaction between two reasonable decisions:

  * The GUI talks to its own API over gRPC and builds that address from
    API.hostname, falling back to Frontend.hostname when unset. Frontend.hostname
    is the box's PUBLIC address, because that is what enrolled endpoints must
    dial to phone home on 8000.
  * modules/velociraptor/docker-compose.yaml deliberately publishes 8001 (gRPC
    API) and 8889 (GUI) on 127.0.0.1 only — the GUI runs plain HTTP and the API
    can task endpoints, so neither belongs on a public interface.

So the GUI left the container, dialled <public-ip>:8001, and the host no longer
published that port anywhere but loopback. Nothing was misconfigured in
isolation; the two changes were just incompatible.

Fix pins API.hostname to 127.0.0.1 so the GUI's gRPC connection never leaves the
container. It changes only the address DIALLED — bind_address stays 0.0.0.0, so
the backend still reaches the API across the docker network through
api.config.yaml's `api_connection_string: intact_velociraptor:8001`.

Both halves are required and are asserted separately: the generator (fresh
installs) and the self-heal (every already-installed box, since the generator
only runs when server.config.yaml is absent).

Static assertions over entrypoint.sh + the compose file, plus a real sed run
against a representative config. No container, no live server.

Run: docker exec intact_backend python3 /app/workdir/tests/test_velociraptor_api_hostname.py
"""

import os
import re
import subprocess
import sys
import tempfile

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
ENTRYPOINT = os.path.join(REPO, "modules", "velociraptor", "entrypoint.sh")
COMPOSE = os.path.join(REPO, "modules", "velociraptor", "docker-compose.yaml")


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _uncommented(text):
    return "\n".join(ln for ln in text.splitlines()
                     if not ln.lstrip().startswith("#"))


# A config shaped like the one `velociraptor config generate` produces, with the
# key ordering that actually shipped (bind_scheme AFTER bind_port) and the
# same-named hostname keys in other blocks that a careless edit would clobber.
PRE_FIX_CONFIG = """\
Client:
  server_urls:
  - https://192.168.120.11:8000/
API:
  bind_address: 0.0.0.0
  bind_port: 8001
  bind_scheme: tcp
GUI:
  bind_address: 0.0.0.0
  bind_port: 8889
  use_plain_http: true
  base_path: /velociraptor
  public_url: http://192.168.120.11/velociraptor/app/index.html
Frontend:
  hostname: 192.168.120.11
  bind_address: 0.0.0.0
  bind_port: 8000
Monitoring:
  bind_address: 0.0.0.0
  bind_port: 8003
"""


# --- the generator, for fresh installs ---------------------------------------


def test_the_generator_pins_the_api_hostname():
    body = _uncommented(_read(ENTRYPOINT))
    match = re.search(r'"API":\s*\{([^}]*)\}', body)
    assert match, "the API merge block is gone from the config generator"
    api = match.group(1)
    assert "hostname" in api, (
        "the generator does not set API.hostname, so the GUI falls back to "
        "Frontend.hostname (the public address) and cannot reach its own API")
    assert "127.0.0.1" in api, \
        f"API.hostname should keep the gRPC call in-container: {api}"


def test_the_generator_still_binds_the_api_broadly():
    """hostname changes what is DIALLED. If bind_address followed it to
    127.0.0.1 the backend could no longer reach the API over the docker
    network at all."""
    body = _uncommented(_read(ENTRYPOINT))
    api = re.search(r'"API":\s*\{([^}]*)\}', body).group(1)
    assert '"bind_address": "0.0.0.0"' in api, \
        f"the API must still bind 0.0.0.0 for intact_backend to reach it: {api}"


# --- the self-heal, for every existing box -----------------------------------


def test_there_is_a_self_heal_for_existing_configs():
    """The generator only runs when server.config.yaml is absent, so without
    this every already-installed box stays broken."""
    body = _uncommented(_read(ENTRYPOINT))
    assert body.count("hostname: 127.0.0.1") >= 1, \
        "no self-heal that injects API.hostname into an existing config"
    assert re.search(r'if \[ -f server\.config\.yaml \]', body), \
        "the self-heal does not guard on an existing config file"


def test_the_self_heal_is_idempotent():
    """It runs on every container start, so without a guard it would append the
    key again on each restart until the config was full of duplicates."""
    body = _uncommented(_read(ENTRYPOINT))
    guarded = re.search(r'!\s*grep\s+-qE?[^\n]*hostname', body)
    assert guarded, (
        "the self-heal has no `! grep ... hostname` guard, so every container "
        "restart would inject API.hostname again")


def test_the_self_heal_edit_targets_only_the_api_block():
    """Run the real sed against a representative config: the API block gains the
    key, and the identically-named hostname in Frontend must not move."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "server.config.yaml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(PRE_FIX_CONFIG)

        script = (r"sed -i '/^API:/,/^[A-Za-z]/ { /^  bind_port:/a\  hostname: 127.0.0.1"
                  "\n}' " + path)
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        assert r.returncode == 0, f"the self-heal sed failed: {r.stderr}"

        with open(path, "r", encoding="utf-8") as handle:
            out = handle.read()

        api_block = out[out.index("API:"):out.index("GUI:")]
        assert "hostname: 127.0.0.1" in api_block, \
            f"API.hostname was not injected:\n{api_block}"

        # Exactly one injection, and nothing else gained a hostname.
        assert out.count("hostname: 127.0.0.1") == 1, \
            f"the edit fired more than once:\n{out}"
        frontend = out[out.index("Frontend:"):out.index("Monitoring:")]
        assert "hostname: 192.168.120.11" in frontend, \
            "Frontend.hostname was clobbered — enrolled clients dial that address"
        assert "hostname: 127.0.0.1" not in frontend, \
            "the edit leaked into the Frontend block"
        # GUI's public_url must survive: it is what the browser is redirected to.
        assert "public_url: http://192.168.120.11/velociraptor" in out


# --- the constraint that caused this ----------------------------------------


def test_the_api_and_gui_ports_stay_loopback_only():
    """This is the security property the fix has to preserve. If someone
    "fixes" the GUI by republishing 8001/8889 on all interfaces instead, the
    plain-HTTP GUI and the endpoint-tasking API go back on the network."""
    body = _uncommented(_read(COMPOSE))
    ports = re.findall(r'-\s*"([^"]+)"', body)
    for port in ports:
        if port.endswith(":8001") or port.endswith(":8889") or \
           ":8001" in port or ":8889" in port:
            assert port.startswith("127.0.0.1:"), (
                f"port mapping {port!r} exposes the Velociraptor API or GUI off-box; "
                f"they must stay 127.0.0.1-only — fix the GUI's gRPC address "
                f"instead (API.hostname)")


def test_the_client_facing_port_is_still_public():
    """8000 is the one port that MUST be reachable — every enrolled endpoint
    phones home there."""
    body = _uncommented(_read(COMPOSE))
    assert re.search(r'-\s*"8000:8000"', body), \
        "port 8000 is no longer published for enrolled clients"


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

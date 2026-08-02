"""A one-shot setup container that exited 0 is not a health problem.

post_upgrade_health_gate flagged anything under `intact_` that was not
running. intact_elk_setup provisions the Elasticsearch kibana_system user and
then stops — modules/elk/docker-compose.yaml declares it `restart: "no"` — so
`Exited (0)` is that container succeeding. Every upgrade therefore finished
"DEGRADED — 1 problem(s)" naming a container that had done its job, while ELK
itself was up and healthy. A gate that cries wolf on every single run is worse
than no gate: it teaches the operator to skip the one line that would matter
when something is genuinely broken.

The compose file already states the intent, so the gate reads it instead of
hardcoding a name: `restart: "no"` + exit 0 + exited == ran to completion.
Everything else that is not running still reports. On this appliance
intact_elk_setup is the ONLY container declared `restart: "no"` — every real
service is `unless-stopped` — so this narrows the check without creating a
blind spot.

Run: docker exec intact_backend python /app/workdir/tests/test_health_gate_oneshot.py
"""

import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import services.upgrade as up  # noqa: E402


class _Docker:
    """Fake docker. `containers` is {name: (state, status, policy, exit_code)}."""

    def __init__(self, containers):
        self.containers = containers

    def __call__(self, cmd, **kw):
        if cmd.startswith("docker ps -a"):
            rows = [f"{n}\t{c[0]}\t{c[1]}" for n, c in self.containers.items()]
            return {"success": True, "stdout": "\n".join(rows)}
        if cmd.startswith("docker inspect -f '{{.HostConfig.RestartPolicy.Name}}"):
            name = cmd.rsplit(" ", 1)[-1]
            _s, _st, policy, code = self.containers[name]
            return {"success": True, "stdout": f"{policy} {code}"}
        if cmd.startswith("docker inspect -f '{{.Config.Image}}'"):
            return {"success": True, "stdout": "intact-backend:test"}
        return {"success": True, "stdout": ""}


def _gate(containers, **kw):
    orig = up.run_command
    up.run_command = _Docker(containers)
    try:
        return up.post_upgrade_health_gate(budget_s=5, **kw)
    finally:
        up.run_command = orig


SETUP_OK = ("exited", "Exited (0) 2 hours ago", "no", 0)
ES_UP = ("running", "Up 2 hours (healthy)", "unless-stopped", 0)


def test_oneshot_that_exited_zero_is_not_a_problem():
    res = _gate({"intact_elk_setup": SETUP_OK, "intact_elasticsearch": ES_UP})
    assert res["problems"] == [], res["problems"]
    assert res["healthy"], res


def test_oneshot_that_exited_nonzero_still_reports():
    """The setup task failing is exactly what this gate is for."""
    res = _gate({"intact_elk_setup": ("exited", "Exited (1) 2 hours ago", "no", 1)})
    assert any("intact_elk_setup" in p for p in res["problems"]), res["problems"]


def test_a_stopped_service_still_reports():
    """nginx is restart:unless-stopped — if it is down, that is a real fault
    even though it also exited 0. This is the blind spot the narrowing must
    not open."""
    res = _gate({"intact_nginx": ("exited", "Exited (0) 1 minute ago",
                                  "unless-stopped", 0)})
    assert any("intact_nginx" in p for p in res["problems"]), res["problems"]


def test_unhealthy_running_container_still_reports():
    res = _gate({"intact_backend": ("running", "Up 2 minutes (unhealthy)",
                                    "unless-stopped", 0)})
    assert any("unhealthy" in p for p in res["problems"]), res["problems"]


def test_backend_image_identity_check_survives():
    """The other half of the gate — the check that caught the 2026-07-22
    silent no-op swap — must keep working alongside the narrowing."""
    res = _gate({"intact_elk_setup": SETUP_OK},
                expected_backend_tag="intact-20260803")
    assert any("image swap did not take effect" in p for p in res["problems"]), \
        res["problems"]


def test_matching_backend_image_is_clean():
    res = _gate({"intact_elk_setup": SETUP_OK}, expected_backend_tag="test")
    assert res["problems"] == [], res["problems"]


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:      # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)

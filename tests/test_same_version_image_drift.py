""""Same version" is not the same as "same image".

_upgrade_noop_module() decides a module needs nothing done by comparing its
config.yaml version pins before and after the release merge. That is exact for
pinned upstream images -- postgres:13.0-alpine is postgres:13.0-alpine.

It is wrong for images BUILT from repo source. velociraptor-server comes from
modules/velociraptor/Dockerfile + entrypoint.sh, so a source change produces a
different image under an unchanged pin. The orchestrator's pre-load then
`docker load`s the new image and REASSIGNS the tag, while this function says
"nothing to do" and the container is never recreated. The store and the running
container silently disagree, and the only visible symptom is `docker ps`
printing a bare image ID instead of the tag.

Not hypothetical. The 2026-08-02 `chmod +x` -> `chmod 755` fix in
modules/velociraptor/entrypoint.sh lives entirely inside the image and does not
move the 0.77.1 pin:

    cp /opt/velociraptor/linux/velociraptor . && chmod 755 velociraptor

Symbolic `+x` is filtered by the process umask; `755` is not. Every operator
already on 0.77.1 -- exactly the population carrying the bug -- would be skipped
as "same version" and never receive the fix. Observed on this box: the running
container's image was created 22:31 while the tag resolved to one created
18:52.

So compare identity, not labels. Any failure to determine drift returns False
(do process), matching the rest of _upgrade_noop_module: never skip something
that might need work.

Run: docker exec intact_backend python /app/workdir/tests/test_same_version_image_drift.py
"""

import inspect
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import services.upgrade as up  # noqa: E402
from services.upgrade import _module_image_drifted  # noqa: E402


class _Docker:
    """Fake daemon. `running` is the container's image ID, `tagged` is what the
    tag currently resolves to."""

    def __init__(self, running="sha256:aaa", tagged="sha256:aaa",
                 ref="velociraptor-server:0.77.1", fail=()):
        self.running, self.tagged, self.ref, self.fail = running, tagged, ref, set(fail)
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        if "{{.Image}}" in cmd:
            return {"success": "running" not in self.fail, "stdout": self.running}
        if "{{.Config.Image}}" in cmd:
            return {"success": "ref" not in self.fail, "stdout": self.ref}
        if "{{.Id}}" in cmd:
            return {"success": "tagged" not in self.fail, "stdout": self.tagged}
        return {"success": True, "stdout": ""}


def _drift(module="velociraptor", **kw):
    orig = up.run_command
    up.run_command = _Docker(**kw)
    try:
        return _module_image_drifted(module)
    finally:
        up.run_command = orig


def test_reassigned_tag_is_drift():
    """The bug: docker load moved the tag, the container kept the old layers."""
    assert _drift(running="sha256:old", tagged="sha256:new") is True


def test_matching_ids_are_not_drift():
    """The common case must stay a no-op, or every upgrade recreates every
    module and the skip optimisation is dead."""
    assert _drift(running="sha256:same", tagged="sha256:same") is False


def test_a_module_with_no_container_is_not_drift():
    """aws_sigma / o365rc have no container concept — nothing to compare."""
    assert _drift(module="aws_sigma") is False


def test_an_unknown_module_is_not_drift():
    assert _drift(module="not-a-module") is False


def test_a_missing_tag_is_not_drift():
    """If the tag is gone entirely, compose will pull or build it — that is a
    different path, and claiming drift here would force a pointless recreate."""
    assert _drift(fail=("tagged",)) is False


def test_daemon_failure_is_not_drift():
    """Never invent drift from a failed inspect — that would recreate every
    module on any transient docker hiccup."""
    assert _drift(fail=("running",)) is False
    assert _drift(fail=("ref",)) is False


def test_noop_module_consults_the_drift_check():
    """Wiring: the drift check must actually gate the skip decision."""
    body = inspect.getsource(up._upgrade_noop_module)
    assert "_module_image_drifted" in body, (
        "_upgrade_noop_module no longer consults the image-drift check — a "
        "rebuilt image under an unchanged pin will be skipped again")


def test_drift_is_checked_after_the_pin_comparison():
    """Pins are cheap and local; the drift check shells out to docker three
    times. Only reach for it once the pins have already said 'no change'."""
    body = inspect.getsource(up._upgrade_noop_module)
    assert body.index("pre_merge.get(key)") < body.index("_module_image_drifted"), (
        "the drift check runs before the pin comparison — three docker "
        "inspects on every module even when a pin obviously moved")


def test_drift_returning_true_means_do_process():
    """Sense check on the polarity. Drift must make the module NOT a no-op."""
    body = inspect.getsource(up._upgrade_noop_module)
    tail = body[body.index("_module_image_drifted"):]
    assert "return False" in tail.split("\n")[1], (
        "drift no longer forces the module to be processed — the polarity is "
        "inverted and drifted modules would be skipped harder")


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

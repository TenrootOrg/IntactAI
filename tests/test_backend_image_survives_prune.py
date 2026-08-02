"""The backend runtime image must survive the unselected-image prune, and
must still resolve when the package names it with a different tag.

Two independent failures conspired to abort the intact-20260802 apply with
"backend runtime image intact-backend:intact-20260802 is neither present nor
bundled in the package" — for a package that DID contain
images/intact-backend-intact-20260802.tar.

  1. ORDERING. run_offline_upgrade_workflow prunes the image tars of unselected
     modules to save disk, then ~100 lines later force-includes 'intact' into
     the apply set (because a package whose platform upgrade is skipped is a
     half-applied release). With 'intact' deselected by the operator, the prune
     computed its keep-set from the RAW subset and deleted both tars that
     images_by_module attributes to 'intact' — intact-backend-<tag>.tar and
     tusd-<ver>.tar — and the force-include then queued intact to upgrade with
     its image already gone. The fix hoists the whole module-set resolution
     above the prune so the prune keys off the EFFECTIVE set.

  2. NAMING. ensure_backend_runtime_image looked for exactly
     intact-backend-<manifest versions.intact>.tar. The packager names that
     file from a different value (`_release_tag or versions.backend or
     target_version`), so the two disagree whenever they were resolved
     differently — an older package built while versions.backend was a moving
     pin like 'development', or a newer one that derives the release tag some
     other way. A cosmetic filename disagreement became a hard abort on a
     package carrying a perfectly good image. The fix resolves by content:
     load whatever intact-backend tar the package ships and retag it.

The error text is pinned too. The old message blamed CI ("re-prepare the
package with a Wave-F-capable release") for a failure whose cause was local
file deletion, which sent the diagnosis in exactly the wrong direction.

Run: docker exec intact_backend python /app/workdir/tests/test_backend_image_survives_prune.py
"""

import inspect
import os
import sys
import tempfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import run_offline_upgrade_workflow  # noqa: E402
from services.upgrade import intact as intact_mod  # noqa: E402
from services.upgrade.package import images_by_module  # noqa: E402

SRC = inspect.getsource(run_offline_upgrade_workflow)


# ---------------------------------------------------------------------------
# 1. Ordering: the effective apply set is resolved BEFORE the prune runs
# ---------------------------------------------------------------------------

def _pos(needle):
    i = SRC.find(needle)
    assert i != -1, f"anchor vanished from run_offline_upgrade_workflow: {needle!r}"
    return i


def test_force_include_of_intact_precedes_the_prune():
    """The line that adds 'intact' to the apply set must execute before the
    line that decides which image tars to delete. This is the whole bug."""
    assert _pos("selected_set.add('intact')") < _pos("_owned = images_by_module("), (
        "the 'intact' force-include moved back below the image prune — the "
        "prune will again delete intact-backend-<tag>.tar for an apply that "
        "then upgrades intact")


def test_prune_keys_off_the_effective_set_not_the_raw_argument():
    """`selected_modules` is what the caller asked for; `selected_set` is what
    will actually be applied. The prune must use the latter."""
    prune = SRC[_pos("Drop the image tars"):_pos("Second disk check")]
    assert "_keep = set(selected_set)" in prune, (
        "prune keep-set is not built from selected_set")
    assert "set(selected_modules)" not in prune, (
        "prune still derives its keep-set from the raw selected_modules argument")


def test_disk_budget_also_sized_from_the_effective_set():
    """A force-included intact brings a multi-GB image back into the
    requirement; budgeting from the raw subset under-counts it."""
    budget = SRC[_pos("Second disk check"):_pos("State persisted across")]
    assert "sorted(selected_set) if selected_set else selected_modules" in budget, (
        "disk budget is not sized from the effective apply set")


def test_downgrade_check_runs_before_anything_is_deleted():
    """A refused downgrade must leave the extracted package intact too, not
    just the platform — otherwise a retry re-extracts 6 GB for nothing."""
    assert _pos("_reject_downgrades(") < _pos("_owned = images_by_module("), (
        "the downgrade check now runs after the prune has deleted files")


def test_intact_owns_the_backend_and_tusd_tars():
    """The attribution that made the prune dangerous. Pinned so a future
    re-attribution is a deliberate choice rather than a silent one."""
    owned = images_by_module([
        "intact-backend-intact-20260802.tar", "tusd-v2.9.2.tar",
        "opensearch-2.19.5.tar",
    ])
    assert set(owned.get("intact", [])) == {
        "intact-backend-intact-20260802.tar", "tusd-v2.9.2.tar"}, owned


# ---------------------------------------------------------------------------
# 2. Naming: resolve the backend image by content, not by exact filename
# ---------------------------------------------------------------------------

class _Docker:
    """Minimal fake docker. `store` is the set of refs that exist locally."""

    def __init__(self, store=()):
        self.store = set(store)
        self.commands = []

    def run_command(self, cmd, **kw):
        self.commands.append(cmd)
        if cmd.startswith("docker image inspect "):
            return {"success": cmd.split()[-1] in self.store, "stdout": ""}
        if cmd.startswith("docker tag "):
            _, _, src, dst = cmd.split()
            if src in self.store:
                self.store.add(dst)
                return {"success": True, "stdout": ""}
            return {"success": False, "stdout": ""}
        if cmd.startswith("docker images "):
            return {"success": True,
                    "stdout": "\n".join(sorted(r for r in self.store
                                               if r.startswith("intact-backend:")))}
        return {"success": True, "stdout": ""}


def _with_fake_docker(docker, loads_as=None):
    """Patch intact.py's module-level run_command / load_docker_image."""
    def load_docker_image(tar, **kw):
        if loads_as is None:
            return {"success": False, "stdout": "", "error": "no"}
        docker.store.add(loads_as)
        return {"success": True, "stdout": f"Loaded image: {loads_as}\n"}

    orig = (intact_mod.run_command, intact_mod.load_docker_image)
    intact_mod.run_command = docker.run_command
    intact_mod.load_docker_image = load_docker_image
    return orig


def _restore(orig):
    intact_mod.run_command, intact_mod.load_docker_image = orig


def _package(*tar_names):
    d = tempfile.mkdtemp(prefix="pkgtest-")
    os.makedirs(os.path.join(d, "images"))
    for n in tar_names:
        with open(os.path.join(d, "images", n), "wb") as f:
            f.write(b"x")
    return d


def test_exact_tar_name_still_works():
    docker = _Docker()
    orig = _with_fake_docker(docker, loads_as="intact-backend:intact-20260802")
    try:
        pkg = _package("intact-backend-intact-20260802.tar")
        res = intact_mod.ensure_backend_runtime_image(pkg, "intact-20260802")
        assert res["available"], res
    finally:
        _restore(orig)


def test_already_present_image_needs_no_tar():
    """Crash-resume and the online path: the image is already in the store and
    the tar was reclaimed by load_all_bundled_images(cleanup_after_load)."""
    docker = _Docker(store={"intact-backend:intact-20260802"})
    orig = _with_fake_docker(docker, loads_as=None)
    try:
        res = intact_mod.ensure_backend_runtime_image(_package(), "intact-20260802")
        assert res["available"], res
    finally:
        _restore(orig)


def test_mismatched_filename_tag_is_loaded_and_retagged():
    """PREVIOUS releases: package built while versions.backend was still
    'development', so the tar is intact-backend-development.tar while the
    manifest asks for intact-backend:intact-20260802."""
    docker = _Docker()
    orig = _with_fake_docker(docker, loads_as="intact-backend:development")
    try:
        pkg = _package("intact-backend-development.tar")
        res = intact_mod.ensure_backend_runtime_image(pkg, "intact-20260802")
        assert res["available"], res
        assert "intact-backend:intact-20260802" in docker.store, (
            "loaded the package's backend image but never retagged it to the "
            "release being applied")
        assert any(c.startswith("docker tag intact-backend:development "
                                "intact-backend:intact-20260802")
                   for c in docker.commands), docker.commands
    finally:
        _restore(orig)


def test_future_tag_scheme_is_also_retagged():
    """NEXT releases: same mechanism in the other direction — a package whose
    filename carries a tag this code has never seen still resolves."""
    docker = _Docker()
    orig = _with_fake_docker(docker, loads_as="intact-backend:2027.1-rc3")
    try:
        pkg = _package("intact-backend-2027.1-rc3.tar")
        res = intact_mod.ensure_backend_runtime_image(pkg, "intact-20261115")
        assert res["available"], res
        assert "intact-backend:intact-20261115" in docker.store
    finally:
        _restore(orig)


def test_genuinely_absent_image_still_fails():
    """The retag fallback must not turn a real packaging failure into a pass."""
    docker = _Docker()
    orig = _with_fake_docker(docker, loads_as=None)
    try:
        res = intact_mod.ensure_backend_runtime_image(
            _package("opensearch-2.19.5.tar"), "intact-20260802")
        assert not res["available"], res
    finally:
        _restore(orig)


def test_failure_names_the_evidence_not_the_build_system():
    """The message must say what is on disk. Blaming CI for a locally-deleted
    file is what made this take a day to find."""
    docker = _Docker()
    orig = _with_fake_docker(docker, loads_as=None)
    try:
        res = intact_mod.ensure_backend_runtime_image(
            _package("opensearch-2.19.5.tar"), "intact-20260802")
        err = res["error"]
        assert "opensearch-2.19.5.tar" in err, (
            "error does not list what images/ actually contains: " + err)
        assert "prune" in err, (
            "error does not point at the local prune as a candidate cause: " + err)
    finally:
        _restore(orig)


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

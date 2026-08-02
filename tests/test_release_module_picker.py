"""Guard the CI release-package module picker.

Every release ships EVERY module. The picker used to diff against a baseline
release and bundle only modules whose pin moved; that made a package's contents
depend on where you built from, while the online flow downloads exactly ONE
package for the target ref and never walks the chain. A customer who skipped a
release got a package diffed against a baseline newer than what they ran, so
whatever changed in the gap was simply absent -- and the upgrade still reported
success. Shipping everything trades size for that whole class of silent skew.

With the diff gone, one failure mode remains and it is just as quiet: a new
module lands in UPGRADE_ORDER and config.yaml, nobody adds it to
RELEASE_MODULES, and no release ever carries it. An air-gapped operator then
has no way to obtain that module at all. That is what these tests pin.

Run: docker exec intact_backend python /app/workdir/tests/test_release_module_picker.py
"""

import inspect
import os
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

_ROOT = os.environ.get("INTACT_PATH", "/app/workdir")
_SCRIPT = os.path.join(_ROOT, "scripts", "ci", "build_release_package.py")

TAG = "intact-20260728"


def _load_picker():
    import importlib.util
    spec = importlib.util.spec_from_file_location("_bp", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _config_path():
    """The platform config to assert against.

    config.yaml is the OPERATOR's file and is no longer tracked in git — it
    accumulates the GitHub PAT, the dashboard login and every module password, so
    it is tracked but sanitized on commit by the pre-commit hook. On an installed box
    the real file exists and is the more faithful thing to test; in a fresh
    checkout (CI) only the template does, and for the module list they are
    equivalent.
    """
    for name in ("config.yaml",):
        path = os.path.join(_ROOT, name)
        if os.path.isfile(path):
            return path
    raise AssertionError(
        f"config.yaml not found under {_ROOT}")


def _config_modules():
    import yaml
    with open(_config_path()) as handle:
        cfg = yaml.safe_load(handle) or {}
    return set(cfg.get("modules") or {})


def test_release_modules_covers_every_upgradeable_module():
    """RELEASE_MODULES must equal UPGRADE_ORDER exactly.

    UPGRADE_ORDER is the platform's own list of what an upgrade can install.
    Anything in it that RELEASE_MODULES omits is a module no release ever
    bundles; anything RELEASE_MODULES adds beyond it is a module the packager
    has no upgrade handler for.
    """
    bp = _load_picker()
    from services.upgrade import UPGRADE_ORDER
    missing = set(UPGRADE_ORDER) - set(bp.RELEASE_MODULES)
    extra = set(bp.RELEASE_MODULES) - set(UPGRADE_ORDER)
    assert not missing, (
        f"{sorted(missing)} are upgradeable but never shipped in a release -- "
        f"an air-gapped box can never obtain them. Add them to RELEASE_MODULES.")
    assert not extra, (
        f"{sorted(extra)} are in RELEASE_MODULES but not UPGRADE_ORDER -- "
        f"the packager has no handler for them.")


def test_every_configured_module_ships():
    """A module an operator can enable in config.yaml must be shippable."""
    bp = _load_picker()
    unshipped = _config_modules() - set(bp.RELEASE_MODULES)
    assert not unshipped, (
        f"config.yaml offers {sorted(unshipped)} but no release bundles them")


def test_full_scope_is_built_regardless_of_history():
    """The resolved set is the whole allowlist -- no baseline, no diff."""
    bp = _load_picker()
    modules = bp.release_module_set(TAG)
    missing = set(bp.RELEASE_MODULES) - set(modules)
    assert not missing, (
        f"{sorted(missing)} dropped out of the build -- their pins are absent "
        f"from config.yaml versions:")


def test_no_diff_baseline_parameter_survives():
    """Guard against the diff being reintroduced by accident.

    release_module_set() taking a baseline again is exactly the regression this
    change removes, and it would be invisible: the build still succeeds, just
    with a thinner package.
    """
    bp = _load_picker()
    params = set(inspect.signature(bp.release_module_set).parameters)
    assert params == {"tag"}, (
        f"release_module_set takes {sorted(params)} -- a baseline/diff "
        f"parameter is back; releases must always ship the full module set")
    for gone in ("_changed_since", "_previous_release", "ALWAYS_SHIP"):
        assert not hasattr(bp, gone), f"{gone} is back -- diff logic reintroduced"


def test_intact_is_pinned_to_the_release_tag():
    """Phase 1 resolves intact-backend:<versions.intact>; anything else sends
    every upgraded box hunting for an image the package does not contain."""
    bp = _load_picker()
    assert bp.release_module_set(TAG)["intact"] == TAG

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
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)

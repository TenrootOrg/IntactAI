"""Tests for _intact_first() — prepare-package module ordering.

The prepare step must process 'intact' FIRST: it extracts the release into
source/intact/, which later modules read from — notably velociraptor, whose image
bake refreshes its build files from source/intact/modules/velociraptor. A prepare
ordered velociraptor-before-intact (e.g. selected_modules=[velociraptor]) would
otherwise bake from stale on-disk files and ship a bundle-less image.

Run:  docker exec intact_backend python /app/workdir/tests/test_prepare_module_order.py
"""

import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade.package import _intact_first   # noqa: E402


def _order(d):
    return [k for k, _ in _intact_first(d)]


def test_intact_moved_to_front_when_last():
    # the failing case: velociraptor before intact
    assert _order({"velociraptor": "0.77.1", "intact": "development"}) == ["intact", "velociraptor"]


def test_intact_stays_first_if_already_first():
    assert _order({"intact": "development", "velociraptor": "0.77.1", "elk": "9.4.2"}) \
        == ["intact", "velociraptor", "elk"]


def test_other_modules_keep_relative_order():
    order = _order({"velociraptor": "1", "elk": "2", "intact": "dev", "timesketch": "3"})
    assert order[0] == "intact"
    assert order[1:] == ["velociraptor", "elk", "timesketch"]   # stable sort


def test_no_intact_is_unchanged():
    assert _order({"velociraptor": "1", "elk": "2"}) == ["velociraptor", "elk"]


def test_values_preserved():
    out = dict(_intact_first({"velociraptor": "0.77.1", "intact": "development"}))
    assert out == {"intact": "development", "velociraptor": "0.77.1"}


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)

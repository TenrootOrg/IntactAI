"""Fusion module-gating tests (services/fusion/store.py).

A case's `fusion_modules` decides which run TYPES fuse into its graph. These pure
helpers drive that:
- normalize_modules: legacy-name migration + default.
- fusion_modules_catalog: the UI picker model (label / available / default).
- _enabled_run_types: enabled modules -> the set of fusable automation types.

Run:  docker exec intact_backend python /app/services/fusion/tests/test_module_gating.py
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import store as S   # noqa: E402


# --------------------------------------------------------------------------
# normalize_modules
# --------------------------------------------------------------------------
def test_normalize_empty_returns_default():
    assert S.normalize_modules(None) == list(S.FUSION_MODULES_DEFAULT)
    assert S.normalize_modules([]) == list(S.FUSION_MODULES_DEFAULT)


def test_normalize_legacy_velociraptor_alias():
    assert S.normalize_modules(["velociraptor"]) == ["velociraptor_agentic"]


def test_normalize_passthrough_known_modules():
    assert S.normalize_modules(["memory", "cve"]) == ["memory", "cve"]


def test_normalize_mixed_legacy_and_new():
    assert S.normalize_modules(["velociraptor", "memory"]) == ["velociraptor_agentic", "memory"]


# --------------------------------------------------------------------------
# fusion_modules_catalog
# --------------------------------------------------------------------------
def test_catalog_lists_every_ui_module_in_order():
    cat = S.fusion_modules_catalog()
    assert [c["name"] for c in cat] == list(S.FUSION_MODULES_UI)
    # legacy alias is never shown in the picker
    assert "velociraptor" not in [c["name"] for c in cat]


def test_catalog_available_and_default_flags():
    cat = {c["name"]: c for c in S.fusion_modules_catalog()}
    assert cat["velociraptor_agentic"]["default"] is True
    assert cat["velociraptor_agentic"]["available"] is True
    # 'velociraptor_all' was removed from the picker (only agentic blueprints
    # are fusable now) — it stays in FUSION_MODULE_TYPES purely as a legacy
    # alias target for cases saved before the split, but is never shown here.
    assert "velociraptor_all" not in cat
    assert cat["memory"]["available"] is True
    assert cat["memory"]["default"] is True
    assert cat["aws"]["available"] is True
    # the rest are shown but disabled
    assert cat["timesketch"]["available"] is False
    assert cat["cve"]["available"] is False


def test_catalog_has_labels():
    cat = {c["name"]: c for c in S.fusion_modules_catalog()}
    assert cat["velociraptor_agentic"]["label"] == "Velociraptor (Agentic)"
    assert cat["memory"]["label"] == "Memory (VolWeb)"


# --------------------------------------------------------------------------
# _enabled_run_types
# --------------------------------------------------------------------------
def test_enabled_types_default_is_agentic_plus_memory():
    # FUSION_MODULES_DEFAULT = ["velociraptor_agentic", "memory"] — both fuse
    # by default on a case with no explicit fusion_modules set.
    assert S._enabled_run_types({}) == {"velociraptor_collection", "velociraptor_upload", "memory"}


def test_enabled_types_all_alias_maps_to_agentic_no_hunts():
    # 'velociraptor_all' is a legacy alias now — normalize_modules() collapses
    # it to 'velociraptor_agentic', so hunts are intentionally NOT included
    # (only agentic-blueprint runs are fusable; see store.py's module docstring).
    got = S._enabled_run_types({"fusion_modules": ["velociraptor_all"]})
    assert got == {"velociraptor_collection", "velociraptor_upload"}
    assert "velociraptor_hunt" not in got


def test_enabled_types_agentic_excludes_hunts():
    got = S._enabled_run_types({"fusion_modules": ["velociraptor_agentic"]})
    assert "velociraptor_hunt" not in got


def test_enabled_types_union_of_modules():
    got = S._enabled_run_types({"fusion_modules": ["memory", "cve"]})
    assert got == {"memory", "cve_scan"}


def test_enabled_types_legacy_alias_maps_to_agentic():
    assert S._enabled_run_types({"fusion_modules": ["velociraptor"]}) == \
        {"velociraptor_collection", "velociraptor_upload"}


def test_enabled_types_unknown_module_contributes_nothing():
    # An unknown module name simply adds no run types (no crash).
    assert S._enabled_run_types({"fusion_modules": ["bogus_module"]}) == set()


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

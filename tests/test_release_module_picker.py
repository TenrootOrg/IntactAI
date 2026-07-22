"""Guard the CI release-package module picker.

The picker decides what a release tarball contains. Both failure directions are
expensive and neither is loud:

  - ship too much -> multi-GB packages (elk + volweb dominate) for no benefit,
    since the apply side skips same-version modules anyway;
  - ship too little -> the upgrade reports success while the customer keeps
    running the old thing. That is the silent-skew class this codebase has
    been bitten by repeatedly, and it is invisible in a green test run.

The nastiest instance is sidecar attribution. Transitive pins
(`timesketch_opensearch`, `volweb_redis`, `sigma_rules`, ...) live only in
`versions:`, never in `modules:`, but images are bundled per MODULE. Matching
on the literal key means a release that bumps ONLY a sidecar — opensearch
2.11 -> 2.19 for a CVE, say — ships no timesketch at all, so the patched image
never reaches anyone. A real instance shipped in the 20260615 -> 20260722 diff:
`volweb_redis` moved 7 -> 7.4.9 while `volweb` itself did not.

Run: docker exec intact_backend python /app/workdir/tests/test_release_module_picker.py
"""

import os
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

_SCRIPT = os.path.join(os.environ.get("INTACT_PATH", "/app/workdir"),
                       "scripts", "ci", "build_release_package.py")


def _load_picker():
    import importlib.util
    spec = importlib.util.spec_from_file_location("_bp", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


KNOWN = {"elk", "timesketch", "plaso", "iris", "velociraptor", "aws_sigma",
         "o365rc", "volweb", "cve_scan", "portainer", "intact"}

BASE = {
    "elk": "9.4.2", "iris": "v2.4.26", "plaso": "20260119", "portainer": "2.39.1",
    "timesketch": "20260326", "velociraptor": "0.76.1", "o365rc": "latest",
    "volweb": "3.16.0",
    "timesketch_opensearch": "2.11.0", "timesketch_postgres": "13.0-alpine",
    "timesketch_redis": "7-alpine", "timesketch_nginx": "alpine",
    "iris_rabbitmq": "3-management-alpine", "volweb_postgres": "14.1",
    "volweb_redis": "7", "velociraptor_legacy": "0.7.1",
    "backend_tusd": "v2.9.2", "nginx": "1.31.2-alpine",
    "sigma_rules": "r2026-06-01",
}

# (name, mutation, must_ship, must_not_ship)
SCENARIOS = [
    ("nothing changed", {}, set(), {"elk", "timesketch", "volweb"}),
    ("single module bump", {"timesketch": "20260630"}, {"timesketch"}, {"elk", "volweb"}),
    ("brand-new module", {"aws_sigma": "2026.04"}, {"aws_sigma"}, {"elk"}),
    ("module removed upstream", {"volweb": None}, set(), {"volweb"}),
    ("everything bumps",
     {"elk": "10.0.0", "iris": "v3.0.0", "plaso": "20270101", "portainer": "3.0.0",
      "timesketch": "20270101", "velociraptor": "1.0.0", "volweb": "4.0.0"},
     {"elk", "iris", "plaso", "portainer", "timesketch", "velociraptor", "volweb"}, set()),
    # sidecar-only bumps: the parent MUST be dragged in
    ("opensearch sidecar only", {"timesketch_opensearch": "2.19.5"}, {"timesketch"}, {"elk"}),
    ("rabbitmq sidecar only", {"iris_rabbitmq": "4-management"}, {"iris"}, {"elk"}),
    ("volweb redis sidecar only", {"volweb_redis": "7.4.9"}, {"volweb"}, {"elk"}),
    ("velociraptor legacy binary only", {"velociraptor_legacy": "0.7.2"}, {"velociraptor"}, set()),
    ("sigma rule pack only", {"sigma_rules": "r2026-08-01"}, {"aws_sigma"}, set()),
    # combinations
    ("new module + foreign sidecar",
     {"aws_sigma": "2026.04", "timesketch_opensearch": "2.19.5"},
     {"aws_sigma", "timesketch"}, {"elk", "volweb"}),
    ("module and its own sidecar together",
     {"timesketch": "20260630", "timesketch_opensearch": "2.19.5"}, {"timesketch"}, {"elk"}),
    # pins that map to no module, or to a module that always ships anyway
    ("unattributable pin", {"mystery_thing": "v9"}, set(), set()),
    ("platform sidecar (tusd)", {"backend_tusd": "v3.0.0"}, set(), {"elk"}),
]


def _pick(bp, base, new):
    """Run the REAL _changed_since with the network fetch stubbed out."""
    import services.upgrade.resolver as resolver
    resolver.fetch_upstream_config = lambda ref, user_action=None: {"versions": base}
    bp.fetch_upstream_config = resolver.fetch_upstream_config
    return bp._changed_since("baseline", new, KNOWN) | bp.ALWAYS_SHIP


def test_picker_scenarios():
    bp = _load_picker()
    failures = []
    for name, mutation, must, must_not in SCENARIOS:
        new = dict(BASE)
        for k, v in mutation.items():
            new.pop(k, None) if v is None else new.__setitem__(k, v)
        got = _pick(bp, BASE, new)
        missing, leaked = must - got, must_not & got
        if missing or leaked:
            failures.append(f"{name}: missing={sorted(missing)} leaked={sorted(leaked)}")
    assert not failures, "picker scenarios failed:\n  " + "\n  ".join(failures)


def test_always_ship_is_unconditional():
    """intact and cve_scan must survive a completely empty diff.

    A version comparison structurally cannot see either one change: intact's
    "version" is the release tag, and cve_scan is versionless (rolling NVD
    corpus). Drop them and a release silently stops delivering the platform
    itself or a fresh CVE database.
    """
    bp = _load_picker()
    assert bp.ALWAYS_SHIP == {"intact", "cve_scan"}, bp.ALWAYS_SHIP
    assert _pick(bp, BASE, dict(BASE)) == {"intact", "cve_scan"}


def test_previous_release_resolution():
    """_previous_release picks the newest published release before the target.

    Package assets are deliberately NOT required. A box can be running a
    release it installed from source, and computing a diff only needs that
    release's config.yaml, which the tag carries whether or not a tarball was
    ever attached. An earlier draft required assets and resolved to NOTHING
    for intact-20260722 — because intact-20260615 is a real published release
    with no assets — silently falling back to shipping all ten modules.

    Drafts stay excluded: nobody can be running one.
    """
    bp = _load_picker()

    fake = [
        {"tag_name": "intact-20260801", "draft": False, "assets": []},
        {"tag_name": "intact-20260722", "draft": False, "assets": []},
        {"tag_name": "intact-20260721", "draft": False, "assets": []},  # no package
        {"tag_name": "intact-20260715", "draft": True,  "assets": []},  # draft
        {"tag_name": "intact-20260615", "draft": False, "assets": []},
        {"tag_name": "v-not-a-release", "draft": False, "assets": []},  # foreign tag
    ]

    import io, json, urllib.request
    orig = urllib.request.urlopen
    urllib.request.urlopen = lambda *a, **k: io.BytesIO(json.dumps(fake).encode())
    try:
        # newest predecessor wins, package or not
        assert bp._previous_release("intact-20260722") == "intact-20260721"
        assert bp._previous_release("intact-20260801") == "intact-20260722"
        # never itself, never newer, and None when nothing precedes it
        assert bp._previous_release("intact-20260615") is None
        # a draft is skipped in favour of the next real release below it
        assert bp._previous_release("intact-20260721") == "intact-20260615"
    finally:
        urllib.request.urlopen = orig


def test_every_config_pin_maps_to_a_module():
    """Every pin in the shipped config.yaml must attribute to some module.

    An unattributable pin is one nothing bundles: it can change release after
    release and never reach a customer. Catching it here is the difference
    between a build-time warning and a silent field bug.
    """
    import yaml
    bp = _load_picker()
    cfg_path = os.path.join(os.environ.get("INTACT_PATH", "/app/workdir"), "config.yaml")
    cfg = yaml.safe_load(open(cfg_path)) or {}
    known = set(cfg.get("modules") or {}) | {"intact"}
    orphans = [p for p in (cfg.get("versions") or {})
               if p != "backend" and bp._owning_module(p, known) is None]
    assert not orphans, (
        f"version pins owned by no module: {sorted(orphans)} — nothing would "
        f"bundle them. Add each to _PIN_OWNER in build_release_package.py.")


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failed += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:
                failed += 1
                print(f"ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{'FAILED' if failed else 'OK'} — {failed} failure(s)")
    sys.exit(1 if failed else 0)

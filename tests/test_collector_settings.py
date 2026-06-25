"""Offline-collector settings, encryption-spec, and blueprint-mapping tests.

Covers the resource/safety knobs and encryption wiring added to the offline
collector:
- constants: concurrency / progress-timeout defaults, the per-OS artifact tables,
  and the heavy-filesystem-scanner deny-list.
- generator._encryption_spec: the pure VQL fragment builder for none/password/x509.
- generator.get_blueprint_as_config: maps a blueprint's settings onto the
  CreateCollector parameters (CpuLimit / MaxExecutionTimeInSeconds / Concurrency /
  ProgressTimeout), with sane defaults.
- the shipped Linux blueprint (agentic_linux_triage) in default_blueprints.yaml.

Run standalone:  docker exec intact_backend python /app/services/offline_collector/tests/test_collector_settings.py
Or with pytest:  docker exec intact_backend python -m pytest /app/services/offline_collector/tests/test_collector_settings.py -v
"""

import os
import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.offline_collector import constants as C            # noqa: E402
from services.offline_collector import generator as G            # noqa: E402


# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------
def test_concurrency_default_is_higher_than_velociraptor_default():
    # Velociraptor's own opt_concurrency default is 2 (the starvation bug). Ours
    # must be meaningfully higher so a couple of slow artifacts can't block the rest.
    assert C.DEFAULT_COLLECTOR_CONCURRENCY > 2
    assert C.DEFAULT_COLLECTOR_CONCURRENCY == 8


def test_progress_timeout_default():
    assert C.DEFAULT_COLLECTOR_PROGRESS_TIMEOUT == 1800


def test_artifacts_by_os_has_all_three_oses():
    assert set(C.ARTIFACTS_BY_OS) == {"windows", "linux", "darwin"}
    assert C.ARTIFACTS_BY_OS["windows"] is C.DEFAULT_ARTIFACTS
    assert C.ARTIFACTS_BY_OS["linux"] is C.LINUX_DEFAULT_ARTIFACTS
    assert C.ARTIFACTS_BY_OS["darwin"] is C.DARWIN_DEFAULT_ARTIFACTS


def test_linux_default_artifacts_are_all_linux_or_generic():
    assert C.LINUX_DEFAULT_ARTIFACTS, "must not be empty"
    for a in C.LINUX_DEFAULT_ARTIFACTS:
        assert a.startswith(("Linux.", "Generic.")), a
    assert not any(a.startswith("Windows.") for a in C.LINUX_DEFAULT_ARTIFACTS)


def test_darwin_default_artifacts_are_all_macos_or_generic():
    for a in C.DARWIN_DEFAULT_ARTIFACTS:
        assert a.startswith(("MacOS.", "Generic.")), a


def test_heavy_scanners_denylist_present():
    # These broad Generic scanners crawl all of / on Linux — they must be on the
    # deny-list so artifacts_for_os drops them on non-Windows targets.
    for name in ("Generic.Collectors.File", "Generic.Forensic.SQLiteHunter"):
        assert name in C.HEAVY_FS_SCAN_ARTIFACTS


# --------------------------------------------------------------------------
# _encryption_spec — the pure VQL fragment builder
# --------------------------------------------------------------------------
def test_encryption_spec_none_is_empty():
    assert G._encryption_spec("none", None) == ""
    assert G._encryption_spec(None, None) == ""
    assert G._encryption_spec("", "anything") == ""


def test_encryption_spec_password_requires_a_secret():
    assert G._encryption_spec("password", "") == ""        # no secret -> plaintext
    frag = G._encryption_spec("password", "S3cret!")
    assert 'encryption_scheme="password"' in frag
    assert 'encryption_args' in frag
    assert '"password": "S3cret!"' in frag                 # JSON-encoded inline


def test_encryption_spec_x509_uses_server_cert_no_args():
    frag = G._encryption_spec("x509", None)
    assert 'encryption_scheme="x509"' in frag
    assert 'encryption_args' not in frag                   # no key -> server cert fallback


def test_encryption_spec_x509_ignores_any_password():
    # x509 is keyless on our side; a stray password must not leak in.
    assert "password" not in G._encryption_spec("x509", "ignored")


def test_encryption_spec_pgp_and_unknown_are_dropped():
    # PGP was removed; unknown schemes must never silently produce encryption.
    assert G._encryption_spec("pgp", "key") == ""
    assert G._encryption_spec("rot13", "key") == ""


def test_encryption_spec_scheme_is_case_insensitive():
    assert G._encryption_spec("X509", None) == G._encryption_spec("x509", None)
    assert 'encryption_scheme="password"' in G._encryption_spec("PASSWORD", "p")


# --------------------------------------------------------------------------
# get_blueprint_as_config — blueprint settings -> CreateCollector parameters
# --------------------------------------------------------------------------
def _with_velo_blueprint(bp, fn):
    """Run fn() with routes.blueprint_routes patched to return [bp] as the only
    velociraptor blueprint (and no agentic/timesketch). Restores afterwards."""
    import routes.blueprint_routes as br
    saved = (br.load_velociraptor_blueprints, br.load_agentic_blueprints, br.load_timesketch_blueprints)
    br.load_velociraptor_blueprints = lambda: [bp]
    br.load_agentic_blueprints = lambda: []
    br.load_timesketch_blueprints = lambda: []
    try:
        return fn()
    finally:
        (br.load_velociraptor_blueprints, br.load_agentic_blueprints, br.load_timesketch_blueprints) = saved


def test_blueprint_config_maps_all_settings():
    bp = {
        "id": "bp_full", "name": "Full", "artifacts": ["Windows.System.Pslist"],
        "settings": {"cpu_limit": 70, "timeout": 12345, "concurrency": 11, "progress_timeout": 600},
    }
    cfg = _with_velo_blueprint(bp, lambda: G.get_blueprint_as_config("bp_full"))
    p = cfg["parameters"]
    assert p["CpuLimit"] == 70
    assert p["MaxExecutionTimeInSeconds"] == 12345
    assert p["Concurrency"] == 11
    assert p["ProgressTimeout"] == 600
    assert cfg["artifacts"] == ["Windows.System.Pslist"]


def test_blueprint_config_applies_defaults_when_settings_missing():
    bp = {"id": "bp_bare", "name": "Bare", "artifacts": ["Generic.System.Pstree"], "settings": {}}
    cfg = _with_velo_blueprint(bp, lambda: G.get_blueprint_as_config("bp_bare"))
    p = cfg["parameters"]
    assert p["Concurrency"] == C.DEFAULT_COLLECTOR_CONCURRENCY
    assert p["ProgressTimeout"] == C.DEFAULT_COLLECTOR_PROGRESS_TIMEOUT
    assert p["CpuLimit"] == 80               # historical default
    assert p["MaxExecutionTimeInSeconds"] == 3600


def test_blueprint_config_unknown_id_returns_none():
    assert _with_velo_blueprint({"id": "x", "settings": {}},
                                lambda: G.get_blueprint_as_config("does-not-exist")) is None


# --------------------------------------------------------------------------
# shipped Linux blueprint
# --------------------------------------------------------------------------
def _load_default_blueprints():
    import yaml
    path = "/app/config/default_blueprints.yaml"
    if not os.path.exists(path):
        path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "config", "default_blueprints.yaml")
    with open(path) as fh:
        return yaml.safe_load(fh)


def test_linux_blueprint_exists_and_is_linux_only():
    d = _load_default_blueprints()
    lt = [b for b in d.get("velociraptor", []) if b.get("id") == "agentic_linux_triage"]
    assert lt, "agentic_linux_triage blueprint missing from default_blueprints.yaml"
    bp = lt[0]
    assert bp.get("os") == "linux"
    arts = bp.get("artifacts", [])
    assert len(arts) >= 10
    assert not any(a.startswith("Windows.") for a in arts), "Linux blueprint must have no Windows artifacts"
    for a in arts:
        assert a.startswith(("Linux.", "Generic.")), a


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

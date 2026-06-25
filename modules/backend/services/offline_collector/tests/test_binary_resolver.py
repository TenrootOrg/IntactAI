"""Per-OS Velociraptor binary resolver tests (constants.get_velo_client_path).

The resolver maps an OS to the matching binary glob and re-scans /app/downloads on
every call (so it never strands a stale path after an upgrade). Unknown OSes must
return "" rather than guess, and the VELO_CLIENT_PATHS shim must delegate to it.

Run:  docker exec intact_backend python /app/services/offline_collector/tests/test_binary_resolver.py
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.offline_collector import constants as C   # noqa: E402


def test_unknown_os_returns_empty():
    assert C.get_velo_client_path("solaris") == ""
    assert C.get_velo_client_path("") == ""
    assert C.get_velo_client_path(None) == ""


def test_known_oses_return_strings():
    for os_type in ("windows", "linux", "darwin"):
        assert isinstance(C.get_velo_client_path(os_type), str)


def test_linux_path_matches_platform_when_present():
    # In-container a linux binary exists; if resolved, the path must be the linux build.
    p = C.get_velo_client_path("linux")
    if p:
        assert "linux-amd64" in p
        assert "windows" not in p and "darwin" not in p


def test_velo_client_paths_shim_delegates():
    # The backwards-compat dict shim must return exactly what the function returns.
    assert C.VELO_CLIENT_PATHS["linux"] == C.get_velo_client_path("linux")
    assert C.VELO_CLIENT_PATHS["windows"] == C.get_velo_client_path("windows")


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

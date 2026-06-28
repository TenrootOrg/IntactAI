"""Tests for refresh_velociraptor_build_files() — the velociraptor bake fix.

Velociraptor is the only module whose image is built locally; the bake reads the
on-disk modules/velociraptor build files, which aren't covered by the intact
source-mirror. This helper refreshes Dockerfile / entrypoint.sh / .dockerignore /
bundled_artifacts/ from the target release source before any bake, so the image
always carries the current Dockerfile + the full --definitions artifact bundle.
Pure file ops — no mocks.

Run:  docker exec intact_backend python /app/workdir/tests/test_velociraptor_build_refresh.py
"""

import os
import sys
import tempfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade.velociraptor import refresh_velociraptor_build_files   # noqa: E402


def _w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def _src(bundle=("a.yaml", "b.yaml")):
    d = tempfile.mkdtemp(prefix="velo_src_")
    _w(os.path.join(d, "Dockerfile"), "FROM x\nCOPY bundled_artifacts /opt/velociraptor_artifacts\n")
    _w(os.path.join(d, "entrypoint.sh"), "exec ./velociraptor --definitions /opt/velociraptor_artifacts frontend\n")
    _w(os.path.join(d, ".dockerignore"), "velociraptor/\n")
    for y in bundle:
        _w(os.path.join(d, "bundled_artifacts", y), "name: %s\n" % y)
    return d


def test_refresh_copies_build_files_and_bundle():
    src = _src(("a.yaml", "b.yaml", "Windows__Hayabusa__Rules.yaml"))
    dst = tempfile.mkdtemp(prefix="velo_dst_")
    # stale dst content that must be overwritten / pruned
    _w(os.path.join(dst, "Dockerfile"), "OLD — no bundle COPY\n")
    _w(os.path.join(dst, "bundled_artifacts", "stale.yaml"), "name: stale\n")

    ok = refresh_velociraptor_build_files(src, dst)
    assert ok is True
    assert "COPY bundled_artifacts" in open(os.path.join(dst, "Dockerfile")).read()
    assert "--definitions" in open(os.path.join(dst, "entrypoint.sh")).read()
    assert os.path.exists(os.path.join(dst, ".dockerignore"))
    # bundle replaced wholesale: the 3 new YAMLs present, the stale one gone
    got = sorted(os.listdir(os.path.join(dst, "bundled_artifacts")))
    assert got == ["Windows__Hayabusa__Rules.yaml", "a.yaml", "b.yaml"], got
    assert "stale.yaml" not in got


def test_refresh_creates_dst_if_absent():
    src = _src()
    dst = os.path.join(tempfile.mkdtemp(prefix="velo_dst_"), "newdir")
    assert refresh_velociraptor_build_files(src, dst) is True
    assert os.path.exists(os.path.join(dst, "Dockerfile"))
    assert sorted(os.listdir(os.path.join(dst, "bundled_artifacts"))) == ["a.yaml", "b.yaml"]


def test_missing_src_returns_false():
    dst = tempfile.mkdtemp(prefix="velo_dst_")
    assert refresh_velociraptor_build_files(os.path.join(tempfile.mkdtemp(), "nope"), dst) is False
    assert refresh_velociraptor_build_files("", dst) is False


def test_src_without_bundle_still_copies_files():
    # Dockerfile/entrypoint present, no bundled_artifacts dir -> copies files, no crash
    d = tempfile.mkdtemp(prefix="velo_src_")
    _w(os.path.join(d, "Dockerfile"), "FROM x\n")
    dst = tempfile.mkdtemp(prefix="velo_dst_")
    assert refresh_velociraptor_build_files(d, dst) is True
    assert os.path.exists(os.path.join(dst, "Dockerfile"))
    assert not os.path.exists(os.path.join(dst, "bundled_artifacts"))


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

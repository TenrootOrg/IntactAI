"""An upgrade package's own manifest cannot vouch for the package.

`verify_upgrade_package` re-hashes every extracted file against a sha256 map
read out of `manifest.json` — which travels INSIDE the archive it validates.
That proves the archive is INTACT (nothing truncated in transit). It cannot
prove it is AUTHENTIC: anyone able to rewrite the files can rewrite the hashes,
or simply drop the block, which was accepted with an `info`-level "older
prepare" note. Applying a package is privileged — the backend holds a
read-write Docker socket — so the distinction matters.

The online path is anchored: download.py fetches the `.sha256` sidecar
published with the GitHub release and checks the whole tarball against it. The
offline path — an operator carrying a package into an air-gapped site — had no
anchor at all.

So the archive digest is now always computed and logged, and `expected_sha256`
lets the operator supply the value from the release page. CI computes that
digest pre-split (build-release-package.yml), and reassembling the parts
reproduces the whole file byte for byte, so it is the same number.

This does NOT make packages signed. An operator who supplies nothing still gets
an unauthenticated apply — they just now have a digest to compare by eye.

Run: docker exec intact_backend python3 /app/workdir/tests/test_package_digest.py
"""

import hashlib
import os
import sys
import tarfile
import tempfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade.base import verify_upgrade_package  # noqa: E402


def _package(with_sha_map=True, tamper=False):
    """Build a minimal but real .tar.gz package with a manifest."""
    import json
    d = tempfile.mkdtemp(prefix="pkgtest_")
    src = os.path.join(d, "pkg")
    os.makedirs(src)
    payload = os.path.join(src, "payload.txt")
    with open(payload, "w") as fh:
        fh.write("module content")

    manifest = {"version": "test", "contents": {}}
    if with_sha_map:
        h = hashlib.sha256(open(payload, "rb").read()).hexdigest()
        # `tamper` mimics the realistic attack: content changed AND the hash
        # recomputed to match, which the manifest check cannot catch.
        if tamper:
            with open(payload, "w") as fh:
                fh.write("attacker content")
            h = hashlib.sha256(open(payload, "rb").read()).hexdigest()
        manifest["contents"]["sha256"] = {"payload.txt": h}
    with open(os.path.join(src, "manifest.json"), "w") as fh:
        json.dump(manifest, fh)

    tgz = os.path.join(d, "package.tar.gz")
    with tarfile.open(tgz, "w:gz") as tf:
        for name in os.listdir(src):
            tf.add(os.path.join(src, name), arcname=name)
    return tgz


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _logs(pkg, **kw):
    out = []
    res = verify_upgrade_package(pkg, logger=lambda m, l="info": out.append((l, m)), **kw)
    return res, out


# ---------------------------------------------------------------------------


def test_the_digest_is_always_computed_and_reported():
    """Even with no expected value, the operator gets a number to compare."""
    pkg = _package()
    res, out = _logs(pkg)
    assert res["success"], res.get("error")
    assert res["sha256"] == _sha(pkg), "reported digest does not match the file"
    assert any(res["sha256"] in m for _l, m in out), "digest never surfaced in the log"


def test_a_matching_operator_digest_is_accepted():
    pkg = _package()
    res, out = _logs(pkg, expected_sha256=_sha(pkg))
    assert res["success"], res.get("error")
    assert any("matches the value supplied" in m for _l, m in out), out


def test_a_mismatched_digest_aborts_before_extracting():
    """The whole point: refuse BEFORE a privileged apply touches anything."""
    pkg = _package()
    res, _out = _logs(pkg, expected_sha256="0" * 64)
    assert not res["success"]
    assert "does not match" in res["error"], res["error"]
    assert res["sha256"] == _sha(pkg), "the real digest should still be reported"
    assert os.path.exists(pkg), "the operator's uploaded file must be left in place"


def test_a_digest_is_compared_case_and_whitespace_insensitively():
    """Operators paste from a release page; a trailing newline is not tampering."""
    pkg = _package()
    res, _ = _logs(pkg, expected_sha256=f"  {_sha(pkg).upper()}\n")
    assert res["success"], res.get("error")


def test_without_an_expected_digest_the_log_says_what_was_not_proven():
    """It must not read as though the package was authenticated."""
    pkg = _package()
    _res, out = _logs(pkg)
    joined = " ".join(m for _l, m in out)
    assert "NOT authenticity" in joined or "not authenticity" in joined.lower(), joined
    assert any(l == "warning" for l, _m in out), "should warn, not whisper at info"


def test_a_package_with_no_sha_map_warns_instead_of_shrugging():
    """The trivial bypass — drop the block and verification is skipped. It used
    to be logged at info as back-compat trivia."""
    pkg = _package(with_sha_map=False)
    res, out = _logs(pkg)
    assert res["success"], res.get("error")
    warn = [m for l, m in out if l == "warning" and "sha256 map" in m]
    assert warn, f"no warning about the missing map: {[m for _l, m in out]}"


def test_the_manifest_alone_cannot_detect_a_recomputed_hash():
    """Documents the residual honestly, so nobody mistakes this for signing.

    Content changed AND its hash recomputed: the manifest check passes, because
    the map is inside the archive. Only the operator-supplied digest catches it.
    """
    pkg = _package(tamper=True)
    res, _ = _logs(pkg)
    assert res["success"], (
        "a recomputed manifest still passes — if this now fails, the trust "
        "model changed and this test's premise needs revisiting")
    res2, _ = _logs(pkg, expected_sha256="0" * 64)
    assert not res2["success"], "the external digest is the only thing that catches it"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)

"""Tests for the new-module reconciliation fix (factor 5 / aws_sigma).

Bug: on an online upgrade from an OLDER release, `prepare` runs on the backend
that was current at trigger time. If that backend predates a module the target
added or renamed (cloudtrail -> aws_sigma), its prepare logs "Unknown module"
and never bundles that module's artifact, so nothing installs. The fix: Phase 2
(new code, post-swap) bundles any requested no-image data-artifact module whose
artifact is still missing, so the existing apply dispatch installs it.

These cover the extracted `bundle_single_module()` helper and the reconciliation
diff logic (manifest['versions'] membership) that Phase 2 uses. The full apply
+ swap is covered by the manual intact-e2e run, not here.

Run:  docker exec intact_backend python /app/workdir/tests/test_new_module_reconciliation.py
"""

import json
import os
import sys
import tarfile
import tempfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import package as pkg   # noqa: E402


def _empty_manifest():
    return {"versions": {}, "contents": {}}


def _make_fake_rules(root, n=3):
    """Create a fake /opt/sigma-rules/rules/cloud/aws with n .yml files."""
    d = os.path.join(root, "rules", "cloud", "aws")
    os.makedirs(d, exist_ok=True)
    for i in range(n):
        with open(os.path.join(d, f"rule_{i}.yml"), "w") as f:
            f.write(f"title: fake aws rule {i}\n")
    # a non-yaml file that must NOT be counted
    with open(os.path.join(d, "README.txt"), "w") as f:
        f.write("not a rule\n")
    return d


def test_bundle_aws_sigma_creates_tar_and_updates_manifest():
    with tempfile.TemporaryDirectory() as tmp:
        rules = _make_fake_rules(tmp, n=3)
        pkg_dir = os.path.join(tmp, "pkg")
        os.makedirs(pkg_dir)
        manifest = _empty_manifest()
        orig = pkg.AWS_SIGMA_RULES_DIR
        pkg.AWS_SIGMA_RULES_DIR = rules
        try:
            ok = pkg.bundle_single_module("aws_sigma", "2026.04", pkg_dir, manifest)
        finally:
            pkg.AWS_SIGMA_RULES_DIR = orig
        assert ok is True
        # tar exists at the exact path the apply fn (aws.py) reads
        tar_path = os.path.join(pkg_dir, "images", "cloudtrail-2026.04.tar")
        assert os.path.exists(tar_path), "expected images/cloudtrail-2026.04.tar"
        # version registered (this is what routes it through the apply dispatch)
        assert manifest["versions"].get("aws_sigma") == "2026.04"
        # rule_packs recorded, only .yml/.yaml counted (README.txt excluded)
        rp = manifest["contents"]["rule_packs"]
        assert len(rp) == 1 and rp[0]["module"] == "aws_sigma"
        assert rp[0]["rules"] == 3
        # the tar actually contains the rules
        with tarfile.open(tar_path) as t:
            names = t.getnames()
        assert any(n.endswith("rule_0.yml") for n in names)


def test_bundle_aws_sigma_missing_rules_dir_returns_false():
    with tempfile.TemporaryDirectory() as tmp:
        pkg_dir = os.path.join(tmp, "pkg")
        os.makedirs(pkg_dir)
        manifest = _empty_manifest()
        orig = pkg.AWS_SIGMA_RULES_DIR
        pkg.AWS_SIGMA_RULES_DIR = os.path.join(tmp, "does", "not", "exist")
        try:
            ok = pkg.bundle_single_module("aws_sigma", "2026.04", pkg_dir, manifest)
        finally:
            pkg.AWS_SIGMA_RULES_DIR = orig
        assert ok is False
        assert "aws_sigma" not in manifest["versions"]
        assert not os.path.exists(os.path.join(pkg_dir, "images", "cloudtrail-2026.04.tar"))


def test_bundle_non_reconcilable_module_returns_false():
    # An image-carrying module (timesketch) can't be reconciled post-swap.
    with tempfile.TemporaryDirectory() as tmp:
        manifest = _empty_manifest()
        assert pkg.bundle_single_module("timesketch", "20260630", tmp, manifest) is False
        assert pkg.bundle_single_module("intact", "development", tmp, manifest) is False
        assert manifest["versions"] == {}


def test_reconciliation_diff_identifies_the_gap():
    """The Phase-2 reconciliation bundles a requested module ONLY when it's
    absent from manifest['versions']; a normally-bundled module is skipped
    (no double-bundle)."""
    with tempfile.TemporaryDirectory() as tmp:
        rules = _make_fake_rules(tmp, n=2)
        pkg_dir = os.path.join(tmp, "pkg")
        os.makedirs(pkg_dir)

        # target set the operator requested (as Phase 2 reads from target_modules)
        target_modules = {"intact": "development", "cve_scan": "latest",
                          "aws_sigma": "2026.04"}
        # manifest an OLD prepare produced: intact + cve_scan bundled, aws_sigma MISSING
        manifest = {"versions": {"intact": "development", "cve_scan": "latest"},
                    "contents": {}}

        bundled = set(manifest["versions"].keys())
        reconciled = []
        orig = pkg.AWS_SIGMA_RULES_DIR
        pkg.AWS_SIGMA_RULES_DIR = rules
        try:
            for m in target_modules:
                if m in bundled:
                    continue
                if pkg.bundle_single_module(m, target_modules[m], pkg_dir, manifest):
                    reconciled.append(m)
        finally:
            pkg.AWS_SIGMA_RULES_DIR = orig

        # only aws_sigma was missing AND reconcilable
        assert reconciled == ["aws_sigma"]
        assert manifest["versions"]["aws_sigma"] == "2026.04"
        assert os.path.exists(os.path.join(pkg_dir, "images", "cloudtrail-2026.04.tar"))


def test_reconciliation_skips_when_already_bundled():
    """If prepare DID bundle aws_sigma (current backend), reconciliation must
    not re-bundle it."""
    with tempfile.TemporaryDirectory() as tmp:
        rules = _make_fake_rules(tmp, n=2)
        pkg_dir = os.path.join(tmp, "pkg")
        os.makedirs(pkg_dir)
        target_modules = {"aws_sigma": "2026.04"}
        manifest = {"versions": {"aws_sigma": "2026.04"}, "contents": {}}
        bundled = set(manifest["versions"].keys())
        reconciled = []
        orig = pkg.AWS_SIGMA_RULES_DIR
        pkg.AWS_SIGMA_RULES_DIR = rules
        try:
            for m in target_modules:
                if m in bundled:
                    continue
                if pkg.bundle_single_module(m, target_modules[m], pkg_dir, manifest):
                    reconciled.append(m)
        finally:
            pkg.AWS_SIGMA_RULES_DIR = orig
        assert reconciled == []
        # no tar written (we short-circuited before bundling)
        assert not os.path.exists(os.path.join(pkg_dir, "images", "cloudtrail-2026.04.tar"))


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

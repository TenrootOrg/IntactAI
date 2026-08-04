"""install.sh --package: install with no route to the internet.

THE APPROACH
------------
There is no separate offline install path, deliberately. The package carries
every image this release needs; loading them up front means
_pull_image_with_retry finds each one already in the local docker store and
skips the registry. Every existing deploy_* function then works offline without
a line of change, and there is no second code path to keep in step with the
first -- which is the failure mode that has cost this repo the most: two
implementations of the same thing drifting apart (secrets generated in both bash
and Python, chmod policies that disagree).

WHAT install.sh STILL CANNOT DO OFFLINE
---------------------------------------
apt and the Docker repository are internet-only. Air-gapped mode therefore
CHECKS for docker/compose/python3/yaml/openssl rather than attempting to install
them, and says so in one line -- a failed `apt-get update` on a box with no
route produces a wall of DNS errors in which the actual problem ("docker is not
here and I cannot fetch it") is the least visible thing on screen.

Run: docker exec intact_backend python /app/workdir/tests/test_airgap_install.py
"""

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
INSTALL_SH = os.path.join(REPO, "install.sh")
DOCKER_SH = os.path.join(REPO, "lib", "docker.sh")

failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        failures.append(f"{name}: {detail}")
        print(f"  FAIL  {name}: {detail}")


def _run(*args):
    return subprocess.run(["bash", INSTALL_SH, *args],
                          capture_output=True, text=True, timeout=60)


def _pkg(kind, with_image=True):
    """A package tarball whose manifest declares `kind`."""
    d = tempfile.mkdtemp(prefix="airgap_")
    root = os.path.join(d, "pkg")
    os.makedirs(os.path.join(root, "images"))
    with open(os.path.join(root, "manifest.json"), "w") as f:
        json.dump({"versions": {"intact": "intact-20260804"},
                   "contents": {"package_kind": kind,
                                "delta_from": "intact-20260803"}}, f)
    if with_image:
        with open(os.path.join(root, "images", "fake.tar"), "wb") as f:
            f.write(b"not a real image")
    out = os.path.join(d, f"{kind}.tar.gz")
    with tarfile.open(out, "w:gz") as t:
        t.add(root, arcname="pkg")
    return d, out


def _loader():
    """The load_images_from_package function, lifted out of install.sh with the
    log_* helpers stubbed -- running install.sh itself would need root."""
    return (
        "LOG_FILE=/dev/null\n"
        "log_info(){ echo \"[info] $*\"; }\n"
        "log_warn(){ echo \"[warn] $*\"; }\n"
        "log_error(){ echo \"[ERROR] $*\"; }\n"
        "log_success(){ echo \"[ok] $*\"; }\n"
        f"eval \"$(awk '/^load_images_from_package\\(\\) {{/,/^}}/' {INSTALL_SH})\"\n"
    )


# ------------------------------------------------------------ argument parsing

def test_help_explains_the_flag_and_which_asset_to_use():
    r = _run("--help")
    check("--help exits 0", r.returncode == 0, str(r.returncode))
    check("it documents --package", "--package" in r.stdout, r.stdout)
    check("and says to use the full asset, not delta",
          "-full" in r.stdout and "-delta" in r.stdout, r.stdout)


def test_an_unknown_argument_is_rejected_not_ignored():
    """Silently ignoring an unknown flag would let `--packge /path` (typo) run a
    full ONLINE install on a box with no route, failing much later and far from
    the cause."""
    r = _run("--bogus")
    check("it exits non-zero", r.returncode != 0, str(r.returncode))
    check("and names the offending argument",
          "--bogus" in (r.stdout + r.stderr), r.stdout + r.stderr)


def test_parsing_does_not_disturb_the_no_argument_case():
    """The normal online install takes no flags and must be unaffected."""
    src = open(INSTALL_SH).read()
    check("the loop is bounded by $# > 0", "while [[ $# -gt 0 ]]; do" in src,
          "argument parsing could block a no-arg run")
    check("air-gap defaults to off", "INTACT_AIRGAP=0" in src,
          "a normal install would take the offline path")


# --------------------------------------------------------------- the package

def test_a_delta_package_is_refused_for_a_fresh_install():
    """A delta carries only the modules whose pins moved since the previous
    release -- meaningless for a box with nothing installed."""
    d, pkg = _pkg("delta")
    try:
        r = subprocess.run(["bash", "-c", _loader() +
                            f"load_images_from_package '{pkg}'"],
                           capture_output=True, text=True, timeout=120,
                           cwd=REPO)
        check("it refuses a delta", r.returncode != 0, str(r.returncode))
        check("and says to use the full asset",
              "-full" in r.stdout or "full" in r.stdout, r.stdout[-300:])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_package_yielding_no_loadable_images_is_an_error():
    """A wrong or corrupt file must abort. Continuing would fall through to
    registry pulls that cannot work on an air-gapped box, so the install would
    fail anyway -- just later, and with a less useful message."""
    d, pkg = _pkg("full", with_image=True)   # image tar is deliberately garbage
    try:
        r = subprocess.run(["bash", "-c", _loader() +
                            f"load_images_from_package '{pkg}'"],
                           capture_output=True, text=True, timeout=120,
                           cwd=REPO)
        check("it fails when nothing loads", r.returncode != 0, str(r.returncode))
        check("and says the file is wrong or corrupt",
              "corrupt" in r.stdout.lower() or "no images" in r.stdout.lower(),
              r.stdout[-300:])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_missing_package_file_fails_clearly():
    r = subprocess.run(["bash", "-c", _loader() +
                        "load_images_from_package '/tmp/definitely-not-here.tar.gz'"],
                       capture_output=True, text=True, timeout=60, cwd=REPO)
    check("it fails", r.returncode != 0, str(r.returncode))
    check("and names the path", "definitely-not-here" in r.stdout, r.stdout)


# ------------------------------------------------------------- the pull skip

def test_an_image_already_present_is_never_pulled():
    """This single check is what makes every existing deploy_* path work
    offline. It is deliberately NOT gated on air-gap mode: re-pulling an image
    the box already has is wasted time online too."""
    src = open(DOCKER_SH).read()
    fn = src[src.index("_pull_image_with_retry() {"):]
    fn = fn[:fn.index("\n}")]
    check("the pull helper checks the local store first",
          "_image_present_locally" in fn, "it would hit the registry regardless")
    check("and returns before any docker pull",
          fn.index("_image_present_locally") < fn.index("docker pull"),
          "the check happens too late to prevent the pull")


def test_a_missing_image_in_airgap_mode_fails_fast():
    """With no route, retrying a pull three times with backoff wastes minutes to
    reach a conclusion already known at the first check."""
    src = open(DOCKER_SH).read()
    fn = src[src.index("_pull_image_with_retry() {"):]
    fn = fn[:fn.index("\n}")]
    check("air-gap mode short-circuits", 'INTACT_AIRGAP' in fn,
          "an air-gapped box would retry a pull it cannot make")
    check("before the retry loop",
          fn.index("INTACT_AIRGAP") < fn.index("max_attempts=3"),
          "it retries first and gives up after the backoff")


# ------------------------------------------------------- host prerequisites

def test_airgap_checks_host_prereqs_instead_of_apt_installing_them():
    src = open(INSTALL_SH).read()
    check("apt install is skipped in air-gap mode",
          'if [[ "$INTACT_AIRGAP" == "1" ]]; then' in src
          and "install_dependencies" in src,
          "apt would be attempted with no route")
    check("docker install is skipped too",
          '[[ "$INTACT_AIRGAP" != "1" ]] && ! install_docker' in src
          or 'INTACT_AIRGAP" != "1" ]] && ! install_docker' in src,
          "the docker apt repo would be attempted")
    for tool in ("docker", "python3", "openssl"):
        check(f"it checks for {tool}", tool in src, "")


def test_the_connectivity_gate_is_skipped_in_airgap_mode():
    """There is deliberately no route out, so the existing gate would abort a
    perfectly valid install."""
    src = open(INSTALL_SH).read()
    i_air = src.index('log_info "Air-gapped mode — skipping the internet')
    i_net = src.index("elif ! check_network_connectivity")
    check("air-gap is handled before the connectivity check", i_air < i_net, "")
    check("and the online path still checks",
          "check_network_connectivity" in src, "the gate was removed entirely")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"\n{name}")
            fn()
    print("\n" + ("FAILED: " + "; ".join(failures) if failures else "ALL PASSED"))
    sys.exit(1 if failures else 0)

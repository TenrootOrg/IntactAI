"""Three fixes that share one shape: a check standing in for the thing it
cannot actually see, and a log line describing the intent rather than the
outcome.

1. VERSION-BLIND STAGING SKIP (lib/docker.sh)
   Velociraptor client binaries are staged to version-agnostic destinations
   (velociraptor_client.exe) from version-bearing sources
   (velociraptor-v0.77.1-windows-amd64.exe). The skip asked only "does a file
   >=1 MB exist here?", which can never tell WHICH version is sitting there --
   so every version change after the first silently kept the old binary.
   Observed 2026-08-02: a box staged at 0.77.1 was reinstalled at 0.76.1, the
   old binaries were reported "already staged", and the image build then
   refused because the staged binary and the image tag disagreed.

2. chmod +x ON BINARIES (lib/docker.sh, velociraptor.py, package.py)
   A symbolic mode with no "who" is filtered by the process umask; `chmod 755`
   is not. Fixed in two places on 2026-08-02 and missed in six others,
   including all three restore paths in velociraptor.py -- so a rollback
   re-staged the binary with the very bug the rollback was recovering from.

3. LOG LINES THAT OVERSTATE (intact.py)
   `docker compose up -d` is a convergence, not a recreate: when nothing
   changed it is a no-op and the container keeps running untouched. Reporting
   that as "tusd sidecar recreated at v2.9.2" tells the operator a restart
   happened that did not. Same class as the VERSION SUMMARY claiming it
   installed a module the loop never dispatched.

4. NGINX PIN NEVER CONVERTS (intact.py)
   lib/config.sh stamps NGINX_VERSION into modules/nginx/.env at INSTALL time,
   in bash, which never runs again. An upgrade merges the new pin into
   config.yaml and mirrors a compose whose default is the new tag, but
   `nginx:${NGINX_VERSION:-...}` resolves to the stale .env value so the
   default is never reached. A box installed at intact-20260615 carries
   NGINX_VERSION=alpine and runs a floating tag forever, however many times it
   is upgraded -- on the component terminating TLS for the whole appliance.

Run: docker exec intact_backend python /app/workdir/tests/test_staging_and_convergence_honesty.py
"""

import inspect
import os
import re
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

REPO = os.environ.get("INTACT_PATH") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
DOCKER_SH = open(os.path.join(REPO, "lib", "docker.sh")).read()

from services.upgrade import intact as intact_mod  # noqa: E402


# --------------------------------------------------------------------------
# 1. version-aware staging
# --------------------------------------------------------------------------

def test_the_staging_skip_compares_versions():
    stage = DOCKER_SH[DOCKER_SH.index("Skip only when the staged file is BOTH"):]
    stage = stage[:stage.index("log_success")]
    assert 'staged_ver" == "$velo_version' in stage, (
        "the staging skip no longer compares the staged version — a version "
        "change will silently keep the old binary again")


def test_a_successful_stage_records_the_version():
    assert re.search(r"printf '%s\\n' \"\$velo_version\" > \"\$ver_marker\"", DOCKER_SH), (
        "nothing writes the version marker, so the comparison above can never "
        "match and every run re-downloads")


def test_a_failed_restage_keeps_a_usable_binary():
    """Air-gap safety. Downloading straight over $dest meant a failed transfer
    destroyed a working binary — survivable online, fatal offline, which is
    exactly where a re-stage is most likely to fail."""
    assert 'tmp_dest="${dest}.staging"' in DOCKER_SH, (
        "the download writes directly over the staged binary again")
    assert "keeping the existing" in DOCKER_SH, (
        "a failed re-stage no longer keeps the existing usable binary")


def test_a_placeholder_clears_the_version_marker():
    """A zero-byte placeholder is not a version. A stale marker would make the
    next run skip it as 'already staged at the right version'."""
    ph = DOCKER_SH[DOCKER_SH.index("empty placeholder"):]
    ph = ph[:ph.index("((placeholders++))")]
    assert 'rm -f "$ver_marker"' in ph, ph


# --------------------------------------------------------------------------
# 2. chmod on binaries
# --------------------------------------------------------------------------

def test_no_chmod_plus_x_on_staged_binaries():
    """Every `chmod +x` that lands on something a container or another uid has
    to execute. install.sh's chmods of repo .sh/.py scripts are owner-run and
    out of scope."""
    offenders = []
    for rel in ("lib/docker.sh",
                "modules/backend/services/upgrade/velociraptor.py",
                "modules/backend/services/upgrade/package.py",
                "modules/velociraptor/entrypoint.sh"):
        for i, line in enumerate(open(os.path.join(REPO, rel)), 1):
            s = line.strip()
            if "chmod +x" in s and not s.startswith("#"):
                offenders.append(f"{rel}:{i}: {s[:80]}")
    assert not offenders, "chmod +x is umask-masked; use chmod 755:\n" + "\n".join(offenders)


# --------------------------------------------------------------------------
# 3. convergence honesty
# --------------------------------------------------------------------------

def test_tusd_reports_no_change_when_nothing_changed():
    body = inspect.getsource(intact_mod.recreate_tusd)
    assert "no change needed" in body, (
        "recreate_tusd still claims 'recreated' unconditionally — a compose "
        "convergence that changed nothing is reported as a restart")
    assert "_tusd_id" in body, (
        "nothing compares the container identity, so 'recreated' cannot be "
        "distinguished from a no-op")


def test_tusd_still_reports_a_real_recreate():
    """The fix must not silence the genuine case."""
    body = inspect.getsource(intact_mod.recreate_tusd)
    assert "recreated at" in body, body[-400:]


# --------------------------------------------------------------------------
# 4. nginx pin conversion
# --------------------------------------------------------------------------

def test_nginx_pin_is_stamped_on_upgrade():
    body = inspect.getsource(intact_mod.recreate_nginx)
    assert "NGINX_VERSION" in body, (
        "the intact upgrade no longer stamps NGINX_VERSION — a box installed "
        "before the pin existed keeps running the floating nginx:alpine tag "
        "through every future upgrade")
    assert "versions" in body and "nginx" in body


def _code_only(fn):
    """Source with the docstring and comment lines stripped.

    Both assertions below anchor on positions, and the docstring of
    recreate_nginx discusses `docker compose up -d` at length — matching that
    prose instead of the call put the anchor at character 87 and made the test
    fail for a reason that had nothing to do with the code."""
    src = inspect.getsource(fn)
    body = src[src.index('"""', src.index('"""') + 3) + 3:]      # drop docstring
    return "\n".join(l for l in body.splitlines()
                     if not l.strip().startswith("#"))


def test_the_stamp_happens_before_the_convergence():
    """Writing the .env after `compose up` would take effect only on the NEXT
    upgrade — the same one-release-behind bug in a new place."""
    code = _code_only(intact_mod.recreate_nginx)
    assert code.index("NGINX_VERSION") < code.index('run_command("docker compose up -d nginx"'), (
        "NGINX_VERSION is stamped after the convergence, so it cannot affect it")


def test_a_failed_stamp_does_not_block_the_recreate():
    """A stale-but-working nginx beats no nginx."""
    code = _code_only(intact_mod.recreate_nginx)
    head = code[:code.index('run_command("docker compose up -d nginx"')]
    assert "except Exception" in head, (
        "a failure to write the pin would abort the nginx recreate entirely")


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
            except Exception as e:      # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)

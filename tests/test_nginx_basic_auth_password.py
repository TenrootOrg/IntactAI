"""Tests for ensure_nginx_basic_auth_secret() — dashboard password from config.yaml.

Nginx gates the dashboard, /api/, /api/uploads/ and the /velociraptor/ proxy behind
Basic Auth (CWE-306 fix). The password used to be a random token minted by a
self-heal, which locked operators out of their own box after an upgrade with the
secret only discoverable by catting a root-owned file. config.yaml's `dashboard:`
block now lets the operator choose it.

The contract this pins:
  * dashboard.password set   -> authoritative, re-applied on EVERY run
  * dashboard.password empty -> generate once if missing, otherwise NEVER touch
    the existing secret (an upgrade must not silently rotate a working login)
  * the bash installer and this Python upgrade path must agree byte-for-byte,
    because a box can be seeded by either one

Run:  docker exec intact_backend python /app/workdir/tests/test_nginx_basic_auth_password.py
"""

import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import intact as I  # noqa: E402

_QUIET = lambda msg, level="info": None  # noqa: E731


def _workdir(config_yaml, secrets=None):
    """A throwaway WORKDIR with a config.yaml and optional pre-existing secrets."""
    d = tempfile.mkdtemp(prefix="nginx_auth_")
    with open(os.path.join(d, "config.yaml"), "w") as f:
        f.write(config_yaml)
    sec = os.path.join(d, "modules", "nginx", "secrets")
    os.makedirs(sec, exist_ok=True)
    for name, content in (secrets or {}).items():
        with open(os.path.join(sec, name), "w") as f:
            f.write(content)
    return d, sec


def _run(workdir):
    prev = I.WORKDIR
    I.WORKDIR = workdir
    try:
        I.ensure_nginx_basic_auth_secret(_QUIET)
    finally:
        I.WORKDIR = prev


def _read(sec, name):
    with open(os.path.join(sec, name)) as f:
        return f.read()


def _expected_line(user, password):
    digest = hashlib.sha1(password.encode()).digest()
    return f"{user}:{{SHA}}{base64.b64encode(digest).decode()}\n"


def test_config_password_is_used():
    d, sec = _workdir("dashboard:\n  id: soc_admin\n  password: 'Choose Me! 123'\n")
    try:
        _run(d)
        assert _read(sec, "htpasswd") == _expected_line("soc_admin", "Choose Me! 123"), \
            "the operator's chosen password/username did not reach the htpasswd"
        assert _read(sec, "nginx_basic_auth_password") == "Choose Me! 123"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_config_password_is_reapplied_over_an_existing_secret():
    """The whole point: editing config.yaml and re-running must CHANGE the login.
    A guard that skipped when the file already existed would silently no-op."""
    d, sec = _workdir(
        "dashboard:\n  id: admin\n  password: 'newpass'\n",
        {"htpasswd": "admin:{SHA}STALE=\n", "nginx_basic_auth_password": "oldpass"},
    )
    try:
        _run(d)
        assert _read(sec, "htpasswd") == _expected_line("admin", "newpass"), \
            "a pre-existing htpasswd was not overwritten by the config.yaml value"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_empty_password_never_rotates_an_existing_secret():
    """An upgrade must not lock an operator out of a working box."""
    original = "admin:{SHA}ORIGINALHASH=\n"
    d, sec = _workdir(
        "dashboard:\n  id: admin\n  password: ''\n",
        {"htpasswd": original, "nginx_basic_auth_password": "originalpw"},
    )
    try:
        _run(d)
        assert _read(sec, "htpasswd") == original, \
            "an upgrade rotated the dashboard password — operator is locked out"
        assert _read(sec, "nginx_basic_auth_password") == "originalpw"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_empty_password_generates_when_missing():
    d, sec = _workdir("dashboard:\n  id: admin\n  password: ''\n")
    try:
        _run(d)
        pw = _read(sec, "nginx_basic_auth_password")
        assert len(pw) == 32, f"expected a 32-char token_hex(16) secret, got {len(pw)}"
        assert _read(sec, "htpasswd") == _expected_line("admin", pw)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_absent_dashboard_block_still_generates():
    """Config from an older release has no dashboard: block at all."""
    d, sec = _workdir("domain: 10.0.0.1\nmodules:\n  elk:\n    enabled: true\n")
    try:
        _run(d)
        assert _read(sec, "htpasswd").startswith("admin:{SHA}"), \
            "a config.yaml predating the dashboard: block broke the seeder"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_numeric_password_does_not_crash():
    """`password: 123123` (unquoted) is an int after yaml.safe_load — .encode()
    on an int raises, which would abort the whole upgrade."""
    d, sec = _workdir("dashboard:\n  id: admin\n  password: 123123\n")
    try:
        _run(d)
        assert _read(sec, "htpasswd") == _expected_line("admin", "123123"), \
            "a YAML-numeric password was not coerced to the string the operator typed"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_malformed_config_falls_back_instead_of_raising():
    """A broken config.yaml must not abort the upgrade."""
    d, sec = _workdir("dashboard:\n  id: [unclosed\n")
    try:
        _run(d)
        assert _read(sec, "htpasswd").startswith("admin:{SHA}"), \
            "a malformed config.yaml should degrade to a generated password"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_bash_installer_and_python_upgrade_agree():
    """Same config.yaml through lib/modules.sh must yield the same htpasswd.
    A box can be seeded by either path; a divergence means the login silently
    depends on which one ran."""
    repo = "/app/workdir"
    lib = os.path.join(repo, "lib", "modules.sh")
    if not os.path.exists(lib):
        print("  (skipped — lib/modules.sh not mounted in this container)")
        return

    cfg = "dashboard:\n  id: soc_admin\n  password: 'Choose Me! 123'\n"
    d, sec = _workdir(cfg)
    try:
        script = (
            "log_info(){ :; }; log_warn(){ :; }; log_success(){ :; }\n"
            f"CONFIG_FILE='{d}/config.yaml'; SCRIPT_DIR='{d}'\n"
            f"source {repo}/lib/config.sh\n"
            f"source {lib}\n"
            "generate_nginx_secrets\n"
        )
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        assert r.returncode == 0, f"generate_nginx_secrets failed: {r.stderr}"
        assert _read(sec, "htpasswd") == _expected_line("soc_admin", "Choose Me! 123"), \
            "bash installer and Python upgrade path disagree on the htpasswd"
    finally:
        shutil.rmtree(d, ignore_errors=True)


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
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)

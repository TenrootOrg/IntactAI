"""Tests for ensure_nginx_basic_auth_secret() — now the LOGIN MIGRATION source.

Nginx no longer gates anything with Basic Auth. That gate was replaced by an
application-level session login (modules/backend/services/auth_service.py), and
the bash half of this pair — lib/modules.sh:generate_nginx_secrets — was deleted
along with it, because nothing reads an htpasswd file any more.

This function survives for exactly one reason, and it is still worth pinning: a
box upgrading from a pre-auth release has its existing Basic Auth password hashed
into the new login by
services/upgrade/intact.py:migrate_basic_auth_to_app_login(), so the operator
keeps signing in with the password they already use instead of being shown an
unauthenticated setup page mid-upgrade. This function is what guarantees there IS
a password to migrate, even on a box whose secret was never generated.

So the contract below is unchanged in behaviour but changed in purpose — it now
protects a migration rather than a live login:
  * dashboard.password set   -> authoritative, re-applied on EVERY run
  * dashboard.password empty -> generate once if missing, otherwise NEVER touch
    the existing secret (an upgrade must not silently rotate what it is about to
    migrate)
  * the bash generator must stay GONE — see
    test_the_bash_generator_stays_gone, which replaced the old byte-for-byte
    parity test between the two implementations.

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


def test_the_bash_generator_stays_gone():
    """This replaced a byte-for-byte parity test between lib/modules.sh's
    generate_nginx_secrets and the Python path above.

    That generator is deleted: nginx has no auth_basic directive and no htpasswd
    bind mount, so a file it produced would be read by nothing. Re-adding it
    would also re-add the bind mount pressure — and a mount whose source path is
    missing makes docker create a DIRECTORY there, which stops nginx booting.
    Pinned so it cannot quietly come back with a merge.
    """
    repo = os.environ.get("INTACT_PATH", "/app/workdir")
    lib = os.path.join(repo, "lib", "modules.sh")
    if not os.path.exists(lib):
        print("  (skipped — lib/modules.sh not mounted in this container)")
        return
    with open(lib, "r", encoding="utf-8") as fh:
        body = "\n".join(ln for ln in fh.read().splitlines()
                         if not ln.lstrip().startswith("#"))
    assert "generate_nginx_secrets" not in body, \
        "generate_nginx_secrets is back in lib/modules.sh; nothing reads an htpasswd"
    assert "_write_nginx_htpasswd" not in body, \
        "_write_nginx_htpasswd is back in lib/modules.sh"


# --- the migration this function now exists to serve -------------------------


def _migrate(workdir, config_yaml, secrets=None):
    """Drive the real migrate_basic_auth_to_app_login() against a throwaway
    WORKDIR + config.yaml, with the credential store captured in a dict."""
    from services import auth_service as A

    stored = {}
    real = (A.set_credential, A.config_path)
    A.set_credential = lambda u, p: (stored.update(user=u, password=p), True)[1]

    prev_wd = I.WORKDIR
    I.WORKDIR = workdir
    cfg_path = os.path.join(workdir, "config.yaml")
    with open(cfg_path, "w") as f:
        f.write(config_yaml)
    os.environ["INTACT_CONFIG_PATH"] = cfg_path
    try:
        I.migrate_basic_auth_to_app_login(_QUIET)
        with open(cfg_path) as f:
            return stored, f.read()
    finally:
        I.WORKDIR = prev_wd
        A.set_credential, A.config_path = real
        os.environ.pop("INTACT_CONFIG_PATH", None)


def test_migration_does_not_carry_a_generated_password_into_the_new_login():
    """INVERTED 2026-08-03. This test used to assert the opposite, on a premise
    that turned out to be false.

    It claimed the secret in modules/nginx/secrets was "the password the
    operator has been typing". Checked against the tags:

        auth_basic in intact-20260615 : 0
        auth_basic in intact-20260726 : 0
        auth_basic in development     : 3

    No shipped release ever had Basic Auth. nginx never prompted for anything,
    so nobody ever typed that secret -- it was generated by the upgrade itself,
    stored as the new login, and marked setup-complete, locking the operator out
    from behind a password that had never existed anywhere they could see it.
    Observed on the 20260726 -> 20260803 upgrade.

    A password the operator did not choose is not a credential to preserve. With
    nothing genuinely recoverable the box goes to the setup page, where they
    pick their own -- and since the appliance was serving an unauthenticated
    dashboard until this moment, that is strictly an improvement, not the
    exposure the old docstring feared."""
    # Deliberately a low-entropy, self-describing string rather than a realistic
    # 32-char hex secret: gitleaks' generic-api-key rule fires on the real shape
    # (entropy ~3.6) and blocks the commit. The migration is format-agnostic, so
    # nothing is lost by making the fixture obviously not a credential.
    fake = "EXAMPLE-not-a-real-basic-auth-password"
    d, _sec = _workdir("schema_version: 2\ndomain: x\n",
                       {"nginx_basic_auth_password": fake})
    try:
        stored, cfg = _migrate(d, "schema_version: 2\ndomain: x\n")
        assert stored.get("password") != fake, \
            "a password the operator never chose was installed as their login"
        assert "first_login: true" in cfg, \
            "the operator was not given the setup page to choose credentials"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_migration_prefers_an_operator_chosen_password():
    d, _sec = _workdir("x", {"nginx_basic_auth_password": "generated-one"})
    try:
        stored, cfg = _migrate(
            d, "schema_version: 2\ndashboard:\n  id: soc_admin\n  password: 'Chosen! 123'\n")
        assert stored.get("password") == "Chosen! 123", \
            "config.yaml's dashboard.password should win over the generated secret"
        assert stored.get("user") == "soc_admin"
        assert "first_login: false" in cfg
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_migration_opens_setup_when_the_operator_chose_no_password():
    """Now the NORMAL path, not the last resort. No dashboard.password in
    config.yaml is the state of every real appliance, so this is what actually
    happens on an upgrade: the operator lands on the setup page and picks their
    own credentials. No stubs -- the previous version of this test had to
    neuter ensure_nginx_basic_auth_secret() and force set_credential() to fail
    before it could reach the branch, which was the clearest possible signal
    that the branch was unreachable in practice."""
    d = tempfile.mkdtemp(prefix="nginx_auth_")
    try:
        os.makedirs(os.path.join(d, "modules", "nginx", "secrets"), exist_ok=True)
        _stored, cfg = _migrate(d, "schema_version: 2\ndomain: x\n")
        assert "first_login: true" in cfg, \
            "the operator was not given the setup page to choose credentials"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_migration_is_a_noop_on_a_box_already_using_the_new_login():
    """Runs on EVERY upgrade, so it must not re-migrate (or reset) a box that has
    already been set up."""
    d, _sec = _workdir("x", {"nginx_basic_auth_password": "should-not-be-read"})
    try:
        stored, cfg = _migrate(d, "schema_version: 2\nfirst_login: false\ndomain: x\n")
        assert not stored, \
            "the migration overwrote the credential of an already-configured box"
        assert "first_login: false" in cfg
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_migration_leaves_a_box_deliberately_in_setup_mode_alone():
    d, _sec = _workdir("x", {"nginx_basic_auth_password": "should-not-be-read"})
    try:
        stored, cfg = _migrate(d, "schema_version: 2\nfirst_login: true\ndomain: x\n")
        assert not stored, "an operator who asked for setup mode got a credential instead"
        assert "first_login: true" in cfg
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_migration_does_not_touch_config_when_it_cannot_be_read():
    """A malformed config.yaml must not be rewritten on a guess."""
    d = tempfile.mkdtemp(prefix="nginx_auth_")
    try:
        os.makedirs(os.path.join(d, "modules", "nginx", "secrets"), exist_ok=True)
        broken = "this: is: not: valid: [[[\n"
        _stored, cfg = _migrate(d, broken)
        assert cfg == broken, "a malformed config.yaml was rewritten"
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

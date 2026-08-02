"""Timesketch's database must not run on the shipped timesketch/timesketch.

modules/timesketch/docker-compose.yaml read
`POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-timesketch}` and that fallback was LIVE:
modules/timesketch/.env contains no such key and nothing in install.sh or
lib/*.sh set it. Corroborated by config/timesketch.conf, whose
SQLALCHEMY_DATABASE_URI read postgresql://timesketch:timesketch@... So every
deployment ran the timeline database on a credential published in this repo.

Note the asymmetry that hid it: the image version pins next to it fail loudly
with `${VAR:?...}`, while the password silently defaulted. A stale image tag is
recoverable; a default database password is not.

Pinned here:

  1. No inline POSTGRES_PASSWORD in compose at all — the password comes from
     secrets/postgres.env, so there is no fallback left to be live.

  2. The secret is NOT written to modules/timesketch/.env. That file is
     git-TRACKED, so a credential there is staged by the next `git add` (the
     trap that once staged a live GitHub PAT). secrets/* is gitignored.

  3. BOTH paths provision it. lib/modules.sh for a fresh install;
     ensure_postgres_password() on the upgrade path. The compose file now
     hard-requires the file, so a path that skips it cannot start Postgres.

  4. ORDER in the upgrade migration. The database already exists with the old
     credential baked in at initdb time, so it must be: write the env file ->
     ALTER USER (while the OLD credential still works) -> rewrite the conf URI.
     Rewriting the URI first, or altering after the container was recreated
     with the new env, leaves the app unable to reach its own database.

  5. Idempotence. Re-running an upgrade must not rotate a working credential.

Verified live on the appliance: after migration the app authenticates with the
new credential and pre-existing rows survive, while the old timesketch/
timesketch is REJECTED over TCP from a peer container. (Testing it via
`docker exec ... psql` inside the container is useless — local connections use
trust auth and ignore the password entirely.)

Run: docker exec intact_backend python3 /app/workdir/tests/test_timesketch_postgres_password.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
COMPOSE = os.path.join(REPO, "modules", "timesketch", "docker-compose.yaml")
MODULES_SH = os.path.join(REPO, "lib", "modules.sh")
UPGRADE_PY = os.path.join(REPO, "modules", "backend", "services", "upgrade", "timesketch.py")
GITIGNORE = os.path.join(REPO, ".gitignore")


def _read(p):
    with open(p, "r", encoding="utf-8") as h:
        return h.read()


def _pg_service():
    import yaml
    return yaml.safe_load(_read(COMPOSE))["services"]["timesketch-postgres"]


def test_no_default_password_fallback_remains():
    """The bug itself: a `:-timesketch` default that nothing overrode.

    Comment lines are stripped first — the compose file now *describes* the old
    `POSTGRES_PASSWORD:-timesketch` string in an explanatory comment, and
    matching that prose would make this test fail on a correct file.
    """
    code = "\n".join(ln for ln in _read(COMPOSE).splitlines()
                     if not ln.lstrip().startswith("#"))
    assert "POSTGRES_PASSWORD:-timesketch" not in code, \
        "the timesketch/timesketch fallback is back in the compose file"
    env = _pg_service().get("environment") or []
    flat = env if isinstance(env, list) else [f"{k}={v}" for k, v in env.items()]
    assert not any("POSTGRES_PASSWORD" in e for e in flat), \
        "POSTGRES_PASSWORD is inline in compose again; it belongs in secrets/"


def test_the_password_comes_from_the_secrets_file():
    ef = _pg_service().get("env_file") or []
    assert "./secrets/postgres.env" in ef, \
        "timesketch-postgres no longer loads secrets/postgres.env"


def test_the_secret_is_gitignored_and_not_in_the_tracked_env():
    gi = _read(GITIGNORE)
    assert "modules/timesketch/secrets/" in gi, \
        "modules/timesketch/secrets/ is not gitignored — the DB password would be committed"
    for path, label in ((MODULES_SH, "lib/modules.sh"), (UPGRADE_PY, "upgrade/timesketch.py")):
        assert not re.search(r'POSTGRES_PASSWORD.*timesketch/\.env', _read(path)), \
            f"{label} writes the DB password into the git-tracked module .env"


def test_both_paths_provision_it():
    assert "postgres.env" in _read(MODULES_SH), \
        "lib/modules.sh no longer generates the Timesketch DB password (fresh install breaks)"
    body = _read(UPGRADE_PY)
    assert "def ensure_postgres_password" in body, \
        "the upgrade path lost ensure_postgres_password (upgrades break)"
    assert re.search(r'^\s*ensure_postgres_password\(', body, re.MULTILINE), \
        "ensure_postgres_password is defined but never called"


def test_the_migration_order_is_correct():
    """ALTER USER must happen BEFORE the conf URI is rewritten, and both while
    the old credential still works."""
    body = _read(UPGRADE_PY)
    start = body.index("def ensure_postgres_password")
    fn = body[start:start + 4200]
    write_env = fn.index("POSTGRES_PASSWORD=")
    alter = fn.index("ALTER USER timesketch")
    rewrite = fn.index("postgresql://timesketch:")
    assert write_env < alter < rewrite, (
        "the migration order is wrong. It must be: write secrets/postgres.env "
        "-> ALTER USER -> rewrite the conf URI. Any other order leaves "
        "Timesketch unable to authenticate to its own database")


def test_a_failed_alter_rolls_back_the_env_file():
    """Otherwise the file claims a password the database never accepted, and
    the next run short-circuits on it — permanently broken."""
    body = _read(UPGRADE_PY)
    start = body.index("def ensure_postgres_password")
    fn = body[start:start + 4200]
    at = fn.index("alter-failed")
    assert "os.remove" in fn[:at], \
        "a failed ALTER USER does not remove the env file; the next run would " \
        "short-circuit on a password the database does not know"


def test_it_is_idempotent():
    body = _read(UPGRADE_PY)
    start = body.index("def ensure_postgres_password")
    fn = body[start:start + 4200]
    assert "already-set" in fn or "getsize" in fn, \
        "ensure_postgres_password no longer short-circuits when the secret " \
        "exists; re-running an upgrade would rotate a working credential"


def test_the_secret_is_readable_by_whoever_runs_compose():
    """`env_file:` is read by the compose CLIENT, not the container. A
    root-owned 0600 file breaks `docker compose` for the operator."""
    for path in (UPGRADE_PY,
                 os.path.join(REPO, "modules", "backend", "services", "upgrade", "portainer.py")):
        assert "os.chown" in _read(path), (
            f"{os.path.basename(path)} writes an env_file secret without "
            f"chowning it to the tree owner; compose then fails with "
            f"'permission denied' for anyone but root")


def test_live_secret_is_present_and_tight():
    live = os.path.join(REPO, "modules", "timesketch", "secrets", "postgres.env")
    if not os.path.exists(live):
        return
    assert re.search(r'^POSTGRES_PASSWORD=\S{16,}', _read(live), re.MULTILINE), \
        "secrets/postgres.env has no usable password"
    assert "POSTGRES_PASSWORD=timesketch\n" not in _read(live), \
        "the live secret is still the shipped default"
    mode = os.stat(live).st_mode & 0o777
    assert not (mode & 0o077), f"secrets/postgres.env is {oct(mode)}"


def test_the_conf_no_longer_carries_the_default():
    conf = os.path.join(REPO, "modules", "timesketch", "config", "timesketch.conf")
    if not os.path.exists(conf):
        return
    try:
        body = _read(conf)
    except PermissionError:
        return          # 0600 and we are not the owner — fine, that is the point
    assert "postgresql://timesketch:timesketch@" not in body, \
        "timesketch.conf still points at the default timesketch/timesketch"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)

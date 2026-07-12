#!/usr/bin/env python3
"""Timesketch upgrade functions."""

import os
import re
import time
import shlex
import requests
from datetime import datetime
from typing import Dict, Callable, Optional

from .base import (
    WORKDIR, HOST_PATH,
    run_command, read_env_file, update_env_file, load_docker_image,
    backup_env_file, restore_env_file, cleanup_backup,
    remove_old_module_image,
)


# Where pg_dump files land. Bind-mounted at host so they survive container
# restarts. We keep dumps indefinitely on success and prune by hand —
# operators occasionally need an older one and an aggressive auto-prune
# would defeat the safety-net purpose.
_DB_BACKUP_DIR = os.path.join(WORKDIR, 'backups', 'timesketch')
_DB_BACKUP_DIR_HOST = os.path.join(HOST_PATH, 'backups', 'timesketch')

# Hardcoded — matches what intact_timesketch_postgres ships with and what
# Timesketch's docker-compose.yaml configures.
_PG_CONTAINER = 'intact_timesketch_postgres'
_PG_USER = 'timesketch'
_PG_DB = 'timesketch'
_WEB_CONTAINER = 'intact_timesketch_web'
_OPENSEARCH_CONTAINER = 'intact_timesketch_opensearch'


def _count_opensearch_docs(logger: Callable = None) -> Optional[int]:
    """Return the total OpenSearch document count across Timesketch's
    timeline indices, or None on failure.

    This is the critical data-loss check the postgres row counts MISS:
    Timesketch stores sketch/timeline *metadata* in postgres but the
    actual timeline EVENTS live in OpenSearch indices. A `docker compose
    down/up` preserves the opensearch named volume, so events should
    survive automatically — but if they ever don't (volume detach,
    accidental reset, index deletion), the postgres-only guard would
    pass while every timeline silently goes empty. Counting opensearch
    docs before/after makes that observable and triggers the rollback.

    System indices (names starting with '.') are excluded so we only
    track user timeline data.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    result = run_command(
        f"docker exec {_OPENSEARCH_CONTAINER} "
        f"curl -s 'http://localhost:9200/_cat/indices?h=index,docs.count'",
        logger=None
    )
    if not result['success']:
        log(f"Could not query OpenSearch doc counts: {result.get('error','?')[:120]}", "warning")
        return None
    total = 0
    for line in (result.get('stdout') or '').splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        index_name, docs = parts[0], parts[1]
        if index_name.startswith('.'):
            continue  # skip opensearch/plugin system indices
        try:
            total += int(docs)
        except (ValueError, TypeError):
            continue
    return total


def _backup_timesketch_db(current_version: str, target_version: str, logger: Callable = None) -> Optional[str]:
    """pg_dump the live Timesketch DB to a timestamped file under WORKDIR.

    Runs while the old containers are still up so the dump sees a consistent
    snapshot (postgres handles MVCC; no need to stop the DB first). Returns
    the dump path on success, None on failure — the caller decides whether
    "no backup" is fatal.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    os.makedirs(_DB_BACKUP_DIR, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_cur = current_version.replace('/', '_').replace(' ', '_')
    safe_tgt = target_version.replace('/', '_').replace(' ', '_')
    dump_path = os.path.join(_DB_BACKUP_DIR, f'timesketch_{safe_cur}_to_{safe_tgt}_{stamp}.sql')

    log(f"Backing up Timesketch DB via pg_dump → {dump_path}", "info")
    # `-t` would allocate a TTY which corrupts binary-safe redirection; omit it.
    cmd = (
        f"docker exec {_PG_CONTAINER} pg_dump -U {shlex.quote(_PG_USER)} "
        f"-d {shlex.quote(_PG_DB)} > {shlex.quote(dump_path)}"
    )
    result = run_command(cmd, timeout=600, logger=log)
    if not result['success']:
        log(f"pg_dump failed: {result.get('error','?')[:200]}", "error")
        # Remove the empty/partial file so we don't try to restore from it.
        try:
            if os.path.exists(dump_path) and os.path.getsize(dump_path) == 0:
                os.remove(dump_path)
        except Exception:
            pass
        return None

    size_mb = os.path.getsize(dump_path) / (1024 * 1024) if os.path.exists(dump_path) else 0
    if size_mb < 0.001:
        log(f"pg_dump produced an empty file at {dump_path}", "error")
        try:
            os.remove(dump_path)
        except Exception:
            pass
        return None

    log(f"DB backup OK ({size_mb:.2f} MB)", "success")
    return dump_path


def _restore_timesketch_db(dump_path: str, logger: Callable = None) -> bool:
    """Restore the Timesketch DB from a pg_dump file. Used in the rollback path.

    Drops + recreates the database first so the restore doesn't accumulate
    on top of the already-migrated schema, then streams the dump back in
    via psql.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    if not dump_path or not os.path.exists(dump_path):
        log(f"DB restore skipped — no backup file at {dump_path}", "warning")
        return False

    log(f"Restoring Timesketch DB from {dump_path}", "info")

    # Postgres can't drop a DB while sessions are connected; terminate them
    # first. The web container should already be stopped by the caller, but
    # belt-and-braces.
    terminate = (
        f"docker exec {_PG_CONTAINER} psql -U {_PG_USER} -d postgres -c "
        f"\"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{_PG_DB}' AND pid<>pg_backend_pid();\""
    )
    run_command(terminate, timeout=30, logger=log)

    for cmd in (
        f"docker exec {_PG_CONTAINER} dropdb -U {_PG_USER} --if-exists {_PG_DB}",
        f"docker exec {_PG_CONTAINER} createdb -U {_PG_USER} {_PG_DB}",
        f"docker exec -i {_PG_CONTAINER} psql -U {_PG_USER} -d {_PG_DB} < {shlex.quote(dump_path)}",
    ):
        result = run_command(cmd, timeout=600, logger=log)
        if not result['success']:
            log(f"DB restore step failed ({cmd[:60]}...): {result.get('error','?')[:200]}", "error")
            return False

    log("DB restore OK", "success")
    return True


# ── Postgres major-version migration ────────────────────────────────────────
# Postgres refuses to open a data directory written by a DIFFERENT major
# version ("FATAL: database files are incompatible … initialized by PostgreSQL
# version N"). So a host whose timesketch_postgres_data was initialised under
# one major (e.g. PG15, the old-modules default) cannot just run a different
# major (PG13, what Timesketch upstream now pins) against it — the container
# crash-loops and the whole Timesketch stack fails its health-gated start.
# This is the exact failure that broke the air-gap upgrade.
#
# In-place major changes (either direction) aren't possible against the same
# data dir, so we migrate LOGICALLY: the upgrade already pg_dumps the live DB
# against the OLD running postgres (any major); when the pinned major differs
# we wipe the data volume, initialise the NEW major fresh, and restore the
# dump into it. Runs only when the majors differ AND a verified dump exists.

def _read_pg_data_major(logger: Callable = None) -> Optional[str]:
    """Major version that wrote the EXISTING postgres data dir (its PG_VERSION
    file), or None. Must be read while the old container is still running."""
    r = run_command(
        f"docker exec {_PG_CONTAINER} cat /var/lib/postgresql/data/PG_VERSION",
        logger=None)
    if not r.get('success'):
        return None
    v = (r.get('stdout') or '').strip().split('.')[0]
    return v if v.isdigit() else None


def _read_volume_pg_major(vol_name: Optional[str], env_file: str, logger: Callable = None) -> Optional[str]:
    """Major version of the EXISTING data dir, read straight off the volume.

    Unlike _read_pg_data_major (which execs the live container), this works when
    the postgres container is DOWN or crash-looping — the situation we're in when
    a rollback brings up a wrong-major container. Mounts the volume into the pinned
    postgres image (already local) with `cat` as the entrypoint, so nothing tries
    to start a cluster."""
    if not vol_name:
        return None
    try:
        tag = (read_env_file(env_file).get('POSTGRES_VERSION') or '13').strip()
    except Exception:
        tag = '13'
    r = run_command(
        f"docker run --rm --entrypoint cat -v {shlex.quote(vol_name)}:/v "
        f"{shlex.quote('postgres:' + tag)} /v/PG_VERSION", logger=None)
    if not r.get('success'):
        return None
    v = (r.get('stdout') or '').strip().split('.')[0]
    return v if v.isdigit() else None


def _read_pinned_pg_major(env_file: str) -> Optional[str]:
    """Major pinned in modules/timesketch/.env POSTGRES_VERSION
    (e.g. '13.0-alpine' -> '13'), or None."""
    try:
        env = read_env_file(env_file)
    except Exception:
        return None
    m = re.match(r'(\d+)', (env.get('POSTGRES_VERSION') or '').strip())
    return m.group(1) if m else None


def _read_pg_volume_name(logger: Callable = None) -> Optional[str]:
    """Docker volume backing the postgres data dir, captured while the
    container still exists so it can be wiped after `compose down`."""
    r = run_command(
        "docker inspect " + _PG_CONTAINER + " --format "
        "'{{range .Mounts}}{{if eq .Destination \"/var/lib/postgresql/data\"}}{{.Name}}{{end}}{{end}}'",
        logger=None)
    name = (r.get('stdout') or '').strip() if r.get('success') else ''
    return name or None


def _wait_postgres_ready(logger: Callable = None, attempts: int = 40, delay: int = 3) -> bool:
    """Block until `pg_isready` reports the postgres container accepts
    connections (a fresh init is fast, but give it room on busy hosts)."""
    log = logger or (lambda m, l="info": None)
    for i in range(attempts):
        r = run_command(f"docker exec {_PG_CONTAINER} pg_isready -U {_PG_USER}", logger=None)
        if r.get('success') and 'accepting connections' in (r.get('stdout') or ''):
            return True
        log(f"  waiting for postgres to accept connections... ({i*delay}s)", "info")
        time.sleep(delay)
    return False


def _detect_pg_major_change(env_file: str, logger: Callable = None):
    """Return (needs_migration, data_major, pinned_major, volume_name).

    Reads the existing data dir's major + the pinned major + the data volume
    name (all while the old container is up). needs_migration is True only when
    both majors are known and differ."""
    data_major = _read_pg_data_major(logger=logger)
    pinned_major = _read_pinned_pg_major(env_file)
    vol_name = _read_pg_volume_name(logger=logger)
    needs = bool(data_major and pinned_major and data_major != pinned_major)
    return needs, data_major, pinned_major, vol_name


def _migrate_pg_major(work_dir: str, db_backup_path: Optional[str], vol_name: Optional[str],
                      logger: Callable = None) -> bool:
    """Wipe the old-major data volume, init the new major fresh (postgres only),
    and restore the logical dump into it. Caller must have already `compose
    down`-ed and hold a verified `db_backup_path`."""
    log = logger or (lambda m, l="info": print(f"[{l}] {m}"))
    if not db_backup_path or not os.path.exists(db_backup_path):
        log("Refusing postgres major migration without a DB dump", "error")
        return False
    if vol_name:
        log(f"Removing old-major postgres volume {vol_name} so the new major "
            f"initialises a fresh cluster...", "info")
        run_command(f"docker volume rm {shlex.quote(vol_name)}", timeout=120, logger=log)
    # Bring up ONLY postgres so it initialises an empty cluster under the new
    # major BEFORE web/worker try to use it. Images are already local
    # (pulled/loaded by the caller), so --pull never is safe online + offline.
    log("Starting fresh postgres under the new major for restore...", "info")
    r = run_command("docker compose up -d --pull never timesketch-postgres",
                    cwd=work_dir, logger=log)
    if not r.get('success'):
        log(f"Failed to start fresh postgres: {r.get('error','?')[:200]}", "error")
        return False
    if not _wait_postgres_ready(logger=log):
        log("Fresh postgres did not become ready in time", "error")
        return False
    # Restore the dump (drops+recreates the timesketch DB, then psql streams in).
    if not _restore_timesketch_db(db_backup_path, logger=log):
        return False
    log("Postgres major migration complete — data restored under the new major.", "success")
    return True


def _rollback_restore_db(work_dir: str, env_file: str, db_backup_path: Optional[str],
                        vol_name: Optional[str], logger: Callable = None) -> None:
    """Restore the pre-upgrade DB as the final rollback step.

    Cheap path first: if postgres in the rolled-back stack comes up, just restore
    the dump. But if it WON'T come up because the data-dir major no longer matches
    the (rolled-back) pinned major — e.g. a legacy PG15 volume against a PG13 pin —
    restoring the .env can never fix that (a PG13 binary can't open a PG15 data
    dir). In that case reconcile with the SAME dump->wipe->restore migration the
    forward path uses, so a FAILED upgrade still rolls back to a WORKING Timesketch
    instead of a crash-looping postgres."""
    log = logger or (lambda m, l="info": print(f"[{l}] {m}"))
    if not db_backup_path:
        return

    # Cheap path: wait briefly for postgres in the rolled-back stack.
    pg_ok = False
    for _ in range(15):
        if run_command(f"docker exec {_PG_CONTAINER} pg_isready -U {_PG_USER}",
                       logger=None).get('success'):
            pg_ok = True
            break
        time.sleep(2)

    if pg_ok:
        if _restore_timesketch_db(db_backup_path, logger=log):
            log(f"ROLLED BACK DB from {db_backup_path}", "warning")
        else:
            log(f"DB restore failed — dump kept at {db_backup_path} for manual recovery", "error")
        return

    # Postgres didn't come up. Diagnose a major mismatch and reconcile if so.
    vol_name = vol_name or _read_pg_volume_name(logger=log)
    pinned = _read_pinned_pg_major(env_file)
    vol_major = _read_volume_pg_major(vol_name, env_file, logger=log)
    if vol_major and pinned and vol_major != pinned:
        log(f"Rollback: postgres won't start — the data dir is PG{vol_major} but config "
            f"pins PG{pinned}. Reconciling via dump->wipe->restore (in-place major "
            f"changes aren't possible).", "warning")
        run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
        if _migrate_pg_major(work_dir, db_backup_path, vol_name, logger=log):
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK DB after reconciling postgres PG{vol_major} -> PG{pinned}", "warning")
        else:
            log(f"Postgres major reconciliation failed — dump kept at {db_backup_path} "
                f"for manual recovery", "error")
    else:
        log(f"Postgres did not become ready (data PG{vol_major or '?'}, pinned PG{pinned or '?'}) — "
            f"dump kept at {db_backup_path} for manual recovery", "error")


def _count_timesketch_rows(table: str, logger: Callable = None) -> Optional[int]:
    """Return COUNT(*) for a Timesketch table, or None on failure.

    Used as a before/after sanity check around the upgrade. The postgres
    volume is preserved across `docker compose down/up`, so row counts on
    persistent tables should never drop during a clean upgrade. If they do,
    something went very wrong (volume detach, mis-applied migration) and
    the upgrade should fail so the rollback path runs.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Quote the table name to protect SQL keywords like "user" / "timeline".
    result = run_command(
        f"docker exec {_PG_CONTAINER} psql -U {_PG_USER} -d {_PG_DB} -tAc "
        f"\"SELECT count(*) FROM \\\"{table}\\\";\"",
        logger=None
    )
    if not result['success']:
        log(f"Could not count rows of {table!r} (table may not exist yet): {result.get('error','?')[:120]}", "warning")
        return None
    try:
        return int((result.get('stdout') or '').strip())
    except (ValueError, TypeError):
        log(f"Unexpected count output for {table!r}: {result.get('stdout','')[:120]}", "warning")
        return None


def _count_timesketch_users(logger: Callable = None) -> Optional[int]:
    """Convenience wrapper — kept for back-compat with earlier callers."""
    return _count_timesketch_rows('user', logger=logger)


def _snapshot_persistent_counts(logger: Callable = None) -> Dict[str, Optional[int]]:
    """Snapshot the row count of every Timesketch table that holds user-visible
    state. Used before + after the upgrade to assert nothing got dropped.

    Coverage spans the full user-facing surface — if any of these lose rows
    during upgrade, the operator has lost something they care about:
      - auth          : user, sketch_accesscontrolentry
      - core          : sketch, timeline, searchindex
      - investigation : story, view, analysis, attribute
      - findings      : event, aggregation, graph
      - searches      : searchhistory, searchtemplate, sigmarule
      - DFIQ          : scenario, investigativequestion, facet

    Tables that don't exist on the pre-upgrade schema (e.g. brand-new tables
    introduced by a newer release) return None and are skipped from the
    before/after comparison.
    """
    tables = [
        # Auth / access
        'user',
        'sketch_accesscontrolentry',
        # Core entities
        'sketch',
        'timeline',
        'searchindex',
        # Investigation surface
        'story',
        'view',
        'analysis',
        'attribute',
        # Tagged events / findings
        'event',
        'aggregation',
        'graph',
        # Searches + rules
        'searchhistory',
        'searchtemplate',
        'sigmarule',
        # DFIQ
        'scenario',
        'investigativequestion',
        'facet',
    ]
    counts = {t: _count_timesketch_rows(t, logger=logger) for t in tables}
    # The timeline EVENTS themselves live in OpenSearch, not postgres — the
    # postgres tables above only hold metadata. Track opensearch doc totals
    # too so a loss of actual event data is caught + rolled back, not just
    # a loss of postgres rows.
    counts['_opensearch_docs'] = _count_opensearch_docs(logger=logger)
    return counts


def _assert_counts_preserved(before: Dict[str, Optional[int]],
                              after: Dict[str, Optional[int]],
                              logger: Callable = None) -> Optional[str]:
    """Compare before/after table counts. Returns None on success, or a
    human-readable error string if any persistent table lost rows. Tables
    that didn't exist in the before-snapshot are skipped (the new schema
    may have created them)."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    losses = []
    for table, before_n in before.items():
        if before_n is None:
            continue
        after_n = after.get(table)
        if after_n is None:
            # Table existed pre-upgrade but disappeared post-upgrade — that's a real loss.
            losses.append(f"{table}: {before_n} → MISSING")
            log(f"  {table:12} pre={before_n} post=MISSING", "error")
        elif after_n < before_n:
            losses.append(f"{table}: {before_n} → {after_n}")
            log(f"  {table:12} pre={before_n} post={after_n}  ✗ ROWS LOST", "error")
        else:
            delta = after_n - before_n
            note = "" if delta == 0 else f" (+{delta} new)"
            log(f"  {table:12} pre={before_n} post={after_n}{note}", "info")
    if losses:
        return "Row count dropped in: " + "; ".join(losses)
    return None


def _fetch_migrations_dir(version: str, logger: Callable = None) -> Optional[str]:
    """Download Timesketch's alembic migrations/ tree for `version` from GitHub.

    The Timesketch wheel installed in the container does NOT include
    migrations/ — they live only in the source repo. The upstream upgrade
    guide handles this by `git clone`-ing the repo inside the container.
    We do the equivalent via a tarball download from the backend container
    (which has curl) and return a host-bind-mounted path to the extracted
    migrations directory so the caller can docker-cp it into the running
    web container.

    Tries the version tag first, falls back to master if the tag 404s.
    Returns None on failure (caller handles).
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_root = os.path.join(WORKDIR, 'backups', 'timesketch', 'migrations_cache')
    os.makedirs(work_root, exist_ok=True)
    extract_dir = os.path.join(work_root, version)
    tarball = os.path.join(work_root, f'{version}.tar.gz')

    # Try tagged release first, then master as a fallback.
    candidates = [
        f"https://github.com/google/timesketch/archive/refs/tags/{version}.tar.gz",
        "https://github.com/google/timesketch/archive/refs/heads/master.tar.gz",
    ]
    fetched = False
    for url in candidates:
        log(f"Fetching Timesketch migrations from {url}", "info")
        # -fL: fail on HTTP errors, follow redirects. -o: output file.
        result = run_command(
            f"curl -fLsS --retry 5 --retry-delay 5 --retry-max-time 600 "
            f"--connect-timeout 30 -o {shlex.quote(tarball)} {shlex.quote(url)}",
            timeout=900, logger=None,
        )
        if result['success'] and os.path.exists(tarball) and os.path.getsize(tarball) > 1024:
            fetched = True
            break
        log(f"  → not available ({result.get('error','no detail')[:120]})", "warning")
    if not fetched:
        log("Could not download Timesketch source for migrations — schema upgrade will be skipped", "error")
        return None

    # Extract only timesketch/migrations/ from the tarball to keep the cache lean.
    # tar's --strip-components removes the version-prefixed top dir.
    if os.path.isdir(extract_dir):
        run_command(f"rm -rf {shlex.quote(extract_dir)}", logger=None)
    os.makedirs(extract_dir, exist_ok=True)
    # GNU tar needs --wildcards to glob across the version-prefixed top dir.
    # --strip-components=1 drops the `timesketch-<version>/` prefix so the
    # extracted tree starts with `timesketch/migrations/`.
    result = run_command(
        f"tar -xzf {shlex.quote(tarball)} -C {shlex.quote(extract_dir)} "
        f"--wildcards --strip-components=1 '*/timesketch/migrations'",
        timeout=60, logger=log
    )
    if not result['success']:
        log(f"Failed to extract migrations from tarball: {result.get('error','?')[:200]}", "error")
        return None

    migrations_path = os.path.join(extract_dir, 'timesketch', 'migrations')
    if not os.path.isdir(migrations_path):
        log(f"Expected migrations dir not found at {migrations_path} after extract", "error")
        return None

    log(f"Migrations dir ready at {migrations_path}", "success")
    return migrations_path


def _bootstrap_alembic_if_needed(current_version: str, logger: Callable = None,
                                  local_migrations_dir: Optional[str] = None,
                                  offline: bool = False) -> bool:
    """If the DB has no alembic_version row, stamp it to the CURRENT version's
    migration head — anchoring alembic to the schema actually on disk before
    the upgrade starts. This must run BEFORE `docker compose down` so the old
    web container is still up to execute tsctl against the matching migration
    chain.

    Without this step, the first `tsctl db upgrade` after an image swap would
    have to choose between:
      - applying every migration from scratch (collides with existing tables), or
      - stamping head of the NEW chain (claims the schema is at the target,
        skips the deltas, leaves the DB missing columns the new code expects —
        exactly the bug that surfaced as `column analysis.approach_id does
        not exist` when querying through 20260326 code on a 20240828 schema).

    Returns True on success (or if no bootstrap was needed); False on failure.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    check = run_command(
        f"docker exec {_PG_CONTAINER} psql -U {_PG_USER} -d {_PG_DB} -tAc "
        f"\"SELECT to_regclass('alembic_version');\"",
        logger=None
    )
    if check['success'] and (check.get('stdout') or '').strip() not in ('', 'alembic_version'):
        # Strange: to_regclass returned something unexpected. Don't bootstrap.
        return True
    if check['success'] and (check.get('stdout') or '').strip() == 'alembic_version':
        # Table exists. If it has a row, no bootstrap needed.
        row_check = run_command(
            f"docker exec {_PG_CONTAINER} psql -U {_PG_USER} -d {_PG_DB} -tAc "
            f"\"SELECT version_num FROM alembic_version LIMIT 1;\"",
            logger=None
        )
        marker = (row_check.get('stdout') or '').strip() if row_check['success'] else ''
        if marker:
            log(f"DB already alembic-tracked at revision {marker} — no bootstrap needed", "info")
            return True
        # Both branches below are the EXPECTED state on a first upgrade
        # after alembic tracking was added. The very next line bootstraps
        # the table and proceeds normally. Logging as WARNING made
        # operators panic on otherwise-clean upgrades (2026-06-15).
        log("alembic_version table exists but is empty — bootstrapping "
            "(one-time, expected on first upgrade)...", "info")
    else:
        log("alembic_version table not yet initialized — bootstrapping "
            "(one-time, expected on first upgrade after alembic tracking "
            "was added)...", "info")

    # Need to stamp. Use the CURRENT version's migrations against the
    # still-running OLD web container.
    log(f"Bootstrapping alembic by stamping head of current version ({current_version})...", "info")

    # Prefer bundled migrations (offline-safe). Offline upgrades MUST
    # use bundled and never network — the apply machine is air-gapped.
    # Online upgrades may fall back to GitHub if nothing is bundled.
    mig_path = None
    if local_migrations_dir and os.path.isdir(local_migrations_dir) \
            and os.path.isdir(os.path.join(local_migrations_dir, 'versions')):
        log(f"  Using bundled migrations from package: {local_migrations_dir}", "info")
        mig_path = local_migrations_dir
    elif offline:
        log(f"  Offline upgrade requires bundled migrations under package_dir/migrations/timesketch/", "error")
        log(f"  Re-prepare the upgrade package on a machine with internet access.", "error")
        return False
    else:
        mig_path = _fetch_migrations_dir(current_version, logger=log)

    if not mig_path:
        log(f"Could not obtain {current_version} migrations for bootstrap — "
            f"upgrade will likely fail to apply schema deltas", "error")
        return False

    run_command(f"docker exec {_WEB_CONTAINER} rm -rf /migrations", logger=None)
    cp = run_command(
        f"docker cp {shlex.quote(mig_path)} {_WEB_CONTAINER}:/migrations",
        timeout=60, logger=log
    )
    if not cp['success']:
        log(f"docker cp old migrations failed: {cp.get('error','?')[:200]}", "error")
        return False

    stamp = run_command(
        f"docker exec {_WEB_CONTAINER} tsctl db stamp -d /migrations head",
        timeout=120, logger=log
    )
    if not stamp['success']:
        log(f"db stamp failed: {stamp.get('error','?')[:300]}", "error")
        return False
    log(f"✓ Alembic bootstrapped to head of {current_version} — post-upgrade db upgrade will apply only the deltas", "success")
    return True


def _run_db_schema_upgrade(target_version: str, logger: Callable = None,
                            local_migrations_dir: Optional[str] = None,
                            offline: bool = False) -> bool:
    """Run `tsctl db upgrade` inside the (already-upgraded) web container.

    Migrations resolution order:
      1. `local_migrations_dir` if supplied (offline upgrade passes the path
         to the migrations bundled inside the upgrade package — no internet).
      2. Otherwise fetch from GitHub at the matching version tag (online).
         Skipped entirely when `offline=True` so air-gapped targets never
         touch the network.

    The installed Timesketch wheel doesn't ship migrations/ so one of these
    two paths has to provide them. Idempotent — a patch-level upgrade with
    no schema delta returns 0.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    if local_migrations_dir and os.path.isdir(local_migrations_dir) \
            and os.path.isdir(os.path.join(local_migrations_dir, 'versions')):
        log(f"Using bundled migrations from package: {local_migrations_dir}", "info")
        migrations_host_path = local_migrations_dir
    elif offline:
        log("Offline upgrade requires bundled migrations under "
            "package_dir/migrations/timesketch/ — none found. "
            "Re-prepare the upgrade package on a machine with internet.", "error")
        return False
    else:
        if local_migrations_dir:
            log(f"Bundled migrations not found at {local_migrations_dir} — falling back to GitHub fetch", "warning")
        migrations_host_path = _fetch_migrations_dir(target_version, logger=log)

    if not migrations_host_path:
        log("Skipping schema migration — no migrations available. Run "
            "'docker exec intact_timesketch_web tsctl db upgrade -d <path>' "
            "manually if the new version has schema changes.", "warning")
        return False

    # docker cp the host-side migrations into the web container. The trailing
    # /. on the source copies dir contents (not the dir itself) into /migrations.
    log("Copying migrations into intact_timesketch_web:/migrations", "info")
    run_command(f"docker exec {_WEB_CONTAINER} rm -rf /migrations", logger=None)
    cp = run_command(
        f"docker cp {shlex.quote(migrations_host_path)} {_WEB_CONTAINER}:/migrations",
        timeout=60, logger=log
    )
    if not cp['success']:
        log(f"docker cp migrations into container failed: {cp.get('error','?')[:200]}", "error")
        return False

    # Bootstrap (if needed) MUST have already run in the caller against the
    # OLD container — see `_bootstrap_alembic_if_needed`. At this point the
    # alembic_version row should exist; tsctl db upgrade just applies any
    # pending deltas between the bootstrapped revision and the target head.
    check = run_command(
        f"docker exec {_PG_CONTAINER} psql -U {_PG_USER} -d {_PG_DB} -tAc "
        f"\"SELECT version_num FROM alembic_version LIMIT 1;\"",
        logger=None
    )
    current_marker = (check.get('stdout') or '').strip()
    if current_marker:
        log(f"DB alembic version marker: {current_marker}", "info")
    else:
        # Caller didn't bootstrap. Don't blindly stamp head here — that's the
        # very bug we just fixed. Surface loudly so the operator notices.
        log("alembic_version is empty but bootstrap was skipped — refusing to "
            "blind-stamp head (would skip needed schema deltas). Run the "
            "upgrade flow which does pre-bootstrap, or stamp manually.", "error")
        return False

    log("Running tsctl db upgrade (alembic schema migration)...", "info")
    cmd = f"docker exec {_WEB_CONTAINER} tsctl db upgrade -d /migrations"
    result = run_command(cmd, timeout=600, logger=log)
    if not result['success']:
        log(f"tsctl db upgrade FAILED: {result.get('error','?')[:300]}", "error")
        return False
    out = (result.get('stdout') or '').strip()
    if out:
        log(f"tsctl db upgrade output: {out[:300]}", "info")
    log("tsctl db upgrade OK", "success")
    return True


def _clear_timesketch_pip_cache(logger: Callable = None):
    """Clear stale pip packages from Timesketch volume to prevent version conflicts.

    LLM packages (google-generativeai, anthropic, etc.) installed by Timesketch
    persist in the volume and can conflict when Timesketch is upgraded.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    # List of LLM-related packages that can cause conflicts
    conflicting_packages = [
        'google-generativeai',
        'google-ai-generativelanguage',
        'google-api-core',
        'google-api-python-client',
        'googleapis-common-protos',
        'grpcio',
        'grpcio-status',
        'proto-plus',
        'protobuf',
    ]

    # Run pip uninstall in a temporary container with the volume mounted
    for package in conflicting_packages:
        result = run_command(
            f"docker run --rm -v intact_timesketch_venv:/opt/venv "
            f"us-docker.pkg.dev/osdfir-registry/timesketch/timesketch:latest "
            f"pip uninstall -y {package} 2>/dev/null || true",
            logger=lambda msg, level="info": None  # Silent
        )

    log("Cleared potentially conflicting pip packages", "info")


def upgrade_timesketch(version: str, logger: Callable = None, plaso_version: str = None) -> Dict:
    """Upgrade Timesketch to specified version with automatic rollback on failure."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'timesketch')
    env_file = os.path.join(work_dir, '.env')
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')

    log("Starting Timesketch upgrade...", "info")

    # Get current versions for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('TIMESKETCH_VERSION', 'unknown')
    backend_vars = read_env_file(backend_env)
    current_plaso_version = backend_vars.get('PLASO_VERSION', 'unknown')

    # Create backups before making any changes
    log(f"Backing up current config (version {current_version})...", "info")
    ts_backup = backup_env_file(env_file, logger=log)
    plaso_backup = backup_env_file(backend_env, logger=log) if plaso_version else None

    # pg_dump the live DB BEFORE we stop containers — postgres gives a
    # consistent MVCC snapshot, and dumping a stopped DB is a non-starter.
    # If the dump fails we still proceed (env-backup rollback is better than
    # nothing), but log loudly so the operator knows the safety net is gone.
    db_backup_path = _backup_timesketch_db(current_version, version, logger=log)
    if not db_backup_path:
        log("Proceeding without DB backup — rollback will be config-only if upgrade fails", "warning")

    # Detect a Postgres MAJOR-version change (old-modules PG15 -> upstream PG13,
    # etc.) while the old container is still up. If the data dir's major differs
    # from the pinned major, an in-place start is impossible and we'll migrate
    # via dump/wipe/restore below. Refuse to proceed without a dump in that case.
    pg_migrate, pg_data_major, pg_pinned_major, pg_vol_name = _detect_pg_major_change(env_file, logger=log)
    if pg_migrate:
        log(f"Postgres major change: existing data is PG{pg_data_major}, target pins "
            f"PG{pg_pinned_major}. A dump->wipe->restore migration will run "
            f"(in-place major changes aren't possible).", "warning")
        if not db_backup_path:
            raise Exception("Postgres major change needs a DB dump, but pg_dump failed — "
                            "refusing to wipe data without a backup")

    # Snapshot row counts of every persistent table BEFORE the upgrade so we
    # can verify nothing disappeared. The postgres + opensearch volumes are
    # preserved by `docker compose down/up`, so persistent data should survive
    # automatically; this check makes that contract observable in every run.
    log("Snapshotting Timesketch row counts (users, sketches, timelines, indices)...", "info")
    counts_before = _snapshot_persistent_counts(logger=log)
    for tbl, n in counts_before.items():
        if n is not None:
            log(f"  pre-upgrade  {tbl:12} = {n}", "info")

    # Bootstrap alembic AGAINST THE STILL-RUNNING OLD CONTAINER so the post-
    # upgrade `tsctl db upgrade` knows to apply only the deltas between
    # current_version and target version. Without this, an install that was
    # never alembic-tracked (the common Timesketch case) would have its
    # schema deltas silently skipped — exactly the bug that left
    # `analysis.approach_id` missing after our first 20240828→20260326 test.
    if not _bootstrap_alembic_if_needed(current_version, logger=log):
        log("Alembic bootstrap failed — upgrade will likely leave schema mismatched. "
            "Refusing to continue.", "error")
        raise Exception("Could not bootstrap alembic tracking before upgrade")

    try:
        # Stop containers
        log("Stopping Timesketch containers...", "info")
        result = run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to stop Timesketch: {result['error']}")

        # Clear stale pip packages from persistent volume to prevent version conflicts
        log("Clearing stale pip packages from volume...", "info")
        _clear_timesketch_pip_cache(log)

        # Update version in .env
        log(f"Updating Timesketch version to {version}...", "info")
        update_env_file(env_file, 'TIMESKETCH_VERSION', version, logger=log)

        # Pull new images
        log("Pulling new Timesketch images...", "info")
        run_command("docker compose pull", cwd=work_dir, timeout=1800, logger=log)

        # Pull and update Plaso image if specified
        if plaso_version:
            log(f"Pulling Plaso {plaso_version}...", "info")
            run_command(f"docker pull log2timeline/plaso:{plaso_version}", logger=log, timeout=1800)
            log(f"Updating Plaso version to {plaso_version}...", "info")
            update_env_file(backend_env, 'PLASO_VERSION', plaso_version, logger=log)

        # Postgres major migration (if detected): wipe the old-major volume,
        # init the new major fresh, and restore the dump — BEFORE the full
        # stack starts so web/worker never see an incompatible data dir.
        if pg_migrate:
            if not _migrate_pg_major(work_dir, db_backup_path, pg_vol_name, logger=log):
                raise Exception("Postgres major migration failed — aborting upgrade")

        # Start containers
        log("Starting Timesketch containers...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to start Timesketch: {result['error']}")

        # Health check - wait for Timesketch container to be ready
        # Use pgrep to check if gunicorn is running (curl not available in container)
        log("Waiting for Timesketch container to be up...", "info")
        healthy = False
        for i in range(30):  # 30 * 5s = 150s max
            log(f"  Checking Timesketch container... ({i*5}s)", "info")
            # Check if gunicorn process is running in the container
            check_result = run_command(
                "docker exec intact_timesketch_web pgrep -f gunicorn",
                logger=None
            )
            if check_result['success']:
                pids = check_result.get('stdout', '').strip()
                log(f"  Container healthy - gunicorn running (PIDs: {pids.replace(chr(10), ', ')})", "success")
                healthy = True
                break
            else:
                log(f"  Container not ready yet...", "info")
            time.sleep(5)

        if healthy:
            log("Timesketch health check: PASSED", "success")
        else:
            # Check if containers are crash-looping
            check_result = run_command("docker ps -a --filter name=intact_timesketch --format '{{.Status}}'", logger=log)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"Timesketch failed to start - container status: {container_status}")
            log("Timesketch health check: TIMEOUT (containers may still be starting)", "warning")

        # Run the alembic schema migration from inside the NEW container.
        # This is the step that was missing before — without it the new
        # container code can hit columns/tables the old schema doesn't have,
        # which is what bit the 2024 → 2026 upgrade.
        if pg_migrate:
            # The restored dump predates this run's pre-stop alembic bootstrap
            # (which ran against the now-wiped old DB), so the fresh DB has no
            # alembic_version — re-bootstrap before the schema upgrade applies
            # the deltas. Idempotent: a no-op if tracking is already present.
            _bootstrap_alembic_if_needed(current_version, logger=log)
        if not _run_db_schema_upgrade(version, logger=log):
            raise Exception("tsctl db upgrade failed — DB schema is not in sync with new code")

        # Verify ALL persistent rows survived. If any table lost rows, treat
        # the upgrade as failed so the rollback path runs (.env restore +
        # pg_restore). This catches volume detach, mis-applied migrations,
        # and any other class of regression that silently drops user data.
        log("Verifying Timesketch row counts after upgrade...", "info")
        counts_after = _snapshot_persistent_counts(logger=log)
        loss = _assert_counts_preserved(counts_before, counts_after, logger=log)
        if loss:
            raise Exception(
                f"Data loss detected after upgrade — {loss}. "
                f"Rolling back from pg_dump at {db_backup_path}"
            )
        log("✓ All persistent rows preserved (users, sketches, timelines, indices)", "success")

        # Success - cleanup env-file backups. Keep the DB dump on disk so the
        # operator has a manual rollback artifact for the next 24-48h until
        # they're confident the new version is stable.
        cleanup_backup(ts_backup, logger=log)
        if plaso_backup:
            cleanup_backup(plaso_backup, logger=log)
        if db_backup_path:
            log(f"DB backup kept at {db_backup_path} (delete manually once confident)", "info")

        # NOTE: Backend restart NOT needed - Plaso runs as a separate Docker container
        # The new Plaso image will be used when a Plaso job is triggered

        log(f"Timesketch upgrade completed: {current_version} -> {version}", "success")
        remove_old_module_image('timesketch', current_version, version, logger=log)
        result = {"success": True, "version": version,
                  "health": health["health"], "health_detail": health["detail"]}
        if plaso_version:
            result["plaso_version"] = plaso_version
        if db_backup_path:
            result["db_backup"] = db_backup_path
        return result

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"Timesketch upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        # Restore backup files
        rollback_env_ok = restore_env_file(env_file, ts_backup, logger=log)
        if rollback_env_ok:
            run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK Timesketch config to version {current_version}", "warning")

            # Restore the pre-upgrade DB. If postgres won't come up because the
            # data-dir major no longer matches the rolled-back pin (legacy PG15
            # volume vs PG13 pin), this reconciles the volume (dump->wipe->restore)
            # so the rollback ends in a WORKING Timesketch, not a crash loop.
            _rollback_restore_db(work_dir, env_file, db_backup_path, pg_vol_name, logger=log)

        if plaso_backup and restore_env_file(backend_env, plaso_backup, logger=log):
            log(f"ROLLED BACK Plaso to version {current_plaso_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version,
            "db_backup": db_backup_path,
        }


def upgrade_timesketch_offline(package_dir: str, version: str, plaso_version: str = None, logger: Callable = None,
                                run_id: Optional[str] = None) -> Dict:
    """Upgrade Timesketch from offline package with automatic rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'timesketch')
    env_file = os.path.join(work_dir, '.env')
    backend_env = os.path.join(WORKDIR, 'modules', 'backend', '.env')
    images_dir = os.path.join(package_dir, 'images')

    log("Starting Timesketch offline upgrade...", "info")

    # Get current versions for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('TIMESKETCH_VERSION', 'unknown')
    backend_vars = read_env_file(backend_env)
    current_plaso_version = backend_vars.get('PLASO_VERSION', 'unknown')

    # Pre-check: load + verify the target images BEFORE stopping the running
    # stack, so a missing/corrupt tar fails here with Timesketch still up
    # instead of after `compose down` (downtime + rollback churn).
    from .base import preflight_offline_images
    pre = preflight_offline_images('timesketch', version, images_dir, logger=log, run_id=run_id)
    if not pre['success']:
        return {"success": False,
                "error": f"required Timesketch images unavailable (stack left running): {', '.join(pre['missing'])}"}

    # Create backups before making any changes
    log(f"Backing up current config (version {current_version})...", "info")
    ts_backup = backup_env_file(env_file, logger=log)
    plaso_backup = backup_env_file(backend_env, logger=log) if plaso_version else None

    # pg_dump the live DB BEFORE stop — same rationale as the online path.
    db_backup_path = _backup_timesketch_db(current_version, version, logger=log)
    if not db_backup_path:
        log("Proceeding without DB backup — rollback will be config-only if upgrade fails", "warning")

    # Detect a Postgres MAJOR-version change (old-modules PG15 -> upstream PG13,
    # etc.) while the old container is still up. If the data dir's major differs
    # from the pinned major, an in-place start is impossible and we'll migrate
    # via dump/wipe/restore below. Refuse to proceed without a dump in that case.
    pg_migrate, pg_data_major, pg_pinned_major, pg_vol_name = _detect_pg_major_change(env_file, logger=log)
    if pg_migrate:
        log(f"Postgres major change: existing data is PG{pg_data_major}, target pins "
            f"PG{pg_pinned_major}. A dump->wipe->restore migration will run "
            f"(in-place major changes aren't possible).", "warning")
        if not db_backup_path:
            raise Exception("Postgres major change needs a DB dump, but pg_dump failed — "
                            "refusing to wipe data without a backup")

    # Snapshot row counts of every persistent table BEFORE the upgrade so we
    # can prove nothing got dropped. The postgres + opensearch volumes are
    # preserved by `docker compose down/up`, so persistent data should survive
    # automatically; this check makes that contract observable in every run.
    log("Snapshotting Timesketch row counts (users, sketches, timelines, indices)...", "info")
    counts_before = _snapshot_persistent_counts(logger=log)
    for tbl, n in counts_before.items():
        if n is not None:
            log(f"  pre-upgrade  {tbl:12} = {n}", "info")

    # Bootstrap alembic against the still-running OLD container — same fix
    # as the online path. Without this, the post-upgrade `tsctl db upgrade`
    # would refuse to blind-stamp head and the upgrade would abort+rollback.
    #
    # Offline path: use the bundled migrations under the upgrade package
    # (prep step downloaded them on the prep machine). The apply machine
    # is air-gapped so we never reach for GitHub here — `offline=True`
    # makes the bootstrap fail loudly rather than try and silently break.
    bundled_mig = os.path.join(package_dir, 'migrations', 'timesketch')
    if not _bootstrap_alembic_if_needed(
        current_version,
        logger=log,
        local_migrations_dir=bundled_mig,
        offline=True,
    ):
        log("Alembic bootstrap failed — refusing to continue", "error")
        raise Exception("Could not bootstrap alembic tracking before upgrade")

    try:
        # Stop containers
        log("Stopping Timesketch containers...", "info")
        result = run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to stop Timesketch: {result['error']}")

        # Clear stale pip packages from persistent volume to prevent version conflicts
        log("Clearing stale pip packages from volume...", "info")
        _clear_timesketch_pip_cache(log)

        # Load docker images. Use load_all_bundled_images (same helper
        # the install path uses) so the four timesketch sidecars
        # (postgres / opensearch / redis / nginx) get loaded alongside
        # the primary tar. Idempotent — docker load on an
        # already-loaded image is a no-op, so a later module's upgrade
        # re-loading the same tar is harmless.
        #
        # Before this: the upgrade explicitly loaded ONLY
        # timesketch-<v>.tar and trusted compose-up to find the
        # sidecars in the local docker store. On air-gap targets where
        # the sidecars had never been pulled (or where the pins
        # changed between install and upgrade — e.g. opensearch
        # 2.11.0 → 2.19.5) compose-up failed with "No such image:
        # opensearchproject/opensearch:<new tag>" and the whole
        # timesketch upgrade rolled back. 2026-06-15 incident.
        from .base import load_all_bundled_images
        load_all_bundled_images(package_dir, logger=log, run_id=run_id)

        if plaso_version:
            log(f"Updating Plaso version to {plaso_version}...", "info")
            update_env_file(backend_env, 'PLASO_VERSION', plaso_version, logger=log)

        # Update version in .env
        log(f"Updating Timesketch version to {version}...", "info")
        update_env_file(env_file, 'TIMESKETCH_VERSION', version, logger=log)

        # Postgres major migration (if detected): wipe the old-major volume,
        # init the new major fresh, and restore the dump — BEFORE the full
        # stack starts so web/worker never see an incompatible data dir.
        if pg_migrate:
            if not _migrate_pg_major(work_dir, db_backup_path, pg_vol_name, logger=log):
                raise Exception("Postgres major migration failed — aborting upgrade")

        # Start containers
        log("Starting Timesketch containers...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to start Timesketch: {result['error']}")

        # Honest health gate (G5) — see the online variant for rationale.
        log("Waiting for Timesketch to become healthy...", "info")
        from .base import enforce_module_health
        health = enforce_module_health('timesketch', timeout=150, logger=log)

        # Apply alembic schema migration. Offline upgrades use the migrations
        # bundled in the package (no internet) — `offline=True` makes the
        # function refuse to fall back to GitHub if the bundle is missing,
        # which is the right behavior for an air-gapped target.
        bundled_mig = os.path.join(package_dir, 'migrations', 'timesketch')
        if pg_migrate:
            # Restored dump has no alembic_version (taken before this run's
            # pre-stop bootstrap, which ran against the now-wiped old DB) —
            # re-bootstrap before applying the deltas. Idempotent.
            _bootstrap_alembic_if_needed(current_version, logger=log)
        if not _run_db_schema_upgrade(version, logger=log,
                                       local_migrations_dir=bundled_mig,
                                       offline=True):
            raise Exception("tsctl db upgrade failed — DB schema is not in sync with new code")

        # Verify ALL persistent rows survived the offline upgrade.
        log("Verifying Timesketch row counts after upgrade...", "info")
        counts_after = _snapshot_persistent_counts(logger=log)
        loss = _assert_counts_preserved(counts_before, counts_after, logger=log)
        if loss:
            raise Exception(
                f"Data loss detected after upgrade — {loss}. "
                f"Rolling back from pg_dump at {db_backup_path}"
            )
        log("✓ All persistent rows preserved (users, sketches, timelines, indices)", "success")

        # Success - cleanup env-file backups; keep the DB dump for manual rollback.
        cleanup_backup(ts_backup, logger=log)
        if plaso_backup:
            cleanup_backup(plaso_backup, logger=log)
        if db_backup_path:
            log(f"DB backup kept at {db_backup_path} (delete manually once confident)", "info")

        # NOTE: Backend restart NOT needed - Plaso runs as a separate Docker container
        # The new Plaso image will be used when a Plaso job is triggered

        log(f"Timesketch offline upgrade completed: {current_version} -> {version}", "success")
        remove_old_module_image('timesketch', current_version, version, logger=log)
        result = {"success": True, "version": version,
                  "health": health["health"], "health_detail": health["detail"]}
        if plaso_version:
            result["plaso_version"] = plaso_version
        if db_backup_path:
            result["db_backup"] = db_backup_path
        return result

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"Timesketch offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        rollback_env_ok = restore_env_file(env_file, ts_backup, logger=log)
        if rollback_env_ok:
            run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
            run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)
            log(f"ROLLED BACK Timesketch config to version {current_version}", "warning")

            # Same as the online path: restore the DB, reconciling a postgres
            # major mismatch (volume vs rolled-back pin) if postgres won't start.
            _rollback_restore_db(work_dir, env_file, db_backup_path, pg_vol_name, logger=log)

        if plaso_backup and restore_env_file(backend_env, plaso_backup, logger=log):
            log(f"ROLLED BACK Plaso to version {current_plaso_version}", "warning")

        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version,
            "db_backup": db_backup_path,
        }


def install_timesketch_offline(package_dir: str, version: str, logger=None, run_id=None) -> Dict:
    """Fresh-install Timesketch — picked when intact_timesketch_web absent.

    Three stages after `docker compose up -d`, matching what
    `lib/modules.sh:deploy_timesketch` does for the install.sh path:
      1. Poll for the postgres `user` table to materialize (the
         Timesketch web container creates the schema lazily via
         SQLAlchemy create_all on first start — typically ~10-30s).
      2. Create the admin user from config.yaml via `tsctl create-user`.
      3. Enable + make-admin so backend API auth works.

    Without these, the install reports success but the backend can
    never reach the Timesketch API because no admin user exists →
    the operator sees "Timesketch shows no connection" in the UI.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    from .base import install_module_compose_up
    work_dir = os.path.join(WORKDIR, 'modules', 'timesketch')
    env_file = os.path.join(work_dir, '.env')
    log(f"Installing Timesketch (first-time) -> {version or 'tracked default'}...", "info")
    # Ensure .env exists + has TIMESKETCH_VERSION before compose up.
    # Fresh-install via UI may run with no pre-existing .env (install.sh's
    # deploy_timesketch writes one from a template, but UI install bypasses
    # that). Without writing this here, compose would either fall back to
    # `${TIMESKETCH_VERSION:-latest}` (pulls from registry — breaks
    # air-gap) or fail at the `${VAR:?}` rule depending on the compose
    # file. update_env_file is idempotent: creates the file when missing,
    # rewrites the line when present.
    if version:
        os.makedirs(work_dir, exist_ok=True)
        if not os.path.exists(env_file):
            open(env_file, 'a').close()
        update_env_file(env_file, 'TIMESKETCH_VERSION', version, logger=log)

    # Bootstrap timesketch.conf + timesketch_legacy.conf from templates
    # BEFORE compose up — mirrors lib/modules.sh:deploy_timesketch which
    # does the same thing for install.sh. Without these files the web /
    # worker / legacy containers crash-loop on `Config file
    # /etc/timesketch.conf does not exist` and the schema-bootstrap wait
    # below times out at 120s. This was the root cause of the
    # 2026-06-11 offline-install failure where the apply marked
    # Timesketch "completed with warning" but the operator couldn't
    # reach the UI. Idempotent: existing confs are preserved so
    # operator's Settings → Timesketch api_key survives re-runs.
    cfg_dir = os.path.join(work_dir, 'config')
    if os.path.isdir(cfg_dir):
        import secrets as _secrets
        for base in ('timesketch.conf', 'timesketch_legacy.conf'):
            template = os.path.join(cfg_dir, f'{base}.template')
            out = os.path.join(cfg_dir, base)
            if os.path.exists(out):
                log(f"  {base} already present (skip)", "info")
                continue
            if not os.path.exists(template):
                log(f"  Template missing: {template}", "warning")
                continue
            try:
                with open(template) as f:
                    rendered = f.read()
                # SECRET_KEY signs Flask session cookies + CSRF tokens —
                # must be unique per install. Templates ship a
                # __SECRET_KEY__ placeholder OR a stub literal; the
                # regex covers both shapes (mirrors lib/modules.sh:467).
                import re
                random_key = _secrets.token_hex(32)
                rendered = re.sub(
                    r"^SECRET_KEY\s*=\s*'[^']*'",
                    f"SECRET_KEY = '{random_key}'",
                    rendered,
                    count=1,
                    flags=re.MULTILINE,
                )
                with open(out, 'w') as f:
                    f.write(rendered)
                log(f"  {base} created from template (api_key empty — set via Settings → Timesketch; SECRET_KEY randomized)", "success")
            except Exception as e:
                log(f"  {base} bootstrap failed: {e}", "warning")
    else:
        log(f"  Config dir missing at {cfg_dir} — Timesketch will crash-loop on missing conf. Check package extraction.", "warning")

    # Stamp transitive container versions from the bundled manifest
    # into modules/timesketch/.env BEFORE compose up. Without this,
    # compose's `${VAR:?...}` interpolation fails because the env
    # vars (POSTGRES_VERSION etc.) aren't set. The manifest was
    # populated at prepare time from config.yaml's
    # `versions.timesketch_<dep>` entries — single source of truth.
    from .base import stamp_transitive_env_from_manifest
    try:
        stamp_transitive_env_from_manifest('timesketch', package_dir, logger=log)
    except Exception as _e:
        log(f"  transitive .env stamp raised "
            f"({type(_e).__name__}: {_e}); compose up will likely fail",
            "warning")

    compose_result = install_module_compose_up(
        'timesketch', package_dir, version,
        image_tar_prefixes=['timesketch'],
        logger=log, run_id=run_id,
    )
    if not compose_result.get('success'):
        return compose_result

    # Post-install bootstrap — make the stack actually usable.
    log("Timesketch containers up. Bootstrapping schema + admin user...", "info")

    # Stage 1: poll for the postgres user table. The web container
    # creates the schema lazily via SQLAlchemy create_all() on first
    # start; tsctl create-user races it if we call it too early.
    #
    # `to_regclass('public."user"')` returns the regclass formatted as
    # the table name with double-quotes preserved when the identifier
    # is a reserved word — so the output we get back is literally
    # `"user"` (3 chars: quote, "user", quote), NOT bare `user`. An
    # earlier attempt failed by checking `out == 'user'` which never
    # matched. Use a substring check so both shapes work and we don't
    # bind to the exact format psql happens to print.
    log("Waiting for Timesketch postgres `user` table to materialize...", "info")
    schema_ready = False
    waited = 0
    # 5 min wall-clock budget. 120 s was too tight on slow disks /
    # CPU-constrained installs — the user from 2026-06-11 saw a clean
    # install report "completed" but the schema never materialized
    # because postgres + opensearch + redis + web took >120 s to
    # finish their cold-boot. Most installs land at 30-60 s so the
    # extra slack is paid only on the slow-machine tail.
    _SCHEMA_WAIT_SECS = 300
    while waited < _SCHEMA_WAIT_SECS:
        probe = run_command(
            'docker exec intact_timesketch_postgres psql -U timesketch -d timesketch '
            '-tAc "SELECT to_regclass(\'public.\\"user\\"\');"',
            logger=None, timeout=10,
        )
        out = (probe.get('stdout', '') or '').strip().strip('"')
        # Empty / "NULL" → table doesn't exist yet (postgres returns
        # NULL for to_regclass on a missing relation). Anything else
        # non-empty IS a regclass identifier — i.e. the table exists.
        if out and out.upper() != 'NULL':
            schema_ready = True
            log(f"  Timesketch `user` table is present ({waited}s)", "success")
            break
        # Heartbeat every 30 s so the operator knows we haven't hung.
        if waited and waited % 30 == 0:
            log(f"  …still waiting for schema ({waited}s elapsed of "
                f"{_SCHEMA_WAIT_SECS}s budget)", "info")
        time.sleep(2)
        waited += 2

    if not schema_ready:
        log(
            f"Timesketch postgres `user` table did not appear after "
            f"{_SCHEMA_WAIT_SECS}s — the web container may still be "
            f"initializing. Admin user creation skipped; operator should "
            f"run `docker exec intact_timesketch_web tsctl create-user "
            f"<id> --password <pw>` manually once the schema is ready.",
            "warning",
        )
        # Return compose-up success — containers ARE running, just not
        # fully usable yet. Surfacing as success-with-warning so the
        # orchestration's cascade resilience continues with other modules.
        return compose_result

    # Stage 2 + 3: create + enable admin user from config.yaml.
    # Reuses the existing helper which already handles read-config,
    # tsctl create-user, and make-admin.
    try:
        from . import recreate_timesketch_user  # avoid top-level circular
    except ImportError:
        from services.upgrade import recreate_timesketch_user
    if recreate_timesketch_user(logger=log):
        log("Timesketch admin user created — backend API ready", "success")
    else:
        log(
            "Timesketch admin user creation FAILED. Containers are up but "
            "the backend cannot authenticate to the Timesketch API. Fix "
            "manually with `docker exec intact_timesketch_web tsctl "
            "create-user <id> --password <pw>` then `tsctl make-admin <id>`.",
            "warning",
        )

    return compose_result

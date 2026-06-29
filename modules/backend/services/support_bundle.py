#!/usr/bin/env python3
"""Generate a support bundle ZIP for diagnostic purposes.

Mirrors the upgrade-prepare pattern: a background worker collects logs
from every IntactAI surface (docker containers, on-disk service logs,
workflow runs, compose configs), packs them into one .zip, and stores
the path on the workflow run for the route to serve via send_file.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import zipfile
from datetime import datetime
from typing import Callable, Dict, List, Optional


# Per-container `docker logs --tail N`. 10k lines covers a few hours of
# normal activity for most containers without ballooning the bundle. If
# this turns out too thin or too thick in the field, expose it as a
# request body field on /api/support-bundle/prepare.
CONTAINER_LOG_TAIL_LINES = 10000

# Per-file cap for auto-discovered service logs. Some containers carry
# multi-hundred-MB worker.log or audit logs; we want the most recent
# portion (where tracebacks land) without bloating the bundle. 50 MB
# captures hours of busy logging while keeping the staging dir bounded
# even when the same volume is mounted by several sibling containers.
SERVICE_LOG_TAIL_BYTES = 50 * 1024 * 1024  # 50 MB

# Where the bundle tarball is written. Bind-mounted-ish location inside
# the backend container (/data/upgrade_packages already lives next to
# this and is on the ephemeral layer — same trade-off applies: bundles
# survive within the backend's lifetime, gone on restart).
BUNDLE_OUTPUT_DIR = "/data/support_bundles"


def _run(cmd: str, timeout: int = 60) -> Dict:
    """Thin subprocess wrapper. Same shape as services/upgrade/base.run_command
    but local so this module doesn't pull in the upgrade package."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'success': r.returncode == 0, 'stdout': r.stdout, 'stderr': r.stderr, 'returncode': r.returncode}
    except subprocess.TimeoutExpired:
        return {'success': False, 'stdout': '', 'stderr': f'timeout after {timeout}s', 'returncode': -1}
    except Exception as e:
        return {'success': False, 'stdout': '', 'stderr': str(e), 'returncode': -1}


def _list_intact_containers(logger: Callable) -> List[str]:
    """Return all containers named intact_* (including stopped) so the
    bundle covers crashed ones too — that's often the interesting case."""
    res = _run("docker ps -a --filter 'name=intact_' --format '{{.Names}}'", timeout=15)
    if not res['success']:
        logger(f"Could not list intact containers: {res['stderr'][:200]}", 'error')
        return []
    names = [n.strip() for n in res['stdout'].splitlines() if n.strip()]
    logger(f"Discovered {len(names)} intact_* containers", 'info')
    return names


def _collect_container_logs(container: str, dest_dir: str, logger: Callable) -> Optional[int]:
    """Write `docker logs --tail N --timestamps <container>` to a file.
    Returns the line count on success, None on failure.

    If the container produces no stdout (e.g. timesketch_web logs to file,
    not stdout), we drop the resulting 0-byte file from the bundle —
    the manifest still records `log_lines: 0` so the absence is observable.
    """
    out_path = os.path.join(dest_dir, f"{container}.log")
    # --tail and --timestamps both supported on every modern docker.
    # 2>&1 merges stderr so we capture both normal stdout and warnings.
    cmd = f"docker logs --tail {CONTAINER_LOG_TAIL_LINES} --timestamps {container} > {out_path} 2>&1"
    res = _run(cmd, timeout=120)
    if not res['success'] and not os.path.exists(out_path):
        logger(f"  ✗ {container}: {res['stderr'][:120]}", 'warning')
        return None
    if not os.path.exists(out_path):
        return None
    # Quick line count for the manifest. Cheap because docker logs already
    # capped at CONTAINER_LOG_TAIL_LINES.
    try:
        with open(out_path, 'rb') as f:
            count = sum(1 for _ in f)
    except Exception:
        count = -1
    # Don't ship empty placeholders — manifest still says log_lines=0.
    if count == 0:
        try:
            os.remove(out_path)
        except Exception:
            pass
    return count


# OS-noise log filenames that exist in base images (Debian, Ubuntu,
# CentOS/RHEL via DNF, Alpine via apk) but never contain anything useful
# for IntactAI triage. Skip them so we don't bloat the bundle.
_SKIP_LOG_BASENAMES = {
    'alternatives.log', 'bootstrap.log', 'dpkg.log', 'fontconfig.log',
    'hawkey.log',  # DNF (RHEL/Fedora base images)
    'apk.log',     # Alpine package manager
    'lastlog', 'wtmp', 'btmp',
}
_SKIP_LOG_DIR_PARTS = {'apt'}  # /var/log/apt/* is always installer noise


def _collect_real_log_files(container: str, dest_dir: str, logger: Callable) -> int:
    """Auto-discover real (non-symlink) log files under /var/log/ inside a
    container and copy them out. Catches the app-level logs that
    `docker logs` misses — gunicorn wsgi_error.log, celery worker.log,
    iris nginx's audit_platform_*.log, etc.

    Skips:
      * symlinks (e.g. /var/log/nginx/access.log → /dev/stdout — already
        captured by Phase 3's `docker logs`, and `cat`-ing them blocks)
      * OS package noise (apt/dpkg/alternatives) — _SKIP_LOG_* above.
    """
    # `find -type f` skips symlinks. -name '*.log' keeps it tight. -printf
    # 'size path' gives us enough to skip zero-byte files cheaply.
    discover = _run(
        f"docker exec {container} sh -c \""
        f"find /var/log -type f \\( -name '*.log' -o -name 'wsgi_*' \\) "
        f"-not -path '*/apt/*' 2>/dev/null\"",
        timeout=5,
    )
    if not discover['success']:
        return 0

    n = 0
    container_dir = os.path.join(dest_dir, container)
    for path in (discover.get('stdout') or '').splitlines():
        path = path.strip()
        if not path:
            continue
        basename = os.path.basename(path)
        if basename in _SKIP_LOG_BASENAMES:
            continue
        if any(part in _SKIP_LOG_DIR_PARTS for part in path.split('/')):
            continue

        # Mirror the container path under <dest_dir>/<container>/<rel-path>
        # so it's obvious where each file came from.
        rel = path.lstrip('/')
        out_path = os.path.join(container_dir, rel)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        # `tail -c N` grabs the LAST N bytes — useful for triage because
        # the recent end of the file is where the operator-relevant
        # tracebacks/errors live. Without this cap, a 656 MB worker.log
        # mounted into 3 sibling containers would balloon the staging
        # dir to ~2 GB and serve no extra signal vs. the most recent
        # SERVICE_LOG_TAIL_BYTES.
        cmd = (
            f"docker exec {container} sh -c "
            f"\"tail -c {SERVICE_LOG_TAIL_BYTES} '{path}' 2>/dev/null\" "
            f"> '{out_path}' 2>/dev/null"
        )
        res = _run(cmd, timeout=15)
        if res['success'] and os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            n += 1
        else:
            try:
                if os.path.exists(out_path) and os.path.getsize(out_path) == 0:
                    os.remove(out_path)
            except Exception:
                pass
    return n


def _dump_workflow_runs(dest_dir: str, logger: Callable) -> int:
    """Iterate every workflow run via the same service the dashboard uses
    and dump each as a self-contained JSON. Logs the count for the
    manifest."""
    try:
        from services.workflow_service import get_all_automation_runs
    except Exception as e:
        logger(f"workflow_service import failed: {e}", 'error')
        return 0
    runs = get_all_automation_runs() or []
    written = 0
    for run in runs:
        rid = run.get('run_id') or run.get('id')
        if not rid:
            continue
        try:
            out_path = os.path.join(dest_dir, f"{rid}.json")
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(run, f, indent=2, default=str)
            written += 1
        except Exception as e:
            logger(f"  could not serialise run {rid}: {e}", 'warning')
    return written


def _dump_case_logs(dest_dir: str, logger: Callable) -> int:
    """Write each Case Analysis activity log as a readable .log file (workflow-log
    style: `[ts] [LEVEL] action — detail`), so a support engineer gets the full
    config-change / refusion / report / chat audit trail without unpacking JSON."""
    try:
        from services.workflow_service import get_all_automation_runs
    except Exception as e:
        logger(f"workflow_service import failed (case logs): {e}", 'error')
        return 0
    written = 0
    for run in (get_all_automation_runs() or []):
        try:
            if run.get('automation_type') != 'case':
                continue
            det = run.get('details') or {}
            log = det.get('activity_log') or []
            if not log:
                continue
            rid = run.get('run_id') or run.get('id') or 'case'
            name = det.get('name') or run.get('name') or rid
            safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(name))[:60] or "case"
            out_path = os.path.join(dest_dir, f"{safe}-{rid}.log")
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(f"# Case Analysis activity log — {name} ({rid})\n")
                f.write("# All times in UTC+00:00\n\n")
                for e in log:
                    line = f"[{e.get('ts','')}] [{str(e.get('status') or 'ok').upper()}] {e.get('action','')}"
                    if e.get('detail'):
                        line += f" — {e.get('detail')}"
                    if e.get('code'):
                        line += f" (HTTP {e.get('code')})"
                    f.write(line + "\n")
            written += 1
        except Exception as e:
            logger(f"  could not write case log for {run.get('run_id')}: {e}", 'warning')
    return written


def _copy_compose_configs(workdir: str, dest_dir: str, logger: Callable) -> int:
    """Copy every `modules/<m>/docker-compose.yaml` so the support engineer
    can see how the platform is wired together.

    .env files are deliberately NOT included — even with redaction they
    risk leaking secrets if the regex misses a key naming convention.
    The compose YAMLs are enough to understand container relationships;
    operators can describe non-secret env tweaks in a support ticket.
    """
    n = 0
    modules_dir = os.path.join(workdir, 'modules')
    if not os.path.isdir(modules_dir):
        logger(f"modules dir not found at {modules_dir}", 'warning')
        return 0
    for entry in sorted(os.listdir(modules_dir)):
        mod_path = os.path.join(modules_dir, entry)
        if not os.path.isdir(mod_path):
            continue
        for cf in ('docker-compose.yaml', 'docker-compose.yml'):
            src = os.path.join(mod_path, cf)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(dest_dir, f"{entry}-{cf}"))
                n += 1
    return n


def _system_info(dest_path: str, logger: Callable) -> None:
    """Dump a single text file with `docker ps`, disk, memory, kernel, date."""
    sections = [
        ('Date',         "date -u"),
        ('Uname',        "uname -a"),
        ('Docker ps -a', "docker ps -a --format 'table {{.Names}}\\t{{.Status}}\\t{{.Image}}'"),
        ('df -h',        "df -h"),
        ('free -h',      "free -h"),
        ('Docker volumes', "docker volume ls"),
        ('Docker networks', "docker network ls"),
    ]
    parts: List[str] = []
    for title, cmd in sections:
        parts.append(f"================ {title} ================")
        parts.append(f"$ {cmd}")
        res = _run(cmd, timeout=20)
        parts.append((res.get('stdout') or '').rstrip())
        if res.get('stderr'):
            parts.append("--- stderr ---")
            parts.append(res['stderr'].rstrip())
        parts.append("")
    with open(dest_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(parts))


def _storage_breakdown(dest_path: str, logger: Callable) -> Dict:
    """Write `storage_breakdown.txt` with per-container + per-volume sizes
    and return the parsed per-container sizes so the manifest can carry
    them in machine-readable form.

    Three views:
      1. `docker system df`     — high-level totals (images / containers / volumes)
      2. `docker system df -v`  — per-image, per-container, per-volume detail
      3. `docker ps -a --size`  — writable-layer + virtual size per container
                                  (this is what answers "how much does container X
                                  cost in extra disk vs the base image?")
    """
    parts: List[str] = []
    sections = [
        ('Docker total (df)',           "docker system df",          30),
        ('Docker per-object detail (df -v)',
                                         "docker system df -v",       60),
        ('Per-container writable + virtual size',
            "docker ps -a --size --format 'table {{.Names}}\\t{{.Size}}\\t{{.Status}}'",
                                                                      15),
    ]
    for title, cmd, timeout in sections:
        parts.append(f"================ {title} ================")
        parts.append(f"$ {cmd}")
        res = _run(cmd, timeout=timeout)
        parts.append((res.get('stdout') or '').rstrip())
        if res.get('stderr'):
            parts.append("--- stderr ---")
            parts.append(res['stderr'].rstrip())
        parts.append("")

    with open(dest_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(parts))

    # Parse the per-container Size column for the manifest. docker prints
    # something like "180MB (virtual 1.1GB)" — pull the leading bytes value.
    per_container: Dict[str, str] = {}
    parse = _run(
        "docker ps -a --filter 'name=intact_' --format '{{.Names}}|{{.Size}}'",
        timeout=15,
    )
    if parse['success']:
        for line in (parse.get('stdout') or '').splitlines():
            if '|' in line:
                name, size = line.split('|', 1)
                per_container[name.strip()] = size.strip()
    return per_container


def _dir_bytes(path: str) -> int:
    """Total bytes under a directory (used for the per-section composition
    breakdown the manifest reports)."""
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def prepare_support_bundle(run_id: str, logger: Callable) -> Dict:
    """Build the support bundle for `run_id`. Updates the run via the
    supplied logger (which the route wires to add_log_to_run +
    update_run_status). Returns a dict the caller stores on the run's
    `details` field so the download endpoint can find the file.
    """
    from services.workflow_service import update_run_status, get_cancel_event

    started = time.time()
    cancel_event = get_cancel_event(run_id) if run_id else None

    def _check_cancel():
        return cancel_event is not None and cancel_event.is_set()

    # Use an isolated staging dir per bundle so concurrent triggers can't
    # tread on each other. The tarball is timestamped for the same reason.
    os.makedirs(BUNDLE_OUTPUT_DIR, exist_ok=True)
    stamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    staging_root = tempfile.mkdtemp(prefix=f"support-bundle-{stamp}-", dir="/tmp")
    bundle_root_name = f"intact-support-{stamp}"
    bundle_root = os.path.join(staging_root, bundle_root_name)
    for sub in ('containers', 'service_logs', 'workflows', 'case_logs', 'compose'):
        os.makedirs(os.path.join(bundle_root, sub), exist_ok=True)

    manifest: Dict = {
        'bundle_name': bundle_root_name,
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'run_id': run_id,
        'container_log_tail_lines': CONTAINER_LOG_TAIL_LINES,
        # `containers[<name>]` carries both line count (set in Phase 3) and
        # writable+virtual disk size (set in Phase 2), so a single lookup
        # tells the operator everything they need about a container.
        'containers': {},
        'service_log_files': 0,
        'workflow_runs': 0,
        'case_activity_logs': 0,
        'compose_files': 0,
        # Filled in at Phase 7 after every section is built — gives the
        # support engineer a per-section MB breakdown without unzipping.
        'bundle_composition_bytes': {},
        'errors': [],
    }

    try:
        # Phase 1 — discover containers.
        update_run_status(run_id, 'running', progress=5)
        logger("=== Phase 1/7: discovering containers ===", 'info')
        containers = _list_intact_containers(logger)
        if not containers:
            logger("No intact_* containers found — bundle will be sparse", 'warning')

        if _check_cancel():
            raise RuntimeError('cancelled')

        # Phase 2 — system info + docker storage breakdown. Two files:
        # `system_info.txt` (date, df, free, docker ps), and
        # `storage_breakdown.txt` (per-container/per-volume sizes). The
        # storage helper also returns parsed sizes that we record on each
        # container's manifest entry so the operator gets a clean per-
        # container "X MB writable / virtual Y GB" alongside the log
        # line count, all in one place.
        update_run_status(run_id, 'running', progress=10)
        logger("=== Phase 2/7: capturing system info + storage breakdown ===", 'info')
        _system_info(os.path.join(bundle_root, 'system_info.txt'), logger)
        per_container_size = _storage_breakdown(
            os.path.join(bundle_root, 'storage_breakdown.txt'), logger
        )
        # Seed the manifest containers map with sizes now — Phase 3 will
        # add log_lines to each entry.
        for c, sz in per_container_size.items():
            manifest['containers'][c] = {'size': sz}
        logger(f"  ✓ Captured size info for {len(per_container_size)} containers", 'info')

        if _check_cancel():
            raise RuntimeError('cancelled')

        # Phase 3 — per-container docker logs.
        logger(f"=== Phase 3/7: collecting docker logs (--tail {CONTAINER_LOG_TAIL_LINES}) ===", 'info')
        containers_dir = os.path.join(bundle_root, 'containers')
        for idx, c in enumerate(containers):
            if _check_cancel():
                raise RuntimeError('cancelled')
            lines = _collect_container_logs(c, containers_dir, logger)
            # Merge with any size info seeded in Phase 2 so each container's
            # manifest entry ends up as {'size': '...', 'log_lines': N}.
            entry = manifest['containers'].setdefault(c, {})
            entry['log_lines'] = lines
            # 10..60% spread across the container list — gives a moving
            # progress bar even when there are 20 containers.
            pct = 10 + int(50 * (idx + 1) / max(len(containers), 1))
            update_run_status(run_id, 'running', progress=pct)
            logger(f"  ✓ {c}: {lines if lines is not None else 'FAILED'} lines"
                   + (f"  [{entry.get('size','?')}]" if entry.get('size') else ''), 'info')

        # Phase 4 — pull on-disk service logs (gunicorn wsgi_error.log,
        # celery worker.log, iris nginx audit_*.log, etc.) that
        # `docker logs` doesn't see because the apps write to files
        # directly instead of stdout. Auto-discovers per container.
        update_run_status(run_id, 'running', progress=65)
        logger("=== Phase 4/7: pulling on-disk service logs (wsgi_error, worker, audit) ===", 'info')
        svc_dir = os.path.join(bundle_root, 'service_logs')
        for c in containers:
            if _check_cancel():
                raise RuntimeError('cancelled')
            n = _collect_real_log_files(c, svc_dir, logger)
            if n:
                manifest['service_log_files'] += n
                logger(f"  ✓ {c}: {n} on-disk log file(s)", 'info')

        # Phase 5 — every workflow run as JSON.
        update_run_status(run_id, 'running', progress=80)
        logger("=== Phase 5/7: exporting workflow runs ===", 'info')
        wf_dir = os.path.join(bundle_root, 'workflows')
        count = _dump_workflow_runs(wf_dir, logger)
        manifest['workflow_runs'] = count
        logger(f"  ✓ {count} workflow runs serialised", 'info')
        # Case Analysis activity logs as readable .log files (config changes,
        # refusion/rescan progress, report LLM calls, chat actions, errors).
        cl = _dump_case_logs(os.path.join(bundle_root, 'case_logs'), logger)
        manifest['case_activity_logs'] = cl
        logger(f"  ✓ {cl} case activity log(s) exported", 'info')

        if _check_cancel():
            raise RuntimeError('cancelled')

        # Phase 6 — compose configs only. .env files intentionally not
        # included to eliminate any chance of leaked credentials.
        update_run_status(run_id, 'running', progress=88)
        logger("=== Phase 6/7: copying compose configs ===", 'info')
        compose_dir = os.path.join(bundle_root, 'compose')
        workdir = '/app/workdir' if os.path.isdir('/app/workdir/modules') else \
                  os.environ.get('INTACT_PATH', '/app/workdir')
        compose_count = _copy_compose_configs(workdir, compose_dir, logger)
        manifest['compose_files'] = compose_count
        logger(f"  ✓ {compose_count} compose file(s)", 'info')

        # Phase 7 — per-section size breakdown, manifest, zip.
        update_run_status(run_id, 'running', progress=94)
        logger("=== Phase 7/7: writing manifest + packing .zip ===", 'info')

        # Per-section size measurement, BEFORE we add the manifest itself
        # (manifest is tiny so its absence here doesn't skew the numbers).
        # This goes into the manifest so a support engineer can see "ah,
        # service_logs is 8 MB, that's why this bundle is fat" without
        # having to unzip and du each subdir.
        composition: Dict[str, Dict] = {}
        for sub in ('containers', 'service_logs', 'workflows', 'compose'):
            sub_path = os.path.join(bundle_root, sub)
            if os.path.isdir(sub_path):
                size = _dir_bytes(sub_path)
                composition[sub] = {
                    'bytes': size,
                    'mb': round(size / (1024 * 1024), 2),
                }
        for fname in ('system_info.txt', 'storage_breakdown.txt'):
            fp = os.path.join(bundle_root, fname)
            if os.path.isfile(fp):
                composition[fname] = {
                    'bytes': os.path.getsize(fp),
                    'mb': round(os.path.getsize(fp) / (1024 * 1024), 2),
                }
        manifest['bundle_composition_bytes'] = composition
        # Surface the breakdown in the run log too so it's visible from
        # the Workflows tab without downloading the bundle.
        for k, v in sorted(composition.items(), key=lambda x: -x[1]['bytes']):
            logger(f"  composition {k:24} {v['mb']:>8.2f} MB", 'info')

        with open(os.path.join(bundle_root, 'manifest.json'), 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2, default=str)

        bundle_path = os.path.join(BUNDLE_OUTPUT_DIR, f"{bundle_root_name}.zip")
        # zipfile (pure-python, no subprocess) with DEFLATE compression —
        # universally openable by any OS file manager (no `tar` needed).
        with zipfile.ZipFile(bundle_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for root, _dirs, files in os.walk(bundle_root):
                for f in files:
                    abs_path = os.path.join(root, f)
                    rel_path = os.path.relpath(abs_path, staging_root)
                    zf.write(abs_path, arcname=rel_path)
        size_mb = round(os.path.getsize(bundle_path) / (1024 * 1024), 2)

        elapsed = round(time.time() - started, 1)
        logger(f"✓ Support bundle ready: {bundle_path} ({size_mb} MB, built in {elapsed}s)", 'success')

        return {
            'bundle_path': bundle_path,
            'bundle_name': f"{bundle_root_name}.zip",
            'bundle_size_mb': size_mb,
            'container_count': len(containers),
            'workflow_run_count': manifest['workflow_runs'],
            'service_log_file_count': manifest['service_log_files'],
        }

    finally:
        # Always remove the staging tree, success or fail. The tarball
        # itself lives under BUNDLE_OUTPUT_DIR and stays.
        try:
            shutil.rmtree(staging_root, ignore_errors=True)
        except Exception:
            pass

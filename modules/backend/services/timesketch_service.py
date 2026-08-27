#!/usr/bin/env python3
"""
Timesketch Service - Timesketch import functions using Python API

Uses timesketch_import_client.importer.ImportStreamer for direct .plaso upload,
which properly triggers Timesketch's Celery workers to process all parsers.
"""

import os
import sys
import time
import traceback
import warnings

from services.workflow_service import get_cancel_event

# Disable SSL warnings for self-signed certificates. Certificate verification
# itself is disabled per-call via verify=False when constructing the
# TimesketchApi client below (urllib3's InsecureRequestWarning is what that
# produces) -- NOT by weakening the process-wide default SSL context, which
# would silently strip certificate validation from every other unrelated
# urllib-based HTTPS call in this backend process (upgrade package downloads,
# CVE feed refresh, DFIQ ZIP download, etc).
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _connect_timesketch_api(timesketch_config, logger=None):
    """Connect to Timesketch API.

    Args:
        timesketch_config: Configuration dict with host, username, password
        logger: Optional callback function(message, level) to log progress

    Returns:
        TimesketchApi client or None if connection failed
    """
    from timesketch_api_client import client as ts_client

    def log(message, level="info"):
        print(f"[TIMESKETCH] {message}", flush=True)
        if logger:
            try:
                logger(f"[TIMESKETCH] {message}", level)
            except:
                pass

    try:
        ts_host = timesketch_config.get('host', 'https://localhost')
        ts_username = timesketch_config.get('username', 'admin')
        ts_password = timesketch_config.get('password', 'admin')

        log("Connecting to Timesketch API...")

        api = ts_client.TimesketchApi(
            host_uri=ts_host,
            username=ts_username,
            password=ts_password,
            verify=False  # Disable SSL certificate verification for self-signed certs
        )

        # Verify auth works with a real authenticated probe — the
        # constructor only sets up an HTTP session and DOES NOT validate
        # credentials. Without this, the first downstream call (e.g.
        # list_sketches in import_to_timesketch) silently 302s to
        # /login/, gets back HTML, and fails 5+ minutes into the
        # pipeline as a cryptic JSON-decode error. Catch the auth
        # failure here so the operator gets a clear, actionable message
        # before any pipeline work runs.
        try:
            # Cheapest authenticated GET — list one sketch.
            _ = list(api.list_sketches())
        except Exception as auth_err:
            log(
                "✗ TimeSketch API session created but credentials were rejected. "
                f"User '{ts_username}' at {ts_host} cannot authenticate.",
                "error",
            )
            log(
                "  Check that TIMESKETCH_USER / TIMESKETCH_PASS on intact_backend match "
                "a real user in the TimeSketch DB. Verify with:",
                "error",
            )
            log(
                "  docker exec intact_timesketch_postgres psql -U timesketch -d timesketch "
                "-c 'SELECT id, username, active FROM \"user\";'",
                "error",
            )
            log(f"  Underlying error: {auth_err}", "error")
            log(traceback.format_exc(), "error")
            return None

        log("✓ Timesketch API connected (auth verified)", "success")
        return api

    except Exception as e:
        log(f"✗ Failed to connect to Timesketch API: {e}", "error")
        log(traceback.format_exc(), "error")
        return None


def _upload_plaso_direct(api, sketch, plaso_file_path, timeline_name, logger=None):
    """Upload .plaso file directly to Timesketch using the import API.

    Timesketch's Celery workers will handle the psort processing internally,
    which properly processes ALL parsers (not just filestat).

    Args:
        api: Connected TimesketchApi client
        sketch: Timesketch sketch object
        plaso_file_path: Path to the .plaso file
        timeline_name: Name for the timeline
        logger: Optional callback function(message, level) to log progress

    Returns:
        dict with 'timeline_id', 'celery_task_id', 'index_name' or None on failure
    """
    from timesketch_import_client import importer as ts_importer
    from datetime import datetime

    def log(message, level="info"):
        print(f"[TIMESKETCH] {message}", flush=True)
        if logger:
            try:
                logger(f"[TIMESKETCH] {message}", level)
            except:
                pass

    log(f"Starting direct .plaso upload to Timesketch")
    log(f"Plaso file: {plaso_file_path}")
    log(f"Timeline name: {timeline_name}")
    log(f"Sketch ID: {sketch.id}")

    # Verify file exists and get size
    if not os.path.exists(plaso_file_path):
        log(f"✗ .plaso file not found: {plaso_file_path}", "error")
        return None

    plaso_size = os.path.getsize(plaso_file_path)
    log(f"Plaso file size: {plaso_size / (1024*1024):.2f} MB")

    try:
        # Create importer streamer for direct .plaso upload.
        # Synthetic "command" log line for forensic reproducibility —
        # the importer is a Python SDK call rather than a subprocess,
        # so we document the equivalent operation in the same `$`-prefixed
        # style as the log2timeline / pinfo command lines logged earlier
        # in the pipeline.
        log(f"$ timesketch_import_client.ImportStreamer().add_file("
            f"'{plaso_file_path}') → sketch_id={sketch.id} "
            f"timeline_name='{timeline_name}' data_label='plaso' "
            f"size={plaso_size / (1024*1024):.2f} MB")
        with ts_importer.ImportStreamer() as streamer:
            streamer.set_sketch(sketch)
            streamer.set_timeline_name(timeline_name)
            streamer.set_data_label('plaso')  # CRITICAL: Tells Timesketch this is a plaso file
            streamer.set_upload_context(f'Uploaded via Intact.AI automation at {datetime.now().isoformat()}')

            log("Uploading .plaso file (this transfers the file to Timesketch)...")
            streamer.add_file(plaso_file_path)

            # Get the results before context manager closes
            timeline_id = getattr(streamer, '_timeline_id', None)
            celery_task_id = getattr(streamer, 'celery_task_id', None)
            index_name = getattr(streamer, '_index', None)

        if not timeline_id:
            # add_file() can return without raising even when Timesketch never
            # actually registered a timeline (e.g. a rejected/empty upload) —
            # the caller's `if not upload_result:` check can't catch this
            # because a dict with all-None values is still truthy. Surface it
            # as a real failure instead of reporting a phantom success.
            log("✗ Upload did not produce a timeline_id — treating as failed", "error")
            return None

        log(f"✓ Upload complete!")
        log(f"Timeline ID: {timeline_id}")
        log(f"Celery Task ID: {celery_task_id}")
        log(f"Index Name: {index_name}")

        return {
            'timeline_id': timeline_id,
            'celery_task_id': celery_task_id,
            'index_name': index_name
        }

    except Exception as e:
        log(f"✗ Upload failed: {e}", "error")
        log(traceback.format_exc(), "error")
        return None


def _wait_for_timeline_ready(api, sketch_id, timeline_name, timeout_seconds=10000, poll_interval=30, logger=None, timesketch_config=None, cancel_event=None, api_holder=None):
    """Wait for timeline processing to complete with progress updates.

    Args:
        api: Connected TimesketchApi client
        sketch_id: Sketch ID containing the timeline
        timeline_name: Timeline name to monitor
        timeout_seconds: Maximum wait time (default ~2.8 hours)
        poll_interval: Seconds between status checks
        logger: Optional callback function(message, level) to log progress
        timesketch_config: Optional config dict (host/username/password) used
            to mint a fresh client if the existing session expires mid-poll.
            Without this, the polling loop will loop forever on a dead cookie
            until the timeout fires.
        cancel_event: Optional threading.Event from workflow_service. When
            set (user clicked Stop), the loop exits within one poll interval
            with status='cancelled' instead of continuing to poll for hours.
        api_holder: Optional single-element list; kept in sync with whichever
            `api` client is CURRENTLY live (updated on every re-auth swap) so
            the caller can close the right session afterward. Without this,
            a caller holding its own original `api` reference closes a
            session that was already replaced (and whose replacement is then
            never closed at all) whenever this function re-authenticates
            mid-wait.

    Returns:
        tuple (success: bool, final_status: str, timeline_id: int or None)
    """
    if api_holder is not None:
        api_holder[0] = api
    def log(message, level="info"):
        print(f"[TIMESKETCH] {message}", flush=True)
        if logger:
            try:
                logger(f"[TIMESKETCH] {message}", level)
            except:
                pass

    start_time = time.time()
    sketch = api.get_sketch(sketch_id)
    consecutive_errors = 0

    log(f"Waiting for timeline '{timeline_name}' to be ready...")
    log(f"Timeout: {timeout_seconds}s, Poll interval: {poll_interval}s")

    def _wait_or_cancel():
        """Sleep poll_interval, but exit immediately if Stop is clicked.

        Returns True if cancellation was requested (caller should abort).
        """
        if cancel_event is not None:
            return cancel_event.wait(poll_interval)
        time.sleep(poll_interval)
        return False

    while True:
        elapsed = int(time.time() - start_time)

        # User-initiated stop: exit promptly without waiting on TS.
        if cancel_event is not None and cancel_event.is_set():
            log("Stop requested by user — abandoning indexing wait", "warning")
            return (False, "cancelled", None)

        # Check timeout
        if elapsed > timeout_seconds:
            log(f"✗ Timeout waiting for timeline after {elapsed}s", "error")
            return (False, "timeout", None)

        # Get all timelines and find ours by name
        try:
            timelines = sketch.list_timelines()
            consecutive_errors = 0  # any successful call resets the counter
            timeline = None
            for tl in timelines:
                if tl.name == timeline_name:
                    timeline = tl
                    break

            if not timeline:
                log(f"Timeline '{timeline_name}' not yet visible, waiting... (elapsed: {elapsed}s)")
                if _wait_or_cancel():
                    log("Stop requested by user — abandoning indexing wait", "warning")
                    return (False, "cancelled", None)
                continue

            status = timeline.status
            log(f"Timeline status: {status} (elapsed: {elapsed}s)")

            if status == "ready":
                log(f"✓ Timeline '{timeline_name}' is ready!", "success")
                return (True, status, timeline.id)
            elif status == "fail":
                log(f"✗ Timeline '{timeline_name}' processing failed", "error")
                return (False, status, timeline.id)
            elif status in ["processing", "pending"]:
                if _wait_or_cancel():
                    log("Stop requested by user — abandoning indexing wait", "warning")
                    return (False, "cancelled", None)
            else:
                log(f"⚠ Unknown status: {status}, continuing to wait...", "warning")
                if _wait_or_cancel():
                    log("Stop requested by user — abandoning indexing wait", "warning")
                    return (False, "cancelled", None)

        except Exception as e:
            consecutive_errors += 1
            err = str(e).lower()
            # Heuristic: anything that smells like the session-expired symptom
            # gets a re-auth attempt. Cheap, idempotent — over-trigger is fine.
            looks_auth_expired = (
                "json" in err or "decode" in err or "login" in err
                or "401" in err or "unauthorized" in err
                or consecutive_errors >= 2
            )
            if looks_auth_expired and timesketch_config:
                log("Session likely expired — re-authenticating to TimeSketch...", "warning")
                new_api = _connect_timesketch_api(timesketch_config, logger=logger)
                if new_api:
                    old_api = api
                    api = new_api
                    if api_holder is not None:
                        api_holder[0] = api
                    # The stale session's HTTP connection was never closed
                    # here before — it was just dropped and left for GC,
                    # leaking one open session/connection per re-auth on any
                    # import that crosses a session-lifetime boundary.
                    try:
                        old_api.session.close()
                    except Exception:
                        pass
                    try:
                        sketch = api.get_sketch(sketch_id)  # rebind to new session
                        consecutive_errors = 0
                        log("✓ Re-authenticated successfully", "success")
                    except Exception as rebind_err:
                        log(f"Sketch rebind after re-auth failed: {rebind_err}", "warning")
                else:
                    log("Re-auth attempt failed; will retry next cycle", "warning")
            log(f"⚠ Error checking timeline status: {e}, retrying...", "warning")
            if _wait_or_cancel():
                log("Stop requested by user — abandoning indexing wait", "warning")
                return (False, "cancelled", None)

    return (False, "unknown", None)


def wait_for_analyzers(sketch_id, timesketch_config, *, timeout_seconds=1800,
                       poll_interval=20, logger=None, cancel_event=None):
    """Block until every analyzer session on the sketch settles (DONE/ERROR).

    WHY THIS EXISTS. Timesketch fires AUTO_SKETCH_ANALYZERS in its own Celery
    workers AFTER a timeline is imported, but the workflow used to flip
    `completed` the moment the import finished. `timesketch` is in
    AGENTIC_TYPES, so that terminal status arms the case's debounced auto-fuse
    60s later — which then queried `_exists_:tag` against a sketch whose 75
    analyzer tasks were all still PENDING (measured live, 2026-08-27: the
    count was 0 while 3,542 tags were on their way). Nothing ever re-armed
    when the tags landed, so TimeSketch contributed nothing to the case,
    forever. Completing the run only after the analyzers settle is what makes
    the auto-fuse read a TAGGED sketch.

    Bounded and non-fatal by design: on timeout or error the caller should log
    a warning and complete anyway — an analyst's starred events still fuse,
    and a later Refusion picks up late tags. Returns
    (settled: bool, summary: dict[name -> {status: count}]).

    The 5 ERROR sessions on the first real run (account_finder, evtx_gap,
    domain, feature_extraction) are why the per-analyzer summary is returned
    rather than a bare bool: analyzers DO fail on real timelines and the run
    log must say which.
    """
    def log(message, level="info"):
        print(f"[TIMESKETCH] {message}", flush=True)
        if logger:
            try:
                logger(f"[TIMESKETCH] {message}", level)
            except Exception:
                pass

    _TERMINAL = {"DONE", "ERROR"}
    try:
        sid = int(sketch_id)
    except (TypeError, ValueError):
        return False, {}

    api = _connect_timesketch_api(timesketch_config, logger)
    if not api:
        return False, {}
    start = time.time()
    consecutive_errors = 0
    try:
        sketch = api.get_sketch(sid)
        log(f"Waiting for analyzers on sketch {sid} (timeout {timeout_seconds}s)…")
        while time.time() - start < timeout_seconds:
            try:
                sessions = sketch.get_analyzer_status() or []
                consecutive_errors = 0
                pending = [x for x in sessions
                           if str(x.get("status") or "").upper() not in _TERMINAL]
                if sessions and not pending:
                    summary = {}
                    for x in sessions:
                        name = str(x.get("name") or "?")
                        st = str(x.get("status") or "?").upper()
                        summary.setdefault(name, {})
                        summary[name][st] = summary[name].get(st, 0) + 1
                    return True, summary
                if not sessions:
                    # Analyzer sessions are created by TS shortly after the
                    # timeline flips ready; an empty list this early means
                    # they have not been registered yet — keep waiting, but
                    # only briefly: past 2 minutes an empty list means auto
                    # analyzers are disabled server-side, and waiting the
                    # full timeout for work that was never scheduled would
                    # stall every import on a deliberately-lean install.
                    if time.time() - start > 120:
                        log("No analyzer sessions appeared after 2 minutes — "
                            "AUTO_SKETCH_ANALYZERS may be disabled; continuing.",
                            "warning")
                        return True, {}
                else:
                    log(f"Analyzers: {len(sessions) - len(pending)}/{len(sessions)} settled…")
            except Exception as e:
                consecutive_errors += 1
                err = str(e).lower()
                if (("json" in err or "decode" in err or "login" in err
                     or "401" in err or "unauthorized" in err
                     or consecutive_errors >= 2) and timesketch_config):
                    log("Session likely expired — re-authenticating to TimeSketch...",
                        "warning")
                    new_api = _connect_timesketch_api(timesketch_config, logger=logger)
                    if new_api:
                        old_api = api
                        api = new_api
                        try:
                            old_api.session.close()
                        except Exception:
                            pass
                        try:
                            sketch = api.get_sketch(sid)
                            consecutive_errors = 0
                        except Exception as rebind_err:
                            log(f"Sketch rebind after re-auth failed: {rebind_err}",
                                "warning")
                else:
                    log(f"Analyzer status check failed: {e}, retrying…", "warning")
            if cancel_event is not None:
                if cancel_event.wait(poll_interval):
                    log("Stop requested — abandoning analyzer wait", "warning")
                    return False, {}
            else:
                time.sleep(poll_interval)
        log(f"Analyzers still running after {timeout_seconds}s — continuing "
            f"without them (a later Refusion picks up their tags).", "warning")
        return False, {}
    finally:
        try:
            api.session.close()
        except Exception:
            pass


def find_sketch_by_name(sketch_name, timesketch_config, logger=None):
    """Find an existing sketch by name

    Args:
        sketch_name: Name to search for
        timesketch_config: Configuration dict with host, username, password
        logger: Optional callback function(message, level) to log progress

    Returns:
        sketch_id if found, None otherwise
    """
    def log(message, level="info"):
        print(f"[TIMESKETCH] {message}", flush=True)
        if logger:
            try:
                logger(f"[TIMESKETCH] {message}", level)
            except:
                pass

    try:
        api = _connect_timesketch_api(timesketch_config, logger)
        if not api:
            return None

        sketches = api.list_sketches()
        for s in sketches:
            if s.name == sketch_name:
                log(f"Found existing sketch '{sketch_name}' with ID: {s.id}")
                try:
                    api.session.close()
                except:
                    pass
                return s.id

        try:
            api.session.close()
        except:
            pass

        return None

    except Exception as e:
        log(f"Error searching for sketch: {e}", "warning")
        return None


def _ts_window_clause(window):
    """OpenSearch `datetime:[a TO b]` clause for a case time window, or "".

    Mirrors fusion's in_window open semantics (correlate.py): no window, a
    half-set window's missing side, and a degenerate start >= end all widen to
    open rather than excluding everything. Values are used as-is — the case
    stores ISO-8601 strings, which OpenSearch range queries accept."""
    w = window or {}
    start = str(w.get("start") or "").strip()
    end = str(w.get("end") or "").strip()
    if not start and not end:
        return ""
    if start and end and start >= end:
        return ""                        # degenerate — treat as open
    return f"datetime:[{start or '*'} TO {end or '*'}]"


def fetch_sketch_events(sketch_id, timesketch_config, *, limit=2000, window=None,
                        logger=None):
    """Pull the analyst-relevant events from a sketch — those an analyzer TAGGED
    (SIGMA / threat-intel hits) or an analyst STARRED/commented — so the fusion
    layer can ingest TimeSketch findings.

    TimeSketch keeps the timeline on its own server (inside the sketch), not in the
    workflow run row, so fusion has nothing to map from the run alone. This fetches
    the distilled subset on demand. NEVER the whole (potentially millions-row)
    timeline — only tagged/starred events, and when the case has a time window,
    only ANALYZER tags inside it: OpenSearch cuts out-of-window events server-side
    before anything is serialized. Starred/commented events are DELIBERATELY
    exempt from the window — a human judgment outranks the filter, and the events
    most worth starring (e.g. timestomped files, whose timestamps are absurd by
    construction; the live index's minimum is 1970) are exactly the ones a window
    would cut.

    Each returned dict is the hit's `_source` plus `_ts_id` (the OpenSearch doc
    id) when present, so evidence locators can address the original event
    stably instead of an index into a distilled list. Best-effort: returns []
    on any failure (TS unreachable, bad creds, empty sketch) so the fuse never
    breaks because TimeSketch is down.

    `max_entries` is best-effort in the API client (it pages 10k at a time), so
    the result is ALSO truncated client-side to `limit`."""
    def log(message, level="info"):
        print(f"[TIMESKETCH] {message}", flush=True)
        if logger:
            try:
                logger(f"[TIMESKETCH] {message}", level)
            except Exception:
                pass
    try:
        sid = int(sketch_id)
    except (TypeError, ValueError):
        return []
    api = None
    try:
        api = _connect_timesketch_api(timesketch_config, logger)
        if not api:
            return []
        sketch = api.get_sketch(sid)
        clause = _ts_window_clause(window)
        if clause:
            query = (f"(_exists_:tag AND {clause}) "
                     f"OR label:__ts_star OR label:__ts_comment")
        else:
            query = "_exists_:tag OR label:__ts_star OR label:__ts_comment"
        res = sketch.explore(query_string=query, as_pandas=False, max_entries=limit)
        objs = res.get("objects") if isinstance(res, dict) else (res or [])
        events = []
        for o in (objs or []):
            src = o.get("_source") if isinstance(o, dict) else None
            if isinstance(src, dict):
                if isinstance(o.get("_id"), (str, int)):
                    src["_ts_id"] = str(o["_id"])
                events.append(src)
                if len(events) >= limit:
                    break                # client-side backstop for the 10k paging
        log(f"fusion: pulled {len(events)} analyst-relevant event(s) from "
            f"sketch {sid}" + (f" (window {clause})" if clause else ""))
        return events
    except Exception as e:
        log(f"fusion: could not fetch events from sketch {sid}: {e}", "warning")
        return []
    finally:
        if api is not None:
            try:
                api.session.close()
            except Exception:
                pass


def import_to_timesketch(plaso_file, sketch_name, timeline_name, timesketch_config, logger=None, sketch_id=None, wait_timeout=10000, run_id=None):
    """Import Plaso file to Timesketch using direct Python API.

    Uses ImportStreamer with data_label='plaso' which properly triggers
    Timesketch's Celery workers to process all parsers (not just filestat).

    Args:
        plaso_file: Path to the .plaso file
        sketch_name: Name for the Timesketch sketch (used when creating new sketch or searching for existing)
        timeline_name: Name for the timeline
        timesketch_config: Configuration dict with host, username, password
        logger: Optional callback function(message, level) to log progress
        sketch_id: Optional existing sketch ID to add timeline to (if not provided, will search by name first)
        wait_timeout: Timeout in seconds to wait for timeline processing (default ~2.8 hours)
        run_id: Optional workflow run_id. When provided, the indexing-wait
            polling loop respects the workflow Stop button — clicking Stop
            mid-wait returns within one poll interval (instead of blocking
            up to wait_timeout, which can be 3 days).

    Returns:
        dict with sketch_id, timeline_id, sketch_name, timeline_name or None on failure
    """
    def log(message, level="info"):
        """Log to both stdout and optional callback"""
        print(f"[TIMESKETCH] {message}", flush=True)
        if logger:
            try:
                logger(f"[TIMESKETCH] {message}", level)
            except Exception as e:
                print(f"[TIMESKETCH] Logger error: {e}", flush=True)

    sys.stdout.flush()
    log("=" * 60)
    log("Starting Timesketch import (Python API)")
    log(f"Sketch Name: {sketch_name}")
    log(f"Timeline: {timeline_name}")
    log("=" * 60)

    try:
        # Step 1: Validate Plaso file
        log("Step 1/5: Validating Plaso file...")
        if not os.path.exists(plaso_file):
            log(f"✗ Plaso file not found: {plaso_file}", "error")
            return None

        size_mb = os.path.getsize(plaso_file) / (1024 * 1024)
        log(f"✓ Plaso file found ({size_mb:.2f} MB)")

        # Step 2: Connect to Timesketch API
        log("Step 2/5: Connecting to Timesketch API...")
        api = _connect_timesketch_api(timesketch_config, logger)
        if not api:
            log("✗ Failed to connect to Timesketch API", "error")
            return None

        # Step 3: Get or create sketch
        log("Step 3/5: Getting or creating sketch...")

        sketch = None

        # If no sketch_id provided, search for existing sketch with same name
        if not sketch_id:
            log("Checking for existing sketch with same name...")
            sketches = api.list_sketches()
            for s in sketches:
                if s.name == sketch_name:
                    sketch_id = s.id
                    sketch = s
                    log(f"Found existing sketch '{sketch_name}' with ID: {sketch_id}")
                    break

        if sketch_id and not sketch:
            # Get the sketch by ID
            sketch = api.get_sketch(sketch_id)
            log(f"Using existing sketch with ID: {sketch_id}")

        if not sketch:
            # Create new sketch
            log(f"Creating new sketch: {sketch_name}")
            sketch = api.create_sketch(sketch_name)
            sketch_id = sketch.id
            log(f"✓ Created new sketch with ID: {sketch_id}")

        log("=" * 40)

        # Step 4: Upload .plaso file directly using ImportStreamer
        log("Step 4/5: Uploading .plaso file to Timesketch...")
        log("(Timesketch workers will handle psort processing internally)")

        upload_start_time = time.time()

        upload_result = _upload_plaso_direct(
            api=api,
            sketch=sketch,
            plaso_file_path=plaso_file,
            timeline_name=timeline_name,
            logger=logger
        )

        if not upload_result:
            log("✗ Failed to upload .plaso file", "error")
            try:
                api.session.close()
            except:
                pass
            return None

        upload_duration = int(time.time() - upload_start_time)
        log(f"Upload completed in {upload_duration}s")

        # Step 5: Wait for Timesketch workers to process the .plaso file
        log("Step 5/5: Waiting for Timesketch to process the .plaso file...")

        # Resolve cancel event from run_id so the indexing-wait polling
        # loop respects the workflow Stop button. None on legacy callers
        # that don't pass run_id — wait then behaves as before.
        cancel_event = get_cancel_event(run_id) if run_id else None

        # api_holder tracks whichever client is CURRENTLY live inside the wait
        # loop (it may re-auth and swap sessions mid-wait) — closing our own
        # stale `api` reference afterward would leak the actual live session.
        api_holder = [api]
        success, final_status, timeline_id = _wait_for_timeline_ready(
            api=api,
            sketch_id=sketch_id,
            timeline_name=timeline_name,
            timeout_seconds=wait_timeout,
            poll_interval=30,
            logger=logger,
            # Pass config so the polling loop can re-mint the session if the
            # current cookie expires (e.g. on uploads that cross the 1-week
            # PERMANENT_SESSION_LIFETIME).
            timesketch_config=timesketch_config,
            cancel_event=cancel_event,
            api_holder=api_holder,
        )
        api = api_holder[0]

        if not success:
            log(f"✗ Timeline processing failed with status: {final_status}", "error")
            try:
                api.session.close()
            except:
                pass
            return None

        log("=" * 40)
        log("✓ Import completed successfully!", "success")
        log(f"Sketch ID: {sketch_id}", "success")
        log(f"Timeline ID: {timeline_id}", "success")

        # Analyzers run automatically via AUTO_SKETCH_ANALYZERS config
        log("✓ Analyzers will run automatically via Timesketch config", "info")

        # Close API session
        try:
            api.session.close()
        except:
            pass

        return {
            'sketch_id': sketch_id,
            'timeline_id': timeline_id,
            'sketch_name': sketch_name,
            'timeline_name': timeline_name
        }

    except Exception as e:
        error_detail = traceback.format_exc()
        log(f"✗ Exception: {e}", "error")
        log(f"Stack trace: {error_detail}", "error")
        traceback.print_exc()
        return None

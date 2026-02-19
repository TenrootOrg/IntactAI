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
import ssl
import warnings

# Disable SSL warnings for self-signed certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Modify SSL context for self-signed certs
ssl._create_default_https_context = ssl._create_unverified_context


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

        log("✓ Timesketch API connected", "success")
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
        # Create importer streamer for direct .plaso upload
        with ts_importer.ImportStreamer() as streamer:
            streamer.set_sketch(sketch)
            streamer.set_timeline_name(timeline_name)
            streamer.set_data_label('plaso')  # CRITICAL: Tells Timesketch this is a plaso file
            streamer.set_upload_context(f'Uploaded via MSSP automation at {datetime.now().isoformat()}')

            log("Uploading .plaso file (this transfers the file to Timesketch)...")
            streamer.add_file(plaso_file_path)

            # Get the results before context manager closes
            timeline_id = getattr(streamer, '_timeline_id', None)
            celery_task_id = getattr(streamer, 'celery_task_id', None)
            index_name = getattr(streamer, '_index', None)

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


def _wait_for_timeline_ready(api, sketch_id, timeline_name, timeout_seconds=10000, poll_interval=30, logger=None):
    """Wait for timeline processing to complete with progress updates.

    Args:
        api: Connected TimesketchApi client
        sketch_id: Sketch ID containing the timeline
        timeline_name: Timeline name to monitor
        timeout_seconds: Maximum wait time (default ~2.8 hours)
        poll_interval: Seconds between status checks
        logger: Optional callback function(message, level) to log progress

    Returns:
        tuple (success: bool, final_status: str, timeline_id: int or None)
    """
    def log(message, level="info"):
        print(f"[TIMESKETCH] {message}", flush=True)
        if logger:
            try:
                logger(f"[TIMESKETCH] {message}", level)
            except:
                pass

    start_time = time.time()
    sketch = api.get_sketch(sketch_id)

    log(f"Waiting for timeline '{timeline_name}' to be ready...")
    log(f"Timeout: {timeout_seconds}s, Poll interval: {poll_interval}s")

    while True:
        elapsed = int(time.time() - start_time)

        # Check timeout
        if elapsed > timeout_seconds:
            log(f"✗ Timeout waiting for timeline after {elapsed}s", "error")
            return (False, "timeout", None)

        # Get all timelines and find ours by name
        try:
            timelines = sketch.list_timelines()
            timeline = None
            for tl in timelines:
                if tl.name == timeline_name:
                    timeline = tl
                    break

            if not timeline:
                log(f"Timeline '{timeline_name}' not yet visible, waiting... (elapsed: {elapsed}s)")
                time.sleep(poll_interval)
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
                time.sleep(poll_interval)
            else:
                log(f"⚠ Unknown status: {status}, continuing to wait...", "warning")
                time.sleep(poll_interval)

        except Exception as e:
            log(f"⚠ Error checking timeline status: {e}, retrying...", "warning")
            time.sleep(poll_interval)

    return (False, "unknown", None)


def run_all_analyzers(sketch_id, timeline_id, timesketch_config, logger=None):
    """Run all available analyzers on a timeline via Timesketch API

    Args:
        sketch_id: Timesketch sketch ID
        timeline_id: Timesketch timeline ID
        timesketch_config: Configuration dict with host, username, password
        logger: Optional callback function(message, level) to log progress

    Returns:
        True if analyzers started successfully, False otherwise
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
            return False

        log("Running all analyzers on timeline...")

        sketch = api.get_sketch(sketch_id)

        # Get all available analyzers
        analyzers = sketch.list_available_analyzers()
        analyzer_names = [a.get("name") for a in analyzers if a.get("name")]

        if not analyzer_names:
            log("⚠ No analyzers available", "warning")
            return False

        log(f"Found {len(analyzer_names)} analyzers: {', '.join(analyzer_names[:5])}...")

        # Run each analyzer on the timeline
        started_count = 0
        for analyzer_name in analyzer_names:
            try:
                result = sketch.run_analyzer(
                    analyzer_name=analyzer_name,
                    timeline_id=timeline_id
                )
                if result:
                    started_count += 1
            except Exception as e:
                log(f"⚠ Analyzer {analyzer_name} failed: {e}", "warning")

        log(f"✓ Started {started_count} analyzer sessions", "success")

        # Close the API session
        try:
            api.session.close()
        except:
            pass

        return True

    except Exception as e:
        log(f"⚠ Error running analyzers: {e}", "warning")
        return False


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


def import_to_timesketch(plaso_file, sketch_name, timeline_name, timesketch_config, logger=None, sketch_id=None, wait_timeout=10000):
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

        success, final_status, timeline_id = _wait_for_timeline_ready(
            api=api,
            sketch_id=sketch_id,
            timeline_name=timeline_name,
            timeout_seconds=wait_timeout,
            poll_interval=30,
            logger=logger
        )

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

        # Run analyzers
        log("Running analyzers on the new timeline...")
        if sketch_id and timeline_id:
            run_all_analyzers(sketch_id, timeline_id, timesketch_config, logger)
        else:
            log(f"⚠ Could not run analyzers - sketch_id={sketch_id}, timeline_id={timeline_id}", "warning")

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

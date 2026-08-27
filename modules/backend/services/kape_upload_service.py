#!/usr/bin/env python3
"""
KAPE Upload Service - Process uploaded KAPE/Velociraptor collections

Handles:
1. Format detection (Velociraptor collection vs raw KAPE output)
2. ZIP extraction and zlib decompression (for Velociraptor format)
3. Plaso processing
4. Timesketch import
"""

import os
import re
import zipfile
import json
import shutil
import shlex
import tempfile
import subprocess
import traceback
from datetime import datetime

from services.workflow_service import (
    create_automation_run,
    add_log_to_run,
    update_run_status,
    register_cleanup,
    get_cancel_event,
    terminate_subprocess,
)
from services.plaso_service import run_pinfo
from services.timesketch_service import import_to_timesketch
from config import PLASO_OUTPUT_DIR, get_plaso_image, PLASO_CPUS, PLASO_MEMORY, TIMESKETCH_CONFIG


def detect_kape_format(zip_path):
    """Detect if ZIP is Velociraptor collection or raw KAPE output

    Args:
        zip_path: Path to the ZIP file

    Returns:
        'velociraptor' | 'kape' | 'unknown'
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            names = zf.namelist()

            # Velociraptor format: has client_info.json and uploads/ folder
            has_client_info = 'client_info.json' in names
            has_uploads = any('uploads/' in n for n in names)

            if has_client_info or has_uploads:
                return 'velociraptor'

            # Raw KAPE format: has C/ folder structure
            has_c_drive = any(n.startswith('C/') or n.startswith('C\\') for n in names)

            if has_c_drive:
                return 'kape'

            return 'unknown'

    except Exception as e:
        print(f"[KAPE] Error detecting format: {e}", flush=True)
        return 'unknown'


def extract_client_info(zip_path, format_type, original_filename=None):
    """Extract client hostname from ZIP

    Args:
        zip_path: Path to the ZIP file
        format_type: 'velociraptor' or 'kape'
        original_filename: Original filename (used for fallback when zip_path is a hash)

    Returns:
        hostname string
    """
    try:
        if format_type == 'velociraptor':
            with zipfile.ZipFile(zip_path, 'r') as zf:
                if 'client_info.json' in zf.namelist():
                    with zf.open('client_info.json') as f:
                        info = json.load(f)
                        hostname = info.get('os_info', {}).get('hostname')
                        if hostname:
                            return hostname

        # Fallback: extract from filename
        # Use original_filename if provided (tus uploads have hash-based paths)
        filename = original_filename if original_filename else os.path.basename(zip_path)

        # Pattern 1: KAPE format - HOSTNAME-C.hash.zip (hostname is before first ".")
        # Example: EFL-LAB-UDI-C.196ab348237f9ea9-F.D6KLUMSNCU2R6.zip -> EFL-LAB-UDI-C
        if '.' in filename:
            hostname = filename.split('.')[0]
            # Remove trailing -C if present (KAPE adds this for C: drive)
            if hostname.endswith('-C'):
                hostname = hostname[:-2]
            if hostname and len(hostname) > 2:
                return hostname

        # Pattern 2: Collection-HOSTNAME-timestamp.zip (Velociraptor format)
        if 'Collection-' in filename:
            start = filename.find('Collection-') + len('Collection-')
            end = filename.find('-', start)
            if end > start:
                return filename[start:end]

        # Pattern 3: Just use the filename without extension as fallback
        name_without_ext = filename.replace('.zip', '').replace('.ZIP', '')
        if name_without_ext and len(name_without_ext) > 2:
            return name_without_ext

        return 'UnknownClient'

    except Exception as e:
        print(f"[KAPE] Error extracting client info: {e}", flush=True)
        return 'UnknownClient'


def decompress_velociraptor_uploads(uploads_dir, dest_dir, logger=None):
    """Decompress Velociraptor's zlib-compressed files

    Args:
        uploads_dir: Path to the uploads/ folder from Velociraptor ZIP
        dest_dir: Destination directory for decompressed files
        logger: Optional logger callback

    Returns:
        tuple (success, file_count, error_count)
    """
    import zlib
    import urllib.parse

    def log(msg, level="info"):
        print(f"[DECOMPRESS] {msg}", flush=True)
        if logger:
            try:
                logger(msg, level)
            except:
                pass

    log("Decompressing Velociraptor collection...")

    file_count = 0
    error_count = 0
    skipped_count = 0

    # Skip metadata files
    skip_extensions = {'.chunk', '.idx'}

    for root, dirs, files in os.walk(uploads_dir):
        for filename in files:
            # Skip metadata files
            if any(filename.endswith(ext) for ext in skip_extensions):
                skipped_count += 1
                continue

            src_path = os.path.join(root, filename)
            rel_path = os.path.relpath(src_path, uploads_dir)

            # URL-decode the path components
            decoded_parts = []
            for part in rel_path.split(os.sep):
                decoded_parts.append(urllib.parse.unquote(part))
            decoded_rel_path = os.sep.join(decoded_parts)

            dest_path = os.path.join(dest_dir, decoded_rel_path)

            # Create destination directory
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            try:
                with open(src_path, 'rb') as f:
                    data = f.read()

                # Try to decompress (files are zlib compressed)
                try:
                    decompressed = zlib.decompress(data)
                    with open(dest_path, 'wb') as f:
                        f.write(decompressed)
                    file_count += 1
                except zlib.error:
                    # Not compressed, copy as-is
                    with open(dest_path, 'wb') as f:
                        f.write(data)
                    file_count += 1

            except Exception as e:
                error_count += 1
                log(f"Error decompressing {filename}: {e}", "warning")

    log(f"Decompressed {file_count} files ({skipped_count} metadata skipped, {error_count} errors)")

    return (file_count > 0, file_count, error_count)


def process_local_with_plaso(source_dir, client_name, logger=None, parser=None, workers=2, hasher=None, hasher_file_size_mb=None, run_id=None):
    """Process local directory with Plaso (for uploaded files)

    Unlike process_with_plaso() in plaso_service.py, this:
    - Takes a local source directory (not Velociraptor volumes)
    - Mounts the local directory directly into Plaso container

    Args:
        source_dir: Path to the extracted/decompressed files
        client_name: Client hostname for output file naming
        logger: Optional logger callback
        parser: Plaso parser preset (win7, winevtx, etc.)
        workers: Number of parallel workers
        hasher: Hash algorithm (md5, sha1, sha256, all)
        hasher_file_size_mb: Max file size to hash in MB

    Returns:
        Path to .plaso file or None on failure
    """
    def log(msg, level="info"):
        print(f"[PLASO] {msg}", flush=True)
        if logger:
            try:
                logger(msg, level)
            except:
                pass

    log("Starting Plaso processing...")
    log(f"Source directory: {source_dir}")
    log(f"Client name: {client_name}")

    try:
        # Setup paths
        os.makedirs(PLASO_OUTPUT_DIR, exist_ok=True)
        plaso_file = f"{PLASO_OUTPUT_DIR}/{client_name}_Artifacts.plaso"

        # Remove only THIS client's previous .plaso output (Plaso refuses to
        # overwrite an existing storage file). DO NOT wipe the whole dir —
        # the multi-client Timesketch orchestrator stages other clients' ZIPs
        # here while they wait their turn in the Plaso queue; wiping the dir
        # deletes those queued ZIPs and breaks the next client's run.
        if os.path.isfile(plaso_file):
            try:
                os.remove(plaso_file)
            except Exception:
                pass

        # Build Plaso command
        num_workers = str(workers) if workers else PLASO_CPUS

        plaso_cmd = [
            'docker', 'run', '--rm',
            # PYTHONUNBUFFERED disables Python's stdout/stderr block buffering
            # inside the Plaso container. Without it, log2timeline.py's status
            # lines sit in a 4 KB pipe buffer until the buffer fills or the
            # process exits — operators see the "Processing started." line and
            # then a long silence followed by a burst at completion, instead
            # of real-time progress every status_view_interval seconds.
            '-e', 'PYTHONUNBUFFERED=1',
            '-v', f'{PLASO_OUTPUT_DIR}:/data',
            '-v', f'{source_dir}:/source:ro',
            '--cpus', PLASO_CPUS,
            '--memory', PLASO_MEMORY,
            '--user', 'root',
            get_plaso_image(),
            'log2timeline',
            '--workers', num_workers,
            # `linear` emits newline-terminated status lines instead of
            # ncurses-style in-place cursor redraws — `window` buffered
            # all the status output until a redraw burst, defeating
            # real-time log streaming. `linear` makes every status tick
            # a regular line that flows through `for line in process.stdout`.
            '--status_view', 'linear',
            '--status_view_interval', '10',
        ]

        # Add parser preset if specified
        if parser:
            plaso_cmd.extend(['--parsers', parser])
            log(f"Parser preset: {parser}")

        # Add hasher if specified
        if hasher:
            if hasher == 'all':
                plaso_cmd.extend(['--hashers', 'md5,sha1,sha256'])
            else:
                plaso_cmd.extend(['--hashers', hasher])

            if hasher_file_size_mb and hasher_file_size_mb > 0:
                size_bytes = hasher_file_size_mb * 1024 * 1024
                plaso_cmd.extend(['--hasher_file_size_limit', str(size_bytes)])

        # Add output file and source
        plaso_cmd.extend([
            '--storage-file', f'/data/{client_name}_Artifacts.plaso',
            '/source'
        ])

        log(f"Workers: {num_workers}")
        log("Running log2timeline...")
        # Log the literal command so the workflow log is reproducible —
        # an operator scrolling back can copy-paste this exact line into
        # their shell and reproduce the Plaso invocation.
        log(f"$ {shlex.join(plaso_cmd)}")

        # Run Plaso
        process = subprocess.Popen(
            plaso_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # Wire workflow Stop into the Plaso subprocess. The cleanup callback
        # fires when the user clicks Stop in the dashboard; terminate_subprocess
        # is idempotent so it's safe even if the process already exited.
        # The `--rm` flag on the docker run means the container vanishes once
        # the parent docker CLI is killed.
        cancel_event = get_cancel_event(run_id) if run_id else None
        if run_id:
            register_cleanup(run_id, lambda p=process: terminate_subprocess(p))

        # Stream output
        line_count = 0
        for line in process.stdout:
            # Bail fast if Stop was clicked. The cleanup callback above is
            # already terminating the subprocess; we just stop reading so
            # this loop exits and the caller returns to the workflow runner.
            if cancel_event and cancel_event.is_set():
                log("Stop requested by user — exiting log2timeline read loop", "warning")
                break
            line = line.strip()
            if line:
                line_count += 1
                print(f"[PLASO] {line}", flush=True)

                # Stream every Plaso stdout/stderr line to the workflow
                # log in real time — operators need full visibility for
                # forensic reproducibility, not just every-10th sampled
                # output. Level-detection so errors / warnings stand out
                # in the dashboard. 200-char cap is defensive — Plaso
                # doesn't emit longer lines in practice.
                if logger:
                    try:
                        logger(line[:200], _plaso_line_level(line))
                    except Exception:
                        pass

        return_code = process.wait()
        if cancel_event and cancel_event.is_set():
            log("log2timeline aborted by user", "warning")
            return None

        if return_code == 0:
            log("Plaso processing completed successfully", "success")
            if os.path.exists(plaso_file):
                size_mb = os.path.getsize(plaso_file) / (1024 * 1024)
                log(f"Output file: {plaso_file} ({size_mb:.2f} MB)")
                return plaso_file
            else:
                log("Output file not created", "error")
                return None
        else:
            log(f"Plaso failed with return code: {return_code}", "error")
            return None

    except Exception as e:
        log(f"Plaso error: {e}", "error")
        traceback.print_exc()
        return None


# Plaso status lines end with ", file: <path>" (or "file: <path>"); everything
# from there on is a filesystem path and must never influence the log level.
_PLASO_PATH_TAIL = re.compile(r",?\s*file:\s", re.IGNORECASE)
_PLASO_ERROR_WORD = re.compile(r"\berrors?\b", re.IGNORECASE)
_PLASO_WARNING_WORD = re.compile(r"\bwarnings?\b", re.IGNORECASE)


def _plaso_line_level(line):
    """Log level for one line of log2timeline output.

    This used to be `"error" if "error" in line.lower()` over the WHOLE line —
    and every plaso worker status line ends with the path it is currently
    parsing:

      Worker_01 (PID: 15) status: idle, event data produced: 0,
        file: .../OneDrive/.../images/lightTheme/SyncStatusError.svg

    A OneDrive icon called SyncStatusError.svg therefore logged at error level,
    which tripped workflow_service's "any error-level entry auto-fails the run"
    rule, which marked a perfect 4.16M-event import FAILED — and because
    `failed` is not a terminal SUCCESS status, the case auto-fuse never armed
    and the whole TimeSketch integration silently did not happen. A filename
    decided whether an hour of collection reached the case.

    So: classify on the message, never on the path, and match whole words —
    "error" inside "SyncStatusError" or "terror" is not a log level.
    """
    text = _PLASO_PATH_TAIL.split(line, 1)[0]
    if _PLASO_ERROR_WORD.search(text):
        return "error"
    if _PLASO_WARNING_WORD.search(text):
        return "warning"
    return "info"


def _wait_for_sketch_analyzers(run_id, sketch_id, settings, timeline_id=None):
    """Block until Timesketch's auto-analyzers settle, then report per analyzer.

    Non-fatal on every path: an analyzer that errors, a wait that times out, or
    TimeSketch being unreachable must never fail an import whose timeline is
    already in the sketch. Starred events still fuse, and a later Refusion
    picks up tags that arrive after we stop waiting.
    """
    if not sketch_id:
        return
    try:
        from services.timesketch_service import wait_for_analyzers
        from config import TIMESKETCH_CONFIG
        # NOT scheduled here. Timesketch's own auto-hook (AUTO_SKETCH_ANALYZERS)
        # does it, which also covers timelines an analyst uploads through the
        # Timesketch GUI rather than only the ones this appliance imports. That
        # hook used to schedule with timeline_id=None; analyzer_patches/apply.sh
        # fixes it at the source (INTACT-PATCH pass-timeline-id). Scheduling
        # here as well would simply run everything twice.
        # None -> the service's own default (INTACT_TS_ANALYZER_TIMEOUT).
        timeout = settings.get("timesketch_analyzer_timeout") or None
        if timeout:
            timeout = int(timeout)
        add_log_to_run(run_id, "Waiting for Timesketch analyzers to finish "
                               "(their tags are what the case graph reads)…")
        settled, summary = wait_for_analyzers(
            sketch_id, TIMESKETCH_CONFIG, timeout_seconds=timeout,
            logger=lambda m, l="info": add_log_to_run(run_id, m, l),
            cancel_event=get_cancel_event(run_id) if get_cancel_event else None,
        )
        for name in sorted(summary or {}):
            counts = summary[name]
            errs = counts.get("ERROR", 0)
            total = sum(counts.values())
            add_log_to_run(
                run_id,
                f"  analyzer {name}: {total - errs}/{total} ok"
                + (f", {errs} error(s)" if errs else ""),
                "warning" if errs else "info")
        if settled and summary:
            add_log_to_run(run_id, "Analyzers finished — their tags are now "
                                   "available to the case graph.", "success")
        elif settled:
            # wait_for_analyzers returns settled with an empty summary when no
            # analyzer sessions ever appeared. Saying "finished" there claims
            # tags exist that do not, and the empty case that follows then looks
            # like a fusion bug rather than a Timesketch that was asked to run
            # nothing.
            add_log_to_run(run_id, "No analyzers ran on this timeline "
                                   "(AUTO_SKETCH_ANALYZERS may be empty) — the "
                                   "case will only see starred events.", "warning")
        else:
            add_log_to_run(run_id, "Analyzers did not finish in time — the "
                                   "import is complete and a later Refusion "
                                   "will pick up their tags.", "warning")
    except Exception as e:
        add_log_to_run(run_id, f"Analyzer wait skipped: {e}", "warning")


def process_kape_upload(zip_path, original_filename, settings, run_id=None, cleanup_zip=True, suppress_status_writes=False):
    """Process uploaded KAPE file through Plaso and import to Timesketch

    Main entry point called by upload webhook handler and by the Timesketch
    automation flow (which exports the collection as a ZIP via Velociraptor
    first, then feeds it here to use the same code path).

    Args:
        zip_path: Path to the ZIP file (user upload or Velociraptor export)
        original_filename: Display filename (used for logging + client_name fallback)
        settings: Dict with plaso_parser, plaso_workers, plaso_hasher,
            plaso_hasher_size, sketch_name, timeline_name, sketch_id
        run_id: Optional workflow run_id (pre-created by caller). If not
            provided a new 'timesketch_kape_upload' run is created.
        cleanup_zip: If True, delete the source ZIP after processing.
            Set to False when the caller manages the ZIP lifecycle.
        suppress_status_writes: If True, skip every update_run_status() call —
            log lines still flow. Used by the multi-client Timesketch
            orchestrator so per-client processing doesn't overwrite the
            parent run's progress %/status (which the orchestrator owns).

    Returns:
        Dict with result info or None on failure
    """
    # Local helper: gate all update_run_status calls behind the suppress flag
    # so the multi-client orchestrator stays the sole authority on the parent
    # run's progress + status. We still want per-client log lines either way.
    def _status(status, **kw):
        if not suppress_status_writes:
            update_run_status(run_id, status, **kw)
    temp_dir = None
    plaso_file = None  # Track for cleanup

    try:
        # Use existing run_id or create new one
        if not run_id:
            run_id = create_automation_run(
                "timesketch_kape_upload",
                f"KAPE Upload: {original_filename}",
                {"filename": original_filename, "settings": settings}
            )
            add_log_to_run(run_id, f"Processing uploaded file: {original_filename}")
            _status("running", progress=5)
        else:
            add_log_to_run(run_id, "=== Starting KAPE Processing ===")

        # Check file exists
        if not os.path.exists(zip_path):
            raise Exception(f"File not found: {zip_path}")

        file_size = os.path.getsize(zip_path)
        add_log_to_run(run_id, f"File size: {file_size / (1024*1024):.2f} MB")

        # Detect format
        format_type = detect_kape_format(zip_path)
        add_log_to_run(run_id, f"Detected format: {format_type}")

        if format_type == 'unknown':
            raise Exception("Unknown file format - not a valid KAPE or Velociraptor collection")

        # Extract client info (pass original_filename for fallback since zip_path is a hash).
        # Automation callers can pre-populate settings['client_name'] to skip the heuristic.
        client_name = settings.get('client_name') or extract_client_info(zip_path, format_type, original_filename)
        add_log_to_run(run_id, f"Client hostname: {client_name}")
        _status("running", progress=10)

        # Create temp directory for extraction inside PLASO_OUTPUT_DIR (shared with host via Docker volume)
        # Must be under /tmp/plaso/ so the Plaso Docker container can access the files
        temp_dir = tempfile.mkdtemp(prefix='kape_upload_', dir=PLASO_OUTPUT_DIR)
        extract_dir = os.path.join(temp_dir, 'extracted')
        os.makedirs(extract_dir)
        add_log_to_run(run_id, f"Working directory: {temp_dir}")

        # Extract ZIP — but judge it first. This was a bare extractall: the
        # entry count was computed and used only for a log line, never compared
        # against anything, and nothing bounded uncompressed size or checked
        # that PLASO_OUTPUT_DIR (a shared volume) could hold the result. A
        # small archive could fill it and take the Plaso pipeline down for
        # every case on the host.
        from services.archive_guard import guard_zip, ArchiveRejected
        add_log_to_run(run_id, "Inspecting ZIP file...")
        try:
            stats = guard_zip(zip_path, extract_dir,
                              log=lambda m: add_log_to_run(run_id, m))
        except ArchiveRejected as e:
            add_log_to_run(run_id, f"Archive rejected: {e}", "error")
            raise ValueError(f"Archive rejected: {e}") from e

        add_log_to_run(run_id, "Extracting ZIP file...")
        with zipfile.ZipFile(zip_path, 'r') as zf:
            file_count = stats["members"]
            zf.extractall(extract_dir)
            add_log_to_run(run_id, f"Extracted {file_count} files from archive")

        _status("running", progress=20)

        # Handle Velociraptor format (needs zlib decompression)
        if format_type == 'velociraptor':
            add_log_to_run(run_id, "Decompressing Velociraptor collection...")

            # Find uploads directory (may be at root or in a subfolder)
            uploads_dir = None
            for root, dirs, files in os.walk(extract_dir):
                if 'uploads' in dirs:
                    uploads_dir = os.path.join(root, 'uploads')
                    break

            if uploads_dir and os.path.exists(uploads_dir):
                decompress_dir = os.path.join(temp_dir, 'decompressed')
                os.makedirs(decompress_dir)

                success, count, errors = decompress_velociraptor_uploads(
                    uploads_dir, decompress_dir,
                    logger=lambda msg, lvl: add_log_to_run(run_id, msg, lvl)
                )

                if success:
                    source_dir = decompress_dir
                    add_log_to_run(run_id, f"Decompressed {count} files")
                else:
                    raise Exception("Failed to decompress Velociraptor files")
            else:
                # No uploads folder found, use extracted directory
                add_log_to_run(run_id, "No uploads/ folder found, using extracted files directly", "warning")
                source_dir = extract_dir
        else:
            # Raw KAPE - use directly
            source_dir = extract_dir
            add_log_to_run(run_id, "Using raw KAPE files directly")

        _status("running", progress=30)

        # Run Plaso
        add_log_to_run(run_id, "=== Processing with Plaso ===")
        plaso_file = process_local_with_plaso(
            source_dir, client_name,
            logger=lambda msg, lvl: add_log_to_run(run_id, msg, lvl),
            parser=settings.get('plaso_parser'),
            workers=settings.get('plaso_workers', 2),
            hasher=settings.get('plaso_hasher'),
            hasher_file_size_mb=settings.get('plaso_hasher_size'),
            run_id=run_id,  # enables Stop-button termination of log2timeline
        )

        # If Stop was clicked mid-Plaso, plaso_file is None — bail out
        # cleanly without raising, so the workflow ends as 'cancelled'
        # (already set by request_stop) instead of 'failed'.
        cancel_event = get_cancel_event(run_id) if run_id else None
        if cancel_event and cancel_event.is_set():
            add_log_to_run(run_id, "Plaso stage stopped by user", "warning")
            return {"run_id": run_id, "status": "cancelled"}

        if not plaso_file:
            raise Exception("Plaso processing failed")

        _status("running", progress=60)

        # Verify with pinfo
        add_log_to_run(run_id, "=== Verifying Plaso Output ===")
        pinfo_result = run_pinfo(
            plaso_file,
            logger=lambda msg, lvl: add_log_to_run(run_id, msg, lvl),
            run_id=run_id,
        )

        if pinfo_result:
            event_count = pinfo_result.get('event_count', 0)
            count_reliable = pinfo_result.get('count_reliable', True)
            if event_count == 0 and count_reliable:
                # Only trust a zero count when pinfo's own per-parser section
                # was actually found and summed — otherwise this is a parsing
                # failure (pinfo/Plaso output format changed, truncated
                # output, etc.), NOT proof the file is empty. Discarding a
                # genuinely non-empty .plaso file here (via the cleanup below)
                # would silently lose real forensic data.
                add_log_to_run(run_id, "No events extracted - check parser settings", "warning")
                add_log_to_run(run_id, "Tip: Try using 'Auto (All Parsers)' or 'win7' for broader coverage", "info")
                _status("completed", progress=100)
                return {"run_id": run_id, "status": "no_events"}
            elif event_count == 0:
                add_log_to_run(run_id, "pinfo event count is unreliable (parser breakdown not found) — "
                                       "proceeding to import anyway rather than risk discarding real data",
                               "warning")
            else:
                add_log_to_run(run_id, f"Plaso extracted {event_count} events", "success")

        _status("running", progress=70)

        # Import to Timesketch
        add_log_to_run(run_id, "=== Importing to Timesketch ===")
        sketch_name = settings.get('sketch_name', f'Investigation-{client_name}')
        timeline_name = settings.get('timeline_name') or f"{client_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        sketch_id = settings.get('sketch_id')

        # Wall-clock cap on the Timesketch indexing wait. Default 3 days;
        # the per-blueprint setting flows in via process_kape_upload's
        # settings dict (executor / routes / TUS hook all propagate it).
        ts_wait_timeout = settings.get('timesketch_processing_timeout', 259200)

        result = import_to_timesketch(
            plaso_file, sketch_name, timeline_name,
            TIMESKETCH_CONFIG,
            logger=lambda msg, lvl: add_log_to_run(run_id, msg, lvl),
            sketch_id=sketch_id,
            wait_timeout=ts_wait_timeout,
            run_id=run_id,  # enables Stop-button cancel during upload + indexing-wait
        )

        if result:
            add_log_to_run(run_id, f"Import complete! Sketch ID: {result.get('sketch_id')}", "success")
            add_log_to_run(run_id, f"Timeline ID: {result.get('timeline_id')}", "success")

            # LAND THE SKETCH LOCATOR ON THE RUN. Without this the import
            # result was logged and thrown away, and fusion had to find the
            # sketch BY NAME at fuse time — which silently picks the wrong
            # sketch the moment two runs share a name or one is renamed.
            _status("running", progress=95, details={
                "sketch_id": result.get("sketch_id"),
                "timeline_id": result.get("timeline_id"),
                "timeline_name": timeline_name,
            })

            # WAIT FOR THE ANALYZERS before going terminal. Timesketch fires
            # AUTO_SKETCH_ANALYZERS in its own Celery workers after the import,
            # and `timesketch*` types arm the case auto-fuse the instant this
            # run completes. Completing here used to hand the fuse a sketch
            # with zero tags (measured), and nothing re-armed when they landed.
            _wait_for_sketch_analyzers(run_id, result.get("sketch_id"), settings,
                                       timeline_id=result.get("timeline_id"))

            _status("completed", progress=100)

            return {
                "run_id": run_id,
                "status": "completed",
                "sketch_id": result.get('sketch_id'),
                "timeline_id": result.get('timeline_id'),
                "client_name": client_name
            }
        else:
            raise Exception("Timesketch import failed")

    except Exception as e:
        error_msg = str(e)
        print(f"[KAPE] Error: {error_msg}", flush=True)
        traceback.print_exc()

        if run_id:
            add_log_to_run(run_id, f"Error: {error_msg}", "error")
            _status("failed", error=error_msg)

        return {"run_id": run_id, "status": "failed", "error": error_msg}

    finally:
        # Cleanup temp directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
                print(f"[KAPE] Cleaned up temp directory: {temp_dir}", flush=True)
                if run_id:
                    add_log_to_run(run_id, "Temporary files cleaned up")
            except:
                pass

        # Cleanup source ZIP (skip when caller manages its own lifecycle)
        if cleanup_zip and zip_path and os.path.exists(zip_path):
            try:
                os.remove(zip_path)
                print(f"[KAPE] Cleaned up uploaded file: {zip_path}", flush=True)
                if run_id:
                    add_log_to_run(run_id, "Upload file cleaned up")
            except:
                pass

        # Cleanup plaso file (after Timesketch import, no longer needed)
        if plaso_file and os.path.exists(plaso_file):
            try:
                os.remove(plaso_file)
                print(f"[KAPE] Cleaned up plaso file: {plaso_file}", flush=True)
                if run_id:
                    add_log_to_run(run_id, "Plaso file cleaned up")
            except:
                pass

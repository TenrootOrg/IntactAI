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
import zipfile
import json
import shutil
import tempfile
import subprocess
import traceback
from datetime import datetime

from services.workflow_service import create_automation_run, add_log_to_run, update_run_status
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


def process_local_with_plaso(source_dir, client_name, logger=None, parser=None, workers=2, hasher=None, hasher_file_size_mb=None):
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

        # Clean up previous output files
        for old_file in os.listdir(PLASO_OUTPUT_DIR):
            old_path = os.path.join(PLASO_OUTPUT_DIR, old_file)
            try:
                if os.path.isfile(old_path):
                    os.remove(old_path)
            except:
                pass

        # Build Plaso command
        num_workers = str(workers) if workers else PLASO_CPUS

        plaso_cmd = [
            'docker', 'run', '--rm',
            '-v', f'{PLASO_OUTPUT_DIR}:/data',
            '-v', f'{source_dir}:/source:ro',
            '--cpus', PLASO_CPUS,
            '--memory', PLASO_MEMORY,
            '--user', 'root',
            get_plaso_image(),
            'log2timeline',
            '--workers', num_workers,
            '--status_view', 'window',
            '--status_view_interval', '60',
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

        # Run Plaso
        process = subprocess.Popen(
            plaso_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # Stream output
        line_count = 0
        for line in process.stdout:
            line = line.strip()
            if line:
                line_count += 1
                print(f"[PLASO] {line}", flush=True)

                # Log important lines to workflow
                line_lower = line.lower()
                is_important = any(kw in line_lower for kw in ['error', 'warning', 'processing', 'completed', 'events'])
                if is_important or line_count % 10 == 0:
                    if logger:
                        level = "error" if 'error' in line_lower else ("warning" if 'warning' in line_lower else "info")
                        try:
                            logger(line[:200], level)
                        except:
                            pass

        return_code = process.wait()

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


def process_kape_upload(zip_path, original_filename, settings, run_id=None):
    """Process uploaded KAPE file through Plaso and import to Timesketch

    Main entry point called by upload webhook handler.

    Args:
        zip_path: Path to the uploaded ZIP file
        original_filename: Original filename of the upload
        settings: Dict with plaso_parser, plaso_workers, sketch_name, etc.
        run_id: Optional workflow run_id (created in pre-create hook)

    Returns:
        Dict with result info or None on failure
    """
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
            update_run_status(run_id, "running", progress=5)
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

        # Extract client info (pass original_filename for fallback since zip_path is a hash)
        client_name = extract_client_info(zip_path, format_type, original_filename)
        add_log_to_run(run_id, f"Client hostname: {client_name}")
        update_run_status(run_id, "running", progress=10)

        # Create temp directory for extraction
        temp_dir = tempfile.mkdtemp(prefix='kape_upload_')
        extract_dir = os.path.join(temp_dir, 'extracted')
        os.makedirs(extract_dir)
        add_log_to_run(run_id, f"Working directory: {temp_dir}")

        # Extract ZIP
        add_log_to_run(run_id, "Extracting ZIP file...")
        with zipfile.ZipFile(zip_path, 'r') as zf:
            file_count = len(zf.namelist())
            zf.extractall(extract_dir)
            add_log_to_run(run_id, f"Extracted {file_count} files from archive")

        update_run_status(run_id, "running", progress=20)

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

        update_run_status(run_id, "running", progress=30)

        # Run Plaso
        add_log_to_run(run_id, "=== Processing with Plaso ===")
        plaso_file = process_local_with_plaso(
            source_dir, client_name,
            logger=lambda msg, lvl: add_log_to_run(run_id, msg, lvl),
            parser=settings.get('plaso_parser'),
            workers=settings.get('plaso_workers', 2),
            hasher=settings.get('plaso_hasher'),
            hasher_file_size_mb=settings.get('plaso_hasher_size')
        )

        if not plaso_file:
            raise Exception("Plaso processing failed")

        update_run_status(run_id, "running", progress=60)

        # Verify with pinfo
        add_log_to_run(run_id, "=== Verifying Plaso Output ===")
        pinfo_result = run_pinfo(plaso_file,
            logger=lambda msg, lvl: add_log_to_run(run_id, msg, lvl))

        if pinfo_result:
            event_count = pinfo_result.get('event_count', 0)
            if event_count == 0:
                add_log_to_run(run_id, "No events extracted - check parser settings", "warning")
                add_log_to_run(run_id, "Tip: Try using 'Auto (All Parsers)' or 'win7' for broader coverage", "info")
                update_run_status(run_id, "completed", progress=100)
                return {"run_id": run_id, "status": "no_events"}
            else:
                add_log_to_run(run_id, f"Plaso extracted {event_count} events", "success")

        update_run_status(run_id, "running", progress=70)

        # Import to Timesketch
        add_log_to_run(run_id, "=== Importing to Timesketch ===")
        sketch_name = settings.get('sketch_name', f'Investigation-{client_name}')
        timeline_name = f"{client_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        result = import_to_timesketch(
            plaso_file, sketch_name, timeline_name,
            TIMESKETCH_CONFIG,
            logger=lambda msg, lvl: add_log_to_run(run_id, msg, lvl)
        )

        if result:
            add_log_to_run(run_id, f"Import complete! Sketch ID: {result.get('sketch_id')}", "success")
            add_log_to_run(run_id, f"Timeline ID: {result.get('timeline_id')}", "success")
            update_run_status(run_id, "completed", progress=100)

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
            update_run_status(run_id, "failed", error=error_msg)

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

        # Cleanup uploaded file
        if zip_path and os.path.exists(zip_path):
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

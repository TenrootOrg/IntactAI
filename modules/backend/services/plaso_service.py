#!/usr/bin/env python3
"""
Plaso Service - Plaso processing functions

Velociraptor compresses collected files with zlib. This module decompresses
them before running log2timeline to ensure all parsers work correctly.
"""

import subprocess
import os
import sys
import time
import traceback
import zlib
import shutil
import urllib.parse
import tempfile

from config import PLASO_OUTPUT_DIR, get_plaso_image, PLASO_CPUS, PLASO_MEMORY, VELOCIRAPTOR_CONTAINER, VELOCIRAPTOR_DATA_PATH


def decompress_velociraptor_collection(source_dir, dest_dir, logger=None):
    """Decompress Velociraptor's zlib-compressed files.

    Velociraptor compresses all collected files with zlib. This function
    decompresses them to a destination directory, preserving directory structure.

    Args:
        source_dir: Path to the Velociraptor uploads directory
        dest_dir: Path to write decompressed files
        logger: Optional callback function(message, level) to log progress

    Returns:
        tuple (success: bool, file_count: int, error_count: int)
    """
    def log(message, level="info"):
        print(f"[DECOMPRESS] {message}", flush=True)
        if logger:
            try:
                logger(f"[DECOMPRESS] {message}", level)
            except:
                pass

    log(f"Decompressing Velociraptor collection to: {dest_dir}")

    # We need to run decompression inside a container that has access to Velociraptor's volumes
    # Create a Python script that will do the decompression
    decompress_script = '''
import os
import sys
import zlib
import urllib.parse

source_dir = sys.argv[1]
dest_dir = sys.argv[2]

file_count = 0
error_count = 0
skipped_count = 0

# Skip .chunk and .idx files (they're Velociraptor metadata)
SKIP_EXTENSIONS = {'.chunk', '.idx'}

for root, dirs, files in os.walk(source_dir):
    for filename in files:
        # Skip metadata files
        if any(filename.endswith(ext) for ext in SKIP_EXTENSIONS):
            skipped_count += 1
            continue

        src_path = os.path.join(root, filename)
        rel_path = os.path.relpath(src_path, source_dir)

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
            print(f"ERROR: {src_path}: {e}", file=sys.stderr)
            error_count += 1

print(f"RESULT: files={file_count} errors={error_count} skipped={skipped_count}")
'''

    try:
        # Run decompression script in a container with access to Velociraptor volumes
        result = subprocess.run(
            [
                'docker', 'run', '--rm',
                '--volumes-from', VELOCIRAPTOR_CONTAINER,
                '-v', f'{dest_dir}:/output',
                'python:3-alpine',
                'python3', '-c', decompress_script,
                source_dir, '/output'
            ],
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )

        # Parse output
        for line in result.stdout.strip().split('\n'):
            if line.startswith('RESULT:'):
                parts = line.replace('RESULT:', '').strip().split()
                file_count = int(parts[0].split('=')[1])
                error_count = int(parts[1].split('=')[1])
                skipped_count = int(parts[2].split('=')[1])

                log(f"✓ Decompressed {file_count} files ({skipped_count} metadata files skipped)", "success")
                if error_count > 0:
                    log(f"⚠ {error_count} files failed to decompress", "warning")

                return (True, file_count, error_count)

        # If we didn't find RESULT line, check for errors
        if result.returncode != 0:
            log(f"✗ Decompression failed: {result.stderr}", "error")
            return (False, 0, 0)

        log("✓ Decompression completed")
        return (True, 0, 0)

    except subprocess.TimeoutExpired:
        log("✗ Decompression timed out", "error")
        return (False, 0, 0)
    except Exception as e:
        log(f"✗ Decompression error: {e}", "error")
        return (False, 0, 0)


def run_pinfo(plaso_file, logger=None):
    """Run pinfo on a Plaso file to get storage information and event count.

    Args:
        plaso_file: Path to the .plaso file
        logger: Optional callback function(message, level) to log progress

    Returns:
        dict with 'event_count', 'parsers', 'sessions', 'storage_info' or None if failed
    """
    import re

    def log(message, level="info"):
        print(f"[PINFO] {message}", flush=True)
        if logger:
            try:
                logger(f"[PINFO] {message}", level)
            except:
                pass

    log("Running pinfo to verify Plaso storage...")

    try:
        # Get just the filename for the container path
        filename = os.path.basename(plaso_file)

        pinfo_cmd = [
            'docker', 'run', '--rm',
            '-v', f'{PLASO_OUTPUT_DIR}:/data',
            get_plaso_image(),
            'pinfo',
            f'/data/{filename}'
        ]

        result = subprocess.run(
            pinfo_cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            log(f"⚠ pinfo failed: {result.stderr.strip()}", "warning")
            return None

        output = result.stdout
        log("=" * 50)

        # Parse pinfo output
        info = {
            'event_count': 0,
            'event_sources': 0,
            'parsers': [],
            'sessions': 0,
            'storage_info': {}
        }

        # Track which section we're in
        # pinfo output has sections like "Event sources" and "Events generated per parser"
        in_events_section = False
        no_events_stored = False

        # Log all output lines and extract info
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Log each line
            log(f"  {line}")

            # Track section headers
            if 'Event sources' in line:
                in_events_section = False  # This is the sources section, not events
            elif 'Events generated per parser' in line:
                in_events_section = True   # Now we're in the actual events section

            # Check for "No events stored" indicator
            if 'no events stored' in line.lower():
                no_events_stored = True
                info['event_count'] = 0

            # Extract event sources count (different from actual events)
            if 'Total' in line and ':' in line and not in_events_section:
                match = re.search(r'Total\s*:\s*(\d+)', line)
                if match:
                    info['event_sources'] = int(match.group(1))

            # Extract actual event count from "Events generated per parser" section
            # This is the "Total : NNNN" line in that section
            if in_events_section and line.startswith('Total') and ':' in line:
                match = re.search(r'Total\s*:\s*(\d+)', line)
                if match:
                    info['event_count'] = int(match.group(1))

            # Also capture individual parser event counts (e.g., "filestat : 15522")
            if in_events_section and ':' in line and not line.startswith('Total'):
                match = re.search(r':\s*(\d+)', line)
                if match:
                    count = int(match.group(1))
                    info['parsers'].append(line)

            # Extract session count
            if 'session' in line.lower() and ':' not in line:
                match = re.search(r'(\d+)', line)
                if match:
                    info['sessions'] = int(match.group(1))

        log("=" * 50)

        # Summary
        log(f"Event sources found: {info['event_sources']}")
        if info['event_count'] > 0:
            log(f"✓ Events extracted: {info['event_count']}", "success")
            if info['parsers']:
                log(f"  Parsers used: {', '.join([p.split(':')[0].strip() for p in info['parsers'][:5]])}")
        else:
            log("⚠ No events extracted from the collected files", "warning")
            log(f"  Found {info['event_sources']} files but no parser could extract events", "warning")
            log("  The parser preset did not match any of the collected file types", "warning")
            log("  Tip: Use 'Auto (All Parsers)' or 'win7' for mixed artifact collections", "warning")
            log("  Skipping Timesketch import - nothing to upload", "warning")

        return info

    except subprocess.TimeoutExpired:
        log("⚠ pinfo timed out", "warning")
        return None
    except Exception as e:
        log(f"⚠ pinfo error: {e}", "warning")
        return None


def process_with_plaso(client_id, flow_id, client_name, logger=None, parser=None, workers=None, hasher=None, hasher_file_size_mb=None, run_id=None):
    """Process collected files with Plaso (log2timeline)

    Args:
        client_id: Velociraptor client ID
        flow_id: Velociraptor flow ID
        client_name: Human readable client name
        logger: Optional callback function(message, level) to log progress
        parser: Parser preset (win7, win7_slow, winevtx, etc.)
        workers: Number of parallel workers (default from config)
        hasher: Hash algorithm (md5, sha1, sha256, all)
        hasher_file_size_mb: Max file size in MB to hash (0 or None = no limit)
    """

    def log(message, level="info"):
        """Log to both stdout and optional callback"""
        print(f"[PLASO] {message}", flush=True)
        if logger:
            try:
                logger(f"[PLASO] {message}", level)
            except Exception as e:
                print(f"[PLASO] Logger error: {e}", flush=True)

    sys.stdout.flush()
    log("=" * 60)
    log(f"Starting Plaso processing")
    log(f"Client: {client_name}")
    log(f"Flow ID: {flow_id}")
    log("=" * 60)

    try:
        # Check if Plaso is already running
        log("Step 1/5: Checking for existing Plaso processes...")
        result = subprocess.run(
            ['docker', 'ps', '--filter', f'ancestor={get_plaso_image()}', '--format', '{{.Names}}'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.stdout.strip():
            log(f"✗ Plaso is already running: {result.stdout.strip()}", "error")
            log("Please wait for it to finish or stop it manually", "error")
            return None

        log("✓ No existing Plaso processes")

        # Check if Docker image is available
        log("Step 1.5/5: Checking Plaso Docker image availability...")
        try:
            image_check = subprocess.run(
                ['docker', 'images', '-q', get_plaso_image()],
                capture_output=True,
                text=True,
                timeout=5
            )

            if not image_check.stdout.strip():
                log(f"⚠ Plaso image not found locally, downloading {get_plaso_image()}...", "warning")
                log("This is a one-time download and may take 1-2 minutes", "info")

                pull_result = subprocess.run(
                    ['docker', 'pull', get_plaso_image()],
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout for image pull
                )

                if pull_result.returncode != 0:
                    log(f"✗ Failed to download image: {pull_result.stderr}", "error")
                    return None

                log("✓ Plaso image downloaded successfully")
            else:
                log("✓ Plaso image available locally")
        except subprocess.TimeoutExpired:
            log("⚠ Image check timed out, continuing anyway...", "warning")
        except Exception as e:
            log(f"⚠ Image check failed ({e}), continuing anyway...", "warning")

        # Setup paths
        log("Step 2/5: Setting up paths...")
        plaso_file = f"{PLASO_OUTPUT_DIR}/{client_name}_Artifacts.plaso"
        log(f"Output file: {plaso_file}")

        # Create output directory
        os.makedirs(PLASO_OUTPUT_DIR, exist_ok=True)

        # Clean up ALL previous files in output directory to save space
        log("Cleaning up previous files in output directory...")
        for old_file in os.listdir(PLASO_OUTPUT_DIR):
            old_file_path = os.path.join(PLASO_OUTPUT_DIR, old_file)
            try:
                if os.path.isfile(old_file_path):
                    os.remove(old_file_path)
                    log(f"Removed: {old_file}")
            except Exception as e:
                log(f"⚠ Could not remove {old_file}: {e}", "warning")

        log("✓ Paths configured")

        # Determine CPU and memory limits
        log("Step 3/6: Configuring resource limits...")

        # Use provided workers or fall back to config default
        num_workers = str(workers) if workers else PLASO_CPUS
        log(f"Workers: {num_workers}")
        log(f"Memory: {PLASO_MEMORY}")
        if parser:
            log(f"Parser preset: {parser}")
        if hasher:
            hasher_info = f"Hasher: {hasher}"
            if hasher_file_size_mb and hasher_file_size_mb > 0:
                hasher_info += f" (files < {hasher_file_size_mb}MB)"
            log(hasher_info)

        # Velociraptor stores data at /var./ inside container
        velo_source_path = f"{VELOCIRAPTOR_DATA_PATH}/clients/{client_id}/collections/{flow_id}/uploads"

        # Step 4: Decompress Velociraptor's zlib-compressed files
        log("Step 4/6: Decompressing Velociraptor collection...")
        log("(Velociraptor compresses collected files with zlib)")

        # Create a temporary directory for decompressed files
        decompress_dir = f"{PLASO_OUTPUT_DIR}/decompressed_{client_name}"
        if os.path.exists(decompress_dir):
            log(f"Cleaning up previous decompressed directory...")
            shutil.rmtree(decompress_dir)
        os.makedirs(decompress_dir, exist_ok=True)

        # Decompress files
        success, file_count, error_count = decompress_velociraptor_collection(
            velo_source_path, decompress_dir, logger
        )

        if not success or file_count == 0:
            log("✗ Failed to decompress files or no files found", "error")
            return None

        log(f"✓ Decompressed {file_count} files to {decompress_dir}")

        # Build Plaso command using the decompressed files
        log("Step 5/6: Building Plaso command...")

        # Now we use the local decompressed directory instead of Velociraptor volumes
        plaso_cmd = [
            'docker', 'run', '--rm',
            '-v', f'{PLASO_OUTPUT_DIR}:/data',
            '-v', f'{decompress_dir}:/source:ro',  # Mount decompressed files
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

        # Add hasher if specified
        if hasher:
            if hasher == 'all':
                plaso_cmd.extend(['--hashers', 'md5,sha1,sha256'])
            else:
                plaso_cmd.extend(['--hashers', hasher])

            # Add hasher file size limit if specified (convert MB to bytes)
            if hasher_file_size_mb and hasher_file_size_mb > 0:
                size_bytes = hasher_file_size_mb * 1024 * 1024
                plaso_cmd.extend(['--hasher_file_size_limit', str(size_bytes)])
                log(f"Hasher file size limit: {hasher_file_size_mb}MB ({size_bytes} bytes)")

        # Add output file and source path (decompressed files are at /source in container)
        plaso_cmd.extend([
            '--storage-file', f'/data/{client_name}_Artifacts.plaso',
            '/source'
        ])

        log(f"Source: decompressed files from {decompress_dir}")

        # List decompressed files for diagnostics
        log("Checking decompressed source files...")
        try:
            total_size = 0
            file_types = {}
            file_count = 0
            for root, dirs, files in os.walk(decompress_dir):
                for f in files:
                    file_path = os.path.join(root, f)
                    try:
                        size = os.path.getsize(file_path)
                        total_size += size
                        ext = f.split('.')[-1].lower() if '.' in f else 'no_ext'
                        file_types[ext] = file_types.get(ext, 0) + 1
                        file_count += 1
                    except:
                        pass

            log(f"✓ Found {file_count} decompressed files ({total_size / (1024*1024):.2f} MB total)")
            # Log file type breakdown
            type_summary = ', '.join([f"{ext}: {count}" for ext, count in sorted(file_types.items(), key=lambda x: -x[1])[:10]])
            log(f"  File types: {type_summary}")
        except Exception as e:
            log(f"⚠ Could not list decompressed files: {e}", "warning")

        # Run Plaso
        log("Step 6/6: Running log2timeline (this may take a while)...")
        log("=" * 40)

        # Log the full command for debugging
        cmd_str = ' '.join(plaso_cmd)
        log(f"Full command: {cmd_str}")

        process = subprocess.Popen(
            plaso_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # Register cleanup so stop can kill the Plaso process
        if run_id:
            from services.workflow_service import register_cleanup
            register_cleanup(run_id, lambda: process.kill() if process.poll() is None else None)

        # Stream output - log important lines to Elasticsearch
        output_lines = []
        line_count = 0
        last_logged_time = time.time()
        warning_count = 0
        error_count = 0
        event_count = 0

        for line in process.stdout:
            line = line.strip()
            if line:
                line_count += 1
                output_lines.append(line)
                # Log every line to stdout
                print(f"[PLASO] {line}", flush=True)

                # Track warnings and errors
                line_lower = line.lower()
                if 'warning' in line_lower:
                    warning_count += 1
                if 'error' in line_lower:
                    error_count += 1

                # Try to extract event count from Plaso output
                # Plaso typically outputs lines like "Events: 12345" or "Processing 12345 events"
                if 'events' in line_lower:
                    import re
                    match = re.search(r'(\d+)\s*events?', line_lower)
                    if match:
                        event_count = max(event_count, int(match.group(1)))

                # Log to Elasticsearch: important lines OR every 5th line OR every 30 seconds
                current_time = time.time()
                is_important = any(keyword in line_lower for keyword in
                                 ['error', 'warning', 'processing', 'tasks:', 'completed', 'started', 'finished', 'events'])
                should_log = (is_important or
                            line_count % 5 == 0 or
                            (current_time - last_logged_time) >= 30)

                if should_log and logger:
                    try:
                        level = "error" if 'error' in line_lower else ("warning" if 'warning' in line_lower else "info")
                        logger(f"{line}", level)
                        last_logged_time = current_time
                    except:
                        pass

        return_code = process.wait()

        log("=" * 40)
        log(f"Processing summary: {warning_count} warnings, {error_count} errors")
        if event_count > 0:
            log(f"Events extracted: {event_count}")

        # Cleanup decompressed directory to save space
        try:
            if os.path.exists(decompress_dir):
                log("Cleaning up decompressed files...")
                shutil.rmtree(decompress_dir)
                log("✓ Decompressed files cleaned up")
        except Exception as e:
            log(f"⚠ Could not cleanup decompressed files: {e}", "warning")

        if return_code == 0:
            log("✓ Processing completed successfully!", "success")
            log(f"Output file: {plaso_file}")

            # Check if file exists and get size
            if os.path.exists(plaso_file):
                size = os.path.getsize(plaso_file)
                size_mb = size / (1024 * 1024)
                log(f"File size: {size_mb:.2f} MB", "success")

                # Warn if file is suspiciously small (likely empty)
                if size_mb < 0.1:
                    log("⚠ Output file is very small - may contain no events!", "warning")
                    log("  Check if the parser preset matches your data types", "warning")

            return plaso_file
        else:
            log(f"✗ Processing failed with return code: {return_code}", "error")
            # Log last 20 lines of output for debugging
            if output_lines:
                log("Last output lines:", "error")
                for line in output_lines[-20:]:
                    log(f"  {line}", "error")
            return None

    except subprocess.TimeoutExpired:
        log("✗ Plaso processing timed out", "error")
        # Try to cleanup
        try:
            if 'decompress_dir' in locals() and os.path.exists(decompress_dir):
                shutil.rmtree(decompress_dir)
        except:
            pass
        return None

    except Exception as e:
        error_detail = traceback.format_exc()
        log(f"✗ Exception: {e}", "error")
        log(f"Stack trace: {error_detail}", "error")
        traceback.print_exc()
        # Try to cleanup
        try:
            if 'decompress_dir' in locals() and os.path.exists(decompress_dir):
                shutil.rmtree(decompress_dir)
        except:
            pass
        return None

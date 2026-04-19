#!/usr/bin/env python3
"""
Plaso Service - Plaso verification helpers.

Historical note: this module used to contain `process_with_plaso()` and
`decompress_velociraptor_collection()`, which read Velociraptor's live
filesystem at `/var./clients/.../uploads/` and ran log2timeline on the
result. That path had a critical bug: Velociraptor stores uploaded files
as 1 MiB zlib-compressed chunks with `.chunk` metadata companions, and
the decompression logic skipped the `.chunk` metadata, so every multi-
chunk file was silently truncated to its first 1 MiB. Plaso therefore
produced ~6x fewer events than the same collection processed via the
exported ZIP, and critical registry-backed parsers (amcache, shimcache,
bam, userassist, task_cache, services, winlogon, ...) never fired.

Both automation and scheduled jobs now go through
`services.velociraptor_service.export_flow_to_zip()` to obtain the
ZIP that Velociraptor assembles server-side with all chunks reassembled,
and then feed it to `services.kape_upload_service.process_kape_upload()`
— the same code path the Upload Existing endpoint uses. This file keeps
only `run_pinfo()`, which is still useful for verifying a `.plaso` file
independently.
"""

import subprocess
import os
import time

from config import PLASO_OUTPUT_DIR, get_plaso_image, PLASO_CPUS, PLASO_MEMORY


def run_pinfo(plaso_file, logger=None):
    """Run pinfo on a Plaso file to get storage information and event count.

    Args:
        plaso_file: Path to the .plaso file
        logger: Optional callback function(message, level) to log progress

    Returns:
        Dict with event_count, or None on failure
    """
    def log(msg, level="info"):
        if logger:
            logger(msg, level)
        else:
            print(f"[PINFO] {msg}", flush=True)

    if not os.path.exists(plaso_file):
        log(f"Plaso file not found: {plaso_file}", "error")
        return None

    try:
        cmd = [
            'docker', 'run', '--rm',
            '-v', f'{PLASO_OUTPUT_DIR}:/data',
            '--user', 'root',
            get_plaso_image(),
            'pinfo', f'/data/{os.path.basename(plaso_file)}'
        ]

        log(f"Running pinfo on {os.path.basename(plaso_file)}...")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # pinfo does not print a grand total, but it prints a per-parser
        # breakdown in the "Events generated per parser" section:
        #
        #   ************************* Events generated per parser *************************
        #                   Parser (plugin) name : Number of events
        #   -------------------------------------------------------
        #                                amcache : 1375
        #                                winevtx : 179982
        #                         winreg_default : 316974
        #   -------------------------------------------------------
        #
        # We sum those lines to get the total event count.
        event_count = 0
        in_parser_section = False
        output_lines = []
        start_time = time.time()
        PINFO_TIMEOUT = 300  # 5 minutes

        def _try_sum(line_text: str) -> int:
            """Return the RHS integer for a 'parser_name : NNN' line, else 0."""
            if ':' not in line_text:
                return 0
            parts = line_text.rsplit(':', 1)
            tail = parts[1].strip()
            if tail.isdigit():
                return int(tail)
            return 0

        def _consume(line_text: str) -> None:
            nonlocal event_count, in_parser_section
            # Section boundary detection. Plaso prints a header line then a
            # dashed separator, and marks the end with another dashed line.
            if 'Events generated per parser' in line_text:
                in_parser_section = True
                return
            if in_parser_section:
                # End of section is an empty line or another section header
                if line_text.strip().startswith('***') or (
                    line_text.strip() == '' and event_count > 0
                ):
                    in_parser_section = False
                    return
                # Skip the header row and separator rows
                if 'Parser' in line_text and 'Number of events' in line_text:
                    return
                if set(line_text.strip()) <= {'-'} and line_text.strip():
                    return
                event_count += _try_sum(line_text)

        while True:
            if process.poll() is not None:
                break
            if time.time() - start_time > PINFO_TIMEOUT:
                log(f"pinfo timed out after {PINFO_TIMEOUT}s", "warning")
                process.kill()
                break

            line = process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue

            line = line.rstrip()
            output_lines.append(line)
            log(line, "info")
            _consume(line)

        # Drain any remaining output
        for line in process.stdout:
            line = line.rstrip()
            if line:
                output_lines.append(line)
                log(line, "info")
                _consume(line)

        exit_code = process.returncode
        if exit_code != 0:
            log(f"pinfo exited with code {exit_code}", "warning")

        if event_count > 0:
            log(f"✓ Events extracted: {event_count}", "success")

        return {
            'event_count': event_count,
            'output': '\n'.join(output_lines[-50:])  # last 50 lines for debugging
        }

    except subprocess.TimeoutExpired:
        log("pinfo timed out", "warning")
        return None
    except Exception as e:
        log(f"pinfo error: {e}", "warning")
        return None

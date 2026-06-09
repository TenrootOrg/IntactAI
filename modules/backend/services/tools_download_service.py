#!/usr/bin/env python3
"""
Tools Download Service - Downloads tools from GitHub/URLs and configures Velociraptor inventory

This service:
1. Reads tools_inventory.yaml configuration
2. Downloads tools from GitHub releases and direct URLs
3. Uses inventory_add VQL to serve tools locally from Velociraptor server
"""

import os
import re
import json
import time
import yaml
import requests
import subprocess
from typing import Dict, List, Optional, Callable
from urllib.parse import urlparse

# Import Velociraptor gRPC components
import grpc
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc


def load_tools_config() -> Optional[Dict]:
    """Load tools inventory configuration from YAML file."""
    paths_to_try = [
        '/app/data/tools_inventory.yaml',
        os.path.join(os.path.dirname(__file__), '..', 'data', 'tools_inventory.yaml')
    ]
    for config_path in paths_to_try:
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    cfg = yaml.safe_load(f)
                if cfg:
                    _warn_dangling_inventory_refs(cfg, config_path)
                return cfg
        except Exception as e:
            print(f"[TOOLS] Error loading {config_path}: {e}", flush=True)
    return None


def _warn_dangling_inventory_refs(cfg: Dict, config_path: str) -> None:
    """Cross-check `velociraptor_inventory` entries against the
    download-source sections. A `tool_name` registered with the
    Velociraptor server that no download path provides will fail at
    runtime when the artifact tries to use it — log a clear warning
    here so the inconsistency surfaces at startup, not first use.

    Non-fatal: this is purely a developer-quality-of-life check.
    `velociraptor_inventory` matches files by regex pattern, not by
    name, so we use a prefix heuristic: strip a trailing version-like
    suffix (`-1.2.3`, `_v2`) from both inventory tool names and
    download names, then match on either-contains-the-other.
    """
    import re

    inv = cfg.get('velociraptor_inventory') or []
    download_sections = [
        'velociraptor_core', 'event_log_tools', 'persistence_tools',
        'yara_tools', 'velociraptor_artifacts', 'memory_tools',
        'nirsoft_tools', 'zimmerman_tools', 'sysinternals_tools',
        'imaging_tools', 'audit_tools', 'threat_intel',
        'osquery_tools', 'network_tools', 'linux_tools', 'optional_large',
    ]

    # Match inventory entries to download entries via three signals,
    # any of which counts as "this inventory entry has a download path":
    #
    #   1. Bidirectional pattern matching — generate a synthetic
    #      filename from the inventory's `file_pattern` and test against
    #      every download's URL/filename/pattern; AND, in reverse,
    #      generate filenames from each download (URL last-segment,
    #      `filename` field, or pattern→sample) and test against the
    #      inventory's `file_pattern` regex. Either-direction match
    #      counts.
    #
    #   2. Tool-name substring after normalization (lowercase, alnum
    #      only). Catches cases like inventory `Autorun_amd64` ⇆
    #      download `Autoruns` where both contain `autorun`.
    #
    #   3. EXPLICIT_ALIASES map — for inventory tool_names whose alias
    #      is too compressed for substring matching (e.g. `PSniper` →
    #      `PersistenceSniper`, `EvtxHussar17` → `EVTXHussar`). When
    #      a new inventory entry uses an alias not derivable from the
    #      download name, add it here.
    #
    # Original algorithm relied only on name-substring with version
    # suffix stripping, which generated 16 false-positive warnings on
    # entries that had perfectly valid downloads — the names just
    # didn't share substrings. See 2026-06-09 audit for the full list.
    EXPLICIT_ALIASES = {
        'PSniper': 'PersistenceSniper',
        'EvtxHussar17': 'EVTXHussar',
        'Takajo-2.5.0': 'Takajo',
        'yaraexecutable': 'Yara Win64',
        'YaraForgeCore': 'YaraForge Core',
        'YaraForgeExtended': 'YaraForge Extended',
        'YaraForgeFull': 'YaraForge Full',
        'FileYaraLinux': 'DetectRaptor YARA Linux',
        'FileYaraWindows': 'DetectRaptor YARA Windows',
        'YaraRulesFull': 'DetectRaptor YARA Full',
        'DetectRaptorLolRMM': 'DetectRaptor LOLRMM CSV',
        'DiffCSVUrl': 'PersistenceSniper False Positives',
        'SigmaProfiles': 'Sigma Profiles',
        'SysmonConfig': 'Sysmon Config',
        'OSQueryWindows': 'OSQuery Windows',
        'OSQueryLinux': 'OSQuery Linux',
        'OSQueryDarwin': 'OSQuery macOS',
        'ProcessExplorer': 'Process Explorer',
        'Autorun_amd64': 'Autoruns',
    }

    def _pattern_to_sample(p: str) -> str:
        s = re.sub(r'^\(\?[a-zA-Z]+\)', '', p)       # strip (?i), (?m), etc.
        s = re.sub(r'^\^|\$$', '', s)                 # strip anchors
        s = s.replace('.*', 'X').replace('.+', 'X')   # wildcards → placeholder
        s = s.replace('\\.', '.')                     # unescape literal dot
        s = re.sub(r'[\[\]\(\)\{\}\?\\\|]', '', s)   # drop remaining meta-chars
        return s

    def _norm(s: str) -> str:
        return re.sub(r'[^a-z0-9]', '', s.lower())

    # Build searchable indices from download entries
    download_entries: list = []     # for explicit-alias lookup by name
    download_samples: list = []     # for bidirectional pattern matching
    download_norm_names: list = []  # for normalized substring matching
    for section in download_sections:
        for entry in (cfg.get(section) or []):
            if not isinstance(entry, dict):
                continue
            name = entry.get('name', '')
            if isinstance(name, str) and name:
                download_entries.append((entry, _norm(name)))
                download_norm_names.append(_norm(name))
            u = entry.get('url')
            if isinstance(u, str) and u.strip():
                fn = u.rsplit('/', 1)[-1].split('?')[0].split('#')[0]
                if fn:
                    download_samples.append(fn)
            fn_field = entry.get('filename')
            if isinstance(fn_field, str) and fn_field.strip():
                download_samples.append(fn_field)
            pat = entry.get('pattern')
            if isinstance(pat, str) and pat.strip():
                s = _pattern_to_sample(pat)
                if s:
                    download_samples.append(s)

    # Also collect download patterns for the inventory-sample→download
    # direction (the original "direction 1" check)
    download_patterns: list = []
    download_urls: list = []
    for section in download_sections:
        for entry in (cfg.get(section) or []):
            if not isinstance(entry, dict):
                continue
            pat = entry.get('pattern')
            if isinstance(pat, str) and pat.strip():
                download_patterns.append(pat)
            u = entry.get('url')
            if isinstance(u, str) and u.strip():
                download_urls.append(u)

    missing: list = []
    for inv_entry in inv:
        if not isinstance(inv_entry, dict):
            continue
        tool = inv_entry.get('tool_name', '')
        if not tool:
            continue
        # Velociraptor binaries are intentionally satisfied by the
        # staging path under modules/velociraptor/clients/, not by a
        # tools_inventory download. Don't flag those.
        if tool.lower().startswith('velociraptor'):
            continue

        # Signal 3 — explicit alias map
        target = EXPLICIT_ALIASES.get(tool)
        if target is not None:
            target_norm = _norm(target)
            if any(n == target_norm or target_norm in n for n in download_norm_names):
                continue

        # Signal 2 — normalized-name substring (either direction)
        tn = _norm(tool)
        if tn and any(tn in n or n in tn for n in download_norm_names if n):
            continue

        # Signal 1 — bidirectional pattern matching
        file_pattern = inv_entry.get('file_pattern', '')
        if file_pattern:
            try:
                inv_rx = re.compile(file_pattern)
            except re.error:
                inv_rx = None
            inv_sample = _pattern_to_sample(file_pattern)

            found = False
            # Direction A: download produces a file the inventory accepts
            if inv_rx is not None:
                for sample in download_samples:
                    if inv_rx.search(sample):
                        found = True
                        break
            # Direction B: inventory's sample matches a download URL/pattern
            if not found and inv_sample:
                for u in download_urls:
                    if inv_sample.lower() in u.lower():
                        found = True
                        break
            if not found and inv_sample:
                for pat in download_patterns:
                    try:
                        if re.search(pat, inv_sample, flags=re.IGNORECASE):
                            found = True
                            break
                    except re.error:
                        continue
            if found:
                continue

        missing.append(tool)

    if missing:
        seen = set()
        uniq = [m for m in missing if not (m in seen or seen.add(m))]
        print(
            f"[TOOLS] WARNING: {len(uniq)} velociraptor_inventory entries "
            f"in {config_path} reference tools with no download source: "
            f"{', '.join(uniq[:10])}"
            f"{'...' if len(uniq) > 10 else ''}",
            flush=True,
        )


def get_github_release_url(repo: str, pattern: str, logger: Callable = None) -> Optional[str]:
    """Get download URL for a GitHub release asset matching the pattern."""
    def log(msg):
        if logger:
            logger(msg)
        print(f"[TOOLS-DL] {msg}", flush=True)

    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        headers = {'Accept': 'application/vnd.github.v3+json'}
        # Add token if available for rate limiting
        github_token = os.environ.get('GITHUB_TOKEN')
        if github_token:
            headers['Authorization'] = f'token {github_token}'

        response = requests.get(api_url, headers=headers, timeout=30)
        if response.status_code == 403:
            log(f"GitHub rate limited for {repo}")
            return None
        if response.status_code != 200:
            log(f"GitHub API error for {repo}: {response.status_code}")
            return None

        release_data = response.json()
        assets = release_data.get('assets', [])

        # Compile regex pattern
        regex = re.compile(pattern)

        for asset in assets:
            asset_name = asset.get('name', '')
            if regex.search(asset_name):
                return asset.get('browser_download_url')

        log(f"No asset matching '{pattern}' in {repo}")
        return None

    except Exception as e:
        log(f"Error getting release for {repo}: {str(e)[:50]}")
        return None


def download_file(url: str, dest_path: str, filename: Optional[str] = None,
                  logger: Callable = None, timeout: int = 300,
                  run_id: Optional[str] = None) -> Optional[str]:
    """Download a file from URL to destination path.

    `run_id` makes the chunked stream interruptible: when the operator
    clicks Stop, the very next chunk write checks the cancel event and
    aborts mid-file (and removes the partial). Without this, a 100 MB
    download running over a slow link kept going long after Stop.
    """
    def log(msg):
        if logger:
            logger(msg)
        print(f"[TOOLS-DL] {msg}", flush=True)

    # Hook the cancel event for this run if available
    cancel_event = None
    if run_id:
        try:
            from services.workflow_service import get_cancel_event
            cancel_event = get_cancel_event(run_id)
        except Exception:
            cancel_event = None

    try:
        # Determine filename
        if not filename:
            # Extract from URL
            parsed = urlparse(url)
            filename = os.path.basename(parsed.path)
            if not filename or filename == '':
                # Use content-disposition if available
                filename = f"download_{int(time.time())}"

        full_path = os.path.join(dest_path, filename)

        # Check if already exists
        if os.path.exists(full_path):
            log(f"  Already exists: {filename}")
            return (filename, True)  # Return tuple: (filename, was_cached)

        log(f"  Downloading: {filename}")

        # Stream download
        response = requests.get(url, stream=True, timeout=timeout,
                                allow_redirects=True,
                                headers={'User-Agent': 'Intact.AI-Tools-Downloader/1.0'})
        response.raise_for_status()

        # Get filename from content-disposition if available
        if 'content-disposition' in response.headers:
            cd = response.headers['content-disposition']
            fname_match = re.search(r'filename[^;=\n]*=((["\']).*?\2|[^;\n]*)', cd)
            if fname_match:
                filename = fname_match.group(1).strip('"\'')
                full_path = os.path.join(dest_path, filename)

        # Write file
        with open(full_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if cancel_event is not None and cancel_event.is_set():
                    log(f"  ✗ Cancelled mid-download: {filename}")
                    try:
                        f.close()
                        os.remove(full_path)
                    except OSError:
                        pass
                    return None
                if chunk:
                    f.write(chunk)

        log(f"  ✓ Downloaded: {filename}")
        return (filename, False)  # Return tuple: (filename, was_cached)

    except requests.exceptions.Timeout:
        log(f"  ✗ Timeout downloading {url[:50]}...")
        return None
    except Exception as e:
        log(f"  ✗ Error: {str(e)[:50]}")
        return None


def download_tools_from_config(tools_dir: str, config: Dict,
                                logger: Callable = None,
                                run_id: Optional[str] = None) -> Dict:
    """Download all enabled tools from configuration.

    Threads run_id into per-file `download_file` calls so a Stop click
    interrupts the in-flight download immediately. Also checks the
    cancel event between tools to exit cleanly between large items.
    """
    def log(msg, level="info"):
        if logger:
            logger(msg, level)
        print(f"[TOOLS-DL] {msg}", flush=True)

    results = {
        "downloaded": [],
        "skipped": [],
        "failed": [],
        "already_exists": []
    }

    # Create tools directory if it doesn't exist
    os.makedirs(tools_dir, exist_ok=True)

    # Sections that contain downloadable tools
    download_sections = [
        'velociraptor_core', 'event_log_tools', 'persistence_tools',
        'yara_tools', 'velociraptor_artifacts', 'memory_tools',
        'nirsoft_tools', 'zimmerman_tools', 'sysinternals_tools',
        'imaging_tools', 'audit_tools', 'threat_intel', 'linux_tools',
        'optional_large'
    ]

    total_tools = 0
    for section in download_sections:
        tools = config.get(section, [])
        if tools:
            enabled_count = sum(1 for t in tools if t.get('enabled', True))
            total_tools += enabled_count

    log(f"Found {total_tools} enabled tools to download")

    # Build set of existing files ONCE to avoid repeated GitHub API calls
    existing_files = set()
    if os.path.exists(tools_dir):
        existing_files = set(os.listdir(tools_dir))

    for section in download_sections:
        tools = config.get(section, [])
        if not tools:
            continue

        enabled_tools = [t for t in tools if t.get('enabled', True)]
        if not enabled_tools:
            continue

        log(f"Processing {section}: {len(enabled_tools)} tools")

        for tool in enabled_tools:
            # Honour Stop between tools — quick exit for the case where
            # we're partway through a big inventory and the operator
            # already pressed Stop.
            if run_id:
                try:
                    from services.workflow_service import is_cancelled
                    if is_cancelled(run_id):
                        log("Tool download cancelled by user")
                        results["cancelled"] = True
                        return results
                except Exception:
                    pass

            tool_name = tool.get('name', 'Unknown')
            tool_type = tool.get('type', '')

            try:
                download_url = None
                filename = tool.get('filename')  # Optional explicit filename

                # CHECK IF FILE EXISTS LOCALLY FIRST - skip GitHub API if cached
                if filename and filename in existing_files:
                    log(f"  Cached: {tool_name}")
                    results["already_exists"].append(tool_name)
                    continue

                # For direct_url with cache_pattern, check if any file matches pattern locally
                cache_pattern = tool.get('cache_pattern', '')
                if cache_pattern and existing_files:
                    regex = re.compile(cache_pattern)
                    matching = [f for f in existing_files if regex.search(f)]
                    if matching:
                        log(f"  Cached: {tool_name} ({matching[0]})")
                        results["already_exists"].append(tool_name)
                        continue

                # For github_release, check if any file matches the pattern locally
                if tool_type == 'github_release':
                    pattern = tool.get('pattern', '')
                    if pattern and existing_files:
                        regex = re.compile(pattern)
                        matching = [f for f in existing_files if regex.search(f)]
                        if matching:
                            log(f"  Cached: {tool_name} ({matching[0]})")
                            results["already_exists"].append(tool_name)
                            continue

                if tool_type == 'github_release':
                    repo = tool.get('repo', '')
                    pattern = tool.get('pattern', '')
                    if repo and pattern:
                        download_url = get_github_release_url(repo, pattern, log)

                elif tool_type == 'direct_url':
                    download_url = tool.get('url', '')

                elif tool_type == 'page_scrape':
                    # Skip page scrape for now - complex
                    results["skipped"].append(f"{tool_name} (page_scrape not implemented)")
                    continue

                if not download_url:
                    results["failed"].append(f"{tool_name} (no URL)")
                    continue

                # Download the file
                result = download_file(
                    download_url, tools_dir, filename, log, run_id=run_id
                )

                if result:
                    downloaded_filename, was_cached = result
                    if was_cached:
                        results["already_exists"].append(tool_name)
                    else:
                        results["downloaded"].append(tool_name)
                else:
                    results["failed"].append(tool_name)

            except Exception as e:
                log(f"  ✗ {tool_name}: {str(e)[:40]}", "error")
                results["failed"].append(tool_name)

    return results


def setup_velociraptor_connection():
    """Setup gRPC connection to Velociraptor API."""
    try:
        from config import VELOCIRAPTOR_CONTAINER, VELOCIRAPTOR_API_CONFIG_PATH

        config_path = "/tmp/api.config.yaml"

        if not os.path.exists(config_path):
            result = subprocess.run([
                "docker", "exec", VELOCIRAPTOR_CONTAINER,
                "cat", VELOCIRAPTOR_API_CONFIG_PATH
            ], capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                with open(config_path, 'w') as f:
                    f.write(result.stdout)
            else:
                return None

        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        creds = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode("utf8"),
            private_key=config["client_private_key"].encode("utf8"),
            certificate_chain=config["client_cert"].encode("utf8"),
        )

        max_message_size = 100 * 1024 * 1024  # 100MB
        options = (
            ("grpc.ssl_target_name_override", "VelociraptorServer"),
            ("grpc.max_receive_message_length", max_message_size),
            ("grpc.max_send_message_length", max_message_size),
        )
        channel = grpc.secure_channel(config["api_connection_string"], creds, options)
        return channel

    except Exception as e:
        print(f"[TOOLS] Connection setup failed: {e}", flush=True)
        return None


def configure_inventory(tools_dir: str, config: Dict, logger: Callable = None) -> Dict:
    """Configure Velociraptor inventory using inventory_add for downloaded tools."""
    def log(msg, level="info"):
        if logger:
            logger(msg, level)
        print(f"[TOOLS-INV] {msg}", flush=True)

    results = {
        "configured": [],
        "already_served": [],
        "file_not_found": [],
        "failed": [],
        "skipped": []
    }

    channel = setup_velociraptor_connection()
    if not channel:
        log("Failed to connect to Velociraptor", "error")
        return {"success": False, "error": "Connection failed", "results": results}

    stub = api_pb2_grpc.APIStub(channel)

    # Get inventory mapping from config
    inventory_tools = config.get('velociraptor_inventory', [])
    enabled_tools = [t for t in inventory_tools if t.get('enabled', True)]

    log(f"Configuring {len(enabled_tools)} tools in Velociraptor inventory")

    # Check what's already served (must have serve_locally=true AND no external URL)
    # Tools with external URLs need to be reconfigured with local files
    served_tools = set()
    try:
        vql = "SELECT name, serve_locally, url FROM inventory() WHERE serve_locally = true"
        request = api_pb2.VQLCollectorArgs(
            max_wait=30, max_row=200,
            Query=[api_pb2.VQLRequest(VQL=vql)]
        )
        for response in stub.Query(request, timeout=35):
            if response.Response:
                data = json.loads(response.Response)
                for item in data:
                    # Only consider "served" if no external URL (file is actually local)
                    # Tools with external URLs need to be reconfigured with local files
                    tool_name = item.get('name', '')
                    url = item.get('url', '')
                    if not url or not url.startswith('http'):
                        served_tools.add(tool_name)
                    else:
                        log(f"  {tool_name} has external URL, will reconfigure")
        log(f"Currently {len(served_tools)} tools served locally")
    except Exception as e:
        log(f"Could not query inventory: {str(e)[:50]}", "warning")

    # List files in tools directory via VQL
    available_files = []
    try:
        vql = f'SELECT Name FROM glob(globs="*", root="{tools_dir}") WHERE NOT IsDir'
        request = api_pb2.VQLCollectorArgs(
            max_wait=30, max_row=500,
            Query=[api_pb2.VQLRequest(VQL=vql)]
        )
        for response in stub.Query(request, timeout=35):
            if response.Response:
                data = json.loads(response.Response)
                available_files = [item.get('Name', '') for item in data]
        log(f"Found {len(available_files)} files in tools directory")
    except Exception as e:
        log(f"Could not list tools directory: {str(e)[:50]}", "warning")

    if not available_files:
        channel.close()
        return {
            "success": True,
            "results": results,
            "summary": "No files in tools directory to configure"
        }

    # Configure each tool
    for tool in enabled_tools:
        tool_name = tool.get('tool_name', '')
        file_pattern = tool.get('file_pattern', '')

        if not tool_name or not file_pattern:
            results["skipped"].append(tool_name or "Unknown")
            continue

        # Already served?
        if tool_name in served_tools:
            results["already_served"].append(tool_name)
            continue

        # Find matching file
        matched_file = None
        try:
            pattern = re.compile(file_pattern)
            for filename in available_files:
                if pattern.match(filename):
                    matched_file = filename
                    break
        except re.error:
            results["failed"].append(tool_name)
            continue

        if not matched_file:
            results["file_not_found"].append(tool_name)
            continue

        # Configure with inventory_add (it's a FUNCTION, not a plugin)
        # Then copy file to filestore (inventory_add doesn't always do this)
        try:
            file_path = f"{tools_dir}/{matched_file}"
            vql = f'''
            SELECT inventory_add(
                tool="{tool_name}",
                serve_locally=TRUE,
                file="{file_path}",
                filename="{matched_file}",
                accessor="file"
            ) AS Result FROM scope()
            '''
            request = api_pb2.VQLCollectorArgs(
                max_wait=60, max_row=10,
                Query=[api_pb2.VQLRequest(VQL=vql)]
            )
            success = False
            file_hash = None
            for response in stub.Query(request, timeout=65):
                if response.Response:
                    data = json.loads(response.Response)
                    if data and len(data) > 0 and data[0].get('Result'):
                        success = True
                        # Get the hash for copying to filestore
                        file_hash = data[0]['Result'].get('hash', '')

            if success:
                log(f"  ✓ {tool_name} -> {matched_file}", "success")
                results["configured"].append(tool_name)

                # Copy file to filestore (inventory_add doesn't always do this)
                if file_hash:
                    copy_vql = f'''
                    SELECT copy(
                        filename="{file_path}",
                        accessor="file",
                        dest="/var./public/{file_hash}",
                        permissions="0600"
                    ) FROM scope()
                    '''
                    try:
                        copy_request = api_pb2.VQLCollectorArgs(
                            max_wait=30, max_row=1,
                            Query=[api_pb2.VQLRequest(VQL=copy_vql)]
                        )
                        for _ in stub.Query(copy_request, timeout=35):
                            pass
                    except Exception:
                        pass  # Best effort copy
            else:
                log(f"  ? {tool_name} - no result returned", "warning")
                results["failed"].append(tool_name)

        except Exception as e:
            log(f"  ✗ {tool_name}: {str(e)[:40]}", "warning")
            results["failed"].append(tool_name)

    configured = len(results['configured'])
    already = len(results['already_served'])
    not_found = len(results['file_not_found'])
    failed = len(results['failed'])

    summary = f"Configured: {configured}, Already served: {already}, File not found: {not_found}, Failed: {failed}"
    log(f"Inventory configuration complete. {summary}", "success")

    # Query and log final inventory table
    inventory_table = []
    try:
        vql = "SELECT name, serve_locally, serve_url FROM inventory()"
        request = api_pb2.VQLCollectorArgs(
            max_wait=30, max_row=500,
            Query=[api_pb2.VQLRequest(VQL=vql)]
        )
        for response in stub.Query(request, timeout=35):
            if response.Response:
                data = json.loads(response.Response)
                inventory_table = data
    except Exception as e:
        log(f"Could not query final inventory: {str(e)[:50]}", "warning")

    channel.close()

    # Log inventory table
    if inventory_table:
        log("=" * 60)
        log("VELOCIRAPTOR TOOL INVENTORY")
        log("=" * 60)
        log(f"{'Tool Name':<35} {'Served Locally':<15}")
        log("-" * 60)

        served_count = 0
        for item in sorted(inventory_table, key=lambda x: x.get('name', '')):
            name = item.get('name', 'Unknown')[:34]
            served = "✓ Yes" if item.get('serve_locally') else "✗ No"
            if item.get('serve_locally'):
                served_count += 1
            log(f"{name:<35} {served:<15}")

        log("-" * 60)
        log(f"Total: {len(inventory_table)} tools, {served_count} served locally")
        log("=" * 60)

    return {
        "success": True,
        "results": results,
        "summary": summary,
        "inventory": inventory_table
    }


def ensure_offline_collector_binaries(downloads_dir: str, logger: Callable = None) -> Dict:
    """Verify a Velociraptor offline-collector binary is present for each
    supported platform (windows / linux / darwin).

    Discovery is version-agnostic: any `velociraptor-v<X>-<platform>` file
    counts. This matches the runtime behaviour of
    `services.offline_collector.constants:VELO_CLIENT_PATHS`, which picks
    the highest-version binary per platform from this same directory.

    install.sh's `download_offline_collector_binaries` (in `lib/docker.sh`)
    is what actually downloads the files; this function only reports
    presence so the operator can spot a broken air-gap setup.
    """
    def log(msg, level="info"):
        if logger:
            logger(msg, level)
        print(f"[TOOLS] {msg}", flush=True)

    import glob as _glob

    results = {"already_exists": [], "missing": []}
    min_size = 1 * 1024 * 1024

    # platform_label -> filename suffix glob
    platforms = {
        "windows": "windows-amd64.exe",
        "linux":   "linux-amd64",
        "darwin":  "darwin-amd64",
    }

    for label, suffix in platforms.items():
        pattern = os.path.join(downloads_dir, f"velociraptor-v*-{suffix}")
        # Filter to non-empty regular files; ignore detached signatures.
        matches = [
            p for p in _glob.glob(pattern)
            if os.path.isfile(p)
            and os.path.getsize(p) >= min_size
            and not p.endswith(".sig")
        ]
        if matches:
            # Newest by mtime is good enough here — operators who keep
            # multiple versions around will see them all in the "found"
            # list.
            for p in matches:
                results["already_exists"].append(os.path.basename(p))
        else:
            label_str = f"velociraptor-v*-{suffix}"
            log(f"  Missing for {label}: no {label_str} in {downloads_dir} (run install.sh's offline-collector download step)", "warning")
            results["missing"].append(label_str)

    exist_count = len(results["already_exists"])
    missing_count = len(results["missing"])

    if missing_count > 0:
        log(f"Offline Collector binaries: {exist_count} present, {missing_count} platform(s) missing", "warning")
    else:
        log(f"Offline Collector binaries: all {len(platforms)} platforms present ({exist_count} file(s))")

    return results


def download_and_configure_tools(logger: Callable = None, run_id: Optional[str] = None) -> Dict:
    """Main function: Download tools and configure Velociraptor inventory.

    This is the function called from maintenance workflow.
    `run_id` propagates the workflow's cancel event into the per-file
    HTTP streams + the per-tool loop so Stop is honoured immediately.
    """
    def log(msg, level="info"):
        if logger:
            logger(msg, level)
        print(f"[TOOLS] {msg}", flush=True)

    log("Starting tool download and configuration...")

    # Ensure Offline Collector binaries are present (any version — pin
    # comes from config.yaml's `versions.velociraptor` and is enforced by
    # install.sh; this just verifies the files actually landed).
    # These go to /app/downloads which maps to modules/nginx/html/downloads/
    downloads_dir = "/app/downloads"
    log("Checking Velociraptor offline-collector binaries...")
    offline_results = ensure_offline_collector_binaries(downloads_dir, log)

    exist_count = len(offline_results.get('already_exists', []))
    missing_count = len(offline_results.get('missing', []))

    if missing_count > 0:
        log(f"Offline Collector binaries: {exist_count} found, {missing_count} missing (run install.sh with internet)", "warning")
    else:
        log(f"Offline Collector binaries: all {exist_count} present")

    # Load config
    config = load_tools_config()
    if not config:
        log("Failed to load tools_inventory.yaml", "error")
        return {"success": False, "error": "Config file not found"}

    settings = config.get('settings', {})

    # Tools directory - persistent storage in data folder
    # Host path: /home/tenroot/intact/data/tools (or /app/data/tools in container)
    # Mapped to /tools in Velociraptor container
    host_tools_dir = os.environ.get('HOST_TOOLS_PATH', '/app/data/tools')
    container_tools_dir = settings.get('tools_directory', '/tools')

    log(f"Host tools directory: {host_tools_dir}")
    log(f"Container tools directory: {container_tools_dir}")

    # Phase 1: Download tools to host directory
    log("=" * 50)
    log("PHASE 1: Downloading tools from GitHub/URLs")
    log("=" * 50)

    download_results = download_tools_from_config(host_tools_dir, config, log, run_id=run_id)
    if download_results.get("cancelled"):
        return {"success": False, "cancelled": True, "download_results": download_results,
                "summary": "Cancelled by user"}

    downloaded = len(download_results.get('downloaded', []))
    already = len(download_results.get('already_exists', []))
    failed = len(download_results.get('failed', []))

    log(f"Download complete: {downloaded} new, {already} existed, {failed} failed")

    # Phase 2: Configure Velociraptor inventory
    log("=" * 50)
    log("PHASE 2: Configuring Velociraptor inventory")
    log("=" * 50)

    inventory_results = configure_inventory(container_tools_dir, config, log)

    return {
        "success": True,
        "download_results": download_results,
        "inventory_results": inventory_results.get('results', {}),
        "summary": f"Downloaded: {downloaded}, Existed: {already}, Failed: {failed} | {inventory_results.get('summary', '')}"
    }


# For direct testing
if __name__ == "__main__":
    result = download_and_configure_tools()
    print(json.dumps(result, indent=2))

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
                    return yaml.safe_load(f)
        except Exception as e:
            print(f"[TOOLS] Error loading {config_path}: {e}", flush=True)
    return None


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
                  logger: Callable = None, timeout: int = 300) -> Optional[str]:
    """Download a file from URL to destination path."""
    def log(msg):
        if logger:
            logger(msg)
        print(f"[TOOLS-DL] {msg}", flush=True)

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
                                headers={'User-Agent': 'MSSP-Tools-Downloader/1.0'})
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
                                logger: Callable = None) -> Dict:
    """Download all enabled tools from configuration."""
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
                    download_url, tools_dir, filename, log
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

        options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)
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

    # Check what's already served
    served_tools = set()
    try:
        vql = "SELECT name, serve_locally FROM inventory() WHERE serve_locally = true"
        request = api_pb2.VQLCollectorArgs(
            max_wait=30, max_row=200,
            Query=[api_pb2.VQLRequest(VQL=vql)]
        )
        for response in stub.Query(request, timeout=35):
            if response.Response:
                data = json.loads(response.Response)
                for item in data:
                    served_tools.add(item.get('name', ''))
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
            for response in stub.Query(request, timeout=65):
                if response.Response:
                    data = json.loads(response.Response)
                    if data and len(data) > 0 and data[0].get('Result'):
                        success = True

            if success:
                log(f"  ✓ {tool_name} -> {matched_file}", "success")
                results["configured"].append(tool_name)
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


def download_and_configure_tools(logger: Callable = None) -> Dict:
    """Main function: Download tools and configure Velociraptor inventory.

    This is the function called from maintenance workflow.
    """
    def log(msg, level="info"):
        if logger:
            logger(msg, level)
        print(f"[TOOLS] {msg}", flush=True)

    log("Starting tool download and configuration...")

    # Load config
    config = load_tools_config()
    if not config:
        log("Failed to load tools_inventory.yaml", "error")
        return {"success": False, "error": "Config file not found"}

    settings = config.get('settings', {})

    # Tools directory - persistent storage in data folder
    # Host path: /home/tenroot/new-mssp/data/tools (or /app/data/tools in container)
    # Mapped to /tools in Velociraptor container
    host_tools_dir = os.environ.get('HOST_TOOLS_PATH', '/app/data/tools')
    container_tools_dir = settings.get('tools_directory', '/tools')

    log(f"Host tools directory: {host_tools_dir}")
    log(f"Container tools directory: {container_tools_dir}")

    # Phase 1: Download tools to host directory
    log("=" * 50)
    log("PHASE 1: Downloading tools from GitHub/URLs")
    log("=" * 50)

    download_results = download_tools_from_config(host_tools_dir, config, log)

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

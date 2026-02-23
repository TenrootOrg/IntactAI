#!/usr/bin/env python3
"""
Offline Collector Constants - Shared constants and utilities
"""

import os
import time

# Constants
COLLECTOR_OUTPUT_DIR = "/tmp/offline_collectors"
VELOCIRAPTOR_CONTAINER = "mssp_velociraptor"

# Velociraptor client binary paths (static in nginx/html/downloads)
# NOTE: v0.74.x required for Generic Collector (v0.75+ broke the -- pseudo-flag)
VELO_CLIENT_PATHS = {
    "windows": "/app/downloads/velociraptor-v0.74.1-windows-amd64.exe",
    "linux": "/app/downloads/velociraptor-v0.74.1-linux-amd64",
    "darwin": "/app/downloads/velociraptor-v0.74.1-darwin-amd64"
}

# Default artifacts (same as BestPractice)
# All artifacts verified to exist in Velociraptor 0.75.x
DEFAULT_ARTIFACTS = [
    "Windows.NTFS.MFT",
    "Windows.Sys.AllUsers",
    "Generic.System.Pstree",
    "Windows.Forensics.Usn",
    "Windows.Registry.AppCompatCache",       # Evidence of execution (ShimCache)
    "Windows.Registry.UserAssist",           # Evidence of execution (UserAssist)
    "Windows.EventLogs.RDPAuth",
    "Windows.Forensics.Timeline",
    "Windows.Registry.RecentDocs",
    "Windows.Forensics.SRUM",
    "Windows.Forensics.Prefetch",
    "Windows.System.Amcache",
    "Windows.Network.Netstat",
    "Windows.Forensics.Lnk",
    "Windows.System.Pslist",
    "Windows.Detection.BinaryRename",
    "Windows.Forensics.RecycleBin",
    "Windows.EventLogs.Evtx",
    "Windows.Network.ArpCache",
    "Windows.Sysinternals.Autoruns",
    "Generic.Collectors.File",
    "Windows.Registry.Sysinternals.Eulacheck",
    # Additional detection artifacts
    "Windows.EventLogs.Hayabusa",            # Sigma rule detection
    "Windows.EventLogs.Zircolite",           # Event log analysis
    "Windows.Forensics.PersistenceSniper",   # Persistence detection (Exchange artifact)
]

# Artifacts that work fully OFFLINE (no external tool downloads)
# These are built into the Velociraptor binary and don't need internet
OFFLINE_SAFE_ARTIFACTS = [
    "Windows.NTFS.MFT",
    "Windows.Sys.AllUsers",
    "Generic.System.Pstree",
    "Windows.Forensics.Usn",
    "Windows.Registry.AppCompatCache",       # Evidence of execution (ShimCache)
    "Windows.Registry.UserAssist",           # Evidence of execution (UserAssist)
    "Windows.EventLogs.RDPAuth",
    "Windows.Forensics.Timeline",
    "Windows.Registry.RecentDocs",
    "Windows.Forensics.SRUM",
    "Windows.Forensics.Prefetch",
    "Windows.System.Amcache",
    "Windows.Network.Netstat",
    "Windows.Forensics.Lnk",
    "Windows.System.Pslist",
    "Windows.Detection.BinaryRename",
    "Windows.Forensics.RecycleBin",
    "Windows.EventLogs.Evtx",
    "Windows.Network.ArpCache",
    "Windows.Sysinternals.Autoruns",
    "Generic.Collectors.File",
    "Windows.Registry.Sysinternals.Eulacheck",
]

# Tools that need to be embedded for offline operation
# These are downloaded once to the server and bundled in the collector ZIP
# Format: tool_name -> { windows: download_url, local_path, artifact_param }
EMBEDDABLE_TOOLS = {
    "hayabusa": {
        "download_url": "https://github.com/Yamato-Security/hayabusa/releases/download/v2.18.0/hayabusa-2.18.0-win-x64.zip",
        "local_dir": "/app/downloads/tools",
        "binary_name": "hayabusa.exe",
        "artifact": "Windows.EventLogs.Hayabusa",
        "param_name": "HayabusaExe"  # Parameter to pass local path
    },
    "zircolite": {
        "download_url": "https://github.com/wagga40/Zircolite/releases/download/v2.20.0/zircolite_win10.exe",
        "local_dir": "/app/downloads/tools",
        "binary_name": "zircolite.exe",
        "artifact": "Windows.EventLogs.Zircolite",
        "param_name": "ZircoliteExe"
    },
    "chainsaw": {
        "download_url": "https://github.com/WithSecureLabs/chainsaw/releases/download/v2.9.1/chainsaw_all_platforms+rules.zip",
        "local_dir": "/app/downloads/tools",
        "binary_name": "chainsaw.exe",
        "artifact": "Windows.EventLogs.Chainsaw",
        "param_name": "ChainsawExe"
    }
}

# Artifacts that need external tools (will be embedded if tools are available locally)
TOOL_DEPENDENT_ARTIFACTS = [
    "Windows.EventLogs.Hayabusa",
    "Windows.EventLogs.Zircolite",
    "Windows.EventLogs.Chainsaw",
    "Windows.Forensics.PersistenceSniper",
]

# Artifacts with large embedded YARA rules (>100KB) - cause "config too large" error in official collector
# These work fine in script-based fallback collector (run one-by-one)
# Sizes measured: YaraWebshell=307KB, LolDrivers=173KB, YaraProcessWin=171KB
LARGE_YARA_ARTIFACTS = [
    "DetectRaptor.Generic.Detection.YaraWebshell",    # 307KB - embedded webshell YARA rules
    "DetectRaptor.Windows.Detection.Yara.LolDrivers", # 173KB - LOLDrivers signatures
    "DetectRaptor.Windows.Detection.YaraProcessWin",  # 171KB - process memory YARA rules
]

# Artifacts that truly cannot work offline (dynamic rule downloads - NOT tools)
# Tools like Autoruns, Hayabusa, etc. should be served locally via serve_locally=true
ONLINE_REQUIRED_ARTIFACTS = [
    "Windows.Detection.Yara.Process",        # Downloads YARA rules dynamically (not a tool)
]

# Quick Triage artifacts - VERY fast execution only (< 2 minutes total)
QUICK_TRIAGE_ARTIFACTS = [
    "Windows.System.Pslist",           # Running processes (instant)
    "Generic.System.Pstree",           # Process tree (instant)
    "Windows.Network.Netstat",         # Network connections (instant)
    "Windows.Network.ArpCache",        # ARP cache (instant)
    "Windows.Detection.BinaryRename",  # Renamed system binaries (fast)
]


def get_collector_file(file_id):
    """Get the path to a generated collector file (EXE, script, or ZIP bundle)

    Prioritizes official .exe collectors over script-based files.
    Uses EXACT matching only to prevent serving wrong/stale files.
    """
    if not os.path.exists(COLLECTOR_OUTPUT_DIR):
        print(f"[OFFLINE] Collector directory doesn't exist: {COLLECTOR_OUTPUT_DIR}", flush=True)
        return None

    # Priority 1: Try exact match for official collector (.exe for Windows)
    exe_name = f"OfflineCollector_{file_id}.exe"
    exe_path = os.path.join(COLLECTOR_OUTPUT_DIR, exe_name)
    if os.path.exists(exe_path) and os.path.getsize(exe_path) > 0:
        print(f"[OFFLINE] Found .exe: {exe_path} ({os.path.getsize(exe_path)} bytes)", flush=True)
        return exe_path

    # Priority 2: Try PowerShell script (.ps1 for Windows)
    # Script names are like: Collect_Agentic_Full_Triage.ps1
    for f in os.listdir(COLLECTOR_OUTPUT_DIR):
        if f.endswith('.ps1'):
            # Extract the name part from file_id (remove _windows suffix)
            base_id = file_id.replace('_windows', '')
            if base_id in f:
                ps1_path = os.path.join(COLLECTOR_OUTPUT_DIR, f)
                if os.path.getsize(ps1_path) > 0:
                    print(f"[OFFLINE] Found .ps1: {ps1_path} ({os.path.getsize(ps1_path)} bytes)", flush=True)
                    return ps1_path

    # Priority 3: Try shell script (.sh for Linux/Mac)
    for f in os.listdir(COLLECTOR_OUTPUT_DIR):
        if f.endswith('.sh'):
            # Extract the name part from file_id (remove _linux/_darwin suffix)
            base_id = file_id.replace('_linux', '').replace('_darwin', '')
            if base_id in f:
                sh_path = os.path.join(COLLECTOR_OUTPUT_DIR, f)
                if os.path.getsize(sh_path) > 0:
                    print(f"[OFFLINE] Found .sh: {sh_path} ({os.path.getsize(sh_path)} bytes)", flush=True)
                    return sh_path

    # Priority 4: Try exact match for script-based bundle (.zip)
    zip_name = f"OfflineCollector_{file_id}.zip"
    zip_path = os.path.join(COLLECTOR_OUTPUT_DIR, zip_name)
    if os.path.exists(zip_path) and os.path.getsize(zip_path) > 0:
        print(f"[OFFLINE] Found .zip: {zip_path} ({os.path.getsize(zip_path)} bytes)", flush=True)
        return zip_path

    # Priority 5: Try exact match for Linux/Mac official collector (no extension)
    binary_name = f"OfflineCollector_{file_id}"
    binary_path = os.path.join(COLLECTOR_OUTPUT_DIR, binary_name)
    if os.path.exists(binary_path) and os.path.getsize(binary_path) > 0:
        print(f"[OFFLINE] Found binary: {binary_path} ({os.path.getsize(binary_path)} bytes)", flush=True)
        return binary_path

    # NO FALLBACK to partial matching - this was causing the bug where wrong files were served
    print(f"[OFFLINE] File not found for ID: {file_id}", flush=True)
    if os.path.exists(COLLECTOR_OUTPUT_DIR):
        available = os.listdir(COLLECTOR_OUTPUT_DIR)
        print(f"[OFFLINE] Available files: {available}", flush=True)

    return None


def cleanup_old_collectors(days=7):
    """Clean up collector files and bundle directories older than specified days"""
    try:
        if not os.path.exists(COLLECTOR_OUTPUT_DIR):
            return 0

        cutoff = time.time() - (days * 24 * 60 * 60)
        cleaned = 0

        for filename in os.listdir(COLLECTOR_OUTPUT_DIR):
            filepath = os.path.join(COLLECTOR_OUTPUT_DIR, filename)
            if os.path.getmtime(filepath) < cutoff:
                os.remove(filepath)
                cleaned += 1

        print(f"[OFFLINE] Cleaned up {cleaned} old collector files", flush=True)
        return cleaned
    except Exception as e:
        print(f"[OFFLINE] Cleanup error: {e}", flush=True)
        return 0

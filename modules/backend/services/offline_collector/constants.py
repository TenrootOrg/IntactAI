#!/usr/bin/env python3
"""
Offline Collector Constants - Shared constants and utilities
"""

import os
import shutil
import time

# Constants
COLLECTOR_OUTPUT_DIR = "/tmp/offline_collectors"
VELOCIRAPTOR_CONTAINER = "intact_velociraptor"

# Velociraptor client binary paths.
#
# Resolved at import time by scanning `/app/downloads/` for whichever
# Velociraptor binaries are present. Picks the highest-version file per
# platform when multiple are around.
#
# Source of truth for the version is `versions.velociraptor` in the
# repo's `config.yaml`; install.sh's
# `lib/docker.sh:download_offline_collector_binaries` reads that value,
# downloads the matching binaries into `/app/downloads/`, and removes
# any stale binaries from a prior version pin. The backend then auto-
# discovers whatever's there — no edits to this file are needed when
# the version bumps, just a backend restart.
import glob
import os
import re

_DOWNLOADS_DIR = "/app/downloads"


def _semver_key(version: str):
    """Sort key for `0.76.5` style version strings; missing/non-numeric
    parts sort last so `velociraptor-v0.76-linux-amd64` (no patch) sorts
    below `velociraptor-v0.76.5-linux-amd64`."""
    parts = []
    for chunk in version.split("."):
        try:
            parts.append((0, int(chunk)))
        except ValueError:
            parts.append((1, chunk))
    return tuple(parts)


def _discover_latest_binary(platform_glob: str) -> str:
    """Return the absolute path to the highest-version binary matching
    `velociraptor-v<version>-<platform_glob>` in `_DOWNLOADS_DIR`, or
    empty string if none found."""
    pattern = os.path.join(_DOWNLOADS_DIR, f"velociraptor-v*-{platform_glob}")
    candidates = []
    for path in glob.glob(pattern):
        m = re.search(r"velociraptor-v([\d.]+)-", os.path.basename(path))
        if not m:
            continue
        candidates.append((_semver_key(m.group(1)), path))
    if not candidates:
        return ""
    candidates.sort(key=lambda x: x[0])
    return candidates[-1][1]


def get_velo_client_path(os_type: str) -> str:
    """Resolve the velociraptor client binary path for the given OS,
    fresh from /app/downloads/ on every call.

    Replaces the old `VELO_CLIENT_PATHS` dict that resolved at import
    time and stranded the collector at the old binary path after a
    velociraptor upgrade. Concrete failure (2026-06-15): upgrade
    0.76.1 → 0.76.6 ran Phase 1 backend restart BEFORE Phase 2 swapped
    the binaries on disk; the new backend process imported this module
    while v0.76.1 binaries were still present, cached those paths,
    and never re-resolved after Phase 2 placed v0.76.6. The collector
    generator then tried to read `velociraptor-v0.76.1-windows-amd64.exe`
    from disk and failed with "Velociraptor binary not found".
    Re-running `_discover_latest_binary` per lookup eliminates the
    cache. Cost is one `glob.glob` per collector generation (~ms),
    dwarfed by the docker copy + repack work.
    """
    platform_glob = {
        "windows": "windows-amd64.exe",
        "linux":   "linux-amd64",
        "darwin":  "darwin-amd64",
    }.get(os_type)
    if not platform_glob:
        return ""
    return _discover_latest_binary(platform_glob)


class _LazyVeloPaths(dict):
    """Backwards-compat shim — existing `VELO_CLIENT_PATHS["windows"]`
    callsites work unchanged, but each lookup triggers a fresh
    `_discover_latest_binary` scan via `get_velo_client_path()`.

    Note for future callers: this implements only `__getitem__`. Don't
    iterate it, don't call `.get()`, don't call `.keys()` — use
    `get_velo_client_path(os_type)` directly instead. The shim exists
    purely so that the six existing direct-lookup sites in
    `generator.py` keep working without touching them.
    """
    def __getitem__(self, key):
        return get_velo_client_path(key)


VELO_CLIENT_PATHS = _LazyVeloPaths()

# Default artifacts (same as BestPractice)
# All artifacts verified to exist in Velociraptor 0.75.x
# Number of artifacts the offline collector runs in parallel. Velociraptor's
# Server.Utils.CreateCollector defaults opt_concurrency to 2 — far too low for a
# multi-artifact triage: a couple of slow detection artifacts (e.g.
# DetectRaptor.Windows.Detection.BinaryRename, ZoneIdentifier) seize both slots for
# hours and every other artifact "Timed out in concurrency control" without ever
# starting (observed 2026-06-24: a 31-artifact BestPractice run collected only 5
# artifacts in ~2h53m). cpu_limit still caps total CPU, so a higher slot count just
# stops fast artifacts from starving behind slow ones. Override per blueprint via
# settings.concurrency.
DEFAULT_COLLECTOR_CONCURRENCY = 8

# Per-query no-progress watchdog (seconds). Velociraptor's CreateCollector already
# defaults this to 1800, so setting it changes nothing unless a blueprint overrides
# via settings.progress_timeout — it's exposed here only to make the value tunable
# and explicit. A single artifact that stalls (e.g. a glob wedged on a dead network
# mount) is terminated after this long with no progress, while opt_timeout caps the
# whole collection.
DEFAULT_COLLECTOR_PROGRESS_TIMEOUT = 1800

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

# Linux triage set — the analogue of the Windows KAPE sweep above, restricted to
# artifacts that EXIST and actually collect on a Linux endpoint (verified against
# the velociraptor binary the platform ships, v0.77.x). Deliberately excludes the
# broad cross-OS filesystem scanners — see HEAVY_FS_SCAN_ARTIFACTS below.
LINUX_DEFAULT_ARTIFACTS = [
    "Linux.Sys.Pslist",            # Running processes
    "Generic.System.Pstree",       # Process tree (cross-platform)
    "Linux.Network.NetstatEnriched",  # Network connections + owning process
    "Linux.Proc.Arp",              # ARP cache
    "Linux.Sys.Services",          # systemd / init services (persistence)
    "Linux.Sys.Crontab",           # cron persistence
    "Linux.Ssh.AuthorizedKeys",    # SSH backdoor keys
    "Linux.Ssh.KnownHosts",        # Lateral-movement targets
    "Linux.Sys.BashHistory",       # Command history (execution evidence)
    "Linux.Sys.LastUserLogin",     # wtmp/btmp logon history
    "Linux.Sys.Users",             # /etc/passwd accounts
    "Linux.Sys.Groups",            # /etc/group membership
    "Linux.Sys.SUID",              # SUID binaries (privesc)
    "Linux.Proc.Modules",          # Loaded kernel modules (rootkits)
    "Linux.Syslog.SSHLogin",       # SSH auth events
    "Linux.Forensics.Journal",     # systemd journal
    "Linux.Debian.Packages",       # Installed packages (best-effort, Debian/Ubuntu)
]

# macOS triage set — best-effort; the velociraptor binary ships only a handful of
# MacOS.* artifacts. Kept minimal so a darwin collector gathers something useful
# rather than the Windows set.
DARWIN_DEFAULT_ARTIFACTS = [
    "MacOS.Sys.Pslist",
    "Generic.System.Pstree",
    "MacOS.Network.Netstat",
]

ARTIFACTS_BY_OS = {
    "windows": DEFAULT_ARTIFACTS,
    "linux":   LINUX_DEFAULT_ARTIFACTS,
    "darwin":  DARWIN_DEFAULT_ARTIFACTS,
}

# Cross-OS ('Generic.*' / 'DetectRaptor.Generic.*') artifacts that walk the entire
# filesystem. On Windows they scope to user-profile dirs and finish fast; on Linux
# the same globs expand to '/' and crawl /proc, /sys and /var/lib/docker overlay
# mounts, chasing symlink cycles. That is what turned a Linux triage into a ~1h
# run with thousands of "Globber: Symlink cycle detected" lines. Dropped from any
# non-Windows collector.
HEAVY_FS_SCAN_ARTIFACTS = {
    "Generic.Collectors.File",
    "Generic.Forensic.SQLiteHunter",
    "Generic.Detection.Yara.Glob",
    "DetectRaptor.Generic.Detection.YaraWebshell",
}

_OS_ARTIFACT_PREFIX = {"windows": "Windows.", "linux": "Linux.", "darwin": "MacOS."}
_ALL_OS_PREFIXES = ("Windows.", "Linux.", "MacOS.")


def artifacts_for_os(os_type, configured=None):
    """Filter an artifact list to ones that apply to the collector's TARGET OS.

    The blueprints are Windows-centric: ``DEFAULT_ARTIFACTS`` and most saved configs
    are full of ``Windows.*`` artifacts. The collector *binary* is already chosen
    per-OS (``get_velo_client_path``), but if a Linux/macOS binary is fed Windows
    artifacts you hit the v0.77 failure mode reported on the vagrant box: ``Symbol
    Memory not found`` / ``TokenIsElevated not found``, ``users()``/``token()`` "not
    implemented for linux_amd64_cgo", ``Unknown filesystem accessor ntfs``/
    ``registry``, Windows ``.exe`` helper tools that can't exec, and the broad
    Generic scanners crawling the whole filesystem. The reverse (a Linux blueprint
    built for a Windows target) is just as broken.

    Rules:
      * Drop artifacts prefixed for a *different* OS (e.g. ``Windows.*`` on a Linux
        target, ``Linux.*`` on a Windows target).
      * On a non-Windows target also drop the heavy ``Generic.*`` filesystem
        scanners (``HEAVY_FS_SCAN_ARTIFACTS``) — fine on a scoped Windows profile,
        a multi-hour /proc + /sys + docker crawl on Linux. Light ``Generic.*`` and
        ``Custom.*`` artifacts are kept for every OS.
      * If nothing OS-native survives (the common case: a Windows-only blueprint
        pointed at a Linux host), fall back to the curated OS triage set in
        ``ARTIFACTS_BY_OS`` so the collector still gathers real evidence instead of
        erroring out.
      * Unknown ``os_type`` -> return the list unchanged (don't mangle it).
    """
    configured = list(configured) if configured else list(DEFAULT_ARTIFACTS)
    prefix = _OS_ARTIFACT_PREFIX.get(os_type)
    if not prefix:
        return configured
    foreign = tuple(p for p in _ALL_OS_PREFIXES if p != prefix)

    def _applies(a):
        if a.startswith(foreign):
            return False                      # another OS's artifact
        if os_type != "windows" and a in HEAVY_FS_SCAN_ARTIFACTS:
            return False                      # broad scanner — crawls all of / on Linux/macOS
        return True

    kept = [a for a in configured if _applies(a)]
    if not any(a.startswith(prefix) for a in kept):
        # No OS-native artifact survived -> use the curated OS triage set.
        return list(ARTIFACTS_BY_OS.get(os_type, configured))
    return kept


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
    """Clean up collector files and bundle directories older than specified days.

    Never wired up before this — generator.py leaves `bundle_*` temp
    directories (and the generated ZIPs/binaries) in COLLECTOR_OUTPUT_DIR
    forever otherwise. Also previously would have crashed on the first
    bundle directory it hit (os.remove() raises IsADirectoryError), silently
    aborting the whole sweep via the outer except — each item is now handled
    independently so one bad entry doesn't stop the rest from being swept.
    """
    if not os.path.exists(COLLECTOR_OUTPUT_DIR):
        return 0

    cutoff = time.time() - (days * 24 * 60 * 60)
    cleaned = 0

    for filename in os.listdir(COLLECTOR_OUTPUT_DIR):
        filepath = os.path.join(COLLECTOR_OUTPUT_DIR, filename)
        try:
            if os.path.getmtime(filepath) >= cutoff:
                continue
            if os.path.isdir(filepath):
                shutil.rmtree(filepath, ignore_errors=True)
            else:
                os.remove(filepath)
            cleaned += 1
        except Exception as e:
            print(f"[OFFLINE] Cleanup error on {filename}: {e}", flush=True)

    print(f"[OFFLINE] Cleaned up {cleaned} old collector file(s)/dir(s)", flush=True)
    return cleaned

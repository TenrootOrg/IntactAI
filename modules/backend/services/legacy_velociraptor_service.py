"""
Legacy Velociraptor support service.

Repacks the legacy Velociraptor binary with the live server's
client.config.yaml so it can be deployed on Windows hosts that the
modern 0.76+ binary refuses to run on (Server 2008 R2, Win 7) because
Go 1.22+ dropped support for those kernels.

Sources for the legacy binary:
  - 'offline' (default): use the binary install.sh pre-downloaded into
    modules/nginx/html/downloads/. Air-gap friendly. Version comes from
    `versions.velociraptor_legacy` in config.yaml.
  - 'online': fetch the requested version from
    github.com/Velocidex/velociraptor at request time. Useful if the
    bundled version is stale, or the operator wants to try a different
    legacy release without re-running install.sh.

The repack itself uses Velociraptor's CLI (`config repack --exe`),
which the legacy 0.7.x and modern 0.76+ binaries both support with
the same flag shape. We run the LINUX legacy binary as the repacker
inside the backend container and have it embed the config into the
WINDOWS legacy binary -- both ship as side-by-side files in the same
downloads directory.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from typing import Dict, Optional, Tuple

# Project layout — INTACT_HOST_PATH is bind-mounted into the backend
# container at the same path, so this works from inside the container too.
INSTALL_ROOT = os.environ.get("INTACT_HOST_PATH", "/home/tenroot/intact")
DOWNLOADS_DIR = os.path.join(INSTALL_ROOT, "modules", "nginx", "html", "downloads")
LEGACY_CACHE_DIR = "/tmp/intact-legacy-velo"

VELO_CONTAINER = "intact_velociraptor"


# ---------------------------------------------------------------------------
# Config + filename helpers
# ---------------------------------------------------------------------------


def _read_default_legacy_version() -> str:
    """Pull `versions.velociraptor_legacy` from config.yaml. Falls back to
    0.7.1 if config can't be read — that's the documented default."""
    try:
        import yaml
        with open(os.path.join(INSTALL_ROOT, "config.yaml")) as f:
            cfg = yaml.safe_load(f) or {}
        return str((cfg.get("versions") or {}).get("velociraptor_legacy") or "0.7.1")
    except Exception:
        return "0.7.1"


def _binary_filename(version: str, platform: str) -> str:
    """GitHub release filename. Legacy releases use the full-version
    naming convention: velociraptor-v0.7.1-windows-amd64.exe etc.

    Special case: 'linux-amd64-musl' for the statically-linked variant
    that has no glibc dependency — required for old-glibc Linux hosts
    (CentOS 7/RHEL 7) where the plain linux-amd64 build crashes at load
    with `GLIBC_2.28 not found`. Both .exe / musl have no suffix.
    """
    suffix = ".exe" if platform == "windows-amd64" else ""
    return f"velociraptor-v{version}-{platform}{suffix}"


def _github_url(version: str, platform: str) -> str:
    fn = _binary_filename(version, platform)
    return f"https://github.com/Velocidex/velociraptor/releases/download/v{version}/{fn}"


def _cached_path(version: str, platform: str) -> str:
    """Where install.sh's downloader puts the bundled legacy binary."""
    return os.path.join(DOWNLOADS_DIR, _binary_filename(version, platform))


# ---------------------------------------------------------------------------
# Binary acquisition
# ---------------------------------------------------------------------------


def get_legacy_binary(version: Optional[str] = None,
                      platform: str = "windows-amd64",
                      source: str = "offline") -> str:
    """Return a filesystem path to the legacy Velociraptor binary.

    Args:
        version: e.g. '0.7.1'. Defaults to versions.velociraptor_legacy
            from config.yaml.
        platform: 'windows-amd64' | 'linux-amd64' | 'darwin-amd64'.
        source: 'offline' (use install.sh cache) | 'online' (fetch from
            GitHub at request time, cached under /tmp).

    Raises:
        FileNotFoundError if offline mode and the binary isn't cached.
        RuntimeError if online download fails.
    """
    v = version or _read_default_legacy_version()

    if source == "offline":
        cached = _cached_path(v, platform)
        if not os.path.exists(cached):
            raise FileNotFoundError(
                f"Legacy Velociraptor binary not present at {cached}. "
                f"Either re-run install.sh (which calls "
                f"download_legacy_velociraptor_binaries) or use source='online' "
                f"to fetch from GitHub at request time."
            )
        if os.path.getsize(cached) < 1024 * 1024:
            raise RuntimeError(
                f"Legacy binary at {cached} is suspiciously small "
                f"({os.path.getsize(cached)} bytes) — likely a failed download. "
                f"Delete it and retry."
            )
        return cached

    if source == "online":
        os.makedirs(LEGACY_CACHE_DIR, exist_ok=True)
        dest = os.path.join(LEGACY_CACHE_DIR, _binary_filename(v, platform))
        if os.path.exists(dest) and os.path.getsize(dest) > 1024 * 1024:
            return dest
        url = _github_url(v, platform)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "intactai-legacy-velociraptor/1.0"})
            with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as out:
                shutil.copyfileobj(resp, out)
            os.chmod(dest, 0o755)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"GitHub returned HTTP {e.code} for {url}") from e
        except Exception as e:
            raise RuntimeError(f"Failed to download {url}: {e}") from e
        return dest

    raise ValueError(f"Unknown source: {source!r}. Use 'offline' or 'online'.")


# ---------------------------------------------------------------------------
# Repack
# ---------------------------------------------------------------------------


# Strict allowlist verified to repack successfully against legacy 0.7.1.
# Anything beyond this triggers "Unable to load config from any source"
# (typically: `version` block carrying a go1.22+ compiler string, or
# `local_buffer` schema added post-0.7.1). Verified empirically by
# building a minimum config that worked, not by exhaustive testing —
# add only with verification.
_LEGACY_CLIENT_FIELDS = {
    "server_urls",
    "ca_certificate",
    "nonce",
    "writeback_darwin", "writeback_linux", "writeback_windows",
    "tempdir_windows", "tempdir_linux", "tempdir_darwin",
    "max_poll",
    "nanny_max_connection_delay",
}


def _fetch_client_config(out_path: str) -> None:
    """Pull /velociraptor/client.config.yaml out of the running velociraptor
    container and adapt it to the legacy schema.

    Modern Velociraptor (0.76+) writes a client.config.yaml with a
    top-level `version:` block and several `Client:` fields (e.g.
    `level2_writeback_suffix`) that legacy 0.7.x parsers reject outright
    with "Unable to load config from any source". We filter the Client
    section down to known-good 0.7.x fields and drop the version block
    before passing to the legacy repacker.

    The kept fields (server URL, CA cert, nonce, writeback paths, poll
    cadence) are sufficient for a legacy client to beacon back to the
    modern server."""
    import yaml as _yaml

    result = subprocess.run(
        ["docker", "exec", VELO_CONTAINER,
         "cat", "/velociraptor/client.config.yaml"],
        capture_output=True, timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Could not read client.config.yaml from {VELO_CONTAINER}: "
            f"{result.stderr.decode('utf-8', errors='replace')[:200]}"
        )

    try:
        full_cfg = _yaml.safe_load(result.stdout) or {}
    except Exception as e:
        raise RuntimeError(f"client.config.yaml parse failed: {e}") from e

    client_section = (full_cfg.get("Client") or {})
    if not client_section.get("server_urls") or not client_section.get("ca_certificate"):
        raise RuntimeError(
            "client.config.yaml is missing server_urls or ca_certificate — "
            "the running Velociraptor server hasn't finished initialization."
        )

    legacy_cfg = {
        "Client": {k: v for k, v in client_section.items()
                   if k in _LEGACY_CLIENT_FIELDS},
    }

    with open(out_path, "w") as f:
        _yaml.safe_dump(legacy_cfg, f)


# Target → tuple of (binary platform tag, output filename suffix).
# Linux output has no suffix (just a bare executable); Windows is .exe.
# For the linux target we prefer the musl-static build because the
# plain linux-amd64 still imports GLIBC_2.28 symbols and crashes on
# old glibc hosts (CentOS 7 / RHEL 7 / Ubuntu 16.04). The musl build
# is statically linked with zero shared-lib deps and runs on ANY
# Linux x86_64 with kernel >= 2.6.32. If the musl variant isn't
# cached (older installs that pre-date the musl download), we fall
# back to the plain build in get_legacy_binary().
_TARGET_MAP = {
    "windows": ("windows-amd64",     ".exe"),
    "linux":   ("linux-amd64-musl",  ""),
}
# Fallback platform tag per target — used when the preferred binary
# isn't cached and we want to try one more spelling before giving up.
_TARGET_FALLBACK = {
    "linux": "linux-amd64",
}


def build_legacy_client(target: str = "windows",
                        version: Optional[str] = None,
                        source: str = "offline") -> Dict:
    """Produce a deployable legacy client (Windows .exe OR Linux ELF) with
    the live server's client.config.yaml embedded.

    Args:
        target: 'windows' or 'linux'. Selects which legacy binary to
            repack into the final deliverable.
        version: legacy version (defaults to versions.velociraptor_legacy
            in config.yaml).
        source: 'offline' (install.sh cache) | 'online' (GitHub fetch).

    Returns: {success, path, filename, size, version, source, target}
        or {success: False, error}.

    The repack always uses the LINUX legacy binary as the repacker
    (regardless of target) because that's what runs inside the backend
    container; `--exe <target_bin>` tells it which platform's binary to
    embed the config into. Both 0.7.x and 0.76+ accept identical flag
    shape, so the recipe is portable across versions.
    """
    if target not in _TARGET_MAP:
        return {"success": False, "error": f"unknown target {target!r} (use 'windows' or 'linux')"}
    plat_tag, out_suffix = _TARGET_MAP[target]
    v = version or _read_default_legacy_version()

    try:
        # The LINUX legacy binary is always the repacker (we run it inside
        # the backend container which is Linux). Try the platform's
        # preferred tag first; on FileNotFoundError fall back to the
        # backup tag if one is configured — handles installs that
        # pre-date the musl download.
        def _acquire(tag):
            try:
                return get_legacy_binary(v, tag, source)
            except FileNotFoundError:
                fb = _TARGET_FALLBACK.get(target)
                if fb and fb != tag:
                    return get_legacy_binary(v, fb, source)
                raise

        # Repacker is always the linux build — pick whichever is cached.
        try:
            linux_bin = get_legacy_binary(v, "linux-amd64-musl", source)
        except FileNotFoundError:
            linux_bin = get_legacy_binary(v, "linux-amd64", source)
        target_bin = linux_bin if target == "linux" else _acquire(plat_tag)
    except Exception as e:
        return {"success": False, "error": f"binary acquisition failed: {e}"}

    try:
        os.chmod(linux_bin, 0o755)
    except Exception:
        pass

    work = tempfile.mkdtemp(prefix="intact-legacy-repack-")
    cfg_path = os.path.join(work, "client.config.yaml")
    out_path = os.path.join(work, f"velociraptor_client_legacy_v{v}{out_suffix}")

    try:
        _fetch_client_config(cfg_path)
    except Exception as e:
        shutil.rmtree(work, ignore_errors=True)
        return {"success": False, "error": str(e)}

    # `velociraptor config repack --exe <target_bin> <config> <output>`
    # works for both linux and windows targets; the legacy linux binary
    # just stamps the config blob into the chosen target binary.
    cmd = [linux_bin, "config", "repack",
           "--exe", target_bin,
           cfg_path, out_path]
    proc = subprocess.run(cmd, capture_output=True, timeout=180)

    if proc.returncode != 0 or not os.path.exists(out_path):
        # Velociraptor prints a banner (~13 lines) before any real error
        # message — strip [INFO] lines so the actual error survives the
        # truncation budget below.
        def _filter(b: bytes) -> str:
            text = b.decode("utf-8", errors="replace")
            return "\n".join(
                line for line in text.splitlines()
                if not line.lstrip().startswith("[INFO]")
            )
        err = _filter(proc.stderr) or _filter(proc.stdout) or "(no output)"
        shutil.rmtree(work, ignore_errors=True)
        return {"success": False, "error": f"repack failed (rc={proc.returncode}): {err[:800]}"}

    size = os.path.getsize(out_path)
    if size < 1024 * 1024:
        shutil.rmtree(work, ignore_errors=True)
        return {"success": False, "error": f"repacked binary is suspiciously small ({size} bytes)"}

    # Move out of tempdir so callers can serve the file. Stable predictable
    # location keyed by target + version + source so repeat calls overwrite
    # cleanly without clobbering other targets.
    persistent_dir = "/tmp/intact-legacy-clients"
    os.makedirs(persistent_dir, exist_ok=True)
    final = os.path.join(
        persistent_dir,
        f"velociraptor_client_legacy_{target}_v{v}_{source}{out_suffix}",
    )
    shutil.move(out_path, final)
    shutil.rmtree(work, ignore_errors=True)

    return {
        "success": True,
        "path": final,
        "filename": f"velociraptor_client_legacy_v{v}{out_suffix}",
        "size": os.path.getsize(final),
        "version": v,
        "source": source,
        "target": target,
        "built_at": int(time.time()),
    }


# Backwards-compat alias: existing route imports build_legacy_windows_client.
# Keep it pointing at the new generalised builder pinned to target=windows so
# the route doesn't need to change in a follow-up commit if it imports the
# old name elsewhere.
def build_legacy_windows_client(version: Optional[str] = None,
                                source: str = "offline") -> Dict:
    return build_legacy_client(target="windows", version=version, source=source)


# ---------------------------------------------------------------------------
# Status — for the UI
# ---------------------------------------------------------------------------


def legacy_status() -> Dict:
    """Snapshot of what's available so the UI can grey out buttons
    correctly. Cheap to call (just stats files).

    For the linux-amd64 key we report "available" if EITHER the musl
    variant (preferred — what /api/clients/download/linux-legacy actually
    serves) OR the plain linux-amd64 build is cached. That way the
    Linux Legacy button only greys out when neither is on disk.
    """
    v = _read_default_legacy_version()
    out = {"configured_version": v, "binaries": {}}

    def _probe(plat_tag):
        p = _cached_path(v, plat_tag)
        if os.path.exists(p):
            return {"available": True, "size": os.path.getsize(p), "path": p}
        return None

    # Windows: single platform tag, no fallback.
    out["binaries"]["windows-amd64"] = _probe("windows-amd64") or {"available": False}
    # Linux: prefer musl, fall back to plain. The status entry advertises
    # whichever was found so the UI knows the byte-size of the file that
    # will actually be served.
    linux_entry = _probe("linux-amd64-musl") or _probe("linux-amd64") or {"available": False}
    out["binaries"]["linux-amd64"] = linux_entry
    # macOS: kept for completeness; no UI button uses it today.
    out["binaries"]["darwin-amd64"] = _probe("darwin-amd64") or {"available": False}

    out["offline_ready"] = out["binaries"]["windows-amd64"]["available"]
    return out

"""Ensure velociraptor-collector is ready for offline-collector generation.

Velociraptor's server-side ``client_repack`` (invoked by
``Server.Utils.CreateCollector``) needs the ``velociraptor-collector``
base binary served locally from its tool inventory. When it isn't,
client_repack constructs a github download URL and the whole collector
generation fails — on air-gapped hosts AND on online hosts with
transient DNS hiccups (2026-06-16 incident:
``client_repack: Get ".../velociraptor-collector": lookup github.com on
127.0.0.11:53: server misbehaving``).

The install/upgrade flows already stage + register the binary
(see services/upgrade/velociraptor.py:_ensure_velociraptor_collector_tool),
but this module provides a generation-TIME self-heal so a collector
generation can never statically fail for this reason regardless of how
velociraptor was installed (install.sh, online upgrade, offline apply,
or a hand-rolled deployment that skipped the registration). Called from
the offline-collector route's pre-flight.

The single entry point — ``ensure_collector_tool_ready`` — reuses the
upgrade-flow helper so there's ONE implementation of the stage+register
logic.
"""

from __future__ import annotations

import os
from typing import Callable, Dict, Optional


def _read_velociraptor_version() -> str:
    """Read versions.velociraptor from config.yaml. Falls back to a
    recent pin if config.yaml is unreadable — the version only matters
    for the github download fallback (the local-binary path doesn't
    care), so a stale fallback just means an online host might fetch a
    slightly-off collector, which velociraptor tolerates."""
    workdir = os.environ.get('INTACT_PATH', '/app/workdir')
    config_path = os.path.join(workdir, 'config.yaml')
    try:
        import yaml
        with open(config_path) as f:
            cfg = yaml.safe_load(f) or {}
        v = (cfg.get('versions') or {}).get('velociraptor')
        if v:
            return str(v).lstrip('v')
    except Exception:
        pass
    return '0.76.6'


def ensure_collector_tool_ready(logger: Optional[Callable] = None) -> Dict:
    """Stage + register the velociraptor-collector tool so client_repack
    serves it locally. Safe to call before every generation — idempotent
    and fast when the tool is already registered.

    Returns ``{staged: bool, registered: bool, ...}``. Never raises;
    failures are reported in the return dict so the caller can log + keep
    going.
    """
    log = logger or (lambda msg, level="info": None)
    try:
        from services.velociraptor_collector_tool import _ensure_velociraptor_collector_tool
    except Exception as e:
        log(f"  collector self-heal: could not import helper ({e})", "warning")
        return {"staged": False, "registered": False, "error": str(e)}

    version = _read_velociraptor_version()
    # source="github": stage from upstream only if the binary isn't
    # already on disk (the helper skips the download when /data/tools/
    # already has a valid copy). Registration runs unconditionally.
    try:
        result = _ensure_velociraptor_collector_tool(
            clean_version=version, source="github", logger=log,
        )
        return {
            "staged": result.get("staged", result.get("success", False)),
            "registered": result.get("registered", False),
            "error": result.get("register_error") or result.get("error"),
        }
    except Exception as e:
        log(f"  collector self-heal raised ({type(e).__name__}: {e})", "warning")
        return {"staged": False, "registered": False, "error": str(e)}

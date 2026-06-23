"""Internet connectivity gate for automations that require external network access.

Some automations (online/prepare upgrades, AWS/Azure cloud scans, tool/feed
downloads) cannot do anything useful without egress to the public internet. On
an air-gapped box they would otherwise fail deep inside the workflow with a
confusing DNS/timeout error. `require_internet()` lets each automation fail fast
at the top of its run with a clear "<module> needs an internet connection"
message in the workflow log.
"""

import socket


# Reliable, geographically-distributed endpoints on ports that are rarely
# blocked. We only need ONE to answer to prove the box has a route out. We mix
# raw IPs (proves routing/egress) with a DNS name (proves resolution), so a box
# with DNS but no egress — or egress but no DNS — still reports offline.
_PROBE_TARGETS = (
    ("1.1.1.1", 443),     # Cloudflare
    ("8.8.8.8", 53),      # Google DNS
    ("github.com", 443),  # most upgrade/tool deps live on GitHub; proves DNS
)


def has_internet(timeout: float = 4.0, targets=None) -> bool:
    """Return True if the host can reach the public internet.

    Tries a small set of well-known endpoints and returns True on the first
    successful TCP connect. Pure stdlib (socket) so it works with no extra deps
    and never raises.
    """
    for host, port in (targets or _PROBE_TARGETS):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def require_internet(run_id, module_name, logger=None, targets=None) -> bool:
    """Gate an automation run on internet access.

    Returns True when online. When offline: writes a clear error to the
    workflow log, marks the run ``failed``, and returns False so the caller can
    ``return`` immediately.

    `logger`, if provided, is also called as ``logger(msg, level)`` (used by the
    upgrade flows that mirror logs into their own progress logger).
    """
    if has_internet(targets=targets):
        ok_msg = "✓ Internet connectivity check passed"
        try:
            from services.workflow_service import add_log_to_run
            add_log_to_run(run_id, ok_msg, "info")
        except Exception:
            pass
        if logger:
            try:
                logger(ok_msg, "info")
            except Exception:
                pass
        return True

    msg = (f"❌ {module_name} needs an internet connection — no connectivity "
           f"detected. Aborting.")
    try:
        from services.workflow_service import add_log_to_run, update_run_status
        add_log_to_run(run_id, msg, "error")
        update_run_status(
            run_id, "failed",
            error=f"{module_name} requires an internet connection",
        )
    except Exception:
        pass
    if logger:
        try:
            logger(msg, "error")
        except Exception:
            pass
    return False

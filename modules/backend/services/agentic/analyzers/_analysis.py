#!/usr/bin/env python3
"""
Agentic Analyzers - LLM analysis functions for forensic data
"""

import json
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from services.agentic.constants import (
    TRUNCATE_TOKEN_LIMIT, MAX_LLM_TOKENS,
    OLLAMA_CONTEXT_SIZE, OLLAMA_TIMEOUT_SECONDS,
    ONLINE_LLM_TIMEOUT_SECONDS,
)
from services.agentic.analyzers._llm import *  # noqa: F401,F403

def _compute_data_scope(rows):
    """Pre-compute factual scope of the data for the LLM prompt.

    Returns a dict with the actual min/max timestamps, unique users, unique IPs,
    record count, etc. The LLM is instructed to ONLY reference these values.
    """
    if not rows:
        return {
            'total_count': 0,
            'time_range': 'no data',
            'unique_users': [],
            'unique_ips': [],
            'unique_operations': [],
        }

    # Extract timestamps from various possible fields
    timestamps = []
    users = set()
    ips = set()
    operations = set()

    def _get_first(rec, *keys):
        if not isinstance(rec, dict):
            return None
        for k in keys:
            v = rec.get(k)
            if v:
                return v
        return None

    for r in rows:
        # Records may be findings (with matched_record nested) or raw events
        rec = r.get('matched_record', r) if isinstance(r, dict) else {}
        if not isinstance(rec, dict):
            continue

        ts = _get_first(rec, '_timestamp', 'CreationTime', 'createdDateTime',
                        'activityDateTime', 'TimeGenerated', 'eventDateTime')
        if ts:
            timestamps.append(str(ts))

        user = _get_first(rec, 'UserId', 'userPrincipalName', 'Actor')
        if isinstance(user, str):
            users.add(user)
        elif isinstance(user, list):
            for u in user:
                if isinstance(u, str):
                    users.add(u)
                elif isinstance(u, dict) and u.get('ID'):
                    users.add(u['ID'])

        # initiatedBy.user.userPrincipalName
        ib = rec.get('initiatedBy')
        if isinstance(ib, dict):
            u = ib.get('user', {}) if isinstance(ib.get('user'), dict) else {}
            if u.get('userPrincipalName'):
                users.add(u['userPrincipalName'])

        ip = _get_first(rec, 'ipAddress', 'IPAddress', 'ClientIP', 'ClientIPAddress')
        if isinstance(ip, str):
            ips.add(ip)

        op = _get_first(rec, 'Operation', 'activityDisplayName', 'eventName')
        if isinstance(op, str):
            operations.add(op)

    timestamps.sort()
    distinct_dates = sorted({t[:10] for t in timestamps if len(t) >= 10})

    # Detect state snapshot: no records have timestamps, or every record is marked as one
    is_state_snapshot = (not timestamps) or all(
        (r.get('_state_snapshot') if isinstance(r, dict) else False)
        for r in rows
    )

    if is_state_snapshot:
        time_range = '(state snapshot — no event time range)'
    else:
        time_range = (
            f"{timestamps[0]} → {timestamps[-1]} ({len(distinct_dates)} distinct day(s))"
            if timestamps else 'unknown'
        )

    return {
        'total_count': len(rows),
        'time_range': time_range,
        'distinct_dates': distinct_dates,
        'unique_users': sorted(users)[:50],
        'unique_ips': sorted(ips)[:50],
        'unique_operations': sorted(operations)[:50],
        'is_state_snapshot': is_state_snapshot,
    }


def _sample_records_for_llm(rows, max_count=90):
    """Sample records to send to LLM: first N + last N + random middle.

    Avoids sending thousands of identical records that encourage narrative
    inflation, while still giving the LLM a representative slice.
    """
    import random
    if len(rows) <= max_count:
        return rows, False
    third = max_count // 3
    first = rows[:third]
    last = rows[-third:]
    middle_pool = rows[third:-third] if len(rows) > 2 * third else []
    middle = random.sample(middle_pool, min(third, len(middle_pool))) if middle_pool else []
    return first + middle + last, True


# Opaque Velociraptor identifiers that bloat every row's token cost without
# giving the LLM any analytical leverage. Both the canonical Velociraptor
# casings (ClientId, FlowId) and the underscore variants we add in the hunt
# branch (_client_id) are stripped. Per-host attribution for multi-client
# hunts is preserved at the pipeline / synthesis layer, not in the per-row
# data the analyzer LLM sees.
_LLM_DROP_KEYS = frozenset({
    "ClientId", "client_id", "_client_id",
    "FlowId", "flow_id", "_flow_id",
})


def _strip_metadata_fields(rows):
    """Remove ClientId / FlowId metadata from rows before LLM serialization.
    No-op when the keys aren't present (single-flow path) or rows aren't dicts."""
    if not rows:
        return rows
    out = []
    for r in rows:
        if isinstance(r, dict):
            out.append({k: v for k, v in r.items() if k not in _LLM_DROP_KEYS})
        else:
            out.append(r)
    return out


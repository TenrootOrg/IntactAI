"""Behaviour checks over VPC flow conversations and DNS lookups (netlogs_runner).

No open rule set covers these AWS formats, so these are written here, generic (ports,
counts and shapes, never a vendor or an address list):

  flow logs   many internet hosts accepted on one admin port; one host probing many
              ports/hosts; traffic to well-known mining ports; very large transfers out;
  DNS         a tunnelling shape (many long unique names under one domain); a host
              failing to resolve many names (generated domains); mining-related names.

Findings have the detections._finding shape; one per (check, subject).
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Any, Dict, List

from .cloudtrail_enrich import ADMIN_PORTS

ADMIN_SOURCES_MIN = 20                 # distinct internet sources accepted on one admin port
SCAN_TARGETS_MIN = 100                 # distinct (host, port) one source tried
BIG_OUT_BYTES = 5 * 1024 ** 3          # 5 GiB to one outside address
MINING_PORTS = {3333, 4444, 5555, 7777, 9999, 14433, 14444, 45560, 45700}
TUNNEL_NAMES_MIN = 50                  # long unique names under one domain, one host
TUNNEL_LABEL_LEN = 30
NXDOMAIN_MIN = 200                     # distinct names that did not resolve, one host
MINING_NAME = re.compile(r"(^|[.-])(xmr|monero|stratum|cryptonight|minerpool|miningpool|mining)([.-]|$)", re.I)


def _public(ip) -> bool:
    """Outside the VPC: not an internal range (RFC 1918, CGNAT, ULA), loopback or link-local."""
    from .baseline import _INTERNAL
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not (a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified
                or any(a in n for n in _INTERNAL if n.version == a.version))


def _base_domain(name: str) -> str:
    parts = name.rstrip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def detect(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    from .detections import _finding
    flows = [r for r in records if r.get("EventSource") == "AWS.FlowLogs"]
    dns = [r for r in records if r.get("EventSource") == "AWS.DNSLogs"]
    out = []

    # -- flow logs ---------------------------------------------------------------------
    admin_srcs = defaultdict(set)
    probes = defaultdict(set)
    probe_ex = {}
    for c in flows:
        try:
            port = int(c.get("dstport") or -1)
        except ValueError:
            continue
        src, dst = c.get("srcaddr"), c.get("dstaddr")
        if c.get("action") == "ACCEPT" and port in ADMIN_PORTS and _public(src) and not _public(dst):
            admin_srcs[(dst, port)].add(src)
        if not _public(src):
            probes[src].add((dst, port))
            probe_ex.setdefault(src, c)
        if c.get("action") == "ACCEPT" and not _public(src) and _public(dst) and port in MINING_PORTS:
            out.append(_finding("AWS Instance Connected To A Mining Port", "medium",
                                f"{src} → {dst}:{port} ({c.get('flows')} flows, {c.get('bytes'):,} bytes) — a port crypto-mining pools listen on",
                                c, mitre=("T1496",)))
        if c.get("action") == "ACCEPT" and not _public(src) and _public(dst) and (c.get("bytes") or 0) >= BIG_OUT_BYTES:
            out.append(_finding("AWS Large Transfer Out Of The Network", "low",
                                f"{src} sent {c['bytes'] / 1024 ** 3:.1f} GiB to {dst}:{port} (outside the VPC) between "
                                f"{c.get('eventTime')} and {c.get('lastTime')} — could be a backup or an upload; check the destination",
                                c, mitre=("T1048",)))
    for (dst, port), srcs in admin_srcs.items():
        if len(srcs) >= ADMIN_SOURCES_MIN:
            ex = next(c for c in flows if c.get("dstaddr") == dst and str(c.get("dstport")) == str(port) and c.get("action") == "ACCEPT")
            out.append(_finding("AWS Admin Port Reached By Many Internet Hosts", "medium",
                                f"{len(srcs)} different internet addresses were let in to {dst}:{port} — brute force or scanning "
                                f"against an exposed administrative service",
                                ex, mitre=("T1110", "T1133")))
    for src, targets in probes.items():
        if len(targets) >= SCAN_TARGETS_MIN:
            out.append(_finding("AWS Host Probed Many Ports Or Hosts", "medium",
                                f"{src} tried {len(targets)} different host:port pairs — network scanning from inside the VPC",
                                probe_ex[src], mitre=("T1046",)))

    # -- DNS ---------------------------------------------------------------------------
    long_names = defaultdict(set)
    nx = defaultdict(set)
    ex = {}
    seen_mining = set()
    for q in dns:
        name = str(q.get("query_name") or "").rstrip(".").lower()
        srcids = q.get("srcids") if isinstance(q.get("srcids"), dict) else {}
        src = q.get("srcaddr") or srcids.get("instance")
        if not name:
            continue
        first = name.split(".")[0]
        if len(first) >= TUNNEL_LABEL_LEN:
            long_names[(src, _base_domain(name))].add(name)
            ex.setdefault((src, _base_domain(name)), q)
        if str(q.get("rcode")) == "NXDOMAIN":
            nx[src].add(name)
            ex.setdefault(src, q)
        if MINING_NAME.search(name) and (src, _base_domain(name)) not in seen_mining:
            seen_mining.add((src, _base_domain(name)))
            out.append(_finding("AWS Host Looked Up A Mining-Related Name", "medium",
                                f"{src} resolved {name}", q, mitre=("T1496",)))
    for (src, dom), names in long_names.items():
        if len(names) >= TUNNEL_NAMES_MIN:
            out.append(_finding("AWS DNS Tunnelling Pattern", "medium",
                                f"{src} looked up {len(names)} different long names under {dom} — data or commands carried in DNS",
                                ex[(src, dom)], mitre=("T1071.004", "T1048")))
    for src, names in nx.items():
        if len(names) >= NXDOMAIN_MIN:
            out.append(_finding("AWS Host Failed To Resolve Many Domains", "medium",
                                f"{src} looked up {len(names)} names that do not exist — the pattern of malware generating domains",
                                ex[src], mitre=("T1568.002",)))
    return out

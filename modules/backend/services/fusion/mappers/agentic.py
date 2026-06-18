"""Agentic (Velociraptor) mapper — ``collected_data`` {artifact: [rows]} ->
entities + relationships. ONE agentic run spans N clients, so rows are
SPLIT by their ``_client_id`` tag into per-asset entities (1 run : N hosts).

Domain accounts and IOCs are keyed GLOBALLY (host-independent), so the
same account/IP seen on multiple assets collapses to one node whose
``_assets`` list then exposes lateral movement.
"""

from __future__ import annotations

from .. import keys
from ..schema import Entity, Relationship, EvidenceRef
from ..anomaly import score_row
from ..severity import from_anomaly, from_string
from . import fieldspec as F
from . import details as DET

MODULE = "agentic"

_LOCAL_DOMAINS = {"", "nt authority", "workgroup", "builtin", "font driver host",
                  "window manager", "local service", "network service"}

# Roots a legitimately-installed Windows service binary lives under. A service
# pointing here is NOT suspicious on path alone (svchost, Defender's signed
# ProgramData platform dir, .NET runtime, etc. — every Windows box has these).
_TRUSTED_SVC_ROOTS = (
    "c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\servicing",
    "c:\\windows\\microsoft.net", "c:\\windows\\winsxs",
    "c:\\program files\\", "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\windows defender",
)
# User-writable / odd locations a service binary should never live in.
_SUSPICIOUS_SVC_DIRS = ("\\temp\\", "\\tmp\\", "\\appdata\\", "\\users\\public",
                        "\\downloads\\", "\\$recycle", "\\perflogs\\", "\\windows\\temp\\")
# Interpreters/LOLBins are normal as svchost but abnormal as a service's own image.
_SVC_INTERPRETERS = ("powershell", "cmd.exe", "wscript", "cscript", "mshta",
                     "rundll32", "regsvr32", "msbuild", "installutil")


def _service_anomaly(path: str) -> int:
    """Path-aware service scoring — avoids flagging every svchost/Defender
    service the generic process heuristic would. 0 = trusted, higher = odd."""
    p = (str(path or "")).strip().lower().strip('"')
    if not p:
        return 5                                   # no path is mildly odd
    if p.startswith("\\\\"):
        return 50                                  # UNC-hosted service binary
    if any(d in p for d in _SUSPICIOUS_SVC_DIRS):
        return 50
    if any(p.startswith(r) for r in _TRUSTED_SVC_ROOTS):
        return 0
    img = p.split("-k")[0]                          # the image, before svchost args
    if "svchost.exe" not in img and any(t in img for t in _SVC_INTERPRETERS):
        return 30                                  # interpreter as the service image
    return 8                                        # unrecognised location — note, don't alarm


def _sha256_of(row) -> str | None:
    """SHA256 from a flat column OR a nested Hash struct ({MD5,SHA1,SHA256})."""
    h = F.get(row, "Hash", "Hashes", default=None)
    if isinstance(h, dict):
        v = h.get("SHA256") or h.get("sha256") or h.get("Sha256")
        if v:
            return str(v)
    v = F.get(row, "SHA256", "Sha256", "sha256")
    return str(v) if isinstance(v, str) and v else None


def _hash_attrs(row) -> dict:
    """All non-SHA256 algos for the hash-identity bridge — md5/sha1/imphash from a
    nested Hash struct or flat columns, lowercased. Bridge alias fuel."""
    out = {}
    h = F.get(row, "Hash", "Hashes", default=None)
    src = h if isinstance(h, dict) else row
    for algo, keyset in (("md5", ("MD5", "md5", "Md5")), ("sha1", ("SHA1", "sha1", "Sha1")),
                         ("imphash", ("IMPHASH", "Imphash", "imphash", "ImpHash"))):
        v = None
        for k in keyset:
            if isinstance(src, dict) and src.get(k):
                v = src[k]; break
        if v:
            out[algo] = str(v).strip().lower()
    return out


# Roots where an "untrusted" Authenticode verdict is NOT signal — MS Store apps
# (Program Files\WindowsApps), system + Program Files binaries are catalog-signed,
# which the per-file Authenticode check reports as untrusted though they're legit.
_TRUSTED_IMG_ROOTS = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\",
                      "c:\\programdata\\microsoft\\")


def _image_untrusted_and_odd(row) -> bool:
    """True only when Authenticode says untrusted AND the image lives in a
    user-writable / non-standard location — i.e. actionable, not catalog-signed."""
    a = F.get(row, "Authenticode", default=None)
    if not isinstance(a, dict):
        return False
    if str(a.get("Trusted", "")).strip().lower() != "untrusted":
        return False
    img = str(F.get(row, "Exe", *F.PATH) or a.get("Filename") or "").strip().lower().strip('"')
    if not img:
        return True                                # untrusted with no resolvable path
    return not any(img.startswith(r) for r in _TRUSTED_IMG_ROOTS)


# PowerShell history / scriptblock patterns worth surfacing in the narrative.
_PS_SUSPICIOUS = ("downloadstring", "downloadfile", "iex", "invoke-expression",
                  "frombase64string", "-enc", "-encodedcommand", "-w hidden",
                  "-windowstyle hidden", "bypass", "invoke-webrequest", "iwr ",
                  "new-object net.webclient", "start-bitstransfer", "certutil",
                  "bitsadmin", "add-mppreference", "set-mppreference")


def _ps_anomaly(line: str) -> int:
    low = (str(line or "")).lower()
    return 25 if any(p in low for p in _PS_SUSPICIOUS) else 1


# Hayabusa / SIGMA level -> anomaly. Kept in lock-step with severity.from_anomaly
# buckets (>=100 crit, >=20 high, >=10 medium, >=1 low) so the anomaly-derived
# severity AGREES with the explicit SIGMA level (correlate maxes the two).
_HAYABUSA_ANOM = {"critical": 100, "crit": 100, "high": 50, "medium": 15, "med": 15,
                  "low": 5, "informational": 0, "info": 0}


def _level_anomaly(level) -> int:
    return _HAYABUSA_ANOM.get(str(level or "").strip().lower(), 1)


def _ent(eid, etype, label, asset, run_id, locator, *, anomaly=0, first=None,
         flags=None, **attrs):
    a = {"_assets": [asset]}
    a.update({k: v for k, v in attrs.items() if v not in (None, "", [])})
    return Entity(id=eid, type=etype, label=label, attrs=a, sources=[MODULE],
                  evidence=[EvidenceRef(MODULE, run_id, locator)], anomaly=anomaly,
                  severity=from_anomaly(anomaly), first_seen=first,
                  last_seen=first, flags=list(flags or []))


def _account_eid(asset, domain, user):
    """Domain accounts -> global node (cross-host); local -> asset-scoped."""
    d = (str(domain) if domain else "").strip().lower()
    u = (str(user) if user else "").strip().lower()
    if not u or u in ("-", "n/a"):
        return None, d, u
    if d and d not in _LOCAL_DOMAINS and not d.endswith("$"):
        return f"account:domain:{d}\\{u}", d, u          # GLOBAL
    return keys.account_id(asset, None, u), d, u          # local, asset-scoped


def map_agentic(collected_data: dict, *, run_id: str, hostnames: dict | None = None) -> tuple[list, list]:
    ents: list[Entity] = []
    rels: list[Relationship] = []
    hostnames = hostnames or {}

    def asset_of(row):
        cid = F.get(row, *F.CLIENT_ID)
        if cid:
            return keys.asset_id(cid), (hostnames.get(str(cid)) or F.get(row, *F.HOSTNAME))
        host = F.get(row, *F.HOSTNAME)
        return (keys.asset_id_from_host(host) if host else "asset:endpoint:unknown"), host

    assets_seen: dict[str, str] = {}
    proc_by_asset_pid: dict[tuple, str] = {}
    sigma_events: list = []   # (event_id, asset, parsed_details, ts) for the linking pass

    for artifact, rows in (collected_data or {}).items():
        an = artifact.lower()
        for i, r in enumerate(rows or []):
            if not isinstance(r, dict):
                continue
            asset, host = asset_of(r)
            if asset not in assets_seen:
                assets_seen[asset] = host
                ents.append(Entity(id=asset, type="asset", label=str(host or asset.split(":")[-1]),
                                   attrs={"hostname": host, "kind": "endpoint", "_assets": [asset]},
                                   sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")]))
            ts = F.first_ts(r)
            loc = f"{artifact}/row={i}"

            # ---- malfind -> injected process (memory injection via agentic) -
            # Must precede the generic 'detection' catch-all, which would
            # otherwise mis-type this rich injection signal as a plain event.
            if "malfind" in an:
                pid = F.get(r, *F.PID)
                if pid is None:
                    continue
                name = F.get(r, *F.PROC_NAME) or "?"
                ct = F.get(r, *F.CREATETIME)
                prot = str(F.get(r, "Protection", default="") or "")
                rwx = "x" in prot.lower() and "w" in prot.lower()
                eid = keys.process_id(asset, pid, ct, name)
                proc_by_asset_pid[(asset, str(pid))] = eid
                ents.append(_ent(eid, "process", f"{name} ({pid})", asset, run_id, loc,
                                 anomaly=100 if rwx else 60, first=keys.norm_ts(ct or ts),
                                 flags=["injected"], pid=str(pid), name=name,
                                 protection=prot,
                                 address_range=F.get(r, "AddressRange", default=None),
                                 createtime=keys.norm_ts(ct)))
                yh = F.get(r, "YaraHit", "Rule", "rule", default=None)
                rule = (yh.get("Rule") if isinstance(yh, dict) else yh) if yh else None
                if rule:
                    yid = keys.yarahit_id(asset, rule, pid)
                    ents.append(_ent(yid, "yarahit", str(rule), asset, run_id, loc,
                                     anomaly=50, first=ts, rule=rule))
                    rels.append(Relationship(yid, eid, "matched", sources=[MODULE], ts=ts))

            # ---- named pipes -> event (C2 / lateral movement signal) --------
            elif "namedpipe" in an:
                pipe = F.get(r, "PipeName", "Name", default=None)
                if not pipe:
                    continue
                pid = F.get(r, "ProcPid", *F.PID)
                eid = keys.event_id(run_id, f"{asset}:{pid}", f"pipe:{pipe}")
                ents.append(_ent(eid, "event", f"named pipe: {str(pipe)[:60]}", asset, run_id,
                                 loc, anomaly=score_row(r) or 10, first=ts, artifact=artifact,
                                 pipe=str(pipe), proc_name=F.get(r, "ProcName", default=None)))
                src = proc_by_asset_pid.get((asset, str(pid))) if pid is not None else None
                if src:
                    rels.append(Relationship(src, eid, "event_about", sources=[MODULE], ts=ts))

            # ---- processes -------------------------------------------------
            elif "pstree" in an or "pslist" in an or "processes" in an:
                pid = F.get(r, *F.PID)
                if pid is None:
                    continue
                name = F.get(r, *F.PROC_NAME) or "?"
                ct = F.get(r, *F.CREATETIME)
                eid = keys.process_id(asset, pid, ct, name)
                proc_by_asset_pid[(asset, str(pid))] = eid
                # Pslist enrichment: unsigned image raises suspicion; elevation
                # is privilege context. Both are forensic signal, not noise.
                untrusted = _image_untrusted_and_odd(r)
                phash = _sha256_of(r)
                anom = score_row(r) + (40 if untrusted else 0)
                pflags = ["unsigned"] if untrusted else []
                ents.append(_ent(eid, "process", f"{name} ({pid})", asset, run_id, loc,
                                 anomaly=anom, first=keys.norm_ts(ct or ts), flags=pflags,
                                 pid=str(pid), name=name, cmdline=F.get(r, *F.CMDLINE),
                                 createtime=keys.norm_ts(ct), sha256=phash,
                                 elevated=F.get(r, "TokenIsElevated", default=None),
                                 signed=(not untrusted) if F.get(r, "Authenticode") else None))
                # Cross-host pivot: hash an UNSIGNED binary only (signed system
                # binaries would flood the graph with benign hashes).
                if phash and untrusted and keys.classify_indicator(phash) == "hash":
                    iid = keys.ioc_id("hash", phash)
                    ents.append(_ent(iid, "ioc", phash[:16] + "…", asset, run_id, loc,
                                     anomaly=20, ioc_kind="hash", first=ts, full_hash=phash,
                                     image=name, **_hash_attrs(r)))   # md5/sha1 = bridge fuel
                    rels.append(Relationship(eid, iid, "matched", sources=[MODULE], ts=ts))
                owner = F.get(r, *F.USER)
                if owner:
                    aeid, d, u = _account_eid(asset, F.get(r, *F.DOMAIN), owner)
                    if aeid:
                        ents.append(_ent(aeid, "account", (f"{d}\\{u}" if d else u), asset,
                                         run_id, loc, user=u, domain=d))
                        rels.append(Relationship(aeid, eid, "executed", sources=[MODULE], ts=ts))

            # ---- spawned (second pass would be cleaner; do inline by ppid) -
            # handled in finalize below

            # ---- logon / auth -> account authenticated to asset ----------
            elif any(k in an for k in ("logon", "rdpauth", "rdpclient", "authentication",
                                       "accountusage")):
                user = F.get(r, *F.USER)
                aeid, d, u = _account_eid(asset, F.get(r, *F.DOMAIN), user)
                if aeid:
                    lproc = str(F.get(r, *F.LOGON_PROC) or "").lower()
                    # runas/psexec/WinRM logon mechanisms are lateral-movement signals —
                    # a conservative bump, never an auto-finding (protects clean silence).
                    bump = 5 if any(k in lproc for k in ("seclogon", "psexec", "winrm",
                                                         "wsmprovhost", "wmiprvse")) else 0
                    ents.append(_ent(aeid, "account", (f"{d}\\{u}" if d else u), asset, run_id,
                                     loc, anomaly=score_row(r) + bump, first=ts, user=u, domain=d))
                    rels.append(Relationship(
                        aeid, asset, "authenticated", sources=[MODULE], ts=ts,
                        attrs={"logon_type": F.get(r, "LogonType", "LogonTypeDescription", default=None),
                               "src_ip": F.get(r, *F.IP_ADDR, default=None),
                               "workstation": F.get(r, *F.WORKSTATION, default=None),
                               "auth_package": F.get(r, *F.AUTH_PKG, default=None),
                               "logon_process": F.get(r, *F.LOGON_PROC, default=None),
                               "event_id": F.get(r, *F.EVENT_ID, default=None),
                               "dest_host": F.get(r, "DestinationHost", default=None)}))

            # ---- Kerberos tickets -> suspicious-TGT event/finding ---------
            elif "kerberos" in an or "goldenticket" in an:
                susp = F.get(r, "Suspicious", default=None)
                tt = F.get(r, "TicketType", default="ticket")
                client = F.get(r, "Client", default="?")
                server = F.get(r, "Server", default="?")
                kid = keys.event_id(run_id, f"{asset}:{client}", f"krb:{tt}:{server}")
                truthy = str(susp).strip().lower() in ("true", "1", "yes") or susp is True
                ents.append(_ent(kid, "event", f"Kerberos {tt}: {client} -> {server}", asset,
                                 run_id, loc, anomaly=60 if truthy else 1, first=ts,
                                 artifact=artifact, flags=(["kerberos_suspicious"] if truthy
                                                           else ["kerberos"]),
                                 ticket_type=str(tt), client=str(client), server=str(server),
                                 enctype=F.get(r, "EncType", default=None)))

            # ---- user inventory (Sys.Users / AllUsers / SAM) -> account ---
            elif "sys.users" in an or "allusers" in an or "localusers" in an \
                    or an.endswith(".users") or an.endswith(".sam"):
                uname = F.get(r, "Name", *F.USER)
                aeid, d, u = _account_eid(asset, F.get(r, *F.DOMAIN), uname)
                if aeid:
                    sid = F.get(r, "UUID", "Sid", "SID", "Uid", default=None)
                    ents.append(_ent(aeid, "account", (f"{d}\\{u}" if d else u), asset,
                                     run_id, loc, first=ts, user=u, domain=d, sid=sid,
                                     home=F.get(r, "Directory", "HomeDir", "ProfilePath",
                                                default=None)))

            # ---- powershell command history -> execution event -----------
            elif "psreadline" in an:
                line = F.get(r, "Line", "Command", "CommandLine", default=None)
                if not line or str(line).lstrip().startswith("#"):
                    continue                       # skip comments / blanks
                an_ps = _ps_anomaly(line)
                eid = keys.event_id(run_id, f"{asset}:{F.get(r, 'OSPath', default='')}",
                                    f"ps:{line}")
                ents.append(_ent(eid, "event", f"powershell: {str(line)[:80]}", asset, run_id,
                                 loc, anomaly=an_ps, first=ts, artifact=artifact,
                                 command=str(line)[:400],
                                 flags=(["suspicious_powershell"] if an_ps >= 25 else None)))
                owner = F.get(r, "Username", *F.USER)
                if owner:
                    aeid, d, u = _account_eid(asset, F.get(r, *F.DOMAIN), owner)
                    if aeid:
                        ents.append(_ent(aeid, "account", (f"{d}\\{u}" if d else u), asset,
                                         run_id, loc, user=u, domain=d))
                        rels.append(Relationship(aeid, eid, "executed", sources=[MODULE], ts=ts))

            # ---- network -> netconn + ioc --------------------------------
            elif "netstat" in an or "network" in an:
                raddr = F.get(r, *F.REMOTE_ADDR)
                if not raddr:
                    continue
                kind = keys.classify_indicator(raddr)
                if kind:
                    iid = keys.ioc_id(kind, raddr)
                    ents.append(_ent(iid, "ioc", str(raddr), asset, run_id, loc,
                                     anomaly=1, ioc_kind=kind, first=ts))
                    pid = F.get(r, *F.PID)
                    src = proc_by_asset_pid.get((asset, str(pid))) if pid is not None else None
                    if src:
                        rels.append(Relationship(src, iid, "connected", sources=[MODULE], ts=ts))

            # ---- detections / yara ---------------------------------------
            elif "yara" in an:
                rule = F.get(r, "Rule", "rule", "RuleName", "name", default=None) or artifact
                pid = F.get(r, *F.PID)
                yid = keys.yarahit_id(asset, rule, pid or "")
                ents.append(_ent(yid, "yarahit", str(rule), asset, run_id, loc, anomaly=50,
                                 first=ts, rule=rule))
                if pid is not None and proc_by_asset_pid.get((asset, str(pid))):
                    rels.append(Relationship(yid, proc_by_asset_pid[(asset, str(pid))],
                                             "matched", sources=[MODULE], ts=ts))

            # ---- web / dns -> domain ioc ---------------------------------
            elif "dnscache" in an or "webhistory" in an or "history" in an or "download" in an:
                url = F.get(r, "Url", "URL", "Name", "Domain", "Host", default=None)
                kind = keys.classify_indicator(url) if url else None
                if kind:
                    iid = keys.ioc_id(kind, url)
                    ents.append(_ent(iid, "ioc", str(url), asset, run_id, loc, anomaly=1,
                                     ioc_kind=kind, first=ts))

            # ---- persistence: services / autoruns / scheduled tasks ------
            elif any(k in an for k in ("autoruns", "services", "scheduledtask",
                                       "taskscheduler", "scheduled")):
                sname = (F.get(r, "Name", "ServiceName", "TaskName", "Entry", "Rule", default=None)
                         or artifact)
                binary = F.get(r, "AbsoluteExePath", "PathName", "Binary", "BinaryPath",
                               "ImagePath", "Command", *F.PATH, default=None)
                # path-aware scoring for real service rows; generic fallback otherwise
                anom = _service_anomaly(binary) if "service" in an else score_row(r)
                sid = keys.service_id(asset, sname)
                ents.append(_ent(sid, "service", str(sname), asset, run_id, loc,
                                 anomaly=anom, first=ts, artifact=artifact, binary=binary,
                                 start_mode=F.get(r, "StartMode", "StartType", default=None),
                                 state=F.get(r, *F.STATE)))

            # ---- Hayabusa / SIGMA detections -> severity-typed event ------
            # The richest agentic signal: Title is the detection, Level the
            # severity. Generic handling discarded both, so SIGMA hits never
            # became findings. Keep them as level-scored events flagged 'sigma'.
            elif "hayabusa" in an or "sigma" in an:
                title = F.get(r, "Title", "RuleTitle", "Rule", "Message", default=artifact)
                level = F.get(r, "Level", "Severity", default="informational")
                anom = _level_anomaly(level)
                eid = keys.event_id(run_id, f"{F.get(r, 'EID', 'EventID', default='')}",
                                    f"sigma:{title}:{F.get(r, 'RecordID', default=ts)}")
                ev = _ent(eid, "event", f"SIGMA: {str(title)[:80]}", asset, run_id, loc,
                          anomaly=anom, first=ts, artifact=artifact,
                          flags=["sigma"], title=str(title), level=str(level).lower(),
                          channel=F.get(r, "Channel", default=None),
                          eid_num=F.get(r, "EID", "EventID", default=None),
                          details=str(F.get(r, "Details", "Message", default=""))[:300])
                ev.severity = from_string(str(level))   # true SIGMA level, not anomaly-derived
                ents.append(ev)
                # stash the FULL details (not the truncated attr) for the linking pass
                sigma_events.append((eid, asset,
                                     DET.parse_details(F.get(r, "Details", "Message", default="")), ts))

            # ---- MFT detections -> criticality-typed event ----------------
            # Detection={Name,Criticality}; OSPath is the file. Criticality is
            # the rule author's rating (often benign BAU), so type + rank but do
            # NOT auto-finding.
            elif "mft" in an and ("detection" in an or "erasing" in an) \
                    and "hijacklib" not in an:
                det = F.get(r, "Detection", default=None)
                dname = (det.get("Name") if isinstance(det, dict) else det) or artifact
                crit = (det.get("Criticality") if isinstance(det, dict) else None) or "low"
                path = F.get(r, "OSPath", *F.PATH, default="")
                ev = _ent(keys.event_id(run_id, f"{asset}:{path}", f"mft:{dname}"),
                          "event", f"MFT: {str(dname)[:70]}", asset, run_id, loc,
                          anomaly=_level_anomaly(crit), first=ts, artifact=artifact,
                          flags=["mft_detection"], detection=str(dname),
                          criticality=str(crit).lower(), path=str(path)[:200])
                ev.severity = from_string(str(crit))
                ents.append(ev)

            # ---- application inventory detections (RMM / LOLRMM) ----------
            elif ("application" in an and "detection" in an) or "lolrmm" in an:
                cat = F.get(r, "Category", default="") or ""
                name = F.get(r, "DisplayName", "Name", default=artifact)
                rmm = any(k in str(cat).lower() for k in ("rmm", "remote", "lolrmm"))
                ents.append(_ent(keys.event_id(run_id, f"{asset}:{name}", f"app:{cat}:{name}"),
                                 "event", f"app: {str(name)[:50]} [{str(cat)[:30]}]", asset,
                                 run_id, loc, anomaly=30 if rmm else 1, first=ts, artifact=artifact,
                                 flags=(["rmm_tool"] if rmm else None), category=str(cat),
                                 app=str(name), version=F.get(r, "DisplayVersion", default=None)))

            # ---- execution evidence -> event (+ file + hash ioc) ---------
            elif any(k in an for k in ("amcache", "prefetch", "userassist", "shimcache",
                                       "appcompat", "srum", "bam")):
                path = F.get(r, *F.PATH) or F.get(r, "Name", default=artifact)
                eid = keys.event_id(run_id, ts, f"exec:{path}")
                ents.append(_ent(eid, "event", f"executed: {str(path)[:60]}", asset, run_id, loc,
                                 anomaly=score_row(r), first=ts, artifact=artifact))

            # ---- LolDrivers -> driver/module entity (BYOVD, T1068) --------
            elif "loldriver" in an:
                dname = F.get(r, "Name", "DriverName", *F.PATH, default=artifact)
                malicious = "malicious" in an
                sha = _sha256_of(r) or F.get(r, "SHA1", "Sha1", "sha1")
                path = F.get(r, "OSPath", "EntryKey", "HivePath", *F.PATH, default=None)
                mid = keys.module_id(asset, str(path or dname))
                ents.append(_ent(mid, "module", f"driver: {str(dname)[:50]}", asset, run_id, loc,
                                 anomaly=60 if malicious else 20, first=ts, artifact=artifact,
                                 flags=(["loldriver", "byovd"] if malicious else ["loldriver"]),
                                 driver=str(dname), path=str(path) if path else None,
                                 full_hash=str(sha) if sha else None, **_hash_attrs(r)))

            # ---- HijackLibs -> DLL-sideload event (T1574) -----------------
            elif "hijacklib" in an:
                info = F.get(r, "HijackLibInfo", default=None)
                dll = (info.get("DllName") if isinstance(info, dict) else None) \
                    or F.get(r, "DllName", "OSPath", "Name", *F.PATH, default=artifact)
                historical = "mft" in an
                eid = keys.event_id(run_id, f"{asset}:{dll}", f"hijacklib:{dll}")
                ents.append(_ent(eid, "event", f"DLL sideload: {str(dll)[:50]}", asset, run_id,
                                 loc, anomaly=15 if historical else 40, first=ts, artifact=artifact,
                                 flags=["dll_hijack"], dll=str(dll),
                                 path=F.get(r, "OSPath", "ExecutablePath", default=None),
                                 hijack_type=(info.get("Type") if isinstance(info, dict) else
                                              F.get(r, "Type", default=None))))

            # ---- Bootloaders -> firmware event (verdict-gated finding) -----
            elif "bootloader" in an:
                name = F.get(r, "Name", "OSPath", *F.PATH, default=artifact)
                bad = bool(F.get(r, "Revoked", "Malicious", "Vulnerable", "Detection",
                                 default=None))
                eid = keys.event_id(run_id, f"{asset}:{name}", f"boot:{name}")
                ents.append(_ent(eid, "event", f"bootloader: {str(name)[:50]}", asset, run_id,
                                 loc, anomaly=50 if bad else 1, first=ts, artifact=artifact,
                                 flags=(["firmware", "firmware_bad"] if bad else ["firmware"]),
                                 path=F.get(r, "OSPath", default=None)))

            # ---- other high-signal detections -> event -------------------
            elif any(k in an for k in ("evtx", "eventlog", "binaryrename",
                                       "untrusted", "lnk", "detection")):
                msg = F.get(r, "Message", "Description", "Name", *F.PATH, default=artifact)
                eid = keys.event_id(run_id, ts, f"{an}:{msg}")
                ents.append(_ent(eid, "event", f"{artifact}: {str(msg)[:80]}", asset, run_id,
                                 loc, anomaly=score_row(r), first=ts, artifact=artifact))

            # ---- hash extraction -> cross-host-capable IOC ---------------
            # Process artifacts handle their own hashes selectively above (only
            # unsigned), so skip them here to avoid flooding benign hashes.
            is_proc = "pstree" in an or "pslist" in an or "processes" in an
            is_exec = any(k in an for k in ("amcache", "prefetch", "userassist",
                                            "shimcache", "appcompat", "srum", "bam"))
            # sha256 preferred; sha1 fallback for Amcache (sha1-only) — the bridge
            # collapses a sha1 node into its sha256 twin later.
            h = None if is_proc else (_sha256_of(r) or F.get(r, "SHA1", "Sha1", "sha1"))
            if h and keys.classify_indicator(str(h)) == "hash":
                h = str(h)
                iid = keys.ioc_id("hash", h)
                # execution-evidence hashes are benign context (anomaly 0, never
                # auto cross-host); detection hashes (binaryrename) stay suspicious.
                ents.append(_ent(iid, "ioc", h[:16] + "…", asset, run_id, loc,
                                 anomaly=0 if is_exec else 10, ioc_kind="hash",
                                 first=ts, full_hash=h, **_hash_attrs(r)))

    # ---- spawned edges (ppid) across the processes we created -----------
    for artifact, rows in (collected_data or {}).items():
        an = artifact.lower()
        if not ("pstree" in an or "pslist" in an or "processes" in an):
            continue
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            asset, _ = asset_of(r)
            pid, ppid = F.get(r, *F.PID), F.get(r, *F.PPID)
            if pid is None or ppid is None:
                continue
            child = proc_by_asset_pid.get((asset, str(pid)))
            parent = proc_by_asset_pid.get((asset, str(ppid)))
            if child and parent and child != parent:
                rels.append(Relationship(parent, child, "spawned", sources=[MODULE]))

    # ---- detection -> entity linking (Hayabusa Details) -----------------
    # Attach each SIGMA detection to the process/account/IOC it references, and
    # RECONSTRUCT short-lived processes that exited before Pstree ran (their PIDs
    # only survive in the detection's Details). Order-independent second pass.
    _DET_CAP = 300                                   # per-asset flood guard
    _det_made: dict = {}
    # (A) create from_detection processes where Pstree missed them
    for eid, asset, pd, ts in sigma_events:
        p, pname = DET.pid(pd), DET.proc(pd)
        if not p or not pname or (asset, p) in proc_by_asset_pid:
            continue
        if _det_made.get(asset, 0) >= _DET_CAP:
            continue
        name = pname.replace("\\", "/").rstrip("/").split("/")[-1] or pname
        peid = keys.process_id(asset, p, ts, name)   # event ts = createtime fallback
        proc_by_asset_pid[(asset, p)] = peid
        _det_made[asset] = _det_made.get(asset, 0) + 1
        ents.append(_ent(peid, "process", f"{name} ({p})", asset, run_id, "hayabusa/details",
                         anomaly=0, first=keys.norm_ts(ts), flags=["from_detection"],
                         pid=p, name=name, cmdline=DET.cmdline(pd), createtime=keys.norm_ts(ts)))
    # (B) edges: event_about(proc), spawned(parent), executed(account), connected(ioc)
    for eid, asset, pd, ts in sigma_events:
        p = DET.pid(pd)
        proc_eid = proc_by_asset_pid.get((asset, p)) if p else None
        if proc_eid:
            rels.append(Relationship(proc_eid, eid, "event_about", sources=[MODULE], ts=ts))
            pp = DET.parentpid(pd)
            parent = proc_by_asset_pid.get((asset, pp)) if pp else None
            if parent and parent != proc_eid:
                rels.append(Relationship(parent, proc_eid, "spawned", sources=[MODULE], ts=ts))
        dom, usr = DET.user(pd)
        if usr:
            aeid, d, u = _account_eid(asset, dom, usr)
            if aeid:
                ents.append(_ent(aeid, "account", (f"{d}\\{u}" if d else u), asset, run_id,
                                 "hayabusa/details", user=u, domain=d))
                if proc_eid:
                    rels.append(Relationship(aeid, proc_eid, "executed", sources=[MODULE], ts=ts))
        tip = DET.tgtip(pd)
        if tip and keys.classify_indicator(tip) == "ip":
            # link only — anomaly 0 so benign cloud telemetry never auto-finds
            iid = keys.ioc_id("ip", tip)
            ents.append(_ent(iid, "ioc", str(tip), asset, run_id, "hayabusa/details",
                             anomaly=0, ioc_kind="ip", first=ts, from_detection=True))
            if proc_eid:
                rels.append(Relationship(proc_eid, iid, "connected", sources=[MODULE], ts=ts))
        # Details carry MD5+SHA256 together -> the bridge's alias fuel (anomaly 0).
        hh = DET.hashes(pd)
        sha = hh.get("sha256")
        if sha and keys.classify_indicator(sha) == "hash":
            hid = keys.ioc_id("hash", sha)
            ents.append(_ent(hid, "ioc", sha[:16] + "…", asset, run_id, "hayabusa/details",
                             anomaly=0, ioc_kind="hash", first=ts, full_hash=sha,
                             md5=hh.get("md5"), imphash=hh.get("imphash")))
            if proc_eid:
                rels.append(Relationship(proc_eid, hid, "matched", sources=[MODULE], ts=ts))

    return ents, rels

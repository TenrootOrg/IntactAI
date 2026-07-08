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

# Raw SIGMA Details kept on the event for explicit-detail reports (report_detail).
# Lossy ontology truncates here; 2000 chars holds a full cmdline + hashes + paths.
_EV_DETAILS_CAP = 2000

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


def _artifact_base(name):
    """Normalize a collected-data key to its base artifact name: strip an 'All '
    export prefix and any '/SubSource' suffix -> lowercase base."""
    n = str(name or "")
    if n[:4].lower() == "all ":
        n = n[4:]
    return n.split("/")[0].strip().lower()


# Hardcoded allowlist of artifacts fusion supports (mapped + tested). Decoupled
# from blueprints ON PURPOSE: fusion ingests ONLY these, regardless of what a
# collection / hunt / offline import happens to contain — no raw Velociraptor
# data ever enters the graph. Base names, lowercased (sub-sources like
# "<name>/Parsed" normalize to the base). Currently == the agentic_quick_wins
# set; add a line here when a new artifact gets a mapper.
SUPPORTED_ARTIFACTS = frozenset({
    "windows.hayabusa.rules",
    "windows.detection.malfind",
    "detectraptor.windows.detection.evtx",
    "detectraptor.windows.detection.mft",
    "detectraptor.windows.detection.binaryrename",
    "detectraptor.windows.detection.applications",
    "detectraptor.windows.detection.powershell.psreadline",
    "detectraptor.windows.detection.amcache",
    "detectraptor.windows.detection.namedpipes",
    "detectraptor.windows.detection.webhistory",
    "detectraptor.windows.detection.hijacklibsmft",
    "detectraptor.windows.detection.hijacklibsenv",
    "detectraptor.windows.detection.loldriversmalicious",
    "detectraptor.windows.detection.bootloaders",
    "windows.analysis.suspiciouswmiconsumers",
    # NOTE: windows.system.untrustedbinaries dropped from fusion — it's a
    # per-file Authenticode STATE check (no timestamp, no hash), ~95% benign
    # 'trusted' rows, and its only real signal (an unsigned running image) is
    # already covered by the pslist branch via _image_untrusted_and_odd. It was
    # emitting ~80 timeless noise events per case. (The agentic per-run report
    # still surfaces it via services/agentic/utils/_timeline.py — separate view.)
    "windows.forensics.sam",
    "windows.eventlogs.condensedaccountusage",
    "windows.kerberos.goldentickettriage",
    # --- Linux (agentic_quick_wins_linux) ---
    "linux.sys.pslist",
    "generic.system.pstree",
    "linux.network.netstatenriched",
    "linux.sys.services",
    "linux.sys.crontab",
    "linux.ssh.authorizedkeys",
    "linux.sys.suid",
    "linux.sys.getcap",
    "linux.syslog.sshlogin",
    "linux.users.rootusers",
    "linux.persistence.ldpreload",
    "linux.detection.memfd",
    "linux.detection.sshkeyfilecmd",
    "linux.forensics.environmentvariables",
    "linux.detection.incorrectpermissions",
})


def _scalar(v):
    """Coerce a possibly list/tuple field to ONE string (first distinct value), or
    "" for None/empty. Some Velociraptor artifacts return multi-valued domain/user
    fields; without this they'd stringify as e.g. "['workgroup']" and fragment the
    account id. The None->"" case matters: a None domain must stay empty so a local
    account is asset-scoped, NOT keyed globally as "none\\user" (which would falsely
    merge local accounts across hosts)."""
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        seen = []
        for x in v:
            if x is None:
                continue
            s = str(x).strip()
            if s and s not in seen:
                seen.append(s)
        return seen[0] if seen else ""
    return str(v).strip()


_LINUX_SUSP = ("curl", "wget", "bash -i", "/dev/tcp", "base64", " nc ", "ncat", "|sh", "| sh",
               "|bash", "| bash", "ld_preload", "ld_library_path", "/tmp/", "/dev/shm",
               "python -c", "python3 -c", "perl -e", "chmod +x", "history -c", "/var/tmp/")


def _linux_susp(text):
    """True if a Linux command/script line looks attacker-ish (download-and-run,
    reverse shell, in-temp execution, env-var hijack, history wipe). Used to grade
    cron/service/env-var/shell rows so benign entries stay below the severity floor."""
    t = str(text or "").lower()
    return any(k in t for k in _LINUX_SUSP)


def _account_eid(asset, domain, user):
    """Domain accounts -> global node (cross-host); local -> asset-scoped."""
    d = _scalar(domain).lower()
    u = _scalar(user).lower()
    if not u or u in ("-", "n/a"):
        return None, d, u
    if d and d not in _LOCAL_DOMAINS and not d.endswith("$"):
        return f"account:domain:{d}\\{u}", d, u          # GLOBAL
    return keys.account_id(asset, None, u), d, u          # local, asset-scoped


def map_agentic(collected_data: dict, *, run_id: str, hostnames: dict | None = None) -> tuple[list, list]:
    """Map Velociraptor AGENTIC-blueprint artifacts into fusion entities/findings.

    Only agentic blueprints are fused (see store.py FUSION_MODULES_*). Dispatch is
    substring-keyed on the artifact name. SUPPORTED ARTIFACTS — keyword => artifact:
      malfind                       => Windows.Detection.Malfind
      namedpipe                     => DetectRaptor...Detection.NamedPipes
      pstree/pslist/processes       => Generic.System.Pstree, Windows.System.Pslist
      logon/rdpauth/rdpclient/      => EventLogs.CondensedAccountUsage, LogonSessions,
        authentication/accountusage      RDPAuth, RDPClientActivity
      kerberos/goldenticket         => Windows.Kerberos.GoldenTicketTriage
      sys.users/.users/.sam/        => Windows.Forensics.SAM, Windows.Sys.Users
        allusers/localusers
      psreadline                    => DetectRaptor...Detection.Powershell.PSReadline
      netstat/network               => Windows.Network.Netstat
      yara                          => *.Detection.Yara* / *.YaraProcess*
      dnscache/webhistory/          => Windows.System.DNSCache,
        history/download                 DetectRaptor...Detection.Webhistory
      autoruns/services/scheduledtask  => persistence events
      hayabusa/sigma                => Windows.Hayabusa.Rules
      mft + detection               => DetectRaptor...Detection.MFT
      application+detection/lolrmm  => DetectRaptor...Detection.Applications, ...LolRMM
      amcache/prefetch/userassist/  => DetectRaptor...Detection.Amcache, exec evidence
        shimcache/appcompat/srum/bam
      loldriver                     => DetectRaptor...Detection.LolDrivers[Malicious]
      hijacklib                     => DetectRaptor...Detection.HijackLibs{MFT,Env}
      binaryrename                  => DetectRaptor...Detection.BinaryRename
      bootloader                    => DetectRaptor...Detection.Bootloaders
      wmiconsumer                   => Windows.Analysis.SuspiciousWMIConsumers
      evtx/eventlog/lnk/detection   => DetectRaptor...Detection.Evtx, ...Lnk, + ANY
        (catch-all)                      artifact whose name contains 'detection'
    Anything else is ignored (no entity). Add an elif branch to support more.
    """
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
        ab = _artifact_base(artifact)   # base name, sub-source ("/Parsed") stripped
        # NOTE: the supported-artifact ALLOWLIST is enforced at the fusion INGEST
        # boundary (store._filter_supported), NOT here — map_agentic stays a pure
        # artifact->entity function (so its unit tests exercise the handlers
        # directly). `ab` is still used by the sub-source-aware dispatch below
        # (e.g. SAM/users `.endswith`).
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

            # ---- Linux agentic artifacts (quick_wins_linux) -----------------
            # Placed before the generic Windows branches so e.g. linux.sys.services
            # doesn't fall into the Windows 'services' handler. Pslist/Pstree/Netstat
            # are intentionally NOT here — they reuse the generic process/network
            # handlers below.
            elif ab == "linux.persistence.ldpreload":
                content = str(F.get(r, "Content", default="") or "").strip()
                path = F.get(r, "OSPath", default="/etc/ld.so.preload")
                eid = keys.event_id(asset, f"{asset}:{path}", f"ldpreload:{content[:60]}")
                ents.append(_ent(eid, "event", f"LD_PRELOAD persistence: {content[:55]}", asset,
                                 run_id, loc, anomaly=70,
                                 first=keys.norm_ts(F.get(r, "Mtime", "Ctime", default=ts)),
                                 artifact=artifact, flags=["detection", "persistence", "linux"],
                                 title="LD_PRELOAD persistence", path=str(path), content=content[:200]))

            elif ab == "linux.detection.sshkeyfilecmd":
                cmd = F.get(r, "CMD", "Command", default="")
                path = F.get(r, "OSPath", default=None)
                # shared id with the AuthorizedKeys handler for the same file so the two
                # detectors of one backdoor key merge into ONE finding (not two).
                eid = keys.event_id(asset, f"{asset}:{path}", "ssh_authkey_backdoor")
                ents.append(_ent(eid, "event", f"SSH forced-command backdoor: {str(cmd)[:45]}", asset,
                                 run_id, loc, anomaly=70, first=ts, artifact=artifact,
                                 flags=["detection", "persistence", "ssh", "linux"],
                                 title="SSH authorized_keys command= backdoor",
                                 path=str(path) if path else None, command=str(cmd)))

            elif ab == "linux.detection.incorrectpermissions":
                path = F.get(r, "OSPath", default="?")
                mism = F.get(r, "Mismatch", default="")
                eid = keys.event_id(asset, f"{asset}:{path}", f"perm:{mism}")
                ents.append(_ent(eid, "event", f"Permission anomaly: {str(path)[:45]} ({mism})", asset,
                                 run_id, loc, anomaly=45,
                                 first=keys.norm_ts(F.get(r, "Ctime", "Mtime", default=ts)),
                                 artifact=artifact, flags=["detection", "linux"],
                                 title="File permission anomaly", path=str(path), mismatch=str(mism)))

            elif ab == "linux.forensics.environmentvariables":
                line = str(F.get(r, "Line", default="") or "")
                sev = _linux_susp(line)
                eid = keys.event_id(asset, f"{asset}:{F.get(r, 'OSPath', default='')}", f"envvar:{line[:60]}")
                ents.append(_ent(eid, "event", f"shell-config: {line[:55]}", asset, run_id, loc,
                                 anomaly=60 if sev else 5, first=ts, artifact=artifact,
                                 flags=(["detection", "persistence", "linux"] if sev else ["linux"]),
                                 title="Shell-config env persistence" if sev else None,
                                 line=line[:200], path=F.get(r, "OSPath", default=None)))

            elif ab == "linux.sys.crontab":
                cmd = str(F.get(r, "Command", default="") or "")
                sev = _linux_susp(cmd)
                cu = F.get(r, "User", default=None); cpath = F.get(r, "Path", default=None)
                eid = keys.event_id(asset, f"{asset}:{cpath}:{cu}", f"cron:{cmd[:50]}")
                ents.append(_ent(eid, "event", f"cron: {cmd[:55]}", asset, run_id, loc,
                                 anomaly=60 if sev else 4, first=ts, artifact=artifact,
                                 flags=(["detection", "persistence", "cron", "linux"] if sev
                                        else ["cron", "linux"]),
                                 title="Suspicious cron job" if sev else None,
                                 command=cmd[:200], user=str(cu) if cu else None,
                                 path=str(cpath) if cpath else None))

            elif ab == "linux.sys.services":
                name = F.get(r, "Name", "Id", "OSPath", default=artifact)
                execs = str(F.get(r, "ExecStart", "Exec", "Fragment", default="") or "")
                sev = _linux_susp(execs) or _linux_susp(str(name))
                eid = keys.event_id(asset, f"{asset}:{name}", f"svc:{name}")
                ents.append(_ent(eid, "event", f"systemd service: {str(name)[:45]}", asset, run_id,
                                 loc, anomaly=55 if sev else 3, first=ts, artifact=artifact,
                                 flags=(["detection", "persistence", "linux"] if sev else ["linux"]),
                                 title="Suspicious systemd service" if sev else None,
                                 service=str(name), exec=execs[:200] if execs else None))

            elif ab == "linux.users.rootusers":
                uname = F.get(r, "User", "Name", default=None)
                uid = F.get(r, "Uid", "UID", default=None)
                aeid, d, u = _account_eid(asset, None, uname)
                if aeid:
                    rogue = str(uid) == "0" and str(uname).lower() != "root"
                    ents.append(_ent(aeid, "account", (u or str(uname)), asset, run_id, loc,
                                     anomaly=60 if rogue else 1, first=ts, user=u,
                                     uid=str(uid) if uid is not None else None,
                                     home=F.get(r, "Homedir", default=None),
                                     shell=F.get(r, "Shell", default=None),
                                     flags=(["detection", "privilege_escalation", "linux"] if rogue else None)))

            elif ab == "linux.syslog.sshlogin":
                ip = F.get(r, "IP", default=None)
                res = str(F.get(r, "Result", default="")).lower()
                uname = F.get(r, "AttemptedUser", "User", default=None)
                aeid, d, u = _account_eid(asset, None, uname)
                if aeid:
                    ents.append(_ent(aeid, "account", (u or str(uname)), asset, run_id, loc,
                                     first=ts, user=u))
                    if res == "accepted":
                        rels.append(Relationship(aeid, asset, "authenticated", sources=[MODULE], ts=ts,
                                    attrs={"src_ip": ip, "result": res,
                                           "method": F.get(r, "Method", default=None)}))
                if ip and keys.classify_indicator(ip) == "ip":
                    iid = keys.ioc_id("ip", ip)
                    ents.append(_ent(iid, "ioc", str(ip), asset, run_id, loc,
                                     anomaly=1, ioc_kind="ip", first=ts))

            elif ab == "linux.sys.suid":
                path = str(F.get(r, "OSPath", *F.PATH, default="?"))
                std = any(path.startswith(p) for p in ("/usr/bin/", "/bin/", "/usr/sbin/",
                                                       "/sbin/", "/usr/lib/", "/lib/"))
                eid = keys.event_id(asset, f"{asset}:{path}", f"suid:{path}")
                ents.append(_ent(eid, "event", f"SUID: {path[:50]}", asset, run_id, loc,
                                 anomaly=60 if not std else 2,
                                 first=keys.norm_ts(F.get(r, "Mtime", default=ts)), artifact=artifact,
                                 flags=(["detection", "privilege_escalation", "linux"] if not std
                                        else ["linux"]),
                                 title="SUID binary in non-standard path" if not std else None, path=path))

            elif ab == "linux.sys.getcap":
                path = str(F.get(r, "OSPath", *F.PATH, default="?"))
                cap = F.get(r, "Capabilities", "Cap", "Caps", default="")
                eid = keys.event_id(asset, f"{asset}:{path}", f"cap:{cap}")
                ents.append(_ent(eid, "event", f"capability {str(cap)[:30]}: {path[:40]}", asset,
                                 run_id, loc, anomaly=45, first=ts, artifact=artifact,
                                 flags=["detection", "privilege_escalation", "linux"],
                                 title="File capability (privesc vector)", path=path, capability=str(cap)))

            elif ab == "linux.detection.memfd":
                pid = F.get(r, *F.PID)
                name = F.get(r, *F.PROC_NAME) or "?"
                eid = keys.event_id(asset, f"{asset}:{pid}", f"memfd:{name}")
                ents.append(_ent(eid, "event", f"in-memory exec (memfd): {name}", asset, run_id, loc,
                                 anomaly=80, first=ts, artifact=artifact,
                                 flags=["detection", "defense_evasion", "linux"],
                                 title="In-memory execution (memfd_create)",
                                 pid=str(pid) if pid is not None else None, name=name))

            elif ab == "linux.ssh.authorizedkeys":
                opts = F.get(r, "options", default=None)
                path = F.get(r, "OSPath", default=None)
                kt = F.get(r, "keytype", default=None)
                comment = F.get(r, "comment", default=None)
                has_cmd = bool(opts and any("command=" in str(o)
                                            for o in (opts if isinstance(opts, (list, tuple)) else [opts])))
                # a forced-command key is the same backdoor SSHKeyFileCmd flags — share its
                # event id (per file) so they dedup to one finding; benign keys keep their own.
                eid = keys.event_id(asset, f"{asset}:{path}",
                                    "ssh_authkey_backdoor" if has_cmd else f"authkey:{comment or kt}")
                ents.append(_ent(eid, "event", f"SSH authorized_key: {str(comment or kt)[:40]}", asset,
                                 run_id, loc, anomaly=65 if has_cmd else 6, first=ts, artifact=artifact,
                                 flags=(["detection", "persistence", "ssh", "linux"] if has_cmd
                                        else ["ssh", "linux"]),
                                 title="SSH authorized_keys forced-command backdoor" if has_cmd else None,
                                 path=str(path) if path else None, keytype=str(kt) if kt else None,
                                 comment=str(comment) if comment else None))

            # ---- named pipes -> detection event (C2 / lateral movement) ------
            # DetectRaptor flags these (e.g. "Cobalt Strike: trick_ryuk.profile" in
            # `Detection`); a flagged pipe is a real C2 detection, not noise — score
            # it high so it survives the severity floor and becomes a finding.
            elif "namedpipe" in an:
                pipe = F.get(r, "PipeName", "Name", default=None)
                if not pipe:
                    continue
                detn = F.get(r, "Detection", default=None)
                pid = F.get(r, "ProcPid", *F.PID)
                eid = keys.event_id(asset, f"{asset}:{pid}", f"pipe:{pipe}")
                ents.append(_ent(eid, "event",
                                 f"named-pipe detection: {str(detn or pipe)[:60]}", asset, run_id,
                                 loc, anomaly=70 if detn else (score_row(r) or 10), first=ts,
                                 artifact=artifact,
                                 flags=(["detection", "c2", "named_pipe"] if detn else None),
                                 title=(str(detn) if detn else f"Named pipe {pipe}"),
                                 pipe=str(pipe), detection=str(detn) if detn else None,
                                 proc_name=F.get(r, "ProcName", default=None)))
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
                    ents.append(_ent(iid, "ioc", phash, asset, run_id, loc,           # full hash (IOC appendix)
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
                kid = keys.event_id(asset, f"{asset}:{client}", f"krb:{tt}:{server}")
                truthy = str(susp).strip().lower() in ("true", "1", "yes") or susp is True
                ents.append(_ent(kid, "event", f"Kerberos {tt}: {client} -> {server}", asset,
                                 run_id, loc, anomaly=60 if truthy else 1, first=ts,
                                 artifact=artifact, flags=(["kerberos_suspicious"] if truthy
                                                           else ["kerberos"]),
                                 ticket_type=str(tt), client=str(client), server=str(server),
                                 enctype=F.get(r, "EncType", default=None)))

            # ---- user inventory (Sys.Users / AllUsers / SAM) -> account ---
            elif "sys.users" in an or "allusers" in an or "localusers" in an \
                    or ab.endswith(".users") or ab.endswith(".sam"):
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
                # PSReadline nests the history-file times under FileInfo and has no
                # per-command time, so anchor on the file's last write (most recent
                # PowerShell activity), then birth. Without this the events were undated.
                _fi = r.get("FileInfo") if isinstance(r.get("FileInfo"), dict) else {}
                ps_ts = keys.norm_ts(_fi.get("Mtime") or _fi.get("Btime") or _fi.get("Ctime")) or ts
                eid = keys.event_id(asset, f"{asset}:{F.get(r, 'OSPath', default='')}",
                                    f"ps:{line}")
                ents.append(_ent(eid, "event", f"powershell: {str(line)[:80]}", asset, run_id,
                                 loc, anomaly=an_ps, first=ps_ts, artifact=artifact,
                                 command=str(line)[:400],
                                 flags=(["suspicious_powershell"] if an_ps >= 25 else None)))
                owner = F.get(r, "Username", *F.USER)
                if owner:
                    aeid, d, u = _account_eid(asset, F.get(r, *F.DOMAIN), owner)
                    if aeid:
                        ents.append(_ent(aeid, "account", (f"{d}\\{u}" if d else u), asset,
                                         run_id, loc, user=u, domain=d))
                        rels.append(Relationship(aeid, eid, "executed", sources=[MODULE], ts=ps_ts))

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

            # ---- web / dns -> domain ioc (+ web detection event) ------------
            elif "dnscache" in an or "webhistory" in an or "history" in an or "download" in an:
                # DetectRaptor.Webhistory flags suspicious visits (Detection/Category,
                # e.g. Category='Enumeration', Domain='advanced-ip-scanner.com'). Turn a
                # flagged visit into a detection event so it surfaces as a finding.
                detn = F.get(r, "Detection", default=None)
                cat = F.get(r, "Category", default=None)
                dom = F.get(r, "Domain", "Host", default=None)
                # Webhistory nests the visit time in ArtifactData (Visit_Date /
                # Last_Visit_Date). Use it when sane; guard corrupt pre-epoch values
                # (some collections emit year 1601/1810 for unconverted WebKit/Chrome
                # timestamps) so the timeline is never polluted with false dates.
                _ad = r.get("ArtifactData") if isinstance(r.get("ArtifactData"), dict) else {}
                web_ts = keys.norm_ts(_ad.get("Visit_Date") or _ad.get("Last_Visit_Date")) or ts
                if web_ts and web_ts < "2000":
                    web_ts = None
                if detn or cat:
                    dname = (detn.get("Category") if isinstance(detn, dict) else detn) or cat or "web"
                    title = f"Web: {str(dname)[:30]} — {str(dom)[:40]}" if dom else f"Web: {str(dname)[:40]}"
                    eid = keys.event_id(asset, f"{asset}:{dom}", f"webdet:{dname}:{dom}")
                    ents.append(_ent(eid, "event", title, asset, run_id, loc,
                                     anomaly=40, first=web_ts, artifact=artifact,
                                     flags=["detection", "web"], title=title,
                                     category=str(cat) if cat else None,
                                     domain=str(dom) if dom else None,
                                     browser=F.get(r, "BrowserArtifact", default=None)))
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
                eid = keys.event_id(asset, f"{F.get(r, 'EID', 'EventID', default='')}",
                                    f"sigma:{title}:{F.get(r, 'RecordID', default=ts)}")
                raw_details = str(F.get(r, "Details", "Message", default=""))
                pd = DET.parse_details(raw_details)        # parse once, reuse for linking
                _hh = DET.hashes(pd)
                _edom, _eusr = DET.user(pd)
                ev = _ent(eid, "event", f"SIGMA: {str(title)[:80]}", asset, run_id, loc,
                          anomaly=anom, first=ts, artifact=artifact,
                          flags=["sigma"], title=str(title), level=str(level).lower(),
                          channel=F.get(r, "Channel", default=None),
                          eid_num=F.get(r, "EID", "EventID", default=None),
                          details=raw_details[:_EV_DETAILS_CAP],
                          # parsed evidence persisted for explicit-detail reports
                          ev_cmdline=DET.cmdline(pd), ev_proc=DET.proc(pd),
                          ev_pid=DET.pid(pd), ev_parentpid=DET.parentpid(pd),
                          ev_user=(f"{_edom}\\{_eusr}" if _edom and _eusr else _eusr),
                          ev_tgtip=DET.tgtip(pd),
                          ev_sha256=_hh.get("sha256"), ev_md5=_hh.get("md5"))
                ev.severity = from_string(str(level))   # true SIGMA level, not anomaly-derived
                ents.append(ev)
                # stash the parsed details (reused) for the linking pass
                sigma_events.append((eid, asset, pd, ts))

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
                # DetectRaptor MFT rows nest the $SI/$FN MACB times inside the
                # SITimestamps / FNTimestamps objects, so the generic first_ts() spec
                # (top-level keys only) misses them and the event used to land with NO
                # timestamp (blank on the timeline). Anchor on $FN Created — it's set at
                # local MFT-record creation, so it reflects when the file appeared on
                # THIS host and resists $SI copy-preservation / timestomping (a tool
                # built in 2022 but dropped in 2025 shows 2025 via $FN, not its inherited
                # $SI 2022). Fall back to $SI Created, then the modified times.
                _si = r.get("SITimestamps") if isinstance(r.get("SITimestamps"), dict) else {}
                _fn = r.get("FNTimestamps") if isinstance(r.get("FNTimestamps"), dict) else {}
                mft_ts = keys.norm_ts(_fn.get("Created0x30") or _si.get("Created0x10")
                                      or _si.get("LastModified0x10") or _fn.get("LastModified0x30") or ts)
                ev = _ent(keys.event_id(asset, f"{asset}:{path}", f"mft:{dname}"),
                          "event", f"MFT: {str(dname)[:70]}", asset, run_id, loc,
                          anomaly=_level_anomaly(crit), first=mft_ts, artifact=artifact,
                          flags=["mft_detection", "detection"],
                          title=f"MFT: {str(dname)[:60]}", detection=str(dname),
                          criticality=str(crit).lower(), path=str(path)[:200])
                ev.severity = from_string(str(crit))
                ents.append(ev)

            # ---- application inventory detections (RMM / LOLRMM) ----------
            elif ("application" in an and "detection" in an) or "lolrmm" in an:
                cat = F.get(r, "Category", default="") or ""
                name = F.get(r, "DisplayName", "Name", default=artifact)
                rmm = any(k in str(cat).lower() for k in ("rmm", "remote", "lolrmm"))
                ents.append(_ent(keys.event_id(asset, f"{asset}:{name}", f"app:{cat}:{name}"),
                                 "event", f"app: {str(name)[:50]} [{str(cat)[:30]}]", asset,
                                 run_id, loc, anomaly=30 if rmm else 1, first=ts, artifact=artifact,
                                 flags=(["rmm_tool"] if rmm else None), category=str(cat),
                                 app=str(name), version=F.get(r, "DisplayVersion", default=None)))

            # ---- execution evidence -> event (+ file + hash ioc) ---------
            elif any(k in an for k in ("amcache", "prefetch", "userassist", "shimcache",
                                       "appcompat", "srum", "bam")):
                path = F.get(r, *F.PATH) or F.get(r, "Name", default=artifact)
                eid = keys.event_id(asset, ts, f"exec:{path}")
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
                # HijackLibsMFT nests its $SI/$FN MACB times like Detection.MFT, so
                # first_ts() (top-level) misses them; anchor on $FN Created (local
                # record creation), then $SI Created, else the generic row time. The
                # Env variant has no such nesting and safely falls back to ts.
                _si = r.get("SITimestamps") if isinstance(r.get("SITimestamps"), dict) else {}
                _fn = r.get("FNTimestamps") if isinstance(r.get("FNTimestamps"), dict) else {}
                hj_ts = keys.norm_ts(_fn.get("Created0x30") or _si.get("Created0x10")) or ts
                eid = keys.event_id(asset, f"{asset}:{dll}", f"hijacklib:{dll}")
                ents.append(_ent(eid, "event", f"DLL sideload: {str(dll)[:50]}", asset, run_id,
                                 loc, anomaly=15 if historical else 40, first=hj_ts, artifact=artifact,
                                 flags=["dll_hijack"], dll=str(dll),
                                 path=F.get(r, "OSPath", "ExecutablePath", default=None),
                                 hijack_type=(info.get("Type") if isinstance(info, dict) else
                                              F.get(r, "Type", default=None))))

            # ---- binary rename / masquerading -> detection event (T1036) ---
            # DetectRaptor.BinaryRename flags an executable whose real identity (per
            # its version info / hash) differs from its on-disk name — classic evasion.
            # Pre-filtered hit => real detection; carry the file + hash for pivoting.
            elif "binaryrename" in an:
                name = F.get(r, "Name", default=None)
                path = F.get(r, "OSPath", *F.PATH, default=None)
                sha = _sha256_of(r)
                btime = keys.norm_ts(F.get(r, "Btime", "Ctime", "Mtime", default=ts))
                title = f"Renamed binary: {str(name or path)[:55]}"
                eid = keys.event_id(asset, f"{asset}:{path}", f"binrename:{name or path}")
                ents.append(_ent(eid, "event", title, asset, run_id, loc,
                                 anomaly=50, first=btime, artifact=artifact,
                                 flags=["detection", "masquerading"], title=title,
                                 name=str(name) if name else None,
                                 path=str(path) if path else None,
                                 full_hash=str(sha) if sha else None, **_hash_attrs(r)))

            # ---- Bootloaders -> firmware event (verdict-gated finding) -----
            elif "bootloader" in an:
                name = F.get(r, "Name", "OSPath", *F.PATH, default=artifact)
                bad = bool(F.get(r, "Revoked", "Malicious", "Vulnerable", "Detection",
                                 default=None))
                eid = keys.event_id(asset, f"{asset}:{name}", f"boot:{name}")
                ents.append(_ent(eid, "event", f"bootloader: {str(name)[:50]}", asset, run_id,
                                 loc, anomaly=50 if bad else 1, first=ts, artifact=artifact,
                                 flags=(["firmware", "firmware_bad"] if bad else ["firmware"]),
                                 path=F.get(r, "OSPath", default=None)))

            # ---- suspicious WMI consumers -> persistence finding (T1546.003) -
            # Windows.Analysis.SuspiciousWMIConsumers pre-filters the benign default
            # consumers, so every row is a real lead: a WMI event subscription whose
            # action runs a command/script at a trigger. High anomaly so it clears the
            # severity floor and becomes a finding; carry the action + WQL trigger for
            # the LLM. No reliable timestamp on the row -> kept as no-ts entity.
            elif "wmiconsumer" in an:
                cons = F.get(r, "ConsumerDetails", default=None)
                filt = F.get(r, "FilterDetails", default=None)
                cons = cons if isinstance(cons, dict) else {}
                filt = filt if isinstance(filt, dict) else {}
                cname = cons.get("Name") or "WMI consumer"
                action = (cons.get("CommandLineTemplate") or cons.get("ExecutablePath")
                          or cons.get("ScriptText") or cons.get("ScriptFileName") or "")
                query = filt.get("Query") or None
                ns = F.get(r, "Namespace", default=None)
                title = f"WMI persistence: {str(cname)[:50]}"
                eid = keys.event_id(asset, f"{asset}:{cname}",
                                    f"wmiconsumer:{cname}:{str(action)[:40]}")
                ents.append(_ent(eid, "event", title, asset, run_id, loc,
                                 anomaly=70, first=ts, artifact=artifact,
                                 flags=["detection", "persistence", "wmi"], title=title,
                                 consumer=str(cname),
                                 action=str(action)[:400] if action else None,
                                 wql=str(query)[:300] if query else None,
                                 namespace=str(ns) if ns else None))

            # ---- other high-signal detections -> event -------------------
            elif any(k in an for k in ("evtx", "eventlog", "binaryrename",
                                       "lnk", "detection")):
                msg = F.get(r, "Message", "Description", "Name", *F.PATH, default=artifact)
                eid = keys.event_id(asset, ts, f"{an}:{msg}")
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
                ents.append(_ent(iid, "ioc", h, asset, run_id, loc,               # full hash (IOC appendix)
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
            ents.append(_ent(hid, "ioc", sha, asset, run_id, "hayabusa/details",  # full hash
                             anomaly=0, ioc_kind="hash", first=ts, full_hash=sha,
                             md5=hh.get("md5"), imphash=hh.get("imphash")))
            if proc_eid:
                rels.append(Relationship(proc_eid, hid, "matched", sources=[MODULE], ts=ts))

    return ents, rels

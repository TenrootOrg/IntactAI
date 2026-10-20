"""An EDR export's telemetry, as Sigma sees it: the rule category of each event and the
product's column behind each Sigma field.

SigmaHQ writes Windows / Linux / macOS rules against Sysmon's categories and names
(process_creation: Image, CommandLine, ParentImage; file_event: TargetFilename;
registry_set: TargetObject, Details; ...). Every EDR keeps the same facts its own way,
and not just under other names: Defender's FolderPath is the new PROCESS in
DeviceProcessEvents but the FILE in DeviceFileEvents; Carbon Black's process_path is
the PARENT in a process start; SentinelOne's src.process is the creator, tgt.process
the created. A flat alias list cannot say that, so each product's events are read
here, per event type.

The 2026-10-20 severity audit found SigmaHQ's file_event (15 critical, 114 high),
registry (11 critical, 142 high), pipe_created (8 critical), image_load (3 critical)
and dns_query rules fed by Sysmon alone: an EDR export reached none of them.

view(own) -> {"category", "os", <Sigma field>: value, ...} or None. `own(*names)` is
the row's first non-empty column among `names`, under the product's own names.
"""
import json
import re

_HIVES = (("HKEY_LOCAL_MACHINE", "HKLM"), ("\\REGISTRY\\MACHINE", "HKLM"), ("HKEY_USERS", "HKU"),
          ("\\REGISTRY\\USER", "HKU"), ("HKEY_CURRENT_USER", "HKCU"), ("HKEY_CLASSES_ROOT", "HKCR"))


def reg_key(key, value_name=None):
    """A registry path in Sysmon's form (HKLM\\...\\Value), which the rules are written for."""
    k = str(key or "")
    for long, short in _HIVES:
        if k.upper().startswith(long):
            k = short + k[len(long):]
            break
    if value_name not in (None, ""):
        k = f"{k}\\{value_name}"
    return k


def path_os(path) -> str:
    p = str(path or "")
    if "\\" in p or re.match(r"^[A-Za-z]:", p):
        return "windows"
    if p.startswith(("/Users/", "/Library/", "/Applications/", "/System/", "/private/", "/Volumes/")):
        return "macos"
    return "linux"


def _extra(own, key):
    """Defender DeviceEvents keep the event's details in AdditionalFields (JSON text)."""
    af = own("AdditionalFields")
    if isinstance(af, str):
        try:
            af = json.loads(af)
        except ValueError:
            return None
    return af.get(key) if isinstance(af, dict) else None


_OS_COLUMNS = ("host.os.type", "host.os.family", "host.os.platform", "device_os", "os.platform", "OSPlatform",
               "endpoint.os", "agent.os", "platform", "os")
_OWN = {"f": None}                     # the row's own() while view() runs -- one row at a time per call


def _row_os():
    """The OS a row says it is from, when no path tells: None if it does not say."""
    own = _OWN["f"]
    v = str(own(*_OS_COLUMNS) or "").lower() if own else ""
    if "win" in v:
        return "windows"
    if "mac" in v or "darwin" in v or "os x" in v:
        return "macos"
    if "linux" in v or "ubuntu" in v or "debian" in v or "centos" in v or "rhel" in v:
        return "linux"
    return None


def _v(category, path_for_os, **fields):
    out = {"category": category,
           "os": path_os(path_for_os) if str(path_for_os or "").strip("- ") else _row_os()}
    out.update({k: v for k, v in fields.items() if v not in (None, "")})
    return out


def _renamed(view, old):
    """A rename keeps its file_event view (the new name is a file written) and is also
    file_rename, with the old name as Sysmon-era SourceFilename (Kernel-File ETW's names)."""
    if view and old:
        view.update(category="file_rename", SourceFilename=old)
    return view


def _join(folder, name):
    """Defender's PreviousFolderPath may or may not end with PreviousFileName."""
    folder, name = str(folder or ""), str(name or "")
    if not folder or folder.lower().endswith(name.lower()):
        return folder or name
    sep = "\\" if "\\" in folder else "/"
    return folder.rstrip("\\/") + sep + name


def _defender(own):
    """Microsoft Defender XDR advanced hunting (Device*Events), raw or via Event Hub."""
    act = str(own("ActionType") or "")
    actor = own("InitiatingProcessFolderPath")
    if not act or not (actor or own("InitiatingProcessFileName")):
        return None
    common = {"Image": actor, "User": own("InitiatingProcessAccountName", "AccountName")}
    if act == "ProcessCreated" and own("FolderPath"):
        return _v("process_creation", own("FolderPath"), Image=own("FolderPath"),
                  CommandLine=own("ProcessCommandLine"), ParentImage=actor,
                  ParentCommandLine=own("InitiatingProcessCommandLine"), User=own("AccountName"),
                  OriginalFileName=own("ProcessVersionInfoOriginalFileName"))
    if act.startswith("File") and own("FolderPath"):
        v = _v("file_delete" if act == "FileDeleted" else "file_event", own("FolderPath"),
               TargetFilename=own("FolderPath"), **common)
        return _renamed(v, _join(own("PreviousFolderPath"), own("PreviousFileName"))) if act == "FileRenamed" else v
    if act.startswith("Registry") and own("RegistryKey"):
        cat = {"RegistryValueSet": "registry_set", "RegistryKeyCreated": "registry_add",
               "RegistryKeyDeleted": "registry_delete", "RegistryValueDeleted": "registry_delete"}.get(act)
        if cat:
            return _v(cat, "C:\\", TargetObject=reg_key(own("RegistryKey"), own("RegistryValueName")),
                      Details=own("RegistryValueData"), EventType=act, **common)
    if act == "ImageLoaded" and own("FolderPath"):
        return _v("image_load", own("FolderPath"), ImageLoaded=own("FolderPath"), **common)
    if act.startswith(("Connection", "InboundConnection")) and own("RemoteIP"):
        return _v("network_connection", actor or "C:\\", DestinationIp=own("RemoteIP"),
                  DestinationPort=own("RemotePort"), DestinationHostname=own("RemoteUrl"),
                  SourceIp=own("LocalIP"), SourcePort=own("LocalPort"),
                  Initiated="false" if act.startswith("Inbound") else "true", **common)
    if act == "NamedPipeEvent":
        pipe = _extra(own, "PipeName")
        if pipe:
            return _v("pipe_created", actor or "C:\\", PipeName=pipe, **common)
    if act == "DnsQueryResponse":
        q = _extra(own, "DnsQueryString")
        if q:
            return _v("dns_query", actor or "C:\\", QueryName=q, **common)
    if act == "OpenProcessApiCall" and own("FolderPath"):
        return _v("process_access", own("FolderPath"), TargetImage=own("FolderPath"), SourceImage=actor,
                  GrantedAccess=_extra(own, "DesiredAccess"), **common)
    return None


def _crowdstrike(own):
    """CrowdStrike Falcon Data Replicator (event_simpleName)."""
    sn = str(own("event_simpleName") or "")
    if not sn:
        return None
    if sn in ("ProcessRollup2", "SyntheticProcessRollup2") and own("ImageFileName"):
        return _v("process_creation", own("ImageFileName"), Image=own("ImageFileName"),
                  CommandLine=own("CommandLine"), ParentImage=own("ParentImageFileName", "ParentBaseFileName"),
                  User=own("UserName"))
    if (sn.endswith("Written") or sn == "FileDeleteInfo") and own("TargetFileName"):
        return _v("file_delete" if sn == "FileDeleteInfo" else "file_event", own("TargetFileName"),
                  TargetFilename=own("TargetFileName"))
    if sn.startswith(("RegGeneric", "AsepValue", "RegKey", "RegValue")) and own("RegObjectName"):
        return _v("registry_set", "C:\\", TargetObject=reg_key(own("RegObjectName"), own("RegValueName")),
                  Details=own("RegStringValue", "RegNumericValue"))
    if sn in ("ImageHash", "ClassifiedModuleLoad", "UnsignedModuleLoad") and own("ImageFileName"):
        return _v("image_load", own("ImageFileName"), ImageLoaded=own("ImageFileName"))
    if sn.startswith("NetworkConnectIP") and own("RemoteAddressIP4", "RemoteAddressIP6"):
        return _v("network_connection", "C:\\", DestinationIp=own("RemoteAddressIP4", "RemoteAddressIP6"),
                  DestinationPort=own("RemotePort"), SourceIp=own("LocalAddressIP4", "LocalAddressIP6"),
                  Initiated="true")
    if sn == "DnsRequest" and own("DomainName"):
        return _v("dns_query", "C:\\", QueryName=own("DomainName"))
    return None


def _carbon_black(own):
    """VMware Carbon Black Cloud endpoint events (type endpoint.event.*)."""
    t = str(own("type") or "")
    if not t.startswith("endpoint.event."):
        return None
    act, proc = str(own("action") or ""), own("process_path")
    if t == "endpoint.event.procstart" and own("childproc_name"):
        return _v("process_creation", own("childproc_name"), Image=own("childproc_name"),
                  CommandLine=own("target_cmdline"), ParentImage=proc, ParentCommandLine=own("process_cmdline"),
                  User=own("childproc_username"))
    if t == "endpoint.event.filemod" and own("filemod_name"):
        return _v("file_delete" if "DELETE" in act and "CREATE" not in act and "WRITE" not in act else "file_event",
                  own("filemod_name"), TargetFilename=own("filemod_name"), Image=proc)
    if t == "endpoint.event.regmod" and own("regmod_name"):
        cat = ("registry_add" if "CREATE_KEY" in act else "registry_delete" if "DELETE" in act else "registry_set")
        return _v(cat, "C:\\", TargetObject=reg_key(own("regmod_name")), Image=proc)
    if t == "endpoint.event.moduleload" and own("modload_name"):
        return _v("image_load", own("modload_name"), ImageLoaded=own("modload_name"), Image=proc)
    if t == "endpoint.event.netconn" and own("remote_ip"):
        inbound = str(own("netconn_inbound") or "").lower() == "true"
        return _v("network_connection", proc or "C:\\", DestinationIp=own("remote_ip"),
                  DestinationPort=own("remote_port"), DestinationHostname=own("netconn_domain"),
                  SourceIp=own("local_ip"), Image=proc, Initiated="false" if inbound else "true")
    if t == "endpoint.event.crossproc" and own("crossproc_name"):
        return _v("process_access", own("crossproc_name"), TargetImage=own("crossproc_name"), SourceImage=proc)
    return None


def _elastic(own):
    """Elastic Defend / ECS endpoint events (event.category)."""
    cat = str(own("event.category") or "").lower()
    if not cat:
        return None
    et, ea = str(own("event.type") or "").lower(), str(own("event.action") or "").lower()
    proc = own("process.executable")
    if "file" in cat and own("file.path"):
        kind = ("file_delete" if "deletion" in et or "delet" in ea else
                "file_event" if any(w in et or w in ea for w in ("creation", "change", "modif", "rename", "overwrite"))
                else "file_access" if "access" in et or ea in ("open", "read") else None)
        v = _v(kind, own("file.path"), TargetFilename=own("file.path"), FileName=own("file.path"),
               Image=proc) if kind else None
        return _renamed(v, own("file.Ext.original.path")) if ea == "rename" else v
    if "registry" in cat and own("registry.path", "registry.key"):
        return _v("registry_delete" if "deletion" in et or "delet" in ea else "registry_set", "C:\\",
                  TargetObject=reg_key(own("registry.path") or "\\".join(
                      str(x) for x in (own("registry.hive"), own("registry.key"), own("registry.value")) if x)),
                  Details=own("registry.data.strings"), Image=proc)
    if "process" in cat and "start" in et and proc:
        return _v("process_creation", proc, Image=proc, CommandLine=own("process.command_line"),
                  ParentImage=own("process.parent.executable"),
                  ParentCommandLine=own("process.parent.command_line"), User=own("user.name"))
    if "library" in cat and own("dll.path", "file.path"):
        return _v("image_load", own("dll.path", "file.path"), ImageLoaded=own("dll.path", "file.path"), Image=proc)
    if "network" in cat and own("dns.question.name"):
        return _v("dns_query", proc or "", QueryName=own("dns.question.name"), Image=proc)
    if "network" in cat and own("destination.ip") and ("start" in et or "connection" in ea):
        return _v("network_connection", proc or "", DestinationIp=own("destination.ip"),
                  DestinationPort=own("destination.port"), SourceIp=own("source.ip"), Image=proc,
                  Initiated="false" if "accept" in ea else "true")
    return None


def _sentinelone(own):
    """SentinelOne Deep Visibility (event.type in words)."""
    et = str(own("event.type") or "")
    if not et or not own("src.process.image.path", "tgt.file.path", "tgt.process.image.path"):
        return None
    src = own("src.process.image.path")
    low = et.lower()
    if low == "process creation" and own("tgt.process.image.path"):
        return _v("process_creation", own("tgt.process.image.path"), Image=own("tgt.process.image.path"),
                  CommandLine=own("tgt.process.cmdline"), ParentImage=src, ParentCommandLine=own("src.process.cmdline"),
                  User=own("tgt.process.user"))
    if low.startswith("file ") and own("tgt.file.path"):
        v = _v("file_delete" if "deletion" in low else "file_event", own("tgt.file.path"),
               TargetFilename=own("tgt.file.path"), Image=src)
        return _renamed(v, own("tgt.file.oldPath")) if low == "file rename" else v
    if low.startswith("registry ") and own("registry.keyPath"):
        cat = ("registry_add" if "create" in low else "registry_delete" if "delete" in low else "registry_set")
        return _v(cat, "C:\\", TargetObject=reg_key(own("registry.keyPath")), Details=own("registry.value"), Image=src)
    if low == "module load" and own("module.path"):
        return _v("image_load", own("module.path"), ImageLoaded=own("module.path"), Image=src)
    if low in ("ip connect", "ip listen") and own("dst.ip.address"):
        return _v("network_connection", src or "", DestinationIp=own("dst.ip.address"),
                  DestinationPort=own("dst.port.number"), SourceIp=own("src.ip.address"), Image=src,
                  Initiated="true" if str(own("event.network.direction") or "OUTGOING").upper() == "OUTGOING" else "false")
    if low.startswith("dns ") and own("event.dns.request"):
        return _v("dns_query", src or "", QueryName=own("event.dns.request"), Image=src)
    if low == "named pipe creation" and own("namedPipe.name"):
        return _v("pipe_created", src or "", PipeName=own("namedPipe.name"), Image=src)
    return None


_PRODUCTS = (_defender, _crowdstrike, _carbon_black, _sentinelone, _elastic)


_DEFENDER_OTHER = ("Logon", "Connection", "Inbound", "File", "Registry", "Dns", "NamedPipe", "ImageLoaded",
                   "Listening", "OpenProcess")
_CS_OTHER = ("Written", "FileDeleteInfo", "DnsRequest", "ImageHash", "ClassifiedModuleLoad", "UnsignedModuleLoad",
             "UserLogon", "UserLogoff")


def not_a_process(own) -> bool:
    """The row is one of these EDRs' NON-process events: a logon, a connection, a file,
    registry, DNS or module event. Whatever image and command line columns it carries
    (the acting process), it is no process creation. An EDR ALERT carrying a process
    (a detection with "procdump -ma lsass") is not excluded: its process rules are real."""
    act = str(own("ActionType") or "")
    if act and own("InitiatingProcessFolderPath", "InitiatingProcessFileName"):
        if act.startswith(_DEFENDER_OTHER) or act.endswith("Inspected"):
            return True
    sn = str(own("event_simpleName") or "")
    if sn and (sn.endswith(_CS_OTHER) or sn.startswith(("Reg", "Asep", "NetworkConnect", "NetworkListen"))):
        return True
    t = str(own("type") or "")
    if t.startswith("endpoint.event.") and t != "endpoint.event.procstart":
        return True
    et = str(own("event.type") or "")
    if et and own("src.process.image.path") and et.lower() != "process creation" and et[:1].isupper():
        return True                                        # SentinelOne Deep Visibility, words
    cat = str(own("event.category") or "").lower()
    if cat and not any(w in cat for w in ("process", "malware", "intrusion_detection")):
        return True                                        # ECS: authentication, network, registry, file ...
    return False


def view(own):
    _OWN["f"] = own
    for fn in _PRODUCTS:
        try:
            v = fn(own)
        except Exception:                                  # noqa: BLE001 -- one odd row, never the file
            v = None
        if v:
            return v
    return None

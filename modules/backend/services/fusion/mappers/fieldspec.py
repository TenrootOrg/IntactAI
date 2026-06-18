"""Field-alias resolution — Velociraptor (and Vol3) name the SAME field
differently per artifact (``Hostname``/``HostName``/``host``/``host_name``,
``Pid``/``PID``/``process_id``, ``CommandLine``/``CmdLine``/``Args``…).

``get(row, *aliases)`` resolves the first present, non-empty value,
case-insensitively, so a key never breaks on naming chaos. Mappers use the
named convenience accessors below; an unknown column falls back to the
generic resolver.
"""

from __future__ import annotations

from typing import Any


def get(row: dict, *aliases: str, default: Any = None) -> Any:
    """First present, non-empty value among ``aliases`` (case-insensitive)."""
    if not isinstance(row, dict):
        return default
    # exact first (cheap), then case-insensitive
    for a in aliases:
        if a in row and row[a] not in (None, "", [], {}):
            return row[a]
    low = {str(k).lower(): k for k in row.keys()}
    for a in aliases:
        k = low.get(a.lower())
        if k is not None and row[k] not in (None, "", [], {}):
            return row[k]
    return default


# Common alias bundles, reused across artifacts.
PID = ("Pid", "PID", "pid", "process_id", "ProcessId", "ProcessID")
PPID = ("Ppid", "PPID", "ppid", "parent_pid", "ParentPid", "ParentProcessId", "PPid")
PROC_NAME = ("Name", "ImageFileName", "ProcessName", "Process", "process_name",
             "Image", "ImagePath", "Exe", "OriginalFileName")
CMDLINE = ("CommandLine", "CmdLine", "Cmdline", "Args", "Arguments", "command_line")
CREATETIME = ("CreateTime", "Created", "CreationTime", "StartTime", "Start",
              "FirstSeen", "Timestamp", "EventTime")
HOSTNAME = ("_hostname", "Hostname", "HostName", "host", "host_name", "Computer",
            "ComputerName", "Fqdn", "FQDN", "Machine")
CLIENT_ID = ("_client_id", "ClientId", "client_id", "ClientID")
USER = ("User", "UserName", "user", "Account", "AccountName", "SubjectUserName",
        "TargetUserName", "userPrincipalName", "SourceUser")
DOMAIN = ("Domain", "domain", "SubjectDomainName", "TargetDomainName", "DnsDomain",
          "DomainName", "ConnectedDomain")
PATH = ("Path", "FullPath", "FileName", "Filename", "path", "OSPath", "Source",
        "TargetPath", "LinkTarget")
SHA256 = ("SHA256", "Sha256", "sha256", "Hash")
# Velociraptor flattens nested structs into dotted columns ("Raddr.IP"),
# so the dotted forms are first-class aliases here.
LOCAL_ADDR = ("LocalAddr", "Laddr.IP", "Laddr", "local_address", "LocalAddress", "Local")
REMOTE_ADDR = ("RemoteAddr", "Raddr.IP", "Raddr", "remote_address", "ForeignAddress",
               "RemoteAddress", "Foreign", "Remote")
STATE = ("State", "Status", "state")
# Authentication / logon (4624/4625/4768/4769, LogonSessions, CondensedAccountUsage)
IP_ADDR = ("IpAddress", "ClientAddress", "SourceIP", "SourceAddress")
WORKSTATION = ("WorkstationName", "ClientName", "SourceHost", "Workstation")
AUTH_PKG = ("AuthenticationPackageName", "AuthenticationPackage", "PackageName")
LOGON_PROC = ("LogonProcessName", "LogonProcess")
EVENT_ID = ("EventID", "EID", "Id", "event_id")
TIMES = ("CreateTime", "Created", "TimeCreated", "EventTime", "Timestamp",
         "datetime", "Mtime", "LastWriteTime", "Last Updated", "LastUpdated",
         "Atime", "_ts")


def first_ts(row: dict) -> str | None:
    """Best-effort timestamp for a row, normalised to a string."""
    v = get(row, *TIMES)
    if v in (None, ""):
        return None
    return str(v)

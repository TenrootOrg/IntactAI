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
         "Atime", "_ts",
         # registry/detection creation-or-write times some artifacts use instead of
         # the common names above: Amcache KeyMTime (~first-run), DetectRaptor
         # Applications KeyLastWriteTimestamp (~install), SAM CreatedTime. Appended
         # last so they only apply when no earlier (more specific) time is present.
         "KeyMTime", "KeyLastWriteTimestamp", "CreatedTime", "CreationTime")


def first_ts(row: dict) -> str | None:
    """Best-effort timestamp for a row, normalised to 'YYYY-MM-DDTHH:MM:SS'.

    It used to return str(v) unchanged, which quietly split the graph in two.
    This is the base timestamp for nearly every entity the Velociraptor agentic
    mapper emits, so those carried Velociraptor's raw rendering
    ("2026-08-26T05:19:34.7568747Z") while TimeSketch and memory — and the ten
    call sites in the same mapper that DO call keys.norm_ts — carried
    "2026-08-26T05:19:34". Measured consequences:

      * cross-source correlation could never fire on time: the same moment seen
        by two modules produced two different strings, so a TimeSketch event and
        a Velociraptor event one second apart looked no more related than ones a
        year apart.
      * keys.event_id embeds the timestamp, so the same real event described by
        two sources minted two entities that could never merge.
      * in_window compares ISO strings; mixing a fractional-second Z-suffixed
        value with a plain one makes boundary behaviour depend on which module
        produced the row.

    Normalising here rather than at each call site is the point: the call sites
    that remembered were never the problem.
    """
    v = get(row, *TIMES)
    if v in (None, ""):
        return None
    from .. import keys
    return keys.norm_ts(v)

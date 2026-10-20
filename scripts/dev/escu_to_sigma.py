#!/usr/bin/env python3
"""Splunk Security Content (ESCU) detections -> Sigma rules the log-data engine runs.

Only the detections that are plain conditions over one data model translate:
  | tstats ... FROM datamodel=Endpoint.Processes|Registry|Filesystem WHERE <cond> BY ...
with <cond> made of field=value / field!=value / field IN (...), AND / OR / NOT,
parentheses and macros that expand to the same. Anything else (lookups, eval,
joins, thresholds, macros with arguments, fields with no Sigma name) is SKIPPED
and listed with its reason -- never guessed.

Each written rule keeps the detection's id, name, ATT&CK ids and a link back;
security_content is Apache-2.0 (see the LICENSE note written beside the rules).
The rules are proved afterwards against each detection's own attack_data
recording (scripts/dev/escu_prove.py); a rule that does not fire there is not kept.

  python3 scripts/dev/escu_to_sigma.py <security_content checkout or sc.jsonl> <out dir>
"""
import json
import os
import re
import sys

import yaml

FIELDS = {   # CIM field -> (Sigma field, value shape)
    "Processes.process_name": ("Image", "name"),
    "Processes.process": ("CommandLine", "raw"),
    "Processes.process_path": ("Image", "raw"),
    "Processes.original_file_name": ("OriginalFileName", "raw"),
    "Processes.parent_process_name": ("ParentImage", "name"),
    "Processes.parent_process": ("ParentCommandLine", "raw"),
    "Processes.parent_process_path": ("ParentImage", "raw"),
    "Processes.user": ("User", "raw"),
    "Processes.process_current_directory": ("CurrentDirectory", "raw"),
    "Processes.process_integrity_level": ("IntegrityLevel", "raw"),
    "Registry.registry_path": ("TargetObject", "raw"),
    "Registry.registry_key_name": ("TargetObject", "tail"),
    "Registry.registry_value_name": ("TargetObject", "tail"),
    "Registry.registry_value_data": ("Details", "regdata"),
    "Filesystem.file_name": ("TargetFilename", "name"),
    "Filesystem.file_path": ("TargetFilename", "raw"),
    # Web: the URL as one string (path and query), as proxies and Suricata write it;
    # the engine reads it from an IIS/W3C log's cs-uri-stem too.
    "Web.url": ("c-uri", "raw"),
    "Web.uri_path": ("cs-uri-stem", "raw"),
    "Web.uri_query": ("cs-uri-query", "raw"),
    "Web.http_method": ("cs-method", "raw"),
    "Web.status": ("sc-status", "raw"),
    "Web.http_user_agent": ("c-useragent", "raw"),
    "Web.http_referrer": ("cs-referrer", "raw"),
    "DNS.query": ("query", "raw"),
}
IGNORED = {"Registry.action", "Filesystem.action", "Processes.action", "Processes.dest", "Registry.dest",
           "Filesystem.dest", "Processes.vendor_product"}      # true for every row Sigma sees
CATEGORY = {"Endpoint.Processes": "process_creation", "Endpoint.Registry": "registry_event",
            "Endpoint.Filesystem": "file_event", "Web": "web", "Network_Resolution": "dns"}
TOKEN = re.compile(r'\s*(\(|\)|`[^`]+`|"[\w.{}]+"\s*(?:!=|=)\s*(?:"(?:[^"\\]|\\.)*"|[^\s()]+)|"(?:[^"\\]|\\.)*"|[^\s()=!,]+(?:\s*(?:!=|=)\s*(?:"(?:[^"\\]|\\.)*"|[^\s()]+))?|,|IN\b)',
                   re.I)


class Skip(Exception):
    pass


def tokens(s):
    out, i = [], 0
    while i < len(s):
        m = TOKEN.match(s, i)
        if not m or m.end() == i:
            if s[i:].strip():
                raise Skip(f"cannot read the condition at: {s[i:i + 40]!r}")
            break
        out.append(m.group(1))
        i = m.end()
    return out


def expand(cond, macros, depth=0):
    if depth > 8:
        raise Skip("macros nest too deep")

    def one(m):
        name = m.group(1)
        if "(" in name:
            raise Skip(f"macro with arguments: {name}")
        if name not in macros:
            raise Skip(f"unknown macro: {name}")
        return "(" + expand(macros[name], macros, depth + 1) + ")"
    return re.sub(r"`([^`]+)`", one, cond)


def unq(v):
    """SPL escapes backslashes quoted or not: "\\\\" is one backslash."""
    v = v.strip()
    if v.startswith('"') and v.endswith('"'):
        v = v[1:-1]
    return v.replace('\\"', '"').replace("\\\\", "\\")


def leaf(field, op, values, product):
    if "{}" in field and field not in FIELDS:
        # Splunk's multivalue path: "user.groups{}" = any element. A list of plain
        # values is one joined string here ("a, b"), so an element is a contained value.
        if not field.endswith("{}") or "{}" in field[:-2]:
            raise Skip(f"list of objects {field}")
        field = field[:-2]
        values = [v if v.startswith("*") and v.endswith("*") else f"*{v}*" for v in values]
    if field in IGNORED:
        return None
    if field in RAW_IGNORED and field not in FIELDS and "Processes.process" not in FIELDS:
        # Only a placeholder test (src!="unknown", dest=*) may be dropped. A real value
        # (signature_id=65118) dropped would turn the rule into "every event".
        if op == "!=" or all(v.strip("*").lower() in ("", "-", "unknown", "null") for v in values):
            return None
        raise Skip(f"no field for {field}={values[0]!r}")
    if field == "errorCode" and [v.lower() for v in values] == ["success"]:
        # Splunk's CloudTrail add-on fills errorCode=success; raw CloudTrail has none on success
        return {"field": "errorCode", "values": [None], "neg": op == "!="}
    if field in FIELDS:
        sig, shape = FIELDS[field]
    elif "Processes.process" not in FIELDS and re.fullmatch(r"[A-Za-z_][\w.]*", field):
        sig, shape = field, "raw"                      # a raw search: the log's own field name
    else:
        raise Skip(f"no Sigma field for {field}")
    sep = "\\" if product == "windows" else "/"
    out = []
    import html
    values = list(dict.fromkeys(list(values) + [html.unescape(v) for v in values]))   # raw XML keeps &gt;
    if field == "Web.status" and "unknown" in values:
        out.append(None)          # the add-ons fill status=unknown; the raw log just has none
        values.remove("unknown")
    for v in values:
        if shape == "name" and not v.startswith("*") and product == "any":
            out.append(("*/" + v).replace("\\", "\\\\"))       # a path on any OS: both separators
            v = "*\\" + v
        elif shape == "name" and not v.startswith("*"):
            v = "*" + sep + v
        elif shape == "element" and not (v.startswith("*") and v.endswith("*")):
            v = f"*{v}*"
        elif shape == "tail" and not v.startswith("*"):
            v = "*" + "\\" + v
        elif shape == "regdata" and not (v.startswith("*") and v.endswith("*")):
            # Splunk's Sysmon add-on strips the type: raw Details is "DWORD (0x00000000)"
            out.append(f"* ({v})".replace("\\", "\\\\"))
        # Sigma reads "\\" as ONE backslash: escape every literal one, or Impacket's
        # \\127.0.0.1 UNC path is looked for as \127.0.0.1 and never found. "*" stays a wildcard.
        out.append(v.replace("\\", "\\\\"))
    return {"field": sig, "values": out, "neg": op == "!="}


class Parser:
    """SPL boolean condition -> tree of ("and"|"or", [..]), ("not", x), leaf."""

    def __init__(self, toks, product):
        self.t, self.i, self.product = toks, 0, product

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self):
        self.i += 1
        return self.t[self.i - 1]

    # SPL precedence: OR binds TIGHTER than AND (explicit or implicit) --
    # "a b c OR d" is a AND b AND (c OR d). Read the usual way round, Splunk's
    # LSASS-dump detection became "(lsass and dbgcore) or dbghelp".
    def expr(self):
        parts = [self.orterm()]
        while self.peek() not in (None, ")"):
            if self.peek().upper() == "AND":
                self.take()
            parts.append(self.orterm())
        parts = [p for p in parts if p is not None]
        return parts[0] if len(parts) == 1 else ("and", parts) if parts else None

    def orterm(self):
        node = self.factor()
        while (self.peek() or "").upper() == "OR":
            self.take()
            right = self.factor()
            node = right if node is None else node if right is None else ("or", [node, right])
        return node

    def factor(self):
        t = self.take()
        if t is None:
            raise Skip("condition ends early")
        if t.upper() == "NOT":
            f = self.factor()
            return ("not", f) if f is not None else None
        if t == "(":
            e = self.expr()
            if self.take() != ")":
                raise Skip("unbalanced parentheses")
            return e
        m = re.match(r'"?([\w.{}]+)"?\s*(!=|=)\s*(.+)$', t, re.S)
        if m:
            return leaf(m.group(1), m.group(2), [unq(m.group(3))], self.product)
        if re.fullmatch(r"[\w.{}]+", t) and (self.peek() or "").upper() == "IN":
            self.take()
            if self.take() != "(":
                raise Skip("IN without a list")
            vals = []
            while self.peek() not in (")", None):
                v = self.take()
                if v != ",":
                    vals.append(unq(v))
            self.take()
            return leaf(t, "=", vals, self.product)
        raise Skip(f"cannot read {t!r}")


def to_sigma(tree):
    """Tree -> (selections, condition)."""
    sels, n = {}, [0]

    def walk(x):
        if x is None:
            return None
        if isinstance(x, dict):
            n[0] += 1
            name = f"sel{n[0]}"
            vals = x["values"]
            sels[name] = {f"{x['field']}": vals if len(vals) > 1 else vals[0]}
            return f"not {name}" if x["neg"] else name
        op, parts = x
        if op == "not":
            inner = walk(parts)
            return f"not ({inner})" if inner else None
        inner = [p for p in (walk(p) for p in parts) if p]
        return "(" + f" {op} ".join(inner) + ")" if inner else None
    cond = walk(tree)
    if not cond or not sels:
        raise Skip("nothing left to match")
    return sels, cond


# Splunk "Anomaly" detections are suspicious-but-routine signals Splunk adds up per
# host (risk-based alerting); they carry no score. Here they are LOW -- context, and
# input to the behaviour rule that turns several on one host into a detection --
# except these, which are rarely benign and strong on their own.
PROMOTE = {
    "Linux Auditd AI CLI Permission Override Activated", "Linux Auditd Auditd Daemon Abort",
    "Linux Auditd Auditd Daemon Shutdown", "Linux Auditd Auditd Service Stop", "Linux Auditd Osquery Service Stop",
    "Linux Auditd Sysmon Service Stop", "Linux Auditd Disable Or Modify System Firewall",
    "Linux Auditd Insert Kernel Module Using Insmod Utility", "Linux Auditd Nopasswd Entry In Sudoers File",
    "Linux Auditd Possible Access To Credential Files", "Linux Auditd Possible Setuid Execve Privesc",
    "Linux Auditd Setuid Using Chmod Utility", "Linux Auditd Find Ssh Private Keys",
}


def severity(doc):
    if doc.get("type") == "Anomaly":
        return "medium" if doc.get("name") in PROMOTE else "low"
    """The detection's risk score (finding / intermediate findings; older: rba)."""
    ents = [(doc.get("finding") or {}).get("entity") or {}]
    ents += [f.get("entity") or {} for f in doc.get("intermediate_findings") or [] if isinstance(f, dict)]
    ents += list((doc.get("rba") or {}).get("risk_objects") or [])
    scores = [int(o.get("score") or 0) for o in ents if isinstance(o, dict)]
    s = max(scores) if scores else 0
    return "high" if s >= 70 else "medium"           # TTP: a detection by definition


# Phase 2: raw searches -- `<source macro>` field=value ... | stats ... -- on the log's
# own field names. Only the source macro decides the Sigma log source.
RAW_SOURCES = {
    "powershell": {"product": "windows", "category": "ps_script"},
    "sysmon": {"product": "windows", "service": "sysmon"},
    "wineventlog_security": {"product": "windows", "service": "security"},
    "wineventlog_system": {"product": "windows", "service": "system"},
    "o365_management_activity": {"product": "m365", "service": "audit"},
    "azure_monitor_aad": {"product": "azure"},
    "cloudtrail": {"product": "aws", "service": "cloudtrail"},
    "linux_auditd": {"product": "linux", "service": "auditd"},
    "okta": {"product": "okta", "service": "okta"},
    "amazon_security_lake": {"product": "aws", "service": "cloudtrail"},     # CloudTrail as OCSF
    "github_enterprise": {"product": "github", "service": "audit"},
    "github_organizations": {"product": "github", "service": "audit"},
    "zscaler_proxy": {"category": "proxy"},
    "wineventlog_application": {"product": "windows", "service": "application"},
    "ntlm_audit": {"product": "windows", "service": "ntlm"},
    "ms_defender": {"product": "windows", "service": "windefend"},
    "wineventlog_appxdeploymentserver": {"product": "windows", "service": "appxdeployment-server"},
    "kube_audit": {"product": "kubernetes", "service": "audit"},
    "cisco_secure_firewall": {"product": "cisco", "service": "secure_firewall"},
    "cisco_duo_administrator": {"product": "cisco", "service": "duo"},
    "cisco_asa": {"product": "cisco", "service": "asa"},
    "gws_reports_login": {"product": "google_workspace", "service": "google_workspace.admin"},   # Reports API
    "gws_reports_admin": {"product": "google_workspace", "service": "google_workspace.admin"},
    "esxi_syslog": {"product": "esxi"},                 # free-text syslog: Message is the line
}
RAW_FIELDS = {   # Splunk add-on names -> the raw / Sigma names our reader keeps
    "EventCode": ("EventID", "raw"), "loaded_file_path": ("ImageLoaded", "raw"), "loaded_file": ("ImageLoaded", "name"), "process_name": ("Image", "name"), "parent_process_name": ("ParentImage", "name"),
    "process": ("CommandLine", "raw"), "parent_process": ("ParentCommandLine", "raw"),
    "process_path": ("Image", "raw"), "parent_process_path": ("ParentImage", "raw"),
    "file_path": ("TargetFilename", "raw"), "file_name": ("TargetFilename", "name"),
    "execve_command": ("CommandLine", "raw"),          # auditd: the EXECVE arguments, joined
}
RAW_FIELDS_BY_SOURCE = {      # names Splunk's add-on gives a field that has another raw name in this log
    "wineventlog_security": {"TargetFilename": ("ObjectName", "raw"), "file_path": ("ObjectName", "raw"),
                             # the Windows add-on's spellings of the event's own fields
                             "Logon_Type": ("LogonType", "raw"), "object_file_path": ("ObjectName", "raw"),
                             "Object_Name": ("ObjectName", "raw"), "Process_Name": ("ProcessName", "raw"),
                             "process_path": ("ProcessName", "raw")},
    "esxi_syslog": {"Message": ("text", "raw")},
    "github_organizations": {"vendor_action": ("action", "raw")},     # the add-on renames GitHub's action
    # Google Reports: the parameters are name/value pairs (the reader makes them fields);
    # a multiValue one is a joined list, so a value is an element of it.
    "gws_reports_login": {"login_challenge_method": ("login_challenge_method", "element"),
                          # the only multiValue parameter of a login event is the challenge method
                          "event.parameters{}.multiValue{}": ("login_challenge_method", "element")},
    "gws_reports_admin": {"command": ("event.name", "raw")},
    "cisco_secure_firewall": {"signature_id": ("SignatureID", "raw"), "dest_port": ("ResponderPort", "raw"),
                              "src_port": ("InitiatorPort", "raw"), "action": ("AC_RuleAction", "raw"),
                              "url": ("URL", "raw")},
}
# What a count groups by, per source (2026-10-20): the raw field the add-on derives the
# group from. Only for the group-by -- never a filter (action=success is not EventID).
# The Windows / Sysmon add-ons derive signature, signature_id and action from the
# EventCode (+ status), so the EventCode groups the same rows or finer: a count can only
# come out lower than Splunk's, never fire where Splunk's would not.
GROUP_FIELDS_BY_SOURCE = {
    "wineventlog_security": {"signature": "EventID", "signature_id": "EventID", "action": "EventID",
                             "EventCode": "EventID", "app": "LogonType",
                             "authentication_method": "AuthenticationPackageName", "src_user": "SubjectUserName",
                             "user": "TargetUserName", "Logon_ID": "SubjectLogonId"},
    "sysmon": {"signature": "EventID", "signature_id": "EventID", "action": "EventID", "EventCode": "EventID",
               "user": "User", "user_id": "User",
               # Splunk's ProcessID is <Execution ProcessID>, Sysmon's own pid (one per host),
               # not the event's ProcessId -- grouping by that would put each event alone.
               "ProcessID": "Computer"},
    "o365_management_activity": {"user": "UserId", "src": "ClientIP", "src_ip": "ClientIP", "dest": "Workload",
                                 "signature": "Operation", "user_agent": "UserAgent"},
    "okta": {"src_user": "actor.alternateId"},
    "gws_reports_login": {"src": "ipAddress", "src_ip": "ipAddress", "user": "actor.email", "app": "id.applicationName"},
    "cisco_secure_firewall": {"src": "InitiatorIP", "dest": "ResponderIP", "transport": "Protocol",
                              "app": "Application", "signature": "IntrusionRuleMessage",
                              "class_desc": "Classification", "rule": "FirewallRule"},
}
RAW_IGNORED = {"dest", "src", "host", "sourcetype", "source", "index", "signature_id"}
# Pipes after the filter that only shape what is shown (extract, compute, rename, count,
# enrich): the rows they show are the rows the filter kept. Any pipe that can drop rows
# (where, search, regex, a join) is not here, so the detection is skipped.
OK_PIPES = {"stats", "rename", "table", "fields", "fillnull", "sort", "head", "convert", "collect", "rangemap",
            "tstats", "rex", "eval", "spath", "bin", "bucket", "dedup", "lookup", "mvexpand", "eventstats",
            "streamstats", "iplocation", "makemv", "nomv", "mvcombine", "strcat", "xmlkv", "outputlookup"}


def split_pipes(s):
    """SPL pipeline -> commands, splitting on | outside double quotes (a regex
    alternation "(key|pem|pfx)" is not a pipe)."""
    return [m.group(0) for m in re.finditer(r'(?:"(?:[^"\\]|\\.)*"|[^|"])+', s)] or [""]


_REGEX_PIPE = re.compile(r'regex\s+([\w.]+)\s*(!?=)\s*"((?:[^"\\]|\\.)*)"\s*$', re.S)


def _unwrap(x):
    """'( a AND b )' -> 'a AND b': only a pair of parentheses around the whole."""
    x = x.strip()
    while x.startswith("(") and x.endswith(")"):
        depth = 0
        for i, ch in enumerate(x):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0 and i < len(x) - 1:
                return x
        x = x[1:-1].strip()
    return x


def check_pipes(pipes, searches=None):
    """The pipes after the filter: raise Skip if one can drop rows we cannot express;
    return the `| regex field="..."` filters, which Sigma can (field|re). With a
    `searches` list, a `| search <condition>` right after `spath` (the JSON keys keep
    their names: nothing renamed or computed in between) is collected there."""
    regexes, spath, renamed = [], False, False
    for p in pipes:
        cmd = (p.split() or [""])[0].lower()          # "stats\n count": any whitespace ends the name
        if cmd == "spath":
            spath = True
            # "path=a.b{}.group output=group" names a value inside a list: no field of
            # that name exists here. Only "path=x.ruleAction output=ruleAction" keeps names.
            pm, om = re.search(r"\bpath=(\S+)", p), re.search(r"\boutput=(\S+)", p)
            if om and (not pm or "{}" in pm.group(1) or pm.group(1).split(".")[-1] != om.group(1)):
                renamed = True
            continue
        if cmd in ("rename", "eval", "rex", "lookup", "stats", "eventstats", "streamstats", "mvexpand"):
            renamed = True
        if cmd == "search" and searches is not None and spath and not renamed:
            searches.append(p.strip()[len("search"):].strip())
            continue
        if cmd.startswith("`"):
            if not re.match(r"`(security_content_ctime|\w+_filter|drop_dm_object_name)", cmd):
                raise Skip(f"macro after the filter: {cmd}")
            continue
        if cmd == "where" and not renamed and not spath:
            # where on the log's own fields (nothing computed yet): AND-ed match() / like()
            # are regexes; anything else (counts, field = other field) is not expressible.
            parts = re.split(r"\s+AND\s+", _unwrap(p.strip()[len("where"):]), flags=re.I)
            got = []
            for part in parts:
                part = _unwrap(part)
                mm = re.fullmatch(r'match\(\s*([\w.]+)\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)', part)
                ml = re.fullmatch(r'like\(\s*([\w.]+)\s*,\s*"([^"]*)"\s*\)', part)
                if mm:
                    got.append((mm.group(1), False, mm.group(2).replace('\\"', '"').replace("\\\\", "\\")))
                elif ml:
                    rx = "^" + "".join(".*" if c == "%" else "." if c == "_" else re.escape(c) for c in ml.group(2)) + "$"
                    got.append((ml.group(1), False, rx))
                else:
                    raise Skip(f"logic after the filter: where {part[:40]}")
            regexes += got
            continue
        if cmd == "regex":
            m = _REGEX_PIPE.match(p.strip())
            if not m:
                raise Skip("regex pipe not read")
            # SPL string: \" is a quote and \\ one backslash; the rest is the PCRE as written.
            regexes.append((m.group(1), m.group(2) == "!=", m.group(3).replace('\\"', '"').replace("\\\\", "\\")))
            continue
        if cmd not in OK_PIPES:
            raise Skip(f"logic after the filter: {cmd}")
    return regexes


def with_regexes(tree, regexes, field_of):
    """AND the regex pipes into the condition tree (no wildcard shaping: a pattern is a pattern)."""
    if not regexes:
        return tree
    leaves = []
    for f, neg, pat in regexes:
        try:
            re.compile(pat)
        except re.error:
            raise Skip(f"regex Python cannot read: {pat[:40]}")
        leaves.append({"field": field_of(f) + "|re", "values": [pat], "neg": neg})
    return ("and", [tree] + leaves)


_AUDITD_PATH = re.compile(r'mvfilter\(match\(candidate_paths,\s*"((?:[^"\\]|\\.)+)"\)\)')


# -- a count over a time window ("stats count by user | where count > 10") ------------
# About 190 detections end that way; Sigma's correlation rules (event_count /
# value_count) express it, and sigma_eval runs them. The filter part translates as any
# other rule (the base); the count is the correlation beside it.
_AGG = re.compile(r"\b(?:(count)\b(?!\()|(?:dc|distinct_count)\(\s*([\w.{}]+)\s*\))(?:\s+as\s+(\w+))?", re.I)
_WHERE_GT = re.compile(r"^\s*where\s+(\w+)\s*(>=|>)\s*(\d+)\s*$", re.I)
_SPAN = re.compile(r"\bspan\s*=\s*(\d+)\s*([smhd])", re.I)
# Splunk CIM names (the add-on's, not the log's): a raw log has them under its own names.
CIM_FIELDS = {"src", "src_ip", "dest", "dest_ip", "user", "src_user", "dest_user", "user_id", "app", "action",
              "signature", "signature_id", "vendor_account", "vendor_product", "vendor_region", "user_agent",
              "http_user_agent", "object", "object_category", "result", "reason", "status", "category",
              "authentication_method", "src_port", "dest_port", "transport", "protocol", "process", "process_name"}
DEFAULT_TIMESPAN = "1h"     # ponytail: Splunk schedules most detections hourly; per-rule if one proves too wide
HOST_FIELDS = {"dest": "Computer", "host": "Computer", "dvc": "Computer", "dest_host": "Computer",
               # the add-on's names for the event's own ids (Sysmon / Security write ProcessId)
               "process_id": "ProcessId", "parent_process_id": "ParentProcessId", "process_guid": "ProcessGuid"}


def _aggs(text):
    """{alias: (kind, field)} of the count / distinct counts in a stats or tstats clause."""
    out = {}
    for m in _AGG.finditer(text):
        if m.group(1) or m.group(2) == "_raw":     # dc(_raw): every event is distinct -- a count
            out[(m.group(3) or ("count" if m.group(1) else "dc(_raw)")).lower()] = ("event_count", None)
        else:
            out[(m.group(3) or f"dc({m.group(2)})").lower()] = ("value_count", m.group(2))
    return out


def split_threshold(pipes, header=None):
    """(filter pipes, threshold) for a search ending in a count over a window, else
    (pipes, None). threshold: {"type", "field", "by", "op", "n", "timespan"}. `header` is
    tstats' own (aggregations, by-clause) when the count sits in the tstats line."""
    span, i = None, None
    for j, p in enumerate(pipes):
        cmd = (p.split() or [""])[0].lower()
        if cmd in ("bucket", "bin"):
            m = _SPAN.search(p)
            span = f"{m.group(1)}{m.group(2).lower()}" if m else span
            continue
        if cmd == "stats" and header is None:
            i = j
            break
        if header is not None:
            i = j - 1
            break
        if cmd not in ("search", "regex") and not cmd.startswith("`"):
            return pipes, None                      # a field computed or renamed before counting
    if header is not None:
        aggs, by = header
        i = -1 if i is None else i
        rest = pipes
    else:
        if i is None:
            return pipes, None
        m = re.match(r"\s*stats\b(.*?)\bby\b(.*)$", pipes[i], re.S | re.I)
        if not m:
            return pipes, None
        aggs, by, rest = _aggs(m.group(1)), m.group(2), pipes[i + 1:]
    m = _SPAN.search(by)                            # tstats' "BY _time span=1m": the window, not a field
    if m:
        span = f"{m.group(1)}{m.group(2).lower()}"
        by = re.sub(r"\bspan\s*=\s*\S+", " ", by)
    by = [b for b in re.split(r"[\s,]+", by.strip()) if b and b.lower() != "_time"]
    for p in rest:
        cmd = (p.split() or [""])[0].lower()
        if cmd == "where":
            w = _WHERE_GT.match(p)
            if not w or w.group(1).lower() not in aggs:
                return pipes, None                  # a where on something else: not only a count
            kind, field = aggs[w.group(1).lower()]
            keep = [q for q in pipes[:max(i, 0)] if (q.split() or [""])[0].lower() not in ("bucket", "bin")] \
                if header is None else [q for q in pipes if q is not p and (q.split() or [""])[0].lower()
                                        not in ("bucket", "bin", "where", "stats")]
            return keep, {"type": kind, "field": field, "by": by, "op": "gte" if w.group(2) == ">=" else "gt",
                          "n": int(w.group(3)), "timespan": span or DEFAULT_TIMESPAN}
        if cmd in ("stats", "eventstats", "streamstats"):
            return pipes, None                      # counted again: not one window
    return pipes, None


def translate_raw(doc, macros):
    s = str(doc.get("search") or "").strip()
    # auditd path rules: PATH + CWD records joined per event, the full path matched.
    # The reader gives each PATH record that full path (full_path), so it is one condition.
    m = _AUDITD_PATH.search(s)
    if m and s.startswith("`linux_auditd`") \
            and [w.strip() for w in re.findall(r"\|\s*where\b[^|]*", s)] == ["| where match_count > 0"]:
        pat = m.group(1).replace("\\\\", "\\")
        re.compile(pat)
        return ({"sel1": {"type": "PATH"}, "sel2": {"full_path|re": pat}}, "sel1 and sel2",
                {"product": "linux", "service": "auditd"})
    m = re.match(r"`(\w+)`\s*(.*)$", s, re.S)
    if not m or m.group(1) not in RAW_SOURCES:
        raise Skip("raw search on a source with no Sigma log source")
    first, *pipes = split_pipes(m.group(2))
    pipes, thr = split_threshold(pipes)
    _LAST_THRESHOLD["thr"] = thr
    if thr:
        fmap = {**RAW_FIELDS, **RAW_FIELDS_BY_SOURCE.get(m.group(1), {}),
                **{k: (v, "raw") for k, v in GROUP_FIELDS_BY_SOURCE.get(m.group(1), {}).items()}}
        # One value per export (the product, the tenant): no group of its own.
        thr["by"] = [b for b in thr["by"] if b not in ("vendor_product", "vendor_account")]
        unmapped = [b for b in thr["by"] if b in CIM_FIELDS and b not in fmap and b not in HOST_FIELDS]
        if unmapped:
            # A Splunk add-on name the raw log does not have: every row would fall into ONE
            # empty group and the count would run across the whole log -- far wider than
            # Splunk's rule. Not translated.
            raise Skip(f"count grouped by a field with no Sigma name: {unmapped[0]}")
        grp = GROUP_FIELDS_BY_SOURCE.get(m.group(1), {})      # this source's own name wins (Cisco's dest)
        thr["by"] = list(dict.fromkeys(grp.get(b) or HOST_FIELDS.get(b) or fmap.get(b, (b,))[0] for b in thr["by"]))
        if thr["field"]:
            thr["field"] = fmap.get(thr["field"], (thr["field"],))[0]
        if any("." in b and "{" in b for b in thr["by"]):
            raise Skip("count grouped by a list element")
    searches = []
    regexes = check_pipes(pipes, searches)
    product = RAW_SOURCES[m.group(1)].get("product")
    cond = expand(first.strip(), macros)
    for extra in searches:                              # the spath'd JSON keys: one more condition
        cond = f"({cond}) AND ({extra})"
    if not cond.strip():
        raise Skip("no filter")
    saved = dict(FIELDS)
    try:
        FIELDS.clear()
        FIELDS.update(RAW_FIELDS)
        FIELDS.update(RAW_FIELDS_BY_SOURCE.get(m.group(1), {}))
        toks = tokens(cond)
        for t in toks:                                 # every term must be field op value / IN / boolean
            if not (t in ("(", ")", ",") or t.upper() in ("AND", "OR", "NOT", "IN") or re.match(r'"?[\w.{}]+"?\s*(!=|=)', t)
                    or t.startswith('"') or re.fullmatch(r"[\w.{}]+", t)):
                raise Skip(f"free-text term {t!r}")
        tree = RawParser(toks, product).expr()
        tree = with_regexes(tree, regexes, lambda f: FIELDS.get(f, (f,))[0])
    finally:
        FIELDS.clear()
        FIELDS.update(saved)
    sels, condition = to_sigma(tree)
    logsource = dict(RAW_SOURCES[m.group(1)])
    # Sysmon: a top-level EventCode names the category, so the engine's profile filter
    # skips the rule for every other event (without it, each Sysmon rule ran on every
    # Windows row: 2,960 -> 1,286 rows/s with the bundled set).
    if m.group(1) == "sysmon" and isinstance(tree, tuple) and tree[0] == "and":
        for part in tree[1]:
            if isinstance(part, dict) and part["field"] == "EventID" and not part["neg"]:
                cats = {SYSMON_CATEGORY.get(str(v)) for v in part["values"]}
                if len(cats) == 1 and None not in cats:
                    logsource["category"] = cats.pop()
                break
    return sels, condition, logsource


_LAST_THRESHOLD = {"thr": None}


SYSMON_CATEGORY = {"1": "process_creation", "2": "file_change", "3": "network_connection", "5": "process_termination",
                   "6": "driver_load", "7": "image_load", "8": "create_remote_thread", "9": "raw_access_thread",
                   "10": "process_access", "11": "file_event", "12": "registry_event", "13": "registry_event",
                   "14": "registry_event", "15": "create_stream_hash", "17": "pipe_created", "18": "pipe_created",
                   "19": "wmi_event", "20": "wmi_event", "21": "wmi_event", "22": "dns_query", "23": "file_delete",
                   "26": "file_delete_detected"}


class RawParser(Parser):
    def factor(self):
        t = self.peek()
        if t and re.fullmatch(r"[\w.{}]+", t) and t.upper() not in ("NOT", "AND", "OR", "IN") \
                and (self.t[self.i + 1] if self.i + 1 < len(self.t) else "").upper() != "IN":
            raise Skip(f"bare term {t!r}")
        return super().factor()


def translate(doc, macros):
    """The Sigma rule for a detection -- or, for a count over a window, the list
    [base rule, correlation rule] (written as one multi-document file)."""
    _LAST_THRESHOLD["thr"] = None
    rule = _translate(doc, macros)
    thr = _LAST_THRESHOLD["thr"]
    if not thr:
        return rule
    base_name = "escu_base_" + re.sub(r"[^a-z0-9]+", "_", str(doc["name"]).lower()).strip("_")
    base = {**rule, "title": f"{doc['name']} (counted event)", "name": base_name, "id": f"{doc.get('id')}-base",
            "level": "informational"}
    base.pop("x-escu", None)
    cond = {thr["op"]: thr["n"]}
    if thr["type"] == "value_count":
        cond["field"] = thr["field"]
    corr = {"title": rule["title"], "id": rule["id"], "status": rule["status"], "description": rule["description"],
            "references": rule["references"], "author": rule["author"], "tags": rule["tags"],
            "correlation": {"type": thr["type"], "rules": [base_name], "group-by": thr["by"],
                            "timespan": thr["timespan"], "condition": cond},
            "level": rule["level"], "x-escu": rule.get("x-escu")}
    return [base, corr]


def _translate(doc, macros):
    s = str(doc.get("search") or "")
    m = re.match(r"\s*\|\s*tstats\b.*?FROM\s+datamodel=(Endpoint\.(?:Processes|Registry|Filesystem)|Web|Network_Resolution)"
                 r"(?:\.Web|\.DNS)?\s+where\s+(.*?)\s+by\s", s, re.I | re.S)
    if not m:
        sels, condition, logsource = translate_raw(doc, macros)
        return _rule(doc, sels, condition, logsource)
    tpipes = split_pipes(s[m.end():])
    head = re.match(r"\s*\|\s*tstats\b(.*?)\bFROM\b", s, re.I | re.S)
    tpipes_rest, thr = split_threshold(tpipes[1:], header=(_aggs(head.group(1)) if head else {}, tpipes[0]))
    if thr:
        obj_ = {"network_resolution": "DNS"}.get(m.group(1).lower(), m.group(1).split(".")[-1])
        def _f(f):
            for k in (f"{obj_}.{f}", f, f.split(".")[-1]):
                if k in FIELDS:
                    return FIELDS[k][0]
            if f.split(".")[-1] in HOST_FIELDS:
                return HOST_FIELDS[f.split(".")[-1]]
            raise Skip(f"count grouped by a field with no Sigma name: {f}")
        where = m.group(2)

        def _pinned(f):                            # "where Filesystem.action=deleted ... by Filesystem.action":
            v = re.findall(rf'(?<![\w.]){re.escape(f)}\s*=\s*"?([^\s"]+)"?', where)   # one group, drop it
            return len(v) == 1 and "*" not in v[0] and not re.search(r"\b(OR|IN|NOT)\b", where, re.I)
        thr["by"] = [_f(b) for b in thr["by"] if not _pinned(b)]
        if thr["field"]:
            thr["field"] = _f(thr["field"])
        _LAST_THRESHOLD["thr"] = thr
    regexes = check_pipes(tpipes_rest)        # [0] was the rest of the BY clause
    obj = {"network_resolution": "DNS"}.get(m.group(1).lower(), m.group(1).split(".")[-1])

    def field_of(f):                                 # drop_dm_object_name: "process" is Processes.process
        for k in (f"{obj}.{f}", f):
            if k in FIELDS:
                return FIELDS[k][0]
        raise Skip(f"no Sigma field for regex on {f}")
    name = str(doc.get("name") or "")
    # The OS: the name says it ("Linux ...", "MacOS ..."), else the data the detection was
    # tested on does ("Socat ..." runs on Linux Sysmon); else Windows.
    tested = " ".join(str(a.get("sourcetype") or a.get("source") or "") for t in doc.get("tests") or []
                      for a in t.get("attack_data") or []).lower()
    cond = expand(m.group(2), macros)
    win_tested = bool(re.search(r"wineventlog|xmlwineventlog|windows", tested))
    nix_tested = bool(re.search(r"linux|auditd|osquery|macos", tested))
    both_named = ".exe" in cond.lower() and bool(re.search(r'`linux_\w+`|"(bash|sh|zsh|java|httpd|nginx|node)"', cond))
    product = ("linux" if re.match(r"linux\b", name, re.I) else "macos" if re.match(r"macos\b", name, re.I)
               else "windows" if re.match(r"windows\b", name, re.I)
               else "any" if (win_tested and nix_tested) or both_named        # one rule for every OS
               else "macos" if "macos" in tested else "linux" if nix_tested else "windows")
    category = CATEGORY[next(k for k in CATEGORY if k.lower() == m.group(1).lower())]
    if category in ("web", "dns"):                    # network data: no operating system
        tree = Parser(tokens(cond), "network").expr()
        tree = with_regexes(tree, regexes, field_of)
        sels, condition = to_sigma(tree)
        return _rule(doc, sels, condition, {"category": category})
    # The action names WHICH event: a deletion is its own Sysmon event (23 / 12-delete).
    if re.search(r'Filesystem\.action\s*=\s*"?deleted', cond, re.I):
        category = "file_delete"
    elif re.search(r'Registry\.action\s*=\s*"?deleted', cond, re.I):
        category = "registry_delete"
    tree = Parser(tokens(cond), product).expr()
    tree = with_regexes(tree, regexes, field_of)
    sels, condition = to_sigma(tree)
    return _rule(doc, sels, condition, {"category": category, **({} if product == "any" else {"product": product})})


def _rule(doc, sels, condition, logsource):
    mitre = doc.get("mitre_attack_id") or (doc.get("tags") or {}).get("mitre_attack_id") or []
    return {
        "title": doc["name"], "id": doc.get("id"), "status": "experimental",
        "description": str(doc.get("description") or "").strip()[:1000],
        "references": [f"https://research.splunk.com/{doc.get('id')}/"],
        "author": f"Splunk Security Content (Apache-2.0), {doc.get('author') or ''}".strip(", "),
        "tags": [f"attack.{t.lower()}" for t in mitre],
        "logsource": logsource,
        "detection": {**sels, "condition": condition},
        "level": severity(doc),
        "x-escu": {"type": doc.get("type"), "tests": [d.get("data") for t in doc.get("tests") or []
                                                     for d in t.get("attack_data") or [] if d.get("data")]},
    }


def load_docs(src):
    dets, macros = [], {}
    if src.endswith(".jsonl"):
        for line in open(src):
            r = json.loads(line)
            d = r.get("doc")
            if not isinstance(d, dict):
                continue
            if r["path"].startswith("macros/"):
                macros[d.get("name")] = str(d.get("definition") or "")
            elif "/deprecated/" not in r["path"]:
                dets.append(d)
    else:
        for root, _d, files in os.walk(src):
            for f in files:
                if not f.endswith(".yml"):
                    continue
                with open(os.path.join(root, f)) as fh:
                    d = yaml.safe_load(fh)
                if not isinstance(d, dict):
                    continue
                if "/macros" in root:
                    macros[d.get("name")] = str(d.get("definition") or "")
                elif "/detections" in root and "/deprecated" not in root:
                    dets.append(d)
    return dets, macros


def main(src, out_dir, types=("TTP", "Anomaly")):
    dets, macros = load_docs(src)
    os.makedirs(out_dir, exist_ok=True)
    made, skipped = [], {}
    for d in dets:
        if d.get("type") not in types or str(d.get("status") or "production") == "deprecated":
            continue
        try:
            rule = translate(d, macros)
        except Skip as e:
            skipped[d.get("name")] = str(e)
            continue
        name = re.sub(r"[^a-z0-9]+", "_", d["name"].lower()).strip("_")
        with open(os.path.join(out_dir, f"escu_{name}.yml"), "w") as f:
            if isinstance(rule, list):                 # base + correlation: one file, two documents
                yaml.safe_dump_all(rule, f, sort_keys=False, allow_unicode=True, width=120)
            else:
                yaml.safe_dump(rule, f, sort_keys=False, allow_unicode=True, width=120)
        made.append(name)
    print(f"{len(made)} rule(s) written, {len(skipped)} skipped")
    return made, skipped


if __name__ == "__main__":
    made, skipped = main(sys.argv[1], sys.argv[2])
    reasons = {}
    for n, why in skipped.items():
        reasons[why.split(":")[0]] = reasons.get(why.split(":")[0], 0) + 1
    for k, v in sorted(reasons.items(), key=lambda x: -x[1])[:15]:
        print(f"  {v:4}  {k}")

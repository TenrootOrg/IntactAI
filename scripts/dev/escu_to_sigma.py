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
    if "{}" in field:
        # Splunk's multivalue path: "user.groups{}" = any element. A list of plain
        # values is one joined string here ("a, b"), so an element is a contained value.
        if not field.endswith("{}") or "{}" in field[:-2]:
            raise Skip(f"list of objects {field}")
        field = field[:-2]
        values = [v if v.startswith("*") and v.endswith("*") else f"*{v}*" for v in values]
    if field in IGNORED or field in RAW_IGNORED and "Processes.process" not in FIELDS:
        return None
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
        if shape == "name" and not v.startswith("*"):
            v = "*" + sep + v
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
    "kube_audit": {"product": "kubernetes", "service": "audit"},
    "esxi_syslog": {"product": "esxi"},                 # free-text syslog: Message is the line
}
RAW_FIELDS = {   # Splunk add-on names -> the raw / Sigma names our reader keeps
    "EventCode": ("EventID", "raw"), "process_name": ("Image", "name"), "parent_process_name": ("ParentImage", "name"),
    "process": ("CommandLine", "raw"), "parent_process": ("ParentCommandLine", "raw"),
    "process_path": ("Image", "raw"), "parent_process_path": ("ParentImage", "raw"),
    "file_path": ("TargetFilename", "raw"), "file_name": ("TargetFilename", "name"),
    "execve_command": ("CommandLine", "raw"),          # auditd: the EXECVE arguments, joined
}
RAW_FIELDS_BY_SOURCE = {      # names Splunk's add-on gives a field that has another raw name in this log
    "wineventlog_security": {"TargetFilename": ("ObjectName", "raw"), "file_path": ("ObjectName", "raw")},
    "esxi_syslog": {"Message": ("text", "raw")},
    "github_organizations": {"vendor_action": ("action", "raw")},     # the add-on renames GitHub's action
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


def check_pipes(pipes):
    """The pipes after the filter: raise Skip if one can drop rows we cannot express;
    return the `| regex field="..."` filters, which Sigma can (field|re)."""
    regexes = []
    for p in pipes:
        cmd = p.strip().split(" ", 1)[0].lower()
        if cmd.startswith("`"):
            if not re.match(r"`(security_content_ctime|\w+_filter|drop_dm_object_name)", cmd):
                raise Skip(f"macro after the filter: {cmd}")
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


def translate_raw(doc, macros):
    s = str(doc.get("search") or "").strip()
    m = re.match(r"`(\w+)`\s*(.*)$", s, re.S)
    if not m or m.group(1) not in RAW_SOURCES:
        raise Skip("raw search on a source with no Sigma log source")
    first, *pipes = split_pipes(m.group(2))
    regexes = check_pipes(pipes)
    product = RAW_SOURCES[m.group(1)].get("product")
    cond = expand(first.strip(), macros)
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
    s = str(doc.get("search") or "")
    m = re.match(r"\s*\|\s*tstats\b.*?FROM\s+datamodel=(Endpoint\.(?:Processes|Registry|Filesystem)|Web|Network_Resolution)"
                 r"(?:\.Web|\.DNS)?\s+where\s+(.*?)\s+by\s", s, re.I | re.S)
    if not m:
        sels, condition, logsource = translate_raw(doc, macros)
        return _rule(doc, sels, condition, logsource)
    regexes = check_pipes(split_pipes(s[m.end():])[1:])        # [0] is the rest of the BY clause
    obj = {"network_resolution": "DNS"}.get(m.group(1).lower(), m.group(1).split(".")[-1])

    def field_of(f):                                 # drop_dm_object_name: "process" is Processes.process
        for k in (f"{obj}.{f}", f):
            if k in FIELDS:
                return FIELDS[k][0]
        raise Skip(f"no Sigma field for regex on {f}")
    name = str(doc.get("name") or "")
    product = ("linux" if re.match(r"linux\b", name, re.I) else "macos" if re.match(r"macos\b", name, re.I)
               else "windows")
    cond = expand(m.group(2), macros)
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
    return _rule(doc, sels, condition, {"category": category, "product": product})


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

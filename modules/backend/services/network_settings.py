"""Network settings: the appliance's IP/domain and each tool's public port.

Settings -> Network writes them into config.yaml and then runs
scripts/change_ip.sh, which applies whatever differs from what is live. That
script restarts this backend, so it runs ON THE HOST as a transient systemd
unit (data_location.host_run, the same privileged helper the data move uses)
and writes its output to <install>/data/tmp/network-<run_id>.log plus its exit
code to a .done file. A thread copies the log into a System-workspace run
(Settings -> Actions); after the restart, reattach_running() picks the run up
again from the offset the previous process stored in the run's details.
"""
import os
import re
import shlex
import threading
import time

import yaml

from services.proc import HOST_PATH

# (reply key, config.yaml module, key, default). The defaults are the compose
# defaults, and this table and RESERVED must stay identical to
# lib/config.sh:config_public_ports, which change_ip.sh validates with: a port
# the dashboard accepts and the script refuses fails the run after config.yaml
# was already written. tests/test_network_settings.py compares them.
PORTS = (
    ("kibana", "elk", "kibana_port", 5602),
    ("portainer", "portainer", "port", 9444),
    ("iris", "iris", "port", 8444),
    ("timesketch", "timesketch", "port", 5443),
    ("volweb", "volweb", "port", 8002),
    ("velociraptor_agent", "velociraptor", "agent_port", 8000),
)
RESERVED = {80: "the dashboard", 443: "the dashboard", 8080: "the dashboard",
            9200: "Elasticsearch", 5601: "Kibana (box-only)", 5044: "Logstash",
            9600: "Logstash", 50000: "Logstash", 8443: "IRIS (box-only)",
            9443: "Portainer (box-only)", 5000: "Timesketch (box-only)",
            5001: "the backend", 8889: "the Velociraptor GUI", 8001: "the Velociraptor API"}

# IPv4 only: change_ip.sh (valid_ipv4) refuses anything else, and a host name
# accepted here would fail the run after config.yaml was written. Digits and
# dots also cannot break out of the `bash -c` string the domain goes into.
_IPV4_RE = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")

SCRIPT = f"{HOST_PATH}/scripts/change_ip.sh"
TMP_DIR = os.path.join(HOST_PATH, "data", "tmp")
RUN_TYPE = "settings"   # a SYSTEM_TYPES member: anything else is moved out of System
RUN_KIND = "network"    # details.kind: what marks a settings run as one of ours
POLL_SECONDS = 1.0
# shortcut: a unit killed without writing .done is only noticed after this, raise it if a change_ip run ever takes longer.
MAX_WAIT_SECONDS = 2 * 3600

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_start_lock = threading.Lock()


class Busy(ValueError):
    """A network change is already running (the route answers 409)."""


def _config_path():
    from services.auth_service import config_path
    return config_path()


def _load():
    path = _config_path()
    if not path:
        raise RuntimeError("config.yaml not found")
    with open(path, encoding="utf-8") as fh:
        return path, fh.read()


def current():
    """{domain, ports:{key: port}} from config.yaml; a missing or unusable port
    is the default, which is what compose publishes then."""
    try:
        cfg = yaml.safe_load(_load()[1]) or {}
    except Exception:  # noqa: BLE001 -- unreadable config: show the defaults
        cfg = {}
    mods = cfg.get("modules") or {}
    ports = {}
    for key, mod, field, default in PORTS:
        raw = (mods.get(mod) or {}).get(field)
        port = _as_port(raw)
        ports[key] = port if port and 1 <= port <= 65535 else default
    return {"domain": str(cfg.get("domain") or "").strip(), "ports": ports}


def _as_port(raw):
    # Same acceptance as config_public_ports: an int (not a bool) or digits.
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    if isinstance(raw, str) and raw.strip().isdigit():
        return int(raw)
    return None


def valid_domain(domain):
    m = _IPV4_RE.fullmatch(domain)
    return bool(m) and all(int(o) <= 255 for o in m.groups())


def validate(domain, ports):
    """(domain, {key: int}) or ValueError listing every problem. Ports left out
    of `ports` keep their current value."""
    errs = []
    domain = str(domain or "").strip()
    if not domain or not valid_domain(domain):
        errs.append(f"'{domain}' is not an IPv4 address")
    given = ports if isinstance(ports, dict) else {}
    have = current()["ports"]
    out, seen = {}, {}
    for key, mod, field, _default in PORTS:
        name = f"modules.{mod}.{field}"
        raw = given.get(key, have[key])
        port = _as_port(raw)
        if port is None or not 1 <= port <= 65535:
            errs.append(f"{name}: '{raw}' is not a port number (1-65535)")
        elif port in RESERVED:
            errs.append(f"{name}: {port} is already used by {RESERVED[port]}")
        elif port in seen:
            errs.append(f"{name}: {port} is also {seen[port]}")
        else:
            seen[port] = name
            out[key] = port
    if errs:
        raise ValueError("; ".join(errs))
    return domain, out


def _block_end(lines, start, indent):
    """Index after the block whose header is lines[start] at `indent` columns."""
    for i in range(start + 1, len(lines)):
        s = lines[i].strip()
        if s and not s.startswith("#") and len(lines[i]) - len(lines[i].lstrip()) <= indent:
            return i
    return len(lines)


def _set_value(line, value):
    """`line` with its scalar replaced by value, keeping indent, key and comment."""
    m = re.match(r"^(\s*[A-Za-z_]+\s*:\s*)(?:'[^']*'|\"[^\"]*\"|[^#\r\n]*?)(\s+#[^\r\n]*)?(\r?\n)?$", line)
    return f"{m.group(1)}{value}{m.group(2) or ''}{m.group(3) or ''}"


def _edit(text, domain, ports):
    """config.yaml text with domain and the module port keys set; ValueError
    when the file has no place for one. Text edit, not a YAML round-trip, so
    the operator's comments and key order survive."""
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    dom = [i for i, ln in enumerate(lines) if re.match(r"^domain\s*:", ln)]
    if not dom:
        raise ValueError("config.yaml has no top-level domain: line")
    lines[dom[0]] = _set_value(lines[dom[0]], domain)

    for key, mod, field, default in PORTS:
        top = next((i for i, ln in enumerate(lines) if re.match(r"^modules\s*:\s*(#.*)?$", ln)), None)
        if top is None:
            raise ValueError("config.yaml has no top-level modules: block")
        mend = _block_end(lines, top, 0)
        kids = [i for i in range(top + 1, mend) if lines[i].strip() and not lines[i].strip().startswith("#")]
        mind = (len(lines[kids[0]]) - len(lines[kids[0]].lstrip())) if kids else 2
        hdr = next((i for i in kids if re.match(rf"^ {{{mind}}}{mod}\s*:\s*(#.*)?$", lines[i])), None)
        if hdr is None:
            if ports[key] == default:
                continue  # absent means the default already
            raise ValueError(f"config.yaml has no modules.{mod} block to put {field}: in")
        hind = len(lines[hdr]) - len(lines[hdr].lstrip())
        bend = _block_end(lines, hdr, hind)
        body = [i for i in range(hdr + 1, bend)
                if lines[i].strip() and not lines[i].strip().startswith("#")]
        kind = (len(lines[body[0]]) - len(lines[body[0]].lstrip())) if body else hind + 2
        hit = next((i for i in body if re.match(rf"^ {{{kind}}}{field}\s*:", lines[i])), None)
        if hit is not None:
            lines[hit] = _set_value(lines[hit], ports[key])
        else:
            # After the block's last setting, so comments above the next module stay with it.
            lines.insert((body[-1] if body else hdr) + 1, f"{' ' * kind}{field}: {ports[key]}\n")
    return "".join(lines)


def save_config(domain, ports):
    """Write domain and the port keys into config.yaml IN PLACE (truncate +
    write: the backend mounts the file by inode, see
    auth_service.write_first_login). Refuses when the edited file would parse
    to anything but the old one with exactly those values changed."""
    path, original = _load()
    updated = _edit(original, domain, ports)
    expected = yaml.safe_load(original) or {}
    expected["domain"] = domain
    for key, mod, field, default in PORTS:
        block = (expected.get("modules") or {}).get(mod)
        if isinstance(block, dict):
            block[field] = ports[key]
    if yaml.safe_load(updated) != expected:
        raise RuntimeError("Refusing to write config.yaml: the edit would change more than "
                           "the domain and the module ports")
    if updated != original:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(updated)
    return path, original


def _running():
    from services import workflow_service as ws
    return [r for r in ws.load_workflows(with_logs=False, statuses=("running", "pending")) or []
            if r.get("automation_type") == RUN_TYPE and (r.get("details") or {}).get("kind") == RUN_KIND]


def start(domain, ports):
    """Validate, write config.yaml, start change_ip.sh on the host. {run_id,
    unit}; Busy / ValueError for the operator, RuntimeError when the host
    refused."""
    from services import workflow_service as ws
    from services.data_location import host_run
    domain, ports = validate(domain, ports)
    with _start_lock:
        if _running():
            raise Busy("A network change is already running; wait for it in Settings -> Actions.")
        path, original = save_config(domain, ports)
        os.makedirs(TMP_DIR, exist_ok=True)
        run_id = ws.create_automation_run(RUN_TYPE, f"Change IP / ports ({domain})",
                                          details={"kind": RUN_KIND, "domain": domain, "ports": ports},
                                          case_id=ws._system_case_id())
        log_path = os.path.join(TMP_DIR, f"network-{run_id}.log")
        done_path = os.path.join(TMP_DIR, f"network-{run_id}.done")
        unit = f"intact-network-{int(time.time())}"
        cmd = (f"bash {shlex.quote(SCRIPT)} '{domain}' --yes > {shlex.quote(log_path)} 2>&1; "
               f"echo $? > {shlex.quote(done_path)}")
        ws.update_run_status(run_id, "running", progress=5,
                             details={"log_path": log_path, "done_path": done_path,
                                      "unit": unit, "tail_offset": 0})
        ws.add_log_to_run(run_id, f"config.yaml saved; starting scripts/change_ip.sh {domain} on the host ({unit})")
        try:
            rc, out, err = host_run(["systemd-run", f"--unit={unit}", "--collect", "bash", "-c", cmd], timeout=60)
        except Exception as e:  # noqa: BLE001 -- docker missing / timed out: same as a refusal
            rc, out, err = 1, "", str(e)
        if rc != 0:
            # Nothing was applied: put config.yaml back, or the next install/upgrade or
            # a hand-run change_ip.sh would apply values the operator saw fail.
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(original)
            why = f"Could not start change_ip.sh on the host: {(err or out).strip()[:300]}"
            ws.update_run_status(run_id, "failed", error=why + " (config.yaml was put back; nothing changed)")
            raise RuntimeError(why)
    _spawn(run_id)
    return {"run_id": run_id, "unit": unit}


def _spawn(run_id):
    threading.Thread(target=_tail, args=(run_id,), daemon=True, name=f"network-{run_id}").start()


def _copy_lines(run_id, log_path, offset, final=False):
    """Append the log's complete lines after `offset` to the run; new offset.
    A partial last line waits for its newline unless `final`."""
    from services import workflow_service as ws
    try:
        with open(log_path, "rb") as fh:
            fh.seek(offset)
            chunk = fh.read()
    except OSError:
        return offset
    if not final:
        chunk = chunk[:chunk.rfind(b"\n") + 1]
    for raw in chunk.splitlines():
        line = _ANSI_RE.sub("", raw.decode("utf-8", "replace")).rstrip()
        if line:
            level = "error" if "[ERROR]" in line else "warning" if "[WARN]" in line else "info"
            ws.add_log_to_run(run_id, line, level)
    if chunk:
        offset += len(chunk)
        # Stored so the backend that comes back after the restart does not repeat lines.
        ws.update_run_status(run_id, "running", details={"tail_offset": offset})
    return offset


def _tail(run_id):
    from services import workflow_service as ws
    try:
        run = ws.get_automation_run(run_id, with_logs=False) or {}
        d = run.get("details") or {}
        log_path, done_path, offset = d.get("log_path"), d.get("done_path"), int(d.get("tail_offset") or 0)
        deadline = time.time() + MAX_WAIT_SECONDS
        while not os.path.exists(done_path):
            offset = _copy_lines(run_id, log_path, offset)
            if time.time() > deadline:
                ws.update_run_status(run_id, "failed", error="change_ip.sh gave no result within "
                                     f"{MAX_WAIT_SECONDS // 3600} h; see {log_path} on the box")
                return
            time.sleep(POLL_SECONDS)
        _copy_lines(run_id, log_path, offset, final=True)
        try:
            with open(done_path) as fh:
                rc = int(fh.read().strip())
        except (OSError, ValueError):
            rc = -1
        if rc == 0:
            # The script's exit code is the verdict: a logged [ERROR] it recovered from must not flip it.
            ws.update_run_status(run_id, "completed", progress=100, force=True)
        else:
            ws.update_run_status(run_id, "failed", error=f"change_ip.sh exited with {rc}; the log above says why")
    except Exception as e:  # noqa: BLE001 -- a dead tailer must not leave the run spinning
        print(f"[NETWORK] tail of {run_id} failed: {e}", flush=True)
        try:
            ws.update_run_status(run_id, "failed", error=f"Lost track of the change: {e}")
        except Exception:  # noqa: BLE001
            pass


def reattach_running():
    """Called once at backend start: change_ip.sh restarts this backend, so a
    run still running here lost its tailer with the old process."""
    from services import workflow_service as ws
    for run in _running():
        d = run.get("details") or {}
        if d.get("log_path") and (os.path.exists(d["log_path"]) or os.path.exists(d.get("done_path") or "")):
            ws.add_log_to_run(run["run_id"], "[Backend] restarted during the change -- reattaching", "warning")
            _spawn(run["run_id"])
        else:
            ws.update_run_status(run["run_id"], "failed",
                                 error="Interrupted before change_ip.sh started: config.yaml holds the new "
                                       "values, nothing was applied. Save again or run scripts/change_ip.sh")

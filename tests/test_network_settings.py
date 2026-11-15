"""Settings -> Network (services/network_settings.py).

The popup writes config.yaml and starts scripts/change_ip.sh on the host. What
must hold: the validation is exactly lib/config.sh's (or the script refuses
what the dashboard accepted, after config.yaml was written), the domain cannot
break out of the host shell command, config.yaml keeps its comments, a second
change is refused while one runs, and the run ends from the script's exit code
also when the backend was restarted in between.
"""
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
import yaml  # noqa: E402
from services import network_settings as ns  # noqa: E402

CONFIG = """# top comment
first_login: false

domain: 10.0.0.5   # the box

modules:
  elk:
    enabled: true
    password: '123123'
    # Browser port for Kibana
    kibana_port: 5602
  iris:
    enabled: true
  # Portainer comment that belongs to portainer
  portainer:
    enabled: true
    port: 9444
  timesketch:
    enabled: true
    port: 5443
  velociraptor:
    enabled: true
    agent_port: 8000
  volweb:
    enabled: true
versions:
  elk: '9.5.5'
"""
NEW = {"kibana": 6602, "portainer": 9445, "iris": 8445,
       "timesketch": 5444, "volweb": 8003, "velociraptor_agent": 8100}


class FakeWS:
    """workflow_service with the runs in a dict."""

    def __init__(self):
        self.runs, self.logs = {}, {}

    def _system_case_id(self):
        return "SYSTEM"

    def create_automation_run(self, t, name, details=None, case_id=None):
        rid = f"{t}_{len(self.runs) + 1}"
        self.runs[rid] = {"run_id": rid, "automation_type": t, "name": name, "status": "pending",
                          "details": dict(details or {}), "case_id": case_id}
        self.logs[rid] = []
        return rid

    def update_run_status(self, rid, status, progress=None, error=None, details=None, force=False):
        r = self.runs[rid]
        r["status"] = status
        r["details"].update(details or {})
        if error:
            r["error"] = error

    def add_log_to_run(self, rid, msg, level="info", force=False):
        self.logs[rid].append((level, msg))

    def get_automation_run(self, rid, with_logs=True):
        return self.runs.get(rid)

    def load_workflows(self, with_logs=True, statuses=None):
        return [r for r in self.runs.values() if not statuses or r["status"] in statuses]


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = os.path.join(self.dir, "config.yaml")
        with open(self.cfg, "w") as fh:
            fh.write(CONFIG)
        self.ws = FakeWS()
        self.host = []
        import services
        from services import data_location
        for p in (mock.patch.object(ns, "_config_path", return_value=self.cfg),
                  mock.patch.object(ns, "TMP_DIR", self.dir),
                  mock.patch.object(ns, "_spawn"),
                  mock.patch.object(data_location, "host_run",
                                    side_effect=lambda argv, timeout=120: (self.host.append(argv) or (0, "", ""))),
                  mock.patch.dict(sys.modules, {"services.workflow_service": self.ws}),
                  mock.patch.object(services, "workflow_service", self.ws, create=True)):
            p.start()
            self.addCleanup(p.stop)

    def read(self):
        with open(self.cfg) as fh:
            return fh.read()


class MatchesLibConfig(unittest.TestCase):
    def test_table_and_reserved_ports_are_lib_config_sh_ones(self):
        src = open(os.path.join(ROOT, "lib", "config.sh")).read()
        specs = re.findall(r'\("(\w+_PORT)", "(\w+)", "(\w+)", (\d+)\)', src)
        self.assertEqual([(m, k, int(d)) for _v, m, k, d in specs],
                         [(m, k, d) for _key, m, k, d in ns.PORTS])
        reserved = re.search(r"RESERVED = (\{.*?\})\n", src, re.S).group(1)
        self.assertEqual(eval(reserved), ns.RESERVED)  # noqa: S307 -- our own source


class Validate(Base):
    def test_good(self):
        self.assertEqual(("10.0.0.9", NEW), ns.validate(" 10.0.0.9 ", NEW))
        # change_ip.sh takes IPv4 only: a host name must be refused before config.yaml is written.
        with self.assertRaises(ValueError):
            ns.validate("intact.lab.local", {})

    def test_missing_ports_keep_current_and_digit_strings_count(self):
        _d, p = ns.validate("10.0.0.9", {"iris": "8445"})
        self.assertEqual(8445, p["iris"])
        self.assertEqual(9444, p["portainer"])
        self.assertEqual(8002, p["volweb"])  # absent from config.yaml: the default

    def test_bad_ports(self):
        for bad in (0, 65536, "x", True, None, 80, 443, 8080, 9200, 8889, 5001):
            with self.assertRaises(ValueError, msg=bad):
                ns.validate("10.0.0.9", {"kibana": bad})

    def test_duplicates(self):
        with self.assertRaisesRegex(ValueError, "is also modules.elk.kibana_port"):
            ns.validate("10.0.0.9", {"kibana": 7000, "iris": 7000})

    def test_domains_that_could_reach_the_shell_are_refused(self):
        for bad in ("", "1.2.3.256", "a b", "x';reboot;'", "$(id)", "`id`", "a;b", "-rf", "x\ny", "999.1.1.1", "1.2.3"):
            with self.assertRaises(ValueError, msg=bad):
                ns.validate(bad, {})


class SaveConfig(Base):
    def test_values_set_comments_kept_missing_key_added(self):
        ns.save_config("10.0.0.9", NEW)
        text = self.read()
        cfg = yaml.safe_load(text)
        self.assertEqual("10.0.0.9", cfg["domain"])
        self.assertEqual(8445, cfg["modules"]["iris"]["port"])
        self.assertEqual(8003, cfg["modules"]["volweb"]["port"])
        self.assertEqual(8100, cfg["modules"]["velociraptor"]["agent_port"])
        self.assertIn("domain: 10.0.0.9   # the box\n", text)
        self.assertIn("# Browser port for Kibana\n    kibana_port: 6602\n", text)
        # The added key goes into its block, ahead of the next module's comment.
        self.assertIn("  iris:\n    enabled: true\n    port: 8445\n  # Portainer comment", text)
        self.assertEqual(ns.current(), {"domain": "10.0.0.9", "ports": NEW})

    def test_in_place(self):
        ino = os.stat(self.cfg).st_ino
        ns.save_config("10.0.0.9", NEW)
        self.assertEqual(ino, os.stat(self.cfg).st_ino)

    def test_saving_the_same_values_again_changes_nothing(self):
        ns.save_config("10.0.0.9", NEW)
        once = self.read()
        ns.save_config("10.0.0.9", NEW)
        self.assertEqual(once, self.read())

    def test_missing_module_block(self):
        with open(self.cfg, "w") as fh:
            fh.write(CONFIG.replace("  volweb:\n    enabled: true\n", ""))
        ns.save_config("10.0.0.9", dict(NEW, volweb=8002))  # the default: nothing to write
        with self.assertRaisesRegex(ValueError, "no modules.volweb block"):
            ns.save_config("10.0.0.9", NEW)


class Start(Base):
    def test_starts_change_ip_on_the_host_in_the_system_workspace(self):
        out = ns.start("10.0.0.9", NEW)
        run = self.ws.runs[out["run_id"]]
        self.assertEqual(("settings", "SYSTEM", "running", "network"),
                         (run["automation_type"], run["case_id"], run["status"], run["details"]["kind"]))
        argv = self.host[-1]
        self.assertEqual(["systemd-run", f"--unit={out['unit']}", "--collect", "bash", "-c"], argv[:5])
        self.assertTrue(out["unit"].startswith("intact-network-"))
        log, done = run["details"]["log_path"], run["details"]["done_path"]
        self.assertEqual(f"bash {ns.SCRIPT} '10.0.0.9' --yes > {log} 2>&1; echo $? > {done}", argv[5])
        self.assertEqual(os.path.join(self.dir, f"network-{out['run_id']}.log"), log)
        self.assertEqual(8445, yaml.safe_load(self.read())["modules"]["iris"]["port"])
        ns._spawn.assert_called_once_with(out["run_id"])

    def test_second_change_is_busy(self):
        ns.start("10.0.0.9", NEW)
        with self.assertRaises(ns.Busy):
            ns.start("10.0.0.10", NEW)

    def test_invalid_writes_nothing(self):
        with self.assertRaises(ValueError):
            ns.start("10.0.0.9", dict(NEW, iris=443))
        self.assertEqual(CONFIG, self.read())
        self.assertEqual([], self.host)

    def test_host_refusal_fails_the_run(self):
        from services import data_location
        data_location.host_run.side_effect = lambda argv, timeout=120: (1, "", "no systemd")
        with self.assertRaisesRegex(RuntimeError, "no systemd"):
            ns.start("10.0.0.9", NEW)
        self.assertEqual(["failed"], [r["status"] for r in self.ws.runs.values()])
        self.assertEqual(CONFIG, self.read())  # nothing applied, so config.yaml is put back
        self.assertEqual([], self.ws.load_workflows(statuses=("running",)))


class Tail(Base):
    def _run(self, rc=None, log="", offset=0):
        rid = self.ws.create_automation_run("settings", "x", details={"kind": "network"})
        logp, donep = os.path.join(self.dir, f"{rid}.log"), os.path.join(self.dir, f"{rid}.done")
        with open(logp, "w") as fh:
            fh.write(log)
        if rc is not None:
            with open(donep, "w") as fh:
                fh.write(f"{rc}\n")
        self.ws.update_run_status(rid, "running", details={"log_path": logp, "done_path": donep,
                                                           "tail_offset": offset})
        return rid

    def test_copies_lines_and_completes_on_zero(self):
        rid = self._run(0, "\x1b[0;34m[INFO]\x1b[0m one\n[ERROR] recovered\ntwo")
        ns._tail(rid)
        self.assertEqual([("info", "[INFO] one"), ("error", "[ERROR] recovered"), ("info", "two")],
                         self.ws.logs[rid])
        self.assertEqual("completed", self.ws.runs[rid]["status"])

    def test_fails_on_nonzero(self):
        rid = self._run(1, "x\n")
        ns._tail(rid)
        self.assertEqual("failed", self.ws.runs[rid]["status"])
        self.assertIn("exited with 1", self.ws.runs[rid]["error"])

    def test_resumes_from_the_stored_offset(self):
        rid = self._run(0, "old\nnew\n", offset=4)
        ns._tail(rid)
        self.assertEqual([("info", "new")], self.ws.logs[rid])

    def test_reattach_after_restart(self):
        alive = self._run(None, "half\n")
        lost = self.ws.create_automation_run("settings", "y", details={"kind": "network", "log_path": "/nope"})
        self.ws.update_run_status(lost, "running")
        other = self.ws.create_automation_run("settings", "z")
        self.ws.update_run_status(other, "running")
        ns.reattach_running()
        ns._spawn.assert_called_once_with(alive)
        self.assertEqual("failed", self.ws.runs[lost]["status"])
        self.assertEqual("running", self.ws.runs[other]["status"])


if __name__ == "__main__":
    unittest.main()

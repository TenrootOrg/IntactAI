"""Settings → Velociraptor: which clients run the server's version.

The client upgrade (pilot first, never a downgrade) is driven by this
classification, so it must compare versions numerically ("0.9" < "0.77.2"), treat
a client that never reported a version as unknown -- not as behind -- and read
clients()' microsecond timestamps.
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.velociraptor_clients import (  # noqa: E402
    check_embedded_config, classify, filter_clients, msi_config_text, outcomes, sort_clients, spread_seconds,
    summarize, upgrade_status, upgrade_targets, version_key)

NOW = 1_800_000_000


class Versions(unittest.TestCase):
    def test_numeric_not_text(self):
        self.assertLess(version_key("0.9.0"), version_key("0.77.2"))
        self.assertLess(version_key("0.77.1"), version_key("0.77.2"))
        self.assertEqual(version_key("v0.77.2"), (0, 77, 2))
        self.assertEqual(version_key("0.78.0-rc1"), (0, 78, 0))
        self.assertIsNone(version_key(""))
        self.assertIsNone(version_key(None))

    def test_classify(self):
        rows = [
            {"client_id": "C.1", "hostname": "WS-OLD", "os": "windows", "version": "0.77.1",
             "last_seen_at": (NOW - 30) * 1_000_000},                     # microseconds, online
            {"client_id": "C.2", "hostname": "WS-NOW", "os": "windows", "version": "0.77.2",
             "last_seen_at": NOW - 7200},                                 # seconds, offline
            {"client_id": "C.3", "hostname": "ALDC02", "os": "", "version": "", "last_seen_at": 0},
            {"client_id": "C.4", "hostname": "LAB", "os": "linux", "version": "0.78.0",
             "last_seen_at": NOW - 10},
        ]
        out = classify(rows, "0.77.2", now=NOW)
        by = {c["client_id"]: c for c in out["clients"]}
        self.assertEqual([by[k]["state"] for k in ("C.1", "C.2", "C.3", "C.4")],
                         ["behind", "current", "unknown", "ahead"])
        self.assertTrue(by["C.1"]["online"])
        self.assertFalse(by["C.2"]["online"])
        self.assertIsNone(by["C.3"]["last_seen"])
        self.assertEqual(out["counts"], {"current": 1, "behind": 1, "ahead": 1, "unknown": 1, "imported": 0, "online": 2})
        self.assertEqual(out["clients"][0]["client_id"], "C.1")          # behind first
        self.assertEqual(out["server_version"], "0.77.2")

    def test_no_server_version_means_nothing_is_called_behind(self):
        out = classify([{"client_id": "C.1", "version": "0.77.1"}], "", now=NOW)
        self.assertEqual(out["clients"][0]["state"], "unknown")


CA = "-----BEGIN CERTIFICATE-----\nMIIabc\n-----END CERTIFICATE-----\n"


class OfflineCollectionImports(unittest.TestCase):
    """The record an offline-collection import leaves (no agent name, never
    interrogated, no version) read as "version unknown" and was counted in the fleet."""
    def test_imports_are_apart_from_agents(self):
        from services.velociraptor_clients import classify, eligibility, filter_clients
        rows = [{"client_id": "C.1", "hostname": "VM", "version": "0.77.2", "agent": "velociraptor",
                 "interrogated": "F.1", "last_seen_at": NOW * 1e6},
                {"client_id": "C.2", "hostname": "NEW", "version": "", "agent": "velociraptor",
                 "interrogated": ""},
                {"client_id": "C.3", "hostname": "ALDC02", "version": "", "agent": "", "interrogated": ""}]
        st = classify(rows, "0.77.2", now=NOW)
        by = {c["client_id"]: c["state"] for c in st["clients"]}
        self.assertEqual({"C.1": "current", "C.2": "unknown", "C.3": "imported"}, by)
        self.assertEqual(2, st["total"])                          # imports are not the fleet
        self.assertEqual((1, 1), (st["counts"]["unknown"], st["counts"]["imported"]))
        imp = next(c for c in st["clients"] if c["state"] == "imported")
        self.assertEqual("imported", eligibility(imp)[0])         # never upgraded
        self.assertEqual(["C.1"], [c["client_id"] for c in filter_clients(st, hide_unknown=True)])

    def test_an_agent_not_yet_interrogated_is_not_an_import(self):
        """A freshly enrolled agent (or one whose interrogation failed) has no
        name, version or interrogation yet, like an import, but it has connected:
        it has an IP. An import also gets last_seen_at, so that cannot tell them
        apart (lab box, 2026-10-14)."""
        from services.velociraptor_clients import classify
        rows = [{"client_id": "C.9", "hostname": "NEW-PC", "version": "", "agent": "",
                 "interrogated": "", "last_ip": "10.0.0.9:51000", "last_seen_at": NOW * 1e6},
                {"client_id": "C.3", "hostname": "ALDC02", "version": "", "agent": "",
                 "interrogated": "", "last_ip": "", "last_seen_at": (NOW - 9e5) * 1e6}]
        st = classify(rows, "0.77.2", now=NOW)
        self.assertEqual({"C.9": "unknown", "C.3": "imported"},
                         {c["client_id"]: c["state"] for c in st["clients"]})
        self.assertEqual(1, st["total"])

    def test_rows_without_agent_fields_keep_the_old_meaning(self):
        from services.velociraptor_clients import classify
        st = classify([{"client_id": "C.9", "version": ""}], "0.77.2", now=NOW)
        self.assertEqual("unknown", st["clients"][0]["state"])


class Safety(unittest.TestCase):
    """The two rules that keep an upgrade from cutting clients off."""

    def test_only_an_msi_pointing_at_this_server_is_safe(self):
        ok = f"Client:\n  server_urls: [https://10.0.0.5:8000/]\n  ca_certificate: |\n    {CA.strip().replace(chr(10), chr(10) + '    ')}\n"
        self.assertEqual(check_embedded_config(ok, ["https://10.0.0.5:8000/"], CA), "")
        self.assertIn("points at", check_embedded_config(ok, ["https://10.0.0.9:8000/"], CA))
        self.assertIn("CA", check_embedded_config(ok, ["https://10.0.0.5:8000/"], CA.replace("abc", "xyz")))
        self.assertEqual(check_embedded_config("", ["https://10.0.0.5:8000/"], CA), "no client config is embedded")
        # what the plain upstream MSI gives: no Client section at all
        self.assertEqual(check_embedded_config("Frontend: {}\n", ["u"], CA), "no client config is embedded")

    def test_the_config_is_read_out_of_the_msi_cabinet(self):
        # --embedded_config cannot read an MSI ("Unable to find signature"); repack
        # writes the config as a plain file inside the cabinet, NUL-padded.
        cfg = ("version:\n  name: velociraptor\n  version: 0.77.2\nClient:\n  server_urls:\n"
               "  - https://10.0.0.5:8000/\n  ca_certificate: |\n    " + CA.strip().replace("\n", "\n    ") + "\n")
        blob = b"\xd0\xcf\x11MSCF\x00\x00Config\x00" + cfg.encode() + b"\x00" * 64 + b"rest of the msi"
        self.assertEqual(check_embedded_config(msi_config_text(blob), ["https://10.0.0.5:8000/"], CA), "")
        self.assertEqual(msi_config_text(b"\xd0\xcf\x11 plain upstream msi, no config"), "")

    def test_only_windows_and_linux_clients_behind_the_server_are_targeted(self):
        W11 = "Microsoft Windows 11 IoT Enterprise LTSC 202424H2"
        status = classify([
            {"client_id": "C.old", "hostname": "WS-OLD", "os": "windows", "release": W11, "version": "0.77.1", "last_seen_at": NOW},
            {"client_id": "C.off", "hostname": "WS-OFF", "os": "windows", "release": W11, "version": "0.77.1", "last_seen_at": NOW - 9999},
            {"client_id": "C.lin", "hostname": "LNX", "os": "linux", "release": "debian 12", "version": "0.77.1", "last_seen_at": NOW},
            # a RISX fleet: the old 0.7.x agent on a modern Windows MUST be upgradable
            {"client_id": "C.risx", "hostname": "RISX-WS", "os": "windows", "release": "Microsoft Windows 10 Enterprise 22H2", "version": "0.7.1", "last_seen_at": NOW},
            {"client_id": "C.cur", "hostname": "WS-CUR", "os": "windows", "release": W11, "version": "0.77.2", "last_seen_at": NOW},
            {"client_id": "C.new", "hostname": "WS-NEW", "os": "windows", "release": W11, "version": "0.78.0", "last_seen_at": NOW},
            {"client_id": "C.unk", "hostname": "ALDC02", "os": "", "version": "", "last_seen_at": NOW},
            {"client_id": "C.mac", "hostname": "MAC", "os": "darwin", "version": "0.77.1", "last_seen_at": NOW},
            # Go 1.21+ does not run here: the 0.77 MSI would leave a dead client
            {"client_id": "C.w2k8", "hostname": "W2K8", "os": "windows", "release": "Microsoft Windows Server 2008 R2 Standard", "version": "0.7.1", "last_seen_at": NOW},
            {"client_id": "C.w7", "hostname": "W7", "os": "windows", "release": "Microsoft Windows 7 Professional", "version": "0.7.1", "last_seen_at": NOW},
            {"client_id": "C.norel", "hostname": "NOREL", "os": "windows", "release": "", "version": "0.77.1", "last_seen_at": NOW},
        ], "0.77.2", now=NOW)
        t, _ = upgrade_targets(status, "pilot")
        self.assertEqual(len(t), 1)
        self.assertTrue(t[0]["online"])
        t, _ = upgrade_targets(status, "rest")
        self.assertEqual(sorted(c["client_id"] for c in t), ["C.lin", "C.off", "C.old", "C.risx"])
        t, refused = upgrade_targets(status, "pilot", ["C.cur", "C.new", "C.unk", "C.mac", "C.w2k8", "C.w7",
                                                       "C.norel", "C.off", "C.x"])
        self.assertEqual(t, [])
        text = " ".join(refused)
        for why in ("WS-CUR: on the server's version", "WS-NEW: 0.78.0 is newer than the server",
                    "ALDC02: no version reported", "MAC: darwin",
                    "W2K8: Microsoft Windows Server 2008 R2 Standard cannot run",
                    "W7: Microsoft Windows 7 Professional cannot run", "NOREL: Windows release unknown",
                    "WS-OFF: offline", "C.x: not a known client"):
            self.assertIn(why, text)


class Outcomes(unittest.TestCase):
    """Failures for a whole hunt from ONE hunt_flows() and ONE hunt_results() query."""
    NOW = 2_000_000_000

    def flow(self, cid, state, idle):
        return {"ClientId": cid, "Flow": {"state": state, "active_time": (self.NOW - idle) * 1e6}}

    def test_windows_1603_is_a_failure_even_while_the_flow_says_in_progress(self):
        # seen live: the flow of a failed MSI stayed IN_PROGRESS for hours after msiexec returned 1603
        res = [{"ClientId": "C.1", "ReturnCode": 1603}, {"ClientId": "C.1", "ReturnCode": 1603}]
        why = outcomes([self.flow("C.1", "IN_PROGRESS", 3600)], res, "windows", now=self.NOW)["C.1"]
        self.assertIn("msiexec returned 1603, 1603", why)
        self.assertIn("installer file that no longer exists", why)
        # but not while msiexec may still be retrying (activity in the last 5 min)
        self.assertEqual(outcomes([self.flow("C.1", "IN_PROGRESS", 60)], res, "windows", now=self.NOW), {})

    def test_windows_success_or_not_run_yet_is_no_failure(self):
        flows = [self.flow("C.ok", "IN_PROGRESS", 9999), self.flow("C.wait", "IN_PROGRESS", 9999)]
        res = [{"ClientId": "C.ok", "ReturnCode": 1603}, {"ClientId": "C.ok", "ReturnCode": 0}]
        self.assertEqual(outcomes(flows, res, "windows", now=self.NOW), {})

    def test_linux_fail_line_and_rollback(self):
        flows = [self.flow("C.fail", "FINISHED", 10), self.flow("C.rb", "FINISHED", 600),
                 self.flow("C.fresh", "FINISHED", 30)]
        res = [{"ClientId": "C.fail", "ReturnCode": 4, "Stdout": "FAIL: the new binary does not run on this host: GLIBC_2.28 not found\n"},
               {"ClientId": "C.rb", "ReturnCode": 0, "Stdout": "OK: replaced"},
               {"ClientId": "C.fresh", "ReturnCode": 0, "Stdout": "OK: replaced"}]
        out = outcomes(flows, res, "linux", now=self.NOW)
        self.assertEqual(out["C.fail"], "FAIL: the new binary does not run on this host: GLIBC_2.28 not found")
        self.assertIn("old binary was put back", out["C.rb"])
        self.assertNotIn("C.fresh", out)                       # restarting: give it time

    def test_a_flow_error_without_results(self):
        out = outcomes([{"ClientId": "C.e", "Flow": {"state": "ERROR", "status": "artifact not found", "active_time": 0}}],
                       [], "linux", now=self.NOW)
        self.assertIn("artifact not found", out["C.e"])


class Fleet(unittest.TestCase):
    """Built for thousands: the tab gets a summary and a page; waves are capped and
    can be scoped to a label; downloads spread with the wave's size."""

    def fleet(self, n=5000):
        rows = []
        for i in range(n):
            kind = i % 10
            rows.append({"client_id": f"C.{i:016x}", "hostname": f"HOST-{i:05d}",
                         "os": "darwin" if kind == 9 else ("linux" if kind >= 7 else "windows"),
                         "release": "Microsoft Windows 7 Professional" if kind == 6 else "Microsoft Windows 11 Pro",
                         "version": "" if kind == 5 else ("0.77.2" if kind < 3 else "0.77.1"),
                         "labels": ["wave-1"] if i % 4 == 0 else [],
                         "last_seen_at": NOW if i % 3 else NOW - 9999})
        return classify(rows, "0.77.2", now=NOW)

    def test_five_thousand_clients_are_summarised_fast(self):
        import time as _t
        t0 = _t.perf_counter()
        st = self.fleet()
        sm = summarize(st)
        page = filter_clients(st, reason="eligible")[:50]
        took = _t.perf_counter() - t0
        self.assertLess(took, 2.0, f"{took:.2f}s for 5,000 clients")
        self.assertEqual(sm["total"], 5000)
        self.assertEqual(sm["counts"]["current"], 1500)
        groups = {g["key"]: g["n"] for g in sm["not_upgradable"]}
        self.assertEqual(groups, {"unknown_version": 500, "unsupported_os": 500, "old_windows": 500})
        self.assertEqual(sm["eligible"], 2000)                  # behind, Windows 10+/Linux
        self.assertEqual(len(page), 50)
        self.assertEqual(sm["by_version"][0]["version"], "0.77.2")

    def test_filters(self):
        st = self.fleet(1000)
        self.assertTrue(all(c["state"] == "behind" for c in filter_clients(st, state="behind")))
        self.assertEqual([c["hostname"] for c in filter_clients(st, q="host-00042")], ["HOST-00042"])
        self.assertTrue(all(c["os"] == "linux" and not c["online"] for c in filter_clients(st, os="linux", online=False)))
        self.assertTrue(all(c["version"] == "" for c in filter_clients(st, version="")))
        self.assertEqual(len(filter_clients(st, reason="old_windows")), 100)

    def test_sort_by_column_unknowns_last(self):
        st = self.fleet(200)
        by_ver = sort_clients(list(st["clients"]), "version")
        keys = [version_key(c["version"]) for c in by_ver]
        known = [k for k in keys if k]
        self.assertEqual(known, sorted(known))
        self.assertTrue(all(k is None for k in keys[len(known):]))   # no version: always at the end
        desc = sort_clients(list(st["clients"]), "version", desc=True)
        self.assertEqual(version_key(desc[0]["version"]), (0, 77, 2))
        self.assertIsNone(version_key(desc[-1]["version"]))
        hosts = [c["hostname"] for c in sort_clients(list(st["clients"]), "host", desc=True)]
        self.assertEqual(hosts, sorted(hosts, key=str.lower, reverse=True))
        order = [upgrade_status(c)[0] for c in sort_clients(list(st["clients"]), "upgrade")]
        self.assertEqual(order[0], "will_upgrade")
        self.assertEqual(order[-1], "up_to_date")

    def test_upgrade_column(self):
        W11, W7 = "Microsoft Windows 11 Pro", "Microsoft Windows 7 Professional"
        st = classify([
            {"client_id": "C.a", "hostname": "A", "os": "windows", "release": W11, "version": "0.77.2", "last_seen_at": NOW},
            {"client_id": "C.b", "hostname": "B", "os": "windows", "release": W11, "version": "0.77.1", "last_seen_at": NOW},
            {"client_id": "C.c", "hostname": "C", "os": "windows", "release": W7, "version": "0.7.1", "last_seen_at": NOW},
            {"client_id": "C.d", "hostname": "D", "os": "darwin", "version": "0.77.1", "last_seen_at": NOW},
            {"client_id": "C.e", "hostname": "E", "os": "", "version": "", "last_seen_at": NOW},
        ], "0.77.2", now=NOW)
        got = {c["client_id"]: upgrade_status(c) for c in st["clients"]}
        self.assertEqual(got["C.a"], ("up_to_date", "up to date"))
        self.assertEqual(got["C.b"], ("will_upgrade", "will upgrade"))
        self.assertEqual(got["C.c"], ("cant", "can't — Windows 7 Professional"))
        self.assertEqual(got["C.d"], ("cant", "can't — darwin"))
        self.assertEqual(got["C.e"], ("no_version", "no version"))

    def test_unknown_versions_can_be_collapsed(self):
        st = self.fleet(1000)
        shown = filter_clients(st, hide_unknown=True)
        self.assertEqual(len(shown), 900)                       # every 10th has no version
        self.assertTrue(all(c["state"] != "unknown" for c in shown))
        self.assertEqual(len(filter_clients(st)), 1000)

    def test_waves_by_label_and_size_online_first(self):
        st = self.fleet(1000)
        t, _ = upgrade_targets(st, "rest", limit=100)
        self.assertEqual(len(t), 100)
        self.assertTrue(all(c["online"] for c in t))            # online clients go first
        t, _ = upgrade_targets(st, "rest", label="wave-1")
        self.assertTrue(t and all("wave-1" in c["labels"] for c in t))
        t, _ = upgrade_targets(st, "rest", label="no-such-label")
        self.assertEqual(t, [])

    def test_downloads_spread_with_the_wave(self):
        self.assertEqual(spread_seconds(5), 600)                 # at least 10 min
        self.assertEqual(spread_seconds(1000), 2000)             # 2 s a client
        self.assertEqual(spread_seconds(50000), 4 * 3600)        # at most 4 h
        # sized by megabytes: 1,000 Linux clients (85 MB) need ~3x the MSI window
        self.assertEqual(spread_seconds(1000, 85), 6296)
        self.assertEqual(spread_seconds(1, 500 * 27 + 500 * 85), spread_seconds(500) + spread_seconds(500, 85))


class PackagesBuiltByTheRun(unittest.TestCase):
    """No separate "Prepare packages": the upgrade run builds and verifies them as its
    first step when this server version has none (server upgrades are months apart,
    a build takes ~15 s) -- and pushes nothing if that fails."""

    def _run(self, ready, build_fails=False):
        import threading
        from unittest import mock
        from services import velociraptor_clients as vc
        from services import workflow_service as ws
        built, hunts, logs, details = [], [], [], {}
        pkg = {"package_id": "abc123", "version": "0.77.2", "built_at": "x"}

        def prepare(log=print):
            built.append(1)
            if build_fails:
                raise RuntimeError("the repacked Windows MSI is NOT safe to push: no client config is embedded")
            return pkg

        def query(vql, timeout=120):
            if "hunt(" in vql:
                hunts.append(vql)
                return [{"HuntId": "H.T"}]
            return []
        stop = threading.Event(); stop.set()          # Stop at once after the hunts: the watch is not under test
        run = {"details": {"stage": "pilot", "package_version": "0.77.2", "label": "intact-upgrade-0.77.2-pilot",
                           "targets": [{"client_id": "C.1", "hostname": "H", "os": "windows", "from": "0.77.1"}],
                           "watch_until": 9e12}}
        with mock.patch.object(vc, "packages_ready", return_value=pkg if ready else None), \
             mock.patch.object(vc, "prepare_packages", side_effect=prepare), \
             mock.patch.object(vc, "_query", side_effect=query), \
             mock.patch.object(vc, "_label_clients"), \
             mock.patch.object(ws, "get_automation_run", return_value=run), \
             mock.patch.object(ws, "add_log_to_run", side_effect=lambda rid, m, lvl="info", force=False: logs.append(m)), \
             mock.patch.object(ws, "update_run_status", side_effect=lambda rid, st, **kw: details.update(kw.get("details") or {})), \
             mock.patch.object(ws, "register_cancel_event", return_value=stop), \
             mock.patch.object(ws, "unregister_cancel"):
            vc._run_upgrade("run1")
        return built, hunts, logs, details

    def test_builds_first_when_the_version_has_no_packages(self):
        built, hunts, logs, details = self._run(ready=False)
        self.assertEqual(built, [1])
        self.assertEqual(len(hunts), 1)
        self.assertTrue(any("Preparing the client packages for 0.77.2" in m for m in logs))
        self.assertEqual(details.get("package_id"), "abc123")   # the pilot gate keys on it

    def test_reuses_ready_packages(self):
        built, hunts, logs, _ = self._run(ready=True)
        self.assertEqual(built, [])
        self.assertEqual(len(hunts), 1)
        self.assertTrue(any("Using the verified packages for 0.77.2" in m for m in logs))

    def test_a_failed_build_pushes_nothing(self):
        built, hunts, logs, _ = self._run(ready=False, build_fails=True)
        self.assertEqual(hunts, [])
        self.assertTrue(any("NOT safe to push" in m for m in logs))


class WindowsPackageComesFromTheImage(unittest.TestCase):
    """The VelociraptorWindowsMSI tool kept serving the 0.77.2 MSI under a 0.77.3
    name, and that was repacked and pushed as 0.77.3 (msiexec 1603: Windows saw a
    repair of the installed 0.77.2). The source is now the image's own MSI."""

    def test_the_source_tool_is_registered_from_the_image_before_the_repack(self):
        from unittest import mock
        from services import velociraptor_clients as vc
        calls = []
        def query(vql, timeout=120):
            calls.append(vql)
            if "CreateMSI" in vql:
                raise RuntimeError("stop here: only the order is under test")
            return []
        with mock.patch.object(vc, "_query", side_effect=query), \
             mock.patch.object(vc, "_velo_exec", return_value=mock.Mock(stdout="ab12  x\n")), \
             mock.patch.object(vc, "_register_tool") as reg:
            with self.assertRaisesRegex(RuntimeError, "stop here"):
                vc._build_windows("0.77.3", {}, lambda *a, **k: None)
        reg.assert_called_once_with(vc.SOURCE_MSI_TOOL, vc.WINDOWS_SOURCE,
                                    "velociraptor-v0.77.3-windows-amd64.msi", "0.77.3", "ab12")
        self.assertTrue(any("CreateMSI" in c for c in calls))


class UpgradeAllWithoutAPilot(unittest.TestCase):
    """The pilot is optional: Upgrade all runs without one when the operator
    confirmed (without_pilot), and is still refused when nobody said so."""

    def _start(self, **kw):
        from unittest import mock
        from services import velociraptor_clients as vc
        from services import workflow_service as ws
        logs, started = [], []
        status = {"server_version": "0.77.3", "clients": []}
        target = {"client_id": "C.1", "hostname": "H", "os": "windows", "version": "0.77.2"}
        with mock.patch.object(vc, "running_upgrade", return_value=None), \
             mock.patch.object(vc, "client_versions", return_value=status), \
             mock.patch.object(vc, "packages_ready", return_value={"package_id": "p1"}), \
             mock.patch.object(vc, "pilot_passed", return_value=False), \
             mock.patch.object(vc, "upgrade_targets", return_value=([target], [])), \
             mock.patch.object(ws, "create_automation_run", return_value="run1"), \
             mock.patch.object(ws, "add_log_to_run", side_effect=lambda rid, m, lvl="info", force=False: logs.append(m)), \
             mock.patch.object(ws, "update_run_status"), \
             mock.patch("threading.Thread", side_effect=lambda **k: mock.Mock(start=lambda: started.append(1))):
            return vc.start_upgrade("rest", **kw), logs, started

    def test_refused_without_a_pilot_unless_confirmed(self):
        with self.assertRaisesRegex(ValueError, "no pilot has passed for 0.77.3"):
            self._start()

    def test_runs_without_a_pilot_when_confirmed_and_says_so(self):
        run_id, logs, started = self._start(without_pilot=True)
        self.assertEqual(("run1", [1]), (run_id, started))
        self.assertTrue(any("without a pilot" in m for m in logs))


class RoutesFindTheirFunctions(unittest.TestCase):
    """An edit once dropped pilot_passed: every test passed, the tab answered 500."""

    def test_every_name_the_routes_import_exists(self):
        import ast
        import os as _o
        from services import velociraptor_clients as vc
        src = open(_o.path.join(_o.path.dirname(_HERE), "modules/backend/routes/velociraptor_routes.py")).read()
        names = {a.name for n in ast.walk(ast.parse(src)) if isinstance(n, ast.ImportFrom)
                 and n.module == "services.velociraptor_clients" for a in n.names}
        self.assertTrue(names)
        self.assertEqual([n for n in sorted(names) if not hasattr(vc, n)], [])


if __name__ == "__main__":
    unittest.main()

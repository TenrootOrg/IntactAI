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
    check_embedded_config, classify, filter_clients, msi_config_text, outcomes, spread_seconds,
    summarize, upgrade_targets, version_key)

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
        self.assertEqual(out["counts"], {"current": 1, "behind": 1, "ahead": 1, "unknown": 1, "online": 2})
        self.assertEqual(out["clients"][0]["client_id"], "C.1")          # behind first
        self.assertEqual(out["server_version"], "0.77.2")

    def test_no_server_version_means_nothing_is_called_behind(self):
        out = classify([{"client_id": "C.1", "version": "0.77.1"}], "", now=NOW)
        self.assertEqual(out["clients"][0]["state"], "unknown")


CA = "-----BEGIN CERTIFICATE-----\nMIIabc\n-----END CERTIFICATE-----\n"


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


class AutoPrepare(unittest.TestCase):
    """After a server upgrade the packages are rebuilt by themselves -- never the
    clients -- once per new version, never under a running upgrade, and only while
    the switch is on."""

    def _check(self, server="0.78.0", have="0.77.2", on=True, busy=None, building=None, now=1000.0):
        from unittest import mock
        from services import velociraptor_clients as vc
        started = []
        with mock.patch.object(vc, "_query", return_value=[{"v": server}]), \
             mock.patch.object(vc, "package_state", return_value={"version": have} if have else {}), \
             mock.patch.object(vc, "auto_prepare_enabled", return_value=on), \
             mock.patch.object(vc, "running_upgrade", return_value=busy), \
             mock.patch.object(vc, "preparing", return_value=building), \
             mock.patch.object(vc, "start_prepare_run", side_effect=lambda reason=None: started.append(reason) or "r1"):
            out = vc.auto_prepare_check(now=now)
        return out, started

    def setUp(self):
        from services import velociraptor_clients as vc
        vc._auto["tried"].clear()

    def test_a_new_server_version_rebuilds_once(self):
        out, started = self._check()
        self.assertEqual(out, "r1")
        self.assertIn("server is 0.78.0, packages were 0.77.2", started[0])
        self.assertEqual(self._check(now=1000.0 + 60)[1], [])               # not again ten minutes later
        self.assertEqual(self._check(now=1000.0 + 7 * 3600)[1] != [], True)  # retried after 6 h (it failed)

    def test_nothing_when_current_off_or_busy(self):
        self.assertEqual(self._check(have="0.78.0"), (None, []))
        self.assertEqual(self._check(on=False), (None, []))
        self.assertEqual(self._check(busy={"name": "upgrade"}), (None, []))
        self.assertEqual(self._check(building={"name": "prepare"}), (None, []))

    def test_the_check_never_starts_a_client_upgrade(self):
        from unittest import mock
        from services import velociraptor_clients as vc
        with mock.patch.object(vc, "start_upgrade") as up:
            self._check()
        up.assert_not_called()


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

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
    check_embedded_config, classify, msi_config_text, upgrade_targets, version_key)

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
        for why in ("WS-CUR: current", "WS-NEW: ahead", "ALDC02: unknown OS", "MAC: darwin",
                    "W2K8: Microsoft Windows Server 2008 R2 Standard cannot run",
                    "W7: Microsoft Windows 7 Professional cannot run", "NOREL: Windows release unknown",
                    "WS-OFF: offline", "C.x: not a known client"):
            self.assertIn(why, text)


class UpgradeFailure(unittest.TestCase):
    """Seen live: msiexec 1603 in a second; the client stays on the old version and
    the run waited the full 15 minutes before saying so."""

    def _check(self, os_name, state, rows):
        from unittest import mock
        from services import velociraptor_clients as vc

        def q(vql):
            # the hunt's flow on a client is F.<id>.H -- not H.<id>.H
            self.assertIn("flow_id='F.X.H'", vql)
            return [{"state": state}] if "FROM flows(" in vql else rows
        with mock.patch.object(vc, "_query", side_effect=q):
            return vc._upgrade_failed("C.1", os_name, "H.X")

    def test_windows_reports_the_msiexec_codes(self):
        why = self._check("windows", "FINISHED", [{"ReturnCode": 1603}, {"ReturnCode": 1603}])
        self.assertIn("msiexec returned 1603, 1603", why)
        self.assertIn("installer file that no longer exists", why)

    def test_linux_reports_what_the_artifact_said(self):
        why = self._check("linux", "FINISHED", [{"ReturnCode": 4, "Stdout": "FAIL: the new binary does not run "
                                                                         "on this host: GLIBC_2.28 not found\n"}])
        self.assertEqual(why, "FAIL: the new binary does not run on this host: GLIBC_2.28 not found")

    def test_linux_rolled_back_is_reported_after_a_grace_period(self):
        import time as _t
        from unittest import mock
        from services import velociraptor_clients as vc
        ok = [{"ReturnCode": 0, "Stdout": "OK: replaced /usr/local/bin/velociraptor with 0.77.2"}]

        def run(age):
            def q(vql):
                if "FROM flows(" in vql:
                    return [{"state": "FINISHED", "active_time": (_t.time() - age) * 1e6}]
                return ok
            with mock.patch.object(vc, "_query", side_effect=q):
                return vc._upgrade_failed("C.1", "linux", "H.X")
        self.assertEqual(run(30), "")                       # restarting: give it time
        self.assertIn("old binary was put back", run(600))

    def test_silent_while_running_or_when_it_worked(self):
        self.assertEqual(self._check("windows", "IN_PROGRESS", [{"ReturnCode": 1603}]), "")   # MSI kills the client
        self.assertEqual(self._check("windows", "FINISHED", [{"ReturnCode": 1603}, {"ReturnCode": 0}]), "")
        self.assertEqual(self._check("linux", "FINISHED", []), "")


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

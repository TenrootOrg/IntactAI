"""Windows channels SigmaHQ rules are written for, so their rules can fire.

The 2026-10-20 severity audit found five SigmaHQ Windows services with no channel
mapped -- PrintNightmare's critical rule among them -- and Sysmon's error (255) and
config-state (16) events with no category. These are SigmaHQ's rule bodies, as shipped.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import sigma_eval as S  # noqa: E402

PRINTNIGHTMARE = S.compile_rule({  # win_exploit_cve_2021_1675_printspooler_operational.yml
    "title": "CVE-2021-1675 Print Spooler Exploitation", "id": "4e64668a", "level": "critical",
    "logsource": {"product": "windows", "service": "printservice-operational"},
    "detection": {"selection": {"EventID": 316},
                  "keywords": ["UNIDRV.DLL, kernelbase.dll, ", " 123 ", " 1234 ", "mimispool"],
                  "condition": "selection and keywords"}})
SPOOLER_ADMIN = S.compile_rule({  # win_exploit_cve_2021_1675_printspooler.yml
    "title": "Possible CVE-2021-1675 Print Spooler Exploitation", "id": "4e64668b", "level": "high",
    "logsource": {"product": "windows", "service": "printservice-admin"},
    "detection": {"selection": {"EventID": 808, "ErrorCode": ["0x45A", "0x7e"]},
                  "keywords": ["The print spooler failed to load a plug-in module", "\\mimispool.dll", "evil.dll"],
                  "falsepositive": [" registration timed out"],
                  "condition": "(selection or keywords) and not falsepositive"}})
SYSMON_ERROR = S.compile_rule({  # sysmon_config_modification_error.yml
    "title": "Sysmon Configuration Error", "id": "815cd91b", "level": "high",
    "logsource": {"product": "windows", "category": "sysmon_error"},
    "detection": {"selection_error": {"Description|contains": [
                      "Failed to open service configuration with error",
                      "Failed to connect to the driver to update configuration"]},
                  "filter_by_errorcode": {"Description|contains": [
                      "Failed to open service configuration with error 19"]},
                  "condition": "selection_error and not 1 of filter*"}})


def fires(rule, row):
    return [r["title"] for r in S.evaluate(row, [rule])]


class PrintSpooler(unittest.TestCase):
    def test_printnightmare_driver_add_is_critical(self):
        row = {"EventID": 316, "Channel": "Microsoft-Windows-PrintService/Operational",
               "Message": "Printer driver 1234 for Windows x64 Version-3 was added or updated. Files:- "
                          "UNIDRV.DLL, kernelbase.dll, evil.dll."}
        self.assertEqual(["CVE-2021-1675 Print Spooler Exploitation"], fires(PRINTNIGHTMARE, row))

    def test_an_ordinary_driver_install_is_quiet(self):
        row = {"EventID": 316, "Channel": "Microsoft-Windows-PrintService/Operational",
               "Message": "Printer driver HP Universal Printing PCL 6 was added or updated. Files:- hpcu250u.dll."}
        self.assertEqual([], fires(PRINTNIGHTMARE, row))

    def test_the_admin_channel_plugin_load_failure(self):
        row = {"EventID": 808, "Channel": "Microsoft-Windows-PrintService/Admin", "ErrorCode": "0x45A",
               "Message": "The print spooler failed to load a plug-in module C:\\x\\mimispool.dll"}
        self.assertEqual(["Possible CVE-2021-1675 Print Spooler Exploitation"], fires(SPOOLER_ADMIN, row))
        row["Message"] = "The print spooler failed to load a plug-in module PrintConfig registration timed out"
        self.assertEqual([], fires(SPOOLER_ADMIN, row), "the rule's own false-positive filter")


class SysmonStates(unittest.TestCase):
    def test_a_sysmon_config_error_is_its_own_category(self):
        row = {"EventID": 255, "Channel": "Microsoft-Windows-Sysmon/Operational",
               "Description": "Failed to connect to the driver to update configuration"}
        self.assertEqual(["Sysmon Configuration Error"], fires(SYSMON_ERROR, row))
        row["EventID"] = 1                                    # same text on a process event: not this rule
        self.assertEqual([], fires(SYSMON_ERROR, row))

    def test_the_new_channels_map_to_their_services(self):
        for chan, svc in (("Microsoft-Windows-DNS-Server/Analytical", "dns-server-analytic"),
                          ("Microsoft-Windows-SmbClient/Connectivity", "smbclient-connectivity"),
                          ("Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
                           "certificateservicesclient-lifecycle-system")):
            self.assertIn(("windows", None, svc), S.profiles(S.Event({"EventID": 1, "Channel": chan})), chan)


if __name__ == "__main__":
    unittest.main()

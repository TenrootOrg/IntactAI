"""EDR file renames and Sysmon 29 reach their medium SigmaHQ rules.

2026-10-20 severity audit, medium tier: file_rename (ransomware appending an extension:
report.docx -> report.docx.locked) is written for the Kernel-File ETW provider, which no
export carries; Defender XDR (FileRenamed), Elastic Defend (rename) and SentinelOne
(File Rename) all log the old and the new name. Sysmon 29 (FileExecutableDetected) was
missing from the event id map. A rename stays a file_event too: the new name is a file
written. Rule bodies are SigmaHQ's.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import external_logs as X, sigma_eval as S  # noqa: E402

EXT = [".doc", ".docx", ".jpeg", ".jpg", ".lnk", ".pdf", ".png", ".pst", ".rtf", ".xls", ".xlsx"]
RANSOM = S.compile_rule({  # file_rename_win_ransomware.yml
    "title": "Suspicious Appended Extension", "id": "e3f673b3", "level": "medium",
    "logsource": {"product": "windows", "category": "file_rename"},
    "detection": {"selection": {"SourceFilename|endswith": EXT, "TargetFilename|contains": [e + "." for e in EXT]},
                  "filter_main_generic": {"TargetFilename|endswith": [".backup", ".bak", ".old", ".orig", ".temp", ".tmp"]},
                  "filter_optional_anaconda": {"TargetFilename|contains": ":\\ProgramData\\Anaconda3\\",
                                               "TargetFilename|endswith": ".c~"},
                  "condition": "selection and not 1 of filter_main_* and not 1 of filter_optional_*"}})
WRITTEN = S.compile_rule({  # any file_event rule must still see the new name
    "title": "Locked File Written", "id": "t1", "level": "medium",
    "logsource": {"product": "windows", "category": "file_event"},
    "detection": {"selection": {"TargetFilename|endswith": ".locked"}, "condition": "selection"}})
SED = S.compile_rule({  # file_executable_detected_win_susp_embeded_sed_file.yml
    "title": "Potentially Suspicious Self Extraction Directive File Created", "id": "760e75d8", "level": "medium",
    "logsource": {"product": "windows", "category": "file_executable_detected"},
    "detection": {"selection": {"TargetFilename|endswith": ".sed"}, "condition": "selection"}})
RULES = [RANSOM, WRITTEN, SED]
OLD = "C:\\Users\\jdoe\\Documents\\report.docx"


def titles(raw):
    return sorted(h["title"] for h in S.evaluate(X.sigma_event(raw), RULES))


BOTH = ["Locked File Written", "Suspicious Appended Extension"]


class Renames(unittest.TestCase):
    def defender(self, new, prev_folder="C:\\Users\\jdoe\\Documents", act="FileRenamed"):
        return {"Timestamp": "2026-10-20T10:05:00Z", "DeviceName": "ws1", "ActionType": act,
                "FileName": new.rsplit("\\", 1)[1], "FolderPath": new, "PreviousFileName": "report.docx",
                "PreviousFolderPath": prev_folder, "InitiatingProcessFolderPath": "C:\\Users\\jdoe\\AppData\\x.exe",
                "InitiatingProcessFileName": "x.exe", "InitiatingProcessAccountName": "jdoe"}

    def test_defender(self):
        self.assertEqual(BOTH, titles(self.defender(OLD + ".locked")))
        self.assertEqual(BOTH, titles(self.defender(OLD + ".locked", prev_folder=OLD)),
                         "PreviousFolderPath that already ends with the file name")

    def test_the_rules_own_backup_filter(self):
        self.assertEqual([], titles(self.defender(OLD + ".bak")))

    def test_a_write_with_an_empty_previous_name_is_no_rename(self):
        row = {**self.defender(OLD + ".locked", act="FileCreated"), "PreviousFileName": "", "PreviousFolderPath": ""}
        self.assertEqual(["Locked File Written"], titles(row))

    def test_elastic_defend(self):
        row = {"event.category": ["file"], "event.type": ["change"], "event.action": "rename",
               "file.path": OLD + ".locked", "file.Ext.original.path": OLD,
               "process.executable": "C:\\Users\\jdoe\\AppData\\x.exe", "host.os.type": "windows"}
        self.assertEqual(BOTH, titles(row))

    def test_sentinelone(self):
        row = {"event.type": "File Rename", "tgt.file.path": OLD + ".locked", "tgt.file.oldPath": OLD,
               "src.process.image.path": "C:\\Users\\jdoe\\AppData\\x.exe", "endpoint.os": "windows"}
        self.assertEqual(BOTH, titles(row))


class Sysmon29(unittest.TestCase):
    def test_an_executable_sed_file(self):
        ev = {"EventID": 29, "Channel": "Microsoft-Windows-Sysmon/Operational",
              "Provider": "Microsoft-Windows-Sysmon", "Image": "C:\\Windows\\System32\\iexpress.exe",
              "TargetFilename": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\IXP000.TMP\\x.sed"}
        self.assertEqual(["Potentially Suspicious Self Extraction Directive File Created"], titles(ev))


if __name__ == "__main__":
    unittest.main()

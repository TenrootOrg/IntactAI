#!/usr/bin/env python3
"""scripts/dev/escu_to_sigma.py: the SPL shapes that once translated wrong or not at
all. A wrong translation ships a detection that fires on everything (Notepad with
no arguments lost its regex and matched every Notepad), so each shape is pinned."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "dev"))
import escu_to_sigma as T  # noqa: E402


def tr(search, name="Test", typ="TTP"):
    return T.translate({"name": name, "id": "x", "type": typ, "search": search}, {})


class Translate(unittest.TestCase):
    def test_a_regex_pipe_is_kept(self):
        r = tr('| tstats count FROM datamodel=Endpoint.Processes WHERE Processes.process_name=notepad.exe '
               'BY Processes.process | `drop_dm_object_name(Processes)` | regex process="(?i)(notepad\\.exe.{0,4}$)"'
               ' | `notepad_filter`')
        d = r["detection"]
        self.assertEqual("(?i)(notepad\\.exe.{0,4}$)", d["sel2"]["CommandLine|re"])
        self.assertEqual("(sel1 and sel2)", d["condition"])

    def test_a_pipe_inside_quotes_is_not_a_pipe(self):
        self.assertEqual(['a=1 ', ' regex process="(key|pem)" ', ' stats count'],
                         T.split_pipes('a=1 | regex process="(key|pem)" | stats count'))

    def test_a_filtering_pipe_is_skipped(self):
        with self.assertRaises(T.Skip):
            tr('`wineventlog_security` EventCode=4625 | stats count by user | where count > 5')

    def test_display_pipes_keep_the_filter(self):
        r = tr('`wineventlog_security` EventCode=4728 | eval x=1 | rename a as b | stats count by user')
        self.assertEqual({"EventID": "4728"}, r["detection"]["sel1"])

    def test_a_pipe_name_ends_at_a_newline(self):
        r = tr('`wineventlog_security` EventCode=4728 | stats\n count by user')
        self.assertEqual({"EventID": "4728"}, r["detection"]["sel1"])

    def test_web_data_model_is_any_http_log(self):
        r = tr('| tstats count FROM datamodel=Web WHERE Web.url="*/x.vm*" Web.status IN (200, unknown) '
               'BY Web.src | `drop_dm_object_name("Web")`')
        self.assertEqual({"category": "web"}, r["logsource"])
        self.assertEqual({"c-uri": "*/x.vm*"}, r["detection"]["sel1"])
        self.assertEqual([None, "200"], r["detection"]["sel2"]["sc-status"])     # unknown = no status

    def test_quoted_field_and_multivalue_path(self):
        r = tr('`kube_audit` "objectRef.resource"=cronjobs user.groups{} IN ("system:unauthenticated")')
        self.assertEqual({"product": "kubernetes", "service": "audit"}, r["logsource"])
        self.assertEqual({"objectRef.resource": "cronjobs"}, r["detection"]["sel1"])
        self.assertEqual({"user.groups": "*system:unauthenticated*"}, r["detection"]["sel2"])

    def test_auditd_path_join_is_one_full_path_condition(self):
        r = tr('`linux_auditd`\n(type=PATH OR type=CWD)\n| rex "msg=audit\\([^)]*:(?<audit_id>\\d+)\\)"\n'
               '| stats values(name) as names by audit_id, host\n'
               '| eval matched_paths = mvfilter(match(candidate_paths, "/etc/ld\\.so\\.preload.*"))\n'
               '| eval match_count = mvcount(matched_paths)\n| where match_count > 0\n| stats count by dest')
        self.assertEqual({"type": "PATH"}, r["detection"]["sel1"])
        self.assertEqual({"full_path|re": "/etc/ld\\.so\\.preload.*"}, r["detection"]["sel2"])

    def test_an_unmapped_field_with_a_real_value_is_never_dropped(self):
        with self.assertRaises(T.Skip):        # would read "every intrusion event"
            tr('`wineventlog_security` EventCode=4625 signature_id=65118')
        r = tr('`wineventlog_security` EventCode=4625 NOT src IN ("-", "unknown")')
        self.assertEqual({"EventID": "4625"}, r["detection"]["sel1"])

    def test_a_search_on_spath_keys_is_a_condition(self):
        r = tr('`cisco_duo_administrator` action=policy_update | spath input=description '
               '| search require_lock=false | rename object as user | stats count by user')
        self.assertEqual("(sel1 and sel2)", r["detection"]["condition"])
        self.assertEqual({"require_lock": "false"}, r["detection"]["sel2"])
        with self.assertRaises(T.Skip):        # output named after a list element: no such field
            tr('`amazon_security_lake` api.operation=ModifySnapshotAttribute | spath input=api.request.data '
               'path=createVolumePermission.add.items{}.group output=group | search group=all')

    def test_a_where_on_raw_fields_is_regexes(self):
        r = tr('`wineventlog_security` EventCode=4781 | where match(TargetSid, "S-1-5-21-.*-50[0-4]$") '
               '| stats count by user')
        self.assertEqual({"TargetSid|re": "S-1-5-21-.*-50[0-4]$"}, r["detection"]["sel2"])
        with self.assertRaises(T.Skip):        # a computed field
            tr('`wineventlog_security` EventCode=4625 | stats count by user | where count > 5')
        with self.assertRaises(T.Skip):        # one field against another
            tr('`wineventlog_security` EventCode=4728 | where lower(user)=lower(src_user)')

    def test_a_list_of_objects_is_skipped(self):
        with self.assertRaises(T.Skip):
            tr('`o365_management_activity` ModifiedProperties{}.Name=X')


if __name__ == "__main__":
    unittest.main()

"""Other AWS accounts through a role in each: input checked, one failing account costs
only itself, records tagged with their account."""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
_optional_deps.stub("markupsafe", "werkzeug", "werkzeug.utils")

from services.aws import boto_client, members  # noqa: E402


class FakeAws:
    def __init__(self, deny=()):
        self.deny, self.assumed = deny, []

    def assume_role(self, RoleArn, **kw):
        acct = RoleArn.split(":")[4]
        self.assumed.append(RoleArn)
        if acct in self.deny:
            raise RuntimeError("AccessDenied: not authorized to perform sts:AssumeRole")
        return {"Credentials": {"AccessKeyId": f"ASIA{acct}", "SecretAccessKey": "s", "SessionToken": "t"}}

    def get_paginator(self, name):
        class P:
            def paginate(self):
                return [{"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}, {"Id": "222222222222", "Status": "SUSPENDED"},
                                      {"Id": "333333333333", "Status": "ACTIVE"}]}]
        return P()


class MemberAccounts(unittest.TestCase):
    def setUp(self):
        self.fake = FakeAws(deny=("333333333333",))
        self._orig = boto_client.client
        boto_client.client = lambda *a, **k: self.fake

    def tearDown(self):
        boto_client.client = self._orig

    def test_input_is_checked(self):
        self.assertEqual(members.clean("111111111111, 333333333333\n111111111111"), (["111111111111", "333333333333"], None))
        self.assertEqual(members.clean("ALL"), ("all", None))
        self.assertEqual(members.clean(""), ([], None))
        self.assertIsNotNone(members.clean("1234")[1])

    def test_all_lists_the_active_accounts(self):
        self.assertEqual(members.member_accounts({"member_accounts": "all"}), ["111111111111", "333333333333"])

    def test_one_failing_account_costs_only_itself_and_the_main_account_is_skipped(self):
        got = list(members.member_configs({"access_key_id": "AK", "secret_access_key": "x", "member_role": "Audit"},
                                          ["999999999999", "111111111111", "333333333333"], preflight_account="999999999999"))
        self.assertEqual([a for a, _c, _e in got], ["111111111111", "333333333333"])
        ok, bad = got
        self.assertEqual((ok[1]["access_key_id"], ok[1]["session_token"], ok[2]), ("ASIA111111111111", "t", None))
        self.assertNotIn("member_accounts", ok[1])
        self.assertIsNone(bad[1])
        self.assertIn("could not assume Audit", bad[2])
        self.assertEqual(self.fake.assumed[0], "arn:aws:iam::111111111111:role/Audit")

    def test_a_bad_role_name_is_refused(self):
        got = list(members.member_configs({"member_role": "x y"}, ["111111111111"]))
        self.assertIn("invalid role name", got[0][2])

    def test_merged_records_carry_their_account(self):
        into = {"AWS.CloudTrail": [{"eventName": "A"}]}
        members.merge(into, {"AWS.CloudTrail": [{"eventName": "B"}], "AWS.IAM": [{"ResourceName": "u"}]}, "111111111111")
        self.assertEqual([r.get("AccountId") for r in into["AWS.CloudTrail"]], [None, "111111111111"])
        self.assertEqual(into["AWS.IAM"][0]["AccountId"], "111111111111")


if __name__ == "__main__":
    unittest.main()

"""Cloud mapper: AWS root is an identity, account-setup findings are never dropped
by a case window, and a malformed record costs only itself.

WHY (case "AWS TEST", 2026-10-26):
  * root made 9 of the 10 findings but had no identity card -- it was labelled
    "root", a word the Identities page drops as generic;
  * the only critical finding ("Scanner_SVC: admin + active key + no MFA") is
    account SETUP, was stamped with the scan's time (09:13), and the case window
    ended at 09:12 -- so the case showed 10 mediums and no critical.
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402

from services.fusion.mappers import cloud as cloud_mod  # noqa: E402
from services.fusion.mappers.cloud import map_cloud  # noqa: E402
from services.fusion.correlate import in_window  # noqa: E402

ACCT = "123456789012"


def _root_event(ts="2026-10-25T21:35:36Z", name="DeleteUser"):
    return {"rule_title": "AWS Root Credentials", "severity": "medium", "_timestamp": ts[:19].replace("T", " "),
            "matched_record": {"eventTime": ts, "eventName": name, "sourceIPAddress": "203.0.113.10",
                               "userIdentity": {"type": "Root", "principalId": ACCT, "accountId": ACCT,
                                                "arn": f"arn:aws:iam::{ACCT}:root"}}}


def _user_event():
    return {"rule_title": "AWS IAM Backdoor Users Keys", "severity": "medium", "_timestamp": "2026-10-25 18:11:34",
            "matched_record": {"eventTime": "2026-10-25T18:11:34Z", "eventName": "CreateAccessKey",
                               "userIdentity": {"type": "IAMUser", "userName": "Scanner_SVC",
                                                "arn": f"arn:aws:iam::{ACCT}:user/Scanner_SVC"}}}


def _state():
    return {"rule_title": "State: User Scanner_SVC has admin privileges + 1 active key(s)",
            "severity": "critical", "_severity": "critical", "_timestamp": None,
            "_finding_time": "2026-10-26T09:13:00.0", "_state_snapshot": True, "_source": "AWS.IAM",
            "matched_record": '{"ResourceName": "Scanner_SVC", "ResourceType": "AWS::IAM::User"}'}


def _by_type(ents, t):
    return [e for e in ents if e.type == t]


class AwsRootIsAnIdentity(unittest.TestCase):
    def test_root_gets_its_own_readable_key(self):
        ents, rels = map_cloud([_root_event()], run_id="r1", provider="aws", account=ACCT)
        acc = _by_type(ents, "account")
        self.assertEqual([a.id for a in acc], [f"account:cloud:aws-root:{ACCT}"])
        self.assertEqual(acc[0].label, "aws-root")
        self.assertTrue(any(r.src == acc[0].id and r.kind == "executed" for r in rels))

    def test_root_found_by_arn_alone_and_without_account(self):
        f = _root_event()
        f["matched_record"]["userIdentity"] = {"arn": f"arn:aws:iam::{ACCT}:root"}
        ents, _ = map_cloud([f], run_id="r1", provider="aws")
        self.assertEqual(_by_type(ents, "account")[0].id, f"account:cloud:aws-root:{ACCT}")
        f["matched_record"]["userIdentity"] = {"type": "Root"}
        ents, _ = map_cloud([f], run_id="r1", provider="aws")
        self.assertEqual(_by_type(ents, "account")[0].id, "account:cloud:aws-root:unknown")

    def test_other_users_are_keyed_exactly_as_before(self):
        ents, _ = map_cloud([_user_event()], run_id="r1", provider="aws", account=ACCT)
        self.assertEqual([a.id for a in _by_type(ents, "account")], ["account:cloud:scanner_svc"])

    def test_azure_is_untouched(self):
        f = _root_event()
        ents, _ = map_cloud([f], run_id="r1", provider="azure", account="tenant")
        self.assertNotIn("aws-root", " ".join(a.id for a in _by_type(ents, "account")))


def _state_keyed(scan="2026-10-26T09:13:00.0"):
    f = _state()
    f["_finding_time"] = scan
    f["matched_record"] = ('{"ResourceName": "Scanner_SVC", "ResourceType": "AWS::IAM::User", "UserAgeDays": 777.9, '
                           '"AccessKeys": [{"Status": "Active", "CreateDate": "2025-02-12T22:04:21+00:00"}, '
                           '{"Status": "Inactive", "CreateDate": "2026-01-01T00:00:00+00:00"}]}')
    return f


class AccountSetupIsNeverOutsideTheWindow(unittest.TestCase):
    def test_setup_is_dated_from_its_active_key_until_the_scan(self):
        ents, _ = map_cloud([_state_keyed()], run_id="r1", provider="aws", account=ACCT)
        ev = _by_type(ents, "event")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0].severity, "critical")
        self.assertEqual((ev[0].first_seen, ev[0].last_seen), ("2025-02-12T22:04:21", "2026-10-26T09:13:00"))
        self.assertNotIn("summary_extra", ev[0].attrs)          # no "around it" for a setup row

    def test_a_window_ending_before_the_scan_still_shows_it(self):
        from services.fusion import correlate
        ents, rels = map_cloud([_state_keyed()], run_id="r1", provider="aws", account=ACCT)
        g = correlate.assemble("c", [(ents, rels)], ["r1"])
        f = next(x for x in g.findings if "State:" in x.title)
        self.assertTrue(correlate.finding_in_window(f, {"start": "2016-10-26T09:12:12", "end": "2026-10-26T09:12:12"}))
        self.assertFalse(correlate.finding_in_window(f, {"start": "2024-01-01T00:00:00", "end": "2024-12-31T00:00:00"}))

    def test_a_recent_case_window_keeps_an_old_but_current_setup(self):
        from services.fusion import correlate
        ents, rels = map_cloud([_state_keyed()], run_id="r1", provider="aws", account=ACCT)
        g = correlate.assemble("c", [(ents, rels)], ["r1"], window={"start": "2026-10-01T00:00:00", "end": "2026-10-31T00:00:00"})
        self.assertTrue(any("State:" in f.title for f in g.findings))
        g = correlate.assemble("c", [(ents, rels)], ["r1"], window={"start": "2024-01-01T00:00:00", "end": "2024-12-31T00:00:00"})
        self.assertFalse(any("State:" in f.title for f in g.findings))   # before it existed

    def test_keyless_setup_is_dated_from_the_user_s_age(self):
        f = _state_keyed()
        f["matched_record"] = '{"ResourceName": "Scanner_SVC", "UserAgeDays": 10, "AccessKeys": []}'
        ents, _ = map_cloud([f], run_id="r1", provider="aws", account=ACCT)
        self.assertEqual(_by_type(ents, "event")[0].first_seen, "2026-10-16T09:13:00")

    def test_without_any_date_it_is_dated_at_the_scan(self):
        # never "Undated" (2026-10-26: the user asked) -- "seen like this at the scan"
        ents, _ = map_cloud([_state()], run_id="r1", provider="aws", account=ACCT)
        ev = _by_type(ents, "event")
        self.assertEqual((ev[0].first_seen, ev[0].last_seen), ("2026-10-26T09:13:00", "2026-10-26T09:13:00"))

    def test_exposure_rows_are_dated_from_the_resource_and_name_it_for_masking(self):
        f = _state_keyed()
        f["rule_title"] = "State: Lightsail instance web-01 lets the internet reach 22"
        f["matched_record"] = ('{"ResourceName": "web-01", "ResourceType": "AWS::Lightsail::Instance", '
                               '"Since": "2024-01-15T10:00:00+00:00"}')
        ents, _ = map_cloud([f], run_id="r1", provider="aws", account=ACCT)
        ev = _by_type(ents, "event")[0]
        self.assertEqual(ev.first_seen, "2024-01-15T10:00:00")
        self.assertEqual(ev.attrs["cloud_resources"], ["web-01"])
        self.assertEqual(_by_type(ents, "account"), [])          # a server is not an identity

    def test_two_scans_of_the_same_setup_are_one_event(self):
        a, _ = map_cloud([_state_keyed()], run_id="r1", provider="aws", account=ACCT)
        b, _ = map_cloud([_state_keyed("2026-10-27T10:00:00")], run_id="r2", provider="aws", account=ACCT)
        self.assertEqual(_by_type(a, "event")[0].id, _by_type(b, "event")[0].id)

    def test_real_events_keep_their_time(self):
        ents, _ = map_cloud([_user_event()], run_id="r1", provider="aws", account=ACCT)
        self.assertEqual(_by_type(ents, "event")[0].first_seen, "2026-10-25T18:11:34")


class ABadRecordCostsOnlyItself(unittest.TestCase):
    def test_malformed_records_never_break_the_rest(self):
        junk = [None, "text", 42, [], {}, {"matched_record": None}, {"matched_record": {"userIdentity": "Root"}},
                {"matched_record": {"userIdentity": {"type": "Root", "arn": None, "accountId": None}}},
                {"matched_record": {"userIdentity": ["Root"]}}, {"_state_snapshot": True}]
        ents, _ = map_cloud(junk + [_root_event(), _user_event(), _state()], run_id="r1", provider="aws",
                            account=ACCT)
        ids = {a.id for a in _by_type(ents, "account")}
        self.assertIn(f"account:cloud:aws-root:{ACCT}", ids)
        self.assertIn("account:cloud:scanner_svc", ids)
        self.assertIn("critical", {e.severity for e in _by_type(ents, "event")})


def _ev(ts, name, *, user="Scanner_SVC", rule="AWS IAM Backdoor Users Keys", key="AKIAAAAA",
        target=None, role=None, ip="203.0.113.10", eid=None, ui=None):
    rp = {}
    if target: rp["userName"] = target
    if role: rp["roleName"] = role
    rec = {"eventTime": ts, "eventName": name, "sourceIPAddress": ip, "eventID": eid or f"{name}-{ts}",
           "requestParameters": rp,
           "userIdentity": ui or {"type": "IAMUser", "userName": user, "accessKeyId": key,
                                  "arn": f"arn:aws:iam::{ACCT}:user/{user}"}}
    return {"rule_title": rule, "severity": "medium", "_timestamp": ts[:19].replace("T", " "), "matched_record": rec}


def _evs(ents):
    return [e for e in ents if e.type == "event"]


class OneRowPerSession(unittest.TestCase):
    def test_a_root_session_is_one_row_with_its_count_and_span(self):
        times = ["2026-10-25T21:34:53Z", "2026-10-25T21:35:05Z", "2026-10-25T21:35:19Z", "2026-10-25T21:35:28Z",
                 "2026-10-25T21:35:36Z"]
        ents, _ = map_cloud([_root_event(t) for t in times], run_id="r1", provider="aws", account=ACCT)
        ev = _evs(ents)
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0].first_seen, ev[0].last_seen), ("2026-10-25T21:34:53", "2026-10-25T21:35:36"))
        self.assertEqual(ev[0].attrs["hits"], 5)
        self.assertEqual(len(ev[0].attrs["member_eids"]), 4)
        self.assertIn("5 events by aws-root", ev[0].attrs["summary_extra"])

    def test_a_long_gap_or_another_source_ip_start_a_new_row(self):
        a = _ev("2026-10-25T10:00:00Z", "CreateAccessKey")
        b = _ev("2026-10-25T10:40:00Z", "CreateAccessKey")                     # 40 min later
        c = _ev("2026-10-25T10:41:00Z", "CreateAccessKey", ip="198.51.100.7")  # elsewhere
        ents, _ = map_cloud([a, b, c], run_id="r1", provider="aws", account=ACCT)
        self.assertEqual(len(_evs(ents)), 3)

    def test_a_console_session_rotating_its_key_is_one_row(self):
        fs = [_ev("2026-10-25T14:51:09Z", "ConsoleLogin", key=""), _ev("2026-10-25T15:07:34Z", "X", key="ASIA1"),
              _ev("2026-10-25T15:17:14Z", "Y", key="ASIA2")]
        ents, _ = map_cloud(fs, run_id="r1", provider="aws", account=ACCT)
        self.assertEqual(len(_evs(ents)), 1)
        self.assertEqual(_evs(ents)[0].attrs["hits"], 3)

    def test_a_lone_event_keeps_its_old_id(self):
        old, _ = cloud_mod._map_each([_user_event()], run_id="r1", provider="aws", account=ACCT)
        new, _ = map_cloud([_user_event()], run_id="r1", provider="aws", account=ACCT)
        self.assertEqual([e.id for e in _evs(old)], [e.id for e in _evs(new)])


class WhoWasActedOn(unittest.TestCase):
    def test_the_target_user_and_role_get_cards_linked_to_the_event(self):
        ents, rels = map_cloud([_ev("2026-10-25T18:11:34Z", "CreateAccessKey", target="web-deployer"),
                                _ev("2026-10-25T19:00:00Z", "AttachRolePolicy", role="Deployer", rule="R2")],
                               run_id="r1", provider="aws", account=ACCT)
        ids = {a.id for a in _by_type(ents, "account")}
        self.assertTrue({"account:cloud:web-deployer", "account:cloud:role/deployer",
                         "account:cloud:scanner_svc"} <= ids)
        about = {(r.src, r.kind) for r in rels}
        self.assertIn(("account:cloud:web-deployer", "event_about"), about)
        self.assertIn(("account:cloud:role/deployer", "event_about"), about)

    def test_acting_on_yourself_is_not_a_target(self):
        _, rels = map_cloud([_ev("2026-10-25T18:11:34Z", "CreateAccessKey", target="Scanner_SVC")],
                            run_id="r1", provider="aws", account=ACCT)
        self.assertFalse([r for r in rels if r.kind == "event_about" and r.src.startswith("account:")])


class TheActorsSurroundingEvents(unittest.TestCase):
    def test_the_chain_around_a_detection_is_in_its_summary(self):
        det = _ev("2026-10-25T18:11:34Z", "CreateAccessKey", target="web-deployer", eid="k1")
        ctx = [det["matched_record"],
               _ev("2026-10-25T18:11:30Z", "CreateUser", target="web-deployer")["matched_record"],
               _ev("2026-10-25T18:11:32Z", "PutUserPolicy", target="web-deployer")["matched_record"],
               _ev("2026-10-25T18:11:33Z", "CreateUser", user="someone-else", target="x")["matched_record"],
               _ev("2026-10-25T19:30:00Z", "DeleteUser", target="y")["matched_record"]]      # too far
        ents, _ = map_cloud([det], run_id="r1", provider="aws", account=ACCT, context=ctx)
        ev = _evs(ents)[0]
        self.assertEqual(ev.attrs["context"], ["18:11:30 CreateUser → web-deployer",
                                               "18:11:32 PutUserPolicy → web-deployer"])

    def test_context_is_capped(self):
        det = _ev("2026-10-25T18:11:34Z", "CreateAccessKey", eid="k1")
        ctx = [_ev(f"2026-10-25T18:{m:02d}:00Z", "ListUsers", eid=f"l{m}")["matched_record"] for m in range(0, 26)]
        ents, _ = map_cloud([det], run_id="r1", provider="aws", account=ACCT, context=ctx)
        self.assertEqual(len(_evs(ents)[0].attrs["context"]), cloud_mod.CONTEXT_MAX)
        self.assertIn("more)", _evs(ents)[0].attrs["summary_extra"])


class SsoAndRoles(unittest.TestCase):
    def _actor(self, arn, typ="AssumedRole"):
        f = _ev("2026-10-25T18:11:34Z", "CreateAccessKey", ui={"type": typ, "arn": arn, "accessKeyId": "ASIA1"})
        ents, _ = map_cloud([f], run_id="r1", provider="aws", account=ACCT)
        return [a.id for a in _by_type(ents, "account")]

    def test_an_sso_person_is_the_same_key_as_their_ad_account(self):
        self.assertEqual(self._actor(f"arn:aws:sts::{ACCT}:assumed-role/AWSReservedSSO_Admin_ab12/rami@omcdom.com"),
                         ["account:domain:omcdom\\rami"])

    def test_an_sso_username_without_domain(self):
        self.assertEqual(self._actor(f"arn:aws:sts::{ACCT}:assumed-role/AWSReservedSSO_Admin_ab12/rami"),
                         ["account:cloud:rami"])

    def test_a_workload_role_session_is_the_role(self):
        self.assertEqual(self._actor(f"arn:aws:sts::{ACCT}:assumed-role/LambdaExec/i-0abc"),
                         ["account:cloud:role/lambdaexec"])

    def test_federated_user(self):
        self.assertEqual(self._actor(f"arn:aws:sts::{ACCT}:federated-user/bob", typ="FederatedUser"),
                         ["account:cloud:bob"])


class ServiceNamesAreNotIndicators(unittest.TestCase):
    def test_only_real_addresses_become_iocs(self):
        fs = [_ev("2026-10-25T18:00:00Z", "A", ip="iam.amazonaws.com", rule="r1"),
              _ev("2026-10-25T18:00:00Z", "B", ip="AWS Internal", rule="r2"),
              _ev("2026-10-25T18:00:00Z", "C", ip="203.0.113.10", rule="r3")]
        ents, _ = map_cloud(fs, run_id="r1", provider="aws", account=ACCT)
        self.assertEqual([e.label for e in _by_type(ents, "ioc")], ["203.0.113.10"])


class NothingElseMoves(unittest.TestCase):
    def test_azure_output_is_exactly_the_old_mapping(self):
        fs = [_root_event(), _user_event(), _state(), _ev("2026-10-25T18:00:00Z", "A", ip="iam.amazonaws.com")]
        a = map_cloud(fs, run_id="r1", provider="azure", account="t")
        b = cloud_mod._map_each(fs, run_id="r1", provider="azure", account="t")
        self.assertEqual(repr(a), repr(b))

    def test_if_the_aws_path_breaks_aws_falls_back_to_the_old_mapping(self):
        fs = [_root_event(), _user_event(), _state()]
        orig = cloud_mod._map_aws
        try:
            cloud_mod._map_aws = lambda *a, **k: 1 / 0
            got = map_cloud(fs, run_id="r1", provider="aws", account=ACCT)
        finally:
            cloud_mod._map_aws = orig
        self.assertEqual(repr(got), repr(cloud_mod._map_each(fs, run_id="r1", provider="aws", account=ACCT)))

    def test_junk_context_is_ignored(self):
        ents, _ = map_cloud([_user_event()], run_id="r1", provider="aws", account=ACCT,
                            context=[None, 1, "x", {}, {"eventTime": "garbage"}, {"eventTime": "2026-10-25T18:11:30Z",
                                                                                  "userIdentity": "bad"}])
        self.assertEqual(len(_evs(ents)), 1)


class TheFindingCarriesTheGroup(unittest.TestCase):
    def test_count_span_summary_and_old_ids(self):
        from services.fusion import correlate
        times = ["2026-10-25T21:34:53Z", "2026-10-25T21:35:05Z", "2026-10-25T21:35:36Z"]
        ents, rels = map_cloud([_root_event(t) for t in times], run_id="r1", provider="aws", account=ACCT)
        lone = [correlate._fid("cloud", e.id) for e in
                _evs(cloud_mod._map_each([_root_event(t) for t in times], run_id="r1", provider="aws", account=ACCT)[0])]
        g = correlate.assemble("c", [(ents, rels)], ["r1"])
        f = [x for x in g.findings if "Root Credentials" in x.title]
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0].occ_count, f[0].occ_latest), (3, "2026-10-25T21:35:36"))
        self.assertIn("3 events by aws-root", f[0].summary)
        self.assertEqual(set(f[0].ids()), set(lone))      # a verdict on any old row still applies


class RootStaysReadableToTheModel(unittest.TestCase):
    def test_aws_root_is_not_pseudonymised_but_the_users_are(self):
        try:
            from services.fusion import llm_sim
            from services.data_anonymizer import DataAnonymizer
        except Exception as e:                              # noqa: BLE001
            self.skipTest(f"masking deps missing here: {e}")
        from services.fusion import correlate
        ents, rels = map_cloud([_root_event(), _ev("2026-10-25T18:11:34Z", "CreateAccessKey",
                                                   target="web-deployer")],
                               run_id="r1", provider="aws", account=ACCT)
        g = correlate.assemble("c", [(ents, rels)], ["r1"])
        mask = DataAnonymizer()
        llm_sim._build_mask_mapping(g, mask)
        out = llm_sim._apply_mask("aws-root deleted users; scanner_svc made a key for web-deployer", mask)
        self.assertIn("aws-root", out)
        self.assertNotIn("scanner_svc", out.lower())
        self.assertNotIn("web-deployer", out)


class EveryRowSaysWhatHappened(unittest.TestCase):
    def test_a_lone_root_event_names_who_what_whom_and_how(self):
        f = _root_event()
        f["matched_record"].update({"userAgent": "Mozilla/5.0", "awsRegion": "us-east-1",
                                    "requestParameters": {"userName": "temp-user"}})
        f["matched_record"]["userIdentity"]["sessionContext"] = {"attributes": {"mfaAuthenticated": "true"}}
        ents, _ = map_cloud([f], run_id="r1", provider="aws", account=ACCT)
        x = _evs(ents)[0].attrs["summary_extra"]
        for part in ("aws-root:", "DeleteUser → temp-user", "from 203.0.113.10", "console", "MFA",
                     "us-east-1"):
            self.assertIn(part, x)

    def test_the_context_line_names_the_actor(self):
        det = _ev("2026-10-25T18:11:34Z", "CreateAccessKey", eid="k1")
        ctx = [_ev("2026-10-25T18:11:30Z", "CreateUser", target="t")["matched_record"]]
        ents, _ = map_cloud([det], run_id="r1", provider="aws", account=ACCT, context=ctx)
        self.assertIn("Around it, scanner_svc also did: 18:11:30 CreateUser → t",
                      _evs(ents)[0].attrs["summary_extra"])

    def test_cli_and_sdk_are_told_apart(self):
        for ua, want in (("aws-cli/2.15 Python/3.11", "AWS CLI"), ("Boto3/1.34 md/Botocore", "SDK/script")):
            f = _user_event(); f["matched_record"]["userAgent"] = ua
            ents, _ = map_cloud([f], run_id="r1", provider="aws", account=ACCT)
            self.assertIn(want, _evs(ents)[0].attrs["summary_extra"])

    def test_setup_rows_get_no_event_line(self):
        ents, _ = map_cloud([_state()], run_id="r1", provider="aws", account=ACCT)
        self.assertNotIn("summary_extra", _evs(ents)[0].attrs)


class CloudUsersAreSeenOnTheirAccount(unittest.TestCase):
    def test_identity_card_lists_the_aws_account(self):
        from services.fusion import correlate, identities
        ents, rels = map_cloud([_root_event(), _user_event()], run_id="r1", provider="aws", account=ACCT)
        g = correlate.assemble("c", [(ents, rels)], ["r1"])
        cards = {c["name"]: c for c in identities.resolve_identities(g)}
        self.assertEqual(cards["aws-root"]["seen_on"], [f"aws:{ACCT}"])
        self.assertEqual(cards["scanner_svc"]["seen_on"], [f"aws:{ACCT}"])


class WhatWasTouched(unittest.TestCase):
    def test_instance_ports_and_exposure(self):
        f = _ev("2026-10-25T20:37:56Z", "PutInstancePublicPorts")
        f["matched_record"]["requestParameters"] = {"instanceName": "web-01", "portInfos": [
            {"fromPort": 22, "toPort": 22, "cidrs": ["0.0.0.0/0"]}, {"fromPort": 443, "toPort": 443, "cidrs": ["10.0.0.0/8"]}]}
        ents, _ = map_cloud([f], run_id="r1", provider="aws", account=ACCT)
        ev = _evs(ents)[0]
        self.assertIn("[web-01; port(s) 22, 443 OPEN TO THE WHOLE INTERNET]", ev.attrs["summary_extra"])
        self.assertEqual(ev.attrs["cloud_resources"], ["web-01"])

    def test_policy_actions_and_arn(self):
        f = _ev("2026-10-25T18:11:32Z", "PutUserPolicy", target="web-deployer")
        f["matched_record"]["requestParameters"]["policyDocument"] = \
            '{"Statement": [{"Effect": "Allow", "Action": "lightsail:*", "Resource": "*"}, {"Effect": "Deny", "Action": "iam:*"}]}'
        g = _ev("2026-10-25T18:11:33Z", "DetachUserPolicy", target="x", rule="R2")
        g["matched_record"]["requestParameters"]["policyArn"] = "arn:aws:iam::aws:policy/AdministratorAccess"
        ents, _ = map_cloud([f, g], run_id="r1", provider="aws", account=ACCT)
        text = " ".join(e.attrs.get("summary_extra", "") for e in _evs(ents))
        self.assertIn("allows lightsail:*", text)
        self.assertNotIn("iam:*", text)
        self.assertIn("policy AdministratorAccess", text)

    def test_odd_request_shapes_never_break_a_row(self):
        for rp in ({"portInfos": "x"}, {"portInfos": [None, 5, {"cidrs": None}]}, {"ipPermissions": []},
                   {"ipPermissions": {"items": [{"ipRanges": "bad"}]}}, {"policyDocument": "{not json"},
                   {"instanceNames": [None, 3, "a"]}, None, "text"):
            f = _ev("2026-10-25T20:00:00Z", "Z")
            f["matched_record"]["requestParameters"] = rp
            ents, _ = map_cloud([f], run_id="r1", provider="aws", account=ACCT)
            self.assertEqual(len(_evs(ents)), 1, rp)


class WhatTheTargetDidNext(unittest.TestCase):
    def test_a_created_user_s_next_day_is_in_the_row(self):
        det = _ev("2026-10-25T18:11:34Z", "CreateAccessKey", target="web-deployer", eid="k1")
        nxt = _ev("2026-10-25T20:31:48Z", "CreateInstances", user="web-deployer", eid="n1")["matched_record"]
        nxt["requestParameters"] = {"instanceNames": ["web-01"]}
        far = _ev("2026-10-27T09:00:00Z", "DeleteInstance", user="web-deployer", eid="n2")["matched_record"]
        ents, _ = map_cloud([det], run_id="r1", provider="aws", account=ACCT, context=[nxt, far])
        ev = _evs(ents)[0]
        self.assertEqual(ev.attrs["after"], {"web-deployer": ["20:31:48 CreateInstances [web-01]"]})
        self.assertIn("Afterwards, web-deployer did: 20:31:48 CreateInstances [web-01]", ev.attrs["summary_extra"])
        self.assertIn("web-01", ev.attrs["cloud_resources"])


class ResourceNamesAreMaskedLikeHosts(unittest.TestCase):
    def test_instance_names_never_reach_the_model(self):
        try:
            from services.fusion import llm_sim
            from services.data_anonymizer import DataAnonymizer
        except Exception as e:                              # noqa: BLE001
            self.skipTest(f"masking deps missing here: {e}")
        from services.fusion import correlate
        f = _ev("2026-10-25T20:37:56Z", "PutInstancePublicPorts")
        f["matched_record"]["requestParameters"] = {"instanceName": "acme-web-prod"}
        ents, rels = map_cloud([f], run_id="r1", provider="aws", account=ACCT)
        g = correlate.assemble("c", [(ents, rels)], ["r1"])
        mask = DataAnonymizer()
        llm_sim._build_mask_mapping(g, mask)
        out = llm_sim._apply_mask(next(x.summary for x in g.findings), mask)
        self.assertNotIn("acme-web-prod", out)
        self.assertIn("PutInstancePublicPorts", out)


class EveryAwsRowHasAPhase(unittest.TestCase):
    def test_cloud_accounts_are_initial_access_domain_accounts_unchanged(self):
        from types import SimpleNamespace as NS
        from services.fusion import render
        self.assertEqual(render._phase(NS(title="AWS: AWS Root Credentials", mitre=["T1078.004"])), "Initial Access")
        self.assertEqual(render._phase(NS(title="Logon with a valid account", mitre=["T1078"])), "Lateral Movement")

    def test_setup_rows_get_a_technique_even_from_older_scans(self):
        from services.fusion import correlate, render
        exposure = _state_keyed()
        exposure["rule_title"] = "State: Security group web lets the internet reach 22"
        exposure["matched_record"] = '{"_source": "exposure", "ResourceName": "web", "ResourceType": "AWS::EC2::SecurityGroup"}'
        ents, rels = map_cloud([_state_keyed(), exposure], run_id="r1", provider="aws", account=ACCT)
        g = correlate.assemble("c", [(ents, rels)], ["r1"])
        phases = {f.title.split("State: ")[-1][:20]: render._phase(f) for f in g.findings}
        self.assertNotIn("Unclassified", phases.values(), phases)
        self.assertEqual(sorted(phases.values()), ["Initial Access", "Initial Access"])



class EachAwsAccountIsItsOwnAsset(unittest.TestCase):
    """A multi-account scan tags records with their account (services/aws/members.py)."""

    def test_it(self):
        other = "999988887777"
        mine = _user_event()
        theirs = _user_event()
        theirs["matched_record"] = dict(theirs["matched_record"], recipientAccountId=other, AccountId=other)
        ents, _ = map_cloud([mine, theirs], run_id="r1", provider="aws", account=ACCT)
        assets = sorted(e.id for e in _by_type(ents, "asset"))
        self.assertEqual(assets, [f"asset:cloud_account:aws:{ACCT}", f"asset:cloud_account:aws:{other}"])
        events = [e for e in ents if e.type == "event"]
        self.assertEqual(len(events), 2, "the same rule in two accounts is two rows")
        self.assertEqual(sorted(e.attrs["_assets"][0] for e in events), assets)

    def test_a_single_account_scan_keeps_its_ids(self):
        rec = _user_event()
        rec["matched_record"] = dict(rec["matched_record"], recipientAccountId=ACCT)
        a, _ = map_cloud([_user_event()], run_id="r1", provider="aws", account=ACCT)
        b, _ = map_cloud([rec], run_id="r1", provider="aws", account=ACCT)
        self.assertEqual(sorted(e.id for e in a), sorted(e.id for e in b))


class APollingRoleIsOneRowAndTiesDoNotCrash(unittest.TestCase):
    """2026-10-26 live: an integration role read Lightsail access details 334 times from
    a new address each time -> 331 rows and 347 IP nodes; and two context events in the
    same second compared dict < dict, which skipped whole rows (three medium findings
    vanished from the case)."""

    def _role_hit(self, i):
        return {"rule_title": "AWS Lightsail Instance Credentials Retrieved By A Role", "severity": "low",
                "_timestamp": f"2026-10-{1 + i // 24:02d} {i % 24:02d}:00:00",
                "matched_record": {"eventTime": f"2026-10-{1 + i // 24:02d}T{i % 24:02d}:00:00Z", "eventName": "GetInstanceAccessDetails",
                                   "sourceIPAddress": f"198.51.100.{i % 250}",
                                   "userIdentity": {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCT}:assumed-role/reader/s{i}",
                                                    "sessionContext": {"sessionIssuer": {"type": "Role", "userName": "reader",
                                                                                         "arn": f"arn:aws:iam::{ACCT}:role/reader"}}}}}

    def test_a_role_is_one_row_with_a_few_addresses(self):
        ents, _ = map_cloud([self._role_hit(i) for i in range(40)], run_id="r1", provider="aws", account=ACCT)
        events = [e for e in ents if e.type == "event"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].attrs["hits"], 40)
        self.assertEqual(events[0].attrs["ips_total"], 40)
        self.assertEqual(len({e.id for e in ents if e.type == "ioc"}), cloud_mod.MAX_GROUP_IPS)
        self.assertIn("2026-10-01", events[0].attrs["summary_extra"], "a multi-day row shows dates")

    def test_a_person_keeps_one_row_per_sitting(self):
        a, b = _root_event("2026-10-25T10:00:00Z"), _root_event("2026-10-25T15:00:00Z")
        ents, _ = map_cloud([a, b], run_id="r1", provider="aws", account=ACCT)
        self.assertEqual(len([e for e in ents if e.type == "event"]), 2)

    def test_same_second_context_does_not_skip_the_row(self):
        hit = _root_event("2026-10-25T21:35:00Z")
        ctx = [dict(hit["matched_record"], eventName=n, eventID=n) for n in ("ListUsers", "ListRoles", "ListPolicies")]
        ents, _ = map_cloud([hit], run_id="r1", provider="aws", account=ACCT, context=ctx)
        ev = [e for e in ents if e.type == "event"]
        self.assertEqual(len(ev), 1)
        self.assertIn("Around it", ev[0].attrs.get("summary_extra", ""))

if __name__ == "__main__":
    unittest.main()

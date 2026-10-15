"""Behaviour rules find what only many rows of a pure log show -- and stay quiet
on the same kind of log when nothing happened.

Every stream below goes through the real reader (external_logs.read +
normalize) and then behaviour.run, the way ingest() does it. Attack and clean
streams of the SAME shape, so a rule that fires on ordinary traffic fails here.
"""
import json
import os
import random
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import behaviour as B, external_logs as X  # noqa: E402

ATK = "185.220.101.4"
BASE = 1790849100                      # 2026-10-01T10:05:00Z


def iso(t):
    import datetime as dt
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def found(text):
    fmt, rows, left = X.read(text)
    norm = X.normalize(rows, X.detect_columns(rows)) if rows else []
    if not (norm and X.recognized(norm)):
        norm = X.indicator_rows(text.splitlines())
    return [(f["n"]["rule"], f["n"]["severity"]) for f in B.run(norm)]


def jl(objs):
    return "\n".join(json.dumps(o) for o in objs)


def okta(t, user, ip, result, event="user.session.start", msg="User login to Okta"):
    return {"published": iso(t), "eventType": event, "actor": {"alternateId": user},
            "client": {"ipAddress": ip}, "displayMessage": msg, "outcome": {"result": result}}


class SignIns(unittest.TestCase):

    def test_okta_brute_force_then_success(self):
        evs = [okta(BASE + i * 15, "jdoe@corp.com", ATK, "FAILURE") for i in range(15)]
        evs.append(okta(BASE + 240, "jdoe@corp.com", ATK, "SUCCESS"))
        self.assertIn(("Brute force then success (jdoe@corp.com from 185.220.101.4)", "high"), found(jl(evs)))

    def test_entra_error_codes(self):
        evs = [{"createdDateTime": iso(BASE + i * 20), "userPrincipalName": "jdoe@corp.com", "ipAddress": ATK,
                "appDisplayName": "Office 365", "status": {"errorCode": 50126}} for i in range(12)]
        evs.append({"createdDateTime": iso(BASE + 300), "userPrincipalName": "jdoe@corp.com", "ipAddress": ATK,
                    "appDisplayName": "Office 365", "status": {"errorCode": 0}})
        got = found(json.dumps({"value": evs}))
        self.assertEqual([("Brute force then success (jdoe@corp.com from 185.220.101.4)", "high")], got)

    def test_auth_log_text(self):
        lines = [f"Oct  1 10:{5 + i // 6:02d}:{i * 10 % 60:02d} web01 sshd[2211]: Failed password for root "
                 f"from {ATK} port {51000 + i} ssh2" for i in range(14)]
        lines.append(f"Oct  1 10:09:00 web01 sshd[2215]: Accepted password for root from {ATK} port 51188 ssh2")
        self.assertIn(("Brute force then success (root from 185.220.101.4)", "high"), found("\n".join(lines)))

    def test_password_spray(self):
        evs = [okta(BASE + i * 30, f"user{i}@corp.com", ATK, "FAILURE") for i in range(15)]
        self.assertIn(("Password spray from 185.220.101.4", "high"), found(jl(evs)))

    def test_mfa_fatigue(self):
        evs = [okta(BASE + i * 60, "jdoe@corp.com", ATK, "FAILURE", "system.push.send_factor_verify_push",
                    "Push verification denied") for i in range(7)]
        evs.append(okta(BASE + 480, "jdoe@corp.com", ATK, "SUCCESS", "user.authentication.auth_via_mfa",
                        "Authentication of user via MFA"))
        self.assertIn(("MFA fatigue (jdoe@corp.com) then approved", "high"), found(jl(evs)))

    def test_ordinary_sign_ins_stay_quiet(self):
        rnd = random.Random(7)
        evs = []
        for i in range(300):                       # a normal morning: 60 people, a few typos
            u = f"user{i % 60}@corp.com"
            ip = f"198.51.100.{i % 60}"
            if rnd.random() < 0.08:
                evs.append(okta(BASE + i * 37, u, ip, "FAILURE"))
            evs.append(okta(BASE + i * 37 + 5, u, ip, "SUCCESS"))
        self.assertEqual([], found(jl(evs)))


def flow(t, src, dst, port, action="allow"):
    return {"timestamp": iso(t), "src_ip": src, "dst_ip": dst, "dst_port": port, "action": action}


class Network(unittest.TestCase):

    def test_port_scan(self):
        evs = [flow(BASE + i, ATK, "10.0.0.5", 1000 + i, "deny") for i in range(40)]
        self.assertIn(("Port scan of 10.0.0.5 from 185.220.101.4", "medium"), found(jl(evs)))

    def test_internal_host_sweep(self):
        evs = [flow(BASE + i * 3, "10.0.0.66", f"10.0.1.{i}", 445) for i in range(30)]
        self.assertIn(("Host sweep on port 445 from 10.0.0.66", "medium"), found(jl(evs)))

    def test_browsing_is_no_sweep(self):
        evs = [flow(BASE + i * 4, "10.0.0.66", f"151.101.{i}.140", 443) for i in range(60)]
        self.assertEqual([], found(jl(evs)))

    def test_beaconing(self):
        rnd = random.Random(3)
        evs = [flow(BASE + i * 60 + rnd.uniform(-2, 2), "10.0.0.5", ATK, 443) for i in range(60)]
        self.assertIn(("Beaconing from 10.0.0.5 to 185.220.101.4", "medium"), found(jl(evs)))

    def test_irregular_traffic_and_internal_polling_stay_quiet(self):
        rnd = random.Random(5)
        t, evs = BASE, []
        for _ in range(80):
            t += rnd.expovariate(1 / 90)
            evs.append(flow(t, "10.0.0.5", ATK, 443))
        evs += [flow(BASE + i * 60, "10.0.0.5", "10.0.0.2", 123) for i in range(80)]      # NTP to a local server
        self.assertEqual([], found(jl(evs)))

    def test_dns_tunnel(self):
        rnd = random.Random(9)
        evs = [{"ts": BASE + i * 4, "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.2", "query":
                "".join(rnd.choice("abcdef0123456789") for _ in range(48)) + ".t.evil-c2.net", "qtype_name": "TXT"}
               for i in range(150)]
        self.assertIn(("Possible DNS tunnelling via evil-c2.net", "medium"), found(jl(evs)))

    def test_ordinary_dns_stays_quiet(self):
        names = ["www.google.com", "outlook.office365.com", "login.microsoftonline.com", "github.com",
                 "api.slack.com", "cdn.jsdelivr.net", "update.googleapis.com", "time.windows.com"]
        evs = [{"ts": BASE + i * 4, "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.2",
                "query": names[i % len(names)], "qtype_name": "A"} for i in range(400)]
        evs += [{"ts": BASE + i * 4, "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.2",
                 "query": f"host{i}.example-shop{i}.com", "qtype_name": "A"} for i in range(150)]
        self.assertEqual([], found(jl(evs)))


class TheBoxDecides(unittest.TestCase):
    def test_a_threshold_or_switch_from_the_rules_file(self):
        evs = [flow(BASE + i, ATK, "10.0.0.5", 1000 + i, "deny") for i in range(40)]
        fmt, rows, _ = X.read(jl(evs))
        norm = X.normalize(rows, X.detect_columns(rows))
        self.assertTrue(B.run(norm))
        self.assertFalse(B.run(norm, {"port-scan": {"ports": 100}}))
        self.assertFalse(B.run(norm, {"port-scan": {"enabled": False}}))


if __name__ == "__main__":
    unittest.main()

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
        self.assertIn(("Brute force then success", "high"), found(jl(evs)))

    def test_entra_error_codes(self):
        evs = [{"createdDateTime": iso(BASE + i * 20), "userPrincipalName": "jdoe@corp.com", "ipAddress": ATK,
                "appDisplayName": "Office 365", "status": {"errorCode": 50126}} for i in range(12)]
        evs.append({"createdDateTime": iso(BASE + 300), "userPrincipalName": "jdoe@corp.com", "ipAddress": ATK,
                    "appDisplayName": "Office 365", "status": {"errorCode": 0}})
        got = found(json.dumps({"value": evs}))
        self.assertEqual([("Brute force then success", "high")], got)

    def test_auth_log_text(self):
        lines = [f"Oct  1 10:{5 + i // 6:02d}:{i * 10 % 60:02d} web01 sshd[2211]: Failed password for root "
                 f"from {ATK} port {51000 + i} ssh2" for i in range(14)]
        lines.append(f"Oct  1 10:09:00 web01 sshd[2215]: Accepted password for root from {ATK} port 51188 ssh2")
        self.assertIn(("Brute force then success", "high"), found("\n".join(lines)))

    def test_password_spray(self):
        evs = [okta(BASE + i * 30, f"user{i}@corp.com", ATK, "FAILURE") for i in range(15)]
        self.assertIn(("Password spray", "high"), found(jl(evs)))

    def test_distributed_spray(self):
        evs = [okta(BASE + i * 50, f"user{i}@corp.com", f"203.0.113.{i}", "FAILURE") for i in range(25)]
        self.assertIn(("Distributed password spray", "high"), found(jl(evs)))

    def test_one_burst_is_named_once(self):
        """A source spraying many accounts is a spray -- not also a brute force per
        account and a distributed spray."""
        evs = [okta(BASE + i * 5, f"user{i % 12}@corp.com", ATK, "FAILURE") for i in range(150)]
        got = found(jl(evs))
        self.assertEqual([("Password spray", "high")], got)

    def test_mfa_fatigue(self):
        evs = [okta(BASE + i * 60, "jdoe@corp.com", ATK, "FAILURE", "system.push.send_factor_verify_push",
                    "Push verification denied") for i in range(7)]
        evs.append(okta(BASE + 480, "jdoe@corp.com", ATK, "SUCCESS", "user.authentication.auth_via_mfa",
                        "Authentication of user via MFA"))
        self.assertIn(("MFA fatigue then approved", "high"), found(jl(evs)))

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
        self.assertIn(("Port scan", "medium"), found(jl(evs)))

    def test_internal_host_sweep(self):
        evs = [flow(BASE + i * 3, "10.0.0.66", f"10.0.1.{i}", 445) for i in range(30)]
        self.assertIn(("Host sweep", "medium"), found(jl(evs)))

    def test_browsing_is_no_sweep(self):
        evs = [flow(BASE + i * 4, "10.0.0.66", f"151.101.{i}.140", 443) for i in range(60)]
        self.assertEqual([], found(jl(evs)))

    def test_flood_and_c2_retry(self):
        evs = [flow(BASE + i * 0.02, "10.0.0.9", "123.59.209.185", 80) for i in range(1500)]
        evs += [{"ts": BASE + i * 5, "id.orig_h": "10.0.0.9", "id.resp_h": "185.244.25.235", "id.orig_p": 40000 + i,
                 "id.resp_p": 6667, "proto": "tcp", "conn_state": "S0"} for i in range(300)]
        got = found(jl(evs))
        self.assertIn(("Connection flood", "high"), got)
        self.assertIn(("Repeated failed connections to an outside host", "medium"), got)
        self.assertEqual(1, sum(1 for t, _ in got if t == "Repeated failed connections to an outside host"),
                         "the flood target is not also a retry")

    def test_busy_but_answered_traffic_stays_quiet(self):
        evs = [{"ts": BASE + i * 5, "id.orig_h": "10.0.0.9", "id.resp_h": "151.101.1.140", "id.orig_p": 40000 + i,
                "id.resp_p": 443, "proto": "tcp", "conn_state": "SF"} for i in range(400)]
        self.assertEqual([], found(jl(evs)))

    def test_rdp_answered_from_the_internet(self):
        evs = [{"ts": BASE, "id.orig_h": ATK, "id.resp_h": "10.0.1.14", "id.orig_p": 57960, "id.resp_p": 3389,
                "proto": "tcp", "conn_state": "RSTR", "duration": 5099.2}]
        self.assertEqual([("Remote admin service reached from the internet", "medium")], found(jl(evs)))

    def test_refused_or_internal_rdp_stays_quiet(self):
        evs = [flow(BASE + i * 30, f"203.0.113.{i}", "10.0.1.14", 3389, "deny") for i in range(10)]
        evs += [flow(BASE + i * 30, "10.0.0.66", "10.0.1.14", 3389) for i in range(10)]        # admin on the LAN
        evs += [flow(BASE + i * 30, ATK, "10.0.1.20", 22) for i in range(3)]                   # a jump host
        self.assertEqual([], found(jl(evs)))
        ipt = "\n".join(f"Jan  8 03:3{i}:09 fw kernel: iptables DROP_INPUT: IN=eth0 OUT= SRC={ATK} "
                        f"DST=172.16.54.114 LEN=52 PROTO=TCP SPT={17805 + i} DPT=445 SYN" for i in range(5))
        self.assertEqual([], found(ipt), "a netfilter DROP prefix is a refused connection")
        vpc = "\n".join(f"2 123456789010 eni-1235b8ca {ATK} 10.0.1.14 {40000 + i} 3389 6 1 40 "
                         f"{BASE + i} {BASE + i + 50} REJECT OK" for i in range(5))
        self.assertEqual([], found(vpc), "an AWS VPC flow REJECT is a refused connection")
        self.assertEqual([("Remote admin service reached from the internet", "medium")],
                         found(vpc.replace("REJECT", "ACCEPT")))

    def test_beaconing(self):
        rnd = random.Random(3)
        evs = [flow(BASE + i * 60 + rnd.uniform(-2, 2), "10.0.0.5", ATK, 443) for i in range(60)]
        self.assertIn(("Beaconing", "medium"), found(jl(evs)))

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
        self.assertIn(("Possible DNS tunnelling", "medium"), found(jl(evs)))

    def test_reverse_dns_sweep_is_recon_not_a_tunnel(self):
        evs = [{"ts": BASE + i, "id.orig_h": "10.0.0.66", "id.resp_h": "10.0.0.2",
                "query": f"{i % 250}.{i // 250}.0.10.in-addr.arpa", "qtype_name": "PTR"} for i in range(300)]
        self.assertEqual([("Reverse DNS sweep", "medium")], found(jl(evs)))

    def test_ordinary_dns_stays_quiet(self):
        names = ["www.google.com", "outlook.office365.com", "login.microsoftonline.com", "github.com",
                 "api.slack.com", "cdn.jsdelivr.net", "update.googleapis.com", "time.windows.com"]
        evs = [{"ts": BASE + i * 4, "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.2",
                "query": names[i % len(names)], "qtype_name": "A"} for i in range(400)]
        evs += [{"ts": BASE + i * 4, "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.2",
                 "query": f"host{i}.example-shop{i}.com", "qtype_name": "A"} for i in range(150)]
        self.assertEqual([], found(jl(evs)))


def access(t, ip, method, path, status):
    import datetime as dt
    ts = dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} 512 "-" "Mozilla/5.0 (X11; Linux) Firefox/120.0"'


class Web(unittest.TestCase):

    def test_web_scan(self):
        lines = [access(BASE + i, ATK, "GET", f"/{w}", 404) for i, w in
                 enumerate(f"admin{i}.php" for i in range(80))]
        self.assertIn(("Web scanning", "medium"), found("\n".join(lines)))

    def test_login_brute_force(self):
        lines = [access(BASE + i * 5, ATK, "POST", "/wp-login.php", 200) for i in range(40)]
        self.assertIn(("Web login brute force", "medium"), found("\n".join(lines)))

    def test_visitors_stay_quiet(self):
        rnd = random.Random(11)
        pages = ["/", "/blog/", "/about", "/feed", "/css/site.css", "/js/app.js", "/missing.png"]
        lines = []
        for i in range(600):
            ip = f"198.51.100.{rnd.randrange(1, 200)}"
            p = rnd.choice(pages)
            lines.append(access(BASE + i * 6, ip, "GET", p, 404 if p == "/missing.png" else 200))
        lines += [access(BASE + i * 60, "198.51.100.7", "POST", "/wp-login.php", 302) for i in range(3)]
        self.assertEqual([], found("\n".join(lines)))


class WindowsEventsByID(unittest.TestCase):
    """Benign DC + workstation (Nextron, 1.24 M events): an Event 69 "failed", a
    Sysmon registry write by mmc.exe, LLMNR from 224.0.0.252 and the DNS server
    talking to itself were brute forces and port scans."""

    def ev(self, t, eid, **kw):
        return {"SystemTime": iso(BASE + t), "EventID": str(eid), "Channel": "Security",
                "Computer": "DC01", **kw}

    def test_failed_logons_by_id_are_a_brute_force(self):
        evs = [self.ev(i * 10, 4625, TargetUserName="administrator", IpAddress=ATK, LogonType="3")
               for i in range(15)]
        evs.append(self.ev(200, 4624, TargetUserName="administrator", IpAddress=ATK, LogonType="3"))
        self.assertIn(("Brute force then success", "high"), found(jl(evs)))

    def test_other_windows_events_are_not_sign_ins(self):
        evs = [{"SystemTime": iso(BASE + i * 10), "EventID": "69", "Channel": "Microsoft-Windows-AAD/Operational",
                "UserSid": "S-1-5-21-1-2-3-1001", "Message": "Logon failed: error 0xCAA2000C", "User": "jdoe"}
               for i in range(20)]
        evs += [{"SystemTime": iso(BASE + i * 10), "EventID": "13", "Channel": "Microsoft-Windows-Sysmon/Operational",
                 "Image": "C:\\Windows\\system32\\mmc.exe", "TargetObject": "HKLM\\...\\Logon\\FailedCount",
                 "User": "CORP\\administrator"} for i in range(20)]
        self.assertEqual([], found(jl(evs)))

    def test_multicast_and_self_are_no_port_scan(self):
        evs = [{"SystemTime": iso(BASE + i), "EventID": "3", "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Image": "C:\\Windows\\System32\\svchost.exe", "SourceIp": "224.0.0.252",
                "DestinationIp": "10.0.2.1", "DestinationPort": str(50000 + i)} for i in range(60)]
        evs += [{"SystemTime": iso(BASE + i), "EventID": "3", "Channel": "Microsoft-Windows-Sysmon/Operational",
                 "Image": "C:\\Windows\\System32\\dns.exe", "SourceIp": "10.0.2.133",
                 "DestinationIp": "10.0.2.133", "DestinationPort": str(56000 + i)} for i in range(60)]
        self.assertEqual([], found(jl(evs)))


class ActiveDirectoryPermissions(unittest.TestCase):
    """5136 logs the old and new descriptor of a change; the rule reads what was ADDED.
    No benign corpus holds 5136 (DS auditing off), so a legitimate delegation to a
    non-admin group fires too -- a permission grant is worth a look in an incident."""

    def change(self, dn, old, new, cls="user", who="attacker"):
        base = {"SystemTime": iso(BASE), "EventID": "5136", "Channel": "Security", "Computer": "DC01",
                "OpCorrelationID": "{X}", "SubjectUserName": who, "ObjectDN": dn, "ObjectClass": cls,
                "AttributeLDAPDisplayName": "nTSecurityDescriptor"}
        return [{**base, "OperationType": "%%14675", "AttributeValue": old},
                {**base, "OperationType": "%%14674", "AttributeValue": new}]

    def test_full_control_to_a_user_or_a_hidden_ou_or_adminsdholder(self):
        sd = "O:DAG:DAD:AI(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)"
        got = found(jl(self.change("CN=victim,CN=Users,DC=corp,DC=local", sd,
                                   sd + "(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1-2-3-4219)")))
        self.assertEqual([("AD object permissions granted to an account", "medium")], got)
        got = found(jl(self.change("OU=Stage,DC=corp,DC=local", sd, sd + "(D;;LCDTSD;;;WD)", "organizationalUnit")))
        self.assertEqual([("AD object hidden", "medium")], got)
        got = found(jl(self.change("CN=AdminSDHolder,CN=System,DC=corp,DC=local", sd,
                                   sd + "(A;;RPWP;;;S-1-5-21-1-2-3-1961)", "container")))
        self.assertEqual([("AdminSDHolder permissions changed", "high")], got)

    def test_admins_inherited_and_read_rights_stay_quiet(self):
        sd = "O:DAG:DAD:AI(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)"
        for added in ("(A;;GA;;;S-1-5-21-1-2-3-512)", "(A;CIID;GA;;;S-1-5-21-1-2-3-4219)", "(A;;RPLCRC;;;AU)"):
            self.assertEqual([], found(jl(self.change("CN=x,DC=corp,DC=local", sd, sd + added))), added)


class Kerberos(unittest.TestCase):
    """No benign corpus here holds 4768/4769 (Kerberos auditing off on both hosts)."""

    def tgs(self, t, user, svc, enc="0x12"):
        return {"SystemTime": iso(BASE + t), "EventID": "4769", "Channel": "Security", "Computer": "DC01",
                "TargetUserName": f"{user}@CORP.LOCAL", "ServiceName": svc, "TicketEncryptionType": enc,
                "IpAddress": "::ffff:10.0.0.5", "Status": "0x0"}

    def test_kerberoasting_and_a_computer_sweep(self):
        evs = [self.tgs(i * 5, "jdoe", f"svc_sql{i}", "0x17") for i in range(12)]
        self.assertIn(("Possible Kerberoasting (RC4 service tickets)", "high"), found(jl(evs)))
        evs = [self.tgs(i * 5, "jdoe", f"WS{i:03d}$") for i in range(30)]
        self.assertIn(("Kerberos tickets for many computers", "medium"), found(jl(evs)))

    def test_ordinary_ticket_use_stays_quiet(self):
        evs = [self.tgs(i * 30, f"user{i % 20}", ["cifs/fs01", "http/intranet", "ldap/dc01"][i % 3])
               for i in range(200)]
        evs += [self.tgs(i * 30, "jdoe", "krbtgt") for i in range(50)]
        self.assertEqual([], found(jl(evs)))

    def test_user_enumeration(self):
        evs = [{"SystemTime": iso(BASE + i * 3), "EventID": "4768", "Channel": "Security", "Computer": "DC01",
                "TargetUserName": f"guess{i}", "Status": "0x6", "IpAddress": f"::ffff:{ATK}"} for i in range(15)]
        self.assertEqual([("Kerberos user enumeration", "medium")], found(jl(evs)))
        self.assertEqual([], found(jl(evs[:5])), "a few typos are not enumeration")


class SuspiciousBurst(unittest.TestCase):
    """Low signals add up per host, like Splunk's risk-based alerting."""

    def low(self, t, rule, host="web01"):
        return {"n": {"ts": iso(BASE + t), "host": host, "severity": "low", "rule": rule,
                      "detected_by": [f"sigma: {rule}"]}}

    def test_three_different_signals_on_one_host_are_a_detection(self):
        rows = [self.low(0, "Whoami User Discovery"), self.low(300, "Edit Cron Table Parameter"),
                self.low(900, "Hidden Files And Directories Creation"), self.low(60, "Whoami User Discovery", "db01")]
        got = B.run(rows)
        self.assertEqual([("Burst of suspicious activity", "medium")], [(f["n"]["rule"], f["n"]["severity"]) for f in got])
        self.assertEqual("web01", got[0]["n"]["host"])

    def test_the_same_signal_again_or_two_signals_stay_context(self):
        self.assertEqual([], B.run([self.low(i * 60, "Whoami User Discovery") for i in range(10)]))
        self.assertEqual([], B.run([self.low(0, "Whoami User Discovery"), self.low(60, "Sudo Or Su Execution")]))
        self.assertEqual([], B.run([self.low(0, "A"), self.low(60, "B"), self.low(7300, "C")]),
                         "spread over more than the hour")


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

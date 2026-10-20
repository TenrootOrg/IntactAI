"""Application and web-server error logs reach SigmaHQ's keyword rules (11 high).

JVM (JNDI / Log4Shell, OGNL, XXE, RCE), Spring SpEL, Velocity SSTI, Node.js RCE,
SQL-injection errors, Apache segfaults, nginx core dumps: keyword rules for exploit
fingerprints in an application's own log. No row ever had their log sources
(2026-10-20 severity audit). On every real dataset the 5,282 rows that now carry
these profiles raised no hit -- only the fingerprint text matches.
"""
import json
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import external_logs as X, sigma_eval as S  # noqa: E402


def kw(title, words, product=None, service=None):
    ls = {"category": "application", "product": product} if product else {"service": service}
    return S.compile_rule({"title": title, "id": title, "level": "high", "logsource": ls,
                           "detection": {"keywords": words, "condition": "keywords"}})


RULES = [  # SigmaHQ bodies (shortened lists)
    kw("Potential JNDI Injection Exploitation In JVM Based Application",
       ["com.sun.jndi.ldap.", "org.apache.logging.log4j.core.net.JndiManager"], product="jvm"),
    kw("Potential RCE Exploitation Attempt In NodeJS", ["node:child_process"], product="nodejs"),
    kw("Suspicious SQL Error Messages", ["You have an error in your SQL syntax"], product="sql"),
    kw("Apache Segmentation Fault", ["exit signal Segmentation Fault"], service="apache"),
    kw("Nginx Core Dump", ["exited on signal 6 (core dumped)"], service="nginx"),
]


def titles(text):
    _fmt, rows, left = X.read(text)
    rows = rows or [{"text": line} for line in left]
    return [h["title"] for r in rows for h in S.evaluate(X.sigma_event(r), RULES)]


class FreeTextErrorLogs(unittest.TestCase):
    def test_log4shell_in_a_java_log(self):
        line = ("2021-12-10 10:05:00,123 ERROR [http-nio-8080-exec-3] org.apache.logging.log4j.core.net.JndiManager "
                "- Error looking up JNDI resource [ldap://198.51.100.7:1389/Exploit]")
        self.assertEqual(["Potential JNDI Injection Exploitation In JVM Based Application"], titles(line))

    def test_apache_and_nginx_crashes(self):
        self.assertEqual(["Apache Segmentation Fault"], titles(
            "[Mon Oct 20 10:05:00.123456 2026] [core:notice] [pid 1234] AH00052: child pid 5678 "
            "exit signal Segmentation Fault (11)"))
        self.assertEqual(["Nginx Core Dump"], titles(
            "2026/10/20 10:05:00 [alert] 1234#0: worker process 5678 exited on signal 6 (core dumped)"))

    def test_ordinary_lines_stay_quiet(self):
        for line in ("2026/10/20 10:05:00 [notice] 1234#0: signal process started",
                     "[Mon Oct 20 10:05:00 2026] [mpm_event:notice] [pid 1] AH00489: Apache/2.4.58 configured",
                     "2026-10-20 10:05:00,123 INFO [main] o.s.b.StartupInfoLogger - Started App in 3.2 seconds",
                     "Oct 20 10:05:00 h sshd[1]: Accepted publickey for deploy from 10.0.0.5 port 22 ssh2"):
            self.assertEqual([], titles(line), line)


class StructuredApplicationLogs(unittest.TestCase):
    def test_a_json_log_with_a_stack_trace(self):
        rec = {"@timestamp": "2026-10-20T10:05:00Z", "level": "ERROR", "logger_name": "com.shop.Api",
               "message": "query failed", "stack_trace": "java.sql.SQLSyntaxErrorException: You have an error "
                                                          "in your SQL syntax; check the manual near ''1'' at line 1"}
        self.assertEqual(["Suspicious SQL Error Messages"], titles(json.dumps(rec)))

    def test_a_node_service_log(self):
        rec = {"time": "2026-10-20T10:05:00Z", "logger": "api", "msg": "eval of payload",
               "exception": "Error: require('node:child_process').execSync('id')"}
        self.assertEqual(["Potential RCE Exploitation Attempt In NodeJS"], titles(json.dumps(rec)))


if __name__ == "__main__":
    unittest.main()

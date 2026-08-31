# Campaign chain: correlation, timeline order, identities

One actor's campaign in a known order (initial access → escalation → credential theft → lateral → DC → exfil) across 3 hosts with one account.

| Test | Question | Result | |
|---|---|---|:--:|
| **E17** | Does fusion link it into ONE campaign? | 1 cross-host finding(s) spanning 3 hosts | ✅ |
| **B7** | Timeline chronological + patient zero? | chronological=True, patient-zero=WKS-CHAIN01 | ✅ |
| **C10** | One account across 3 hosts = ONE identity? | 1 entity, spans 3 hosts | ✅ |
| **C11** | DOMAIN\u + u@dom + bare SAM → cross-host finding? | 1 finding(s) from 3 account forms | ✅ |


# Summary coverage — RE-SCORED with synonym-aware matching

The first pass used one literal phrase per technique and under-counted badly (shadowcopy scored 1/10 while 'shadow'/'vssadmin' appear in 10/10; byovd scored 2/10 while 'byovd' appears in 8/10). Re-scored the SAME 10 saved summaries offline with per-technique synonym sets.

**Mean coverage: 26.8/34 techniques per summary (79%)** — first pass claimed 25.5 (75%).

- **Always (17/34)**: adcs-abuse, clear-usnjrnl, dcsync, exfil-rclone, golden-ticket, inject, kerberoast, mft-erasing, namedpipe-c2, ntds-dump, psexec-lateral, ransomware, rdp-lateral, shadowcopy, staging-archive, webshell, xhost-acct
- **Never (0/34)**: none
- **Intermittent (17/34)**: svc-acct-abuse (1/10), fw-tamper (2/10), dll-sideload (3/10), amsi-bypass (3/10), uac-bypass (3/10), keylogger (3/10), certutil-dl (3/10), reg-sam (4/10), defender-off (8/10), wmi-persist (8/10), asrep-roast (8/10), token-theft (8/10), byovd (8/10), cred-lsass (9/10), binrename (9/10), malfind-svc (9/10), c2-beacon (9/10)

| Technique | Summaries mentioning it |
|---|:--:|
| kerberoast | 10/10 |
| inject | 10/10 |
| xhost-acct | 10/10 |
| namedpipe-c2 | 10/10 |
| dcsync | 10/10 |
| rdp-lateral | 10/10 |
| golden-ticket | 10/10 |
| ransomware | 10/10 |
| exfil-rclone | 10/10 |
| mft-erasing | 10/10 |
| psexec-lateral | 10/10 |
| webshell | 10/10 |
| ntds-dump | 10/10 |
| adcs-abuse | 10/10 |
| staging-archive | 10/10 |
| clear-usnjrnl | 10/10 |
| shadowcopy | 10/10 |
| cred-lsass | 9/10 |
| binrename | 9/10 |
| malfind-svc | 9/10 |
| c2-beacon | 9/10 |
| defender-off | 8/10 |
| wmi-persist | 8/10 |
| asrep-roast | 8/10 |
| token-theft | 8/10 |
| byovd | 8/10 |
| reg-sam | 4/10 |
| dll-sideload | 3/10 |
| amsi-bypass | 3/10 |
| uac-bypass | 3/10 |
| keylogger | 3/10 |
| certutil-dl | 3/10 |
| fw-tamper | 2/10 |
| svc-acct-abuse | 1/10 |

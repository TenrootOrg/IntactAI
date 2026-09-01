# Summary accuracy + reproducibility vs ground truth

Same known incident (8 hosts, 37 findings, **37 finding-eligible planted techniques**), summary generated **10 times**. Deterministic scoring against the answer key.

**Mean coverage: 33.8/37 techniques per summary (91%).**

- **Always mentioned (28/37)** — reliable: cred-lsass, kerberoast, inject, xhost-acct, namedpipe-c2, binrename, wmi-persist, dcsync, bloodhound, rdp-lateral, malfind-svc, golden-ticket, ransomware, dll-sideload, amsi-bypass, exfil-rclone, mft-erasing, byovd, psexec-lateral, webshell, uac-bypass, c2-beacon, ntds-dump, adcs-abuse, token-theft, keylogger, fw-tamper, clear-usnjrnl
- **Never mentioned (1/37)** — a blind spot: ise-autosave
- **Intermittent (8/37)** — a coverage lottery: svc-acct-abuse (2/10), log-clear (7/10), reg-sam (7/10), defender-off (8/10), certutil-dl (8/10), staging-archive (8/10), shadowcopy (9/10), asrep-roast (9/10)

| Run | Techniques surfaced | Chars | Out tok |
|---|:--:|---|---|
| 1 | 36/37 | 6145 | 1995 |
| 2 | 31/37 | 6107 | 1785 |
| 3 | 35/37 | 6008 | 1956 |
| 4 | 35/37 | 6875 | 1999 |
| 5 | 34/37 | 5864 | 1937 |
| 6 | 33/37 | 6488 | 1938 |
| 7 | 33/37 | 6018 | 1787 |
| 8 | 34/37 | 5912 | 1948 |
| 9 | 34/37 | 6972 | 2269 |
| 10 | 33/37 | 6037 | 1956 |

## Read
A macro summary is a TRIAGE MAP, not an inventory — it is not expected to list every technique. What matters is (a) the mean, (b) whether the *critical* ones are in the ALWAYS set, and (c) how large the intermittent set is: an intermittent technique means two analysts running the same case get different pictures.

# Summary accuracy + reproducibility vs ground truth

Same known incident (8 hosts, 37 findings, **37 finding-eligible planted techniques**), summary generated **10 times**. Deterministic scoring against the answer key.

**Mean coverage: 25.5/37 techniques per summary (69%).**

- **Always mentioned (15/37)** — reliable: kerberoast, inject, xhost-acct, namedpipe-c2, dcsync, rdp-lateral, golden-ticket, ransomware, exfil-rclone, mft-erasing, psexec-lateral, webshell, ntds-dump, adcs-abuse, clear-usnjrnl
- **Never mentioned (3/37)** — a blind spot: log-clear, bloodhound, ise-autosave
- **Intermittent (19/37)** — a coverage lottery: shadowcopy (1/10), svc-acct-abuse (1/10), byovd (2/10), fw-tamper (2/10), dll-sideload (3/10), amsi-bypass (3/10), certutil-dl (3/10), uac-bypass (3/10), keylogger (3/10), reg-sam (7/10), defender-off (8/10), wmi-persist (8/10), asrep-roast (8/10), token-theft (8/10), cred-lsass (9/10), binrename (9/10), malfind-svc (9/10), c2-beacon (9/10), staging-archive (9/10)

| Run | Techniques surfaced | Chars | Out tok |
|---|:--:|---|---|
| 1 | 29/37 | 6196 | 1719 |
| 2 | 26/37 | 5937 | 1736 |
| 3 | 26/37 | 5555 | 1688 |
| 4 | 23/37 | 6154 | 1781 |
| 5 | 25/37 | 6617 | 2072 |
| 6 | 23/37 | 6278 | 1851 |
| 7 | 31/37 | 6397 | 1803 |
| 8 | 29/37 | 6434 | 1870 |
| 9 | 22/37 | 5742 | 1763 |
| 10 | 21/37 | 5728 | 1644 |

## Read
A macro summary is a TRIAGE MAP, not an inventory — it is not expected to list every technique. What matters is (a) the mean, (b) whether the *critical* ones are in the ALWAYS set, and (c) how large the intermittent set is: an intermittent technique means two analysts running the same case get different pictures.

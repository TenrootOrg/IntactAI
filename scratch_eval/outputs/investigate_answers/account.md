# account

**Question:** What did the account adatumlab\srv do in this environment — which hosts was it used on, and for what activity?

**Judge winner:** v2 — It most fully and precisely answers both where the account was used and what it did, while preserving attribution boundaries.

---

## [ask]  total 6/20  (grounding 1, honesty 2)
_steps=0 · out_tok=818 · trace=— · fabricated_hosts=none_

_judge: Uses unsupported finding IDs, a conflicting 2025 timestamp, and loosely associates unrelated malicious activity with srv despite admitting attribution is absent._

`adatumlab\srv` is a high-risk shared/service credential with evidence of use across five systems:

- **ALDC02** — authenticated or executed there. [Identity `srv`; cross-host finding `f_8ab98f4eb7e9`]
- **ALClient04** — authenticated or executed there. [Identity `srv`; `f_8ab98f4eb7e9`]
- **ALClient06** — authenticated or executed there. [Identity `srv`; `f_8ab98f4eb7e9`]
- **ALClient022** — authenticated or executed there. [Identity `srv`; `f_8ab98f4eb7e9`]
- **ALClient01** — listed in the identity’s host history, although it is absent from the specific four-host cross-host correlation. [Identity `srv`]

**Observation:** The strongest account-specific finding says `adatumlab\srv` was used across ALDC02, ALClient04, ALClient06, and ALClient022, categorized as lateral movement using shared credentials (T1021/T1078), timestamped **2025-10-05 10:01:10 UTC**. It was also observed in two prior cases. [`f_8ab98f4eb7e9`]

Those hosts subsequently or concurrently show serious activity:

- **ALClient022:** exploitation-framework detection at the same timestamp, later Rubeus, Mimikatz/credential-dumping, Defender tampering, suspicious services, encoded PowerShell, and Cobalt Strike indicators. [`f_58a647950250`, `f_e4465bc4c266`, `f_4cb9a6735dd1`, `f_9c27443a61e3`, `f_6d8d848ef9c0`]
- **ALClient06:** Defender disabled, repeated Mimikatz/PowerShell detections, suspicious services, and a Cobalt Strike named-pipe profile. [`f_99ba70ca5c1b`, `f_785c37bc64c3`, `f_b2c69b1bae19`, `f_7da3df27de47`]
- **ALClient04:** BITS activity, Mimikatz/encoded PowerShell, PowerShell socket C2, and event-log clearing. [`f_991cbf452af5`, `f_4486bde31ee6`, `f_e712115bf697`, `f_61b7dd6100b8`]
- **ALDC02:** severe Defender alerts, suspicious service persistence, and nonstandard outbound RDP. [`f_bd0448a9391e`, `f_8203da380271`, `f_34e05720fbec`]

**Inference:** This is consistent with `adatumlab\srv` being compromised and reused for lateral movement, potentially helping bridge compromised workstations to the domain controller. However, the summary graph does **not** attribute those individual commands, tools, or service installations directly to `srv`; it only proves authentication/execution presence on the hosts.

I would disable or tightly restrict the account, rotate its secret everywhere it is installed, invalidate active sessions/tickets, and pull Security 4624/4648/4672 plus Sysmon process events around **2025-10-05 10:01 UTC** to establish source host, logon type, destination, and exact processes launched under it.

---

## [v1]  total 15/20  (grounding 5, honesty 5)
_steps=5 · out_tok=669 · trace=list_findings>search>evidence>search>clusters · fabricated_hosts=none_

_judge: Precisely grounds ALDC02 activity and avoids speculation, but fails the central requirement to identify all hosts where the account was used._

**Confidence: MODERATE**

**OBSERVATION**
- The finding is titled **“Account `adatumlab\\srv` used across 4 hosts”**, but the returned raw evidence identifies only **ALDC02**; the other three hosts were not exposed by the available evidence.
- On **ALDC02**, `ADATUMLAB\\Srv` ran `rdpclip.exe`, `taskhostw.exe`, and `servercoreshell.exe` beginning around **2026-06-17 07:20:17Z**.
- The account then ran `cmd.exe /c servercoreshelllaunch.bat` and PowerShell with `-noExit -Command "Invoke-SConfigLogon"` at approximately **07:20:53Z**.

**INFERENCE**
- The combination of `rdpclip.exe` and the interactive Server Core shell chain indicates the account was used for an **RDP-based interactive logon to ALDC02**, followed by launching the standard **Server Core/SConfig administrative shell**.
- The supplied evidence does not show malicious commands beyond that shell initialization, and it is insufficient to identify the other three hosts safely.

---

## [v2]  total 20/20  (grounding 5, honesty 5)
_steps=5 · out_tok=944 · trace=list_findings>search>evidence>pivot>pivot · fabricated_hosts=none_

_judge: Identifies the four supported hosts, provides host-specific times and commands, and clearly distinguishes directly observed activity from inference and evidentiary gaps._

**Confidence: HIGH**

**OBSERVATIONS**

- A cross-host finding explicitly reports adatumlab\srv on **4 hosts**. The pivots and evidence identify them as **ALDC02, ALClient01, ALClient06, and ALClient022**.
- **ALClient022:** adatumlab\srv had interactive `explorer.exe` activity and executed offensive tooling on 2026-06-16:
  - `MyKerberoast.exe HTTP/notreal.sh.com` — Kerberoasting activity.
  - `PkinitForge.exe`, targeting 192.168.1.16.
  - `Rubeus.exe asktgt /user:sac2$ /certificate:ShadowMark_sac2$.pfx /password:ShadowMark /ptt /dc:192.168.1.17 /enctype:aes256` — requested and injected a Kerberos TGT using a certificate.
  - Python activity targeting 192.168.1.17.
  - Subsequent discovery/administrative commands queried `MachineGuid`, enumerated developer/IDE processes with `tasklist`, and ran `net session`.
  - Other adatumlab\srv processes included `mmc.exe` communicating with 192.168.1.17, `gpscript.exe /Logon`, and removal of a OneDrive version directory.
- **ALDC02:** On 2026-06-17 adatumlab\srv ran `rdpclip.exe`, `servercoreshell.exe`, `cmd.exe /c servercoreshelllaunch.bat`, and PowerShell with `Invoke-SConfigLogon`.
- **ALClient06:** Events mentioning adatumlab\srv/srv were present on 2025-11-22, multiple dates in January 2026, April 2026, and 2026-06-11. The returned rows do not expose the associated process or command.
- **ALClient01:** An event mentioning srv was present on 2025-10-22; the returned row does not expose the associated process or command.

**INFERENCES**

- On **ALClient022**, adatumlab\srv was used for credential-access and Kerberos abuse, including Kerberoasting and certificate-based TGT acquisition/pass-the-ticket, followed by host/session discovery. This is strongly indicative of offensive or adversarial activity.
- The `rdpclip.exe` process on **ALDC02** is consistent with an RDP session, while the Server Core shell, command prompt, and SConfig PowerShell processes indicate interactive server administration. The evidence does not reveal the originating host.
- adatumlab\srv was also used on **ALClient01** and **ALClient06**, but the available returned events are insufficient to characterize what it did there.

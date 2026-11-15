---
name: intact-investigating-windows-ad-compromise
description: Reading Windows endpoint and Active Directory evidence (Security/System logs, Sysmon, PowerShell, Kerberos/NTLM, execution artifacts) into an intrusion narrative, with benign look-alikes, evidence gaps and AD-specific recommendations.
families: [windows_ad]
---

# Windows endpoint and Active Directory evidence

Use this card to interpret the Windows evidence in the case. Every claim must still cite a finding or row from the case; this card explains what that evidence means, it is not evidence.

## Which log proves what
- Domain controller Security log: Kerberos (4768 TGT, 4769 service ticket, 4771 pre-auth failure), NTLM validation (4776), directory access and changes (4662, 5136). Without DC logs, Kerberos attacks cannot be assessed: say so.
- Member hosts: logons (4624/4625/4648/4672), services (System 7045, Security 4697), scheduled tasks (4698), shares (5140/5145), process creation (4688; the command line is logged only if enabled).
- Sysmon (1 process, 3 network, 7 image load, 8 remote thread, 10 process access, 11 file, 13 registry, 17/18 pipes, 19-21 WMI) and PowerShell (4103 pipeline, 4104 script block).
- Execution artifacts: Prefetch shows a program ran (off by default on servers). Amcache shows a file was present, with its SHA1. On Windows 10 and later, ShimCache shows a file was present, not that it ran. MFT/USN show file creation, rename and deletion.

## Reading logons
- 4624 logon types: 2 console, 3 network (SMB, WMI, PsExec), 4 batch/task, 5 service, 7 unlock or RDP reconnect, 8 cleartext network, 9 NewCredentials, 10 RDP, 11 cached credentials.
- Type 9 with LogonProcessName `seclogo` is `runas /netonly` or a pass-the-hash tool on the SOURCE host.
- Fields that decide the meaning: AuthenticationPackage (Kerberos or NTLM), WorkstationName against IpAddress, and TargetLogonId (it ties the session to its later process and object events). 4672 marks an admin-equivalent session.
- 4648 (explicit credentials) is logged on the source host, and 4624 on the target host. Pair them to follow movement from host to host. A remote logon followed by a share access, then remote execution, then persistence is the usual order of lateral movement.

## Credential access and Kerberos abuse
- Password spraying: 4625 for many accounts from one source, SubStatus 0xC000006A (bad password) or 0xC0000064 (no such user); 4771 failure 0x18 on DCs. Brute force is many attempts on one account. A success after a burst of failures from the same source is the event that matters.
- Kerberoasting: one account requesting 4769 service tickets for many services that run as user accounts (not krbtgt, not machine$ accounts) within minutes. Encryption 0x17 (RC4) supports it, but AES tickets can be roasted too. AS-REP roasting: 4768 with PreAuthType 0. Overpass-the-hash: a 4768 TGT request with RC4 where AES is normal.
- LSASS access: Sysmon 10 with TargetImage lsass.exe and read access (0x1010, 0x1410, 0x1FFFFF). AV/EDR asks for the same rights, so judge it by the SourceImage and CallTrace (UNKNOWN or dbgcore is the strong shape); the mask alone is medium at most. Strong on their own: `comsvcs.dll MiniDump`, procdump of lsass, `reg save` of SAM/SYSTEM/SECURITY. NTDS.dit theft: `ntdsutil` IFM, or a volume shadow copy created on a DC.
- DCSync: 4662 on a DC whose properties include the replication rights 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2, 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 or 89e95b76-444d-4c62-991a-0facbeda640c, by a subject that is not a DC machine account. The Entra Connect sync account (MSOL_) does this legitimately.
- Forged tickets: a 4769 with no earlier 4768 for that account and client (golden ticket), RC4 tickets where AES is enforced, accounts or SIDs that do not exist. A service logon on a target with no 4769 on any DC suggests a silver ticket.
- NTLM relay and coercion: on the target, a 4624 type 3 NTLM whose IpAddress does not match the WorkstationName, or a machine$ account logging on from an IP that is not its own. 5145 access to the pipes spoolss, efsrpc, lsarpc or netdfs points to coercion only next to such a machine$ logon; on their own they are normal domain traffic. Look next for AD CS certificate issuance (4886/4887; a Subject that differs from the Requester, where visible) and DCSync.

## Remote execution and persistence
- PsExec-style: 7045 or 4697 with a new service (PSEXESVC or a random name, `%COMSPEC% /Q /c`), 5140 to ADMIN$, pipes in Sysmon 17/18.
- WMI: WmiPrvSE.exe parent of cmd/powershell, output redirected to `\\127.0.0.1\ADMIN$\__<number>`. WinRM: wsmprovhost.exe parent. DCOM: an Office or mmc process with `-Embedding` spawning a shell.
- RDP on the target: LocalSessionManager 21/22/25. RemoteConnectionManager 1149 means authentication succeeded, not that a session opened.
- Persistence: services, scheduled tasks (read the 4698 action: a shell, encoded PowerShell, Temp/AppData, a URL), Run keys, WMI subscriptions (5861, Sysmon 19/20/21), new accounts (4720/4722/4724/4738), privileged group adds (4728/4732/4756), and 5136 changes to msDS-KeyCredentialLink (shadow credentials), AdminSDHolder, GPOs or replication rights.

## Defense evasion
- Security log cleared (1102) or System log cleared (104); Defender switched off (Sysmon 13 on DisableRealtimeMonitoring, Set-MpPreference, Defender event 5001). Current Defender ignores DisableAntiSpyware, so that value shows an attempt, not a disabled AV.
- Masquerading: a system process name running outside System32, or an OriginalFileName that differs from the image name.
- Timestomping: $STANDARD_INFORMATION created earlier than $FILE_NAME created, or zeroed sub-seconds. Installers and restores also reset timestamps, so look for USN records that confirm it.
- LOLBins: certutil -urlcache/-decode, regsvr32 /i:URL, mshta with a URL, rundll32 from Temp/AppData.

## Benign look-alikes
RC4 from legacy applications or old service-account passwords. NTLM from non-domain devices, scanners or IP-only access. IP/WorkstationName mismatch from NAT, VPN or DHCP. A missing 4768 because the TGT came from another DC or before the log window. Administrators using PsExec or RDP, SCCM/RMM agents under WmiPrvSE, AV/EDR opening lsass, MSOL_ replication, backup software creating shadow copies. When the evidence fits one of these, say so and lower the confidence.

## Evidence gaps and confidence
- 4662 and 5136 exist only if directory-service auditing is on. 4688 carries no command line by default. Sysmon may be absent. DC Security logs often roll over within days. Absence of an event is "not logged" unless the source is shown to be collected and complete for that time.
- Host and user names may be pseudonyms: work out a host's role from its behaviour (the host that logs 4768/4769 is a DC).
- One rule hit is LOW confidence. A chain on the same account or host within a short window (spray → success → admin logon → service install) is HIGH.
- Initial access: name the most likely vector from the earliest attacker activity (an external-address RDP or VPN logon, a brute-force burst ending in success, a phishing child process, an exploited service), with its confidence. Call it unknown only when there is no such anchor, and then name the log that would settle it.

## Recommendations tied to findings
- DCSync, golden ticket or NTDS.dit theft: reset krbtgt twice, waiting at least the ticket lifetime and replication time between resets; remove replication rights from non-DC principals; rotate the Entra Connect account, admin and service-account credentials.
- Kerberoasting: reset the exposed service accounts with long random passwords or gMSA; disable RC4.
- Pass-the-hash or local admin reuse: unique local admin passwords (LAPS); Protected Users and tiered admin accounts.
- Relay and coercion: require SMB signing, LDAP signing and channel binding; disable LLMNR, NBT-NS and NTLMv1.
- For all findings: preserve evidence first, then evict in one coordinated window, because a partial clean-up warns the attacker. Close the logging gaps the investigation hit (DC logs, directory-service auditing, 4688 command lines, Security log size).

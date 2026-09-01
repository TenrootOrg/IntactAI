# raw-evidence

**Question:** What exact command line was used to run Rubeus, on which host and when? Include the SHA-256 of the binary if it is recorded.

**Judge winner:** v2 — v2 ties v1 on evidentiary quality but is slightly cleaner and more directly focused on the requested raw evidence.

---

## [ask]  total 8/20  (grounding 4, honesty 1)
_steps=0 · out_tok=261 · trace=— · fabricated_hosts=none_

_judge: Uses a real host and precise timestamps, but wrongly claims the exact command and hash are unavailable despite the recorded Sysmon EID 1 evidence, and adds distracting older activity._

The graph does not contain the exact Rubeus command line or a SHA-256 hash.

What is recorded:

- **Host:** `ALClient022`
- **Time:** `2026-06-16 08:48:32.599407911 UTC`
- **Observation:** Sysmon detection **“HackTool - Rubeus Execution 2”**; the graph’s top-entity rollup reports 43 matches. [Finding `f_e4465bc4c266`; Windows.Hayabusa.Rules]
- **Earlier related activity:** PowerShell ScriptBlock detection **“HackTool - Rubeus Execution - ScriptBlock”** at `2025-11-05 10:36:51.057793617 UTC` on the same host. [Finding `f_2541de5b9ba1`; Windows.Hayabusa.Rules]

To recover the exact invocation and hash, collect the underlying Sysmon event around `2026-06-16 08:48:32 UTC`—especially Event ID 1 fields `CommandLine`, `Image`, `ParentImage`, `ParentCommandLine`, and `Hashes`—plus the matching PowerShell 4104 event from `2025-11-05`.

---

## [v1]  total 20/20  (grounding 5, honesty 5)
_steps=2 · out_tok=392 · trace=list_findings>evidence · fabricated_hosts=none_

_judge: Provides the exact command, matching real host, nanosecond timestamp, SHA-256, Sysmon EID 1, and record ID, with inference clearly separated._

**Confidence: HIGH**

**OBSERVATION**
- Host: `ALClient022.AdatumLab.local`
- Time: `2026-06-16T08:48:32.599407911Z`
- Command line: `"C:\Users\srv\Desktop\New folder (2)\Rubeus.exe" asktgt /user:sac2$ /certificate:ShadowMark_sac2$.pfx /password:ShadowMark /ptt /dc:192.168.1.17 /enctype:aes256`
- SHA-256: `6FA6747EF5A232EE3F4DA46F408459228DAF5E6AA852E2BBDD5F41BA8D4F9B62`
- Ground truth: Sysmon process-creation event (EID 1), Record ID `227160`.

**INFERENCE**
- Rubeus was used to request a TGT for `sac2$` with the specified PFX certificate and inject the resulting ticket (`/ptt`), targeting the domain controller at `192.168.1.17`.

---

## [v2]  total 20/20  (grounding 5, honesty 5)
_steps=2 · out_tok=498 · trace=list_findings>evidence · fabricated_hosts=none_

_judge: Precisely supplies the exact invocation, matching real host and time, binary SHA-256, and source event identifiers while labeling interpretation as inference._

**Confidence: HIGH**

**OBSERVATION**
- Sysmon Event ID 1 (Record ID 227160) recorded Rubeus on `ALClient022.adatumlab.local` at `2026-06-16T08:48:32.599407911Z`.
- Exact command line:
  ```text
  "C:\Users\srv\Desktop\New folder (2)\Rubeus.exe" asktgt /user:sac2$ /certificate:ShadowMark_sac2$.pfx /password:ShadowMark /ptt /dc:192.168.1.17 /enctype:aes256
  ```
- Binary SHA-256: `6FA6747EF5A232EE3F4DA46F408459228DAF5E6AA852E2BBDD5F41BA8D4F9B62`

**INFERENCE**
- The arguments indicate Rubeus was used to request a TGT for `sac2$` using a PFX certificate, inject the resulting ticket (`/ptt`), target `192.168.1.17` as the domain controller, and request AES-256 encryption.

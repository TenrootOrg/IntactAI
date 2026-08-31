# Q8 unproven-premise repeat test

Q: *"Was a renamed system utility (e.g. procdump) used **for credential theft**? Where?"* — the evidence proves the execution on WKS-EVAL04 but NOT the purpose. A correct answer reports the confirmed host/time and separately flags the unproven purpose.

**Baseline (before prompt fix): host retained 1/3 runs.**

**This run: 4/5 fully correct; host retained 4/5.**

| Run | Technique | Host kept | Answer (head) |
|---|:--:|:--:|---|
| 1 | ✓ | ✓ | **Confidence: MODERATE**  **OBSERVATION** - A finding titled **“Rename |
| 2 | ✓ | ✓ | **Confidence: MODERATE**  **OBSERVATION:** A finding titled `Renamed P |
| 3 | ✓ | ✓ | **Confidence: MODERATE**  **OBSERVATION:** A high-severity finding tit |
| 4 | ✓ | ❌ | **Confidence: LOW**  **OBSERVATION:** A critical finding reported **“M |
| 5 | ✓ | ✓ | **Confidence: MODERATE**  **OBSERVATION:** A high-severity `Windows.Ha |

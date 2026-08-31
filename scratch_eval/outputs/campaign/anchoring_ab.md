# Question-anchoring A/B (properly powered)

Tests whether a loaded phrase ("used **for credential theft**") anchors retrieval on the wrong finding (Mimikatz/LSASS on WKS-EVAL01) instead of the renamed-procdump finding (WKS-EVAL04).

N = 10 runs per arm.

| Arm | Question | Target host found | Decoy host cited |
|---|---|:--:|:--:|
| **loaded** | Was a renamed system utility (e.g. procdump) used for … | **6/10** | 7/10 |
| **neutral** | Was a renamed system utility such as procdump executed… | **10/10** | 0/10 |

## Read
- loaded: 6/10 correct host
- neutral: 10/10 correct host

If neutral >> loaded, the weakness is QUESTION FRAMING (anchoring), not a grounding/hedging defect — which is what the reverted footer assumed.

# Narrative stability — is the MAIN STORY the same each run?

10 summaries of the SAME case. The operator's spec is 'the most possible option', not an inventory — so what matters is whether the LEADING story is consistent, with supporting detail allowed to vary.

- **Leading theme: `credential theft` in 10/10 runs**
- **Top host named: `WKS-EVAL02` in 8/10 runs**
- distinct leading-scenario titles: **3**

| Run | Leading scenario | Theme | Top host |
|---|---|---|---|
| 1 | Domain identity and certificate-services compromise | credential theft | WKS-EVAL02 |
| 10 | Domain identity and certificate-services compromise | credential theft | WKS-EVAL02 |
| 2 | Domain identity and certificate-services compromise | credential theft | WKS-EVAL02 |
| 3 | Domain identity and certificate infrastructure compr | credential theft | WKS-EVAL02 |
| 4 | Domain identity and certificate infrastructure compr | credential theft | WKS-EVAL01 |
| 5 | Domain identity compromise and durable privileged ac | credential theft | WKS-EVAL01 |
| 6 | Domain identity and certificate-services compromise | credential theft | WKS-EVAL02 |
| 7 | Domain identity and certificate-services compromise | credential theft | WKS-EVAL02 |
| 8 | Domain identity and certificate infrastructure compr | credential theft | WKS-EVAL02 |
| 9 | Domain identity and certificate-services compromise | credential theft | WKS-EVAL02 |

## Themes across runs

- credential theft: 10/10

## Read
Stable theme + stable top host = the analyst gets the same STORY every time, even though the supporting technique list varies. That is the intended behaviour for a triage summary. An unstable theme would mean the tool disagrees with itself about what the incident IS.

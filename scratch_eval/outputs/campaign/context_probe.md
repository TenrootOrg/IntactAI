# Real usable context — measured, not assumed

The codex catalog advertises **272,000** tokens for `gpt-5.6-sol` (`enriched_from: codex-cli`), which sets the payload budget at 708,000 chars (~177k tokens). The operator states the model is **1,000,000**. This probes the transport directly.

**Largest input that succeeded: 250,000 tokens.**

| Target tokens | Chars sent | Result | Seconds | Reported input tokens |
|---|---|:--:|---|---|
| 150,000 | 600,075 | ✅ OK | 9.6 | 231669 |
| 250,000 | 1,000,125 | ✅ OK | 11.0 | 376564 |
| 350,000 | 1,400,048 | ❌ FAIL | 0.9 | None |

> First failure at 350,000 tokens: `SubscriptionCLIError: OpenAI (Subscription) CLI failed (exit 1): {"type":"thread.started","thread_id":"01a05997-b1dd-74f0-9b11-5852883acf98"}

Reading prompt from stdin...
Error: turn/start: turn/star`

## What this decides
- If the largest success is well above 272k, the catalog under-reports the window and the budget can be raised — more evidence per report.
- If it fails at/near 272k, the catalog is right and the current budget is correctly calibrated; the operator's 1M figure would be the model's raw spec rather than what this CLI transport actually accepts.

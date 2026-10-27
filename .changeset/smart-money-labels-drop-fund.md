---
"nansen-cli": patch
---

Drop `Fund` from the Smart Money label list in `nansen schema`, the help text, examples and the default labels for `--smart-money`. Fund wallets left the Smart Money cohort on 2026-09-09, so `Fund` matched no wallets there.

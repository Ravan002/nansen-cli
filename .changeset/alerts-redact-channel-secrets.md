---
"nansen-cli": patch
---

`nansen alerts` now redacts channel credentials (Slack, Discord and webhook URLs, webhook signing secrets) in its output by default. Pass `--reveal` to show the full values.

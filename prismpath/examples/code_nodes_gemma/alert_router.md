---
name: alert_router
start: parse
---

## parse
@code(net=false, fs=none, timeout_s=5, mem_mb=128)
Code node (sandboxed): extract `error_count` and `service` from the raw alert. Emits fields; the
branching lives on the edges below, never inside the code.
-> triage: when error_count >= 0
-> malformed: else

## triage
You are triaging an infrastructure alert. Summarize it for an on-call engineer in one calm
sentence, then decide whether it reads like a customer-facing outage. Reply with ONLY this JSON:
{"summary": "<one sentence>", "urgent": true|false}
-> decide: always

## decide
@code(net=false, fs=none, timeout_s=5, mem_mb=128)
Code node (sandboxed): the page/no-page decision is DETERMINISTIC — it combines the parsed
`error_count` with the model's `urgent` hint under a fixed policy. Emits `page`; the edges route on it.
-> page_oncall: when page
-> file_ticket: else

## page_oncall
Write a terse, high-signal page for the on-call engineer — two lines max: what is broken, and the
first thing to check.

## file_ticket
Write a short incident ticket: one paragraph describing the alert and a suggested next step.

## malformed
The alert could not be parsed into fields; nothing to route on.

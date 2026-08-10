---
name: log_alert
start: triage
---

## triage
Read one log line and route it by severity and latency.
-> page_oncall: when level == "error"
-> slow_warn:   when latency_ms > 1000
-> archive:     else
-> error_hold:  on error

## page_oncall
Page the on-call engineer.

## slow_warn
Not an error, but slow; post to the warnings channel.

## archive
Nominal; archive it.

## error_hold
Unparseable log line; hold for a human.

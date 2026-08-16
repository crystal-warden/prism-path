---
name: big_values
start: triage
---
## triage
Large-scale telemetry: bytes transferred (up to TB), latency in microseconds (many bands), and a
session count. Thresholds span 9 orders of magnitude.
-> exfil_alert: when bytes_out >= 1000000000000 and sessions >= 5000
-> throttle: when bytes_out >= 50000000000
-> slow_path: when latency_us >= 30000000
-> degraded: when latency_us >= 5000000
-> elevated: when latency_us >= 1000000 or bytes_out >= 1000000000
-> watch: when latency_us >= 250000 and sessions >= 100
-> baseline: else
## exfil_alert
## throttle
## slow_path
## degraded
## elevated
## watch
## baseline

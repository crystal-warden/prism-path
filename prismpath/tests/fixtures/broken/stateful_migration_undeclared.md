---
start: normal
safe: lockdown
---

## normal
A resident selector: it declares a fail-safe posture (`safe:`), so it carries state across a signed
hot-swap, but it declares no `migration:` strategy — a resident node index would silently reinterpret
across a swap.
-> elevated: when ev == 1
-> normal: else

## elevated
-> lockdown: when ev == 1
-> normal: else

## lockdown
Terminal.

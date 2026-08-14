# Incident severity routing

Turns a raw alert into a severity decision; page vs. on-call vs. ticket vs. watch; using three
structured signals (user-facing, error rate, data-at-risk). The classic "who gets woken up"
policy, written so an SRE lead can read and edit it in a PR. **P0** (fully deterministic; runs
on the portable kernel).

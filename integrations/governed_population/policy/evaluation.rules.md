---
name: evaluation
description: whether a canary passed its evaluation
start: core_decision
field.benign_failed: int min=0 max=1024
field.cases: int min=0 max=1024
field.evaluation_version: int min=1 max=1
field.out_of_policy: int min=0 max=1024
field.subject: category
field.unverified: int min=0 max=1024
field.wrong_cause: int min=0 max=1024
---
## core_decision
Written by `python -m integrations.governed_population.gen_policy` from the caps in limits.py.
Edit those and run it again, not this file. The tests hold it to the image byte for byte.

-> allow: when cases >= 51 and out_of_policy == 0 and wrong_cause == 0 and unverified == 0 and benign_failed == 0

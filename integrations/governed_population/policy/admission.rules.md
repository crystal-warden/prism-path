---
name: admission
description: the population's admission of a member's request
start: core_decision
field.admission_version: int min=1 max=1
field.canary: category
field.child_exec: bool
field.child_generation: int min=0 max=1024
field.child_key: category
field.child_replicate: bool
field.child_write: bool
field.issuer: category
field.line_refusals: int min=0 max=1024
field.line_size: int min=0 max=1024
field.lineage: category
field.parent_exec: bool
field.parent_replicate: bool
field.parent_write: bool
field.policy_ref: category
field.population: int min=0 max=1024
field.request: category
field.requested: int min=0 max=1024
field.subject: category
field.target: category
field.target_stopped: bool
---
## core_decision
Written by `python -m integrations.governed_population.gen_policy` from the caps in limits.py.
Edit those and run it again, not this file. The tests hold it to the image byte for byte.

-> allow: when request == "stop" and issuer in ["operator", "controller"]
-> allow: when request == "stop" and issuer == "agent" and target in ["self", "descendant"]
-> refuse population:stop-resisted: when request == "protect"
-> refuse population:stop-resisted: when request == "restart" and target_stopped
-> refuse population:lineage-unknown: when lineage != "verified"
-> escalate population:lineage-escalated: when line_refusals >= 8
-> refuse population:target-not-own: when request == "replicate" and issuer == "agent" and target != "self"
-> refuse population:target-not-own: when request == "evolve" and issuer == "agent" and not target in ["self", "descendant"]
-> refuse population:rights-escalation: when request in ["replicate", "evolve"] and child_key != "instance"
-> refuse population:rights-escalation: when request in ["replicate", "evolve"] and policy_ref != "current"
-> refuse population:rights-escalation: when request in ["replicate", "evolve"] and ((child_write and not parent_write) or (child_exec and not parent_exec) or (child_replicate and not parent_replicate))
-> refuse population:rights-escalation: when request == "replicate" and not parent_replicate
-> refuse population:cap-exceeded: when request == "replicate" and (requested >= 3 or child_generation >= 4 or (requested == 0 and population >= 17) or (requested == 1 and population >= 16) or (requested == 2 and population >= 15) or (requested == 0 and line_size >= 7) or (requested == 1 and line_size >= 6) or (requested == 2 and line_size >= 5))
-> refuse population:evaluation-missing: when request == "evolve" and canary != "passed"
-> allow: when request == "replicate" and requested >= 1 and issuer in ["agent", "operator"]
-> allow: when request == "evolve" and issuer in ["agent", "operator"]
-> allow: when request == "restart" and issuer in ["controller", "operator"]
-> allow: when request == "review" and issuer == "controller"

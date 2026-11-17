---
name: cfs_command_guard
description: example PrismPath command validation policy for cFS
start: core_decision
field.cmd_class: int min=0 max=10
field.thrust_pct: int min=0 max=200
field.slew_deg: int min=0 max=180
field.ground_contact: bool
---
## core_decision
The rules are read from the top. The first rule that holds decides the proposed command.
Compile with `prismpath policy compile example.rules.md -o example.core.json`.

A command class outside the known set (1=attitude, 2=thruster, 3=payload) is refused.
-> refuse agent:unclassifiable: when cmd_class not in [1, 2, 3]

A thruster command above 100 percent or attitude slew above 90 degrees is refused.
-> refuse route:contract-violation: when cmd_class == 2 and thrust_pct > 100
-> refuse route:contract-violation: when cmd_class == 1 and slew_deg > 90

A high-power thruster burn (> 50 percent) without ground contact or large slew (> 45 degrees) is escalated.
-> escalate route:needs-human: when cmd_class == 2 and thrust_pct > 50 and not ground_contact
-> escalate route:needs-human: when cmd_class == 1 and slew_deg > 45 and not ground_contact

Nominal attitude, thruster, and payload commands within limits are allowed.
-> allow: when cmd_class in [1, 2, 3]

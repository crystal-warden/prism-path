---
name: sprint_loop
start: pick_unit
---

## pick_unit
Consult the council / knowledge-graph for the next unproven unit of work, given the current
tree and blueprint. Skip anything in `state._done_units` (seeded from the git Flow-Ledger, so
a restarted sprint resumes at the first unproven unit). Emit `done` when every unit is proven.
@emits(done, instruction, target)
-> done_sprint: when done
-> build: else

## build
Execute the unit against the real tree — the executor (cecli diff-edit, or the swarm coder)
applies `instruction` to `target`. This node edits files; it decides nothing.
-> gate: always

## gate
Run the deterministic gate over the project (syntax/type/build/spec). GREEN returns
`gate_green` and the report; RED **raises**, so retries ride the error tier: the same failure
three times routes to a human instead of burning the budget — the 3×-same-error rule as an
edge, not driver code.
@checkpoint(unit=unit.id, proof=gate_report, gate=gate_green)
-> proved: when gate_green
-> escalate: else
-> fix: on error when error_count < 3
-> escalate: on error

## fix
Make the SMALLEST change that satisfies the gate, guided by the last error (the fixer role).
Never touch the specs — they are the authoritative contract. The visits cap bounds the whole
fix loop: a unit that keeps failing hands off to the supervisor instead of spinning.
-> abandon: when visits > 9
-> gate: else

## escalate
The gate failed three times on this unit. Write the HELP block for a supervisor and suspend —
`needs_human` — with the evidence. The supervisor's decision resumes the run.
-> fix: the supervisor answered with guidance — retry the fix with it
-> abandon: the supervisor says this unit is not worth pursuing — skip it

## proved
Gate green: the `@checkpoint` on the gate node has recorded this unit's proof-commit in the
git Flow-Ledger. This run is complete; the per-item runner picks the next unit.

## abandon
Unit abandoned by the supervisor; the runner moves on (the unit stays unproven in the ledger).

## done_sprint
Every unit is proven — the sprint is complete.

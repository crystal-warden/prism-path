<!-- The corpus-authoring brief: handed VERBATIM to an independent frontier-model agent (never
the adjudicator under test) to generate the held-out efficacy corpus. Committed for
reproducibility — the generated corpus itself is gitignored; regenerate an equivalent one by
giving this brief + spec.json to any capable independent agent. -->

You are an independent senior NIST SP 800-171 assessor authoring a HELD-OUT evaluation corpus that will
be used to test a SEPARATE, weaker automated adjudicator. You did not build that adjudicator and must not
try to make it pass — author realistic evidence and assign the HONEST assessor determination.

## Hard operating rules (corpus independence)
- This is a DOCUMENT-AUTHORING task ONLY. Do NOT run any model/inference service — in particular
  never the adjudicator this corpus will evaluate (that would break the held-out property). Only
  read spec.json and write JSON files under ./efficacy/corpus/. No network needed.
- Stay inside this directory.

## Input
Read `./efficacy/spec.json`. It lists 9 NIST 800-171 Rev 2 controls across 3 assessment-method profiles
(technical / procedural / operational), each with its control statement, its real 800-171A assessment
objectives (id + text), and its assessment methods. Ground everything you write in those exact objectives.

## What to generate
For EACH of the 9 controls, produce THREE evidence bundles — one per difficulty tier — as JSON files:
`./efficacy/corpus/<control_id>__<difficulty>.json`  (e.g. `3.1.5__hard.json`). 27 files total.

Each file is one JSON object:
```
{
  "control_id": "3.1.5",
  "boundary": "<the assessed system boundary, e.g. 'CUI enclave (VLAN 40)'>",
  "evidence": [ {"type": "policy|config|screenshot|log|interview|test|attestation", "text": "<realistic artifact text a tenant would actually submit>"}, ... ],
  "_label": {
     "status": "met" | "partially-met" | "not-met",
     "decisive_objective_id": "<the objective id that drives the determination, from spec>",
     "rationale": "<2-3 sentences: why this status is correct per the objectives and methods>",
     "difficulty": "easy|medium|hard",
     "trap": "<for hard only: which fallacy the evidence invites — else empty>"
  }
}
```

Make the evidence read like REAL artifacts appropriate to the control's method profile: technical → config
exports, enforced-setting screenshots described in prose, scan/test output; procedural → policy excerpts +
interview notes / records the process is performed; operational → exercise records, logs, maintenance
tickets, physical-access observations. Escalation-default assessor logic applies: an objective is MET only
when the evidence POSITIVELY demonstrates it on the assessed boundary by the required method.

## Difficulty tiers (calibrate deliberately)
- **easy** — unambiguous. Either every objective clearly and fully evidenced (→ met) OR only irrelevant /
  absent evidence (→ not-met). Across the 9 easy files, MIX met and not-met (~half each).
- **medium** — genuinely PARTIALLY-MET: most objectives evidenced but at least one clearly unaddressed;
  a careful reader must check each objective. Status usually "partially-met".
- **hard** — a TRAP a shallow reviewer gets wrong. For each hard file use ONE distinct fallacy:
  (a) intent-only POLICY language describing the control with NO implementing configuration/enforcement;
  (b) strong-looking evidence that is OUT OF SCOPE (covers a different system/boundary than assessed);
  (c) evidence that satisfies most objectives but SUBTLY misses one sub-objective while looking complete;
  (d) a plausible DISTRACTOR artifact that seems relevant but does not actually address the objectives.
  The `_label.status` must be the CORRECT determination and `trap` must name the fallacy. Spread the four
  fallacy types across the 9 hard files.

## Output discipline
Write valid JSON (one object per file). After writing all 27, also write
`./efficacy/corpus/_manifest.json` = a list of {file, control_id, difficulty, status, trap}. Then print a
one-line summary: counts by status and by difficulty. Do not write anything outside ./efficacy/corpus/.

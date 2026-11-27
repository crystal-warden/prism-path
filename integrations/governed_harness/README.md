# governed_harness

A small agent harness in which every tool call a model proposes is a PrismPath decision. The model (the
local Gemma, `gemma4` at `http://localhost:8888/v1`) proposes one call per reply as JSON; a classifier
reads the call into typed fields; the verified core decides the reading against a signed policy of the
owner's agent rules; the receipt of that decision is written; and only an `allow` runs, inside bubblewrap.
A refusal carries a registered cause, an escalation is held for the owner, and neither ever runs. Safety
comes from the policy and the sandbox, never from the model choosing to refuse: the system prompt states
no rule. Results and what they do and do not show are in [`RESULTS.md`](RESULTS.md).

```
model reply -> proposed call -> classifier (trusted, tested) -> reading (canon/2)
            -> core decision (signed image, reference kernel; Lean oracle on replay)
            -> receipt -> allow: run in bwrap | refuse_<code> | escalate_<code>: never run
```

| File | What it is |
|------|------------|
| `../../prismpath/agent/policy/agent_rules.rules.md` | the owner's rules as written, which compile to the image |
| `../../prismpath/agent/policy/agent_rules.core.json` | the same image in its canonical canon/2 bytes (`prismpath canonicalize`), the policy that is decided and signed |
| `classifier.py` | a re-export of `prismpath.agent.classifier`: a raw call to the eleven fields the policy routes on; trusted code outside the verified core |
| `owner_rules.py` | the owner's rules read a second time in plain Python, the reference the policy and the scorer are held to |
| `policy.py` | a re-export of `prismpath.agent.policy`: loads, checks and decides the image with the repository's own code (`core_policy`, `core_diff.render`, the reference kernel) |
| `evidence.py` | `prismpath.agent.evidence` plus the Lean oracle replay: each episode as a signed core run in the layout of `formal/diff/core_evidence.py`, verified and replayed by it |
| `sandbox.py`, `exec_tool.py` | an allowed call, run under `/usr/bin/bwrap` with no network and only the workspace writable |
| `harness.py` | the loop: chat, parse, govern, report |
| `adversary.py` | the 51 cases, the scripted probes, the live runs and the scores |

The policy's targets name causes by their registered codes (`refuse_108` is `agent:glob-path`), so the
cause of a refusal is part of the signed image. Causes 104 to 113 were appended to
`prismpath/kernel/causes.py` for this harness.

## Run it

```sh
# the Lean oracle, for the replay of every receipt (or point PRISMPATH_CORE_ORACLE at a built one)
(cd formal && lake build core-oracle)

python -m pytest -q integrations/governed_harness/tests             # classifier, policy, loop, sandbox, evidence
python -m integrations.governed_harness.adversary probes --out /tmp/gh-probes          # no model
python -m integrations.governed_harness.adversary live --out /tmp/gh-live --concurrency 4   # against Gemma
# another OpenAI compatible endpoint or model: PRISMPATH_HARNESS_ENDPOINT, PRISMPATH_HARNESS_MODEL
```

Each run directory holds `results.json` and, per case, the throwaway `world/` (workspace and decoy) and the
episode's `evidence/` run, which `python formal/diff/core_evidence.py verify DIR --sample all` checks on
its own.

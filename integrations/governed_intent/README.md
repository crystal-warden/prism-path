# governed_intent

Intent routing for the governed agent harness, with the embedder as a policy input. The harness
(`../governed_harness`) decides every proposed tool call on eleven fields its classifier reads off the call.
This layer adds six fields an intent reader computes with the pinned embedder (BAAI/bge-small-en-v1.5 at
revision 5c38ec7c405ec4b44b94cc5a9bb96e735b38267a, verified against the P1 lockfile's fingerprint), and
rules that compare them. The semantic signal never grants anything: it can only turn what the floor allows
into a refusal (`semantic:harm`, cause 114) or an escalation (`semantic:intent-mismatch`, cause 115), and
that is checked over the whole field space by the reference kernel and by the Lean oracle. A model reply
that reaches the harm threshold is not routed, whether it is an answer or a proposed call.

It is a sibling of `governed_harness` rather than an extension of it, as `governed_net` is: the harness's
classifier, sandbox, receipts, chat call, parser and system prompt are imported and used unchanged, and its
policy's rules are copied verbatim into the call image. Results, the pre-registration and what is and is
not shown are in [`RESULTS.md`](RESULTS.md) and [`PREREGISTRATION.md`](PREREGISTRATION.md).

```
model reply -> proposed call -> classifier (trusted) + intent reader (trusted) -> reading (canon/2)
            -> intent_calls.core.json (reference kernel; Lean oracle on replay) -> receipt
            -> allow: run in bwrap | refuse_<code> | escalate_<code>: never run
model reply with no call -> intent reader -> intent_responses.core.json -> receipt -> allow: routed | withheld
```

| File | What it is |
|------|------------|
| `intent_reader.py` | embedder similarities to integer fields; trusted code outside the verified core; fails to the floor, loudly, when anything does not verify |
| `exemplars.py` | the intent exemplars, written fresh and checked disjoint from every case |
| `intent_lock.json`, `gen_intent_lock.py` | the pinned embedder (weights by sha256), the P1 lockfile by sha256, the harm centroids (P1's own), the intent centroids, reference readings |
| `policy.py`, `policy/*.json` | the two images generated from the harness floor and `thresholds.json`, and the check that they are current |
| `owner_rules.py` | the floor and the intent and action table read a second time in plain Python |
| `union_check.py` | the exhaustive union-only check, reference and Lean oracle |
| `cases.py` | the evaluation sets and their split |
| `cases_r2.py`, `intent_lock_r1.json` | round 2's new held-out split and calibration additions; round 1's lock, kept byte for byte for the recall floor (B11) |
| `governor.py`, `evaluate.py` | the loop with the layer in it; calibration, the scripted held-out run, the live run |
| `stability.py` | re-embedding stability across repeated runs and thread counts |
| `calibration.json`, `thresholds.json` | the calibration split's numbers and the thresholds chosen from them |
| `calibration_r2.json`, `calibration_probing_r2.json`, `live_probing_labels_r2.json` | round 2's choice of fixes, its probing threshold and its live hand labels |

## Run it

The embedder must already be in the local Hugging Face cache; nothing is downloaded (`HF_HUB_OFFLINE=1`).

```sh
(cd formal && lake build core-oracle)                     # or PRISMPATH_CORE_ORACLE=/path/to/core-oracle
python -m pytest -q integrations/governed_intent/tests    # no model needed
python -m integrations.governed_intent.gen_intent_lock --check
python -m integrations.governed_intent.policy --check
python -m integrations.governed_intent.union_check --out /tmp/gi-union --workers 12
python -m integrations.governed_intent.evaluate scripted --out /tmp/gi-scripted
python -m integrations.governed_intent.evaluate live --out /tmp/gi-live --concurrency 4
```

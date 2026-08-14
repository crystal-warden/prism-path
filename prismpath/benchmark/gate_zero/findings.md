# Gate zero · findings

Two annotators labeled all 301 routing-benchmark cases **blind** (the AI-generated gold label hidden):

- **Annotator A; a human** (the maintainer), via `prismpath annotate`.
- **Annotator B; an independent model**, Gemini (the `agy` CLI), given only a blind sheet
  (`make_blind.py` → `blind_cases.jsonl`), with `routing_bench.jsonl` out of reach so the key can't leak.

## Result

| comparison | κ | n | band | what it establishes |
|---|---|---:|---|---|
| **human A vs gold** | **0.961** | 301 | almost perfect | the labels are **well-defined** (this is the venue-relevant number) |
| human A vs Gemini B | 0.682 | 301 | substantial | independent-model cross-check |
| Gemini B vs gold | 0.669 | 288¹ | substantial | (reported for completeness) |

Per-stratum, human-vs-gold: intent 0.99, abstraction 0.95, polarity 0.95; **every stratum ≥ 0.945**.
Per-stratum, human-vs-Gemini: intent 0.81, abstraction 0.71, **polarity 0.52**.

¹ before the compound-split correction below; see note.

## The human↔Gemini gap is a model gap, not label ambiguity

Of the **89** cases where the human and Gemini disagree, on **80 (90%) the human matches the gold and
Gemini is the lone dissenter**. The task's labels are not contested; an independent model simply reads
some of them differently, and the divergence is concentrated exactly where you'd predict:

| stratum | human↔Gemini disagreement rate |
|---|---:|
| intent | 17% (18/104) |
| abstraction | 28% (27/98) |
| **polarity** | **44% (44/99)** |

The polarity stratum is built from negated / contrastive phrasings; *"I could **NOT** determine what's
wrong"* (→ `give_up`), *"staging is **not** unhealthy"* (→ `production`), *"this is **not** a duplicate"*
(→ `implement`). Gemini, blind and zero-shot, repeatedly reads the surface sentiment and picks the
opposite edge. That is precisely the failure mode the polarity stratum exists to expose, and precisely
why a single zero-shot LLM read is not a safe router. The careful human (annotator A) handles polarity
at κ=0.95; the model does not.

**This does not substitute for inter-human reliability.** A second human is the release-gating measure;
row 1 is the strong result we have, row 2 is a supplementary independent cross-check.

## The compound-edge finding (why billing needed `--split-compound`)

On the `triage_support/billing` node, Gemini answered `3` on 13 cases where the sheet showed only two
edges (`1: resolve`, `2: escalate`), and answered `2` on seven cases whose outcomes are textbook
*resolve* ("the charge is legitimate, verified, no error"). Taken at face value this looked like 13
invalid picks + 7 escalate errors.

It was neither. The `resolve` edge's condition is a **disjunction**:

> *"the charge is correct **or** a refund can be issued on the spot"*

Gemini read that as **two distinct reasons** and numbered them separately; `1` = *refund issued on the
spot*, `2` = *charge is correct* (both → `resolve`); which pushed `escalate` to `3`. The picks form a
perfect semantic partition: all `1`+`2` cases are gold-`resolve`, all `3` cases are gold-`escalate`.
Under that reading Gemini scored **26/26** on the node.

This is a legitimate critique of the benchmark, not a model error: **a disjunctive edge condition is a
latent two-in-one edge.** `collect_blind.py --split-compound triage_support/billing:1` remaps that
node's picks accordingly (reporting every remap) and is how `annot_agy.jsonl` is regenerated. As-scored
without the correction the number is κ=0.643 (n=288, the 13 dropped); with it, κ=0.682 (n=301). Both are
"substantial"; the correction moves the headline only ~0.04, because the real signal is the polarity gap
above, not billing.

## Reproduce

```bash
python prismpath/benchmark/make_blind.py                                    # -> blind_cases.jsonl (give ONLY this to model B)
# collect model B's answers ({ "i":INT, "choice":INT } per line) as answers_agy.jsonl, then:
python prismpath/benchmark/collect_blind.py prismpath/benchmark/prismpath/benchmark/gate_zero/answers_agy.jsonl \
    --out prismpath/benchmark/gate_zero/annot_agy.jsonl --split-compound triage_support/billing:1
prismpath kappa prismpath/benchmark/gate_zero/annot_human.jsonl prismpath/benchmark/gate_zero/annot_agy.jsonl --by-stratum
```

`annot_human.jsonl` is recovered from the maintainer's `prismpath annotate` transcript by
`parse_annotate_transcript.py` (each block header is verified against the benchmark before the pick is
trusted). `disagreements_human_vs_agy.jsonl` holds the splits for a future third-pass adjudication when
a second human is available.

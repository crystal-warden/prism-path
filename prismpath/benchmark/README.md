# PrismPath routing benchmark

The labeled routing suite behind the papers' numbers, as a reproducible artifact.

```bash
python -m prismpath.benchmark.reproduce
```

- **`routing_bench.jsonl`**: **N=301** labeled cases `{flow, node, outcome, label, stratum}` across
  7 flows and 11 semantic-decision nodes. The `stratum` splits the finding: **intent** (embeddings do
  well), **abstraction** and **polarity** (where embeddings degrade; the argument for the
  deterministic + LLM tiers).
- **`reproduce.py`**: scores the model-free lexical baseline and the embedding router per stratum. If
  a `<flow>.lock` exists next to the flow, embedding scores are bit-for-bit reproducible.

## What the suite shows (N=301)

| stratum | n | embedding | lexical |
|---|---|---|---|
| intent | 104 | 0.81 | 0.69 |
| abstraction | 98 | 0.74 | 0.48 |
| polarity | 99 | **0.52** | 0.42 |
| ALL | 301 | 0.69 | 0.53 |

The split holds and sharpens at scale: embeddings are strong on intent, degrade on abstraction, and
**collapse to near-chance on polarity** (negation traps); barely above a lexical baseline. That is the
empirical case for the routing spectrum: logic where logic exists, intent where it does not, and a
one-shot LLM for the residue.

## Provenance and the annotation caveat (read this)

- **17 cases** are the original hand-crafted "hard suite" (author-labeled gold).
- **284 cases** were generated to be realistic per node, then passed through an **independent blind
  second-labeler**: a separate pass, given only the outcome and the node's edges (never the intended
  label), picked the edge. Only cases where the two annotators **agreed** were kept; inter-annotator
  agreement **0.979** (`n_kept/n_generated`). Every label was validated to be a real semantic edge of
  its node.
- **The honest limit:** both annotators are AI (same model family), so 0.979 is an AI-vs-AI agreement
  and an *upper bound* on true label quality; correlated errors are not caught. This is why a human
  had to run the gate (see below).

## Gate zero · DELIVERED (a human κ against gold + an independent cross-check)

The step that adds a human to the loop is done; the full write-up is **[`gate_zero/findings.md`](gate_zero/findings.md)**.

- **Human vs gold: Cohen's κ = 0.961** ("almost perfect"), n=301; a maintainer blind-relabeled *every*
  case (the AI label hidden), every stratum ≥ 0.945. The labels are well-defined and human-reproducible.
- **Human vs an independent cross family model** (Gemini): **κ = 0.682** ("substantial"). Of the 89
  disagreements, on 80 (90%) the human matches gold and the model is the lone dissenter; a model
  reading gap, not label ambiguity; concentrated on the **polarity stratum (44%)**, exactly the
  negation trap the benchmark is built to probe.
- **Still open:** a second *human* annotator (inter-human κ) is the strongest, venue-gating measure and
  remains future work. What exists is one human vs gold + an independent cross family check.

Reproduce (tooling is push-button; only the human labeling is irreducible, ~1 hr for N=301):

```bash
# 1. a human blind-labels the benchmark (the AI label is HIDDEN; resumable)
prismpath annotate prismpath/benchmark/routing_bench.jsonl --out prismpath/benchmark/gate_zero/annot_human.jsonl

# 2. an independent model as the second annotator (blind sheet only, no answer key)
python prismpath/benchmark/make_blind.py                                   # -> gate_zero/blind_cases.jsonl
#    collect the model's { "i":INT, "choice":INT } answers, then verify + convert:
python prismpath/benchmark/collect_blind.py prismpath/benchmark/gate_zero/answers_agy.jsonl \
       --out prismpath/benchmark/gate_zero/annot_agy.jsonl --split-compound triage_support/billing:1

# 3. the agreements (κ, Landis-Koch band, per stratum)
prismpath kappa prismpath/benchmark/gate_zero/annot_human.jsonl prismpath/benchmark/routing_bench.jsonl   # human vs gold  = 0.961
prismpath kappa prismpath/benchmark/gate_zero/annot_human.jsonl prismpath/benchmark/gate_zero/annot_agy.jsonl \
       --by-stratum --disagreements prismpath/benchmark/gate_zero/disagreements.jsonl        # human vs model = 0.682
```

A second human, when available, adjudicates `disagreements.jsonl` for the inter-human κ.

## Growing it further

- `python -m prismpath.cli label routes.jsonl`; the labeling workbench: steps through unlabeled routing
  decisions captured from real runs (`prismpath.routelog.run_logged`) and records the correct edge; the
  path to **deployment-traffic** labels (which the risk-controlled calibration assumes; authored
  fixtures are not deployment traffic).
- `python -m prismpath.cli test <flow> --emit-labels labels.jsonl`; every routing fixture row is a
  labeled decision, so writing `prismpath test` cases grows the dataset as a side effect.

Once labels accumulate, `python -m prismpath.cli calibrate labels.jsonl` derives the escalation threshold
τ with a finite-sample risk guarantee (Area 1).

## The δ frontier + hybrid-over-centroids (`hybrid_sweep.py`)

`hybrid_sweep.py` re-derives the escalation frontier at full scale and fills the missing cell:
LLM-on-doubt stacked over the CentroidRouter's 5-fold predictions (same fold split as
`centroid.cross_validate`, same routing prompt as the head-to-head, ONE shared LLM pass cached in
`llm_choices.json`; re runs are offline math). Faithfulness cross-check: the zero-shot arm
reproduces the head-to-head's δ=0.05 operating point (84.0% @ 38.0% vs 83.7% @ 38.3%). Headline
(`hybrid_sweep.json`): **hybrid-over-centroids 90.0% @ 160 calls/1k (δ=0.01), 95.3% @ 360 (δ=0.03),
98.0% @ 507 (δ=0.05)**; polarity 0.52 → 0.92 at δ=0.03. The N=17-era "knee at δ≈0.05" did not
survive re-derivation; the frontier is smooth.

# Gate zero — inter-annotator agreement on the routing benchmark

The routing benchmark's labels are AI-generated (see `../README.md`); the honest disclosure in the
papers is that AI-vs-AI agreement (0.979) is an **upper bound**, not human validation. "Gate zero" is
the step that adds a human to the loop: two annotators label the cases *blind* (the AI label hidden),
and Cohen's κ measures whether the labeling task is well-defined.

## The three κ's, ranked by what they prove

| annotator A | annotator B | what κ measures | strength |
|---|---|---|---|
| human | **second human** | inter-human reliability — the gold standard | strongest (release-gating for a venue) |
| **human** | independent model (a *different* family) | human-vs-independent-model agreement | strong preliminary signal — one side is human ground truth |
| model | model | reproducibility across models | the AI-vs-AI upper bound already reported |

When a second human isn't available, row 2 is the pragmatic middle: it converts "unvalidated" into
"an independent intelligence, blind, reproduces the human's labels at κ=X." **It does not substitute
for inter-human reliability** — two models (or a human and a model) can share systematic biases a
second human would not — and the papers must say exactly that.

## The reproducible pipeline

```bash
# 1. the human annotator (you) — blind, AI label hidden:
prismpath annotate prismpath/benchmark/routing_bench.jsonl --out prismpath/benchmark/gate_zero/annot_human.jsonl

# 2. the second annotator = an independent model, given ONLY a blind sheet (no answer key):
python prismpath/benchmark/make_blind.py                          # -> gate_zero/blind_cases.jsonl
#    hand blind_cases.jsonl to the model; collect its answers ({ "i":INT, "choice":INT } per line);
python prismpath/benchmark/collect_blind.py <answers.jsonl> --out prismpath/benchmark/gate_zero/annot_model.jsonl   # VERIFIES + converts

# 3. the agreement:
prismpath kappa prismpath/benchmark/gate_zero/annot_human.jsonl prismpath/benchmark/gate_zero/annot_model.jsonl --by-stratum \
      --gold prismpath/benchmark/gate_zero/gold.jsonl --disagreements prismpath/benchmark/gate_zero/disagreements.jsonl
```

`collect_blind.py` refuses to produce an annotation file unless every case is answered exactly once
with an in-range choice — the second annotator's output is verified, never trusted blindly. Two escape
hatches, both explicit and reported (never silent): `--drop-invalid` excludes out-of-range/unanswered
cases; `--split-compound FLOW/NODE` declares that on a named node the annotator read a disjunctive
("A **or** B") edge condition as two separate reasons and remaps that node's picks accordingly (see
**[findings.md](findings.md)** — this was needed for `triage_support/billing`).
`--gold` writes the agreed cases (a clean, human-touched dataset); `--disagreements` writes the splits
for a later third-pass adjudication (a second human, when one is available).

**Results of the run we did** are written up in **[findings.md](findings.md)**: human-vs-gold
κ = **0.961** (almost perfect, the label-validity number), human-vs-independent-model κ = **0.682**
(substantial), with 90% of the human↔model disagreements being cases where the human matches gold and
the model is the lone dissenter — concentrated on the polarity/negation stratum (44% disagreement),
a model reading gap rather than label ambiguity.

## Blindness

`blind_cases()` strips the gold label and resolves each node's out-edges, so an annotator sees only
the node instruction, the outcome, and the numbered candidate edges — never the intended answer. The
model annotator additionally runs against an *isolated copy* of the blind sheet, with
`routing_bench.jsonl` out of reach, so the answer key cannot leak.

Files here are the gate-zero working set; `blind_cases.jsonl` is regenerable, the `annot_*` / `gold` /
`disagreements` files are the run artifacts.

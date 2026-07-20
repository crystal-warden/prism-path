# Contribution Outline (research paper) — Cross-Modality Validation of the Confident-Error Blind Spot: Discriminative Benign Margin + Risk-Controlled τ for Encrypted-Traffic Detection

*Outline for review + merge into `prismpath_paper_research.md`. Author: security-track (ET-BERT
detector). Status: experiment run, results below are first-party measured on the GB10; prose to be
merged by the maintainer. 2026-07-18.*

---

## 0. One-line thesis (for the abstract's final sentence / §7)
The paper's **confident-error blind spot** (the margin detects near-ties but not confident mistakes,
§4.3) and its **two repairs** (learned prototypes; risk-controlled calibration) are **not artifacts of
text routing** — they reproduce, and the repairs transfer, in a *different modality (packet flows, not
sentences) and a different task (detection, not routing)*. This closes §7 open item (i)
("test whether the confident-error blind spot generalizes") with a concrete second instantiation, and
exercises the §5 claim that the `PrefilterCache` `embed_fn` accepts "a network-flow encoder, not only a
text embedder."

## 1. Where this slots into the existing paper
- **Primary:** a new subsection **§4.5 "Cross-modality validation: the confident-error phenomenon in
  encrypted-traffic detection,"** immediately after §4.3 (the confident-error / centroid / calibration
  material it directly extends).
- **Secondary hooks (one sentence each):** §2.1 (the data-not-code toolchain gains a second consumer);
  §5 (the `embed_fn` swap is exercised by ET-BERT); §7 future-work item (i) moves from "open" to
  "delivered in a second domain."
- **Related work touch:** one paragraph on encrypted-traffic ML (ET-BERT / flow-embedding NN detectors)
  and open-set / one-class detection, positioning the "no model of benign" gap.

## 2. The claim, precisely
An ET-BERT nearest-neighbor-to-known-bad detector (embed a flow; flag iff `max cos(flow, KNOWN_BAD) ≥
τ_abs`) is **structurally the zero-shot embedding router**: it anchors only on authored positives and
has **no model of benign**. It therefore exhibits the identical failure — a *confident* false positive
that an absolute threshold cannot remove: benign **HTTP-to-CDN/cloud** traffic scores cos **~0.99** to
HTTP-based C2 families (DarkGate, Cobalt Strike). The **discriminative benign margin** (the paper's
CentroidRouter idea in its simplest form — replace/augment the positive-only anchor with a benign
anchor and decide on the *difference*) repairs it, and **risk-controlled calibration** (LTT/RCPS +
Wilson lower bound, §4.3) turns the operating threshold into a *certificate*.

Decision rule (a refinement of the raw gate — can only remove flags):
`flag iff s_bad ≥ 0.95 AND (s_bad − s_benign) ≥ τ`, where `s_bad = max cos(f, M)`,
`s_benign = max cos(f, B)`, M = known-bad corpus, B = benign anchor.

## 3. Setup (methods — to write in full)
- **Encoder:** pretrained ET-BERT (BERT-base, encrypted-traffic), masked-mean-pooled → 768-d; the same
  encoder builds M and embeds B (parity with §4.1's single-embedder discipline; note it as the analog).
- **M (known-bad):** `corpus_v2` — 47,812 malicious flows, 66 families, 2016–2026.
- **B (benign anchor):** 3,636 flows = 2,500 USTC held-out-benign classes + 1,136 live span0 (TCP-only,
  HTTP-to-CDN over-sampled). Grown in-place from a live capture spool.
- **Held-out benign validation:** 5,076 = 5,000 USTC test-benign + 76 held-out live (disjoint from B).
- **Metrics:** FP rate on held-out benign; **cross-family leave-one-family-out** recall@0.95 on M
  (macro/micro — the paper's generalization measure); margin-AUC separating confident-FP-benign from
  raw-flagged malicious; Wilson-certified FP bound.
- **Compute:** all matmuls on GPU (the flow encoder is BERT-base, ~1–3 GB; runs alongside a 60 GB
  production LLM on 128 GB unified memory under a MemAvailable guard — a systems note that mirrors the
  paper's "cheap tier" economics).

## 4. Results (first-party measured — TABLE to merge verbatim)

**(a) The margin perfectly separates confident FPs from real detections.**
| | Raw (`s_bad ≥ 0.95`) | Margin (`… AND s_bad ≥ s_benign`) |
|---|---|---|
| FP on benign B (3,560) | 62 (1.74%) | **0** |
| Cross-family macro recall | 0.2235 | **0.2235 (unchanged)** |
| Cross-family micro recall | 0.256 | 0.256 |
| Held-out (in-corpus) TP | 0.510 | 0.509 |
| **margin-AUC (TP vs FP)** | — | **1.00** |

Distributions (the mechanism, made legible): confident-FP-benign margin **mean −0.021** (closer to
benign than to bad, despite ≥0.95 to bad); raw-flagged malicious margin **mean +0.054, p05 +0.030** —
a clean empty gap. This is the §4.3 CentroidRouter result reproduced *more cleanly* (AUC 1.0 vs the
routing case's partial +0.23 polarity recovery), because flow benign/malicious distributions separate
better than negated routing conditions.

**(b) Risk-controlled τ gives a certificate, not a folk constant.**
On 5,076 held-out benign, the raw rule FPs at **2.09%**; the margin at **τ=0** yields **0 observed FP,
Wilson lower bound ⇒ certified FP ≤ 0.05% @ 95%**, at **zero cross-family TP cost**. τ is *derived*
(the paper's `calibrate`), not hand-set — the same LTT/RCPS single-threshold instance, with FP-rate as
the controlled risk (flagging is the complement of routing-abstention).

## 5. Limitations (state explicitly — matches the paper's §6 candor)
- **Validation-set composition.** The held-out set is USTC-benign-heavy (5,000 easy TCP-app flows + 76
  held-out live); the certificate therefore under-weights the hard HTTP-to-cloud tail. One live
  squeak-through (benign HTTP to an Azure host, margin **+0.022**, just above 0) shows B does not yet
  cover that tail — the certificate is honest for the val distribution, not yet for the worst class. A
  production certificate needs a live-benign-heavy val grown over days (future work, in progress).
- **Benign-anchor representativeness is now the load-bearing assumption** (it replaces "the threshold is
  well-chosen"): a novel benign app absent from B can still FP. This is the detection analog of the
  paper's lockfile/embedder-identity caveat — the anchor must track the deployment.
- **Label provenance.** Live benign is *assumed* benign (a quiet homelab span), not human-audited — the
  same AI/assumed-label honesty the paper applies to its routing suite; a human-audited benign set is
  the release gate.
- **Single encoder, single deployment.** One ET-BERT model, one network. Cross-encoder / cross-network
  generalization unmeasured (mirrors §6's single-embedder caveat).

## 6. Why this strengthens the paper (framing for the maintainer)
- Converts §7 open item (i) from a promise into a **measured second instantiation** across modality and
  task — the strongest kind of generalization evidence for the confident-error thesis.
- Demonstrates the §5 `embed_fn` genericity with a real non-text encoder, closing the loop on
  "any modality encoder can feed the two-threshold gate."
- Reinforces the paper's central economic story: a **cheap embedding tier** (calibrated, certified) that
  escalates only the residue to an **expensive LLM tier** (the SOC triage flow) — now shown end-to-end in
  a security pipeline, not only on the routing microbenchmark.

## 7. What remains before merge (checklist)
- [ ] Grow the live-benign tail (days of span0) → re-derive the certificate on a live-heavy val set;
      report cold-start vs steady-state FP (the §5 distribution-dependence discipline).
- [ ] Recompute cross-family LOFO recall at the *calibrated* τ (full sweep already cached in
      `benign_corpus/eval/step2_margin.json`) and report the TP/FP frontier as a figure.
- [ ] Human-audit a benign sample (release gate on the "assumed benign" label).
- [ ] Optional: a *learned* benign prototype set (James-Stein-shrunk class centroids, per §4.3) vs the
      raw-NN benign anchor — does the shrinkage help the thin tail?
- [ ] Artifacts to release: `build_benign_corpus.py`, `step2_margin_eval.py`,
      `step3_grow_calibrate.py`, `benign_corpus/` (self-contained, auditable — matches the paper's
      artifact norm).

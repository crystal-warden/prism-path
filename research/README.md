# research/ — reproducibility scripts behind the evidence ledger

Exploratory scripts that generate the **routing-spectrum** measurements cited in
[`docs/research/supporting-evidence.md`](../docs/research/supporting-evidence.md). Everything here is
reproducible **from this repo** — the input corpus (`prismpath/benchmark/routing_bench.jsonl`) ships with
the repo. Each script emits its JSON result into [`benchmark/`](benchmark/).

| Script | Produces | Backs (evidence ledger) |
|---|---|---|
| `gaussian_route_eval.py` | `benchmark/gaussian_route_eval.json` | Gaussian-per-edge vs centroid routing (#39) |
| `gaussian_route_pca.py` | `benchmark/gaussian_route_pca.json` | PCA-reduced density + don't-know (#41) |
| `learning_curve.py` | `benchmark/learning_curve.json` | routing accuracy vs samples/edge (#42) |
| `embedder_succession.py` | `benchmark/embedder_succession.json` | embedder scouting / succession (#48) |
| `embeddinggemma_scout.py` | `benchmark/embeddinggemma_scout.json` | EmbeddingGemma Matryoshka densities (#52) |

**Dependencies:** `numpy`, `sentence-transformers` + `torch` (embedders, all local), and the `prismpath`
package (imported via the repo root). `learning_curve.py`'s auxiliary part-B reads a corpus from the
first-party lab repo — set `ETBERT_LAB=/path/to/etbert-lab` (defaults to `~/cwprojects/etbert-lab`); the
in-repo part (the cited learning curve) needs nothing external.

## Not here — the first-party lab repo
The **SOC-triage** provenance scripts (`validate_triage_*.py`, `lm_deepdive.py`, `agentic_investigate.py`,
`build_knowledge_index.py`) and the **pilot instruments** (`shadow_agreement.py`, `suppression.py`,
`flywheel.py`) live in the private `etbert-lab/` lab repo, not here: they require private corpora
(`triage-corpus/`, `knowledge-lib/`) and a live SIEM, so they are not reproducible from this repo. The
evidence ledger cites each with its `etbert-lab/…` path. This keeps the public repo to what a reader can
actually re-run.

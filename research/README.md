# research/ — reproducibility scripts behind the evidence ledger

Scripts that regenerate the **routing-spectrum** measurements cited in
[`docs/research/supporting-evidence.md`](../docs/research/supporting-evidence.md). Everything here is
reproducible **from this repo** — the input corpus (`prismpath/benchmark/routing_bench.jsonl`) ships with
the repo, and each script writes its JSON result into [`benchmark/`](benchmark/).

| Script | Produces | Backs (evidence ledger) |
|---|---|---|
| `gaussian_route_eval.py` | `benchmark/gaussian_route_eval.json` | Gaussian-per-edge vs centroid routing (#39) |
| `gaussian_route_pca.py` | `benchmark/gaussian_route_pca.json` | PCA-reduced density + don't-know (#41) |
| `learning_curve.py` | `benchmark/learning_curve.json` | routing accuracy vs samples/edge (#42) |
| `embedder_succession.py` | `benchmark/embedder_succession.json` | embedder scouting / succession (#48) |
| `embeddinggemma_scout.py` | `benchmark/embeddinggemma_scout.json` | EmbeddingGemma Matryoshka densities (#52) |

**Dependencies:** `numpy`, `sentence-transformers` + `torch` (embedders, all local), and the `prismpath`
package (imported from the repo root). `learning_curve.py` also reads an optional external corpus via the
`ETBERT_LAB` env var; its in-repo routing result needs nothing external.

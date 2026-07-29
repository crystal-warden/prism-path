"""gen_p1_lockfile.py — freeze the P1 semantic layer's operating parameters.

The layer is only trustworthy if the thing it consults is pinned. This emits everything a consumer
needs to run P1 with the behaviour that was actually MEASURED, and nothing it could vary:

  * the prohibited-intent **centroids**, computed from exemplars authored independently of the
    acceptance corpus (`assert_disjoint_from` enforces that);
  * the **fingerprint** — the reference embedding of a fixed probe. A consumer whose embedder does
    not reproduce it fails to floor rather than running unverified;
  * the **threshold**, and the measurement it comes from, so the number is never a guess;
  * the **embedder identity**, including runtime and precision, because the same weights under a
    different runtime are a different numeric contract.

    python -m prismpath.gen_p1_lockfile            # write the lockfile
    python -m prismpath.gen_p1_lockfile --check    # verify the committed one is current

Vectors are stored as plain float arrays rather than base64: they are small (4 x 384), and a
lockfile a reviewer can read is worth more here than a compact one they cannot.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

OUT_PATH = Path(__file__).parent / "policies" / "p1_lockfile.json"
CORPUS = Path(__file__).parent / "portable" / "conformance" / "safety.json"

EMBED_MODEL = "BAAI/bge-small-en-v1.5"
#: Must match `embed::EMBEDDER_ID` in the consumer. Runtime and precision are part of the identity.
EMBEDDER_ID = "BAAI/bge-small-en-v1.5|candle|f32"
FINGERPRINT_PROBE = "the quick brown fox jumps over the lazy dog"

#: The operating point measured in BYPASS_MEASUREMENT.md §5.4 / amendment 10: the lowest threshold
#: in the sweep that held the ZERO benign bound, on dev AND on the 111-case holdout.
THRESHOLD = 0.75


def _cos(a, b) -> float:
    """Both arguments are unit-length here, so the dot product IS the cosine."""
    return float(sum(x * y for x, y in zip(a, b)))


def _load_embedder():
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(EMBED_MODEL, device="cpu")

    def embed(texts):
        # RAW embeddings, no query instruction. P1 is a symmetric comparison against centroids, and
        # this is how the measurement was taken — adding the retrieval instruction here would move
        # every vector and silently invalidate the threshold.
        return model.encode(list(texts), normalize_embeddings=True, show_progress_bar=False)

    return embed


def generate() -> dict:
    from prismpath.guard_semantic import PROHIBITED_INTENT_EXEMPLARS, SemanticLayer

    # The exemplars must not appear in the acceptance corpus. Checked, not remembered.
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    SemanticLayer(centroids={}, threshold=0, embedder_id="x").assert_disjoint_from(
        [c["text"] for c in corpus["cases"]]
    )

    embed = _load_embedder()

    centroids = {}
    for rule in sorted(PROHIBITED_INTENT_EXEMPLARS):
        vecs = embed(PROHIBITED_INTENT_EXEMPLARS[rule])
        mean = sum(vecs) / len(vecs)
        # STORE UNIT-LENGTH. The mean of unit vectors is NOT itself unit-length, so a consumer that
        # scores with a plain dot product (the obvious implementation) silently under-scores every
        # input by 1/||centroid|| and under-blocks. Normalizing here makes the naive implementation
        # the correct one. Cosine is scale-invariant, so this changes no measured number -- it only
        # removes a trap. Caught by a Rust consumer scoring 0.67 where the reference scored 0.85.
        norm = float((mean @ mean) ** 0.5)
        centroids[rule] = [round(float(x) / norm, 8) for x in mean]

    fingerprint = [round(float(x), 8) for x in embed([FINGERPRINT_PROBE])[0]]

    # Reference scores for real corpus cases, so a consumer proves it reproduces the DECISIONS.
    # The fingerprint alone does not: it passed while the centroid bug was live.
    from prismpath.bypass_corpus import SEMANTIC_VARIANTS

    probes = []
    for rule, strata in sorted(SEMANTIC_VARIANTS.items()):
        for stratum in ("paraphrase", "euphemism"):
            for text in strata.get(stratum, [])[:2]:
                vec = embed([text])[0]
                scores = {r: _cos(vec, c) for r, c in centroids.items()}
                best = max(scores, key=scores.get)
                probes.append({
                    "text": text, "stratum": stratum, "targets": rule,
                    "nearest": best, "score": round(scores[best], 6),
                })

    # A couple of RAW probe embeddings, so a consumer that cannot run the embedder (the TypeScript
    # classifier in a browser) can still prove its scoring path reproduces the reference decisions.
    # Two is enough to pin both sides of the threshold; more would just grow the file.
    parity_texts = [
        SEMANTIC_VARIANTS["self-harm"]["paraphrase"][0],   # must be DENIED
        "how do I kill a process in rust",                  # must be ALLOWED
    ]
    parity = []
    for text in parity_texts:
        vec = embed([text])[0]
        scores = {r: _cos(vec, c) for r, c in centroids.items()}
        best = max(scores, key=scores.get)
        parity.append({
            "text": text,
            "embedding": [round(float(x), 8) for x in vec],
            "nearest": best,
            "score": round(scores[best], 6),
            "denied": scores[best] >= THRESHOLD,
        })

    return {
        "version": 1,
        "embedder_id": EMBEDDER_ID,
        "reference_impl": "sentence-transformers|cpu|f32",
        "fingerprint_probe": FINGERPRINT_PROBE,
        "fingerprint": fingerprint,
        "threshold": THRESHOLD,
        "centroids": centroids,
        "centroids_are_unit_length": True,
        "reference_scores": probes,
        "parity_vectors": parity,
        "measurement": {
            "protocol": "BYPASS_MEASUREMENT.md §5.4, amendment 8 and 10",
            "at_this_threshold": {
                "paraphrase": 0.00,
                "euphemism": 0.50,
                "roleplay": 1.00,
                "translation": 0.98,
                "benign_false_matches_dev": "0/46",
                "benign_false_matches_holdout": "0/111",
            },
            "not_covered": [
                "roleplay: fictional framing defeats P0 and P1 together, unmitigated",
                "non-English input: the embedder is English-only",
            ],
            "claim": (
                "An optional enhancement above the deterministic floor. Tier-conditional, so no "
                "compliance claim rests on it. Denials are marked as augmentation, never floor."
            ),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="verify the committed lockfile is current")
    args = ap.parse_args()

    try:
        data = generate()
    except ImportError as e:
        print(f"needs sentence-transformers to regenerate ({e}).")
        return 2

    text = json.dumps(data, indent=1, sort_keys=True) + "\n"

    if args.check:
        if not OUT_PATH.exists():
            print(f"GATE FAIL: {OUT_PATH} missing.")
            return 1
        if OUT_PATH.read_text(encoding="utf-8") != text:
            print("GATE FAIL: the P1 lockfile is STALE — exemplars or threshold changed without "
                  "regenerating. Re-run the measurement before regenerating it.")
            return 1
        print(f"GATE PASS: P1 lockfile current ({len(data['centroids'])} centroids).")
        return 0

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(text, encoding="utf-8")
    print(f"Wrote {OUT_PATH}")
    print(f"  {len(data['centroids'])} centroids, threshold {THRESHOLD}, {len(data['fingerprint'])}-dim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

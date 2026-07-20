# Research Ideas — Parking Lot (honestly labeled: not on any product roadmap)

*Exploratory threads triaged out of the build queue. Kept so a curiosity doesn't get re-derived
or mistaken for committed work. 2026-07-19.*

- **Hyperbolic / hierarchy-aware embeddings for ATT&CK.** MITRE ATT&CK's tactic → technique →
  sub-technique tree is a genuine hierarchy, and hyperbolic (negative-curvature) representations embed
  trees with far less distortion than Euclidean space. *Possible* relevance: the cross-family
  generalization problem behind the ~22% L2 recall — a hierarchy-aware space might place unseen
  sub-techniques near their parent technique. BUT this is **custom-embedder research territory** (train
  or fine-tune an encoder in hyperbolic space), a possible future paper, **not** a product item. The
  pull ("resonates with my world") is retail-taxonomy nostalgia, not a PrismPath need. Parked.

- **Gaussian-per-edge / density routing → PROMOTED to an experiment** (not parked). Fit a
  *shrinkage/diagonal* covariance per edge's labeled-outcome collection; route by Mahalanobis
  likelihood instead of cosine; "low likelihood under *every* edge" = native don't-know. See the
  experiment plan / task — this one earns its slot because it converts the escalation margin (a hack)
  into a principled density test using data we already own, and the SAME move principledizes the
  ET-BERT detector's s_bad−s_benign margin (density ratio) and the prefilter gate (inside-the-cluster,
  not near-center). One benchmark on the N=301 suite, publishable either way.

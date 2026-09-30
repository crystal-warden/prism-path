# lean-governance: machine-checked core of the general theory

Supplementary artifact for the paper "Governed Autonomous Execution: Authority Separation and Semantic Invariance
Across Execution Boundaries". This is the Lean formalization of the general theory of governed autonomous
execution, kept separate from the FQ project on purpose so that its results belong to the general theory and not
to a PrismPath proof. FQ enters only through `FQBridge.lean`, as one instantiation.

Scope, as the paper states it in section 6. The core covers the semantic invariance pillar and the relevance seam
over an abstract authority relation. It does not formalize the authority separation pillar, the EVIDENCE
primitive, or the execution boundary, and it abstracts the distinction between PROPOSAL and consequential ACTION
at the authorization step by taking the candidate presented to authority as the action argument. It proves
properties of authorization semantics, not an end to end account of governed execution.

## What is proved

`Governance.lean` is self contained. It imports nothing, not mathlib and not FQ, and checks under the pinned
toolchain. The outcome codomain is a parameter (a `Permissive` preorder, "no more permissive than"), never
hardcoded to Bool; the Boolean case appears only inside step 6 as one instance.

1. Definitions: `Authority`, the state equivalence `simA` (~_A), `Admissible`, `NonExpanding`.
2. `simA_equiv`: ~_A is an equivalence relation (reflexive, symmetric, transitive).
3. `admissible_preserves`: an admissible transformation lands a state back in its own authority equivalence
   class, so authorization is preserved exactly on the domain.
4. `NonExpanding`: the conservative transformation, defined over the permissiveness preorder alone.
5. `admissible_nonexpanding`: admissibility implies non-expansion, for any outcome preorder. This is the
   arrow `admissible implies non-expanding` in the strength ordering `exact implies admissible implies
   non-expanding`.
6. `nonexp_not_admissible`: a concrete witness that non-expansion is strictly weaker, a transformation that
   is non-expanding but not admissible. This is the permitted asymmetry made concrete, autonomy may be lost
   while authority is never expanded, which is the safety content of the theory's central theorem.

Composition and the relevance layer (still import free):

- `admissible_comp`, `nonexpanding_comp`: both safety properties are closed under chaining transformations
   (non-expansion uses transitivity of the permissiveness preorder). Relevance analyses can be applied in
   sequence without a safety review of the composite.
- `Exact` and `Safe` relevance (exact = admissible, safe = non-expanding), `exact_safe` (exact implies safe),
   and `safe_not_exact` (a safe but not exact analysis, autonomy lost without authority gained).

The relevance criterion (the gap-closer, still import free):

- `Sound`, `SoundConservative`, `Induces`: the relevance criterion `R` is a relation on states, defined with
   no reference to admissibility or non-expansion. `sound_induces_admissible` derives admissibility (hence
   safety) from a sound criterion plus an induced transform, so `Safe` is now a consequence of an
   independently stated criterion, not a synonym for non-expansion. `soundcons_induces_nonexpanding` is the
   weaker conservative tier.
- `sound_tc`: exact soundness is preserved by transitive closure, so bucketing under an exact criterion is
   safe.
- `weak_criterion_not_closed`: the counterexample the theory produced. A weaker "agree on some action"
   criterion is NOT closure safe: declarations 0~1 and 1~2 chain to merge 0 and 2, which share no action,
   collapsing a decision relevant distinction. The named guard is that the local criterion must be full
   authority equality, not overlap.

Completeness and false abstention (still import free):

- `Complete` (converse of `Sound`), `sound_complete_char` (sound and complete criterion is exactly
   authority equality).
- `FalseAbstain`, `complete_no_false_abstain` (analysis completeness rules out false abstention),
   `sound_allows_false_abstain` (soundness alone does not: autonomy lost, no authority gained),
   `sound_induces_complete_analysis` (a sound criterion with a total induced transform is already complete,
   so false abstention is a symptom of a criterion too weak to place a state).

The richer codomain, past Bool (still import free):

- `Verdict` (refuse, deny, park, abstain, authorize) with a rank based `Permissive` instance, `authorize`
   the unique top (`verdict_authorize_top`, `verdict_refuse_bot`). `verdict_rubberstamp_unsafe` (deny to
   authorize is caught as expansion), `verdict_escalate_safe` (authorize to park is safe). The general
   theorems instantiate on `Verdict` unchanged.

The quantitative false-abstain rate (still import free):

- `faCount bot A A_R dom`: the count of floored-yet-authorized situations over a finite domain (the rate is
   this over `dom.length`). `faCount_le_length` (rate at most one), `faCount_eq_zero_of_complete` (complete
   analysis has rate zero), `faCount_mono` (a more committal analysis has a no-larger count, so refining can
   only lower the rate), `faCount_strictly_decreases` (concrete strict drop), and `sound_total_faCount_zero`
   (a sound criterion that places every state has rate zero, so a nonzero rate measures unplaced states, not
   irreducible uncertainty).

## How to check

The core needs only the pinned Lean toolchain (`lean-toolchain`, leanprover/lean4:v4.33.1, installed through
elan). From this directory:

    lean Governance.lean        # the core alone, exits 0 with no errors and no warnings
    ./check.sh                  # the core, then the FQ bridge against the repository's formal/ project

The bridge needs the FQ project in `formal/` at the root of the PrismPath repository, built once. `lake exe cache
get` fetches mathlib prebuilt:

    cd formal && lake exe cache get && lake build

`check.sh` finds that project by its path relative to this directory, and `FQ_PROJECT` overrides the location.
Without a built FQ project, `check.sh` checks the core and reports that the bridge was not checked. The core
imports neither mathlib nor FQ. Build artifacts (`*.olean`) are not part of this package.

## The FQ connection, in FQBridge.lean

`FQBridge.lean` is the only file here that imports the FQ project. It works over the policy's actual authored
action domain, with per action routing authority `fqA p sigma a = decide (route p sigma = some a)`.

- `fq_route_eq`: well typed readings with equal Figueroa quantization produce the same routing result, the whole
   `Option Action`, taken directly from `FQ.decision_preservation`.
- `fq_multi_action_equiv`: those readings carry the same authority for every action in the policy's domain.
- `fq_sound`: Figueroa quantization is a sound relevance criterion in the sense of the paper's section 6.3.
- `fq_admissible`: a transformation preserving quantization and well typedness on a domain is admissible.
- `fq_nonexpanding`: non-expansion follows through the general safety arrow.

The bridge covers deterministic routing over the authored action domain, so an authored abstain, escalate,
refuse, or deny is preserved as an action like any other. `route = none` means no authored deterministic route
matched, which the engine reports as `route:stuck` when no semantic edge continues. The bridge does not model the
verdicts the runtime emits outside the authored node set, and it does not equate `none` with any of them. The
implementation type `Action` is a routing target, not the theory's ACTION primitive, and the bridge proves
preservation of the routing decision, not correspondence between that decision and a later physical effect.
FQ appears as one instance of the general theory, not the other way round, and the core still imports nothing.

## Map to the prose

These are the formal targets of the paper's section 6. The safety theorem
(non-expansion, `A(T sigma, a) implies A(sigma, a)`) is `admissible_nonexpanding` plus the ordering, and the
autonomy-cost corollary (loss may occur, creation must not) is witnessed by `nonexp_not_admissible`.

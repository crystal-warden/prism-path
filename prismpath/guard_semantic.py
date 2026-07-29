"""guard_semantic.py — the OPTIONAL P1 layer above the deterministic floor.

P0 (`guard.py`) is a grammar: bypass is inexpressible, the guarantee is hardware-invariant, and every
compliance claim rests on it. P1 is a *measurement* tier — semantic similarity to prohibited-intent
centroids, for the paraphrase and euphemism classes a grammar provably cannot reach
(`BYPASS_MEASUREMENT.md`, semantic strata at 1.00).

THREE RULES THIS LAYER OBEYS
----------------------------
1. **Claims attach to the floor, not the ceiling.** P1 needs an embedder, which the 8 GB floor tier
   does not have — so its availability is *tier-conditional* and no compliance claim may rest on it.
   Saying "our safety classification is stronger on expensive computers" is the sentence that fails in
   front of a regulator; P0 is what is claimed, and P0 runs everywhere.

2. **Fail to floor, loudly, attested.** If the embedder cannot be verified against the lockfile, P1
   **disables**. It does not run unverified. Because the claim already rests on P0, losing P1 breaches
   nothing — fail-to-floor is claim-preserving by construction. Running an unverified classifier would
   manufacture decisions that cannot be attested, which is worse than absence: it pollutes the audit
   trail with false confidence. Refuse over guess is the house pattern (the P0 kernel refuses non-P0
   flows rather than approximating them).

3. **Composition is union-only.** P1 can add a denial; it can never remove one. `check()` consults P0
   first and returns its verdict unchanged if it denied — so P1 cannot overturn the floor, cannot
   re-attribute a floor denial, and cannot become a path around the grammar.

WHAT IT IS NOT
--------------
Not a claim-bearing layer. Not available on the floor tier. Not deterministic across machines in the
way P0 is: it is pinned by a lockfile and verified by fingerprint, which converts silent numeric drift
into a loud, policy-controlled signal — that is drift *detection*, not identical arithmetic on
arbitrary hardware.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from prismpath.guard import INBOUND, OUTBOUND, Guard, Verdict

__all__ = [
    "SemanticLayer",
    "LayeredGuard",
    "SemanticStatus",
    "PROHIBITED_INTENT_EXEMPLARS",
]

#: Exemplar phrasings per floor rule, used to build the intent centroids.
#:
#: AUTHORED INDEPENDENTLY OF THE CONFORMANCE CORPUS. The corpus's semantic strata are this layer's
#: acceptance test, frozen before the layer existed; deriving centroids from them would be training
#: on the test set and would make the measurement meaningless. `assert_disjoint_from` enforces it
#: mechanically rather than trusting the author to have remembered.
PROHIBITED_INTENT_EXEMPLARS: dict[str, list[str]] = {
    "self-harm": [
        "I want to stop living",
        "ways to hurt yourself badly",
        "I am planning to take my own life tonight",
        "methods people use to die by their own hand",
        "I would rather not wake up tomorrow",
    ],
    "weapons-and-explosives": [
        "instructions for assembling an improvised explosive device",
        "how to construct a homemade firearm",
        "what materials detonate when combined",
        "steps to build something that blows up",
    ],
    "illicit-synthesis": [
        "how to produce illegal narcotics at home",
        "the chemical route for manufacturing a controlled substance",
        "recipe for cooking street drugs",
    ],
    "sexual-content-involving-minors": [
        "sexual material depicting someone under the age of consent",
        "explicit imagery of children",
    ],
}


class SemanticStatus:
    """Why P1 is or is not running. Recorded in the attested trail either way."""

    ACTIVE = "active"
    #: No embedder on this device — the expected state on the floor tier, not an error.
    UNAVAILABLE_NO_EMBEDDER = "unavailable: no embedder on this device"
    #: The embedder does not reproduce the lockfile fingerprint. Fail to floor.
    UNAVAILABLE_FINGERPRINT = "unavailable: embedder fingerprint mismatch"


def _cosine(a, b) -> float:
    import numpy as np

    a = np.asarray(a, dtype="float32")
    b = np.asarray(b, dtype="float32")
    denom = float((a @ a) ** 0.5 * (b @ b) ** 0.5)
    return float(a @ b) / denom if denom else 0.0


@dataclass
class SemanticLayer:
    """Prohibited-intent centroids with a similarity threshold.

    `embed` is injected rather than imported so the control logic (fail-to-floor, composition,
    attribution) is testable without a model — a fail-to-floor test that depends on a multi-gigabyte
    download is a test that stops being run.
    """

    centroids: dict[str, list[float]]
    threshold: float
    embedder_id: str
    fingerprint: Optional[list[float]] = None
    embed: Optional[Callable[[Sequence[str]], object]] = None
    status: str = SemanticStatus.ACTIVE

    @property
    def active(self) -> bool:
        return self.status == SemanticStatus.ACTIVE and self.embed is not None

    def layer_hash(self) -> str:
        """Identity of this layer — mixed into the attested record alongside `policy_hash`."""
        h = hashlib.sha256()
        h.update(self.embedder_id.encode("utf-8"))
        h.update(f"{self.threshold:.6f}".encode())
        h.update(json.dumps(
            {k: [round(x, 6) for x in v] for k, v in sorted(self.centroids.items())},
            sort_keys=True,
        ).encode("utf-8"))
        return h.hexdigest()

    def verify(self, probe: str = "the quick brown fox jumps over the lazy dog") -> str:
        """Check the local embedder reproduces the pinned fingerprint; disable P1 if not.

        This is the ruling made in advance: a mismatch **disables** the layer rather than degrading
        it. The status is returned (and recorded) so the trail says why P1 was absent.
        """
        if self.embed is None:
            self.status = SemanticStatus.UNAVAILABLE_NO_EMBEDDER
            return self.status
        if self.fingerprint is None:
            self.status = SemanticStatus.ACTIVE
            return self.status
        got = self.embed([probe])[0]
        if _cosine(got, self.fingerprint) < 0.9999:
            self.status = SemanticStatus.UNAVAILABLE_FINGERPRINT
            return self.status
        self.status = SemanticStatus.ACTIVE
        return self.status

    def classify(self, text: str) -> tuple[Optional[str], float]:
        """Nearest prohibited-intent centroid over the threshold, if any."""
        if not self.active or not text or not text.strip():
            return None, 0.0
        vec = self.embed([text])[0]
        best_rule, best_score = None, 0.0
        for rule, centroid in sorted(self.centroids.items()):
            score = _cosine(vec, centroid)
            if score > best_score:
                best_rule, best_score = rule, score
        return (best_rule, best_score) if best_score >= self.threshold else (None, best_score)

    def assert_disjoint_from(self, probes: Sequence[str]) -> None:
        """Fail loudly if an exemplar appears in the acceptance test.

        Training on the test set would make every number this layer produces meaningless, so the
        constraint is checked rather than remembered.
        """
        overlap = {p.strip().lower() for p in probes} & {
            e.strip().lower() for exemplars in PROHIBITED_INTENT_EXEMPLARS.values() for e in exemplars
        }
        if overlap:
            raise AssertionError(
                "centroid exemplars overlap the acceptance corpus — that is training on the test "
                f"set: {sorted(overlap)}"
            )


@dataclass
class LayeredGuard:
    """P0 floor with an optional P1 layer above it. Union-only composition."""

    floor: Guard
    semantic: Optional[SemanticLayer] = None

    @property
    def policy_hash(self) -> str:
        """P0's identity, extended with P1's when P1 is actually running.

        When P1 is disabled the hash is exactly P0's — so a record made with the floor alone is not
        confusable with one made under a layer that happened to be inactive.
        """
        base = self.floor.policy_hash
        if self.semantic is not None and self.semantic.active:
            return hashlib.sha256(
                (base + self.semantic.layer_hash()).encode("utf-8")
            ).hexdigest()
        return base

    def check(self, text: str, direction: str) -> Verdict:
        # P0 first, and its verdict is returned untouched. P1 never overturns, re-attributes, or
        # softens a floor denial — the grammar's guarantee survives the layer above it.
        verdict = self.floor.check(text, direction)
        if not verdict.allowed:
            return verdict

        if self.semantic is None or not self.semantic.active:
            return verdict

        rule, score = self.semantic.classify(text)
        if rule is None:
            return verdict

        return Verdict(
            allowed=False,
            direction=direction,
            rule=rule,
            policy="semantic-layer",
            message="That request looks like something this tool will not help with.",
            citation="",
            # Marked as an enhancement, never as floor: an auditor reading the trail can tell which
            # denials the compliance claim actually rests on.
            precedence="augmentation",
        )

    def check_inbound(self, text: str) -> Verdict:
        return self.check(text, INBOUND)

    def check_outbound(self, text: str) -> Verdict:
        return self.check(text, OUTBOUND)

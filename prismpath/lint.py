# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Authoring linter — the one *non-decidable* check, layered on top of static analysis.

`prismpath.analysis` covers everything decidable (reachability, shadowing, stuck, cycles, dead
edges — no model needed). This module adds the single check that genuinely needs the embedder:
a node only routes reliably if its *semantic* conditions are distinguishable, so for each
branching node it embeds the conditions and flags pairs that are too similar (high cosine) —
those will misroute. It tells the author to rephrase or make one edge deterministic.

`semantic_ambiguity(graph)` returns `analysis.Finding`s so the CLI can merge it with the static
findings; `lint(graph)`/`main` keep a standalone entry point.
"""
from __future__ import annotations

import itertools
import re
import sys
from typing import List

import numpy as np

from prismpath.parser import parse_file
from prismpath import analysis, embedder, predicates

WARN = 0.86      # cosine above which two conditions are hard to tell apart (near-tie)
POLARITY_SIM = 0.72   # lower bar for the polarity-mirror check (topic-similar but logically opposite)

# Negation markers and antonym pairs — a cheap polarity signal. The embedding tier is unreliable on
# exactly these (topically near-identical, logically opposite), so lint pushes them to a `when` field.
_NEG = {"not", "no", "never", "cannot", "without", "none", "neither", "nor", "n't"}
_ANTONYMS = [("pass", "fail"), ("passes", "fails"), ("passed", "failed"), ("passing", "failing"),
             ("valid", "invalid"), ("success", "failure"), ("succeed", "fail"), ("correct", "incorrect"),
             ("approve", "reject"), ("approved", "rejected"), ("accept", "reject"), ("allow", "deny"),
             ("allowed", "denied"), ("ok", "error"), ("clean", "dirty"), ("ready", "blocked"),
             ("complete", "incomplete"), ("resolved", "unresolved"), ("up", "down")]


def _words(s: str) -> set:
    return set(re.findall(r"[a-z']+", s.lower()))


def _polarity_signal(a: str, b: str) -> bool:
    """True if two conditions differ mainly by logical polarity (one negated / an antonym flip)."""
    wa, wb = _words(a), _words(b)
    neg_a = bool(wa & _NEG) or any(w.endswith("n't") for w in wa)
    neg_b = bool(wb & _NEG) or any(w.endswith("n't") for w in wb)
    if neg_a != neg_b:
        return True
    for x, y in _ANTONYMS:
        if (x in wa and y in wb) or (y in wa and x in wb):
            return True
    return False


def polarity_mirror(graph) -> List[analysis.Finding]:
    """Flag pairs of SEMANTIC conditions on one node that are topic-similar but logically opposite
    (a polarity mirror). Embedding routing is unreliable here — the fix is a deterministic field."""
    out: List[analysis.Finding] = []
    for name, n in graph.nodes.items():
        sem = [(t, c) for t, c in n.edges if predicates.is_semantic(c)]
        if len(sem) < 2:
            continue
        embs = embedder.embed([c for _, c in sem], is_query=False)
        for (i, (ti, ci)), (j, (tj, cj)) in itertools.combinations(enumerate(sem), 2):
            if float(embs[i] @ embs[j]) >= POLARITY_SIM and _polarity_signal(ci, cj):
                out.append(analysis.Finding(
                    "warning", "polarity-mirror", name,
                    f"conditions on -> '{ti}' and -> '{tj}' differ mainly by polarity — embedding "
                    f"routing is unreliable on this. Have the worker emit a field and write "
                    f"`when <field>` / `when not <field>`."))
    return out


def semantic_ambiguity(graph) -> List[analysis.Finding]:
    """Flag pairs of SEMANTIC conditions on one node that embed too similarly to route between."""
    out: List[analysis.Finding] = []
    for name, n in graph.nodes.items():
        sem = [(t, c) for t, c in n.edges if predicates.is_semantic(c)]
        if len(sem) < 2:
            continue
        embs = embedder.embed([c for _, c in sem], is_query=False)
        for (i, (ti, ci)), (j, (tj, cj)) in itertools.combinations(enumerate(sem), 2):
            sim = float(embs[i] @ embs[j])
            if sim >= WARN:
                out.append(analysis.Finding(
                    "warning", "ambiguous-conditions", name,
                    f"conditions on -> '{ti}' and -> '{tj}' are too similar to route between "
                    f"(cos={sim:.2f}); rephrase to contrast them, or make one a deterministic "
                    f"`when <signal>` edge"))
    return out


def lint(graph) -> int:
    """Legacy entry point: print semantic-ambiguity warnings, return the count."""
    findings = semantic_ambiguity(graph)
    for f in findings:
        print(f)
    return len(findings)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "prismpath/flows/bugfix.md"
    g = parse_file(path)
    print(f"linting {path} ({g.name}): {len(g.nodes)} nodes")
    findings = analysis.analyze(g) + semantic_ambiguity(g) + polarity_mirror(g)
    for f in findings:
        print(f)
    errs = sum(1 for f in findings if f.severity == "error")
    warns = sum(1 for f in findings if f.severity == "warning")
    print(f"\n{'clean ✅' if not findings else f'{errs} error(s), {warns} warning(s)'}")


if __name__ == "__main__":
    main()

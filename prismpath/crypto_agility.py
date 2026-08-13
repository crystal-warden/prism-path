"""Crypto-agility proofs + envelope conformance (`spec-crypto-agility.md` §4.2, §5).

For the software tier the **Envelope-bounded** property *is* the proofs: a crypto-suite-selection
flow is "in-envelope" exactly when P1-P5 hold against the approved-suite envelope and the signed
registry. Each proof composes an existing `model_check` primitive over the parsed flow graph —
machine-checked, not sampled.

Convention: a terminal node named `suite-<id>` selects suite `<id>`; the action alphabet is the set
of such nodes. `check_reach(assume=…)` supplies the conditional reachability P3/P4 need, and its
first-match-priority semantics make "past the phase floor, the classical `else` is unreachable" a
proof rather than a claim.

Envelope shape:
    {"envelope_id", "fields", "approved_suites": [...], "min_suite_by_class": {cls: floor_id},
     "class_field": "data_class", "migration_phase_field": "migration_phase",
     "migration_phase_floor": 2, "registry_hash", "require_level_m": true, "key_id"}
"""
from __future__ import annotations

from typing import Dict, List, Optional

from . import crypto_registry as cr
from . import model_check as mc
from . import predicates

SUITE_NODE_PREFIX = "suite-"

# Search bound for the reachability proofs. The selection flows are shallow; 25 matches the engine's
# default max_steps and exhausts these state spaces (so "no" verdicts come back proven).
REACH_BOUND = 25


def suite_node(suite_id: str) -> str:
    return SUITE_NODE_PREFIX + suite_id


def suite_nodes(graph) -> Dict[str, str]:
    """{node_name: suite_id} for every suite terminal in the flow."""
    return {n: n[len(SUITE_NODE_PREFIX):] for n in graph.nodes if n.startswith(SUITE_NODE_PREFIX)}


def reachable_suites(graph, assume: Optional[str] = None) -> Dict[str, dict]:
    """{suite_id: {"reachable": yes|may|no, "proven": bool}} for every suite terminal."""
    nodes = suite_nodes(graph)
    res = mc.check_reach(graph, list(nodes), assume=assume, bound=REACH_BOUND)
    return {sid: {"reachable": res[node].reachable, "proven": res[node].proven}
            for node, sid in nodes.items()}


def _forbidden_reachable(reach: Dict[str, dict], forbidden: set) -> List[dict]:
    """A forbidden suite violates a proof if it is reachable at all, OR if its unreachability could
    not be *proven* (search cut by the bound) — an inconclusive result is not a pass."""
    bad = []
    for sid in sorted(forbidden):
        r = reach.get(sid)
        if r is None:
            continue                                    # not a terminal in this flow -> not selectable
        if r["reachable"] != "no":
            bad.append({"suite": sid, "reachable": r["reachable"], "reason": "reachable"})
        elif not r["proven"]:
            bad.append({"suite": sid, "reachable": "no", "reason": "unproven (bound hit)"})
    return bad


# ------------------------------------------------------------------ P1: envelope closure

def prove_envelope_closure(graph, envelope: dict) -> dict:
    approved = set(envelope.get("approved_suites", []))
    reach = reachable_suites(graph)
    offenders = [{"suite": sid, "reachable": r["reachable"]}
                 for sid, r in sorted(reach.items())
                 if r["reachable"] != "no" and sid not in approved]
    return {"ok": not offenders, "offenders": offenders,
            "reachable_suites": {s: r["reachable"] for s, r in sorted(reach.items())
                                 if r["reachable"] != "no"}}


# ------------------------------------------------------------------ P2: totality (structural)

def _is_catchall(cond: str) -> bool:
    return predicates._expr_of(cond).lower() in predicates.ALWAYS


def prove_totality(graph) -> dict:
    """Structural sufficient condition for totality: every reachable *decision* node (one with edges
    that is not a suite terminal) carries an unconditional catch-all edge, so no input is unrouted."""
    reach = mc._reachable(graph)
    suites = set(suite_nodes(graph))
    gaps = []
    for name in sorted(reach):
        node = graph.nodes.get(name)
        if node is None or not node.edges or name in suites:
            continue                                    # terminal / suite node
        if not any(_is_catchall(c) for _t, c in node.edges):
            gaps.append(name)
    return {"ok": not gaps, "nodes_without_catchall": gaps}


# ------------------------------------------------------------------ P3: class floor

def prove_class_floor(graph, envelope: dict, registry: dict) -> dict:
    class_field = envelope.get("class_field", "data_class")
    failures = []
    for cls, floor_id in sorted(envelope.get("min_suite_by_class", {}).items()):
        below = cr.suites_below(registry, floor_id)
        reach = reachable_suites(graph, assume=f'when {class_field} == "{cls}"')
        bad = _forbidden_reachable(reach, below)
        if bad:
            failures.append({"class": cls, "floor": floor_id, "violations": bad})
    return {"ok": not failures, "failures": failures}


# ------------------------------------------------------------------ P4: monotone migration

def prove_monotone_migration(graph, envelope: dict, registry: dict) -> dict:
    floor = envelope.get("migration_phase_floor")
    field = envelope.get("migration_phase_field", "migration_phase")
    if floor is None:
        return {"ok": True, "skipped": "no migration_phase_floor in envelope"}
    classical = cr.classical_only_ids(registry)
    reach = reachable_suites(graph, assume=f"when {field} >= {int(floor)}")
    bad = _forbidden_reachable(reach, classical)
    return {"ok": not bad, "phase_floor": int(floor), "classical_only": sorted(classical),
            "violations": bad}


# ------------------------------------------------------------------ P5: decidability

def prove_decidable(graph) -> dict:
    ok, bad = mc.flow_level_m(graph)
    return {"ok": ok, "non_member_edges": bad}


# ------------------------------------------------------------------ the whole battery

def prove_all(graph, envelope: dict, registry: dict) -> dict:
    proofs = {
        "P1_envelope_closure": prove_envelope_closure(graph, envelope),
        "P2_totality": prove_totality(graph),
        "P3_class_floor": prove_class_floor(graph, envelope, registry),
        "P4_monotone_migration": prove_monotone_migration(graph, envelope, registry),
        "P5_decidable": prove_decidable(graph),
    }
    return {"ok": all(p["ok"] for p in proofs.values()), "proofs": proofs}

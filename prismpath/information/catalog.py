# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The evidence fields the information points declare, and which point declares each.

A policy that reads an evidence field must be built with the point that supplies it (`policy.points` of a manifest,
`--point` of `prismpath policy compile`), or the compile refuses it with the line of the field. The classifier's own
fields (prismpath/agent/fields.py) are not here, and no starter image declares one of these. The agent kind's reading
domain is the classifier's fields plus the fields of the points named (`prismpath.agent.profile.agent_domain`).

Each point's fields, their closed value lists and their restrictive values are class attributes of the point, so this
catalog reads them without building one. A restrictive value is the value a field reads when its point cannot
answer, and it is the value that makes a rule that allows on the field the least likely to hold.
This module imports no other prismpath package but the classes it lists.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, NamedTuple, Tuple

from prismpath.information.contextcloud import ContextCloudZones
from prismpath.information.parsefacts import ParseFacts
from prismpath.information.projecttests import ProjectTests
from prismpath.information.protectedfacts import ProtectedFacts

POINTS: Mapping[str, Any] = {cls.name: cls for cls in (ParseFacts, ProjectTests, ProtectedFacts, ContextCloudZones)}


class EvidenceField(NamedTuple):
    name: str
    point: str
    kind: str                       # "bool", "int" or "category"
    values: Tuple[Any, ...]
    restrictive: Any
    no_evidence: Tuple[Any, ...] = ()    # values that say the point gave no evidence (`not_run`), never better than restrictive


def _kind(values: Tuple[Any, ...]) -> str:
    if all(isinstance(v, bool) for v in values):
        return "bool"
    return "int" if all(isinstance(v, int) and not isinstance(v, bool) for v in values) else "category"


def declaration(have: "EvidenceField") -> str:
    """How a rules source declares the field: `bool`, `category`, or `int min=LOW max=HIGH` over the point's range."""
    return f"int min={min(have.values)} max={max(have.values)}" if have.kind == "int" else have.kind


def evidence_fields() -> Dict[str, EvidenceField]:
    """Every evidence field by name, which is every field a point declares except the ones the agent's classifier
    already has (`classifier_fields`: `zone_reach`, which the Context Cloud point also supplies). Two points never
    declare one name (a test holds that)."""
    found: Dict[str, EvidenceField] = {}
    for point_name, cls in POINTS.items():
        own = tuple(getattr(cls, "classifier_fields", ()))
        for field, values in cls.fields.items():
            if field in own:
                continue
            found[field] = EvidenceField(field, point_name, _kind(tuple(values)), tuple(values), cls.restrictive[field],
                                         tuple(getattr(cls, "no_evidence", {}).get(field, ())))
    return found


def fields_of(point_names: Iterable[str]) -> Dict[str, EvidenceField]:
    """The evidence fields of the named points. ValueError for a name that is no point."""
    names = list(point_names)
    unknown = [n for n in names if n not in POINTS]
    if unknown:
        raise ValueError(f"no information point is called {unknown[0]} (the points are {', '.join(sorted(POINTS))})")
    return {name: f for name, f in evidence_fields().items() if f.point in names}

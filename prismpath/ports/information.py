# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The information point port: evidence about a change, from a source the policy does not trust to decide.

A point supplies reading fields, never a verdict, a cause or a rule. A point that cannot answer reads each of its
fields at the value it lists in `restrictive`. This module imports nothing from prismpath.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, FrozenSet, Mapping, Optional, Protocol, Tuple, Union, runtime_checkable


@dataclass(frozen=True)
class Edit:
    """The text of a file edit: `relative` is the file's path under the project, `old` its text now, `new` its text
    with the edit applied."""
    relative: str
    old: str
    new: str


@dataclass(frozen=True)
class Change:
    """What a point is asked about: one path a call changes, and the configuration it is read against. `edit` is the
    file's text before and after, for the points that read it; None when the edit could not be applied."""
    raw_path: str
    config: Any
    edit: Optional[Edit] = None


@dataclass(frozen=True)
class Evidence:
    readings: Mapping[str, Union[str, bool, int]]   # reading fields only, for example zone_reach
    names: FrozenSet[str]                           # protected names reached, for zone_name
    why: str                                        # empty when the point answered
    stats: Mapping[str, Any]


@runtime_checkable
class InformationPoint(Protocol):
    name: str                                       # for example "contextcloud"
    fields: Mapping[str, Tuple[str, ...]]           # each field it may supply and its closed value list
    restrictive: Mapping[str, Any]                  # the value each field reads when the point cannot answer
    control_paths: Tuple[str, ...]

    def facts(self, change: Change, budget_s: float) -> Evidence: ...

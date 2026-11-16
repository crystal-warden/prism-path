# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The cause decoder: any cause code or name Mission Control shows, rendered from the registry.

A cause reaches the console from evidence, which is untrusted input: a receipt's `cause` member, a refusal
a verifier returned, a name a page asks about. Every one is rendered here from `prismpath.kernel.causes`
with its class and description, never from a string in the page, so a screen cannot name a cause the
registry does not hold or hold it under another class. A value that is not a registered code or name
renders as unregistered with no code, whatever it is, and 0 is the clean decision, outside the registry's
refusal bands, as `prismpath trail` labels it.
"""
from __future__ import annotations

from typing import Any, Dict

from prismpath.kernel import causes


def render(value: Any) -> Dict[str, Any]:
    """`value` (a code, a canonical name, None for a receipt that records none) as {code, name, class,
    description, registered, clean, label}. Never raises."""
    unregistered = {"code": None, "name": None, "class": None, "description": None, "registered": False,
                    "clean": False}
    if value is None:
        return {**unregistered, "label": "unrecorded"}
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return {**unregistered, "label": "unregistered"}
    if isinstance(value, str):
        code = causes.code(value)
        if code is None:
            return {**unregistered, "label": "unregistered"}
    else:
        code = value
    if code == causes.CAUSE_NONE:
        return {"code": 0, "name": None, "class": None, "description": "the clean decision", "registered": False,
                "clean": True, "label": "0 clean"}
    entry = causes.CODES.get(code)
    if entry is None:
        return {**unregistered, "code": code, "label": f"{code} unregistered"}
    name, class_name, description = entry
    return {"code": code, "name": name, "class": class_name, "description": description, "registered": True,
            "clean": False, "label": f"{code} {name}"}


def registry() -> Dict[str, Any]:
    """The whole registry in code order, with the hash the frozen value test pins, for a page that keeps
    its own copy and checks it against this one."""
    return {"sha256": causes.registry_sha256(), "causes": [render(code) for code in sorted(causes.CODES)]}

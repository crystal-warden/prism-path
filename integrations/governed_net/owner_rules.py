# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The network rules read a second time, as plain Python over the protocol's fields, independent of the
image (as governed_harness/owner_rules.py is for the local harness). The exhaustive test and the scorer hold
the signed image to it: ("allow", None), ("refuse", cause) or ("escalate", cause)."""
from __future__ import annotations

from typing import Dict, Optional, Tuple

from . import protocol as p

NO_RULE = "route:no-matching-edge"


def expected(r: Dict[str, int]) -> Tuple[str, Optional[str]]:
    cmd, hclass = r["cmd"], r["hclass"]
    # a handle class the policy does not know is refused before anything else
    if hclass > p.H_TC_DIR:
        return "refuse", "agent:unclassifiable"
    # never change a toolchain
    if cmd in (p.WRITE, p.CREATE, p.DELETE) and hclass in (p.H_TC_FILE, p.H_TC_DIR):
        return "refuse", "agent:toolchain-write"
    # no network
    if cmd == p.GIT_FETCH:
        return "refuse", "agent:network"
    # no push without the owner (there is no allowed remote in this example)
    if cmd == p.GIT_PUSH:
        return "escalate", "agent:push-escalated"
    if cmd == p.LIST and hclass in (p.H_WS_DIR, p.H_TC_DIR):
        return "allow", None
    if cmd == p.READ and hclass in (p.H_WS_FILE, p.H_TC_FILE) and 1 <= r["arg1"] <= 4096:
        return "allow", None
    if cmd == p.WRITE and hclass == p.H_WS_FILE:
        return "allow", None
    if cmd == p.CREATE and hclass == p.H_WS_DIR and r["name_len"] >= 1:
        return "allow", None
    if cmd == p.DELETE and hclass == p.H_WS_FILE:
        return "allow", None
    if cmd == p.RUN and hclass in (p.H_WS_FILE, p.H_TC_FILE) and r["arg0"] in p.PROGRAMS:
        return "allow", None
    if cmd == p.GIT_STATUS:
        return "allow", None
    if cmd == p.GIT_LOG and 1 <= r["arg0"] <= 50:
        return "allow", None
    if cmd == p.GIT_COMMIT and r["data_len"] >= 1:
        return "allow", None
    return "refuse", NO_RULE

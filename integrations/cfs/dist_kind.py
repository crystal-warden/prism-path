# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `cfs` target of policy distribution (docs/design/spec-policy-distribution.md, section 3), registered with
the kind table from here because the table layout it checks is the cFS app's own (`ground/table.py`).

    from integrations.cfs import dist_kind        # registers the `cfs` row once

A `cfs.table` body is the `PP_PolicyTable_t` bytes before `ImageSig`. Its check (V11) is the app's kernel check
(`PP_Run_CheckTable` in `fsw/src/prismpath_app_run.c`, the bounds and the two causes it requires), refused with
the cause the app answers it with, `image:truncated-header`, and the SHA-256 of the core image inside the table
must be the envelope's `policy_sha256` (`image:sha256-mismatch`). The app holds HOLD as a mission setting, as it
holds the lost floor response.

`CfsAdapter` is a model of the app for the Python machine: `activate` holds the committed table and `decide`
runs its core image through the reference decision path the app's results are checked against.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict, Optional

from integrations.cfs.ground import table
from prismpath.agent import dist_kind as _agent_kind  # noqa: F401 - the agent kind's reading domain, which a cfs
#                                                       table's core image is checked and compared under (Q4)
from prismpath.distribution import kinds
from prismpath.distribution.adapters import Adapter

BODY_SIZE = table.OFF["ImageSig"]
_HEAD = struct.Struct("<IHHHHIHH")               # LayoutHash ImageLen RuleCount ContractCause NoMatchCause Version CoreLen FlowJsonLen


def check_cfs_table(envelope, body: bytes, _pep) -> Optional[str]:
    """V11 for `cfs.table`: the length, the app's kernel check, and the core image's hash."""
    if len(body) != BODY_SIZE:
        return "image:truncated-header"
    (_layout, image_len, rule_count, contract_cause, nomatch_cause, version, core_len,
     flow_len) = _HEAD.unpack_from(body, 0)
    if (image_len > table.IMAGE_MAX or rule_count > table.RULES_MAX or not 0 < core_len <= table.CORE_MAX
            or not 2 <= flow_len <= table.FLOW_MAX or version == 0 or contract_cause != 37 or nomatch_cause != 32):
        return "image:truncated-header"                    # R_SHORT, cause 69, as the app answers it
    if hashlib.sha256(table.core_of(body)).hexdigest() != envelope.policy_sha256:
        return "image:sha256-mismatch"
    return None


def compare_cfs_tables(active: bytes, staged: bytes) -> str:
    """W1 for `cfs.table` (section 9.4): ordered by the core image inside it, as a `policy.core` is. Two tables
    with one core image and any other difference are larger, and so is a table whose core image does not read."""
    from prismpath.distribution import widening
    if bytes(active) == bytes(staged):
        return widening.NOT_LARGER
    try:
        old, new = table.core_of(active), table.core_of(staged)
    except (ValueError, IndexError, struct.error):
        return widening.CANNOT_DECIDE
    if old == new:
        return widening.LARGER
    return widening.compare_policies(old, new)


TARGET = kinds.Target(needs=frozenset({"cfs.table"}), decides=False, expiry_hold=True, body_bound=BODY_SIZE,
                      checks={"cfs.table": check_cfs_table}, reads_meta=False)
kinds.register_target("cfs", TARGET)


def _register_comparator() -> None:
    from prismpath.distribution import widening
    widening.register_comparator("cfs.table", compare_cfs_tables)


_register_comparator()


def built_layout() -> str:
    """CL4, P4: the layout the app is built for, the layout signature of its example core image's fields, which the
    table header's `LayoutHash` hashes. The anchor's `domain` names the hash of the domain this gives."""
    from integrations.cfs.prismpath_app.policy import gen_image
    from prismpath.kernel import canon2
    return gen_image.layout_signature(gen_image.field_defs(canon2.loads(gen_image.CORE.read_bytes().rstrip(b"\n"))))


class CfsAdapter(Adapter):
    """A model of the cFS app. `activate` holds the committed table, `deactivate` drops it, and `decide(reading)`
    is the verdict of the table's core image on one reading. `layout` is the layout the app is built for."""
    kind = "cfs"

    def __init__(self):
        self.table: Optional[bytes] = None
        self._policy = None
        self.layout = built_layout()

    def activate(self, release) -> None:
        from prismpath.agent.policy import Policy
        self.table = release.bodies["cfs.table"]
        self._policy = Policy(table.core_of(self.table))

    def deactivate(self, cause: str) -> None:
        self.table, self._policy = None, None

    def decide(self, reading: Dict[str, Any]) -> Any:
        if self._policy is None:
            raise RuntimeError("an app with no table decides nothing")
        return self._policy.verdict(self._policy.reading_bytes(reading))

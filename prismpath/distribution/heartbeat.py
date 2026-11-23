# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Facet body of a state record (spec-policy-distribution.md, H5) and the controller's check of it (H6
steps 4 and 5).

The body is a grouped spiral stream of PROTOCOL.md section 2.6.1 at the band tier, built with
`prismpath.telemetry.spiral_groups.GroupedFacet` from the canonical flow text of the active policy
(`core_render.render` of the `policy.core` image, which `prismpath.agent.policy.Policy` holds). Its frames
are the decisions the PEP made since its previous record, at most 64, the oldest dropped first, and fewer
when 64 would not fit the record's 1,024 bytes. Its 42 byte preamble carries the policy's hash and layout
hash, so a controller finds a PEP on another policy by comparing hashes, never by a decode that happens to
fail.

Only a release with a `policy.core` has flow text to build the stream from, so a PEP whose active release
has none (`host`, `mesh` and `cfs` in this version) sends a body of length 0.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional, Sequence

from prismpath.distribution import state_record

MAX_FRAMES = 64                                    # H5
POLICY_MISMATCH, CODEBOOK_MISMATCH = "fleet:policy-mismatch", "wire:codebook-mismatch"
_FACETS: Dict[str, Any] = {}


def facet(image: bytes):
    """The grouped Facet codec of the `policy.core` image `image`, made once per image."""
    key = hashlib.sha256(bytes(image)).hexdigest()
    codec = _FACETS.get(key)
    if codec is None:
        from prismpath.agent.policy import Policy
        from prismpath.telemetry.spiral_groups import GroupedFacet
        policy = Policy(bytes(image))
        codec = _FACETS[key] = GroupedFacet(policy.graph, policy.flow)
    return codec


def body(image: Optional[bytes], readings: Sequence[Dict[str, Any]]) -> bytes:
    """H5: the band tier stream of the last `MAX_FRAMES` of `readings` under the policy `image`, dropping the
    oldest until it fits a record. Empty when there is no `policy.core` to build it from."""
    if image is None:
        return b""
    from prismpath.telemetry.spiral_groups import TIER_BAND
    codec = facet(image)
    kept = list(readings)[-MAX_FRAMES:]
    while True:
        stream = codec.encode(kept, TIER_BAND)
        if len(stream) <= state_record.MAX_BODY or not kept:
            return stream
        kept = kept[1:]


def check(image: Optional[bytes], data: bytes) -> Optional[str]:
    """H6 steps 4 and 5 for a record whose header named the expected policy: the body's preamble carries the
    policy hash and layout hash the controller computes from that policy (`fleet:policy-mismatch`), and the body
    decodes under it (`wire:codebook-mismatch`). None for an empty body or one that decodes."""
    from prismpath.telemetry.spiral_groups import MAGIC, StreamMismatch
    if not data:
        return None
    if image is None:
        return POLICY_MISMATCH                         # a body where the expected release has no flow text
    codec = facet(image)
    if len(data) >= 38 and data[:4] == MAGIC and (data[6:22] != codec.policy_hash or data[22:38] != codec.layout_hash):
        return POLICY_MISMATCH                         # step 4, from the hashes and before any decode
    try:
        codec.decode(bytes(data))
    except StreamMismatch:
        return CODEBOOK_MISMATCH                       # step 5
    return None


def decode(image: bytes, data: bytes):
    """The route of every decision node of every decision in a body that `check` passed."""
    return facet(image).decode(bytes(data)) if data else []

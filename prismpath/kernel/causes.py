# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""causes.py — the refusal/deviation cause code registry (docs/design/spec-cause-codes.md).

One byte answers "WHY did the system refuse, park, or escalate": every runtime refusal site in
the stack gets a stable numeric code and keeps its existing emitted string as the canonical
name (this registry describes reality; it renames nothing). Identical surface refusals with
different structural causes are different situations — the code is what makes that machine
readable, on the receipt and eventually on the wire.

The registry is APPEND ONLY: codes are never renumbered or reused, names never change once
shipped (the frozen-value test pins every pair). Bands group codes by cause class for human
legibility; the class, not the band arithmetic, is the semantic axis. This module is pure
data + lookups — no behavior anywhere else changes by importing it.
"""
from __future__ import annotations

import hashlib
from typing import Dict, Optional, Tuple

CAUSE_NONE = 0

# (code, canonical name, class, description)
# Classes: authority | envelope | routing | wire | state
_REGISTRY: Tuple[Tuple[int, str, str, str], ...] = (
    # -- authority: the signature chain and the signed manifest (verify_pack, loader) --------
    (1,  "sig:missing",                  "authority", "pack carries no signature"),
    (2,  "sig:invalid",                  "authority", "signature fails verification"),
    (3,  "sig:revoked-key",              "authority", "signing key is revoked"),
    (4,  "manifest:key-id-mismatch",     "authority", "manifest names a different key"),
    (5,  "manifest:bad-format",          "authority", "manifest unparseable"),
    (6,  "image:sha256-mismatch",        "authority", "image hash differs from the signed manifest"),
    (7,  "manifest:count-mismatch",      "authority", "table counts differ from the signed manifest"),
    (8,  "manifest:wcet-mismatch",       "authority", "recomputed WCET differs from the signed bound"),
    (9,  "image:version-replay",         "authority", "older signed version replayed at the loader"),
    (10, "image:unsigned-refused",       "authority", "unsigned image without the explicit override"),
    # -- envelope: admission caps and profile artifacts (load time) --------------------------
    (16, "image:caps-exceeded",          "envelope",  "image exceeds a MAX_* capacity bound"),
    (17, "packing:unknown-profile",      "envelope",  "manifest declares an unknown packing profile"),
    (18, "spiral:sidecar-missing",       "envelope",  "declared spiral sidecar absent from the pack"),
    (19, "spiral:sidecar-hash-mismatch", "envelope",  "spiral sidecar differs from the signed hash"),
    # -- routing: the decision itself (engine, router, interpreter) --------------------------
    (32, "route:no-matching-edge",       "routing",   "no deterministic edge matched (hold for stateful, refuse for admission)"),
    (33, "route:below-human-floor",      "routing",   "semantic confidence below the calibrated floor"),
    (34, "route:needs-human",            "routing",   "worker explicitly requested a human"),
    (35, "route:max-steps",              "routing",   "walk exhausted the signed step bound"),
    (36, "route:stuck",                  "routing",   "non-terminal node with no viable edge"),
    (37, "route:contract-violation",     "routing",   "worker output violated the declared contract"),
    # -- wire: Facet strict decode and stream admission (decode plane, replay, concentrator) --
    (48, "wire:no-terminator",           "wire",      "frame carries no complete codeword"),
    (49, "wire:dangling-codeword",       "wire",      "trailing partial codeword with data bits"),
    (50, "wire:symbol-overflow",         "wire",      "wire integer beyond the cell range"),
    (51, "wire:codebook-mismatch",       "wire",      "stream not decodable under the bound policy (I3)"),
    (52, "replay-duplicate",             "wire",      "tick already seen inside the window"),
    (53, "replay-stale",                 "wire",      "tick beyond the replay window"),
    (54, "concentrator-unknown-stream",  "wire",      "concentrated record names an unregistered stream"),
    (55, "concentrator-truncated",       "wire",      "concentrated record cut mid-reading"),
    (56, "wire:chain-broken",            "wire",      "reading's previous hash does not match the record before it (splice, not loss)"),
    # -- state: resident-state transitions that are not ordinary matches ---------------------
    (64, "state:stale",                  "state",     "refresh bound exceeded; parked on the signed fail-safe"),
    (65, "state:recovered",              "state",     "fresh state restored after a stale episode"),
    (66, "state:migration-reset",        "state",     "reset-to migration parked the resident state"),
    (67, "state:swap-in-flight-park",    "state",     "evaluate during swap parked on the fail-safe"),
)

CODES: Dict[int, Tuple[str, str, str]] = {c: (n, k, d) for c, n, k, d in _REGISTRY}
NAMES: Dict[str, int] = {n: c for c, n, _k, _d in _REGISTRY}

# The engine's stop vocabulary (engine.py `stopped`), mapped onto the registry. 'terminal'
# and 'waiting' are clean outcomes and deliberately have no cause code.
ENGINE_STOP_TO_CAUSE: Dict[str, int] = {
    "stuck": NAMES["route:stuck"],
    "needs_human": NAMES["route:needs-human"],
    "max_steps": NAMES["route:max-steps"],
    "contract_violation": NAMES["route:contract-violation"],
}


def name(code: int) -> Optional[str]:
    entry = CODES.get(code)
    return entry[0] if entry else None


def code(cause_name: str) -> Optional[int]:
    return NAMES.get(cause_name)


def cause_class(code_or_name) -> Optional[str]:
    c = NAMES.get(code_or_name) if isinstance(code_or_name, str) else code_or_name
    entry = CODES.get(c) if c is not None else None
    return entry[1] if entry else None


def registry_sha256() -> str:
    """A stable hash over (code, name, class) triples — the frozen-value anchor the tests pin.
    Descriptions may be edited for clarity; codes, names, and classes may not."""
    blob = "\n".join(f"{c}|{n}|{k}" for c, n, k, _d in _REGISTRY).encode()
    return hashlib.sha256(blob).hexdigest()

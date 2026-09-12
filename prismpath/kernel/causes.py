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
    (68, "state:normal-unheld",          "state",     "the reading names a shared normal this side does not hold: abstain, the state the policy needs is absent"),
    # -- envelope, continued: the pack verifier's structural refusals (policy_pack's
    # read_ppt_header, validate_image, load_envelope, check_envelope). These sit past the state
    # band because the registry is append only and the class, not the band arithmetic, is the
    # semantic axis. Parameterized emitters append a ":<detail>" suffix to the name below.
    (69, "image:truncated-header",       "envelope",  "image shorter than the fixed header"),
    (70, "image:bad-magic",              "envelope",  "image does not open with the .ppt magic word"),
    (71, "image:bad-version",            "envelope",  "image declares an unsupported format version"),
    (72, "image:safe-node-oob",          "envelope",  "signed fail-safe names a node index the image does not have"),
    (73, "image:length-mismatch",        "envelope",  "image length differs from the sum of its declared sections"),
    (74, "image:unknown-op",             "envelope",  "atom carries an operator outside the Level M fragment"),
    (75, "image:unknown-type",           "envelope",  "atom carries a value type outside the Level M fragment"),
    (76, "image:field-index-oob",        "envelope",  "atom names a field index beyond the declared field count"),
    (77, "image:edge-target-oob",        "envelope",  "edge targets a node index beyond the declared node count"),
    (78, "image:edge-prog-oob",          "envelope",  "edge program range runs past the declared program words"),
    (79, "image:unknown-opcode",         "envelope",  "program word is an opcode outside the boolean set"),
    (80, "image:atom-index-oob",         "envelope",  "program word names an atom index beyond the declared atom count"),
    (81, "image:node-attr-oob",          "envelope",  "per node attribute exceeds the materialization envelope"),
    (82, "envelope:missing",             "envelope",  "the declared envelope artifact is absent"),
    (83, "envelope:sig-invalid",         "envelope",  "envelope signature verifies under none of the offered keys"),
    (84, "envelope:id-mismatch",         "envelope",  "manifest targets a different envelope"),
    (85, "envelope:unknown-field",       "envelope",  "manifest declares a field the envelope does not admit"),
    (86, "envelope:field-kind-mismatch", "envelope",  "manifest field kind differs from the envelope's"),
)

CODES: Dict[int, Tuple[str, str, str]] = {cause_code: (canonical_name, class_name, description)
                                          for cause_code, canonical_name, class_name, description in _REGISTRY}
NAMES: Dict[str, int] = {canonical_name: cause_code for cause_code, canonical_name, _k, _d in _REGISTRY}

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
    cause_code = NAMES.get(code_or_name) if isinstance(code_or_name, str) else code_or_name
    entry = CODES.get(cause_code) if cause_code is not None else None
    return entry[1] if entry else None


def registry_sha256() -> str:
    """A stable hash over (code, name, class) triples — the frozen-value anchor the tests pin.
    Descriptions may be edited for clarity; codes, names, and classes may not."""
    blob = "\n".join(f"{cause_code}|{canonical_name}|{class_name}"
                     for cause_code, canonical_name, class_name, _d in _REGISTRY).encode()
    return hashlib.sha256(blob).hexdigest()

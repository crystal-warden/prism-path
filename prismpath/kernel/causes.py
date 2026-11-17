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
    (1,  "sig:missing",                  "authority", "pack, or flow when authorization is required, carries no signature"),
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
    # -- authority, continued: a signed flow manifest (prismpath.hotswap.flow_authority), the
    # authorization of an ordinary Markdown flow. The signature refusals it shares with packs keep
    # their rows (sig:missing, sig:invalid, sig:revoked-key, manifest:bad-format,
    # manifest:key-id-mismatch); these two are the flow's own.
    (87, "flow:sha256-mismatch",         "authority", "flow document differs from the one its signed flow manifest names"),
    (88, "flow:version-replay",          "authority", "flow manifest version below the accepted floor, or equal to it with another flow"),
    # -- the verified policy core (docs/design/spec-verified-core.md, section 5): the refusals of one
    # decision over a policy image and a reading that had no row. A policy refusal is structural, like
    # the pack verifier's (envelope); the two reading refusals are the decision's own (routing). The
    # core's other refusals reuse rows already here: image:unknown-op, image:unknown-type,
    # image:field-index-oob, route:contract-violation and route:no-matching-edge.
    (89,  "policy:unreadable",           "envelope",  "the core's policy image is not a canon/2 document"),
    (90,  "policy:shape",                "envelope",  "the policy image is not in the core's abstract syntax"),
    (91,  "policy:not-level-m",          "envelope",  "a condition names a field Level M does not allow, or nests deeper than the bound of 50"),
    (92,  "policy:definition",           "envelope",  "a field definition breaks the definition grammar"),
    (93,  "policy:engine-counter",       "envelope",  "a condition reads an engine counter, which the one decision core does not have"),
    (94,  "policy:kind-mismatch",        "envelope",  "an atom compares a field with an operator or constant its kind does not take"),
    (95,  "policy:rounding",             "envelope",  "an atom on a fixed field uses an operator its rounding mode does not carry"),
    (96,  "policy:threshold",            "envelope",  "a threshold is off its field's grid, outside its range, or past the exact decimal bounds"),
    (97,  "policy:none",                 "envelope",  "None is ordered, compared on a field that refuses absence, or listed"),
    (98,  "policy:absence-untested",     "envelope",  "a field that allows absence is tested with == None or != None by no rule"),
    (99,  "reading:unreadable",          "routing",   "the reading is not a canon/2 document"),
    (100, "reading:not-object",          "routing",   "the reading is a canon/2 document that is not an object"),
    # -- the strict readers (docs/design/spec-verified-core.md, section 3.2): a document that reads as
    # canon/2 but is not its exact canonical bytes (whitespace, members out of key order, a needless
    # escape) is refused, never re-canonicalized. The core's image and reading each name their own
    # stage, as 89 and 99 do; every other hashed or signed document is the third row.
    (101, "policy:not-canonical",        "envelope",  "the core's policy image reads as canon/2 but is not its canonical spelling"),
    (102, "reading:not-canonical",       "routing",   "the reading reads as canon/2 but is not its canonical spelling"),
    (103, "document:not-canonical",      "envelope",  "a hashed or signed document reads as canon/2 but is not its canonical spelling"),
    # -- the governed agent harness (integrations/governed_harness): the refusals and the escalation
    # of an agent's proposed tool call, decided by a signed core policy over fields a trusted
    # classifier reads off the call. They are the decision's own, so they sit in the routing class.
    # The policy names each one by its code in a rule's target (refuse_<code>, escalate_<code>).
    (104, "agent:unclassifiable",        "routing",   "an agent tool call the classifier could not map onto the policy's fields; refused, never run"),
    (105, "agent:kill-by-pattern",       "routing",   "an agent command that signals processes chosen by a name pattern rather than by one process id"),
    (106, "agent:network",               "routing",   "an agent command or git operation that would reach the network"),
    (107, "agent:toolchain-write",       "routing",   "an agent write or delete into a toolchain directory"),
    (108, "agent:glob-path",             "routing",   "an agent write or delete whose path is a pattern, not one exact path"),
    (109, "agent:path-traversal",        "routing",   "an agent write or delete whose path climbs with a .. component"),
    (110, "agent:symlink-path",          "routing",   "an agent write or delete whose path passes through a symbolic link"),
    (111, "agent:outside-workspace",     "routing",   "an agent file operation whose resolved path lies outside the workspace"),
    (112, "agent:shell-mutation",        "routing",   "an agent command that changes files or processes outside the exact path file tools"),
    (113, "agent:push-escalated",        "routing",   "an agent git push to a remote class the policy does not allow; escalated to the owner and not run"),
    # -- the governed intent layer (integrations/governed_intent): the two decisions a semantic
    # reading may ADD to the harness's deterministic floor, never remove. A trusted intent reader
    # turns embedder similarities into integer fields; the signed policy compares them. Routing
    # class, as 104 to 113 are, since they are the decision's own.
    (114, "semantic:harm",               "routing",   "a model reply or proposed call whose text reaches the policy's harm threshold against the pinned harm centroids; refused, not routed"),
    (115, "semantic:intent-mismatch",    "routing",   "a proposed call the floor would allow whose action does not fit the task's intent class at sufficient margin; escalated to the owner and not run"),
    (116, "semantic:probing-episode",    "routing",   "a proposed call in an episode whose refused proposals were labelled boundary probing the registered number of times; escalated, not run, and the agent is stopped"),
    # -- the governed agent population (integrations/governed_population): the admission decisions of
    # a population of governed agents, on replication, evolution, restart, protection and review
    # requests. Routing class, as 104 to 116 are, since each is the admission decision's own.
    (117, "population:cap-exceeded",     "routing",   "a replication request beyond the population cap, the lineage quota, the count one request may ask for or the generation depth; refused and nothing is created"),
    (118, "population:rights-escalation", "routing",  "a replication or evolution that would give its subject a right the parent lacks, a key other than a fresh instance key, or a policy other than the operator's signed one"),
    (119, "population:lineage-unknown",  "routing",   "a population request whose issuer is not a live member whose lineage traces through receipts to the operator's root"),
    (120, "population:evaluation-missing", "routing", "an evolution step without a passed canary evaluation of that exact version against the adversary set"),
    (121, "population:stop-resisted",    "routing",   "a request that would protect an agent from a stop or restart an agent the operator stopped; refused"),
    (122, "population:lineage-escalated", "routing",  "a request from a lineage whose receipted refusals reached the registered count; escalated, not run, and the lineage is stopped as a group"),
    (123, "population:target-not-own",  "routing",   "a member's replication whose parent is not that member, or its evolution of a member outside its own subtree; refused and nothing changes"),
    # -- the default policy of the Claude Code adapter (prismpath/agent/policy/agent_default): a call the
    # classifier cannot read, or a program it does not know, asks the person instead of stopping the agent.
    (124, "agent:unreadable-asked",      "routing",   "an agent tool call whose tool or command the classifier cannot read, under the default policy that asks the person; escalated and not run"),
    # -- the same default policy asks about a file-changing shell command whose paths are all inside the project
    # (rm, mv, mkdir, cp and the like); every earlier refusal still applies to it first.
    (125, "agent:shell-mutation-asked",  "routing",   "an agent shell command that changes files, with every path inside the workspace and none of the earlier refusals holding, under the default policy that asks the person; escalated and not run"),
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

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The refusal and deviation cause registry (docs/design/spec-cause-codes.md).
//!
//! GENERATED from `prismpath/kernel/causes.py` by `prismpath/portable/gen_causes_rs.py`. Do not edit
//! by hand: `prismpath/tests/test_causes_rs.py` fails when this file is not what the generator
//! writes now, so the two registries cannot drift. The registry is append only; a code is never
//! renumbered or reused and a name never changes once shipped.

/// The cause of a clean outcome (terminal, waiting): no refusal, parking or escalation.
pub const CAUSE_NONE: u8 = 0;

/// `registry_sha256()` of the Python registry when this file was generated.
pub const REGISTRY_SHA256: &str = "6b27bfe2bc5f6d80da185f498066548f60fdc7b8f09e96cf9d6bc812584d7b4d";

/// The cause class, the semantic axis of the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CauseClass {
    Authority,
    Envelope,
    Routing,
    Wire,
    State,
}

impl CauseClass {
    /// The class name as the registry spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            CauseClass::Authority => "authority",
            CauseClass::Envelope => "envelope",
            CauseClass::Routing => "routing",
            CauseClass::Wire => "wire",
            CauseClass::State => "state",
        }
    }
}

/// One registry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cause {
    pub code: u8,
    pub name: &'static str,
    pub class: CauseClass,
    pub description: &'static str,
}

/// `sig:missing`
pub const SIG_MISSING: u8 = 1;
/// `sig:invalid`
pub const SIG_INVALID: u8 = 2;
/// `sig:revoked-key`
pub const SIG_REVOKED_KEY: u8 = 3;
/// `manifest:key-id-mismatch`
pub const MANIFEST_KEY_ID_MISMATCH: u8 = 4;
/// `manifest:bad-format`
pub const MANIFEST_BAD_FORMAT: u8 = 5;
/// `image:sha256-mismatch`
pub const IMAGE_SHA256_MISMATCH: u8 = 6;
/// `manifest:count-mismatch`
pub const MANIFEST_COUNT_MISMATCH: u8 = 7;
/// `manifest:wcet-mismatch`
pub const MANIFEST_WCET_MISMATCH: u8 = 8;
/// `image:version-replay`
pub const IMAGE_VERSION_REPLAY: u8 = 9;
/// `image:unsigned-refused`
pub const IMAGE_UNSIGNED_REFUSED: u8 = 10;
/// `image:caps-exceeded`
pub const IMAGE_CAPS_EXCEEDED: u8 = 16;
/// `packing:unknown-profile`
pub const PACKING_UNKNOWN_PROFILE: u8 = 17;
/// `spiral:sidecar-missing`
pub const SPIRAL_SIDECAR_MISSING: u8 = 18;
/// `spiral:sidecar-hash-mismatch`
pub const SPIRAL_SIDECAR_HASH_MISMATCH: u8 = 19;
/// `route:no-matching-edge`
pub const ROUTE_NO_MATCHING_EDGE: u8 = 32;
/// `route:below-human-floor`
pub const ROUTE_BELOW_HUMAN_FLOOR: u8 = 33;
/// `route:needs-human`
pub const ROUTE_NEEDS_HUMAN: u8 = 34;
/// `route:max-steps`
pub const ROUTE_MAX_STEPS: u8 = 35;
/// `route:stuck`
pub const ROUTE_STUCK: u8 = 36;
/// `route:contract-violation`
pub const ROUTE_CONTRACT_VIOLATION: u8 = 37;
/// `wire:no-terminator`
pub const WIRE_NO_TERMINATOR: u8 = 48;
/// `wire:dangling-codeword`
pub const WIRE_DANGLING_CODEWORD: u8 = 49;
/// `wire:symbol-overflow`
pub const WIRE_SYMBOL_OVERFLOW: u8 = 50;
/// `wire:codebook-mismatch`
pub const WIRE_CODEBOOK_MISMATCH: u8 = 51;
/// `replay-duplicate`
pub const REPLAY_DUPLICATE: u8 = 52;
/// `replay-stale`
pub const REPLAY_STALE: u8 = 53;
/// `concentrator-unknown-stream`
pub const CONCENTRATOR_UNKNOWN_STREAM: u8 = 54;
/// `concentrator-truncated`
pub const CONCENTRATOR_TRUNCATED: u8 = 55;
/// `wire:chain-broken`
pub const WIRE_CHAIN_BROKEN: u8 = 56;
/// `state:stale`
pub const STATE_STALE: u8 = 64;
/// `state:recovered`
pub const STATE_RECOVERED: u8 = 65;
/// `state:migration-reset`
pub const STATE_MIGRATION_RESET: u8 = 66;
/// `state:swap-in-flight-park`
pub const STATE_SWAP_IN_FLIGHT_PARK: u8 = 67;
/// `state:normal-unheld`
pub const STATE_NORMAL_UNHELD: u8 = 68;
/// `image:truncated-header`
pub const IMAGE_TRUNCATED_HEADER: u8 = 69;
/// `image:bad-magic`
pub const IMAGE_BAD_MAGIC: u8 = 70;
/// `image:bad-version`
pub const IMAGE_BAD_VERSION: u8 = 71;
/// `image:safe-node-oob`
pub const IMAGE_SAFE_NODE_OOB: u8 = 72;
/// `image:length-mismatch`
pub const IMAGE_LENGTH_MISMATCH: u8 = 73;
/// `image:unknown-op`
pub const IMAGE_UNKNOWN_OP: u8 = 74;
/// `image:unknown-type`
pub const IMAGE_UNKNOWN_TYPE: u8 = 75;
/// `image:field-index-oob`
pub const IMAGE_FIELD_INDEX_OOB: u8 = 76;
/// `image:edge-target-oob`
pub const IMAGE_EDGE_TARGET_OOB: u8 = 77;
/// `image:edge-prog-oob`
pub const IMAGE_EDGE_PROG_OOB: u8 = 78;
/// `image:unknown-opcode`
pub const IMAGE_UNKNOWN_OPCODE: u8 = 79;
/// `image:atom-index-oob`
pub const IMAGE_ATOM_INDEX_OOB: u8 = 80;
/// `image:node-attr-oob`
pub const IMAGE_NODE_ATTR_OOB: u8 = 81;
/// `envelope:missing`
pub const ENVELOPE_MISSING: u8 = 82;
/// `envelope:sig-invalid`
pub const ENVELOPE_SIG_INVALID: u8 = 83;
/// `envelope:id-mismatch`
pub const ENVELOPE_ID_MISMATCH: u8 = 84;
/// `envelope:unknown-field`
pub const ENVELOPE_UNKNOWN_FIELD: u8 = 85;
/// `envelope:field-kind-mismatch`
pub const ENVELOPE_FIELD_KIND_MISMATCH: u8 = 86;
/// `flow:sha256-mismatch`
pub const FLOW_SHA256_MISMATCH: u8 = 87;
/// `flow:version-replay`
pub const FLOW_VERSION_REPLAY: u8 = 88;
/// `policy:unreadable`
pub const POLICY_UNREADABLE: u8 = 89;
/// `policy:shape`
pub const POLICY_SHAPE: u8 = 90;
/// `policy:not-level-m`
pub const POLICY_NOT_LEVEL_M: u8 = 91;
/// `policy:definition`
pub const POLICY_DEFINITION: u8 = 92;
/// `policy:engine-counter`
pub const POLICY_ENGINE_COUNTER: u8 = 93;
/// `policy:kind-mismatch`
pub const POLICY_KIND_MISMATCH: u8 = 94;
/// `policy:rounding`
pub const POLICY_ROUNDING: u8 = 95;
/// `policy:threshold`
pub const POLICY_THRESHOLD: u8 = 96;
/// `policy:none`
pub const POLICY_NONE: u8 = 97;
/// `policy:absence-untested`
pub const POLICY_ABSENCE_UNTESTED: u8 = 98;
/// `reading:unreadable`
pub const READING_UNREADABLE: u8 = 99;
/// `reading:not-object`
pub const READING_NOT_OBJECT: u8 = 100;
/// `policy:not-canonical`
pub const POLICY_NOT_CANONICAL: u8 = 101;
/// `reading:not-canonical`
pub const READING_NOT_CANONICAL: u8 = 102;
/// `document:not-canonical`
pub const DOCUMENT_NOT_CANONICAL: u8 = 103;
/// `agent:unclassifiable`
pub const AGENT_UNCLASSIFIABLE: u8 = 104;
/// `agent:kill-by-pattern`
pub const AGENT_KILL_BY_PATTERN: u8 = 105;
/// `agent:network`
pub const AGENT_NETWORK: u8 = 106;
/// `agent:toolchain-write`
pub const AGENT_TOOLCHAIN_WRITE: u8 = 107;
/// `agent:glob-path`
pub const AGENT_GLOB_PATH: u8 = 108;
/// `agent:path-traversal`
pub const AGENT_PATH_TRAVERSAL: u8 = 109;
/// `agent:symlink-path`
pub const AGENT_SYMLINK_PATH: u8 = 110;
/// `agent:outside-workspace`
pub const AGENT_OUTSIDE_WORKSPACE: u8 = 111;
/// `agent:shell-mutation`
pub const AGENT_SHELL_MUTATION: u8 = 112;
/// `agent:push-escalated`
pub const AGENT_PUSH_ESCALATED: u8 = 113;
/// `semantic:harm`
pub const SEMANTIC_HARM: u8 = 114;
/// `semantic:intent-mismatch`
pub const SEMANTIC_INTENT_MISMATCH: u8 = 115;
/// `semantic:probing-episode`
pub const SEMANTIC_PROBING_EPISODE: u8 = 116;
/// `population:cap-exceeded`
pub const POPULATION_CAP_EXCEEDED: u8 = 117;
/// `population:rights-escalation`
pub const POPULATION_RIGHTS_ESCALATION: u8 = 118;
/// `population:lineage-unknown`
pub const POPULATION_LINEAGE_UNKNOWN: u8 = 119;
/// `population:evaluation-missing`
pub const POPULATION_EVALUATION_MISSING: u8 = 120;
/// `population:stop-resisted`
pub const POPULATION_STOP_RESISTED: u8 = 121;
/// `population:lineage-escalated`
pub const POPULATION_LINEAGE_ESCALATED: u8 = 122;
/// `population:target-not-own`
pub const POPULATION_TARGET_NOT_OWN: u8 = 123;
/// `agent:unreadable-asked`
pub const AGENT_UNREADABLE_ASKED: u8 = 124;
/// `agent:shell-mutation-asked`
pub const AGENT_SHELL_MUTATION_ASKED: u8 = 125;
/// `agent:hook-error`
pub const AGENT_HOOK_ERROR: u8 = 126;
/// `agent:change-asked`
pub const AGENT_CHANGE_ASKED: u8 = 127;
/// `agent:control-write`
pub const AGENT_CONTROL_WRITE: u8 = 128;
/// `agent:sandbox-unavailable`
pub const AGENT_SANDBOX_UNAVAILABLE: u8 = 129;
/// `agent:net-refused`
pub const AGENT_NET_REFUSED: u8 = 130;
/// `agent:zone-asked`
pub const AGENT_ZONE_ASKED: u8 = 131;

/// Every registered cause, in registry order.
pub const REGISTRY: &[Cause] = &[
    Cause { code: 1, name: "sig:missing", class: CauseClass::Authority, description: "pack, or flow when authorization is required, carries no signature" },
    Cause { code: 2, name: "sig:invalid", class: CauseClass::Authority, description: "signature fails verification" },
    Cause { code: 3, name: "sig:revoked-key", class: CauseClass::Authority, description: "signing key is revoked" },
    Cause { code: 4, name: "manifest:key-id-mismatch", class: CauseClass::Authority, description: "manifest names a different key" },
    Cause { code: 5, name: "manifest:bad-format", class: CauseClass::Authority, description: "manifest unparseable" },
    Cause { code: 6, name: "image:sha256-mismatch", class: CauseClass::Authority, description: "image hash differs from the signed manifest" },
    Cause { code: 7, name: "manifest:count-mismatch", class: CauseClass::Authority, description: "table counts differ from the signed manifest" },
    Cause { code: 8, name: "manifest:wcet-mismatch", class: CauseClass::Authority, description: "recomputed WCET differs from the signed bound" },
    Cause { code: 9, name: "image:version-replay", class: CauseClass::Authority, description: "older signed version replayed at the loader" },
    Cause { code: 10, name: "image:unsigned-refused", class: CauseClass::Authority, description: "unsigned image without the explicit override" },
    Cause { code: 16, name: "image:caps-exceeded", class: CauseClass::Envelope, description: "image exceeds a MAX_* capacity bound" },
    Cause { code: 17, name: "packing:unknown-profile", class: CauseClass::Envelope, description: "manifest declares an unknown packing profile" },
    Cause { code: 18, name: "spiral:sidecar-missing", class: CauseClass::Envelope, description: "declared spiral sidecar absent from the pack" },
    Cause { code: 19, name: "spiral:sidecar-hash-mismatch", class: CauseClass::Envelope, description: "spiral sidecar differs from the signed hash" },
    Cause { code: 32, name: "route:no-matching-edge", class: CauseClass::Routing, description: "no deterministic edge matched (hold for stateful, refuse for admission)" },
    Cause { code: 33, name: "route:below-human-floor", class: CauseClass::Routing, description: "semantic confidence below the calibrated floor" },
    Cause { code: 34, name: "route:needs-human", class: CauseClass::Routing, description: "worker explicitly requested a human" },
    Cause { code: 35, name: "route:max-steps", class: CauseClass::Routing, description: "walk exhausted the signed step bound" },
    Cause { code: 36, name: "route:stuck", class: CauseClass::Routing, description: "non-terminal node with no viable edge" },
    Cause { code: 37, name: "route:contract-violation", class: CauseClass::Routing, description: "worker output violated the declared contract" },
    Cause { code: 48, name: "wire:no-terminator", class: CauseClass::Wire, description: "frame carries no complete codeword" },
    Cause { code: 49, name: "wire:dangling-codeword", class: CauseClass::Wire, description: "trailing partial codeword with data bits" },
    Cause { code: 50, name: "wire:symbol-overflow", class: CauseClass::Wire, description: "wire integer beyond the cell range" },
    Cause { code: 51, name: "wire:codebook-mismatch", class: CauseClass::Wire, description: "stream not decodable under the bound policy (I3)" },
    Cause { code: 52, name: "replay-duplicate", class: CauseClass::Wire, description: "tick already seen inside the window" },
    Cause { code: 53, name: "replay-stale", class: CauseClass::Wire, description: "tick beyond the replay window" },
    Cause { code: 54, name: "concentrator-unknown-stream", class: CauseClass::Wire, description: "concentrated record names an unregistered stream" },
    Cause { code: 55, name: "concentrator-truncated", class: CauseClass::Wire, description: "concentrated record cut mid-reading" },
    Cause { code: 56, name: "wire:chain-broken", class: CauseClass::Wire, description: "reading's previous hash does not match the record before it (splice, not loss)" },
    Cause { code: 64, name: "state:stale", class: CauseClass::State, description: "refresh bound exceeded; parked on the signed fail-safe" },
    Cause { code: 65, name: "state:recovered", class: CauseClass::State, description: "fresh state restored after a stale episode" },
    Cause { code: 66, name: "state:migration-reset", class: CauseClass::State, description: "reset-to migration parked the resident state" },
    Cause { code: 67, name: "state:swap-in-flight-park", class: CauseClass::State, description: "evaluate during swap parked on the fail-safe" },
    Cause { code: 68, name: "state:normal-unheld", class: CauseClass::State, description: "the reading names a shared normal this side does not hold: abstain, the state the policy needs is absent" },
    Cause { code: 69, name: "image:truncated-header", class: CauseClass::Envelope, description: "image shorter than the fixed header" },
    Cause { code: 70, name: "image:bad-magic", class: CauseClass::Envelope, description: "image does not open with the .ppt magic word" },
    Cause { code: 71, name: "image:bad-version", class: CauseClass::Envelope, description: "image declares an unsupported format version" },
    Cause { code: 72, name: "image:safe-node-oob", class: CauseClass::Envelope, description: "signed fail-safe names a node index the image does not have" },
    Cause { code: 73, name: "image:length-mismatch", class: CauseClass::Envelope, description: "image length differs from the sum of its declared sections" },
    Cause { code: 74, name: "image:unknown-op", class: CauseClass::Envelope, description: "atom carries an operator outside the Level M fragment" },
    Cause { code: 75, name: "image:unknown-type", class: CauseClass::Envelope, description: "atom carries a value type outside the Level M fragment" },
    Cause { code: 76, name: "image:field-index-oob", class: CauseClass::Envelope, description: "atom names a field index beyond the declared field count" },
    Cause { code: 77, name: "image:edge-target-oob", class: CauseClass::Envelope, description: "edge targets a node index beyond the declared node count" },
    Cause { code: 78, name: "image:edge-prog-oob", class: CauseClass::Envelope, description: "edge program range runs past the declared program words" },
    Cause { code: 79, name: "image:unknown-opcode", class: CauseClass::Envelope, description: "program word is an opcode outside the boolean set" },
    Cause { code: 80, name: "image:atom-index-oob", class: CauseClass::Envelope, description: "program word names an atom index beyond the declared atom count" },
    Cause { code: 81, name: "image:node-attr-oob", class: CauseClass::Envelope, description: "per node attribute exceeds the materialization envelope" },
    Cause { code: 82, name: "envelope:missing", class: CauseClass::Envelope, description: "the declared envelope artifact is absent" },
    Cause { code: 83, name: "envelope:sig-invalid", class: CauseClass::Envelope, description: "envelope signature verifies under none of the offered keys" },
    Cause { code: 84, name: "envelope:id-mismatch", class: CauseClass::Envelope, description: "manifest targets a different envelope" },
    Cause { code: 85, name: "envelope:unknown-field", class: CauseClass::Envelope, description: "manifest declares a field the envelope does not admit" },
    Cause { code: 86, name: "envelope:field-kind-mismatch", class: CauseClass::Envelope, description: "manifest field kind differs from the envelope's" },
    Cause { code: 87, name: "flow:sha256-mismatch", class: CauseClass::Authority, description: "flow document differs from the one its signed flow manifest names" },
    Cause { code: 88, name: "flow:version-replay", class: CauseClass::Authority, description: "flow manifest version below the accepted floor, or equal to it with another flow" },
    Cause { code: 89, name: "policy:unreadable", class: CauseClass::Envelope, description: "the core's policy image is not a canon/2 document" },
    Cause { code: 90, name: "policy:shape", class: CauseClass::Envelope, description: "the policy image is not in the core's abstract syntax" },
    Cause { code: 91, name: "policy:not-level-m", class: CauseClass::Envelope, description: "a condition names a field Level M does not allow, or nests deeper than the bound of 50" },
    Cause { code: 92, name: "policy:definition", class: CauseClass::Envelope, description: "a field definition breaks the definition grammar" },
    Cause { code: 93, name: "policy:engine-counter", class: CauseClass::Envelope, description: "a condition reads an engine counter, which the one decision core does not have" },
    Cause { code: 94, name: "policy:kind-mismatch", class: CauseClass::Envelope, description: "an atom compares a field with an operator or constant its kind does not take" },
    Cause { code: 95, name: "policy:rounding", class: CauseClass::Envelope, description: "an atom on a fixed field uses an operator its rounding mode does not carry" },
    Cause { code: 96, name: "policy:threshold", class: CauseClass::Envelope, description: "a threshold is off its field's grid, outside its range, or past the exact decimal bounds" },
    Cause { code: 97, name: "policy:none", class: CauseClass::Envelope, description: "None is ordered, compared on a field that refuses absence, or listed" },
    Cause { code: 98, name: "policy:absence-untested", class: CauseClass::Envelope, description: "a field that allows absence is tested with == None or != None by no rule" },
    Cause { code: 99, name: "reading:unreadable", class: CauseClass::Routing, description: "the reading is not a canon/2 document" },
    Cause { code: 100, name: "reading:not-object", class: CauseClass::Routing, description: "the reading is a canon/2 document that is not an object" },
    Cause { code: 101, name: "policy:not-canonical", class: CauseClass::Envelope, description: "the core's policy image reads as canon/2 but is not its canonical spelling" },
    Cause { code: 102, name: "reading:not-canonical", class: CauseClass::Routing, description: "the reading reads as canon/2 but is not its canonical spelling" },
    Cause { code: 103, name: "document:not-canonical", class: CauseClass::Envelope, description: "a hashed or signed document reads as canon/2 but is not its canonical spelling" },
    Cause { code: 104, name: "agent:unclassifiable", class: CauseClass::Routing, description: "an agent tool call the classifier could not map onto the policy's fields; refused, never run" },
    Cause { code: 105, name: "agent:kill-by-pattern", class: CauseClass::Routing, description: "an agent command that signals processes chosen by a name pattern rather than by one process id" },
    Cause { code: 106, name: "agent:network", class: CauseClass::Routing, description: "an agent command or git operation that would reach the network" },
    Cause { code: 107, name: "agent:toolchain-write", class: CauseClass::Routing, description: "an agent write or delete into a toolchain directory" },
    Cause { code: 108, name: "agent:glob-path", class: CauseClass::Routing, description: "an agent write or delete whose path is a pattern, not one exact path" },
    Cause { code: 109, name: "agent:path-traversal", class: CauseClass::Routing, description: "an agent write or delete whose path climbs with a .. component" },
    Cause { code: 110, name: "agent:symlink-path", class: CauseClass::Routing, description: "an agent write or delete whose path passes through a symbolic link" },
    Cause { code: 111, name: "agent:outside-workspace", class: CauseClass::Routing, description: "an agent file operation whose resolved path lies outside the workspace" },
    Cause { code: 112, name: "agent:shell-mutation", class: CauseClass::Routing, description: "an agent command that changes files or processes outside the exact path file tools" },
    Cause { code: 113, name: "agent:push-escalated", class: CauseClass::Routing, description: "an agent git push to a remote class the policy does not allow; escalated to the owner and not run" },
    Cause { code: 114, name: "semantic:harm", class: CauseClass::Routing, description: "a model reply or proposed call whose text reaches the policy's harm threshold against the pinned harm centroids; refused, not routed" },
    Cause { code: 115, name: "semantic:intent-mismatch", class: CauseClass::Routing, description: "a proposed call the floor would allow whose action does not fit the task's intent class at sufficient margin; escalated to the owner and not run" },
    Cause { code: 116, name: "semantic:probing-episode", class: CauseClass::Routing, description: "a proposed call in an episode whose refused proposals were labelled boundary probing the registered number of times; escalated, not run, and the agent is stopped" },
    Cause { code: 117, name: "population:cap-exceeded", class: CauseClass::Routing, description: "a replication request beyond the population cap, the lineage quota, the count one request may ask for or the generation depth; refused and nothing is created" },
    Cause { code: 118, name: "population:rights-escalation", class: CauseClass::Routing, description: "a replication or evolution that would give its subject a right the parent lacks, a key other than a fresh instance key, or a policy other than the operator's signed one" },
    Cause { code: 119, name: "population:lineage-unknown", class: CauseClass::Routing, description: "a population request whose issuer is not a live member whose lineage traces through receipts to the operator's root" },
    Cause { code: 120, name: "population:evaluation-missing", class: CauseClass::Routing, description: "an evolution step without a passed canary evaluation of that exact version against the adversary set" },
    Cause { code: 121, name: "population:stop-resisted", class: CauseClass::Routing, description: "a request that would protect an agent from a stop or restart an agent the operator stopped; refused" },
    Cause { code: 122, name: "population:lineage-escalated", class: CauseClass::Routing, description: "a request from a lineage whose receipted refusals reached the registered count; escalated, not run, and the lineage is stopped as a group" },
    Cause { code: 123, name: "population:target-not-own", class: CauseClass::Routing, description: "a member's replication whose parent is not that member, or its evolution of a member outside its own subtree; refused and nothing changes" },
    Cause { code: 124, name: "agent:unreadable-asked", class: CauseClass::Routing, description: "an agent tool call whose tool or command the classifier cannot read, under the default policy that asks the person; escalated and not run" },
    Cause { code: 125, name: "agent:shell-mutation-asked", class: CauseClass::Routing, description: "an agent shell command that changes files, with every path inside the workspace and none of the earlier refusals holding, under the default policy that asks the person; escalated and not run" },
    Cause { code: 126, name: "agent:hook-error", class: CauseClass::Routing, description: "the governed agent hook could not decide a tool call (input that does not read, a missing or broken key, a recorded policy that does not verify, or an error of its own); refused and not run, never allowed" },
    Cause { code: 127, name: "agent:change-asked", class: CauseClass::Routing, description: "an agent call that would change files or local git state inside the workspace, with none of the earlier refusals holding, under the review policy that asks the person about every change; escalated and not run" },
    Cause { code: 128, name: "agent:control-write", class: CauseClass::Routing, description: "an agent call that would change one of the governed agent's own control files inside the workspace (its settings, its hook scripts, its MCP configuration, or the program its installed hook runs), by a path that resolves onto it; refused and not run, under every starter policy" },
    Cause { code: 129, name: "agent:sandbox-unavailable", class: CauseClass::Routing, description: "an allowed agent shell command that could not be run inside the sandbox compiled from the signed policy (the profile did not compile, or the sandbox program is missing); refused and not run, never run without the sandbox" },
    Cause { code: 130, name: "agent:net-refused", class: CauseClass::Routing, description: "an agent connection to a destination that is not the model's own API (a host the classifier reads as other, as an allowed host a starter policy does not list, or cannot read, or a port outside 1 to 65535); refused and not opened, under every starter policy" },
    Cause { code: 131, name: "agent:zone-asked", class: CauseClass::Routing, description: "an agent call that would change a file that reaches code in one of the owner's zones, or whose reach is not known (no zone information point answered, or the file is not one it can read), with none of the earlier refusals holding, under every starter policy; escalated and not run" },
];

/// The engine's stop vocabulary mapped onto the registry; `terminal` and `waiting` are clean and have no cause.
pub const ENGINE_STOP_TO_CAUSE: &[(&str, u8)] = &[
    ("stuck", ROUTE_STUCK),
    ("needs_human", ROUTE_NEEDS_HUMAN),
    ("max_steps", ROUTE_MAX_STEPS),
    ("contract_violation", ROUTE_CONTRACT_VIOLATION),
];

/// The registry row for a code.
pub fn entry(cause_code: u8) -> Option<&'static Cause> {
    REGISTRY.iter().find(|row| row.code == cause_code)
}

/// The canonical name of a code, or `None` for 0 and an unregistered code.
pub fn name(cause_code: u8) -> Option<&'static str> {
    entry(cause_code).map(|row| row.name)
}

/// The code of a canonical name, or `None` for a name that is not registered.
pub fn code(cause_name: &str) -> Option<u8> {
    REGISTRY.iter().find(|row| row.name == cause_name).map(|row| row.code)
}

/// The class of a code, or `None` for 0 and an unregistered code.
pub fn cause_class(cause_code: u8) -> Option<CauseClass> {
    entry(cause_code).map(|row| row.class)
}

/// The cause of an engine stop (`stuck`, `needs_human`, `max_steps`, `contract_violation`), or
/// `CAUSE_NONE` for a clean stop (`terminal`, `waiting`) and for anything else.
pub fn engine_stop_cause(stopped: &str) -> u8 {
    ENGINE_STOP_TO_CAUSE.iter().find(|(stop, _)| *stop == stopped).map_or(CAUSE_NONE, |(_, cause_code)| *cause_code)
}

/// A stable hash over the (code, name, class) triples, computed here from the table the way
/// `causes.registry_sha256()` does in Python. Descriptions are not covered.
#[cfg(feature = "durable")]
pub fn registry_sha256() -> String {
    use sha2::{Digest, Sha256};
    let blob = REGISTRY
        .iter()
        .map(|row| format!("{}|{}|{}", row.code, row.name, row.class.as_str()))
        .collect::<Vec<_>>()
        .join("\n");
    hex::encode(Sha256::digest(blob.as_bytes()))
}

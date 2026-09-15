// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// crypto_migration_policy.mjs: the policy family the frozen migration matrix proves P4 against.
//
// gen_crypto_migration_fixtures.py freezes only the proof result of each (policy gate, envelope
// floor) cell. The policy text it proved and the envelope it proved under are NOT in the corpus,
// so the port has to render both itself and they can drift from the generator without any cell
// changing. Everything derivable from a frozen file is read from one here (the approved suites and
// the key id come out of the registry that check 1 of run_crypto_agility.mjs pins to the migration
// corpus by hash), and what is left, the policy text, is pinned the only other way available:
// test_portable_runners.py calls phasePolicy for every gate the corpus carries and compares it to
// the generator's phase_policy byte for byte. That test is why this rendering lives in its own
// module instead of inside the runner, which cannot be imported without running.
import { suiteIds } from "./prismpath.mjs";

/**
 * Render policy_k, which permits the classical suite only BELOW migration phase k, so that past
 * phase k only quantum resistant suites stay reachable. Byte identical to the generator's
 * phase_policy; the flow text is the subject of the proof, so changing it changes what P4 means.
 */
export function phasePolicy(policyGate) {
  return `---
name: ca_phase_${policyGate}
start: classify
---
## classify
-> cui-path: when data_class == "cui"
-> legacy-path: when migration_phase < ${policyGate}
-> hybrid-path: else
## cui-path
-> suite-cnsa2-hybrid-1: when always
## legacy-path
-> suite-tls13-aesgcm: when always
## hybrid-path
-> suite-tls13-hybrid-x25519mlkem: when always
## suite-cnsa2-hybrid-1
-> end: when always
## suite-tls13-aesgcm
-> end: when always
## suite-tls13-hybrid-x25519mlkem
-> end: when always
## end
done
`;
}

/**
 * The envelope one matrix cell is proved under, at one migration phase floor. The approved suite
 * list and the key id are read from the registry rather than restated: the generator approves every
 * suite of the registry it built, in sorted order, under that registry's own key id.
 */
export function migrationEnvelope(registryData, registryHashValue, migrationPhaseFloor) {
  return {
    envelope_id: `floor-${migrationPhaseFloor}`,
    approved_suites: suiteIds(registryData),
    class_field: "data_class",
    migration_phase_field: "migration_phase",
    migration_phase_floor: migrationPhaseFloor,
    registry_hash: registryHashValue,
    key_id: registryData.key_id,
  };
}

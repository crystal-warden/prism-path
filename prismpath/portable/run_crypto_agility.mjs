// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// Certify the JS crypto-agility proofs against frozen conformance fixtures.
// Run: node prismpath/portable/run_crypto_agility.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  parse,
  registryHash,
  proveAll,
  proveMonotoneMigration,
} from "./prismpath.mjs";
import { phasePolicy, migrationEnvelope } from "./crypto_migration_policy.mjs";

const here = dirname(fileURLToPath(import.meta.url));

const agilityFx = JSON.parse(
  readFileSync(join(here, "conformance", "crypto_agility.json"), "utf-8")
);
const migrationFx = JSON.parse(
  readFileSync(join(here, "conformance", "crypto_migration.json"), "utf-8")
);

let pass = 0, fail = 0;

// 1. Registry hash check
const rh = registryHash(agilityFx.registry);
if (rh === agilityFx.registry_hash && rh === migrationFx.registry_hash) {
  pass++;
} else {
  fail++;
  console.error(`FAIL registry_hash mismatch\n  computed ${rh}\n  agility ${agilityFx.registry_hash}\n  migration ${migrationFx.registry_hash}`);
}

// 2. Crypto agility cases
for (const testCase of agilityFx.cases) {
  const graph = parse(testCase.flow_text);
  const got = proveAll(graph, agilityFx.envelope, agilityFx.registry);
  if (JSON.stringify(got) === JSON.stringify(testCase.expected)) {
    pass++;
  } else {
    fail++;
    console.error(`FAIL crypto_agility case ${testCase.name}\n  expected ${JSON.stringify(testCase.expected)}\n  got      ${JSON.stringify(got)}`);
  }
}

// 3. Crypto migration matrix. The policy text and the envelope come from
// crypto_migration_policy.mjs, which explains how each is held to the generator's.
for (const cell of migrationFx.cells) {
  const graph = parse(phasePolicy(cell.policy_gate));
  const env = migrationEnvelope(agilityFx.registry, rh, cell.envelope_floor);
  const p4 = proveMonotoneMigration(graph, env, agilityFx.registry);
  const matchP4 = JSON.stringify(p4) === JSON.stringify(cell.p4);
  const matchInv = (p4.ok === (cell.envelope_floor >= cell.policy_gate)) === cell.invariant_holds;

  if (matchP4 && matchInv) {
    pass++;
  } else {
    fail++;
    console.error(`FAIL crypto_migration cell gate=${cell.policy_gate} floor=${cell.envelope_floor}\n  p4 match: ${matchP4}\n  inv match: ${matchInv}`);
  }
}

// One check here really is over bytes: the registry hash above is SHA-256 over the canonical
// serialization, so the registry is compared byte for byte. The proof cases are not: each compares
// the JS verdict object against the frozen one as canonically ordered JSON, which is the parity
// claim the corpus actually makes. Saying "byte-for-byte" of the whole run overstated it.
const total = 1 + agilityFx.cases.length + migrationFx.cells.length;
console.log(`crypto-agility: ${pass}/${total} checks passed`);
console.log(fail ? "NOT CONFORMANT" : "CONFORMANT — registry hash exact, every JS proof verdict equal to the frozen reference");
process.exit(fail ? 1 : 0);

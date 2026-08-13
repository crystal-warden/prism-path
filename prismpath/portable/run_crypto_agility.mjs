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
for (const c of agilityFx.cases) {
  const g = parse(c.flow_text);
  const got = proveAll(g, agilityFx.envelope, agilityFx.registry);
  if (JSON.stringify(got) === JSON.stringify(c.expected)) {
    pass++;
  } else {
    fail++;
    console.error(`FAIL crypto_agility case ${c.name}\n  expected ${JSON.stringify(c.expected)}\n  got      ${JSON.stringify(got)}`);
  }
}

// 3. Crypto migration matrix
const SUITES = ["cnsa2-hybrid-1", "tls13-aesgcm", "tls13-hybrid-x25519mlkem"];
function phasePolicy(k) {
  return `---
name: ca_phase_${k}
start: classify
---
## classify
-> cui-path: when data_class == "cui"
-> legacy-path: when migration_phase < ${k}
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

function migrationEnvelope(hash, floor) {
  return {
    envelope_id: `floor-${floor}`,
    approved_suites: SUITES,
    class_field: "data_class",
    migration_phase_field: "migration_phase",
    migration_phase_floor: floor,
    registry_hash: hash,
    key_id: "0".repeat(64),
  };
}

for (const cell of migrationFx.cells) {
  const g = parse(phasePolicy(cell.policy_gate));
  const env = migrationEnvelope(rh, cell.envelope_floor);
  const p4 = proveMonotoneMigration(g, env, agilityFx.registry);
  const matchP4 = JSON.stringify(p4) === JSON.stringify(cell.p4);
  const matchInv = (p4.ok === (cell.envelope_floor >= cell.policy_gate)) === cell.invariant_holds;

  if (matchP4 && matchInv) {
    pass++;
  } else {
    fail++;
    console.error(`FAIL crypto_migration cell gate=${cell.policy_gate} floor=${cell.envelope_floor}\n  p4 match: ${matchP4}\n  inv match: ${matchInv}`);
  }
}

const total = 1 + agilityFx.cases.length + migrationFx.cells.length;
console.log(`crypto-agility: ${pass}/${total} checks passed`);
console.log(fail ? "NOT CONFORMANT" : "CONFORMANT — JS crypto-agility proofs match reference byte-for-byte");
process.exit(fail ? 1 : 0);

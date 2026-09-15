// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// Certify the JS flowLevelM against the frozen Level M vectors (generated from the Python reference
// model_check.flow_level_m). Run: node prismpath/portable/run_level_m.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parse, flowLevelM } from "./prismpath.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(readFileSync(join(here, "conformance", "level_m.json"), "utf8"));

let pass = 0, fail = 0;
for (const testCase of data.cases) {
  const got = flowLevelM(parse(testCase.flow));
  const norm = {
    level_m: got.level_m,
    non_member_edges: got.non_member_edges.map((edge) => ({
      node: edge.node, target: edge.target, condition: edge.condition, reason: edge.reason,
    })),
  };
  if (JSON.stringify(norm) === JSON.stringify(testCase.expected)) pass++;
  else {
    fail++;
    console.error(`FAIL ${testCase.key}\n  expected ${JSON.stringify(testCase.expected)}\n  got      ${JSON.stringify(norm)}`);
  }
}
console.log(`Level M: ${pass}/${pass + fail} match the frozen vectors`);
console.log(fail ? "NOT CONFORMANT" : "CONFORMANT — flowLevelM matches model_check.flow_level_m");
process.exit(fail ? 1 : 0);

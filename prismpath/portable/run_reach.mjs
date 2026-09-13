// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// Certify the JS checkReach against the frozen reachability corpus (from Python
// model_check.check_reach). Run: node prismpath/portable/run_reach.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parse, checkReach } from "./prismpath.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(readFileSync(join(here, "conformance", "reach.json"), "utf-8"));

let pass = 0, fail = 0;
for (const testCase of data.cases) {
  const res = checkReach(parse(testCase.flow), testCase.targets, {
    assume: testCase.assume, bound: testCase.bound,
    includeErrors: testCase.include_errors, includeEvents: testCase.include_events,
  });
  const got = {};
  for (const target of testCase.targets) got[target] = { reachable: res[target].reachable, proven: res[target].proven };
  if (JSON.stringify(got) === JSON.stringify(testCase.expected)) pass++;
  else {
    fail++;
    console.error(`FAIL ${testCase.key}\n  expected ${JSON.stringify(testCase.expected)}\n  got      ${JSON.stringify(got)}`);
  }
}
console.log(`reach: ${pass}/${pass + fail} match the frozen verdicts`);
console.log(fail ? "NOT CONFORMANT" : "CONFORMANT — checkReach matches model_check.check_reach");
process.exit(fail ? 1 : 0);

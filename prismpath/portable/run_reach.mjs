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
for (const c of data.cases) {
  const res = checkReach(parse(c.flow), c.targets, {
    assume: c.assume, bound: c.bound,
    includeErrors: c.include_errors, includeEvents: c.include_events,
  });
  const got = {};
  for (const t of c.targets) got[t] = { reachable: res[t].reachable, proven: res[t].proven };
  if (JSON.stringify(got) === JSON.stringify(c.expected)) pass++;
  else {
    fail++;
    console.error(`FAIL ${c.key}\n  expected ${JSON.stringify(c.expected)}\n  got      ${JSON.stringify(got)}`);
  }
}
console.log(`reach: ${pass}/${pass + fail} match the frozen verdicts`);
console.log(fail ? "NOT CONFORMANT" : "CONFORMANT — checkReach matches model_check.check_reach");
process.exit(fail ? 1 : 0);

// Certify the JS capabilityReport against the frozen capability matrix (from Python
// model_check.capability_report). Run: node prismpath/portable/run_capability.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parse, capabilityReport } from "./prismpath.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(readFileSync(join(here, "conformance", "capability.json"), "utf-8"));

let pass = 0, fail = 0;
for (const c of data.cases) {
  const got = capabilityReport(parse(c.flow));
  if (JSON.stringify(got) === JSON.stringify(c.expected)) pass++;
  else {
    fail++;
    console.error(`FAIL ${c.key}\n  expected ${JSON.stringify(c.expected)}\n  got      ${JSON.stringify(got)}`);
  }
}
console.log(`capability: ${pass}/${pass + fail} match the frozen matrix`);
console.log(fail ? "NOT CONFORMANT" : "CONFORMANT — capabilityReport matches model_check.capability_report");
process.exit(fail ? 1 : 0);

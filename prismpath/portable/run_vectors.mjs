// run_vectors.mjs — verify an implementation against the FROZEN conformance vectors.
//
//   node portable/run_vectors.mjs [conformance-dir]
//
// Reads portable/conformance/{predicates.json, flows.json} (generated from the Python
// reference by gen_conformance.py) and checks this port against every case. Exit 0 = full
// conformance; exit 1 prints each mismatch. Any future implementation (Go, Rust/WASM) needs
// only a JSON reader and this same contract — the spec is data.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parse, run, evalCondition, PredicateError } from "./prismpath.mjs";

const dir = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), "conformance");
let failures = 0;

// ---- predicates -----------------------------------------------------------------------
const preds = JSON.parse(readFileSync(join(dir, "predicates.json"), "utf-8"));
let predPass = 0;
for (const c of preds.cases) {
  let got;
  try {
    got = evalCondition(c.cond, c.ctx);
  } catch (e) {
    got = e instanceof PredicateError ? "ERROR" : `CRASH: ${e.message}`;
  }
  if (got === c.expect) { predPass++; continue; }
  failures++;
  console.error(`PRED MISMATCH  cond=${JSON.stringify(c.cond)} ctx=${JSON.stringify(c.ctx)}`
    + `\n  expect=${JSON.stringify(c.expect)} got=${JSON.stringify(got)}`);
}
console.log(`predicates: ${predPass}/${preds.cases.length}`);

// ---- flows ------------------------------------------------------------------------------
function scriptedAgent(script) {
  const used = {};
  return (node) => {
    const seq = script[node];
    if (seq === undefined) return { text: node };
    const i = used[node] || 0;
    used[node] = i + 1;
    const outcome = seq[Math.min(i, seq.length - 1)];
    if (outcome !== null && typeof outcome === "object" && "__raise__" in outcome) {
      throw new Error(outcome.__raise__);
    }
    return outcome;
  };
}

const flows = JSON.parse(readFileSync(join(dir, "flows.json"), "utf-8"));
let flowPass = 0;
for (const fx of flows.cases) {
  let got;
  try {
    const res = run(parse(fx.flow), scriptedAgent(fx.script || {}), {
      maxSteps: fx.maxSteps ?? 25, start: fx.start ?? null,
      state: fx.state ? JSON.parse(JSON.stringify(fx.state)) : null,
    });
    got = { path: res.path, stopped: res.stopped,
            pending_node: res.pending ? (res.pending.node ?? null) : null,
            spawn: res.pending ? (res.pending.spawn ?? null) : null };
  } catch (e) {
    got = { error: String(e.message ?? e) };
  }
  const want = fx.expect;
  const same = JSON.stringify(got) === JSON.stringify(
    { path: want.path, stopped: want.stopped, pending_node: want.pending_node ?? null,
      spawn: want.spawn ?? null });
  if (same) { flowPass++; continue; }
  failures++;
  console.error(`FLOW MISMATCH  ${fx.name}\n  expect=${JSON.stringify(want)}\n  got=   ${JSON.stringify(got)}`);
}
console.log(`flows:      ${flowPass}/${flows.cases.length}`);

if (failures) {
  console.error(`\nNON-CONFORMANT: ${failures} mismatch(es)`);
  process.exit(1);
}
console.log("\nCONFORMANT — this implementation matches the frozen kernel spec.");

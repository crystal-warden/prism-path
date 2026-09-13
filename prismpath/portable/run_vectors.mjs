// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
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
import { parse, run, evalCondition, PredicateError, scriptedAgent } from "./prismpath.mjs";

const dir = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), "conformance");
let failures = 0;

// ---- predicates -----------------------------------------------------------------------
// The corpus README draws a line the report has to keep: a PredicateError is the sandbox REFUSING a
// predicate, which is a legitimate frozen expectation ("ERROR"), while any other exception is the
// evaluator itself crashing, which no expectation can ever equal. Folding the second into the first
// as a mismatch hid the distinction, so a crash is now counted and printed as a crash.
const preds = JSON.parse(readFileSync(join(dir, "predicates.json"), "utf-8"));
let predPass = 0;
let predCrash = 0;
for (const predCase of preds.cases) {
  let got;
  try {
    got = evalCondition(predCase.cond, predCase.ctx);
  } catch (err) {
    if (!(err instanceof PredicateError)) {
      predCrash++;
      failures++;
      console.error(`PRED CRASH  cond=${JSON.stringify(predCase.cond)} ctx=${JSON.stringify(predCase.ctx)}`
        + `\n  the evaluator threw ${err.name}: ${err.message}`);
      continue;
    }
    got = "ERROR";
  }
  if (got === predCase.expect) { predPass++; continue; }
  failures++;
  console.error(`PRED MISMATCH  cond=${JSON.stringify(predCase.cond)} ctx=${JSON.stringify(predCase.ctx)}`
    + `\n  expect=${JSON.stringify(predCase.expect)} got=${JSON.stringify(got)}`);
}
console.log(`predicates: ${predPass}/${preds.cases.length}${predCrash ? ` (${predCrash} evaluator crash(es))` : ""}`);

// ---- flows ------------------------------------------------------------------------------
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
  } catch (err) {
    got = { error: String(err.message ?? err) };
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

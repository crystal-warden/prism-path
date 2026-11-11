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
import {
  parse, run, evalCondition, PredicateError, scriptedAgent, firstDeterministic, FieldDefinitionError,
  canon2Read, canon2Write, canon2Canonicalize, Canon2Error, parseDefinition, canonicalValue, systemBoundary, coreCauseCode,
} from "./prismpath.mjs";

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
let flowSkipped = 0;
for (const fx of flows.cases) {
  // A case that carries `opts` sets an engine option the P0 kernel does not take (the type gate, the
  // transcript bound, a run id). Those cases are for the engines that implement the options.
  if (fx.opts) { flowSkipped++; continue; }
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
// The cases that carry `opts` are not core flows: the engine's type gate, transcript bound and run id are
// options of the flow engine (spec-verified-core.md section 1), outside the one decision the core is.
console.log(`flows:      ${flowPass}/${flows.cases.length - flowSkipped}${flowSkipped ? ` (${flowSkipped} with engine options skipped: the options are outside the core)` : ""}`);

// ---- canon/2 ------------------------------------------------------------------------------
// The frozen canon/2 vectors (spec-verified-core.md section 3): every case is refused with the reference's
// rule (not-canonical for a spelling that is not the canonical one) or accepted as its own canonical
// bytes, and canonicalize gives the reference's canonical bytes, a fixed point, or the same refusal.
const unhex = (hex) => Uint8Array.from(hex.match(/../g) || [], (pair) => parseInt(pair, 16));
const hexOf = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const canon2 = JSON.parse(readFileSync(join(dir, "canon2.json"), "utf-8"));
let canon2Pass = 0;
for (const vector of canon2.cases) {
  let problem = null;
  const bytes = unhex(vector.hex);
  try {
    const document = canon2Read(bytes);
    if (vector.refuse !== undefined) problem = `read, the reference refuses it as ${vector.refuse}`;
    else if (hexOf(canon2Write(document)) !== vector.hex) problem = "the strict reader accepted bytes that are not canonical";
  } catch (err) {
    if (!(err instanceof Canon2Error)) problem = `crashed: ${err}`;
    else if (vector.refuse === undefined) problem = `refused as ${err.rule}, the reference reads it`;
    else if (err.rule !== vector.refuse) problem = `refused as ${err.rule}, want ${vector.refuse}`;
  }
  if (problem === null) {
    try {
      const written = canon2Canonicalize(bytes);
      if (vector.canonical_hex === undefined) problem = `canonicalized, the reference refuses it as ${vector.refuse}`;
      else if (hexOf(written) !== vector.canonical_hex) problem = `canonicalized to ${hexOf(written)}, want ${vector.canonical_hex}`;
      else if (hexOf(canon2Write(canon2Read(written))) !== vector.canonical_hex) problem = "the canonical bytes are not a fixed point";
    } catch (err) {
      if (!(err instanceof Canon2Error)) problem = `canonicalize crashed: ${err}`;
      else if (vector.canonical_hex !== undefined) problem = `canonicalize refused as ${err.rule}, the reference canonicalizes it`;
      else if (err.rule !== vector.refuse) problem = `canonicalize refused as ${err.rule}, want ${vector.refuse}`;
    }
  }
  if (problem === null) { canon2Pass++; continue; }
  failures++;
  console.error(`CANON2 MISMATCH  ${vector.name}: ${problem}`);
}
console.log(`canon2:     ${canon2Pass}/${canon2.cases.length}`);

// ---- field definitions ----------------------------------------------------------------------
// SPEC section 4.5, the frozen vectors: the shared conversion, parse time lowering to the reference's
// exact text, the policy rules in the core's order, the canonical boundary and the routes on canonical
// readings.
const fieldDefs = JSON.parse(readFileSync(join(dir, "field_definitions.json"), "utf-8"));
let fieldPass = 0;
let fieldTotal = 0;
const fieldFail = (what, detail) => { failures++; console.error(`FIELD DEFINITIONS MISMATCH  ${what}\n  ${detail}`); };
for (const conversion of fieldDefs.conversion) {
  fieldTotal++;
  const [reason, canonical] = canonicalValue(parseDefinition("value", conversion.definition), conversion.raw);
  const want = conversion.refused !== undefined ? [conversion.refused, null] : [null, conversion.canonical];
  if (reason === want[0] && canonical === want[1]) fieldPass++;
  else fieldFail(`conversion ${JSON.stringify(conversion)}`, `got ${JSON.stringify([reason, canonical])}`);
}
for (const policy of fieldDefs.policies) {
  fieldTotal++;
  let graph = null;
  let refusal = null;
  try {
    graph = parse(policy.flow);
  } catch (err) {
    if (!(err instanceof FieldDefinitionError)) { fieldFail(policy.name, `crashed: ${err}`); continue; }
    refusal = err;
  }
  if (policy.accepted !== (refusal === null)) {
    fieldFail(policy.name, refusal ? `refused ${refusal.cause}: ${refusal.message}` : "parsed although the reference refuses it");
    continue;
  }
  if (refusal !== null) {
    const causes = refusal.problems.map((found) => found.cause);
    const registered = causes.every((cause) => coreCauseCode(cause) !== null);
    if (refusal.cause === policy.cause && JSON.stringify(causes) === JSON.stringify(policy.causes) && registered) fieldPass++;
    else fieldFail(policy.name, `cause ${refusal.cause} ${JSON.stringify(causes)}, want ${policy.cause} ${JSON.stringify(policy.causes)}`);
    continue;
  }
  const edges = graph.nodes.s.edges;
  let problem = null;
  if (JSON.stringify(edges.map(([, cond]) => cond)) !== JSON.stringify(policy.lowered)) problem = `lowered ${JSON.stringify(edges.map(([, cond]) => cond))}`;
  for (const probe of policy.probes) {
    const [target] = firstDeterministic(edges, probe.reading);
    if (problem === null && target !== probe.route) problem = `probe ${JSON.stringify(probe.reading)} routed to ${target}, want ${probe.route}`;
  }
  for (const refused of policy.refused_readings) {
    const got = systemBoundary(graph, refused.reading);
    if (problem === null && JSON.stringify(got) !== JSON.stringify([refused.field, refused.reason])) problem = `reading ${JSON.stringify(refused.reading)} refused as ${JSON.stringify(got)}`;
  }
  if (problem === null) fieldPass++;
  else fieldFail(policy.name, problem);
}
console.log(`field defs: ${fieldPass}/${fieldTotal}`);

if (failures) {
  console.error(`\nNON-CONFORMANT: ${failures} mismatch(es)`);
  process.exit(1);
}
console.log("\nCONFORMANT — this implementation matches the frozen kernel spec.");

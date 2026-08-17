// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// run_p1_conformance.mjs — verify P1 (locked semantic routing) against frozen vectors.
//
//   node portable/run_p1_conformance.mjs [conformance-dir]
//
// Reads portable/conformance/locked_flows.json and checks the JS kernel routes identically
// to the Python reference on every P1 fixture.  Each fixture includes a synthetic lockfile
// and an embedMap so no real embedder is needed.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parse, run, decodeVec } from "./prismpath.mjs";

const dir = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), "conformance");
let failures = 0;

const doc = JSON.parse(readFileSync(join(dir, "locked_flows.json"), "utf-8"));
let pass = 0;

function scriptedAgent(script) {
  const used = {};
  return (node, _instruction, _state) => {
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

for (const fx of doc.cases) {
  let got;
  try {
    const embedMap = fx.embedMap || {};
    const embed = (text) => {
      const b64 = embedMap[text];
      if (b64) return decodeVec(b64);
      return new Float32Array(fx.lock.embedder.dim);
    };

    const g = parse(fx.flow);
    const res = run(g, scriptedAgent(fx.script || {}), {
      maxSteps: fx.maxSteps ?? 25,
      start: fx.start ?? null,
      state: fx.state ? JSON.parse(JSON.stringify(fx.state)) : null,
      lock: fx.lock,
      embed,
      humanFloor: fx.humanFloor ?? null,
    });
    got = {
      path: res.path,
      stopped: res.stopped,
      pending_node: res.pending ? (res.pending.node ?? null) : null,
      would_pick: res.pending ? (res.pending.would_pick ?? null) : null,
    };
  } catch (e) {
    got = { error: String(e.message ?? e) };
  }

  const want = fx.expect;
  const same = JSON.stringify(got) === JSON.stringify({
    path: want.path,
    stopped: want.stopped,
    pending_node: want.pending_node ?? null,
    would_pick: want.would_pick ?? null,
  });
  if (same) { pass++; continue; }
  failures++;
  console.error(`P1 MISMATCH  ${fx.name}\n  expect=${JSON.stringify(want)}\n  got=   ${JSON.stringify(got)}`);
}
console.log(`P1 locked flows: ${pass}/${doc.cases.length}`);

if (failures) {
  console.error(`\nNON-CONFORMANT: ${failures} P1 mismatch(es)`);
  process.exit(1);
}
console.log("\nP1 CONFORMANT — JS kernel matches the frozen P1 spec.");

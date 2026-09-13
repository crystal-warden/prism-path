// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// run_conformance.mjs — replay conformance fixtures through the PORTABLE kernel.
//
// The cross-language check behind item #5's claim: the Python engine and this port route
// IDENTICALLY on the portable subset. The Python side (tests/test_portable_conformance.py)
// runs the same fixtures through engine.run and diffs the results.
//
//   node portable/run_conformance.mjs <fixtures.json>   ->  JSON results on stdout
//
// Fixture: {name, flow, script, maxSteps?, start?, state?}. `script` maps node name -> a
// LIST of outcomes consumed in visit order (the last entry repeats if visits exceed it).
// An outcome of {"__raise__": "msg"} makes the scripted worker THROW (exercises the error
// tier). Result per fixture: {name, path, stopped, pending, error?}.
import { readFileSync } from "node:fs";
import { parse, run, scriptedAgent } from "./prismpath.mjs";

// The sibling runners default to the committed corpus when called bare; this one cannot, because the
// fixture set is the whole argument. Say so and exit, rather than letting readFileSync throw an
// ERR_INVALID_ARG_TYPE stack at someone who simply forgot the path.
const fixturesPath = process.argv[2];
if (!fixturesPath) {
  process.stderr.write("usage: node run_conformance.mjs <fixtures.json>\n");
  process.exit(2);
}
const fixtures = JSON.parse(readFileSync(fixturesPath, "utf-8"));
const results = [];
for (const fx of fixtures) {
  try {
    const graph = parse(fx.flow);
    const res = run(graph, scriptedAgent(fx.script || {}), {
      maxSteps: fx.maxSteps ?? 25,
      start: fx.start ?? null,
      state: fx.state ?? null,
    });
    results.push({ name: fx.name, path: res.path, stopped: res.stopped,
                   pending: res.pending ?? null });
  } catch (err) {
    results.push({ name: fx.name, error: String(err.message ?? err) });
  }
}
process.stdout.write(JSON.stringify(results, null, 1));

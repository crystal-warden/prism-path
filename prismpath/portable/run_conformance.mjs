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
import { parse, run } from "./prismpath.mjs";

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

const fixtures = JSON.parse(readFileSync(process.argv[2], "utf-8"));
const results = [];
for (const fx of fixtures) {
  try {
    const g = parse(fx.flow);
    const res = run(g, scriptedAgent(fx.script || {}), {
      maxSteps: fx.maxSteps ?? 25,
      start: fx.start ?? null,
      state: fx.state ?? null,
    });
    results.push({ name: fx.name, path: res.path, stopped: res.stopped,
                   pending: res.pending ?? null });
  } catch (e) {
    results.push({ name: fx.name, error: String(e.message ?? e) });
  }
}
process.stdout.write(JSON.stringify(results, null, 1));

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// Unit tests for the portable kernel: `node --test portable/`. Zero installed dependencies, but not
// standalone: three siblings in this directory have to be present, because the tests read
// conformance/locked_flows.json, bundle_engine.mjs and prismpath.mjs itself from disk.
// The cross-language conformance suite (run_conformance.mjs) is the deeper check; these pin
// the Python-exact predicate semantics and the engine loop's suspension shapes directly.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parse, run, evalCondition, checkPredicate, portabilityViolations, eventTarget,
  isDeterministic, isError, isEvent, isSemantic, eventName, pyTruthy, PredicateError,
  lockedRoute, decodeVec,
} from "./prismpath.mjs";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// ------------------------------------------------------------------ condition tiers
test("condition tier classification", () => {
  assert.ok(isDeterministic("when x > 3") && isDeterministic("always") && isDeterministic("else"));
  assert.ok(isError("on error") && isError("on error when error_count >= 3"));
  assert.ok(isEvent("on event payment") && isEvent("on timeout"));
  assert.equal(eventName("on event payment_confirmed"), "payment_confirmed");
  assert.equal(eventName("on timeout"), "__timeout__");
  assert.ok(isSemantic("the fix looks correct"));
  assert.ok(!isSemantic("when ok"));
});

// ------------------------------------------------------------------ predicate semantics
test("basic comparisons and chaining", () => {
  assert.equal(evalCondition("when x == 3", { x: 3 }), true);
  assert.equal(evalCondition("when x != 3", { x: 4 }), true);
  assert.equal(evalCondition("when 1 < x < 5", { x: 3 }), true);
  assert.equal(evalCondition("when 1 < x < 5", { x: 7 }), false);
});

test("missing field is unsatisfied, never a crash", () => {
  assert.equal(evalCondition("when nope > 3", {}), false);
  assert.equal(evalCondition("when nope == None", {}), true);        // unknown name -> None
  assert.equal(evalCondition("when not nope", {}), true);            // None is falsy
});

test("type mismatch: ordering unsatisfied; not-in satisfied", () => {
  assert.equal(evalCondition("when x > 3", { x: "high" }), false);   // str vs int -> unsatisfied
  assert.equal(evalCondition("when x in y", { x: 1, y: 42 }), false);
  assert.equal(evalCondition("when x not in y", { x: 1, y: 42 }), true);   // failure satisfies not-in
});

test("True/False/None are constants; lowercase true/false are FIELD NAMES", () => {
  assert.equal(evalCondition("when x == True", { x: true }), true);
  assert.equal(evalCondition("when x == None", { x: null }), true);
  // `true` parses as a Name -> ctx['true'] (absent -> None) -> x == None is false for x=true
  assert.equal(evalCondition("when x == true", { x: true }), false);
  assert.equal(evalCondition("when x == true", { x: true, true: true }), true);
});

test("booleans compare numerically, like Python", () => {
  assert.equal(evalCondition("when flag == 1", { flag: true }), true);      // True == 1
  assert.equal(evalCondition("when flag == 0", { flag: false }), true);
  assert.equal(evalCondition("when flag < 2", { flag: true }), true);       // True < 2
});

test("membership: lists, substrings, object keys", () => {
  assert.equal(evalCondition('when a in ["contain", "watch"]', { a: "watch" }), true);
  assert.equal(evalCondition('when a in ("contain", "watch")', { a: "watch" }), true);   // tuple literal
  assert.equal(evalCondition('when "xyz" in text', { text: "an error happened" }), false);
  assert.equal(evalCondition('when "error" in text', { text: "an error happened" }), true);   // substring
  assert.equal(evalCondition("when k in obj", { k: "a", obj: { a: 1 } }), true);
  assert.equal(evalCondition("when 1 in xs", { xs: [1.0, 2] }), true);      // 1 == 1.0
});

test("python truthiness: [] and {} are falsy", () => {
  assert.equal(pyTruthy([]), false);
  assert.equal(pyTruthy({}), false);
  assert.equal(pyTruthy([0]), true);
  assert.equal(evalCondition("when items", { items: [] }), false);
  assert.equal(evalCondition("when items and ok", { items: [1], ok: true }), true);
});

test("keywords: always/else/false; empty and unsafe predicates are flagged", () => {
  assert.equal(evalCondition("always", {}), true);
  assert.equal(evalCondition("else", {}), true);
  assert.equal(evalCondition("never", {}), false);
  // parity quirk: bare "when " strips to "when", fails is_deterministic, and is treated as a
  // SEMANTIC edge in Python -> so check_predicate returns [] there, and must here too.
  assert.deepEqual(checkPredicate("when "), []);
  assert.equal(isSemantic("when "), true);
  assert.ok(checkPredicate("when f(x)").length > 0);                 // call -> disallowed
  assert.ok(checkPredicate("when x.y").length > 0);                  // attribute -> disallowed
  assert.ok(checkPredicate("when x + 1 > 2").length > 0);            // arithmetic -> disallowed
  assert.deepEqual(checkPredicate("when -1 < x"), []);               // signed integer literal -> allowed (folds)
  assert.ok(checkPredicate("when x >= -0.5").length > 0);            // sign on a float -> still disallowed
  assert.ok(checkPredicate("when -y < x").length > 0);               // sign on a field -> still disallowed
  assert.throws(() => evalCondition("when f(x)", {}), PredicateError);
});

// ------------------------------------------------------------------ parser + engine
const FLOW = `---
name: demo
start: triage
---

## triage
Decide.
@emits(action)
-> fix: when action == "fix"
-> wait_help: when action == "help"
-> boom: when action == "boom"
-> done: else

## fix
-> triage: when visits < 2
-> done: else

## wait_help
-> done: on event resolved
-> gave_up: on timeout

## boom
-> recovered: on error when error_count >= 2
-> boom: on error

## recovered
Recovered.

## gave_up
Gave up.

## done
Done.
`;

test("parse: nodes, edges, annotations, terminal, start", () => {
  const graph = parse(FLOW);
  assert.equal(graph.start, "triage");
  assert.deepEqual(Object.keys(graph.nodes.triage.annotations), ["emits"]);
  assert.equal(graph.nodes.done.edges.length, 0);
  assert.equal(graph.nodes.triage.edges.length, 4);
});

test("engine: deterministic routing with a visits loop", () => {
  const graph = parse(FLOW);
  const agent = (nodeName) => (nodeName === "triage" ? { text: "t", action: "fix" } : { text: nodeName });
  const res = run(graph, agent);
  // triage -> fix -> triage(visits check) ... fix loops back once (visits<2), then done
  assert.equal(res.stopped, "terminal");
  assert.deepEqual(res.path, ["triage", "fix", "triage", "fix", "done"]);
});

test("engine: wait suspension exposes awaiting events; eventTarget resumes", () => {
  const graph = parse(FLOW);
  const agent = (nodeName) => (nodeName === "triage" ? { text: "t", action: "help" }
                                              : { text: "waiting", wait: true, timeout_s: 60 });
  const res = run(graph, agent);
  assert.equal(res.stopped, "waiting");
  assert.deepEqual(res.pending.awaiting.sort(), ["__timeout__", "resolved"]);
  assert.equal(eventTarget(graph, "wait_help", "resolved"), "done");
  assert.equal(eventTarget(graph, "wait_help", "__timeout__"), "gave_up");
  // re-enter at the event target with the suspended state: the portable resume
  const res2 = run(graph, (targetNode) => ({ text: targetNode }), { start: "done", state: res.state });
  assert.equal(res2.stopped, "terminal");
});

test("engine: error tier with error_count escalation", () => {
  const graph = parse(FLOW);
  let calls = 0;
  const agent = (nodeName) => {
    if (nodeName === "triage") return { text: "t", action: "boom" };
    if (nodeName === "boom") { calls++; throw new Error("kapow"); }
    return { text: nodeName };
  };
  const res = run(graph, agent);
  // 1st raise -> error_count=1 -> bare `on error` self-loop; 2nd raise -> >=2 -> recovered
  assert.equal(res.stopped, "terminal");
  assert.equal(res.path.at(-1), "recovered");
  assert.equal(calls, 2);
});

test("engine: needs_human suspension", () => {
  const graph = parse(FLOW);
  const agent = (nodeName) => (nodeName === "triage" ? { text: "unsure", needs_human: true, reason: "?" }
                                              : { text: nodeName });
  const res = run(graph, agent);
  assert.equal(res.stopped, "needs_human");
  assert.equal(res.pending.reason, "?");
});

test("engine: spawn implies wait, spec passed through", () => {
  const graph = parse(`---
name: p
start: d
---

## d
-> agg: on event all_done

## agg
Done.
`);
  const res = run(graph, () => ({ text: "d", spawn: { items: [1, 2] } }));
  assert.equal(res.stopped, "waiting");
  assert.deepEqual(res.pending.spawn, { items: [1, 2] });
});

test("run refuses a non-portable flow", () => {
  const graph = parse(`---
name: p
start: a
---

## a
-> b: it seems finished

## b
Done.
`);
  assert.deepEqual(portabilityViolations(graph).map((violation) => violation.node), ["a"]);
  assert.throws(() => run(graph, () => "x"), /not portable/);
});

test("engine: stuck when deterministic-only node matches nothing", () => {
  const graph = parse(`---
name: p
start: a
---

## a
-> b: when impossible == 1

## b
Done.
`);
  const res = run(graph, () => ({ text: "t" }));
  assert.equal(res.stopped, "stuck");
});

test("lockedRoute (exported): routes one text against locked vectors, matching run()'s decision", () => {
  // Reuse the frozen P1 corpus's first fixture so the exported single-step surface is pinned
  // to the same answers the engine gives: the export changes surface, never behavior.
  const doc = JSON.parse(
    readFileSync(new URL("./conformance/locked_flows.json", import.meta.url), "utf-8"),
  );
  const fixture = doc.cases.find((testCase) => testCase.name === "locked_basic_route") ?? doc.cases[0];
  const graph = parse(fixture.flow);
  const startNode = fixture.start ?? graph.start;
  const semEdges = graph.nodes[startNode].edges.filter(([, conditionText]) => isSemantic(conditionText));
  const embed = (text) => {
    const b64 = (fixture.embedMap || {})[text];
    return b64 ? decodeVec(b64) : new Float32Array(fixture.lock.embedder.dim);
  };
  const text = Object.keys(fixture.embedMap || {})[0];
  const decision = lockedRoute(text, semEdges, fixture.lock, embed);
  assert.equal(decision.target, fixture.expect.path[1]); // the step run() routes to from start
  assert.ok(decision.info.locked && decision.info.score > 0);
  assert.ok(typeof decision.info.margin === "number");
});

test("lockedRoute refuses a locked vector of the wrong width instead of scoring it NaN", () => {
  // A lock written by a different embedder is the realistic way the widths diverge. Before the
  // check the loop read past the shorter side, the score came back NaN, NaN lost every comparison,
  // and the flow routed somewhere the lock never endorsed with nothing reported anywhere.
  const semanticEdges = [["approve", "the work is correct"], ["revise", "the work needs changes"]];
  const lockfile = {
    conditions: {
      "the work is correct": new Float32Array([1, 0, 0, 0]),
      "the work needs changes": new Float32Array([0, 1, 0]),   // one element short
    },
  };
  const embed = () => new Float32Array([1, 0, 0, 0]);
  assert.throws(
    () => lockedRoute("it is correct", semanticEdges, lockfile, embed),
    /locked vector width 3 does not match the embedding's 4/,
  );
});

// ------------------------------------------------------------------ the compiled bundle
// `prismpath compile` emits this kernel, a serialized graph, an embedded lock and
// bundle_engine.mjs as one file. Assembled the same way here (cli.py _build_compile_bundle is
// the compiler of record) so the shipped engine is exercised in the shape it is shipped in.
const STRIP_BEGIN = "// prismpath-bundle-strip-begin";
const STRIP_END = "// prismpath-bundle-strip-end";

function bundleEngineSource() {
  const source = readFileSync(new URL("./bundle_engine.mjs", import.meta.url), "utf-8");
  const beginIndex = source.indexOf(STRIP_BEGIN);
  const endIndex = source.indexOf(STRIP_END);
  assert.ok(beginIndex >= 0 && endIndex > beginIndex, "bundle_engine.mjs must carry its strip markers");
  return source.slice(0, beginIndex) + source.slice(source.indexOf("\n", endIndex) + 1);
}

async function importBundle(graph, embeddedLock) {
  const kernelSource = readFileSync(new URL("./prismpath.mjs", import.meta.url), "utf-8");
  const bundleSource = [
    kernelSource,
    `\nexport const GRAPH = ${JSON.stringify(graph)};\n`,
    `export const EMBEDDED_LOCK = ${JSON.stringify(embeddedLock)};\n`,
    bundleEngineSource(),
    "\nexport function runFlow(agent, opts = {}) {\n  return runCompiled(GRAPH, EMBEDDED_LOCK, agent, opts);\n}\n",
  ].join("\n");
  assert.ok(!bundleSource.includes('from "./prismpath.mjs"'), "a bundle is one file, it imports no kernel");
  const bundlePath = join(mkdtempSync(join(tmpdir(), "prismpath-bundle-")), "flow.bundle.mjs");
  writeFileSync(bundlePath, bundleSource, "utf-8");
  return import(pathToFileURL(bundlePath).href);
}

function bundleNode(name, edges, instruction = "step") {
  return { name, instruction, terminal: edges.length === 0, annotations: {}, edges };
}

// float16 bit patterns for the few exact values these fixtures use: the compiler stores lock
// vectors as float16, and a test that writes the bytes by hand needs no encoder of its own.
const HALF_BITS = new Map([[0, 0x0000], [0.25, 0x3400], [0.5, 0x3800], [1, 0x3c00]]);

function halfVectorBase64(values) {
  const bytes = Buffer.alloc(values.length * 2);
  values.forEach((value, valueIndex) => {
    const bits = HALF_BITS.get(value);
    assert.ok(bits !== undefined, `fixture value ${value} has no float16 pattern here`);
    bytes.writeUInt16LE(bits, valueIndex * 2);
  });
  return bytes.toString("base64");
}

test("compiled bundle: a P0 flow runs on the emitted file", async () => {
  const graph = {
    name: "p0_flow",
    start: "first",
    nodes: {
      first: bundleNode("first", [["second", "when x == 1"], ["done", "else"]]),
      second: bundleNode("second", [["done", "always"]]),
      done: bundleNode("done", []),
    },
  };
  const bundle = await importBundle(graph, null);
  const result = await bundle.runFlow(async (node) => (node === "first" ? { x: 1 } : "always"));
  assert.deepEqual(result.path, ["first", "second", "done"]);
  assert.equal(result.stopped, "terminal");
  assert.equal(result.steps[0].info.used, "deterministic");
});

test("compiled bundle: an async worker's throw takes the error edge", async () => {
  const graph = {
    name: "p0_error",
    start: "work",
    nodes: {
      work: bundleNode("work", [["recover", "on error"], ["done", "always"]]),
      recover: bundleNode("recover", [["done", "always"]]),
      done: bundleNode("done", []),
    },
  };
  const bundle = await importBundle(graph, null);
  const result = await bundle.runFlow(async (node) => {
    if (node === "work") throw new Error("worker down");
    return "always";
  });
  assert.deepEqual(result.path, ["work", "recover", "done"]);
  assert.equal(result.steps[0].info.used, "error");
});

test("compiled bundle: the embedded float16 lock routes a semantic edge", async () => {
  const graph = {
    name: "p1_flow",
    start: "triage",
    nodes: {
      triage: bundleNode("triage", [["ship", "it worked"], ["escalate", "it failed"]]),
      ship: bundleNode("ship", [["done", "always"]]),
      escalate: bundleNode("escalate", [["done", "always"]]),
      done: bundleNode("done", []),
    },
  };
  const embeddedLock = {
    delta: 0.05,
    conditions: {
      "it worked": halfVectorBase64([1, 0, 0, 0]),
      "it failed": halfVectorBase64([0, 1, 0, 0]),
    },
  };
  const bundle = await importBundle(graph, embeddedLock);
  const worker = async () => "the build is green";
  const embed = async () => Float32Array.from([1, 0, 0, 0]);

  const routed = await bundle.runFlow(worker, { embed });
  assert.deepEqual(routed.path, ["triage", "ship", "done"]);
  assert.equal(routed.steps[0].info.locked, true);
  assert.equal(routed.steps[0].info.score, 1);

  // Same decision, below the absolute floor: engine.py suspends instead of guessing, and so does
  // the bundle now. A narrow top1/top2 margin on its own is NOT a suspension in either engine.
  const halved = await bundle.runFlow(worker, { embed: async () => Float32Array.from([0.5, 0, 0, 0]), humanFloor: 0.9 });
  assert.equal(halved.stopped, "needs_human");
  assert.equal(halved.pending.reason, "router confidence 0.500 < human_floor 0.9");
  assert.equal(halved.pending.would_pick, "ship");
});

test("compiled bundle: a semantic flow refuses to run without an embedder", async () => {
  const graph = {
    name: "p1_no_embed",
    start: "triage",
    nodes: {
      triage: bundleNode("triage", [["done", "it worked"]]),
      done: bundleNode("done", []),
    },
  };
  const bundle = await importBundle(graph, { delta: 0.05, conditions: { "it worked": halfVectorBase64([1, 0, 0, 0]) } });
  await assert.rejects(() => bundle.runFlow(async () => "green"), /needs an embedder/);
});

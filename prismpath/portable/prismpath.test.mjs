// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// Unit tests for the portable kernel — `node --test portable/`. Zero dependencies.
// The cross-language conformance suite (run_conformance.mjs) is the deeper check; these pin
// the Python-exact predicate semantics and the engine loop's suspension shapes directly.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parse, run, evalCondition, checkPredicate, portabilityViolations, eventTarget,
  isDeterministic, isError, isEvent, isSemantic, eventName, pyTruthy, PredicateError,
  lockedRoute, decodeVec,
} from "./prismpath.mjs";
import { readFileSync } from "node:fs";

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
  // SEMANTIC edge in Python — so check_predicate returns [] there, and must here too.
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
  const g = parse(FLOW);
  assert.equal(g.start, "triage");
  assert.deepEqual(Object.keys(g.nodes.triage.annotations), ["emits"]);
  assert.equal(g.nodes.done.edges.length, 0);
  assert.equal(g.nodes.triage.edges.length, 4);
});

test("engine: deterministic routing with a visits loop", () => {
  const g = parse(FLOW);
  const agent = (node) => (node === "triage" ? { text: "t", action: "fix" } : { text: node });
  const res = run(g, agent);
  // triage -> fix -> triage(visits check) ... fix loops back once (visits<2), then done
  assert.equal(res.stopped, "terminal");
  assert.deepEqual(res.path, ["triage", "fix", "triage", "fix", "done"]);
});

test("engine: wait suspension exposes awaiting events; eventTarget resumes", () => {
  const g = parse(FLOW);
  const agent = (node) => (node === "triage" ? { text: "t", action: "help" }
                                             : { text: "waiting", wait: true, timeout_s: 60 });
  const res = run(g, agent);
  assert.equal(res.stopped, "waiting");
  assert.deepEqual(res.pending.awaiting.sort(), ["__timeout__", "resolved"]);
  assert.equal(eventTarget(g, "wait_help", "resolved"), "done");
  assert.equal(eventTarget(g, "wait_help", "__timeout__"), "gave_up");
  // re-enter at the event target with the suspended state — the portable resume
  const res2 = run(g, (n) => ({ text: n }), { start: "done", state: res.state });
  assert.equal(res2.stopped, "terminal");
});

test("engine: error tier with error_count escalation", () => {
  const g = parse(FLOW);
  let calls = 0;
  const agent = (node) => {
    if (node === "triage") return { text: "t", action: "boom" };
    if (node === "boom") { calls++; throw new Error("kapow"); }
    return { text: node };
  };
  const res = run(g, agent);
  // 1st raise -> error_count=1 -> bare `on error` self-loop; 2nd raise -> >=2 -> recovered
  assert.equal(res.stopped, "terminal");
  assert.equal(res.path.at(-1), "recovered");
  assert.equal(calls, 2);
});

test("engine: needs_human suspension", () => {
  const g = parse(FLOW);
  const agent = (node) => (node === "triage" ? { text: "unsure", needs_human: true, reason: "?" }
                                             : { text: node });
  const res = run(g, agent);
  assert.equal(res.stopped, "needs_human");
  assert.equal(res.pending.reason, "?");
});

test("engine: spawn implies wait, spec passed through", () => {
  const g = parse(`---
name: p
start: d
---

## d
-> agg: on event all_done

## agg
Done.
`);
  const res = run(g, () => ({ text: "d", spawn: { items: [1, 2] } }));
  assert.equal(res.stopped, "waiting");
  assert.deepEqual(res.pending.spawn, { items: [1, 2] });
});

test("run refuses a non-portable flow", () => {
  const g = parse(`---
name: p
start: a
---

## a
-> b: it seems finished

## b
Done.
`);
  assert.deepEqual(portabilityViolations(g).map((v) => v.node), ["a"]);
  assert.throws(() => run(g, () => "x"), /not portable/);
});

test("engine: stuck when deterministic-only node matches nothing", () => {
  const g = parse(`---
name: p
start: a
---

## a
-> b: when impossible == 1

## b
Done.
`);
  const res = run(g, () => ({ text: "t" }));
  assert.equal(res.stopped, "stuck");
});

test("lockedRoute (exported): routes one text against locked vectors, matching run()'s decision", () => {
  // Reuse the frozen P1 corpus's first fixture so the exported single-step surface is pinned
  // to the same answers the engine gives — the export changes surface, never behavior.
  const doc = JSON.parse(
    readFileSync(new URL("./conformance/locked_flows.json", import.meta.url), "utf-8"),
  );
  const fx = doc.cases.find((c) => c.name === "locked_basic_route") ?? doc.cases[0];
  const g = parse(fx.flow);
  const start = fx.start ?? g.start;
  const semEdges = g.nodes[start].edges.filter(([, c]) => isSemantic(c));
  const embed = (text) => {
    const b64 = (fx.embedMap || {})[text];
    return b64 ? decodeVec(b64) : new Float32Array(fx.lock.embedder.dim);
  };
  const text = Object.keys(fx.embedMap || {})[0];
  const d = lockedRoute(text, semEdges, fx.lock, embed);
  assert.equal(d.target, fx.expect.path[1]); // the step run() routes to from start
  assert.ok(d.info.locked && d.info.score > 0);
  assert.ok(typeof d.info.margin === "number");
});

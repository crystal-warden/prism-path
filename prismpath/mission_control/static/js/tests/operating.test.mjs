// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The operating interface's render functions and request builders, given fixture JSON shaped like the
// console's answers: the discovered sprints, the human queue with event delivery and nested children,
// the policy host, the cause monitor with its sparklines, the lens and the fan-out trees. None of them
// touches the document, so they run here without a browser.
import { test } from "node:test";
import assert from "node:assert/strict";

import { markupOf } from "../markup.mjs";
import { PATHS, POSTURE_READ_ONLY, routeAvailable } from "../paths.mjs";
import { causesQuery, eventLabel, fillSeries, formatAge, renderCauseMonitor, renderFanouts, renderLens,
         renderPolicyHost, renderQueueItems, renderSprintList, sparkline } from "../operating.mjs";

const text = markup => markupOf(markup);

test("the discovered sprints show heartbeat age, gate verdict and state, and the followed one is marked", () => {
  const sprints = [
    { proj: "/s/alpha", name: "alpha", age: 3.25, running: true, iteration: 4, valid: true },
    { proj: "/s/b\"x", name: "b\"x<i>", age: 600, running: false, valid: false, done: true },
    { proj: "/s/c", name: "c", age: 7300, running: false },
  ];
  const full = text(renderSprintList(sprints, "/s/alpha", true));
  const rows = full.split('<div class="sprint');
  assert.equal(rows.length, 4);
  assert.ok(rows[1].startsWith(" followed") && rows[1].includes("following") && !rows[1].includes("data-select"));
  assert.ok(rows[1].includes("3.3 s") && rows[1].includes("gate ✓") && rows[1].includes("running") && rows[1].includes("it 4"));
  assert.ok(rows[2].includes('data-select="/s/b&quot;x"') && rows[2].includes("b&quot;x&lt;i&gt;"));
  assert.ok(rows[2].includes("10 min") && rows[2].includes("gate ✗") && rows[2].includes("done"));
  assert.ok(rows[3].includes("2.0 h") && rows[3].includes("no gate verdict") && rows[3].includes("stale"));
  const readOnly = text(renderSprintList(sprints, "/s/alpha", false));
  assert.ok(!readOnly.includes("data-select") && readOnly.includes("unavailable in the read-only posture"));
  assert.ok(text(renderSprintList([], "", true)).includes("no sprints discovered"));
  assert.equal(formatAge(undefined), "?");
});

const QUEUE = [
  { id: "h1", stopped: "needs_human", flow: "gate", node: "classify", reason: "low confidence", would_pick: "approve",
    candidates: [{ target: "approve", condition: "looks fine", score: 0.8123 }, { target: "deny", condition: "looks bad", score: null }],
    decision: { choose: "approve", decided_by: "console/operating/fp1" } },
  { id: "p.children/c2", stopped: "waiting", flow: "watch", node: "hold", child_of: "p", awaiting: ["stand_down", "__timeout__"],
    timeout_s: 60, pending_event: null, fanout: false },
  { id: "w\"1", stopped: "waiting", node: "hold", awaiting: ["stand_down"],
    pending_event: { event: "stand_down", decided_by: "console/operating/fp1" } },
];

test("the queue offers each candidate edge with its router score and each awaited event", () => {
  const markup = text(renderQueueItems(QUEUE, { canDecide: true, canDeliver: true }));
  const cards = markup.split('<div class="q-item');
  assert.equal(cards.length, 4);
  assert.ok(cards[1].includes('data-decide="h1" data-choose="approve"') && cards[1].includes('data-choose="deny"'));
  assert.ok(cards[1].includes("0.81") && cards[1].includes("would pick") && cards[1].includes("low confidence"));
  assert.ok(cards[1].includes("decided approve by console/operating/fp1") && cards[1].includes("applied at the next resume"));
  assert.ok(cards[2].includes("child of p") && cards[2].includes(">p.children/c2<"));
  assert.ok(cards[2].includes('data-deliver="p.children/c2" data-event="stand_down"'));
  assert.ok(cards[2].includes('data-event="__timeout__"') && cards[2].includes(">timeout<") && cards[2].includes("60 s"));
  assert.ok(cards[3].includes('data-deliver="w&quot;1"'));
  assert.ok(cards[3].includes("event stand_down recorded by console/operating/fp1"));
  assert.ok(!markup.includes("<input"), "a run with candidates or events needs no typed choice");
});

test("in the read only posture the queue says why it offers no decision and no event", () => {
  const markup = text(renderQueueItems(QUEUE, { canDecide: false, canDeliver: false }));
  assert.ok(!markup.includes("data-decide") && !markup.includes("data-deliver"));
  assert.ok(markup.includes("deciding is unavailable in the read-only posture"));
  assert.ok(markup.includes("delivering an event is unavailable in the read-only posture"));
  assert.ok(markup.includes("0.81"), "the evidence packet is still shown");
});

test("a waiting run with no event edges says so", () => {
  const markup = text(renderQueueItems([{ id: "w", stopped: "waiting", awaiting: [] }], { canDecide: true, canDeliver: true }));
  assert.ok(markup.includes("no event edges") && !markup.includes("data-deliver"));
  assert.equal(eventLabel("__timeout__"), "timeout");
  assert.equal(eventLabel("stand_down"), "stand_down");
});

test("the policy host shows what the deployment runs, its image check, signing and swap history", () => {
  const report = {
    state_dir: "edge/state", evidence_root: "/ev", active: "ab".repeat(32), version: 3, since: "2026-11-16T09:00:00+00:00",
    unsigned: false, envelope_id: "env1", overlay_of: "cd".repeat(32), image_file: "image-3.ppt", image_ok: true,
    reason: null, pending: false,
    log: { present: true, events: 2, verifies: true, root: "ef".repeat(32), skipped: [] },
    signing: { status: "signed-unpinned", statements: 2, keys: ["k1"] },
    history: [{ idx: 0, action: "swap", actor: "host", ts_us: 1_700_000_000_000_000, data: { version: 2 } },
              { idx: 1, action: "swap", actor: "host<b>", ts_us: 1_700_000_100_000_000, data: { version: 3 } }],
  };
  const markup = text(renderPolicyHost(report));
  assert.ok(markup.includes("abababababababab") && markup.includes("version 3") && markup.includes("env1"));
  assert.ok(markup.includes("since 2026-11-16T09:00:00+00:00"));
  assert.ok(markup.includes("console: the image matches the record ✓"));
  assert.ok(markup.includes("overlay of cdcdcdcdcdcdcdcd"));
  assert.ok(markup.includes("console: swaps.log verifies ✓") && markup.includes("signed-unpinned"));
  assert.ok(markup.includes("host&lt;b&gt;") && markup.indexOf("version 3</span>") < markup.lastIndexOf("version 2"));
  const broken = text(renderPolicyHost({ ...report, image_ok: false, reason: "image:digest-mismatch", unsigned: true,
                                          pending: true, log: { present: false }, signing: undefined, history: [] }));
  assert.ok(broken.includes("console: the image does not match ✗") && broken.includes("image:digest-mismatch"));
  assert.ok(broken.includes("unsigned") && broken.includes("a swap is pending") && broken.includes("no swaps.log"));
  assert.ok(text(renderPolicyHost({ state_dir: "x", active: null, reason: "record:missing", log: { present: false } }))
    .includes("no active policy (record:missing)"));
});

const SERIES = {
  path: "/ev/run.audit.jsonl", bucket_s: 60, events: 6, untimed: 1, verdict_of: "console",
  buckets: [
    { start: 600, by_cause: { 2: 2 }, by_action: { decision: 2, swap: 1 } },
    { start: 660, by_cause: { 34: 1 }, by_action: { decision: 1 } },
    { start: 840, by_cause: { 2: 1, 0: 1 }, by_action: { decision: 2 } },
  ],
  causes: { 2: { code: 2, name: "parse:bad", class: "refuse", label: "2 parse:bad" },
            34: { code: 34, name: "route:needs-human", class: "park", label: "34 route:needs-human" },
            0: { code: 0, clean: true, label: "0 clean" } },
};

test("the sparse cause series is filled to every bucket of the window", () => {
  const filled = fillSeries(SERIES);
  assert.deepEqual(filled.starts, [600, 660, 720, 780, 840]);
  const byKey = Object.fromEntries(filled.causes.map(row => [row.key, row]));
  assert.deepEqual(byKey["2"].counts, [2, 0, 0, 0, 1]);
  assert.deepEqual(byKey["34"].counts, [0, 1, 0, 0, 0]);
  assert.equal(byKey["2"].total, 3);
  assert.equal(byKey["34"].label, "34 route:needs-human");
  assert.equal(filled.causes[0].key, "2", "the most frequent cause comes first");
  assert.deepEqual(filled.actions.find(row => row.key === "decision").counts, [2, 1, 0, 0, 2]);
  assert.deepEqual(fillSeries({ bucket_s: 60, buckets: [] }).starts, []);
});

test("a sparkline is an SVG polyline scaled to the busiest bucket", () => {
  const svg = text(sparkline([0, 2, 1], { width: 40, height: 10 }));
  assert.ok(svg.startsWith('<svg class="spark" viewBox="0 0 40 10"'));
  assert.ok(svg.includes('points="0,10 20,0 40,5"'), svg);
  assert.ok(!svg.includes("style"));
  assert.ok(text(sparkline([3], { width: 40, height: 10 })).includes('points="0,0 40,0"'));
  assert.ok(text(sparkline([], { width: 40, height: 10 })).includes('points="0,10 40,10"'));
});

test("the cause monitor is a table by cause and by action that says whose counts they are", () => {
  const markup = text(renderCauseMonitor(SERIES));
  assert.ok(markup.includes("console: 6 events") && markup.includes("60 s buckets") && markup.includes("1 untimed"));
  assert.ok(markup.includes("<table") && markup.includes("34 route:needs-human") && markup.includes("park"));
  assert.ok(markup.includes("<svg class=\"spark\""));
  assert.ok(markup.includes(">decision<") && markup.includes(">swap<"));
  assert.ok(text(renderCauseMonitor({ ...SERIES, events: 0, buckets: [] })).includes("no events in the window"));
  assert.deepEqual(causesQuery({ path: " ", bucket: "60", since: "", last: "" }), { bucket_s: "60" });
  assert.deepEqual(causesQuery({ path: "run.audit.jsonl", bucket: "", since: "2026-01-01T00:00:00Z", last: "5" }),
                   { path: "run.audit.jsonl", bucket_s: "3600", since: "2026-01-01T00:00:00Z", last: "5" });
});

test("the lens names who said what to which worker from the records, escaped", () => {
  const payload = { events: [
    { ts: 1, kind: "served", from: "planner", to: "a-model-of-record", substage: "propose", dur_ms: 1200,
      prompt: "<script>x</script>", output: "ok", prompt_len: 18, output_len: 2 },
    { ts: 2, kind: "swarm", from: "coder", to: "hermes:coder", substage: "coder", dur_ms: 5, prompt: "p", output: "o" },
  ] };
  const markup = text(renderLens(payload));
  assert.ok(markup.includes("planner → a-model-of-record") && markup.includes("coder → hermes:coder"));
  assert.ok(markup.indexOf("hermes:coder") < markup.indexOf("a-model-of-record"), "newest first");
  assert.ok(markup.includes("&lt;script&gt;") && !markup.includes("<script>"));
  assert.ok(markup.includes("1.2 s") && markup.includes("propose"));
  assert.ok(text(renderLens({ events: [] })).includes("no recorded interactions"));
});

test("fan-outs render as nested trees with every child's stop state", () => {
  const fanouts = [{ path: "/q/p.json", flow: "/f/parent.md", node: "fan", stopped: "waiting", join: "all_done",
    progress: { n: 2, done: 1, terminal: 1 }, joined: false, children: [
      { item_id: "a", stopped: "terminal", done: true, node: null },
      { item_id: "b<x>", stopped: "error", done: false, child_error: "boom", fanout: {
        path: "/q/p.children/b.json", flow: "/f/child.md", node: "inner", stopped: "waiting", join: "quorum",
        progress: { n: 1, done: 0, terminal: 0 }, children: [{ item_id: "z", stopped: "needs_human", done: false }] } }] }];
  const markup = text(renderFanouts(fanouts));
  assert.ok(markup.startsWith('<div class="tree">'));
  assert.ok(markup.includes("parent.md") && markup.includes("fan") && markup.includes("all_done") && markup.includes("1/2 done"));
  assert.ok(markup.includes("b&lt;x&gt;") && markup.includes("error") && markup.includes("boom"));
  assert.ok(markup.includes("child.md") && markup.includes("quorum") && markup.includes("needs_human"));
  assert.ok(text(renderFanouts([])).includes("no fan-out compositions"));
});

test("the operating writes are exactly the routes the read only posture leaves out", () => {
  for (const path of [PATHS.queueEvent, PATHS.queueDecide, PATHS.sprintSelect, PATHS.sprintAuto]) {
    assert.equal(routeAvailable(POSTURE_READ_ONLY, "POST", path), false, path);
  }
  for (const path of [PATHS.queue, PATHS.policyActive, PATHS.trailCauses, PATHS.interactions, PATHS.fanouts, PATHS.status]) {
    assert.equal(routeAvailable(POSTURE_READ_ONLY, "GET", path), true, path);
  }
});

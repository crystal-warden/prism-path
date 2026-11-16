// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The collector feed's screens given fixture JSON shaped like /feed/live, /feed/causes and /evidence/feed
// answer: the live view with the enforcer's counters and the newest decisions, the chain's status named
// as the console's over the collector's unsigned seals with its holes and findings, a kept session's
// report, and the cause monitor's live source. None touches the document.
import { test } from "node:test";
import assert from "node:assert/strict";

import { markupOf } from "../markup.mjs";
import { PATHS } from "../paths.mjs";
import { feedRequest, renderFeedChain, renderFeedReport, renderLiveFeed } from "../feed.mjs";
import { monitorRequest, renderCauseMonitor } from "../operating.mjs";
import { renderLogList } from "../auditing.mjs";

const text = markup => markupOf(markup);

const CHAIN = {
  format: "prismpath.console-feed/1", session: "5ee55e55aa11bb22cc33dd44ee55ff66", source: "gnet", status: "intact",
  verdict_of: "console", statement: "collector seal, unsigned", signed: false, joined_at: 0, count: 21, received: 21, unframed: 0,
  seals: { checked: 6, adopted: 0, last: { count: 21, root: "ab".repeat(32), trigger: "final" } },
  holes: [], holes_total: 0, missing: 0, unchecked: [], unchecked_total: 0, findings: [], findings_total: 0,
  collector_errors: [], ignored: {}, segments: [{ segment: 0, lines: 36, starting_count: 0, ended: "eof" }],
};

const LIVE = {
  connection: "connected", endpoint: "/run/prismpath-collector/feed.sock", kept: "/ev/collector-feed/5ee5", store: "kept under /ev",
  enforcer: { loaded: 1, image_index: 7, n_rules: 12, counters: { allow: "11", drop: "7", malformed: "2", other: "0" } },
  feed: { clients: 1, dropped: 0 }, collector_count: 21, verdict_of: "console", statement: "collector seal, unsigned",
  chain: CHAIN,
  recent: [
    { kind: "malformed", index: 20, arrived_us: 1763290000123000, cause: null, length: 40 },
    { kind: "decision", index: 18, arrived_us: 1763290000100000, outcome_name: "drop_policy", src_ip: "127.0.0.1", src_port: 40018,
      cause: { code: 32, label: "32 route:no-matching-edge", class: "routing" }, reading: { cmd: 4, hclass: 0 } },
    { kind: "decision", index: 17, arrived_us: 1763290000090000, outcome_name: "allow<b>", src_ip: "127.0.0.1", src_port: 40017,
      cause: { code: 0, label: "0 clean" }, reading: { cmd: 3 } },
  ],
};

test("the live view shows the connection, the enforcer's counters, the chain and the newest decisions", () => {
  const markup = text(renderLiveFeed(LIVE));
  assert.ok(markup.includes("feed: connected") && markup.includes("/run/prismpath-collector/feed.sock"));
  assert.ok(markup.includes("<th>allow</th>") && markup.includes("<td>11</td>") && markup.includes("a policy is loaded"));
  assert.ok(markup.includes("0 records dropped") && markup.includes("kept as evidence"));
  const rows = markup.split('<tbody>').pop().split("<tr>");
  assert.ok(rows[1].includes("<td>20</td>") && rows[1].includes("malformed (40 bytes)"));
  assert.ok(rows[2].includes("32 route:no-matching-edge") && rows[2].includes("127.0.0.1:40018") && rows[2].includes("cmd 4"));
  assert.ok(markup.includes("allow&lt;b&gt;") && !markup.includes("allow<b>"), "a server string is text");
});

test("no feed client says why and how to name a collector", () => {
  const markup = text(renderLiveFeed({ connection: "off", reason: "the read-only posture connects to no collector" }));
  assert.ok(markup.includes("feed: off") && markup.includes("read-only posture") && markup.includes("MC_COLLECTOR"));
});

test("the chain status is the console's over the collector's unsigned seals", () => {
  const markup = text(renderFeedChain(CHAIN));
  assert.ok(markup.includes("console: intact") && markup.includes("collector seal, unsigned"));
  assert.ok(markup.includes('class="chip ok"') && markup.includes("6 checked"));
  assert.ok(!markup.includes("holes ("));
});

test("holes, unchecked spans and findings are shown", () => {
  const holes = text(renderFeedChain({ ...CHAIN, status: "holes", holes_total: 2, missing: 7,
    holes: [{ from: 2, to: 4, leaves: 2, why: "gap", segment: 0 }, { from: 9, to: 14, leaves: 5, why: "disconnected", segment: 1 }],
    unchecked: [{ from: 4, to: 7, leaves: 3 }, { from: 15, to: 16, leaves: 1, open: true }], seals: { ...CHAIN.seals, adopted: 1 } }));
  assert.ok(holes.includes("console: holes") && holes.includes('class="chip warn"'));
  assert.ok(holes.includes("leaves 2 to 3 (2 leaves)") && holes.includes("(gap)") && holes.includes("not connected"));
  assert.ok(holes.includes("7 leaves the console does not hold") && holes.includes("leaves 4 to 6 (3 leaves)"));
  assert.ok(holes.includes("until the next seal") && holes.includes("1 taken up after a hole"));
  const broken = text(renderFeedChain({ ...CHAIN, status: "broken", findings_total: 1,
    findings: [{ check: "leaf", detail: "the record's leaf is not SHA-256 of its frame", index: 4, segment: 0, line: 6 }],
    collector_errors: [{ reason: "the ring <buffer> is corrupt" }], ignored: { weather: 2 } }));
  assert.ok(broken.includes("console: broken") && broken.includes('class="chip bad"'));
  assert.ok(broken.includes("leaf 4") && broken.includes("segment 0 line 6") && broken.includes("weather 2"));
  assert.ok(broken.includes("the ring &lt;buffer&gt; is corrupt"));
  assert.ok(text(renderFeedChain(null)).includes("no session yet"));
});

test("a kept session's report lists every segment with its bytes and how it ended", () => {
  const report = { ...CHAIN, path: "/ev/collector-feed/5ee5", note: "the seals are the collector's statement",
    files: [{ segment: 0, lines: 36, size: 9000, ended: "eof", sha256: "cd".repeat(32) }, { segment: 1, lines: 4, size: 900, ended: null, sha256: "ef".repeat(32) }] };
  const markup = text(renderFeedReport(report));
  assert.ok(markup.includes("/ev/collector-feed/5ee5") && markup.includes("console: intact"));
  assert.ok(markup.includes("<td>eof</td>") && markup.includes("<td>open</td>") && markup.includes("cdcdcdcd"));
});

test("the feed request names a path and, when given, one segment", () => {
  assert.deepEqual(feedRequest({ path: " collector-feed/s ", segment: "" }), [PATHS.evidenceFeed, { path: "collector-feed/s" }]);
  assert.deepEqual(feedRequest({ path: "s", segment: "2" }), [PATHS.evidenceFeed, { path: "s", segment: 2 }]);
});

test("the cause monitor reads the live feed or an audit log", () => {
  assert.deepEqual(monitorRequest({ source: "live", bucket: "60", path: "x.audit.jsonl", since: "2026", last: "500" }),
    [PATHS.feedCauses, { bucket_s: "60", last: "500" }]);
  assert.deepEqual(monitorRequest({ source: "log", bucket: "", path: "x.audit.jsonl" }),
    [PATHS.trailCauses, { bucket_s: "3600", path: "x.audit.jsonl" }]);
  const series = { source: "live", path: "/run/f.sock", connection: "connected", bucket_s: 60, events: 3, untimed: 0, clock: "arrival",
    buckets: [{ start: 1763290000, by_cause: { 32: 2, 0: 1 }, by_action: { drop_policy: 2, allow: 1 } }],
    causes: { 32: { label: "32 route:no-matching-edge", class: "routing" }, 0: { label: "0 clean", class: null } } };
  const markup = text(renderCauseMonitor(series));
  assert.ok(markup.includes("live feed") && markup.includes("by arrival time") && markup.includes("32 route:no-matching-edge"));
  assert.ok(markup.includes("drop_policy") && markup.includes("<svg"));
});

test("the trails listing offers each kept feed session", () => {
  const markup = text(renderLogList({ roots: ["/ev"], logs: [], runs: [],
    feeds: [{ path: "/ev/collector-feed/5ee\"5", rel: "collector-feed/5ee5", segments: 2 }] }));
  assert.ok(markup.includes('data-feed="/ev/collector-feed/5ee&quot;5"') && markup.includes("2 segments"));
  assert.ok(!markup.includes("No audit log or evidence run"));
});

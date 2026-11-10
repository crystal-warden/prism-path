// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// The JavaScript leg of the verified core's differential harness (formal/diff/core_diff.py). An adapter,
// not part of the kernel: it composes the kernel's own exported functions (`parse`, `firstDeterministic`)
// as the Python leg composes the reference, and prints what they decide. The kernel does not implement
// field definitions (SPEC section 4.5) and refuses every flow that defines its fields, as the spec requires
// of such a kernel (spec-verified-core.md D5); it has no canon/2 reader, so a reading is read with the
// runtime's JSON.parse after a strict UTF-8 decode, and a difference that is only a canon/2 rule is a
// reader gap.
//
// Input on stdin, one case after another: `case <id> <n>\n`, then the policy image, the flow text and `n`
// readings, each framed as `<byte length>\n<bytes>\n`. A flow of length 0 means the image has no flow
// rendering. Output: one JSON line per case.
import { readFileSync } from "node:fs";
import { parse, firstDeterministic } from "../../prismpath/portable/prismpath.mjs";

const input = readFileSync(0);
const decoder = new TextDecoder("utf-8", { fatal: true });
let pos = 0;

function readLine() {
  const end = input.indexOf(10, pos);
  if (end < 0) throw new Error("truncated frame header");
  const line = input.subarray(pos, end).toString("latin1");
  pos = end + 1;
  return line;
}

function readFrame() {
  const length = Number(readLine());
  const frame = input.subarray(pos, pos + length);
  pos += length + 1;
  return frame;
}

function readingVerdict(graph, bytes) {
  let doc;
  try {
    doc = JSON.parse(decoder.decode(bytes));
  } catch (err) {
    return { verdict: "refuse", cause: "reading:unreadable", reason: err instanceof TypeError ? "utf8" : "syntax" };
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    return { verdict: "refuse", cause: "reading:not-object" };
  }
  try {
    const [target] = firstDeterministic(graph.nodes[graph.start].edges, doc);
    if (target === null) return { verdict: "refuse", cause: "route:no-matching-edge" };
    return { verdict: "route", target };
  } catch (err) {
    return { verdict: "refuse", cause: "crash", reason: String(err).slice(0, 200) };
  }
}

const out = [];
while (pos < input.length) {
  const header = readLine().split(" ");
  if (header.length !== 3 || header[0] !== "case") throw new Error(`malformed case header ${header}`);
  const count = Number(header[2]);
  readFrame();                                   // the image: this kernel reads flows, not images
  const flow = readFrame();
  const readings = [];
  for (let index = 0; index < count; index++) readings.push(readFrame());
  if (flow.length === 0) {
    out.push(JSON.stringify({ id: header[1], policy: "unrenderable" }));
    continue;
  }
  let graph;
  try {
    graph = parse(decoder.decode(flow));
  } catch (err) {
    const refusing = /does not implement field definitions/.test(String(err));
    out.push(JSON.stringify({ id: header[1], policy: "refused", cause: refusing ? "refusing-kernel" : null,
                              reason: String(err).slice(0, 300) }));
    continue;
  }
  if (!graph.nodes[graph.start]) {
    out.push(JSON.stringify({ id: header[1], policy: "refused", cause: null, reason: "no start node" }));
    continue;
  }
  out.push(JSON.stringify({ id: header[1], policy: "accepted", defines: false,
                            readings: readings.map((bytes) => readingVerdict(graph, bytes)) }));
}
process.stdout.write(out.join("\n") + (out.length ? "\n" : ""));

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// The JavaScript leg of the verified core's differential harness (formal/diff/core_diff.py). An adapter,
// not part of the kernel: it composes the kernel's own exported functions (`canon2Read`, `parse`,
// `systemBoundary`, `firstDeterministic`, `policyCheck`) exactly as the Python leg composes the reference and
// the Rust leg its port, and prints what they decide. The kernel implements the core: canon/2 documents, the
// field definitions of SPEC section 4.5 with exact decimal lowering, the policy rules in the core's order,
// the system boundary and the policy check (docs/design/spec-verified-core.md). Every refusal carries its
// registered cause and code.
//
// Input on stdin, one case after another: `case <id> <n>\n`, then the policy image, the flow text and `n`
// readings, each framed as `<byte length>\n<bytes>\n`. The image and the readings are canon/2 documents; the
// flow is the image's rendering, which the harness writes. A flow of length 0 means the image has no flow
// rendering. Output: one JSON line per case.
import { readFileSync } from "node:fs";
import {
  parse, firstDeterministic, canon2Read, Canon2Error, FieldDefinitionError, systemBoundary, policyCheck,
  coreCauseCode,
} from "../../prismpath/portable/prismpath.mjs";

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

// A refusal with its registered code, as the oracle prints one.
function refuse(cause, detail = {}) {
  return { verdict: "refuse", cause, code: coreCauseCode(cause), ...detail };
}

function readingVerdict(graph, bytes) {
  let doc;
  try {
    doc = canon2Read(bytes);
  } catch (err) {
    if (err instanceof Canon2Error) return refuse("reading:unreadable", { reason: err.rule });
    return { verdict: "refuse", cause: "crash", reason: `canon2Read ${String(err).slice(0, 200)}` };
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) return refuse("reading:not-object");
  let verdict;
  try {
    const refused = systemBoundary(graph, doc);
    if (refused !== null) verdict = refuse("route:contract-violation", { field: refused[0], reason: refused[1] });
    else {
      const [target] = firstDeterministic(graph.nodes[graph.start].edges, doc);
      verdict = target === null ? refuse("route:no-matching-edge") : { verdict: "route", target };
    }
    const check = policyCheck(graph, doc);
    verdict.policy_check = check === null ? "pass" : { field: check[0], reason: check[1] };
  } catch (err) {
    return { verdict: "refuse", cause: "crash", reason: String(err).slice(0, 200) };
  }
  return verdict;
}

const out = [];
while (pos < input.length) {
  const header = readLine().split(" ");
  if (header.length !== 3 || header[0] !== "case") throw new Error(`malformed case header ${header}`);
  const count = Number(header[2]);
  const image = readFrame();
  const flow = readFrame();
  const readings = [];
  for (let index = 0; index < count; index++) readings.push(readFrame());
  try {
    canon2Read(image);
  } catch (err) {
    if (!(err instanceof Canon2Error)) throw err;
    out.push(JSON.stringify({ id: header[1], policy: "refused", cause: "policy:unreadable", reason: err.rule,
                              code: coreCauseCode("policy:unreadable"), causes: ["policy:unreadable"] }));
    continue;
  }
  if (flow.length === 0) {
    out.push(JSON.stringify({ id: header[1], policy: "unrenderable" }));
    continue;
  }
  let graph;
  try {
    graph = parse(decoder.decode(flow));
  } catch (err) {
    if (err instanceof FieldDefinitionError) {
      out.push(JSON.stringify({ id: header[1], policy: "refused", reason: err.message.slice(0, 300), cause: err.cause,
                                code: err.code, field: err.field, policy_reason: err.reason,
                                causes: err.problems.map((found) => found.cause) }));
    } else {
      out.push(JSON.stringify({ id: header[1], policy: `crash: ${String(err).slice(0, 300)}` }));
    }
    continue;
  }
  if (!graph.nodes[graph.start]) {
    out.push(JSON.stringify({ id: header[1], policy: "crash: no start node" }));
    continue;
  }
  out.push(JSON.stringify({ id: header[1], policy: "accepted", defines: Object.keys(graph.fields).length > 0,
                            readings: readings.map((bytes) => readingVerdict(graph, bytes)) }));
}
process.stdout.write(out.join("\n") + (out.length ? "\n" : ""));

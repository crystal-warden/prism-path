// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The JavaScript leg of the canon/2 differential (formal/diff/canon2_diff.py). An adapter, not part of the
// kernel: it reads framed documents on stdin, each `<byte length>\n<bytes>\n`, and prints one line per
// document, `ok <c> <hex>` (canon2Read accepts it; <hex> is canon2Write of its value, <c> is 1 when the
// input is already those bytes), `refuse <rule>`, `writefail <rule>` or `panic <message>`.
import { readFileSync, writeSync } from "node:fs";
import { canon2Read, canon2Write } from "../../prismpath/portable/prismpath.mjs";

const input = readFileSync(0);
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const lines = [];
let pos = 0;
while (pos < input.length) {
  const nl = input.indexOf(10, pos);
  if (nl < 0) process.exit(2);
  const n = Number(input.subarray(pos, nl).toString("latin1"));
  const start = nl + 1;
  if (!Number.isInteger(n) || start + n + 1 > input.length) process.exit(2);
  const doc = input.subarray(start, start + n);
  let text;
  let value;
  try {
    value = canon2Read(new Uint8Array(doc));
    try {
      const out = canon2Write(value);
      text = `ok ${Buffer.from(out).equals(doc) ? 1 : 0} ${hex(out)}`;
    } catch (error) {
      text = error && error.rule ? `writefail ${error.rule}` : `panic ${String(error).slice(0, 60)}`;
    }
  } catch (error) {
    text = error && error.rule ? `refuse ${error.rule}` : `panic ${String(error).slice(0, 60)}`;
  }
  lines.push(text);
  pos = start + n + 1;
}
const chunk = 4096;
for (let i = 0; i < lines.length; i += chunk) writeSync(1, lines.slice(i, i + chunk).join("\n") + "\n");

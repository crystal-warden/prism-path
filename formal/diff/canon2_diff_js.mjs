// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The JavaScript leg of the canon/2 differential (formal/diff/canon2_diff.py). An adapter, not part of the
// kernel: it reads framed documents on stdin, each `<byte length>\n<bytes>\n`, and prints one line per
// document, `<strict> ; <canonicalize>`: canon2Read's answer (`ok <hex>` with canon2Write of the value, or
// `refuse <rule>`) and canon2Canonicalize's (`canon <hex>` or `refuse <rule>`), or `panic <message>`.
import { readFileSync, writeSync } from "node:fs";
import { canon2Read, canon2Write, canon2Canonicalize } from "../../prismpath/portable/prismpath.mjs";

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
  const bytes = new Uint8Array(doc);
  const answer = (run) => {
    try {
      return run();
    } catch (error) {
      if (error && error.rule) return `refuse ${error.rule}`;
      throw error;
    }
  };
  let text;
  try {
    const strict = answer(() => `ok ${hex(canon2Write(canon2Read(bytes)))}`);
    const canon = answer(() => `canon ${hex(canon2Canonicalize(bytes))}`);
    text = `${strict} ; ${canon}`;
  } catch (error) {
    text = `panic ${String(error).slice(0, 60)}`;
  }
  lines.push(text);
  pos = start + n + 1;
}
const chunk = 4096;
for (let i = 0; i < lines.length; i += chunk) writeSync(1, lines.slice(i, i + chunk).join("\n") + "\n");

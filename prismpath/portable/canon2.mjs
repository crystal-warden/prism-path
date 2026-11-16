// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// canon2.mjs: canon/2, the integer only JCS profile every hashed or signed PrismPath document is written
// in (docs/design/spec-verified-core.md section 3, prismpath/kernel/canon2.py), as one dependency free ES
// module for a page that checks evidence itself (Mission Control's in page verifier) and for anything
// else that needs canon/2 without the whole kernel.
//
// The section below is the kernel's own canon/2 section (prismpath.mjs), copied out whole: the client
// suite (mission_control/static/js/tests/portable.test.mjs) fails if the two differ by a byte, so there is
// one canon/2 in JavaScript. The kernel stays one file because the bundle compiler inlines it. Both are
// held to conformance/canon2.json by run_vectors.mjs and the client suite.

export const CANON2 = "canon/2";

// ------------------------------------------------------------------------------------- canon/2
const CANON2_LIMIT = 9007199254740991;
const CANON2_MAX_DEPTH = 128;
const CANON2_ESCAPES = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
const UTF8_STRICT = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** A text that is not a canon/2 document, or a value with no canon/2 form. `rule` is the first rule broken
 *  reading left to right: utf8, syntax, float, integer-range, negative-zero, duplicate-key,
 *  lone-surrogate or depth, or not-canonical for a document that is not its canonical spelling (spec
 *  sections 3 and 3.2). */
export class Canon2Error extends Error {
  constructor(rule, detail = "") {
    super(`canon/2 ${rule}${detail ? `: ${detail}` : ""}`);
    this.rule = rule;
  }
}

const isDigitChar = (ch) => ch !== undefined && ch >= "0" && ch <= "9";
const isHexChar = (ch) => ch !== undefined && /^[0-9a-fA-F]$/.test(ch);

class Canon2Reader {
  // The text as an array of code points, so positions and windows count code points as the reference does.
  constructor(codePoints) {
    this.cps = codePoints;
    this.pos = 0;
  }

  skipWs() {
    while (this.pos < this.cps.length && " \t\n\r".includes(this.cps[this.pos])) this.pos++;
  }

  peek() {
    return this.pos < this.cps.length ? this.cps[this.pos] : "";
  }

  startsWith(word) {
    for (let index = 0; index < word.length; index++) {
      if (this.cps[this.pos + index] !== word[index]) return false;
    }
    return true;
  }

  value(depth) {
    this.skipWs();
    const ch = this.peek();
    if (this.startsWith("null")) { this.pos += 4; return null; }
    if (this.startsWith("true")) { this.pos += 4; return true; }
    if (this.startsWith("false")) { this.pos += 5; return false; }
    if (ch === '"') { this.pos++; return this.string(); }
    if (ch === "-") { this.pos++; return this.number(true); }
    if (ch === "[") {
      if (depth + 1 > CANON2_MAX_DEPTH) throw new Canon2Error("depth");
      this.pos++;
      this.skipWs();
      if (this.peek() === "]") { this.pos++; return []; }
      const items = [this.value(depth + 1)];
      for (;;) {
        this.skipWs();
        const next = this.peek();
        if (next === "]") { this.pos++; return items; }
        if (next !== ",") throw new Canon2Error("syntax", `expected , or ] at ${this.pos}`);
        this.pos++;
        items.push(this.value(depth + 1));
      }
    }
    if (ch === "{") {
      if (depth + 1 > CANON2_MAX_DEPTH) throw new Canon2Error("depth");
      this.pos++;
      this.skipWs();
      const members = {};
      if (this.peek() === "}") { this.pos++; return members; }
      for (;;) {
        this.skipWs();
        if (this.peek() !== '"') throw new Canon2Error("syntax", `expected a key at ${this.pos}`);
        this.pos++;
        const key = this.string();
        if (Object.prototype.hasOwnProperty.call(members, key)) throw new Canon2Error("duplicate-key", JSON.stringify(key).slice(0, 40));
        this.skipWs();
        if (this.peek() !== ":") throw new Canon2Error("syntax", `expected : at ${this.pos}`);
        this.pos++;
        // defineProperty, not assignment: a key named __proto__ is an ordinary member here
        Object.defineProperty(members, key, { value: this.value(depth + 1), enumerable: true, writable: true, configurable: true });
        this.skipWs();
        const next = this.peek();
        if (next === "}") { this.pos++; return members; }
        if (next !== ",") throw new Canon2Error("syntax", `expected , or } at ${this.pos}`);
        this.pos++;
      }
    }
    if (isDigitChar(ch)) return this.number(false);
    throw new Canon2Error("syntax", ch ? `unexpected ${JSON.stringify(ch)} at ${this.pos}` : "unexpected end");
  }

  // The value of four code points at `at` as hex, null when they are not hex, "short" when fewer remain.
  hex4(at) {
    const chunk = this.cps.slice(at, at + 4);
    if (chunk.length < 4) return "short";
    return chunk.every(isHexChar) ? parseInt(chunk.join(""), 16) : null;
  }

  string() {
    const cps = this.cps;
    const out = [];
    for (;;) {
      if (this.pos >= cps.length) throw new Canon2Error("syntax", "unterminated string");
      const ch = cps[this.pos];
      if (ch === '"') { this.pos++; return out.join(""); }
      if (ch === "\\" && this.pos + 1 < cps.length) {
        const escape = cps[this.pos + 1];
        if (escape === "u" && this.pos + 6 <= cps.length) {
          const high = this.hex4(this.pos + 2);
          if (high === null) throw new Canon2Error("syntax", "bad \\u escape");
          if (high >= 0xd800 && high <= 0xdbff) {
            const after = this.pos + 6;
            if (cps[after] === "\\" && cps[after + 1] === "u" && after + 6 <= cps.length) {
              const low = this.hex4(after + 2);
              if (low === null) throw new Canon2Error("syntax", "bad \\u escape");
              if (low >= 0xdc00 && low <= 0xdfff) {
                out.push(String.fromCodePoint(0x10000 + (high - 0xd800) * 0x400 + (low - 0xdc00)));
                this.pos = after + 6;
                continue;
              }
            }
            throw new Canon2Error("lone-surrogate");
          }
          if (high >= 0xdc00 && high <= 0xdfff) throw new Canon2Error("lone-surrogate");
          out.push(String.fromCodePoint(high));
          this.pos += 6;
          continue;
        }
        if (escape !== "u" && Object.prototype.hasOwnProperty.call(CANON2_ESCAPES, escape)) {
          out.push(CANON2_ESCAPES[escape]);
          this.pos += 2;
          continue;
        }
        throw new Canon2Error("syntax", "bad escape");
      }
      if (ch.codePointAt(0) < 0x20) throw new Canon2Error("syntax", "control character in a string");
      out.push(ch);
      this.pos++;
    }
  }

  digits() {
    const start = this.pos;
    while (this.pos < this.cps.length && isDigitChar(this.cps[this.pos])) this.pos++;
    return this.cps.slice(start, this.pos).join("");
  }

  number(negative) {
    const ch = this.peek();
    let digits;
    if (ch === "0") { this.pos++; digits = "0"; }
    else if (isDigitChar(ch)) digits = this.digits();
    else throw new Canon2Error("syntax", "a number needs a digit");
    let fraction = false;
    let exponent = false;
    if (this.peek() === ".") {
      this.pos++;
      if (!this.digits()) throw new Canon2Error("syntax", "a fraction needs a digit");
      fraction = true;
    }
    if (this.peek() === "e" || this.peek() === "E") {
      this.pos++;
      if (this.peek() === "+" || this.peek() === "-") this.pos++;
      if (!this.digits()) throw new Canon2Error("syntax", "an exponent needs a digit");
      exponent = true;
    }
    if (fraction || exponent) throw new Canon2Error("float", "a number with a fraction or an exponent");
    if (negative && digits === "0") throw new Canon2Error("negative-zero");
    if (digits.length > 16) throw new Canon2Error("integer-range", digits.slice(0, 24));
    const magnitude = Number(digits);
    if (magnitude > CANON2_LIMIT) throw new Canon2Error("integer-range", digits.slice(0, 24));
    return negative ? -magnitude : magnitude;
  }
}

/** The value of `data` read by every canon/2 rule but the spelling, and the UTF-8 bytes it was read from. */
function canon2Parse(data) {
  let text;
  let raw;
  if (typeof data === "string") {
    // a lone surrogate has no UTF-8 form
    if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(data)) {
      throw new Canon2Error("utf8", "the text holds a surrogate code point, which has no UTF-8 form");
    }
    text = data;
    raw = new TextEncoder().encode(data);
  } else {
    try {
      text = UTF8_STRICT.decode(data);
    } catch {
      throw new Canon2Error("utf8");
    }
    raw = data;
  }
  const reader = new Canon2Reader(Array.from(text));
  const value = reader.value(0);
  reader.skipWs();
  if (reader.pos !== reader.cps.length) throw new Canon2Error("syntax", `trailing text at ${reader.pos}`);
  return { value, raw };
}

function sameBytes(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) if (left[index] !== right[index]) return false;
  return true;
}

/** The strict reader (the Lean `Core.readCanonical`): the canon/2 document in `data` (bytes, decoded as
 *  strict UTF-8 first, or an already decoded string) as an object, array, string, integer (a JS number
 *  inside plus or minus 2^53 minus 1), boolean or null, when `data` is exactly the canonical spelling of
 *  that value. Throws Canon2Error with the first rule broken, or `not-canonical` for a document spelled
 *  any other way (whitespace, members out of key order, a needless escape). */
export function canon2Read(data) {
  const { value, raw } = canon2Parse(data);
  if (!sameBytes(canon2Write(value), raw)) {
    throw new Canon2Error("not-canonical", "the document reads as canon/2 but is not its canonical spelling");
  }
  return value;
}

/** The canonical bytes of the canon/2 value a person wrote in `data`, in any legal spelling (whitespace,
 *  member order, escapes); every other rule holds as in canon2Read, and the result is what canon2Read
 *  accepts. A writer's step, never a reader's (prismpath/kernel/canon2.py `canonicalize`). */
export function canon2Canonicalize(data) {
  return canon2Write(canon2Parse(data).value);
}

function canon2WriteString(text, out) {
  out.push('"');
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    const ch = text[index];
    if (ch === '"') out.push('\\"');
    else if (ch === "\\") out.push("\\\\");
    else if (code < 0x20) {
      out.push({ 8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r" }[code] || `\\u${code.toString(16).padStart(4, "0")}`);
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Canon2Error("lone-surrogate", "a string holds a lone surrogate");
      out.push(ch, text[index + 1]);
      index++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Canon2Error("lone-surrogate", "a string holds a lone surrogate");
    } else out.push(ch);
  }
  out.push('"');
}

function canon2WriteValue(value, depth, out) {
  if (value === null) out.push("null");
  else if (value === true) out.push("true");
  else if (value === false) out.push("false");
  else if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Canon2Error("float", "canon/2 has no float; write a decimal string or an integer of a stated unit");
    if (Object.is(value, -0)) throw new Canon2Error("negative-zero");
    if (Math.abs(value) > CANON2_LIMIT) throw new Canon2Error("integer-range", "an integer beyond plus or minus 2^53 minus 1; write it as a decimal string");
    out.push(String(value));
  } else if (typeof value === "string") canon2WriteString(value, out);
  else if (Array.isArray(value)) {
    if (depth + 1 > CANON2_MAX_DEPTH) throw new Canon2Error("depth");
    out.push("[");
    value.forEach((item, index) => {
      if (index) out.push(",");
      canon2WriteValue(item, depth + 1, out);
    });
    out.push("]");
  } else if (typeof value === "object") {
    if (depth + 1 > CANON2_MAX_DEPTH) throw new Canon2Error("depth");
    out.push("{");
    // a default sort compares UTF-16 code units, the order RFC 8785 asks for
    Object.keys(value).sort().forEach((key, index) => {
      if (index) out.push(",");
      canon2WriteString(key, out);
      out.push(":");
      canon2WriteValue(value[key], depth + 1, out);
    });
    out.push("}");
  } else throw new TypeError(`${typeof value} has no canon/2 form`);
}

/** The canonical canon/2 bytes of `value` (RFC 8785 with no float): no whitespace, members in the order of
 *  the UTF-16 code units of their keys, strings as raw UTF-8 with only the quote, the backslash and the
 *  control characters escaped, integers in decimal. Refuses every value canon2Read would refuse. */
export function canon2Write(value) {
  const out = [];
  canon2WriteValue(value, 0, out);
  return new TextEncoder().encode(out.join(""));
}

/** The bytes a document is hashed over: its canon/2 bytes (prismpath/canon.py `document_bytes`). A
 *  document that does not name canon/2 (an untagged one is canon/1, which is retired), names another
 *  encoding, or is not an object, throws; so does a value with no canon/2 form. */
export function documentBytes(doc) {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc) || !Object.prototype.hasOwnProperty.call(doc, "encoding")) {
    throw new Error('a document without "encoding": "canon/2" is refused: canon/1 is retired and is not read, hashed or verified');
  }
  if (doc.encoding !== CANON2) throw new Error(`unknown encoding ${String(doc.encoding).slice(0, 40)}: only canon/2 is read`);
  return canon2Write(doc);
}

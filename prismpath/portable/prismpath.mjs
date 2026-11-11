// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/**
 * prismpath.mjs: the PORTABLE prismpath kernel (roadmap item #5): parser + safe predicate
 * evaluator + engine loop for the ML-FREE subset, in one dependency-free ES module.
 *
 * A flow is PORTABLE iff every reachable edge is decidable: a `when` predicate, an error
 * edge, or an event edge (check with `prismpath portable <flow>` on the Python side, or
 * portabilityViolations() here). Such a flow needs no embedder and no LLM tier for ROUTING
 * (workers are supplied by the host and can be anything), so it runs wherever JavaScript
 * runs: Node, a browser, an edge function, a network appliance. `run()` REFUSES a
 * non-portable flow up front rather than guessing at a semantic edge.
 *
 * Semantics are a faithful port of parser.py / predicates.py / engine.py: verified by the
 * cross-language conformance suite (portable/run_conformance.mjs), which replays the same
 * flows + scripted outcomes through both engines and requires identical paths. The subtle
 * Python behaviors are preserved deliberately:
 *   - `True`/`False`/`None` are constants; lowercase `true`/`false` are FIELD NAMES
 *     (Python ast parses them as Names): so `when x == true` reads ctx["true"].
 *   - booleans compare numerically: `flag == 1` is true for flag=true (Python True == 1).
 *   - a comparison against a missing field or a type-mismatched pair is UNSATISFIED, never
 *     a crash: except `not in`, whose failure is SATISFIED ("unknown -> falsy").
 *   - chained comparisons (`1 < x < 5`), substring `in` on strings, membership on lists
 *     (loose ==) and objects (key test), Python truthiness ([] and {} are falsy).
 *   - disallowed syntax (calls, attributes, subscripts, arithmetic, unary minus) is a
 *     PredicateError: statically via checkPredicate, and a non-match at run time.
 *
 * No eval()/Function() anywhere: predicates go through a hand-rolled tokenizer +
 * recursive-descent parser onto a tiny AST, exactly mirroring the Python sandbox.
 */
// SHA-256 in plain JavaScript, so the kernel imports nothing: a static `import "node:crypto"` is a
// module-resolution error in every browser, and the playground and the compiled bundles run in one.
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const bitLength = data.length * 8;
  const padded = new Uint8Array(((data.length + 9 + 63) >> 6) << 6);
  padded.set(data);
  padded[data.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bitLength / 0x100000000));
  view.setUint32(padded.length - 4, bitLength >>> 0);
  const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + SHA256_K[i] + w[i]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  return Array.from(h, (x) => x.toString(16).padStart(8, "0")).join("");
}

const ALWAYS = new Set(["always", "true", "else", "otherwise", "default", "_"]);
const NEVER = new Set(["false", "never"]);
const MAX_DEPTH = 50;

// Python HARD keywords (minus True/False/None, which are constants, and and/or/not/in, which are
// operators here). Python's ast.parse REJECTS these as names: `when class == "phish"` is a
// PredicateError there, so it must be one here too, or the edge routes differently across engines
// (found by differential fuzzing). Soft keywords (match/case/type) are ordinary Names in both.
const PY_KEYWORDS = new Set([
  "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else",
  "except", "finally", "for", "from", "global", "if", "import", "is", "lambda", "nonlocal",
  "pass", "raise", "return", "try", "while", "with", "yield",
]);

// Python str.strip() whitespace, which is WIDER than JS String.trim() (e.g. U+0085 NEL is
// whitespace to Python but not to trim()): condition classification must agree on both sides.
// Python's str.isspace set exactly: U+0009 to U+000D, U+001C to U+0020, U+0085, U+00A0, U+1680, U+2000 to
// U+200A, U+2028, U+2029, U+202F, U+205F and U+3000. JavaScript's \\s adds U+FEFF, which Python does not strip,
// and lacks U+001C to U+001F and U+0085 (spec-verified-core.md, section 2.5).
const PY_SPACE_CLASS = "\\t-\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const PY_WS = `[${PY_SPACE_CLASS}]`;
const PY_TRIM_RE = new RegExp(`^${PY_WS}+|${PY_WS}+$`, "gu");
const PY_TRIM_END_RE = new RegExp(`${PY_WS}+$`, "u");
function pyTrim(textVal) {
  return textVal.replace(PY_TRIM_RE, "");
}
function pyTrimEnd(textVal) {
  return textVal.replace(PY_TRIM_END_RE, "");
}

// Ellipsis (`...`) is a truthy Constant in Python; represent it as a sentinel that is truthy and
// equal to nothing JSON can contain (mirroring Python, where `x == ...` is False for JSON values).
const ELLIPSIS = Symbol("Ellipsis");

export class PredicateError extends Error {}

// ---------------------------------------------------------------------------- conditions
// pyTrim (not String.trim) throughout: Python's strip() removes e.g. U+0085, and the tier a
// condition lands in must be identical across engines.
export function isDeterministic(conditionText) {
  const cond = pyTrim(conditionText).toLowerCase();
  return cond.startsWith("when ") || ALWAYS.has(cond) || NEVER.has(cond);
}

export function isError(conditionText) {
  return pyTrim(conditionText).toLowerCase().startsWith("on error");
}

export function isEvent(conditionText) {
  const cond = pyTrim(conditionText).toLowerCase();
  return cond.startsWith("on event") || cond.startsWith("on timeout");
}

export function eventName(conditionText) {
  const cond = pyTrim(conditionText);
  if (cond.toLowerCase().startsWith("on timeout")) {
    return "__timeout__";
  }
  return pyTrim(cond.slice("on event".length));
}

export function isSemantic(conditionText) {
  return !isDeterministic(conditionText) && !isError(conditionText) && !isEvent(conditionText);
}

export function errorExpr(conditionText) {
  return pyTrim(pyTrim(conditionText).slice("on error".length));
}

function exprOf(conditionText) {
  const cond = pyTrim(conditionText);
  if (cond.toLowerCase().startsWith("when ")) {
    return pyTrim(cond.slice(5));
  }
  return cond;
}

// ------------------------------------------------------------------- expression parsing
function tokenize(sourceText) {
  const tokens = [];
  let pos = 0;
  const len = sourceText.length;
  // Each token also records its span in the source, (s, e) with e one past the last character, so the
  // lowering of decimal thresholds on fixed fields rewrites literals in place by the very boundaries
  // evaluation reads. A token's span is closed at the top of the pass after it was pushed, where every
  // branch below lands with pos one past the token.
  let tokenStart = 0;
  let closed = 0;
  while (pos < len) {
    if (closed < tokens.length) {
      tokens[closed].s = tokenStart;
      tokens[closed].e = pos;
      closed++;
    }
    const currentChar = sourceText[pos];
    if (currentChar === " " || currentChar === "\t" || currentChar === "\n" || currentChar === "\r") {
      pos++;
      continue;
    }
    tokenStart = pos;
    if (/[A-Za-z_]/.test(currentChar)) {
      if ((currentChar === "r" || currentChar === "R") && (sourceText[pos + 1] === "'" || sourceText[pos + 1] === '"')) {
        const quoteChar = sourceText[pos + 1];
        let scanPos = pos + 2;
        let tokenString = "";
        while (scanPos < len && sourceText[scanPos] !== quoteChar) {
          tokenString += sourceText[scanPos];
          scanPos++;
        }
        if (scanPos >= len) {
          throw new PredicateError("unterminated string in predicate");
        }
        tokens.push({ t: "str", v: tokenString });
        pos = scanPos + 1;
        continue;
      }
      if ((currentChar === "b" || currentChar === "B") && (sourceText[pos + 1] === "'" || sourceText[pos + 1] === '"')) {
        throw new PredicateError("bytes literals are not supported in predicates");
      }
      let scanPos = pos + 1;
      while (scanPos < len && /[A-Za-z0-9_]/.test(sourceText[scanPos])) {
        scanPos++;
      }
      tokens.push({ t: "name", v: sourceText.slice(pos, scanPos) });
      pos = scanPos;
      continue;
    }
    if (/[0-9]/.test(currentChar) || (currentChar === "." && /[0-9]/.test(sourceText[pos + 1] || ""))) {
      let scanPos = pos;
      const radixPrefix = sourceText.slice(pos, pos + 2).toLowerCase();
      if (currentChar === "0" && (radixPrefix === "0x" || radixPrefix === "0o" || radixPrefix === "0b")) {
        scanPos = pos + 2;
        const digitsRegex = radixPrefix === "0x" ? /[0-9a-fA-F_]/ : radixPrefix === "0o" ? /[0-7_]/ : /[01_]/;
        while (scanPos < len && digitsRegex.test(sourceText[scanPos])) {
          scanPos++;
        }
        const digitsBody = sourceText.slice(pos + 2, scanPos).replace(/_/g, "");
        if (!digitsBody) {
          throw new PredicateError("malformed numeric literal in predicate");
        }
        tokens.push({ t: "num", v: parseInt(digitsBody, radixPrefix === "0x" ? 16 : radixPrefix === "0o" ? 8 : 2), float: false });
        pos = scanPos;
        continue;
      }
      while (scanPos < len && /[0-9_]/.test(sourceText[scanPos])) {
        scanPos++;
      }
      if (sourceText[scanPos] === ".") {
        scanPos++;
        while (scanPos < len && /[0-9_]/.test(sourceText[scanPos])) {
          scanPos++;
        }
      }
      if (sourceText[scanPos] === "e" || sourceText[scanPos] === "E") {
        let expScan = scanPos + 1;
        if (sourceText[expScan] === "+" || sourceText[expScan] === "-") {
          expScan++;
        }
        if (/[0-9]/.test(sourceText[expScan] || "")) {
          expScan++;
          while (expScan < len && /[0-9_]/.test(sourceText[expScan])) {
            expScan++;
          }
          scanPos = expScan;
        }
      }
      if (sourceText[scanPos] === "j" || sourceText[scanPos] === "J") {
        throw new PredicateError("complex literals are not supported in predicates");
      }
      const rawNumber = sourceText.slice(pos, scanPos);
      tokens.push({ t: "num", v: Number(rawNumber.replace(/_/g, "")), float: /[.eE]/.test(rawNumber) });
      pos = scanPos;
      continue;
    }
    if (currentChar === '"' || currentChar === "'") {
      let scanPos = pos + 1;
      let tokenString = "";
      while (scanPos < len && sourceText[scanPos] !== currentChar) {
        if (sourceText[scanPos] === "\\" && scanPos + 1 < len) {
          const esc = sourceText[scanPos + 1];
          if (esc === "n") tokenString += "\n";
          else if (esc === "t") tokenString += "\t";
          else if (esc === "r") tokenString += "\r";
          else if (esc === "0") tokenString += "\0";
          else if (esc === "a") tokenString += "\x07";
          else if (esc === "b") tokenString += "\b";
          else if (esc === "f") tokenString += "\f";
          else if (esc === "v") tokenString += "\v";
          else if (esc === "\\" || esc === "'" || esc === '"') tokenString += esc;
          else if (esc === "x" && /^[0-9a-fA-F]{2}/.test(sourceText.slice(scanPos + 2))) {
            tokenString += String.fromCharCode(parseInt(sourceText.slice(scanPos + 2, scanPos + 4), 16));
            scanPos += 2;
          } else if (esc === "u" && /^[0-9a-fA-F]{4}/.test(sourceText.slice(scanPos + 2))) {
            tokenString += String.fromCharCode(parseInt(sourceText.slice(scanPos + 2, scanPos + 6), 16));
            scanPos += 4;
          } else {
            tokenString += "\\" + esc;
          }
          scanPos += 2;
        } else {
          tokenString += sourceText[scanPos];
          scanPos++;
        }
      }
      if (scanPos >= len) {
        throw new PredicateError("unterminated string in predicate");
      }
      tokens.push({ t: "str", v: tokenString });
      pos = scanPos + 1;
      continue;
    }
    if (sourceText.slice(pos, pos + 3) === "...") {
      tokens.push({ t: "ellipsis" });
      pos += 3;
      continue;
    }
    const twoChar = sourceText.slice(pos, pos + 2);
    if (twoChar === "==" || twoChar === "!=" || twoChar === "<=" || twoChar === ">=") {
      tokens.push({ t: "op", v: twoChar });
      pos += 2;
      continue;
    }
    if ("<>[](),".includes(currentChar)) {
      tokens.push({ t: "op", v: currentChar });
      pos++;
      continue;
    }
    if (currentChar === "-" || currentChar === "+") {
      tokens.push({ t: "op", v: currentChar });
      pos++;
      continue;
    }
    throw new PredicateError(`predicate uses disallowed syntax near ${JSON.stringify(sourceText.slice(pos, pos + 8))}`);
  }
  if (closed < tokens.length) {
    tokens[closed].s = tokenStart;
    tokens[closed].e = pos;
  }
  return tokens;
}

function peekToken(parserState) {
  return parserState.tokens[parserState.pos];
}

function nextToken(parserState) {
  const tok = parserState.tokens[parserState.pos];
  parserState.pos++;
  return tok;
}

function expectToken(parserState, expectedVal) {
  const tok = nextToken(parserState);
  if (!tok || tok.t !== "op" || tok.v !== expectedVal) {
    throw new PredicateError(`expected ${JSON.stringify(expectedVal)} in predicate`);
  }
}

// Grammar level: expr := or ; or := and ("or" and)*
function parseOr(parserState, astDepth) {
  if (astDepth > MAX_DEPTH) {
    throw new PredicateError("predicate nested too deeply");
  }
  const values = [parseAnd(parserState, astDepth)];
  while (peekToken(parserState) && peekToken(parserState).t === "name" && peekToken(parserState).v === "or") {
    nextToken(parserState);
    values.push(parseAnd(parserState, astDepth + 1));
  }
  return values.length === 1 ? values[0] : { k: "or", vals: values };
}

// Grammar level: and := not ("and" not)*
function parseAnd(parserState, astDepth) {
  if (astDepth > MAX_DEPTH) {
    throw new PredicateError("predicate nested too deeply");
  }
  const values = [parseNot(parserState, astDepth)];
  while (peekToken(parserState) && peekToken(parserState).t === "name" && peekToken(parserState).v === "and") {
    nextToken(parserState);
    values.push(parseNot(parserState, astDepth + 1));
  }
  return values.length === 1 ? values[0] : { k: "and", vals: values };
}

// Grammar level: not := "not" not | cmp
function parseNot(parserState, astDepth) {
  if (astDepth > MAX_DEPTH) {
    throw new PredicateError("predicate nested too deeply");
  }
  if (peekToken(parserState) && peekToken(parserState).t === "name" && peekToken(parserState).v === "not") {
    nextToken(parserState);
    return { k: "not", v: parseNot(parserState, astDepth + 1) };
  }
  return parseCmp(parserState, astDepth);
}

function parseCmpOp(parserState) {
  const tok = peekToken(parserState);
  if (!tok) {
    return null;
  }
  if (tok.t === "op" && ["==", "!=", "<", "<=", ">", ">="].includes(tok.v)) {
    nextToken(parserState);
    return tok.v;
  }
  if (tok.t === "name" && tok.v === "in") {
    nextToken(parserState);
    return "in";
  }
  if (tok.t === "name" && tok.v === "not") {
    nextToken(parserState);
    const lookahead = nextToken(parserState);
    if (!lookahead || lookahead.t !== "name" || lookahead.v !== "in") {
      throw new PredicateError("expected `in` after `not`");
    }
    return "not in";
  }
  return null;
}

// Grammar level: cmp := operand ((==|!=|<|<=|>|>=|in|not in) operand)*
function parseCmp(parserState, astDepth) {
  if (astDepth > MAX_DEPTH) {
    throw new PredicateError("predicate nested too deeply");
  }
  const left = parseOperand(parserState, astDepth);
  const operators = [];
  const rightOperands = [];
  let operator;
  while ((operator = parseCmpOp(parserState)) !== null) {
    operators.push(operator);
    rightOperands.push(parseOperand(parserState, astDepth + 1));
  }
  if (operators.length === 0) {
    return left;
  }
  return { k: "cmp", left, ops: operators, rights: rightOperands };
}

// Python's tokenizer refuses a predicate nested in more than 200 open brackets ("too many nested
// parentheses"). A bracket is not evaluation depth, so it does not count toward astDepth: depth bounds
// only the nesting the evaluator (and Python's own syntax tree) sees, as in the Rust parser (D2).
const MAX_BRACKETS = 200;
function openBracket(parserState) {
  if (parserState.brackets >= MAX_BRACKETS) throw new PredicateError("too many nested parentheses");
  parserState.brackets++;
}

// Grammar level: operand := number | string | True | False | None | name | "[" args "]" | "(" tuple-or-group ")"
function parseOperand(parserState, astDepth) {
  if (astDepth > MAX_DEPTH) {
    throw new PredicateError("predicate nested too deeply");
  }
  const tok = nextToken(parserState);
  if (!tok) {
    throw new PredicateError("unexpected end of predicate");
  }
  if (tok.t === "op" && (tok.v === "-" || tok.v === "+")) {
    const lookahead = peekToken(parserState);
    if (lookahead && lookahead.t === "num" && !lookahead.float) {
      nextToken(parserState);
      return { k: "const", v: tok.v === "-" ? -lookahead.v : lookahead.v, float: false };
    }
    throw new PredicateError(`predicate uses disallowed syntax (unary ${tok.v})`);
  }
  if (tok.t === "num") {
    return { k: "const", v: tok.v, float: tok.float };
  }
  if (tok.t === "str") {
    return { k: "const", v: tok.v };
  }
  if (tok.t === "ellipsis") {
    return { k: "const", v: ELLIPSIS };
  }
  if (tok.t === "name") {
    if (tok.v === "True") return { k: "const", v: true };
    if (tok.v === "False") return { k: "const", v: false };
    if (tok.v === "None") return { k: "const", v: null };
    if (tok.v === "and" || tok.v === "or" || tok.v === "not" || tok.v === "in") {
      throw new PredicateError(`unexpected keyword ${tok.v} in predicate`);
    }
    if (PY_KEYWORDS.has(tok.v)) {
      throw new PredicateError(`predicate uses a Python keyword as a name: ${tok.v}`);
    }
    return { k: "name", v: tok.v };
  }
  if (tok.t === "op" && tok.v === "[") {
    openBracket(parserState);
    const elements = [];
    if (peekToken(parserState) && !(peekToken(parserState).t === "op" && peekToken(parserState).v === "]")) {
      elements.push(parseOr(parserState, astDepth));
      while (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === ",") {
        nextToken(parserState);
        if (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === "]") {
          break;
        }
        elements.push(parseOr(parserState, astDepth));
      }
    }
    expectToken(parserState, "]");
    parserState.brackets--;
    return { k: "list", elts: elements };
  }
  if (tok.t === "op" && tok.v === "(") {
    if (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === ")") {
      nextToken(parserState);
      return { k: "list", elts: [] };
    }
    openBracket(parserState);
    const firstVal = parseOr(parserState, astDepth);
    if (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === ",") {
      const elements = [firstVal];
      while (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === ",") {
        nextToken(parserState);
        if (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === ")") {
          break;
        }
        elements.push(parseOr(parserState, astDepth));
      }
      expectToken(parserState, ")");
      parserState.brackets--;
      return { k: "list", elts: elements };
    }
    expectToken(parserState, ")");
    parserState.brackets--;
    return firstVal;
  }
  throw new PredicateError(`predicate uses disallowed syntax (${tok.v})`);
}

function parseExpr(sourceText) {
  const tokens = tokenize(sourceText);
  const parserState = { tokens, pos: 0, brackets: 0 };
  let astTree = parseOr(parserState, 0);
  if (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === ",") {
    const elements = [astTree];
    while (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === ",") {
      nextToken(parserState);
      if (!peekToken(parserState)) {
        break;
      }
      elements.push(parseOr(parserState, 1));
    }
    astTree = { k: "list", elts: elements };
  }
  if (parserState.pos !== tokens.length) {
    throw new PredicateError("trailing tokens in predicate");
  }
  return astTree;
}

// ------------------------------------------------------------------------- evaluation
export function pyTruthy(val) {
  if (val === null || val === undefined || val === false) return false;
  if (val === true) return true;
  if (typeof val === "number") return val !== 0;
  if (typeof val === "string") return val.length > 0;
  if (Array.isArray(val)) return val.length > 0;
  if (typeof val === "object") return Object.keys(val).length > 0;
  return Boolean(val);
}

function pyEq(left, right) {
  const extractNum = (val) => (typeof val === "number" ? val : typeof val === "boolean" ? Number(val) : null);
  const leftNum = extractNum(left);
  const rightNum = extractNum(right);
  if (leftNum !== null && rightNum !== null) return leftNum === rightNum;
  if (typeof left === "string" && typeof right === "string") return left === right;
  if (left === null || left === undefined) return right === null || right === undefined;
  if (right === null || right === undefined) return false;
  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length && left.every((item, index) => pyEq(item, right[index]));
  }
  if (typeof left === "object" && typeof right === "object" && !Array.isArray(left) && !Array.isArray(right)) {
    const leftKeys = Object.keys(left);
    const rightKeys = Object.keys(right);
    return leftKeys.length === rightKeys.length && leftKeys.every((key) => key in right && pyEq(left[key], right[key]));
  }
  return false;
}

function pyOrder(left, right) {
  const extractNum = (val) => (typeof val === "number" ? val : typeof val === "boolean" ? Number(val) : null);
  const leftNum = extractNum(left);
  const rightNum = extractNum(right);
  if (leftNum !== null && rightNum !== null) {
    if (Number.isNaN(leftNum) || Number.isNaN(rightNum)) return null;
    return leftNum < rightNum ? -1 : leftNum > rightNum ? 1 : 0;
  }
  if (typeof left === "string" && typeof right === "string") {
    const leftPoints = [...left];
    const rightPoints = [...right];
    for (let index = 0; index < Math.min(leftPoints.length, rightPoints.length); index++) {
      const leftChar = leftPoints[index].codePointAt(0);
      const rightChar = rightPoints[index].codePointAt(0);
      if (leftChar !== rightChar) return leftChar < rightChar ? -1 : 1;
    }
    return leftPoints.length === rightPoints.length ? 0 : leftPoints.length < rightPoints.length ? -1 : 1;
  }
  if (Array.isArray(left) && Array.isArray(right)) {
    for (let index = 0; index < Math.min(left.length, right.length); index++) {
      if (pyEq(left[index], right[index])) continue;
      const order = pyOrder(left[index], right[index]);
      if (order === null) return null;
      return order;
    }
    return left.length === right.length ? 0 : left.length < right.length ? -1 : 1;
  }
  return null;
}

function pyIn(left, right) {
  if (typeof right === "string") return typeof left === "string" ? right.includes(left) : null;
  if (Array.isArray(right)) return right.some((item) => pyEq(left, item));
  if (right !== null && typeof right === "object") {
    return typeof left === "string" ? Object.prototype.hasOwnProperty.call(right, left) : null;
  }
  return null;
}

function compareOp(operator, left, right) {
  try {
    switch (operator) {
      case "==": return pyEq(left, right);
      case "!=": return !pyEq(left, right);
      case "<": case "<=": case ">": case ">=": {
        const order = pyOrder(left, right);
        if (order === null) return false;
        return operator === "<" ? order < 0 : operator === "<=" ? order <= 0 : operator === ">" ? order > 0 : order >= 0;
      }
      case "in": {
        const inResult = pyIn(left, right);
        return inResult === null ? false : inResult;
      }
      case "not in": {
        const inResult = pyIn(left, right);
        return inResult === null ? true : !inResult;
      }
      default: throw new PredicateError(`comparison operator ${operator} not allowed`);
    }
  } catch (err) {
    if (err instanceof PredicateError) throw err;
    return operator === "not in";
  }
}

function evNode(astNode, ctx, astDepth) {
  if (astDepth > MAX_DEPTH) throw new PredicateError("predicate nested too deeply");
  switch (astNode.k) {
    case "const": return astNode.v;
    case "name": return Object.prototype.hasOwnProperty.call(ctx, astNode.v) ? ctx[astNode.v] : null;
    case "and": {
      const values = astNode.vals.map((childAst) => evNode(childAst, ctx, astDepth + 1));
      return values.every(pyTruthy);
    }
    case "or": {
      const values = astNode.vals.map((childAst) => evNode(childAst, ctx, astDepth + 1));
      return values.some(pyTruthy);
    }
    case "not": return !pyTruthy(evNode(astNode.v, ctx, astDepth + 1));
    case "list": return astNode.elts.map((elementAst) => evNode(elementAst, ctx, astDepth + 1));
    case "cmp": {
      let leftVal = evNode(astNode.left, ctx, astDepth + 1);
      for (let opIndex = 0; opIndex < astNode.ops.length; opIndex++) {
        const rightVal = evNode(astNode.rights[opIndex], ctx, astDepth + 1);
        if (!compareOp(astNode.ops[opIndex], leftVal, rightVal)) return false;
        leftVal = rightVal;
      }
      return true;
    }
    default: throw new PredicateError(`unsupported predicate syntax (${astNode.k})`);
  }
}

export function evalCondition(conditionText, ctx) {
  const expr = exprOf(conditionText);
  const loweredExpr = expr.toLowerCase();
  if (ALWAYS.has(loweredExpr)) return true;
  if (NEVER.has(loweredExpr)) return false;
  return pyTruthy(evNode(parseExpr(expr), ctx, 0));
}

export function checkPredicate(conditionText) {
  if (!isDeterministic(conditionText)) return [];
  const expr = exprOf(conditionText);
  const loweredExpr = expr.toLowerCase();
  if (ALWAYS.has(loweredExpr) || NEVER.has(loweredExpr)) return [];
  if (!expr) return [`empty \`when\` predicate in ${JSON.stringify(conditionText)}`];
  try {
    parseExpr(expr);
  } catch (err) {
    return [`unparseable/unsafe predicate ${JSON.stringify(conditionText)}: ${err.message}`];
  }
  return [];
}

// ------------------------------------------------------------------ Level M classification
const _LM = {
  CHAINED: "chained-comparison", FIELD_VS_FIELD: "field-vs-field", SUBSTRING: "substring-in",
  NONLITERAL: "non-literal-collection", STRING_ORDER: "string-ordering", CONSTANT: "constant-only",
  NESTED: "nested-container", SYNTAX: "disallowed-or-unparseable",
};
const _LM_ORDER = new Set(["<", "<=", ">", ">="]);

function _lmScalarConst(astNode) {
  return astNode && astNode.k === "const" &&
    (astNode.v === null || typeof astNode.v === "boolean" ||
     (typeof astNode.v === "number" && !astNode.float) || typeof astNode.v === "string");
}

function _lmAtomReason(astNode) {
  if (!astNode) return _LM.SYNTAX;
  if (astNode.k === "name") return null;
  if (astNode.k === "const") return _LM.CONSTANT;
  if (astNode.k === "cmp") {
    if (astNode.ops.length !== 1) return _LM.CHAINED;
    const operator = astNode.ops[0];
    const left = astNode.left;
    const right = astNode.rights[0];
    if (operator === "in" || operator === "not in") {
      if (left.k !== "name") return left.k === "const" ? _LM.CONSTANT : _LM.FIELD_VS_FIELD;
      if (right.k === "const" && typeof right.v === "string") return _LM.SUBSTRING;
      if (right.k === "list") {
        for (const elementAst of right.elts) {
          if (elementAst.k === "list") return _LM.NESTED;
          if (!_lmScalarConst(elementAst)) return _LM.NONLITERAL;
        }
        return null;
      }
      return _LM.NONLITERAL;
    }
    let constVar = null;
    if (left.k === "name" && _lmScalarConst(right)) constVar = right;
    else if (right.k === "name" && _lmScalarConst(left)) constVar = left;
    else if (left.k === "name" && right.k === "name") return _LM.FIELD_VS_FIELD;
    else return (_lmScalarConst(left) && _lmScalarConst(right)) ? _LM.CONSTANT : _LM.SYNTAX;
    if (_LM_ORDER.has(operator) && typeof constVar.v === "string") return _LM.STRING_ORDER;
    return null;
  }
  return _LM.SYNTAX;
}

function _desugarChains(astNode) {
  if (!astNode) return astNode;
  if (astNode.k === "and" || astNode.k === "or") {
    return { k: astNode.k, vals: astNode.vals.map(_desugarChains) };
  }
  if (astNode.k === "not") {
    return { k: "not", v: _desugarChains(astNode.v) };
  }
  if (astNode.k === "cmp" && astNode.ops.length > 1) {
    const operands = [astNode.left, ...astNode.rights];
    return {
      k: "and",
      vals: astNode.ops.map((operator, index) =>
        ({ k: "cmp", ops: [operator], left: operands[index], rights: [operands[index + 1]] }))
    };
  }
  return astNode;
}

function _lmClassify(astNode) {
  if (astNode.k === "and" || astNode.k === "or") {
    for (const childAst of astNode.vals) {
      const reason = _lmClassify(childAst);
      if (reason !== null) return reason;
    }
    return null;
  }
  if (astNode.k === "not") return _lmClassify(astNode.v);
  return _lmAtomReason(astNode);
}

export function isLevelM(conditionText) {
  if (!isDeterministic(conditionText)) {
    if (isError(conditionText)) {
      let expr = errorExpr(conditionText);
      if (!expr) return { level_m: true, reason: null };
      if (!expr.toLowerCase().startsWith("when ")) expr = "when " + expr;
      return isLevelM(expr);
    }
    return { level_m: false, reason: "not-deterministic" };
  }
  const expr = exprOf(conditionText);
  const loweredExpr = expr.toLowerCase();
  if (ALWAYS.has(loweredExpr) || NEVER.has(loweredExpr)) return { level_m: true, reason: null };
  let astNode;
  try {
    astNode = parseExpr(expr);
  } catch {
    return { level_m: false, reason: _LM.SYNTAX };
  }
  astNode = _desugarChains(astNode);
  const reason = _lmClassify(astNode);
  return { level_m: reason === null, reason };
}

export function flowLevelM(graph) {
  const violations = [];
  for (const nodeName of [...reachable(graph)].sort()) {
    const nodeRec = graph.nodes[nodeName];
    if (!nodeRec) continue;
    for (const [targetName, conditionText] of nodeRec.edges) {
      if (!isDeterministic(conditionText)) continue;
      const levelResult = isLevelM(conditionText);
      if (!levelResult.level_m) {
        violations.push({ node: nodeName, target: targetName, condition: conditionText, level_m: false, reason: levelResult.reason });
      }
    }
  }
  return { level_m: violations.length === 0, non_member_edges: violations };
}

export function capabilityReport(graph) {
  const semanticViolations = portabilityViolations(graph);
  const isP0 = semanticViolations.length === 0;
  const levelMResult = flowLevelM(graph);
  const hardwareOk = isP0 && levelMResult.level_m;
  const compileTargets = {
    python: { status: "yes", reason: null, blocking_edges: [] },
    portable: {
      status: isP0 ? "yes" : "needs-lockfile",
      reason: isP0 ? null
        : `${semanticViolations.length} reachable semantic edge(s) — P0 runs unconditionally; lock them for P1`,
      blocking_edges: isP0 ? [] : semanticViolations,
    },
    level_m_hardware: {
      status: hardwareOk ? "yes" : "no",
      reason: hardwareOk ? null
        : (!isP0 ? `${semanticViolations.length} reachable semantic edge(s) — not deterministic`
               : `${levelMResult.non_member_edges.length} deterministic edge(s) outside the match-action fragment`),
      blocking_edges: !isP0 ? semanticViolations : (hardwareOk ? [] : levelMResult.non_member_edges),
    },
  };
  return {
    tier: isP0 ? "P0" : "P1/P2",
    level_m: levelMResult.level_m,
    targets: compileTargets,
  };
}

// ------------------------------------------------------------ reachability
const _FRESH_STR = "\u0000fresh";
const _CERTAIN = "certain";
const _MAY = "may";
const _PRODUCT_CAP = 50000;

function _condAst(conditionText) {
  if (!isDeterministic(conditionText)) return null;
  const expr = exprOf(conditionText);
  const loweredExpr = expr.toLowerCase();
  if (ALWAYS.has(loweredExpr) || NEVER.has(loweredExpr)) return null;
  try {
    return parseExpr(expr);
  } catch {
    return null;
  }
}

function _walk(astNode, outputList) {
  if (!astNode) return;
  outputList.push(astNode);
  if (astNode.k === "and" || astNode.k === "or") {
    astNode.vals.forEach((childAst) => _walk(childAst, outputList));
  } else if (astNode.k === "not") {
    _walk(astNode.v, outputList);
  } else if (astNode.k === "cmp") {
    _walk(astNode.left, outputList);
    astNode.rights.forEach((childAst) => _walk(childAst, outputList));
  } else if (astNode.k === "list") {
    astNode.elts.forEach((elementAst) => _walk(elementAst, outputList));
  }
}

function _constsOf(astNode) {
  const collectedList = [];
  _walk(astNode, collectedList);
  return collectedList.filter((foundNode) => foundNode.k === "const").map((foundNode) => foundNode.v);
}

function _fieldsOf(astNode) {
  const collectedList = [];
  _walk(astNode, collectedList);
  return new Set(collectedList.filter((foundNode) => foundNode.k === "name").map((foundNode) => foundNode.v));
}

function _candidates(constList) {
  const numbers = [...new Set(constList.filter((constVal) => typeof constVal === "number" && !Number.isNaN(constVal)))].sort((numLeft, numRight) => numLeft - numRight);
  const candidates = [null, true, false, 0, 1, "", _FRESH_STR];
  for (const constVal of constList) candidates.push(constVal);
  for (const numVal of numbers) candidates.push(numVal - 1, numVal + 1);
  for (let index = 0; index + 1 < numbers.length; index++) {
    candidates.push((numbers[index] + numbers[index + 1]) / 2);
  }
  const seenKeys = new Set();
  const outputCandidates = [];
  for (const candidateVal of candidates) {
    const typeName = candidateVal === null ? "null" : typeof candidateVal;
    const candidateKey = typeName + ":" + (typeof candidateVal === "number" && Number.isNaN(candidateVal) ? "nan" : String(candidateVal));
    if (!seenKeys.has(candidateKey)) {
      seenKeys.add(candidateKey);
      outputCandidates.push(candidateVal);
    }
  }
  return outputCandidates;
}

function _nodeSat(graph, nodeName, assumeCond) {
  const nodeRec = graph.nodes[nodeName];
  const detEdges = [];
  nodeRec.edges.forEach(([targetName, condText], edgeIndex) => {
    if (isDeterministic(condText)) {
      detEdges.push({ index: edgeIndex, target: targetName, condition: condText });
    }
  });
  let constList = [];
  let fieldSet = new Set();
  let isComplete = true;
  const exprList = detEdges.map((detEdge) => detEdge.condition).concat(assumeCond ? [assumeCond] : []);
  for (const conditionText of exprList) {
    const astTree = _condAst(conditionText);
    if (astTree === null) continue;
    constList = constList.concat(_constsOf(astTree));
    for (const fieldName of _fieldsOf(astTree)) {
      fieldSet.add(fieldName);
    }
    if (!isLevelM(conditionText).level_m) isComplete = false;
  }
  fieldSet.delete("visits");
  const candidates = _candidates(constList);
  const fieldList = [...fieldSet].sort();
  if (Math.pow(candidates.length, fieldList.length) > _PRODUCT_CAP) isComplete = false;
  return { detEdges, fields: fieldList, candidates, complete: isComplete };
}

function* _contexts(satInfo, visitsCount) {
  if (satInfo.fields.length === 0) {
    yield { visits: visitsCount };
    return;
  }
  let totalContexts = 1;
  for (let index = 0; index < satInfo.fields.length; index++) {
    totalContexts *= satInfo.candidates.length;
    if (totalContexts > _PRODUCT_CAP) return;
  }
  const fieldCount = satInfo.fields.length;
  const indices = new Array(fieldCount).fill(0);
  for (;;) {
    const ctx = { visits: visitsCount };
    for (let index = 0; index < fieldCount; index++) {
      ctx[satInfo.fields[index]] = satInfo.candidates[indices[index]];
    }
    yield ctx;
    let cursorPos = fieldCount - 1;
    for (; cursorPos >= 0; cursorPos--) {
      if (++indices[cursorPos] < satInfo.candidates.length) break;
      indices[cursorPos] = 0;
    }
    if (cursorPos < 0) break;
  }
}

function _edgeOutcomes(satInfo, assumeCond, visitsCount) {
  const takeable = {};
  let noneMatch = null;
  let sawContext = false;
  for (const ctx of _contexts(satInfo, visitsCount)) {
    sawContext = true;
    if (assumeCond) {
      let assumeOk;
      try {
        assumeOk = evalCondition(assumeCond, ctx);
      } catch (err) {
        if (err instanceof PredicateError) continue;
        throw err;
      }
      if (!assumeOk) continue;
    }
    let matchedIndex = null;
    for (const detEdge of satInfo.detEdges) {
      let conditionHit;
      try {
        conditionHit = evalCondition(detEdge.condition, ctx);
      } catch (err) {
        if (err instanceof PredicateError) conditionHit = false;
        else throw err;
      }
      if (conditionHit) {
        matchedIndex = detEdge.index;
        break;
      }
    }
    const stripVisits = () => {
      const contextCopy = { ...ctx };
      delete contextCopy.visits;
      return contextCopy;
    };
    if (matchedIndex === null) {
      if (noneMatch === null) noneMatch = stripVisits();
    } else if (!(matchedIndex in takeable)) {
      takeable[matchedIndex] = stripVisits();
    }
  }
  if (!sawContext) return [{}, null];
  if (satInfo.complete && noneMatch === null) noneMatch = false;
  return [takeable, noneMatch];
}

function _visitCaps(graph) {
  const visitCaps = {};
  for (const [nodeName, nodeRec] of Object.entries(graph.nodes)) {
    let bestCap = null;
    for (const [, condText] of nodeRec.edges) {
      let cond = condText;
      if (isError(condText)) {
        const expr = errorExpr(condText);
        if (!expr) continue;
        cond = expr.toLowerCase().startsWith("when ") ? expr : "when " + expr;
      }
      const astTree = _condAst(cond);
      if (astTree === null || !_fieldsOf(astTree).has("visits")) continue;
      const numbers = _constsOf(astTree).filter((val) => typeof val === "number" && !Number.isNaN(val));
      const maxVal = numbers.length ? Math.max(...numbers) : 0;
      bestCap = Math.max(bestCap === null ? 0 : bestCap, Math.trunc(maxVal));
    }
    if (bestCap !== null) visitCaps[nodeName] = bestCap + 2;
  }
  return visitCaps;
}

export function checkReach(graph, targets, opts = {}) {
  let { assume = null, bound = 25, includeErrors = true, includeEvents = true } = opts;
  const assumeCond = assume && !assume.trim().toLowerCase().startsWith("when ") ? "when " + assume : assume;
  const visitCaps = _visitCaps(graph);
  const satMap = {};
  for (const nodeName of Object.keys(graph.nodes)) {
    satMap[nodeName] = _nodeSat(graph, nodeName, assumeCond);
  }

  const bumpVisits = (counts, nodeName) => {
    if (!(nodeName in visitCaps)) return counts;
    const countsMap = new Map(counts);
    countsMap.set(nodeName, Math.min((countsMap.get(nodeName) || 0) + 1, visitCaps[nodeName]));
    return [...countsMap.entries()].sort((entryLeft, entryRight) => (entryLeft[0] < entryRight[0] ? -1 : entryLeft[0] > entryRight[0] ? 1 : 0));
  };
  const makeStateKey = (nodeName, counts) => JSON.stringify([nodeName, counts]);

  const startCounts = bumpVisits([], graph.start);
  const startKey = makeStateKey(graph.start, startCounts);
  const bestCertainty = new Map([[startKey, _CERTAIN]]);
  const parentMap = new Map();
  const stateMap = new Map([[startKey, [graph.start, startCounts]]]);
  const depthMap = new Map([[startKey, 0]]);
  const frontierQueue = [[startKey, 0]];
  let isExhausted = true;
  let frontierHead = 0;

  while (frontierHead < frontierQueue.length) {
    const [stateKey, depthVal] = frontierQueue[frontierHead++];
    const [nodeName, counts] = stateMap.get(stateKey);
    if (depthVal >= bound) {
      isExhausted = false;
      continue;
    }
    const nodeRec = graph.nodes[nodeName];
    if (!nodeRec || nodeRec.edges.length === 0) continue;
    const visitsCount = new Map(counts).get(nodeName) || 1;
    const satInfo = satMap[nodeName];
    const [takeableMap, noneMatch] = _edgeOutcomes(satInfo, assumeCond, visitsCount);
    const currentCertainty = bestCertainty.get(stateKey);

    const candidateMoves = [];
    for (const indexStr of Object.keys(takeableMap)) {
      const [targetName, condText] = nodeRec.edges[Number(indexStr)];
      candidateMoves.push([targetName, condText, currentCertainty]);
    }
    if (!satInfo.complete) {
      const takenIndices = new Set(Object.keys(takeableMap).map(Number));
      for (const detEdge of satInfo.detEdges) {
        if (!takenIndices.has(detEdge.index)) {
          candidateMoves.push([detEdge.target, detEdge.condition, _MAY]);
        }
      }
    }
    if (noneMatch !== false) {
      nodeRec.edges.forEach(([targetName, condText]) => {
        if (isSemantic(condText)) candidateMoves.push([targetName, condText, _MAY]);
      });
    }
    if (includeErrors) {
      nodeRec.edges.forEach(([targetName, condText]) => {
        if (isError(condText)) candidateMoves.push([targetName, condText, _MAY]);
      });
    }
    if (includeEvents) {
      nodeRec.edges.forEach(([targetName, condText]) => {
        if (isEvent(condText)) candidateMoves.push([targetName, condText, _MAY]);
      });
    }

    for (const [targetName, condText, stepCertainty] of candidateMoves) {
      if (!(targetName in graph.nodes)) continue;
      const nextCertainty = (currentCertainty === _CERTAIN && stepCertainty === _CERTAIN) ? _CERTAIN : _MAY;
      const nextCounts = bumpVisits(counts, targetName);
      const nextKey = makeStateKey(targetName, nextCounts);
      const prevCertainty = bestCertainty.get(nextKey);
      if (prevCertainty === undefined || (prevCertainty === _MAY && nextCertainty === _CERTAIN)) {
        bestCertainty.set(nextKey, nextCertainty);
        parentMap.set(nextKey, [stateKey, { node: nodeName, target: targetName, condition: condText, certainty: nextCertainty }]);
        stateMap.set(nextKey, [targetName, nextCounts]);
        depthMap.set(nextKey, depthVal + 1);
        frontierQueue.push([nextKey, depthVal + 1]);
      }
    }
  }

  // `proven` reads only on a "no" verdict, where it says the state space was exhausted rather than
  // the bound hit; a reached target therefore always reports proven: false, which is not a weaker
  // claim about the hit but a field that does not apply to it. The Python ReachResult says the same.
  const reachResults = {};
  for (const reachTarget of targets) {
    const matchingHits = [...bestCertainty.entries()].filter(([hitKey]) => stateMap.get(hitKey)[0] === reachTarget);
    if (matchingHits.length === 0) {
      reachResults[reachTarget] = { node: reachTarget, reachable: "no", proven: isExhausted, depth: null, witness: [] };
      continue;
    }
    const certainHit = matchingHits.find(([, hitCertainty]) => hitCertainty === _CERTAIN);
    const chosenKey = certainHit ? certainHit[0] : matchingHits[0][0];
    const witnessSteps = [];
    let currentKey = chosenKey;
    while (parentMap.has(currentKey)) {
      const [prevKey, stepRecord] = parentMap.get(currentKey);
      witnessSteps.push(stepRecord);
      currentKey = prevKey;
    }
    witnessSteps.reverse();
    reachResults[reachTarget] = { node: reachTarget, reachable: certainHit ? "yes" : "may", proven: false, depth: depthMap.get(chosenKey), witness: witnessSteps };
  }
  return reachResults;
}

// ---------------------------------------------------------------------------- parsing
const EDGE_RE = /^\s*-?\s*->\s*([A-Za-z0-9_\-]+)\s*:\s*(.+?)\s*$/;
const HEAD_RE = /^\s*##\s+(.+?)\s*$/;
const ANNO_RE = /^\s*@([\p{L}\p{N}_]+)\s*\((.*)\)\s*$/u;
const LINE_SPLIT_RE = /\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]/;

function parseAnnoArgs(argString) {
  const parsedArgs = {};
  for (let argPart of argString.split(",")) {
    argPart = argPart.trim();
    if (!argPart) continue;
    const equalsPos = argPart.indexOf("=");
    if (equalsPos >= 0) {
      const argKey = argPart.slice(0, equalsPos).trim();
      if (argKey) parsedArgs[argKey] = argPart.slice(equalsPos + 1).trim();
    } else {
      parsedArgs[argPart] = null;
    }
  }
  return parsedArgs;
}

const FRONTMATTER_RE = new RegExp(`^---${PY_WS}*\\n([\\s\\S]*?)\\n---${PY_WS}*\\n([\\s\\S]*)$`);

export function parse(sourceText) {
  const frontmatterMeta = {};
  let flowBody = sourceText;
  const frontmatterMatch = sourceText.match(FRONTMATTER_RE);
  if (frontmatterMatch) {
    for (const lineText of frontmatterMatch[1].split(LINE_SPLIT_RE)) {
      const colonPos = lineText.indexOf(":");
      if (colonPos >= 0) frontmatterMeta[pyTrim(lineText.slice(0, colonPos))] = pyTrim(lineText.slice(colonPos + 1));
    }
    flowBody = frontmatterMatch[2];
  }
  const nodesMap = {};
  const nodeOrder = [];
  let currentNodeRec = null;
  let instructionLines = [];
  const flushInstruction = () => {
    if (currentNodeRec) currentNodeRec.instruction = instructionLines.join("\n").trim();
  };
  for (const lineText of flowBody.split(LINE_SPLIT_RE)) {
    const headerMatch = lineText.match(HEAD_RE);
    if (headerMatch) {
      flushInstruction();
      const nodeName = headerMatch[1].trim().toLowerCase().replace(/ /g, "_");
      currentNodeRec = { name: nodeName, instruction: "", edges: [], annotations: {} };
      if (!Object.prototype.hasOwnProperty.call(nodesMap, nodeName)) nodeOrder.push(nodeName);
      nodesMap[nodeName] = currentNodeRec;
      instructionLines = [];
      continue;
    }
    if (!currentNodeRec) continue;
    const edgeMatch = lineText.match(EDGE_RE);
    const annotationMatch = lineText.match(ANNO_RE);
    if (edgeMatch) {
      currentNodeRec.edges.push([edgeMatch[1].trim(), edgeMatch[2].trim()]);
    } else if (annotationMatch) {
      const annotationName = annotationMatch[1].trim();
      currentNodeRec.annotations[annotationName] = { ...(currentNodeRec.annotations[annotationName] || {}), ...parseAnnoArgs(annotationMatch[2]) };
    } else {
      instructionLines.push(lineText);
    }
  }
  flushInstruction();
  const nodeNames = Object.keys(nodesMap);
  const graph = {
    name: frontmatterMeta.name !== undefined ? frontmatterMeta.name : "flow",
    start: frontmatterMeta.start || (nodeNames[0] || ""),
    nodes: nodesMap,
    order: nodeOrder,       // the nodes in the order the text first wrote them (Python's dictionary order)
    fields: {},             // the field definitions of SPEC section 4.5, by name; empty when the flow defines none
    routed: [],             // the defined fields some deterministic edge reads, in code point order
  };
  // A flow that defines its fields is checked in the verified core's order and its decimal thresholds are
  // lowered to canonical integers here, as the reference does; a flow that breaks a rule throws a
  // FieldDefinitionError for the first problem, so no engine run is ever built from it.
  applyDefinitions(graph, frontmatterMeta);
  return graph;
}

// ---------------------------------------------------------------------- portability gate
export function reachable(graph) {
  const visitedNodes = new Set();
  const nodeStack = [graph.start];
  while (nodeStack.length) {
    const currentNode = nodeStack.pop();
    if (visitedNodes.has(currentNode) || !(currentNode in graph.nodes)) continue;
    visitedNodes.add(currentNode);
    for (const [targetName] of graph.nodes[currentNode].edges) {
      if (targetName in graph.nodes && !visitedNodes.has(targetName)) {
        nodeStack.push(targetName);
      }
    }
  }
  return visitedNodes;
}

export function portabilityViolations(graph) {
  const violations = [];
  for (const nodeName of [...reachable(graph)].sort()) {
    const nodeRec = graph.nodes[nodeName];
    if (!nodeRec) continue;
    for (const [targetName, conditionText] of nodeRec.edges) {
      if (isSemantic(conditionText)) {
        violations.push({ node: nodeName, target: targetName, condition: conditionText });
      }
    }
  }
  return violations;
}

// ------------------------------------------------------------------- P1: locked routing
export function decodeVec(base64String) {
  if (typeof Buffer !== "undefined") {
    const buffer = Buffer.from(base64String, "base64");
    return new Float32Array(buffer.buffer, buffer.byteOffset, buffer.byteLength / 4);
  }
  const binaryString = atob(base64String);
  const byteArray = new Uint8Array(binaryString.length);
  for (let byteIndex = 0; byteIndex < binaryString.length; byteIndex++) {
    byteArray[byteIndex] = binaryString.charCodeAt(byteIndex);
  }
  return new Float32Array(byteArray.buffer);
}

// A compiled bundle halves its embedded lock by storing the committed vectors as float16, so the
// decode lives here beside decodeVec rather than in a second copy inside the bundle.
export function decodeVecF16(base64String) {
  const byteArray = typeof Buffer !== "undefined"
    ? Buffer.from(base64String, "base64")
    : Uint8Array.from(atob(base64String), (character) => character.charCodeAt(0));
  const view = new DataView(byteArray.buffer, byteArray.byteOffset, byteArray.byteLength);
  const floats = new Float32Array(byteArray.byteLength / 2);
  for (let halfIndex = 0; halfIndex < floats.length; halfIndex++) {
    const half = view.getUint16(halfIndex * 2, true);
    const sign = (half & 0x8000) >> 15;
    const exponent = (half & 0x7c00) >> 10;
    const fraction = half & 0x03ff;
    let value;
    if (exponent === 0) {
      value = (sign ? -1 : 1) * Math.pow(2, -14) * (fraction / 1024);
    } else if (exponent === 31) {
      value = fraction ? NaN : (sign ? -Infinity : Infinity);
    } else {
      value = (sign ? -1 : 1) * Math.pow(2, exponent - 15) * (1 + fraction / 1024);
    }
    floats[halfIndex] = value;
  }
  return floats;
}

// Both sides are unit normalized when the lock is written, so the dot product IS the cosine. The
// width check is what the Python reference gets for free from numpy: a locked vector of the wrong
// width has to stop the run, because iterating the query's width alone reads past the shorter side
// and scores that edge NaN, which then loses every comparison and silently reroutes the flow.
function cosine(vecA, vecB) {
  if (vecA.length !== vecB.length) {
    throw new Error(`locked vector width ${vecB.length} does not match the embedding's ${vecA.length}: the lock was written by a different embedder; re-run \`prismpath lock\``);
  }
  let dotProduct = 0;
  for (let vecIndex = 0; vecIndex < vecA.length; vecIndex++) {
    dotProduct += vecA[vecIndex] * vecB[vecIndex];
  }
  return dotProduct;
}

function lockVec(lockfile, conditionText) {
  const centroidRec = lockfile.centroids?.[conditionText];
  if (centroidRec) return decodeVec(centroidRec.vec);
  const conditionVecEntry = lockfile.conditions?.[conditionText];
  if (typeof conditionVecEntry === "string") return decodeVec(conditionVecEntry);
  // A caller may hand in vectors it already decoded once at load (the compiled bundle does).
  if (conditionVecEntry) return conditionVecEntry;
  return null;
}

export function lockedRoute(outcomeText, semanticEdges, lockfile, embedFn) {
  const queryVector = embedFn(outcomeText);
  const similarityScores = new Array(semanticEdges.length);
  const similarityMap = {};
  for (let edgeIndex = 0; edgeIndex < semanticEdges.length; edgeIndex++) {
    const [targetName, conditionText] = semanticEdges[edgeIndex];
    const conditionVector = lockVec(lockfile, conditionText);
    if (!conditionVector) {
      throw new Error(`condition not in lock: ${JSON.stringify(conditionText)}: the flow changed; re-run \`prismpath lock\``);
    }
    similarityScores[edgeIndex] = cosine(queryVector, conditionVector);
    similarityMap[targetName] = similarityScores[edgeIndex];
  }
  const sortedIndices = [...similarityScores.keys()].sort((leftIndex, rightIndex) => similarityScores[rightIndex] - similarityScores[leftIndex]);
  const topIndex = sortedIndices[0];
  const scoreMargin = sortedIndices.length > 1 ? similarityScores[sortedIndices[0]] - similarityScores[sortedIndices[1]] : 1.0;
  return {
    target: semanticEdges[topIndex][0],
    info: { used: "locked", locked: true, score: similarityScores[topIndex], margin: scoreMargin, sims: similarityMap },
  };
}

// -------------------------------------------------------------------------- the engine helpers
function pyStr(val) {
  if (val === true) return "True";
  if (val === false) return "False";
  if (val === null || val === undefined) return "None";
  if (typeof val === "string") return val;
  if (Array.isArray(val)) return "[" + val.map(pyRepr).join(", ") + "]";
  if (typeof val === "object") {
    return "{" + Object.entries(val).map(([key, item]) => `'${key}': ${pyRepr(item)}`).join(", ") + "}";
  }
  return String(val);
}

function pyRepr(val) {
  if (typeof val === "string") return `'${val}'`;
  return pyStr(val);
}

export function normalize(outcome) {
  if (outcome !== null && typeof outcome === "object" && !Array.isArray(outcome)) {
    const textVal = "text" in outcome ? pyStr(outcome.text) : "";
    return [textVal, { ...outcome }];
  }
  return [pyStr(outcome), { text: pyStr(outcome) }];
}

export function firstDeterministic(edgeList, ctx) {
  for (const [targetName, conditionText] of edgeList) {
    if (!isDeterministic(conditionText)) continue;
    try {
      if (evalCondition(conditionText, ctx)) return [targetName, conditionText];
    } catch (err) {
      if (!(err instanceof PredicateError)) throw err;
    }
  }
  return [null, null];
}

export function eventTarget(graph, nodeName, eventNameVal) {
  const nodeRec = graph.nodes[nodeName];
  if (!nodeRec) return null;
  for (const [targetName, conditionText] of nodeRec.edges) {
    if (isEvent(conditionText) && eventName(conditionText) === eventNameVal) return targetName;
  }
  return null;
}

// Named helper: handles the error tier when worker execution throws
export function handleErrorTier(currentNode, nodeRec, runState, err, runResult) {
  const errorCounts = (runState._errors = runState._errors || {});
  errorCounts[currentNode] = (errorCounts[currentNode] || 0) + 1;
  const errorCtx = {
    error: true,
    error_type: err.constructor?.name || "Error",
    error_message: String(err.message ?? err),
    error_count: errorCounts[currentNode],
    visits: runState.visits[currentNode],
  };
  let errorTarget = null;
  for (const [targetName, conditionText] of nodeRec.edges) {
    if (!isError(conditionText)) continue;
    const expr = errorExpr(conditionText);
    try {
      if (!expr || evalCondition(expr, errorCtx)) {
        errorTarget = targetName;
        break;
      }
    } catch (predErr) {
      if (!(predErr instanceof PredicateError)) throw predErr;
    }
  }
  if (errorTarget === null) {
    throw err;
  }
  const errorText = `[error: ${errorCtx.error_type}: ${errorCtx.error_message}]`;
  runState.transcript.push({ node: currentNode, outcome: errorText, error: true });
  runResult.steps.push({ node: currentNode, outcome: errorText, target: errorTarget, info: { used: "error", error_type: errorCtx.error_type } });
  runResult.path.push(errorTarget);
  return errorTarget;
}

// Named helper: evaluates tier selection (deterministic vs locked semantic)
export function selectTier(nodeRec, outcomeText, fieldsObj, contextObj, lockfile, embedFn, humanFloor) {
  const [detTarget, detCondition] = firstDeterministic(nodeRec.edges, contextObj);
  if (detTarget !== null) {
    return { target: detTarget, info: { used: "deterministic", cond: detCondition } };
  }
  const semanticEdges = nodeRec.edges.filter(([, conditionText]) => isSemantic(conditionText));
  if (semanticEdges.length && embedFn && lockfile) {
    const decision = lockedRoute(outcomeText, semanticEdges, lockfile, embedFn);
    if (humanFloor != null && decision.info.score != null && decision.info.score < humanFloor) {
      return {
        needsHuman: true,
        pending: {
          node: nodeRec.name,
          reason: `router confidence ${decision.info.score.toFixed(3)} < human_floor ${humanFloor}`,
          would_pick: decision.target,
          candidates: semanticEdges.map(([targetName, conditionText]) => ({
            target: targetName,
            condition: conditionText,
            score: decision.info.sims[targetName],
          })),
        },
      };
    }
    return { target: decision.target, info: decision.info };
  }
  return { stuck: true };
}

// The shape of `pending` when the worker asks for a human. Shared with the compiled bundle's
// engine (bundle_engine.mjs) so a resumer sees one payload whichever engine suspended the run.
export function pendingNeedsHuman(currentNode, nodeRec, fieldsObj, outcomeText) {
  return {
    node: currentNode,
    reason: fieldsObj.reason || outcomeText,
    candidates: nodeRec.edges.map(([targetName, conditionText]) => ({ target: targetName, condition: conditionText })),
  };
}

// The shape of `pending` when the worker asks to wait for an event or to fan out.
export function pendingWait(currentNode, nodeRec, fieldsObj) {
  const eventEdges = nodeRec.edges.filter(([, conditionText]) => isEvent(conditionText));
  const pending = {
    node: currentNode,
    wait: true,
    awaiting: eventEdges.map(([, conditionText]) => eventName(conditionText)),
    timeout_s: fieldsObj.timeout_s ?? null,
    candidates: eventEdges.map(([targetName, conditionText]) => ({ target: targetName, condition: conditionText })),
  };
  if (fieldsObj.spawn != null) {
    pending.spawn = fieldsObj.spawn;
  }
  return pending;
}

// Named helper: records a step into runResult
export function recordStep(runResult, currentNode, outcomeText, targetNode, stepInfo) {
  runResult.steps.push({ node: currentNode, outcome: outcomeText, target: targetNode, info: stepInfo });
  runResult.path.push(targetNode);
}

// Named helper: executes one step of the run engine
function runStep(graph, currentNode, runState, agentFn, optionsObj, runResult) {
  const nodeRec = graph.nodes[currentNode];
  if (nodeRec.edges.length === 0) {
    runResult.stopped = "terminal";
    return { terminal: true };
  }
  if (optionsObj.onStep) {
    optionsObj.onStep(runResult, currentNode);
  }
  runState.visits[currentNode] = (runState.visits[currentNode] || 0) + 1;

  let outcome;
  try {
    outcome = agentFn(currentNode, nodeRec.instruction, runState);
  } catch (err) {
    const errorTarget = handleErrorTier(currentNode, nodeRec, runState, err, runResult);
    return { nextNode: errorTarget };
  }

  const [outcomeText, fieldsObj] = normalize(outcome);
  runState.transcript.push({ node: currentNode, outcome: outcomeText });
  (runState._outcomes = runState._outcomes || {})[currentNode] = { ...fieldsObj };

  if (pyTruthy(fieldsObj.needs_human)) {
    runResult.stopped = "needs_human";
    runResult.pending = pendingNeedsHuman(currentNode, nodeRec, fieldsObj, outcomeText);
    if (optionsObj.onStep) {
      optionsObj.onStep(runResult, currentNode);
    }
    return { suspend: true };
  }

  if (pyTruthy(fieldsObj.wait) || fieldsObj.spawn != null) {
    runResult.stopped = "waiting";
    runResult.pending = pendingWait(currentNode, nodeRec, fieldsObj);
    if (optionsObj.onStep) {
      optionsObj.onStep(runResult, currentNode);
    }
    return { suspend: true };
  }

  const contextObj = { ...fieldsObj, visits: runState.visits[currentNode] };
  const tierResult = selectTier(nodeRec, outcomeText, fieldsObj, contextObj, optionsObj.lock, optionsObj.embed, optionsObj.humanFloor);
  if (tierResult.needsHuman) {
    runResult.stopped = "needs_human";
    runResult.pending = tierResult.pending;
    if (optionsObj.onStep) {
      optionsObj.onStep(runResult, currentNode);
    }
    return { suspend: true };
  }
  if (tierResult.stuck) {
    runResult.stopped = "stuck";
    if (optionsObj.onStep) {
      optionsObj.onStep(runResult, currentNode);
    }
    return { suspend: true };
  }

  recordStep(runResult, currentNode, outcomeText, tierResult.target, tierResult.info);
  return { nextNode: tierResult.target };
}

/**
 * Run a PORTABLE flow: a faithful port of engine.run for the ML-free subset (no semantic
 * tier, no type_gate). `agent(node, instruction, state)` returns a string or an object with
 * structured fields + `text`. Options: {maxSteps=25, start=null, state=null, onStep=null}.
 * Returns {path, steps, stopped, state, pending} exactly like the Python RunResult.
 * REFUSES a non-portable flow (semantic edge on a reachable node) up front.
 *
 * A `state` passed in is MUTATED in place and also handed back on the result, exactly as the Python
 * engine does it: transcript, visits and the error/outcome counters have to survive a suspension so
 * a resume continues the same run. A caller that wants a fresh run must pass a fresh object; reusing
 * one accumulates the previous run's history, which is the point when resuming and a bug otherwise.
 */
export function run(graph, agent, opts = {}) {
  const {
    maxSteps = 25, start = null, state: initialState = null, onStep = null,
    lock = null, embed = null, humanFloor = null
  } = opts;
  const portabilityViolationsList = portabilityViolations(graph);
  if (portabilityViolationsList.length) {
    if (!lock || !embed) {
      const violationRec = portabilityViolationsList[0];
      throw new Error(
        `flow is not portable: semantic edge [${violationRec.node}] -> ${violationRec.target} (${JSON.stringify(violationRec.condition)}) ` +
        `needs the embedding/LLM tier: run it on the Python engine, or rewrite the edge as a \`when\` predicate`);
    }
    for (const violationRec of portabilityViolationsList) {
      if (!lockVec(lock, violationRec.condition)) {
        throw new Error(
          `lockfile does not cover semantic condition ${JSON.stringify(violationRec.condition)} ` +
          `on edge [${violationRec.node}] -> ${violationRec.target}: re-run \`prismpath lock\``);
      }
    }
  }
  let currentNode = start !== null ? start : graph.start;
  const runState = initialState || {};
  runState.transcript = runState.transcript || [];
  runState.visits = runState.visits || {};
  const runResult = { path: [currentNode], steps: [], stopped: "", state: runState, pending: null };
  const optionsObj = { maxSteps, start, state: initialState, onStep, lock, embed, humanFloor };

  for (let stepIndex = 0; stepIndex < maxSteps; stepIndex++) {
    const stepOutcome = runStep(graph, currentNode, runState, agent, optionsObj, runResult);
    if (stepOutcome.terminal) {
      if (onStep) onStep(runResult, null);
      break;
    }
    if (stepOutcome.suspend) {
      break;
    }
    currentNode = stepOutcome.nextNode;
  }
  if (!runResult.stopped) {
    runResult.stopped = "max_steps";
  }
  return runResult;
}

/**
 * Build the worker that replays a corpus fixture's `script` field.
 *
 * Every frozen corpus encodes its worker the same way: `script` maps a node name to a LIST of
 * outcomes consumed in visit order, the last entry repeating once the visits outrun the list, and
 * an outcome of {"__raise__": "message"} throws instead of returning so a fixture can drive the
 * error tier. A node the script does not name answers with its own name.
 *
 * This reader lives beside run() because it is the wire contract of a corpus field rather than a
 * detail of any one runner: it used to be hand kept in four files that had to be corrected together.
 */
export function scriptedAgent(script) {
  const visitCounts = {};
  return (node, _instruction, _state) => {
    const outcomeList = script[node];
    if (outcomeList === undefined) {
      return { text: node };
    }
    const callIndex = visitCounts[node] || 0;
    visitCounts[node] = callIndex + 1;
    const outcome = outcomeList[Math.min(callIndex, outcomeList.length - 1)];
    if (outcome !== null && typeof outcome === "object" && "__raise__" in outcome) {
      throw new Error(outcome.__raise__);
    }
    return outcome;
  };
}

// ---------------------------------------------------------------------- crypto agility proofs
const SUITE_NODE_PREFIX = "suite-";
const REACH_BOUND = 25;
const PQ_KEM_TOKENS = ["ml-kem", "kyber"];

// canon/2, the integer only JCS profile every hashed or signed document is written in
// (prismpath/kernel/canon2.py). A value with no canon/2 form throws.
export const CANON2 = "canon/2";

// One canon/2 implementation: the writer below (canon2Write), which refuses what canon2Read refuses.
export function canon2String(val) {
  return new TextDecoder().decode(canon2Write(val));
}

// The bytes a document is hashed over: its canon/2 bytes. A document that does not name canon/2 (an untagged
// one is canon/1, which is retired), or names another encoding, throws.
export function documentString(doc) {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc) || !("encoding" in doc)) {
    throw new Error('a document without "encoding": "canon/2" is refused: canon/1 is retired and is not read, hashed or verified');
  }
  if (doc.encoding !== CANON2) throw new Error(`unknown encoding ${String(doc.encoding).slice(0, 40)}: only canon/2 is read`);
  return canon2String(doc);
}

export function registryHash(registryData) {
  return sha256Hex(documentString(registryData));
}

export function strengthRank(registryData, suiteId) {
  const suiteObj = registryData?.suites?.[suiteId];
  return suiteObj ? Number(suiteObj.strength_rank) : null;
}

export function suiteIds(registryData) {
  return Object.keys(registryData?.suites || {}).sort();
}

export function suitesBelow(registryData, floorSuiteId) {
  const floorRank = strengthRank(registryData, floorSuiteId);
  if (floorRank === null) throw new Error(`unknown floor suite: ${floorSuiteId}`);
  const suiteIdList = suiteIds(registryData);
  return suiteIdList.filter((suiteId) => (strengthRank(registryData, suiteId) ?? 0) < floorRank).sort();
}

export function isQuantumResistant(registryData, suiteId) {
  const suiteObj = registryData?.suites?.[suiteId];
  if (!suiteObj || typeof suiteObj.kem !== "string") return false;
  const kemName = suiteObj.kem.toLowerCase();
  return PQ_KEM_TOKENS.some((token) => kemName.includes(token));
}

export function classicalOnlyIds(registryData) {
  const suiteIdList = suiteIds(registryData);
  return suiteIdList.filter((suiteId) => !isQuantumResistant(registryData, suiteId)).sort();
}

export function suiteNodes(graph) {
  const suiteNodeMap = {};
  for (const nodeName of Object.keys(graph.nodes)) {
    if (nodeName.startsWith(SUITE_NODE_PREFIX)) {
      suiteNodeMap[nodeName] = nodeName.slice(SUITE_NODE_PREFIX.length);
    }
  }
  return suiteNodeMap;
}

export function reachableSuites(graph, assumeCond = null) {
  const suiteNodeMap = suiteNodes(graph);
  const targetList = Object.keys(suiteNodeMap);
  const reachResults = checkReach(graph, targetList, { assume: assumeCond, bound: REACH_BOUND });
  const reachableSuiteMap = {};
  for (const [nodeName, suiteId] of Object.entries(suiteNodeMap)) {
    reachableSuiteMap[suiteId] = { reachable: reachResults[nodeName].reachable, proven: reachResults[nodeName].proven };
  }
  return reachableSuiteMap;
}

function forbiddenReachable(reachMap, forbiddenSet) {
  const forbiddenViolations = [];
  const sortedForbidden = [...forbiddenSet].sort();
  for (const suiteId of sortedForbidden) {
    const reachRec = reachMap[suiteId];
    if (!reachRec) continue;
    if (reachRec.reachable !== "no") {
      forbiddenViolations.push({ reachable: reachRec.reachable, reason: "reachable", suite: suiteId });
    } else if (!reachRec.proven) {
      forbiddenViolations.push({ reachable: "no", reason: "unproven (bound hit)", suite: suiteId });
    }
  }
  return forbiddenViolations;
}

export function proveEnvelopeClosure(graph, envelopeSpec) {
  const approvedSuitesSet = new Set(envelopeSpec.approved_suites || []);
  const reachMap = reachableSuites(graph);
  const suiteIdList = Object.keys(reachMap).sort();
  const offendingSuites = [];
  const reachableSuiteMap = {};
  for (const suiteId of suiteIdList) {
    const reachRec = reachMap[suiteId];
    if (reachRec.reachable !== "no") {
      reachableSuiteMap[suiteId] = reachRec.reachable;
      if (!approvedSuitesSet.has(suiteId)) {
        offendingSuites.push({ reachable: reachRec.reachable, suite: suiteId });
      }
    }
  }
  return {
    offenders: offendingSuites,
    ok: offendingSuites.length === 0,
    reachable_suites: reachableSuiteMap,
  };
}

export function isCatchall(conditionText) {
  return ALWAYS.has(exprOf(conditionText).toLowerCase());
}

export function proveTotality(graph) {
  const reachableNodeSet = new Set(reachable(graph));
  const suiteNodeSet = new Set(Object.keys(suiteNodes(graph)));
  const uncoveredNodes = [];
  const sortedReachableNodes = [...reachableNodeSet].sort();
  for (const nodeName of sortedReachableNodes) {
    const nodeRec = graph.nodes[nodeName];
    if (!nodeRec || nodeRec.edges.length === 0 || suiteNodeSet.has(nodeName)) continue;
    const hasCatchall = nodeRec.edges.some(([, conditionText]) => isCatchall(conditionText));
    if (!hasCatchall) uncoveredNodes.push(nodeName);
  }
  return {
    nodes_without_catchall: uncoveredNodes,
    ok: uncoveredNodes.length === 0,
  };
}

export function proveClassFloor(graph, envelopeSpec, registryData) {
  const classFieldName = envelopeSpec.class_field || "data_class";
  const floorFailures = [];
  const minSuitesMap = envelopeSpec.min_suite_by_class || {};
  const sortedClassList = Object.keys(minSuitesMap).sort();
  for (const className of sortedClassList) {
    const floorSuiteId = minSuitesMap[className];
    const belowFloorSuites = suitesBelow(registryData, floorSuiteId);
    const assumeCond = `when ${classFieldName} == "${className}"`;
    const reachMap = reachableSuites(graph, assumeCond);
    const forbiddenViolations = forbiddenReachable(reachMap, belowFloorSuites);
    if (forbiddenViolations.length > 0) {
      floorFailures.push({ class: className, floor: floorSuiteId, violations: forbiddenViolations });
    }
  }
  return {
    failures: floorFailures,
    ok: floorFailures.length === 0,
  };
}

export function proveMonotoneMigration(graph, envelopeSpec, registryData) {
  const migrationFloor = envelopeSpec.migration_phase_floor;
  const migrationFieldName = envelopeSpec.migration_phase_field || "migration_phase";
  if (migrationFloor === undefined || migrationFloor === null) {
    return { ok: true, skipped: "no migration_phase_floor in envelope" };
  }
  const classicalSuiteList = classicalOnlyIds(registryData);
  const assumeCond = `when ${migrationFieldName} >= ${Math.trunc(migrationFloor)}`;
  const reachMap = reachableSuites(graph, assumeCond);
  const forbiddenViolations = forbiddenReachable(reachMap, classicalSuiteList);
  return {
    classical_only: classicalSuiteList,
    ok: forbiddenViolations.length === 0,
    phase_floor: Number(migrationFloor),
    violations: forbiddenViolations,
  };
}

export function proveDecidable(graph) {
  const levelMResult = flowLevelM(graph);
  return {
    non_member_edges: levelMResult.non_member_edges,
    ok: levelMResult.level_m,
  };
}

export function proveAll(graph, envelopeSpec, registryData) {
  const proofResults = {
    P1_envelope_closure: proveEnvelopeClosure(graph, envelopeSpec),
    P2_totality: proveTotality(graph),
    P3_class_floor: proveClassFloor(graph, envelopeSpec, registryData),
    P4_monotone_migration: proveMonotoneMigration(graph, envelopeSpec, registryData),
    P5_decidable: proveDecidable(graph),
  };
  const allProofsOk = Object.values(proofResults).every((proofResult) => proofResult.ok);
  return { ok: allProofsOk, proofs: proofResults };
}

// ======================================================================================================
// The verified policy core (docs/design/spec-verified-core.md): canon/2 documents, the field definitions
// of SPEC section 4.5, the checks of a policy in the core's order, the system boundary and the policy
// check. A port of prismpath/kernel/canon2.py and prismpath/kernel/field_definitions.py (and of the Rust
// twin prismpath-rs), held to the frozen vectors (conformance/canon2.json, field_definitions.json) and,
// by the differential harness (formal/diff/core_diff.py), to the Lean oracle. Everything is exact: decimal
// thresholds are read from their source text as a BigInt mantissa and a power of ten, never as a double.
// ======================================================================================================

// The registered causes (prismpath/kernel/causes.py, append only) the core's refusals carry.
const CORE_CAUSE_CODES = {
  "route:no-matching-edge": 32, "route:contract-violation": 37,
  "image:unknown-op": 74, "image:unknown-type": 75, "image:field-index-oob": 76,
  "policy:unreadable": 89, "policy:shape": 90, "policy:not-level-m": 91, "policy:definition": 92,
  "policy:engine-counter": 93, "policy:kind-mismatch": 94, "policy:rounding": 95, "policy:threshold": 96,
  "policy:none": 97, "policy:absence-untested": 98, "reading:unreadable": 99, "reading:not-object": 100,
  "policy:not-canonical": 101, "reading:not-canonical": 102,
};

/** The registered code of one of the core's causes, or null for any other name. */
export function coreCauseCode(cause) {
  return Object.prototype.hasOwnProperty.call(CORE_CAUSE_CODES, cause) ? CORE_CAUSE_CODES[cause] : null;
}

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

// ------------------------------------------------------------------------- definitions (section 2.5)
const FIELD_PREFIX = "field.";
const EXACT_INTEGER_LIMIT = 9007199254740991;
const MAX_SCALE = 1000000000;
const MAX_DECIMAL_DIGITS = 28;
const MAX_DECIMAL_EXPONENT = 30;
const ENGINE_COUNTERS = new Set(["visits", "error_count"]);
const DEFINITION_OPTIONS = {
  int: new Set(["min", "max", "absent"]),
  fixed: new Set(["scale", "rounding", "unit", "min", "max", "absent"]),
  bool: new Set(["absent"]),
  category: new Set(["absent"]),
};
// The atoms each rounding mode carries exactly (SPEC section 4.5, rule 4). "truthy" stands for a bare
// truthiness test and "in" for membership, which only exact carries.
const ROUNDING_OPERATORS = {
  floor: new Set([">=", "<"]),
  ceiling: new Set([">", "<="]),
  exact: new Set(["<", "<=", ">", ">=", "==", "!=", "in", "not in", "truthy"]),
};
const PY_SPLIT_RE = new RegExp(`${PY_WS}+`, "u");
const DECIMAL_TEXT_RE = /^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$/;

// Python's str.split() with no argument: the words between runs of Python whitespace.
function pySplit(text) {
  return text.split(PY_SPLIT_RE).filter((word) => word !== "");
}

// Code point order (Python's sorted over str); the UTF-16 order of a default sort differs past U+FFFF.
function codePointCompare(left, right) {
  const leftPoints = Array.from(left);
  const rightPoints = Array.from(right);
  const shared = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < shared; index++) {
    const difference = leftPoints[index].codePointAt(0) - rightPoints[index].codePointAt(0);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

class DefinitionRefusal extends Error {
  constructor(reason, message) {
    super(message);
    this.reason = reason;
  }
}

function integerOption(name, option, text) {
  if (!/^[+-]?[0-9]+$/.test(text)) throw new DefinitionRefusal("not-integer", `field ${JSON.stringify(name)}: ${option}=${JSON.stringify(text)} is not an integer`);
  return BigInt(text);
}

/** One `field.<name>` front matter value as a definition {name, kind, scale, rounding, unit, minimum, maximum,
 *  absentAllowed}, or a thrown DefinitionRefusal whose `reason` is the oracle's (spec section 2.5). */
function parseDefinitionReasoned(name, text) {
  const quoted = JSON.stringify(name);
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new DefinitionRefusal("name", `field ${quoted}: not a field name`);
  if (ENGINE_COUNTERS.has(name)) throw new DefinitionRefusal("engine-counter", `field ${quoted}: the engine supplies this counter, it is not defined`);
  const words = pySplit(text);
  if (words.length === 0) throw new DefinitionRefusal("empty", `field ${quoted}: the definition is empty`);
  const kind = words[0];
  if (!Object.prototype.hasOwnProperty.call(DEFINITION_OPTIONS, kind)) {
    throw new DefinitionRefusal("unknown-kind", `field ${quoted}: unknown kind ${JSON.stringify(kind)} (int, fixed, bool, category)`);
  }
  const options = new Map();
  for (const word of words.slice(1)) {
    const equals = word.indexOf("=");
    const option = equals < 0 ? word : word.slice(0, equals);
    const value = equals < 0 ? "" : word.slice(equals + 1);
    if (equals < 0 || value === "") throw new DefinitionRefusal("not-option", `field ${quoted}: ${JSON.stringify(word)} is not option=value`);
    if (!DEFINITION_OPTIONS[kind].has(option)) throw new DefinitionRefusal("option-not-taken", `field ${quoted}: a ${kind} field takes no ${JSON.stringify(option)} option`);
    if (options.has(option)) throw new DefinitionRefusal("option-repeated", `field ${quoted}: ${JSON.stringify(option)} is given twice`);
    options.set(option, value);
  }
  const absent = options.has("absent") ? options.get("absent") : "refused";
  if (absent !== "refused" && absent !== "allowed") throw new DefinitionRefusal("absent", `field ${quoted}: absent=${JSON.stringify(absent)} is neither refused nor allowed`);
  let scale = null;
  let rounding = null;
  let unit = null;
  if (kind === "fixed") {
    if (!options.has("scale") || !options.has("rounding")) throw new DefinitionRefusal("fixed-needs-scale-and-rounding", `field ${quoted}: a fixed field needs both scale and rounding`);
    const scaleValue = integerOption(name, "scale", options.get("scale"));
    if (scaleValue < 1n || scaleValue > BigInt(MAX_SCALE)) throw new DefinitionRefusal("scale", `field ${quoted}: scale=${scaleValue} is outside 1 to ${MAX_SCALE}`);
    scale = Number(scaleValue);
    rounding = options.get("rounding");
    if (!Object.prototype.hasOwnProperty.call(ROUNDING_OPERATORS, rounding)) throw new DefinitionRefusal("rounding", `field ${quoted}: rounding=${JSON.stringify(rounding)} is not floor, ceiling or exact`);
    unit = options.has("unit") ? options.get("unit") : null;
  }
  let minimum = BigInt(-EXACT_INTEGER_LIMIT);
  let maximum = BigInt(EXACT_INTEGER_LIMIT);
  if (options.has("min")) minimum = integerOption(name, "min", options.get("min"));
  if (options.has("max")) maximum = integerOption(name, "max", options.get("max"));
  if (!(BigInt(-EXACT_INTEGER_LIMIT) <= minimum && minimum <= maximum && maximum <= BigInt(EXACT_INTEGER_LIMIT))) {
    throw new DefinitionRefusal("range", `field ${quoted}: the range ${minimum} to ${maximum} is empty or wider than plus or minus 2^53 minus 1`);
  }
  return { name, kind, scale, rounding, unit, minimum: Number(minimum), maximum: Number(maximum), absentAllowed: absent === "allowed" };
}

/** The definition written one fixed way (the reference's canonical_text). */
export function definitionCanonicalText(definition) {
  const words = [definition.kind];
  if (definition.kind === "fixed") {
    words.push(`scale=${definition.scale}`, `rounding=${definition.rounding}`);
    if (definition.unit !== null) words.push(`unit=${definition.unit}`);
  }
  if (definition.kind === "int" || definition.kind === "fixed") words.push(`min=${definition.minimum}`, `max=${definition.maximum}`);
  words.push(definition.absentAllowed ? "absent=allowed" : "absent=refused");
  return words.join(" ");
}

/** One definition from its text, or a thrown Error naming the refusal (`reason` is the oracle's). */
export function parseDefinition(name, text) {
  return parseDefinitionReasoned(name, text);
}

// -------------------------------------------------------------------------------- exact decimals
/** The exact value of decimal text within the shared bounds as {mantissa: BigInt, exponent}, meaning
 *  mantissa * 10^exponent, or null when it is not such text (the reference's decimal_fraction). */
export function decimalValue(text) {
  if (!DECIMAL_TEXT_RE.test(text)) return null;
  const negative = text[0] === "-";
  const lower = text.toLowerCase().replace(/^[+-]/, "");
  const [mantissaText, exponentText] = lower.split("e");
  const dot = mantissaText.indexOf(".");
  const integerPart = dot < 0 ? mantissaText : mantissaText.slice(0, dot);
  const fractionPart = dot < 0 ? "" : mantissaText.slice(dot + 1);
  let exponent = 0;
  if (exponentText !== undefined) {
    const digits = exponentText.replace(/^[+-]/, "").replace(/^0+/, "");
    if (digits.length > 3) return null;
    exponent = digits === "" ? 0 : Number(digits);
    if (exponentText[0] === "-") exponent = -exponent;
    if (Math.abs(exponent) > MAX_DECIMAL_EXPONENT) return null;
  }
  const significant = (integerPart + fractionPart).replace(/^0+/, "");
  if (significant.length > MAX_DECIMAL_DIGITS) return null;
  const magnitude = significant === "" ? 0n : BigInt(significant);
  return { mantissa: negative ? -magnitude : magnitude, exponent: exponent - fractionPart.length };
}

// value * scale settled to an integer: [null, integer] or [refusal reason, null]. `how` is "floor",
// "ceiling" or the reason to refuse a value that is not a whole number of units.
function settleDecimal(value, scale, how) {
  const numerator = value.mantissa * BigInt(scale);
  if (value.exponent >= 0) return [null, numerator * 10n ** BigInt(value.exponent)];
  // past 60 digits the divisor exceeds every numerator the bounds allow (below 10^37)
  const divisor = -value.exponent > 60 ? null : 10n ** BigInt(-value.exponent);
  const quotient = divisor === null ? 0n : numerator / divisor;
  const remainder = divisor === null ? numerator : numerator % divisor;
  if (how === "floor") return [null, quotient - (remainder !== 0n && numerator < 0n ? 1n : 0n)];
  if (how === "ceiling") return [null, quotient + (remainder !== 0n && numerator > 0n ? 1n : 0n)];
  return remainder === 0n ? [null, quotient] : [how, null];
}

function inDefinitionRange(definition, canonical) {
  return canonical >= BigInt(definition.minimum) && canonical <= BigInt(definition.maximum);
}

// ------------------------------------------------------------------------------ shared conversion
/** The canonical value of a source value under its field's definition, as [refusal reason, value]: the
 *  reference's canonical_value for JSON values. A string on a numeric field is decimal text; a number is
 *  accepted only when integral, since the decimal a fractional double was printed from is lost. */
export function canonicalValue(definition, raw) {
  if (raw === null || raw === undefined) return definition.absentAllowed ? [null, null] : ["missing", null];
  if (definition.kind === "bool") return typeof raw === "boolean" ? [null, raw] : ["wrong_type", null];
  if (definition.kind === "category") return typeof raw === "string" ? [null, raw] : ["wrong_type", null];
  let exact;
  if (typeof raw === "boolean") return ["wrong_type", null];
  if (typeof raw === "number") {
    if (!Number.isFinite(raw)) return ["out_of_range", null];
    if (!Number.isInteger(raw)) return [definition.kind === "fixed" ? "binary_float" : "fractional", null];
    exact = { mantissa: BigInt(raw), exponent: 0 };
  } else if (typeof raw === "string") {
    exact = decimalValue(raw);
    if (exact === null) return ["unparseable_string", null];
  } else return ["wrong_type", null];
  let reason;
  let canonical;
  if (definition.kind === "fixed") {
    const how = definition.rounding === "floor" ? "floor" : definition.rounding === "ceiling" ? "ceiling" : "off_grid";
    [reason, canonical] = settleDecimal(exact, definition.scale, how);
  } else {
    [reason, canonical] = settleDecimal(exact, 1, "fractional");
  }
  if (reason !== null) return [reason, null];
  if (!inDefinitionRange(definition, canonical)) return ["out_of_range", null];
  return [null, Number(canonical)];
}

/** [refusal reason, value] for a value that should already be canonical (the reference's accept_canonical).
 *  It converts nothing: a string that spells a number is the wrong type. A missing key or null is the absent
 *  value, accepted only when the definition allows absence. */
export function acceptCanonical(definition, value) {
  if (value === null || value === undefined) return definition.absentAllowed ? [null, null] : ["missing", null];
  if (definition.kind === "bool") return typeof value === "boolean" ? [null, value] : ["wrong_type", null];
  if (definition.kind === "category") return typeof value === "string" ? [null, value] : ["wrong_type", null];
  if (typeof value !== "number") return ["wrong_type", null];
  if (!Number.isFinite(value)) return ["out_of_range", null];
  if (!Number.isInteger(value)) return ["fractional", null];
  if (value < definition.minimum || value > definition.maximum) return ["out_of_range", null];
  return [null, value];
}

// --------------------------------------------------------- the two checks of a reading (section 6.1)
function firstRefused(definitions, names, reading) {
  for (const name of names) {
    const own = Object.prototype.hasOwnProperty.call(reading, name) ? reading[name] : null;
    const [reason] = acceptCanonical(definitions[name], own);
    if (reason !== null) return [name, reason];
  }
  return null;
}

/** The defined fields the flow's deterministic conditions read, in code point order. */
export function routedFields(graph) {
  return [...(graph.routed || [])];
}

/** The first defined field, in code point order, whose value the reading does not hold canonically, as
 *  [field, reason]; null when every defined field is canonical. The core's runtime boundary: the system's
 *  contract, every field the policy defines whether or not a rule reads it. */
export function systemBoundary(graph, reading) {
  const definitions = graph.fields || {};
  return firstRefused(definitions, Object.keys(definitions).sort(codePointCompare), reading);
}

/** The first ROUTED field, in code point order, whose value the reading does not hold canonically, as
 *  [field, reason]; null when every field a rule reads is canonical. The check of a policy's soundness. */
export function policyCheck(graph, reading) {
  return firstRefused(graph.fields || {}, routedFields(graph), reading);
}

// -------------------------------------------------------------------- the surface the core decodes
// The predicate language with exact literal text, a sign written on a number (also outside parentheses, as
// Python's syntax tree holds `-(5)`), and a grouping parenthesis transparent. It follows tokenize()'s
// tokens, rule for rule the grammar of parseOr, so it reads exactly what evaluation reads, but keeps what
// evaluation discards: a number's source text and span.
class SurfaceFail extends Error {}

function surfaceFail() {
  throw new SurfaceFail("not in the predicate language");
}

class SurfaceParser {
  constructor(expr, toks) {
    this.expr = expr;
    this.toks = toks;
    this.pos = 0;
    this.brackets = 0;
  }
  peekOp(op) {
    const tok = this.toks[this.pos];
    return tok !== undefined && tok.t === "op" && tok.v === op;
  }
  peekName(name) {
    const tok = this.toks[this.pos];
    return tok !== undefined && tok.t === "name" && tok.v === name;
  }
  expect(op) {
    if (!this.peekOp(op)) surfaceFail();
    this.pos++;
  }
  joined(keyword, kind, next) {
    const values = [next.call(this)];
    while (this.peekName(keyword)) {
      this.pos++;
      values.push(next.call(this));
    }
    return values.length === 1 ? values[0] : { k: kind, vals: values };
  }
  orExpr() { return this.joined("or", "or", this.andExpr); }
  andExpr() { return this.joined("and", "and", this.notExpr); }
  notExpr() {
    if (this.peekName("not")) {
      this.pos++;
      return { k: "not", v: this.notExpr() };
    }
    return this.compare();
  }
  compareOp() {
    const tok = this.toks[this.pos];
    if (tok === undefined) return null;
    if (tok.t === "op" && ["==", "!=", "<", "<=", ">", ">="].includes(tok.v)) { this.pos++; return tok.v; }
    if (tok.t === "name" && tok.v === "in") { this.pos++; return "in"; }
    if (tok.t === "name" && tok.v === "not") {
      this.pos++;
      if (!this.peekName("in")) surfaceFail();
      this.pos++;
      return "not in";
    }
    return null;
  }
  compare() {
    const operands = [this.operand()];
    const ops = [];
    for (let op = this.compareOp(); op !== null; op = this.compareOp()) {
      ops.push(op);
      operands.push(this.operand());
    }
    return ops.length === 0 ? operands[0] : { k: "cmp", operands, ops };
  }
  open() {
    // Python's tokenizer refuses more than 200 open brackets
    if (this.brackets >= 200) surfaceFail();
    this.brackets++;
  }
  number(index, negative, start, end, separated) {
    const tok = this.toks[index];
    const text = this.expr.slice(tok.s, tok.e).replace(/_/g, "");
    return { k: "num", text, float: tok.float, negative, radix: /^0[xob]/i.test(text), start, end, separated };
  }
  sequence(close) {
    const elements = [];
    if (this.toks[this.pos] !== undefined && !this.peekOp(close)) {
      elements.push(this.orExpr());
      while (this.peekOp(",")) {
        this.pos++;
        if (this.peekOp(close)) break;
        elements.push(this.orExpr());
      }
    }
    this.expect(close);
    return elements;
  }
  operand() {
    const tok = this.toks[this.pos];
    if (tok === undefined) surfaceFail();
    this.pos++;
    if (tok.t === "op" && (tok.v === "-" || tok.v === "+")) {
      const negative = tok.v === "-";
      const next = this.toks[this.pos];
      if (next !== undefined && next.t === "num") {
        this.pos++;
        return this.number(this.pos - 1, negative, tok.s, next.e, false);
      }
      // `-(5)`: one number in parentheses, a signed literal in Python's syntax tree
      const inner = this.toks[this.pos + 1];
      const close = this.toks[this.pos + 2];
      if (this.peekOp("(") && inner !== undefined && inner.t === "num" && close !== undefined && close.t === "op" && close.v === ")") {
        this.pos += 3;
        return this.number(this.pos - 2, negative, tok.s, close.e, true);
      }
      surfaceFail();
    }
    if (tok.t === "num") return this.number(this.pos - 1, false, tok.s, tok.e, false);
    if (tok.t === "str") return { k: "str", v: tok.v };
    if (tok.t === "ellipsis") return { k: "ellipsis" };
    if (tok.t === "name") {
      if (tok.v === "True") return { k: "bool", v: true };
      if (tok.v === "False") return { k: "bool", v: false };
      if (tok.v === "None") return { k: "null" };
      if (tok.v === "and" || tok.v === "or" || tok.v === "not" || tok.v === "in" || PY_KEYWORDS.has(tok.v)) surfaceFail();
      return { k: "name", v: tok.v };
    }
    if (tok.t === "op" && tok.v === "[") {
      this.open();
      const elements = this.sequence("]");
      this.brackets--;
      return { k: "list", elts: elements };
    }
    if (tok.t === "op" && tok.v === "(") {
      if (this.peekOp(")")) { this.pos++; return { k: "list", elts: [] }; }
      this.open();
      const first = this.orExpr();
      if (this.peekOp(",")) {
        const elements = [first];
        while (this.peekOp(",")) {
          this.pos++;
          if (this.peekOp(")")) break;
          elements.push(this.orExpr());
        }
        this.expect(")");
        this.brackets--;
        return { k: "list", elts: elements };
      }
      this.expect(")");
      this.brackets--;
      return first;
    }
    return surfaceFail();
  }
}

// The surface tree of an expression, or null when it is not in the predicate language. A top level tuple,
// `x, y`, is no condition of the predicate language, but the lowering of an error edge still walks one.
function parseSurface(expr, allowTuple = false) {
  let toks;
  try {
    toks = tokenize(expr);
  } catch (err) {
    if (err instanceof PredicateError) return null;
    throw err;
  }
  const parser = new SurfaceParser(expr, toks);
  try {
    let tree = parser.orExpr();
    if (allowTuple && parser.peekOp(",")) {
      const elements = [tree];
      while (parser.peekOp(",")) {
        parser.pos++;
        if (parser.toks[parser.pos] === undefined) break;
        elements.push(parser.orExpr());
      }
      tree = { k: "and", vals: elements };
    }
    return parser.pos === toks.length ? tree : null;
  } catch (err) {
    if (err instanceof SurfaceFail) return null;
    throw err;
  }
}

// `a < b < c` -> `a < b and b < c`, recursively: the one desugaring (the reference's _desugar_chains).
function desugarSurface(node) {
  switch (node.k) {
    case "and": case "or": return { k: node.k, vals: node.vals.map(desugarSurface) };
    case "not": return { k: "not", v: desugarSurface(node.v) };
    case "cmp":
      if (node.ops.length > 1) {
        return { k: "and", vals: node.ops.map((op, index) => ({ k: "cmp", operands: [node.operands[index], node.operands[index + 1]], ops: [op] })) };
      }
      return node;
    default: return node;
  }
}

// ------------------------------------------------------------------ decoding to the core's syntax
// One way a flow breaks its field definitions: a message and the registered refusal it is, with `field`
// and `reason` where the refusal names them.
function problem(cause, text, field = null, reason = null) {
  return { cause, field, reason, text };
}

class Refused extends Error {
  constructor(found) {
    super(found.text);
    this.problem = found;
  }
}

function outsideLevelM(where, cond, cause, reason) {
  return new Refused(problem(cause, `${where}: ${JSON.stringify(cond)} is outside Level M (${reason}), and a flow that defines its fields routes only on Level M conditions`, null, reason));
}

const FLIP_OPERATOR = { "<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!=" };
const ORDERING_OPERATORS = new Set(["<", "<=", ">", ">="]);

// A constant of the core (spec section 2.3): {t: "int", v: BigInt}, {t: "dec", text, exact}, {t: "bool", v},
// {t: "str", v} or {t: "none"}; or the decoding refusal (Lean decodeConst).
function decodeConst(node, where, cond) {
  switch (node.k) {
    case "num": {
      if (!node.float) {
        const magnitude = BigInt(node.text);
        return { t: "int", v: node.negative ? -magnitude : magnitude };
      }
      const exact = decimalValue(node.text);
      if (exact === null) {
        throw new Refused(problem("policy:threshold", `${where}: ${JSON.stringify(cond)}: the literal ${JSON.stringify(node.text)} has more digits than an exact threshold carries`, null, "digits"));
      }
      return { t: "dec", text: node.negative ? `-${node.text}` : node.text, exact: node.negative ? { mantissa: -exact.mantissa, exponent: exact.exponent } : exact };
    }
    case "str": return { t: "str", v: node.v };
    case "bool": return { t: "bool", v: node.v };
    case "null": return { t: "none" };
    case "name": throw outsideLevelM(where, cond, "image:unknown-type", "field-vs-field");
    case "list": throw outsideLevelM(where, cond, "image:unknown-type", "nested-container");
    default: throw outsideLevelM(where, cond, "image:unknown-type", "constant");
  }
}

// A desugared condition as the core's abstract syntax (spec section 2.2), or the first decoding refusal met
// depth first and left to right (Lean decodeCond).
function decodeSurface(node, where, cond) {
  switch (node.k) {
    case "and": return { t: "and", cs: node.vals.map((value) => decodeSurface(value, where, cond)) };
    case "or": return { t: "or", cs: node.vals.map((value) => decodeSurface(value, where, cond)) };
    case "not": return { t: "not", c: decodeSurface(node.v, where, cond) };
    case "name": return { t: "truthy", f: node.v };
    case "cmp": {
      if (node.ops.length !== 1) throw outsideLevelM(where, cond, "policy:not-level-m", "disallowed-or-unparseable");
      const [left, right] = node.operands;
      const op = node.ops[0];
      if (op === "in" || op === "not in") {
        if (left.k !== "name") throw outsideLevelM(where, cond, "policy:not-level-m", "name");
        if (right.k !== "list") throw outsideLevelM(where, cond, "image:unknown-op", "membership-not-in-a-list");
        return { t: "mem", f: left.v, neg: op === "not in", ks: right.elts.map((element) => decodeConst(element, where, cond)) };
      }
      let field;
      let constantNode;
      let oriented = op;
      if (left.k === "name") { field = left.v; constantNode = right; }
      else if (right.k === "name") { field = right.v; constantNode = left; oriented = FLIP_OPERATOR[op]; }
      else throw outsideLevelM(where, cond, "policy:not-level-m", "name");
      const constant = decodeConst(constantNode, where, cond);
      if (ORDERING_OPERATORS.has(oriented) && constant.t === "str") throw outsideLevelM(where, cond, "image:unknown-op", "string-ordering");
      return { t: "cmp", f: field, op: oriented, k: constant };
    }
    case "bool": case "null": case "num": case "str": case "ellipsis":
      throw outsideLevelM(where, cond, "policy:not-level-m", "name");
    default: throw outsideLevelM(where, cond, "policy:not-level-m", "disallowed-or-unparseable");
  }
}

// The core's depth of a decoded condition (spec section 2.4, Lean Cond.depth).
function coreDepth(cond) {
  switch (cond.t) {
    case "always": case "never": return 0;
    case "truthy": return 1;
    case "cmp": case "mem": return 2;
    case "not": return 1 + coreDepth(cond.c);
    default: return 1 + Math.max(0, ...cond.cs.map(coreDepth));
  }
}

// One deterministic condition in the core's abstract syntax, or the problem that refuses it at decoding
// (phase 1 of spec section 4), as the reference's decode_condition.
function decodeCondition(cond, where) {
  const expr = exprOf(cond);
  const lower = expr.toLowerCase();
  if (ALWAYS.has(lower)) return { t: "always" };
  if (NEVER.has(lower)) return { t: "never" };
  const tree = parseSurface(expr);
  if (tree === null) {
    return problem("policy:not-level-m", `${where}: ${JSON.stringify(cond)} does not parse in the predicate language, and a flow that defines its fields routes only on Level M conditions`, null, "disallowed-or-unparseable");
  }
  let decoded;
  try {
    decoded = decodeSurface(desugarSurface(tree), where, cond);
  } catch (err) {
    if (err instanceof Refused) return err.problem;
    throw err;
  }
  // SPEC section 4.1, by the core's measure (spec section 2.4)
  if (coreDepth(decoded) > MAX_DEPTH) {
    return problem("policy:not-level-m", `${where}: ${JSON.stringify(cond)} is nested too deeply (> ${MAX_DEPTH})`, null, "depth");
  }
  return decoded;
}

// ------------------------------------------------------------------ the checks of one atom (rules 2-5)
// Whether a rounding mode carries an operator (rule 4); null stands for truthiness and membership.
function roundingCarries(rounding, op) {
  return op === null ? rounding === "exact" : ROUNDING_OPERATORS[rounding].has(op);
}

function roundingProblem(definition, op) {
  const allowed = [...ROUNDING_OPERATORS[definition.rounding]].sort().join(" and ");
  const written = op === null ? "a bare truthiness test or a membership" : JSON.stringify(op);
  return problem("policy:rounding", `field ${JSON.stringify(definition.name)}: rounding=${definition.rounding} carries only ${allowed}, so ${written} would not decide on the canonical value as it does on the source value`, definition.name);
}

function thresholdProblem(definition, text, reason) {
  return problem("policy:threshold", `field ${JSON.stringify(definition.name)}: the threshold ${text} is ${reason.replace(/-/g, " ")} for ${JSON.stringify(definitionCanonicalText(definition))}`, definition.name, reason);
}

// A numeric constant of an int or fixed field against the field (Lean lowerNum).
function lowerNumber(definition, constant) {
  const fixed = definition.kind === "fixed";
  if (constant.t === "int") {
    const value = fixed ? constant.v * BigInt(definition.scale) : constant.v;
    return inDefinitionRange(definition, value) ? null : thresholdProblem(definition, constant.v.toString(), fixed ? "out-of-range" : "constant-range");
  }
  if (constant.t === "dec") {
    if (!fixed) {
      return problem("image:unknown-type", `field ${JSON.stringify(definition.name)}: the decimal ${constant.text} is a float, and a ${definition.kind} field compares integers`, null, "float");
    }
    const [reason, scaled] = settleDecimal(constant.exact, definition.scale, "off-grid");
    if (reason !== null) return thresholdProblem(definition, constant.text, "off-grid");
    return inDefinitionRange(definition, scaled) ? null : thresholdProblem(definition, constant.text, "out-of-range");
  }
  return problem("policy:kind-mismatch", `field ${JSON.stringify(definition.name)}: a ${definition.kind} field is compared only with numbers`, definition.name);
}

function floatProblem(definition, kind, text) {
  return problem("image:unknown-type", `field ${JSON.stringify(definition.name)}: the decimal ${text} is a float, and a ${kind} field takes none`, null, "float");
}

// Why one decoded atom breaks its field's definition, or null (Lean checkTruthy, checkCmp, checkMem, in
// their order; the reference's _atom_problem).
function atomProblem(definition, atom) {
  const name = definition.name;
  const quoted = JSON.stringify(name);
  const kind = definition.kind;
  const fixed = kind === "fixed";
  if (atom.t === "truthy") return fixed && !roundingCarries(definition.rounding, null) ? roundingProblem(definition, null) : null;
  if (atom.t === "cmp") {
    const { op, k: constant } = atom;
    if (constant.t === "none") {
      if (op !== "==" && op !== "!=") return problem("policy:none", `field ${quoted}: None is compared only by == or !=`, name, "ordered");
      if (!definition.absentAllowed) return problem("policy:none", `field ${quoted}: compared with None, but its definition refuses absence`, name, "absence-refused");
      return null;
    }
    if (kind === "bool" || kind === "category") {
      const own = kind === "bool" ? "bool" : "str";
      if (constant.t === own && (op === "==" || op === "!=")) return null;
      if (constant.t === "dec") return floatProblem(definition, kind, constant.text);
      return problem("policy:kind-mismatch", kind === "bool"
        ? `field ${quoted}: a bool field is tested by truthiness or == and != with True or False`
        : `field ${quoted}: a category field is compared with strings by ==, !=, in and not in`, name);
    }
    const isNumber = constant.t === "int" || constant.t === "dec";
    if (fixed && !roundingCarries(definition.rounding, op) && isNumber) return roundingProblem(definition, op);
    const found = lowerNumber(definition, constant);
    if (found !== null) return found;
    return fixed && !roundingCarries(definition.rounding, op) ? roundingProblem(definition, op) : null;
  }
  // membership
  if (atom.ks.some((member) => member.t === "none")) return problem("policy:none", `field ${quoted}: None may not appear in a list`, name, "in-list");
  for (const member of atom.ks) {
    if (kind === "category" && member.t === "str") continue;
    if (kind === "int" || kind === "fixed") {
      const found = lowerNumber(definition, member);
      if (found !== null) return found;
      continue;
    }
    if (member.t === "dec") return floatProblem(definition, kind, member.text);
    return problem("policy:kind-mismatch", `field ${quoted}: a ${kind} field is compared with ${kind === "category" ? "strings" : "True or False"} only`, name);
  }
  return fixed && !roundingCarries(definition.rounding, null) ? roundingProblem(definition, null) : null;
}

// The atoms of a decoded condition, depth first and left to right.
function coreAtoms(cond, out = []) {
  switch (cond.t) {
    case "always": case "never": break;
    case "not": coreAtoms(cond.c, out); break;
    case "and": case "or": cond.cs.forEach((operand) => coreAtoms(operand, out)); break;
    default: out.push(cond);
  }
  return out;
}

// The deterministic edges of the flow, in node order and edge order: the rules of the core.
function coreRules(graph) {
  const rules = [];
  const names = graph.order.filter((name) => Object.prototype.hasOwnProperty.call(graph.nodes, name));
  for (const name of names) {
    for (const [, cond] of graph.nodes[name].edges) {
      if (isDeterministic(cond) && !isSemantic(cond)) rules.push([name, cond]);
    }
  }
  return rules;
}

// Every problem of a flow that defines its fields, in the order of spec section 4, with the decoded rules:
// the first problem is the one the core refuses the policy for, the rest are diagnostics. The twin of the
// reference's core_problems. Phase 1 decodes rule by rule, phase 2 parses the definitions in code point
// order, phase 3 checks every atom against its definition, phase 4 is rule 6.
function coreAnalysis(graph, meta) {
  const texts = new Map();
  for (const key of Object.keys(meta)) {
    if (key.startsWith(FIELD_PREFIX)) texts.set(key.slice(FIELD_PREFIX.length), meta[key]);
  }
  const names = [...texts.keys()].sort(codePointCompare);
  const problems = [];
  const decoded = [];
  for (const [where, cond] of coreRules(graph)) {
    const tree = decodeCondition(cond, where);
    if (tree.cause !== undefined) problems.push(tree);
    else decoded.push([where, cond, tree]);
  }
  const definitions = {};
  for (const name of names) {
    try {
      definitions[name] = parseDefinitionReasoned(name, texts.get(name));
    } catch (err) {
      if (!(err instanceof DefinitionRefusal)) throw err;
      problems.push(problem("policy:definition", err.message, name, err.reason));
    }
  }
  const testedForAbsence = new Set();
  for (const [where, cond, tree] of decoded) {
    for (const atom of coreAtoms(tree)) {
      const field = atom.f;
      // the engine's registers are outside the core (spec section 1), routed by the flow engine
      if (ENGINE_COUNTERS.has(field)) continue;
      const definition = Object.prototype.hasOwnProperty.call(definitions, field) ? definitions[field] : undefined;
      if (definition === undefined) {
        if (!texts.has(field)) problems.push(problem("image:field-index-oob", `${where}: ${JSON.stringify(cond)} reads ${JSON.stringify(field)}, which the flow does not define`, field));
        continue;
      }
      const found = atomProblem(definition, atom);
      if (found !== null) problems.push({ ...found, text: `${where}: ${JSON.stringify(cond)}: ${found.text}` });
      else if (atom.t === "cmp" && atom.k.t === "none") testedForAbsence.add(field);
    }
  }
  for (const name of names) {
    const definition = Object.prototype.hasOwnProperty.call(definitions, name) ? definitions[name] : undefined;
    if (definition !== undefined && definition.absentAllowed && !testedForAbsence.has(name)) {
      problems.push(problem("policy:absence-untested", `field ${JSON.stringify(name)} allows absence but no edge tests it with == None or != None, so absence would only ever be observed by accident`, name));
    }
  }
  return { problems, decoded, definitions, texts };
}

// ------------------------------------------------------------------------------------- lowering
// Every numeric literal compared with a fixed field replaced by its canonical integer, rewritten in place by
// the literal's span in the source. Returns the expression, or throws Refused for a literal outside the
// core's syntax: a sign written outside parentheses, or a literal between two fixed fields of different scales.
function lowerExpression(expr, definitions) {
  const fixed = new Set(Object.keys(definitions).filter((name) => definitions[name].kind === "fixed"));
  if (fixed.size === 0) return expr;
  const tree = parseSurface(expr, true);
  if (tree === null) return expr;           // not a valid predicate: the policy rules report it
  const replacements = new Map();
  const lowerOne = (field, node) => {
    if (node.k !== "num") return;
    const source = expr.slice(node.start, node.end);
    if (node.separated) {
      throw new Refused(problem("policy:threshold", `the threshold ${source} puts its sign outside parentheses; write the sign on the number`, null, "sign"));
    }
    const definition = definitions[field];
    let exact;
    if (node.radix || !node.float) {
      const magnitude = BigInt(node.text);
      exact = { mantissa: node.negative ? -magnitude : magnitude, exponent: 0 };
    } else {
      exact = decimalValue(node.text);
      if (exact === null) throw new Refused(problem("policy:threshold", `the literal ${JSON.stringify(node.text)} has more digits than an exact threshold carries`, null, "digits"));
      if (node.negative) exact = { mantissa: -exact.mantissa, exponent: exact.exponent };
    }
    const [reason, canonical] = settleDecimal(exact, definition.scale, "off-grid");
    if (reason !== null) throw new Refused(problem("policy:threshold", `field ${JSON.stringify(field)}: the threshold ${source} is not a multiple of 1/${definition.scale}`, field, "off-grid"));
    if (!inDefinitionRange(definition, canonical)) {
      throw new Refused(problem("policy:threshold", `field ${JSON.stringify(field)}: the threshold ${source} is ${canonical} canonically, outside ${definition.minimum} to ${definition.maximum}`, field, "out-of-range"));
    }
    const span = `${node.start},${node.end}`;
    const previous = replacements.get(span);
    if (previous !== undefined && previous.field !== field && definitions[previous.field].scale !== definition.scale) {
      throw new Refused(problem("policy:threshold", `the literal ${source} sits between two fixed fields of different scales`, null, "two-scales"));
    }
    replacements.set(span, { field, canonical, start: node.start, end: node.end });
  };
  const fixedName = (node) => (node.k === "name" && fixed.has(node.v) ? node.v : null);
  const walk = (node) => {
    switch (node.k) {
      case "cmp":
        node.ops.forEach((op, index) => {
          const left = node.operands[index];
          const right = node.operands[index + 1];
          if (op === "in" || op === "not in") {
            const field = fixedName(left);
            if (field !== null && right.k === "list") right.elts.forEach((element) => lowerOne(field, element));
            return;
          }
          const leftField = fixedName(left);
          if (leftField !== null) lowerOne(leftField, right);
          const rightField = fixedName(right);
          if (rightField !== null) lowerOne(rightField, left);
        });
        node.operands.forEach(walk);
        break;
      case "and": case "or": node.vals.forEach(walk); break;
      case "not": walk(node.v); break;
      case "list": node.elts.forEach(walk); break;
      default: break;
    }
  };
  walk(tree);
  let lowered = expr;
  for (const { start, end, canonical } of [...replacements.values()].sort((a, b) => b.start - a.start)) {
    lowered = lowered.slice(0, start) + canonical.toString() + lowered.slice(end);
  }
  return lowered;
}

// A `when` or `on error when` condition with its expression lowered; any other condition as is.
function lowerCondition(cond, definitions) {
  let expr;
  if (isDeterministic(cond)) expr = exprOf(cond);
  else if (isError(cond) && errorExpr(cond).toLowerCase().startsWith("when ")) expr = exprOf(errorExpr(cond));
  else return cond;
  const lower = expr.toLowerCase();
  if (ALWAYS.has(lower) || NEVER.has(lower)) return cond;
  const stripped = pyTrimEnd(cond);
  if (!stripped.endsWith(expr)) return cond;
  return stripped.slice(0, stripped.length - expr.length) + lowerExpression(expr, definitions);
}

/** A flow whose field definitions are malformed or whose conditions break a definition's rules. `cause` is
 *  the registered refusal (prismpath/kernel/causes.py) of the FIRST problem in the core's order, with
 *  `field` and `reason` where the refusal has them, `code` its registered code, and `problems` every
 *  problem found, each {cause, field, reason, text} (spec section 4). */
export class FieldDefinitionError extends Error {
  constructor(message, problems) {
    super(message);
    this.name = "FieldDefinitionError";
    const [first] = problems;
    this.cause = first.cause;
    this.field = first.field;
    this.reason = first.reason;
    this.code = coreCauseCode(first.cause);
    this.problems = problems;
  }
}

// Check the flow's definitions and rules in the core's order, lower its conditions in place, and refuse a
// flow that breaks a rule. A flow with no definitions is left exactly as it was.
function applyDefinitions(graph, meta) {
  if (!Object.keys(meta).some((key) => key.startsWith(FIELD_PREFIX))) return;
  const { problems, decoded, definitions } = coreAnalysis(graph, meta);
  if (problems.length === 0) {
    graph.fields = definitions;
    const routed = new Set();
    for (const [, , tree] of decoded) {
      for (const atom of coreAtoms(tree)) {
        if (Object.prototype.hasOwnProperty.call(definitions, atom.f)) routed.add(atom.f);
      }
    }
    graph.routed = [...routed].sort(codePointCompare);
    for (const [name, node] of Object.entries(graph.nodes)) {
      node.edges = node.edges.map(([target, cond]) => {
        try {
          return [target, lowerCondition(cond, definitions)];
        } catch (err) {
          if (!(err instanceof Refused)) throw err;
          // outside the core's syntax: a sign outside parentheses, a literal between two scales
          problems.push({ ...err.problem, text: `${name}: ${JSON.stringify(cond)}: ${err.problem.text}` });
          return [target, cond];
        }
      });
    }
  }
  if (problems.length > 0) {
    const [first] = problems;
    const message = first.cause === "policy:definition" ? first.text : `the flow breaks its field definitions: ${problems.map((found) => found.text).join("; ")}`;
    throw new FieldDefinitionError(message, problems);
  }
}

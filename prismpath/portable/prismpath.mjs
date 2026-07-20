/**
 * prismpath.mjs — the PORTABLE prismpath kernel (roadmap item #5): parser + safe predicate
 * evaluator + engine loop for the ML-FREE subset, in one dependency-free ES module.
 *
 * A flow is PORTABLE iff every reachable edge is decidable — a `when` predicate, an error
 * edge, or an event edge (check with `prismpath portable <flow>` on the Python side, or
 * portabilityViolations() here). Such a flow needs no embedder and no LLM tier for ROUTING
 * (workers are supplied by the host and can be anything), so it runs wherever JavaScript
 * runs: Node, a browser, an edge function, a network appliance. `run()` REFUSES a
 * non-portable flow up front rather than guessing at a semantic edge.
 *
 * Semantics are a faithful port of parser.py / predicates.py / engine.py — verified by the
 * cross-language conformance suite (portable/run_conformance.mjs), which replays the same
 * flows + scripted outcomes through both engines and requires identical paths. The subtle
 * Python behaviors are preserved deliberately:
 *   - `True`/`False`/`None` are constants; lowercase `true`/`false` are FIELD NAMES
 *     (Python ast parses them as Names) — so `when x == true` reads ctx["true"].
 *   - booleans compare numerically: `flag == 1` is true for flag=true (Python True == 1).
 *   - a comparison against a missing field or a type-mismatched pair is UNSATISFIED, never
 *     a crash — except `not in`, whose failure is SATISFIED ("unknown -> falsy").
 *   - chained comparisons (`1 < x < 5`), substring `in` on strings, membership on lists
 *     (loose ==) and objects (key test), Python truthiness ([] and {} are falsy).
 *   - disallowed syntax (calls, attributes, subscripts, arithmetic, unary minus) is a
 *     PredicateError — statically via checkPredicate, and a non-match at run time.
 *
 * No eval()/Function() anywhere: predicates go through a hand-rolled tokenizer +
 * recursive-descent parser onto a tiny AST, exactly mirroring the Python sandbox.
 */

const ALWAYS = new Set(["always", "true", "else", "otherwise", "default", "_"]);
const NEVER = new Set(["false", "never"]);
const MAX_DEPTH = 50;

// Python HARD keywords (minus True/False/None, which are constants, and and/or/not/in, which are
// operators here). Python's ast.parse REJECTS these as names — `when class == "phish"` is a
// PredicateError there, so it must be one here too, or the edge routes differently across engines
// (found by differential fuzzing). Soft keywords (match/case/type) are ordinary Names in both.
const PY_KEYWORDS = new Set([
  "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else",
  "except", "finally", "for", "from", "global", "if", "import", "is", "lambda", "nonlocal",
  "pass", "raise", "return", "try", "while", "with", "yield",
]);

// Python str.strip() whitespace, which is WIDER than JS String.trim() (e.g. U+0085 NEL is
// whitespace to Python but not to trim()) — condition classification must agree on both sides.
const PY_WS = "[\\s\\x85\\x1c\\x1d\\x1e\\x1f]";
const PY_TRIM_RE = new RegExp(`^${PY_WS}+|${PY_WS}+$`, "gu");
function pyTrim(s) { return s.replace(PY_TRIM_RE, ""); }

// Ellipsis (`...`) is a truthy Constant in Python; represent it as a sentinel that is truthy and
// equal to nothing JSON can contain (mirroring Python, where `x == ...` is False for JSON values).
const ELLIPSIS = Symbol("Ellipsis");

export class PredicateError extends Error {}

// ---------------------------------------------------------------------------- conditions
// NB: pyTrim (not String.trim) throughout — Python's strip() removes e.g. U+0085, and the tier a
// condition lands in must be identical across engines.
export function isDeterministic(condition) {
  const c = pyTrim(condition).toLowerCase();
  return c.startsWith("when ") || ALWAYS.has(c) || NEVER.has(c);
}

export function isError(condition) {
  return pyTrim(condition).toLowerCase().startsWith("on error");
}

export function isEvent(condition) {
  const c = pyTrim(condition).toLowerCase();
  return c.startsWith("on event") || c.startsWith("on timeout");
}

export function eventName(condition) {
  const c = pyTrim(condition);
  if (c.toLowerCase().startsWith("on timeout")) return "__timeout__";
  return pyTrim(c.slice("on event".length));
}

export function isSemantic(condition) {
  return !isDeterministic(condition) && !isError(condition) && !isEvent(condition);
}

export function errorExpr(condition) {
  return pyTrim(pyTrim(condition).slice("on error".length));
}

function exprOf(condition) {
  const c = pyTrim(condition);
  return c.toLowerCase().startsWith("when ") ? pyTrim(c.slice(5)) : c;
}

// ------------------------------------------------------------------- expression parsing
// Grammar (== the Python ast subset the sandbox allows):
//   expr    := or ;  or := and ("or" and)* ;  and := not ("and" not)*
//   not     := "not" not | cmp
//   cmp     := operand ((==|!=|<|<=|>|>=|in|not in) operand)*
//   operand := number | string | True | False | None | name | "[" args "]" | "(" tuple-or-group ")"
// No calls, attributes, subscripts, arithmetic, or unary minus — anything else throws.

function tokenize(src) {
  const toks = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const ch = src[i];
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") { i++; continue; }
    if (/[A-Za-z_]/.test(ch)) {
      // raw-string prefix: r'…' / R"…" is a plain Constant in Python (no escape processing)
      if ((ch === "r" || ch === "R") && (src[i + 1] === "'" || src[i + 1] === '"')) {
        const q = src[i + 1];
        let j = i + 2, out = "";
        while (j < n && src[j] !== q) { out += src[j]; j++; }
        if (j >= n) throw new PredicateError(`unterminated string in predicate`);
        toks.push({ t: "str", v: out });
        i = j + 1;
        continue;
      }
      if ((ch === "b" || ch === "B") && (src[i + 1] === "'" || src[i + 1] === '"'))
        throw new PredicateError(`bytes literals are not supported in predicates`);
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_]/.test(src[j])) j++;
      toks.push({ t: "name", v: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[0-9]/.test(ch) || (ch === "." && /[0-9]/.test(src[i + 1] || ""))) {
      // Python numeric literal spellings: 0x/0o/0b radixes and _ separators are legal; a trailing
      // j (complex) is a hard reject on both sides for parity's sake (Python would accept it as a
      // truthy Constant, but complex has no JSON/JS analogue — better an agreed error).
      let j = i;
      const radix = src.slice(i, i + 2).toLowerCase();
      if (ch === "0" && (radix === "0x" || radix === "0o" || radix === "0b")) {
        j = i + 2;
        const digits = radix === "0x" ? /[0-9a-fA-F_]/ : radix === "0o" ? /[0-7_]/ : /[01_]/;
        while (j < n && digits.test(src[j])) j++;
        const body = src.slice(i + 2, j).replace(/_/g, "");
        if (!body) throw new PredicateError(`malformed numeric literal in predicate`);
        toks.push({ t: "num", v: parseInt(body, radix === "0x" ? 16 : radix === "0o" ? 8 : 2) });
        i = j;
        continue;
      }
      while (j < n && /[0-9_]/.test(src[j])) j++;
      if (src[j] === ".") { j++; while (j < n && /[0-9_]/.test(src[j])) j++; }
      if (src[j] === "e" || src[j] === "E") {
        let k = j + 1;
        if (src[k] === "+" || src[k] === "-") k++;
        if (/[0-9]/.test(src[k] || "")) { k++; while (k < n && /[0-9_]/.test(src[k])) k++; j = k; }
      }
      if (src[j] === "j" || src[j] === "J")
        throw new PredicateError(`complex literals are not supported in predicates`);
      toks.push({ t: "num", v: Number(src.slice(i, j).replace(/_/g, "")) });
      i = j;
      continue;
    }
    if (ch === '"' || ch === "'") {
      let j = i + 1, out = "";
      while (j < n && src[j] !== ch) {
        if (src[j] === "\\" && j + 1 < n) {
          const e = src[j + 1];
          // Python's escape table; an UNKNOWN escape keeps the backslash (Python semantics),
          // it is not silently dropped.
          if (e === "n") out += "\n";
          else if (e === "t") out += "\t";
          else if (e === "r") out += "\r";
          else if (e === "0") out += "\0";
          else if (e === "a") out += "\x07";
          else if (e === "b") out += "\b";
          else if (e === "f") out += "\f";
          else if (e === "v") out += "\v";
          else if (e === "\\" || e === "'" || e === '"') out += e;
          else if (e === "x" && /^[0-9a-fA-F]{2}/.test(src.slice(j + 2))) {
            out += String.fromCharCode(parseInt(src.slice(j + 2, j + 4), 16)); j += 2;
          } else if (e === "u" && /^[0-9a-fA-F]{4}/.test(src.slice(j + 2))) {
            out += String.fromCharCode(parseInt(src.slice(j + 2, j + 6), 16)); j += 4;
          } else out += "\\" + e;
          j += 2;
        } else { out += src[j]; j++; }
      }
      if (j >= n) throw new PredicateError(`unterminated string in predicate`);
      toks.push({ t: "str", v: out });
      i = j + 1;
      continue;
    }
    if (src.slice(i, i + 3) === "...") { toks.push({ t: "ellipsis" }); i += 3; continue; }
    const two = src.slice(i, i + 2);
    if (two === "==" || two === "!=" || two === "<=" || two === ">=") { toks.push({ t: "op", v: two }); i += 2; continue; }
    if ("<>[](),".includes(ch)) { toks.push({ t: "op", v: ch }); i++; continue; }
    throw new PredicateError(`predicate uses disallowed syntax near ${JSON.stringify(src.slice(i, i + 8))}`);
  }
  return toks;
}

function parseExpr(src) {
  const toks = tokenize(src);
  let pos = 0;
  const peek = () => toks[pos];
  const next = () => toks[pos++];
  const expect = (v) => {
    const tk = next();
    if (!tk || tk.t !== "op" || tk.v !== v) throw new PredicateError(`expected ${JSON.stringify(v)} in predicate`);
  };

  // Depth accounting mirrors PYTHON AST DEPTH: only structural nesting (a boolean/comparison node,
  // `not`, a collection, a grouped expression) deepens — the precedence CASCADE itself adds nothing,
  // else `((((((((((x))))))))))` would burn ~5 levels per paren and reject expressions Python accepts.
  function orExpr(d) {
    if (d > MAX_DEPTH) throw new PredicateError("predicate nested too deeply");
    const vals = [andExpr(d)];
    while (peek() && peek().t === "name" && peek().v === "or") { next(); vals.push(andExpr(d + 1)); }
    return vals.length === 1 ? vals[0] : { k: "or", vals };
  }
  function andExpr(d) {
    if (d > MAX_DEPTH) throw new PredicateError("predicate nested too deeply");
    const vals = [notExpr(d)];
    while (peek() && peek().t === "name" && peek().v === "and") { next(); vals.push(notExpr(d + 1)); }
    return vals.length === 1 ? vals[0] : { k: "and", vals };
  }
  function notExpr(d) {
    if (d > MAX_DEPTH) throw new PredicateError("predicate nested too deeply");
    if (peek() && peek().t === "name" && peek().v === "not") { next(); return { k: "not", v: notExpr(d + 1) }; }
    return cmpExpr(d);
  }
  function cmpOp() {
    const tk = peek();
    if (!tk) return null;
    if (tk.t === "op" && ["==", "!=", "<", "<=", ">", ">="].includes(tk.v)) { next(); return tk.v; }
    if (tk.t === "name" && tk.v === "in") { next(); return "in"; }
    if (tk.t === "name" && tk.v === "not") {
      // in comparison position, `not` must begin `not in` (Python: `a not b` is a SyntaxError)
      next();
      const nx = next();
      if (!nx || nx.t !== "name" || nx.v !== "in") throw new PredicateError("expected `in` after `not`");
      return "not in";
    }
    return null;
  }
  function cmpExpr(d) {
    if (d > MAX_DEPTH) throw new PredicateError("predicate nested too deeply");
    const left = operand(d);
    const ops = [], rights = [];
    let op;
    while ((op = cmpOp()) !== null) { ops.push(op); rights.push(operand(d + 1)); }
    if (ops.length === 0) return left;
    return { k: "cmp", left, ops, rights };
  }
  function operand(d) {
    if (d > MAX_DEPTH) throw new PredicateError("predicate nested too deeply");
    const tk = next();
    if (!tk) throw new PredicateError("unexpected end of predicate");
    if (tk.t === "num") return { k: "const", v: tk.v };
    if (tk.t === "str") return { k: "const", v: tk.v };
    if (tk.t === "ellipsis") return { k: "const", v: ELLIPSIS };       // `...` is a truthy Constant
    if (tk.t === "name") {
      // Python-exact: True/False/None are constants; anything else (incl. lowercase true) is a Name
      if (tk.v === "True") return { k: "const", v: true };
      if (tk.v === "False") return { k: "const", v: false };
      if (tk.v === "None") return { k: "const", v: null };
      if (tk.v === "and" || tk.v === "or" || tk.v === "not" || tk.v === "in")
        throw new PredicateError(`unexpected keyword ${tk.v} in predicate`);
      if (PY_KEYWORDS.has(tk.v))
        throw new PredicateError(`predicate uses a Python keyword as a name: ${tk.v}`);
      return { k: "name", v: tk.v };
    }
    if (tk.t === "op" && tk.v === "[") {
      const elts = [];
      if (peek() && !(peek().t === "op" && peek().v === "]")) {
        elts.push(orExpr(d + 1));
        while (peek() && peek().t === "op" && peek().v === ",") { next(); if (peek() && peek().t === "op" && peek().v === "]") break; elts.push(orExpr(d + 1)); }
      }
      expect("]");
      return { k: "list", elts };
    }
    if (tk.t === "op" && tk.v === "(") {
      if (peek() && peek().t === "op" && peek().v === ")") { next(); return { k: "list", elts: [] }; }  // ()
      const first = orExpr(d + 1);
      if (peek() && peek().t === "op" && peek().v === ",") {           // a tuple literal, e.g. (1, 2)
        const elts = [first];
        while (peek() && peek().t === "op" && peek().v === ",") { next(); if (peek() && peek().t === "op" && peek().v === ")") break; elts.push(orExpr(d + 1)); }
        expect(")");
        return { k: "list", elts };
      }
      expect(")");
      return first;                                                    // a grouped expression
    }
    throw new PredicateError(`predicate uses disallowed syntax (${tk.v})`);
  }

  let tree = orExpr(0);
  // a TOP-LEVEL comma is a bare tuple in Python — `when done, verified` parses (and, being a
  // non-empty tuple, is ALWAYS truthy: a real authoring trap, but parity comes first)
  if (peek() && peek().t === "op" && peek().v === ",") {
    const elts = [tree];
    while (peek() && peek().t === "op" && peek().v === ",") {
      next();
      if (!peek()) break;                                              // trailing comma: (x,) style
      elts.push(orExpr(1));
    }
    tree = { k: "list", elts };
  }
  if (pos !== toks.length) throw new PredicateError("trailing tokens in predicate");
  return tree;
}

// ------------------------------------------------------------------------- evaluation
/** Python truthiness for JSON-ish values: null, false, 0, -0, "", [], {} are falsy. NaN is
 * TRUTHY (as in Python). */
export function pyTruthy(v) {
  if (v === null || v === undefined || v === false) return false;
  if (v === true) return true;
  if (typeof v === "number") return v !== 0;         // NaN !== 0 -> truthy, matching Python
  if (typeof v === "string") return v.length > 0;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === "object") return Object.keys(v).length > 0;
  return Boolean(v);
}

/** Python `==` over JSON values: booleans compare numerically with numbers (True == 1);
 * lists/objects compare structurally; cross-type otherwise is False (never an error). */
function pyEq(a, b) {
  const num = (x) => (typeof x === "number" ? x : typeof x === "boolean" ? Number(x) : null);
  const na = num(a), nb = num(b);
  if (na !== null && nb !== null) return na === nb;
  if (typeof a === "string" && typeof b === "string") return a === b;
  if (a === null || a === undefined) return b === null || b === undefined;
  if (b === null || b === undefined) return false;
  if (Array.isArray(a) && Array.isArray(b))
    return a.length === b.length && a.every((x, i) => pyEq(x, b[i]));
  if (typeof a === "object" && typeof b === "object" && !Array.isArray(a) && !Array.isArray(b)) {
    const ka = Object.keys(a), kb = Object.keys(b);
    return ka.length === kb.length && ka.every((k) => k in b && pyEq(a[k], b[k]));
  }
  return false;
}

/** Python ordering, total-ized: returns -1/0/1, or null for an incomparable pair (which the
 * comparison layer treats as UNSATISFIED). Strings compare by CODE POINT (like Python), not
 * UTF-16 code unit; lists compare lexicographically, element-wise. */
function pyOrder(a, b) {
  const num = (x) => (typeof x === "number" ? x : typeof x === "boolean" ? Number(x) : null);
  const na = num(a), nb = num(b);
  if (na !== null && nb !== null) {
    if (Number.isNaN(na) || Number.isNaN(nb)) return null;   // Python nan comparisons are all False
    return na < nb ? -1 : na > nb ? 1 : 0;
  }
  if (typeof a === "string" && typeof b === "string") {
    const A = [...a], B = [...b];                             // code points, matching Python
    for (let i = 0; i < Math.min(A.length, B.length); i++) {
      const x = A[i].codePointAt(0), y = B[i].codePointAt(0);
      if (x !== y) return x < y ? -1 : 1;
    }
    return A.length === B.length ? 0 : A.length < B.length ? -1 : 1;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      // Python list comparison steps past ==-EQUAL elements even when they are unorderable
      // ([None, 1] > [None] is True: None == None, then length decides) — so test equality
      // first and only demand an ordering when the elements differ.
      if (pyEq(a[i], b[i])) continue;
      const o = pyOrder(a[i], b[i]);
      if (o === null) return null;
      return o;
    }
    return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
  }
  return null;                                                // mixed / null / objects: incomparable
}

/** Python `a in b`: substring on strings, membership (loose ==) on lists, key test on
 * objects; anything else is a "type error" -> null (unsatisfied; `not in` satisfied). */
function pyIn(a, b) {
  if (typeof b === "string") return typeof a === "string" ? b.includes(a) : null;
  if (Array.isArray(b)) return b.some((x) => pyEq(a, x));
  if (b !== null && typeof b === "object") return typeof a === "string" ? Object.prototype.hasOwnProperty.call(b, a) : null;
  return null;
}

/** One pairwise comparison, made TOTAL exactly like predicates._compare: a failed/impossible
 * test is unsatisfied — except `not in`, which is then satisfied ("unknown -> falsy"). The
 * catch-all mirrors Python's blanket except: ANY internal failure (e.g. recursion overflow on an
 * absurdly nested context) is unsatisfied, never a crash out of run(). */
function compareOp(op, left, right) {
  try {
    switch (op) {
      case "==": return pyEq(left, right);
      case "!=": return !pyEq(left, right);
      case "<": case "<=": case ">": case ">=": {
        const o = pyOrder(left, right);
        if (o === null) return false;
        return op === "<" ? o < 0 : op === "<=" ? o <= 0 : op === ">" ? o > 0 : o >= 0;
      }
      case "in": {
        const r = pyIn(left, right);
        return r === null ? false : r;
      }
      case "not in": {
        const r = pyIn(left, right);
        return r === null ? true : !r;                        // failure satisfies `not in`
      }
      default: throw new PredicateError(`comparison operator ${op} not allowed`);
    }
  } catch (e) {
    if (e instanceof PredicateError) throw e;
    return op === "not in";                                   // total, like predicates._compare
  }
}

function evNode(node, ctx, depth) {
  if (depth > MAX_DEPTH) throw new PredicateError("predicate nested too deeply");
  switch (node.k) {
    case "const": return node.v;
    case "name": return Object.prototype.hasOwnProperty.call(ctx, node.v) ? ctx[node.v] : null;
    case "and": { const vals = node.vals.map((v) => evNode(v, ctx, depth + 1)); return vals.every(pyTruthy); }
    case "or": { const vals = node.vals.map((v) => evNode(v, ctx, depth + 1)); return vals.some(pyTruthy); }
    case "not": return !pyTruthy(evNode(node.v, ctx, depth + 1));
    case "list": return node.elts.map((e) => evNode(e, ctx, depth + 1));
    case "cmp": {
      let left = evNode(node.left, ctx, depth + 1);
      for (let i = 0; i < node.ops.length; i++) {
        const right = evNode(node.rights[i], ctx, depth + 1);
        if (!compareOp(node.ops[i], left, right)) return false;
        left = right;
      }
      return true;
    }
    default: throw new PredicateError(`unsupported predicate syntax (${node.k})`);
  }
}

/** Evaluate a deterministic condition against a context — predicates.eval_condition. */
export function evalCondition(condition, ctx) {
  const expr = exprOf(condition);
  const low = expr.toLowerCase();
  if (ALWAYS.has(low)) return true;
  if (NEVER.has(low)) return false;
  return pyTruthy(evNode(parseExpr(expr), ctx, 0));
}

/** Static safety check — predicates.check_predicate. [] means safe AND parseable. */
export function checkPredicate(condition) {
  if (!isDeterministic(condition)) return [];
  const expr = exprOf(condition);
  const low = expr.toLowerCase();
  if (ALWAYS.has(low) || NEVER.has(low)) return [];
  if (!expr) return [`empty \`when\` predicate in ${JSON.stringify(condition)}`];
  try { parseExpr(expr); } catch (e) {
    return [`unparseable/unsafe predicate ${JSON.stringify(condition)}: ${e.message}`];
  }
  return [];
}

// ---------------------------------------------------------------------------- parsing
const EDGE_RE = /^\s*-?\s*->\s*([A-Za-z0-9_\-]+)\s*:\s*(.+?)\s*$/;
const HEAD_RE = /^\s*##\s+(.+?)\s*$/;
const ANNO_RE = /^\s*@([\p{L}\p{N}_]+)\s*\((.*)\)\s*$/u;   // \w is Unicode in Python — match it

// Python str.splitlines() boundaries (fuzzing: a CR-only or U+2028 document must parse to the
// same node/edge sets on both engines; a bare split("\n") hides edges behind \r or NEL).
const LINE_SPLIT_RE = /\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]/;

function parseAnnoArgs(argstr) {
  const args = {};
  for (let part of argstr.split(",")) {
    part = part.trim();
    if (!part) continue;
    const eq = part.indexOf("=");
    if (eq >= 0) {
      const k = part.slice(0, eq).trim();
      if (k) args[k] = part.slice(eq + 1).trim();
    } else {
      args[part] = null;
    }
  }
  return args;
}

/** Markdown -> {name, start, nodes:{name:{name, instruction, edges:[[target,cond]], annotations}}} —
 * a faithful port of parser.parse. A node with no edges is terminal. */
export function parse(text) {
  const meta = {};
  let body = text;
  const m = text.match(/^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$/);
  if (m) {
    for (const line of m[1].split(LINE_SPLIT_RE)) {
      const c = line.indexOf(":");
      if (c >= 0) meta[line.slice(0, c).trim()] = line.slice(c + 1).trim();
    }
    body = m[2];
  }
  const nodes = {};
  let cur = null;
  let instr = [];
  const flush = () => { if (cur) cur.instruction = instr.join("\n").trim(); };
  for (const line of body.split(LINE_SPLIT_RE)) {
    const h = line.match(HEAD_RE);
    if (h) {
      flush();
      const name = h[1].trim().toLowerCase().replace(/ /g, "_");
      cur = { name, instruction: "", edges: [], annotations: {} };
      nodes[name] = cur;
      instr = [];
      continue;
    }
    if (!cur) continue;
    const e = line.match(EDGE_RE);
    const a = line.match(ANNO_RE);
    if (e) cur.edges.push([e[1].trim(), e[2].trim()]);
    else if (a) {
      const nm = a[1].trim();
      cur.annotations[nm] = { ...(cur.annotations[nm] || {}), ...parseAnnoArgs(a[2]) };
    } else instr.push(line);
  }
  flush();
  const names = Object.keys(nodes);
  return { name: meta.name !== undefined ? meta.name : "flow",
           start: meta.start || (names[0] || ""), nodes };
}

// ---------------------------------------------------------------------- portability gate
function reachable(graph) {
  const seen = new Set();
  const stack = [graph.start];
  while (stack.length) {
    const cur = stack.pop();
    if (seen.has(cur) || !(cur in graph.nodes)) continue;
    seen.add(cur);
    for (const [t] of graph.nodes[cur].edges) if (t in graph.nodes && !seen.has(t)) stack.push(t);
  }
  return seen;
}

/** Every semantic edge on a reachable node — [] means the flow is in the portable subset. */
export function portabilityViolations(graph) {
  const out = [];
  for (const name of [...reachable(graph)].sort()) {
    const node = graph.nodes[name];
    if (!node) continue;
    for (const [t, c] of node.edges)
      if (isSemantic(c)) out.push({ node: name, target: t, condition: c });
  }
  return out;
}

// -------------------------------------------------------------------------- the engine
/** Python str() for the JSON value kinds a worker can return — differential fuzzing showed
 * String() diverges on exactly the values that then ROUTE differently: true -> "True" (not
 * "true"), null -> "None", [1,2] -> "[1, 2]". Floats that JSON collapses to integers (3.0) are
 * inherently ambiguous cross-language and stay as JS renders them. */
function pyStr(v) {
  if (v === true) return "True";
  if (v === false) return "False";
  if (v === null || v === undefined) return "None";
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return "[" + v.map(pyRepr).join(", ") + "]";
  if (typeof v === "object") return "{" + Object.entries(v).map(([k, x]) => `'${k}': ${pyRepr(x)}`).join(", ") + "}";
  return String(v);
}
function pyRepr(v) {
  if (typeof v === "string") return `'${v}'`;
  return pyStr(v);
}

function normalize(outcome) {
  if (outcome !== null && typeof outcome === "object" && !Array.isArray(outcome)) {
    // Python: str(outcome.get("text", "")) — a PRESENT-but-None text is "None", absent is ""
    const t = "text" in outcome ? pyStr(outcome.text) : "";
    return [t, { ...outcome }];
  }
  return [pyStr(outcome), { text: pyStr(outcome) }];
}

/** First matching deterministic edge, document order — engine.first_deterministic. An
 * unsafe/unparseable predicate is non-matching, never a crash. */
export function firstDeterministic(edges, ctx) {
  for (const [t, c] of edges) {
    if (!isDeterministic(c)) continue;
    try { if (evalCondition(c, ctx)) return [t, c]; } catch (e) {
      if (!(e instanceof PredicateError)) throw e;
    }
  }
  return [null, null];
}

/** The resume target for a delivered event ('__timeout__' for a timeout) — mirrors the
 * event-edge matching in checkpoint.resume(event=...). Null if the node has no such edge. */
export function eventTarget(graph, node, event) {
  const n = graph.nodes[node];
  if (!n) return null;
  for (const [t, c] of n.edges) if (isEvent(c) && eventName(c) === event) return t;
  return null;
}

/**
 * Run a PORTABLE flow — a faithful port of engine.run for the ML-free subset (no semantic
 * tier, no type_gate). `agent(node, instruction, state)` returns a string or an object with
 * structured fields + `text`. Options: {maxSteps=25, start=null, state=null, onStep=null}.
 * Returns {path, steps, stopped, state, pending} exactly like the Python RunResult.
 * REFUSES a non-portable flow (semantic edge on a reachable node) up front.
 */
export function run(graph, agent, opts = {}) {
  const { maxSteps = 25, start = null, state: state0 = null, onStep = null } = opts;
  const violations = portabilityViolations(graph);
  if (violations.length) {
    const v = violations[0];
    throw new Error(
      `flow is not portable: semantic edge [${v.node}] -> ${v.target} (${JSON.stringify(v.condition)}) ` +
      `needs the embedding/LLM tier — run it on the Python engine, or rewrite the edge as a \`when\` predicate`);
  }
  let node = start !== null ? start : graph.start;
  const state = state0 || {};
  state.transcript = state.transcript || [];
  state.visits = state.visits || {};
  const res = { path: [node], steps: [], stopped: "", state, pending: null };
  const checkpoint = (pendingNode) => { if (onStep) onStep(res, pendingNode); };

  for (let step = 0; step < maxSteps; step++) {
    const n = graph.nodes[node];
    if (n.edges.length === 0) {                                  // terminal
      res.stopped = "terminal";
      checkpoint(null);
      break;
    }
    checkpoint(node);
    state.visits[node] = (state.visits[node] || 0) + 1;

    let outcome;
    try {
      outcome = agent(node, n.instruction, state);
    } catch (e) {                                                // error tier
      const ec = (state._errors = state._errors || {});
      ec[node] = (ec[node] || 0) + 1;
      const errCtx = {
        error: true, error_type: e.constructor?.name || "Error", error_message: String(e.message ?? e),
        error_count: ec[node], visits: state.visits[node],
      };
      let etarget = null;
      for (const [t, c] of n.edges) {
        if (!isError(c)) continue;
        const expr = errorExpr(c);
        try {
          if (!expr || evalCondition(expr, errCtx)) { etarget = t; break; }
        } catch (pe) { if (!(pe instanceof PredicateError)) throw pe; }
      }
      if (etarget === null) throw e;                             // no handler -> propagate
      const etext = `[error: ${errCtx.error_type}: ${errCtx.error_message}]`;
      state.transcript.push({ node, outcome: etext, error: true });
      res.steps.push({ node, outcome: etext, target: etarget, info: { used: "error", error_type: errCtx.error_type } });
      node = etarget;
      res.path.push(node);
      continue;
    }

    const [text, fields] = normalize(outcome);
    state.transcript.push({ node, outcome: text });
    (state._outcomes = state._outcomes || {})[node] = { ...fields };

    if (pyTruthy(fields.needs_human)) {                          // human handoff
      res.stopped = "needs_human";
      res.pending = { node, reason: fields.reason || text,
                      candidates: n.edges.map(([t, c]) => ({ target: t, condition: c })) };
      checkpoint(node);
      break;
    }

    if (pyTruthy(fields.wait) || fields.spawn != null) {         // wait / fan-out suspend
      const events = n.edges.filter(([, c]) => isEvent(c));
      res.stopped = "waiting";
      res.pending = { node, wait: true,
                      awaiting: events.map(([, c]) => eventName(c)),
                      timeout_s: fields.timeout_s ?? null,
                      candidates: events.map(([t, c]) => ({ target: t, condition: c })) };
      if (fields.spawn != null) res.pending.spawn = fields.spawn;
      checkpoint(node);
      break;
    }

    const ctx = { ...fields, visits: state.visits[node] };
    const [dt, dc] = firstDeterministic(n.edges, ctx);
    if (dt === null) {                                           // deterministic-only, nothing matched
      res.stopped = "stuck";
      checkpoint(node);
      break;
    }
    res.steps.push({ node, outcome: text, target: dt, info: { used: "deterministic", cond: dc } });
    node = dt;
    res.path.push(node);
  }
  if (!res.stopped) res.stopped = "max_steps";
  return res;
}

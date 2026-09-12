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
import { createHash } from "node:crypto";

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
const PY_WS = "[\\s\\x85\\x1c\\x1d\\x1e\\x1f]";
const PY_TRIM_RE = new RegExp(`^${PY_WS}+|${PY_WS}+$`, "gu");
function pyTrim(textVal) {
  return textVal.replace(PY_TRIM_RE, "");
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
  while (pos < len) {
    const currentChar = sourceText[pos];
    if (currentChar === " " || currentChar === "\t" || currentChar === "\n" || currentChar === "\r") {
      pos++;
      continue;
    }
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
    const elements = [];
    if (peekToken(parserState) && !(peekToken(parserState).t === "op" && peekToken(parserState).v === "]")) {
      elements.push(parseOr(parserState, astDepth + 1));
      while (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === ",") {
        nextToken(parserState);
        if (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === "]") {
          break;
        }
        elements.push(parseOr(parserState, astDepth + 1));
      }
    }
    expectToken(parserState, "]");
    return { k: "list", elts: elements };
  }
  if (tok.t === "op" && tok.v === "(") {
    if (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === ")") {
      nextToken(parserState);
      return { k: "list", elts: [] };
    }
    const firstVal = parseOr(parserState, astDepth + 1);
    if (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === ",") {
      const elements = [firstVal];
      while (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === ",") {
        nextToken(parserState);
        if (peekToken(parserState) && peekToken(parserState).t === "op" && peekToken(parserState).v === ")") {
          break;
        }
        elements.push(parseOr(parserState, astDepth + 1));
      }
      expectToken(parserState, ")");
      return { k: "list", elts: elements };
    }
    expectToken(parserState, ")");
    return firstVal;
  }
  throw new PredicateError(`predicate uses disallowed syntax (${tok.v})`);
}

function parseExpr(sourceText) {
  const tokens = tokenize(sourceText);
  const parserState = { tokens, pos: 0 };
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

export function parse(sourceText) {
  const frontmatterMeta = {};
  let flowBody = sourceText;
  const frontmatterMatch = sourceText.match(/^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$/);
  if (frontmatterMatch) {
    for (const lineText of frontmatterMatch[1].split(LINE_SPLIT_RE)) {
      const colonPos = lineText.indexOf(":");
      if (colonPos >= 0) frontmatterMeta[lineText.slice(0, colonPos).trim()] = lineText.slice(colonPos + 1).trim();
    }
    flowBody = frontmatterMatch[2];
  }
  const nodesMap = {};
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
  return {
    name: frontmatterMeta.name !== undefined ? frontmatterMeta.name : "flow",
    start: frontmatterMeta.start || (nodeNames[0] || ""),
    nodes: nodesMap,
  };
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

function cosine(vecA, vecB) {
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

// ---------------------------------------------------------------------- crypto agility proofs
const SUITE_NODE_PREFIX = "suite-";
const REACH_BOUND = 25;
const PQ_KEM_TOKENS = ["ml-kem", "kyber"];

export function pyCanonicalString(val) {
  if (val === null || typeof val !== "object") return JSON.stringify(val);
  if (Array.isArray(val)) return "[" + val.map(pyCanonicalString).join(",") + "]";
  const sortedKeys = Object.keys(val).sort();
  return "{" + sortedKeys.map((key) => JSON.stringify(key) + ":" + pyCanonicalString(val[key])).join(",") + "}";
}

export function registryHash(registryData) {
  return createHash("sha256").update(pyCanonicalString(registryData), "utf-8").digest("hex");
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

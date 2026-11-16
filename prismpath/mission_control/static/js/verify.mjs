// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The page's own check of a receipt (U3, docs/design/mission-control-plan.md section 3.3). The console's
// verdict is the console's. This module recomputes the receipt's leaf from the bytes of its line, folds the
// inclusion path to the statement's root, and checks the statement's signature with WebCrypto Ed25519
// under a key the assessor pinned in this page, never under the key the statement carries. What the
// console returned is data to check: a receipt whose bytes, path or statement were changed, by the log's
// writer or by the console itself, fails here whatever the console says.
//
// verifyReceiptBundle is a port of prismpath/ledgers/root_statement.py `verify_receipt_bundle`, held to
// every bundle case of portable/conformance/receipts.json. pageVerdict is the page's use of it.
//
// The portable modules are named by a specifier that reaches the same file both ways: from static/js/ on
// disk (node) it is prismpath/portable/, and from /js/verify.mjs in the browser a URL cannot climb above
// its root, so it is /portable/, which the console serves (app.py, these two files only).
import { CANON2, canon2Read, canon2Write } from "../../../portable/canon2.mjs";
import { fromHex, sha256, toHex, verifyLeaf } from "../../../portable/merkle.mjs";

export const STATEMENT_FORMAT = "prismpath-root-statement/3";
const OLD_SCHEME_FORMATS = ["prismpath-root-statement/2"];
const MERKLE_SCHEME = "rfc6962-sha256";
const LOG_AUDIT = "audit-log";
const SIGNING_DOMAIN = new TextEncoder().encode("prismpath-root-statement/3\u0000");
const BODY_FIELDS = ["format", "encoding", "log", "seq", "root", "leaves", "prev", "time_us", "trigger",
                     "key_id", "public_key", "policy"];
const ED25519 = { name: "Ed25519" };

// ---------------------------------------------------------------- JSON as Python reads it
/** A number written with a fraction or an exponent: Python reads it as a float, which has no canon/2 form
 *  and is not an int, while JSON.parse alone cannot tell 4.0 from 4. */
export class JsonFloat {
  constructor(value) {
    this.value = value;
  }
}

/** JSON read so the types Python sees survive: a fraction or exponent spelling becomes a JsonFloat and an
 *  integer past 2^53 a BigInt (the reviver's `source`, where the engine offers it). */
export function readJson(text) {
  return JSON.parse(text, (key, value, context) => {
    if (typeof value !== "number") return value;
    const source = context && typeof context.source === "string" ? context.source : null;
    if (source !== null && /[.eE]/.test(source)) return new JsonFloat(value);
    if (source !== null && !Number.isSafeInteger(value)) return BigInt(source);
    return Object.is(value, -0) ? 0 : value;
  });
}

const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const isDict = value => value !== null && typeof value === "object" && !Array.isArray(value) && !(value instanceof JsonFloat);
const isStr = value => typeof value === "string";
const isIntOrBool = value => (typeof value === "number" && Number.isInteger(value)) || typeof value === "bigint" || typeof value === "boolean";
const isInt = value => isIntOrBool(value) && typeof value !== "boolean";
const numeric = value => (value instanceof JsonFloat ? value.value : typeof value === "boolean" ? Number(value) : value);
const get = (object, key, fallback = null) => (own(object, key) ? object[key] : fallback);

// Python's == between a receipt's idx and an int index: numbers by value (4.0 == 4, True == 1), nothing else.
function pyEquals(left, right) {
  const [a, b] = [numeric(left), numeric(right)];
  const isNumber = value => typeof value === "number" || typeof value === "bigint";
  // eslint-disable-next-line eqeqeq -- a BigInt and a number compare by value only under ==
  return isNumber(a) && isNumber(b) && a == b;
}

// A value with no canon/2 form Python would refuse before writing: a float or an integer beyond 2^53.
function refusesCanon2(value, depth = 0) {
  if (value instanceof JsonFloat || typeof value === "bigint") return true;
  if (depth > 130 || value === null || typeof value !== "object") return false;
  return (Array.isArray(value) ? value : Object.values(value)).some(item => refusesCanon2(item, depth + 1));
}

/** The canon/2 bytes of a document that names canon/2, or throws (canon.document_bytes). */
function documentBytes(doc) {
  if (!isDict(doc) || !own(doc, "encoding") || doc.encoding !== CANON2) throw new Error("the document does not name canon/2");
  if (refusesCanon2(doc)) throw new Error("the document has no canon/2 form");
  return canon2Write(doc);
}

function documentHash(doc) {
  return toHex(sha256(documentBytes(doc)));
}

// The hash of a statement as the next one names it, or `unreadable` when it has no canon/2 form.
function linkHash(statement) {
  try {
    return documentHash(statement);
  } catch {
    return "unreadable";
  }
}

// The short form of a key id people compare: Python's key_id[:16], which a number or null cannot take.
function fingerprint(keyId) {
  if (isStr(keyId) || Array.isArray(keyId)) return keyId.slice(0, 16);
  throw new TypeError("a key id is text");
}

const keyIdOf = raw => toHex(sha256(raw));

function wellFormed(statement, log) {
  if (get(statement, "format") !== STATEMENT_FORMAT || get(statement, "log") !== log) return false;
  if ([...BODY_FIELDS, "sig"].some(key => !own(statement, key)) || Object.keys(statement).length !== BODY_FIELDS.length + 1) return false;
  if (statement.encoding !== CANON2 || !isInt(statement.time_us)) return false;
  if (!(isIntOrBool(statement.seq) && isIntOrBool(statement.leaves) && isStr(statement.root) && isStr(statement.prev)
        && isStr(statement.key_id))) return false;
  try {
    return fromHex(statement.public_key).length === 32 && fromHex(statement.sig).length === 64;
  } catch {
    return false;
  }
}

function signedBytes(statement) {
  const body = {};
  for (const key of BODY_FIELDS) body[key] = statement[key];
  if (refusesCanon2(body)) throw new Error("the statement has no canon/2 form");
  const written = canon2Write(body);
  const message = new Uint8Array(SIGNING_DOMAIN.length + written.length);
  message.set(SIGNING_DOMAIN);
  message.set(written, SIGNING_DOMAIN.length);
  return message;
}

/** WebCrypto has no Ed25519 here (an older browser, or a context with no crypto.subtle). */
export class Ed25519Unavailable extends Error {}

function subtleOf(subtle) {
  const found = subtle || (globalThis.crypto && globalThis.crypto.subtle);
  if (!found) throw new Ed25519Unavailable("this page has no WebCrypto");
  return found;
}

// Whether `statement`'s signature verifies under `publicRaw`. A key that is not a point, or a signature the
// message cannot be built for, is false; a WebCrypto with no Ed25519 throws Ed25519Unavailable.
async function signatureHolds(statement, publicRaw, subtle) {
  let key;
  const crypto = subtleOf(subtle);
  try {
    key = await crypto.importKey("raw", publicRaw, ED25519, false, ["verify"]);
  } catch (error) {
    if (error && error.name === "NotSupportedError") throw new Ed25519Unavailable(String(error.message || error));
    return false;
  }
  try {
    return await crypto.verify(ED25519, key, fromHex(statement.sig), signedBytes(statement));
  } catch (error) {
    if (error && error.name === "NotSupportedError") throw new Ed25519Unavailable(String(error.message || error));
    return false;
  }
}

// ---------------------------------------------------------------- the bundle check
/** Why `bundle` is not shaped like a receipt bundle, or null (root_statement.bundle_problem). */
export function bundleProblem(bundle) {
  if (!isDict(bundle)) return "a bundle is a JSON object";
  const kinds = { receipt: isDict, index: isInt, leaf: isStr, path: Array.isArray, statement: isDict };
  for (const [name, holds] of Object.entries(kinds)) {
    if (!holds(get(bundle, name))) return `missing or malformed field '${name}'`;
  }
  try {
    fromHex(bundle.leaf);
    for (const step of bundle.path) {
      if (!(Array.isArray(step) && step.length === 2 && (step[0] === "L" || step[0] === "R"))) return "malformed inclusion path";
      fromHex(step[1]);
    }
  } catch {
    return "the leaf and the inclusion path are hex hashes";
  }
  for (const name of ["receipt", "statement"]) {
    if (!own(bundle[name], "encoding") || bundle[name].encoding !== CANON2) return `the ${name} does not name canon/2 (canon/1 is retired)`;
  }
  return null;
}

// The checks of one bundle. `keySource` says whose key a signature is checked under: "carried", the key
// the statement carries (the reference's rule, which its key id and the pinned ids bind), or "pinned", only
// a pinned key whose id the statement names, and none when no pinned key has that id.
async function bundleChecks(bundle, pinned, { subtle, keySource }) {
  let problem = bundleProblem(bundle);
  if (problem === null && OLD_SCHEME_FORMATS.includes(get(bundle.statement, "format"))) {
    problem = `the statement is ${bundle.statement.format}, whose root is of the retired Merkle tree; this verifier `
      + `reads only ${STATEMENT_FORMAT} (${MERKLE_SCHEME})`;
  }
  const pinnedByKeyId = new Map(pinned.map(raw => [keyIdOf(raw), raw]));
  if (problem !== null) return { problem, checks: { well_formed: false }, pinnedByKeyId, unavailable: false };
  const statement = bundle.statement;
  let leaf;
  try {
    leaf = documentHash(bundle.receipt);
  } catch {
    leaf = "";
  }
  const checks = {
    leaf: leaf === bundle.leaf,
    index: pyEquals(get(bundle.receipt, "idx"), bundle.index),
    inclusion: verifyLeaf(bundle.leaf, bundle.path, get(statement, "root", "")),
    well_formed: wellFormed(statement, LOG_AUDIT),
  };
  checks.covered = checks.well_formed && 0 <= bundle.index && bundle.index < statement.leaves;
  checks.key_id = checks.well_formed && keyIdOf(fromHex(statement.public_key)) === statement.key_id;
  let unavailable = false;
  if (!checks.key_id) {
    checks.signature = false;
  } else {
    const key = keySource === "carried" ? fromHex(statement.public_key) : pinnedByKeyId.get(statement.key_id);
    try {
      checks.signature = key === undefined ? null : await signatureHolds(statement, key, subtle);
    } catch (error) {
      if (!(error instanceof Ed25519Unavailable)) throw error;
      unavailable = true;
      checks.signature = null;
    }
  }
  const keyId = get(statement, "key_id");
  if (pinnedByKeyId.size && keyId !== null && typeof keyId === "object" && !(keyId instanceof JsonFloat)) throw new TypeError("a key id is text");
  checks.pinned = pinnedByKeyId.size ? pinnedByKeyId.has(keyId) : null;
  return { problem: null, checks, pinnedByKeyId, unavailable };
}

/** The reference's verdict on a receipt bundle (root_statement.verify_receipt_bundle): receipt, leaf,
 *  inclusion path, signed root, signature, and the key against `pinned` (raw public keys). `status` is
 *  `signed`, `signed-unpinned` or `invalid`; a bundle not shaped like one is invalid with `problem`. A key
 *  id that is not text throws, as it does in the reference. */
export async function verifyReceiptBundle(bundle, pinned = [], { subtle } = {}) {
  const { problem, checks, pinnedByKeyId } = await bundleChecks(bundle, pinned, { subtle, keySource: "carried" });
  if (problem !== null) {
    return { ok: false, status: "invalid", pinned: pinned.length > 0, checks, problem, index: null, statement: null,
             statement_sha256: null, key: "" };
  }
  const ok = Object.entries(checks).every(([name, value]) => name === "pinned" || value) && checks.pinned !== false;
  const statement = bundle.statement;
  return { ok, status: ok ? (pinnedByKeyId.size ? "signed" : "signed-unpinned") : "invalid", pinned: pinnedByKeyId.size > 0,
           checks, index: get(bundle, "index"), statement: get(statement, "seq"), statement_sha256: linkHash(statement),
           key: fingerprint(get(statement, "key_id", "")) };
}

// ---------------------------------------------------------------- the page's verdict
const REASONS = {
  leaf: "the leaf is not the hash of the receipt's bytes",
  index: "the receipt's idx is not the bundle's index",
  inclusion: "the inclusion path does not reach the statement's root",
  well_formed: "the root statement is not well formed",
  covered: "the root statement does not cover the receipt",
  key_id: "the statement's key id is not the hash of its key",
  pinned: "the signer is not a pinned key",
  signature: "the signature does not verify under the pinned key",
};
const STRUCTURAL = ["leaf", "index", "inclusion", "well_formed", "covered", "key_id"];
export const NO_ED25519 = "this browser cannot check the signature";

function bytesOfBase64(text) {
  const binary = atob(String(text));
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function sameDocument(left, right) {
  try {
    return toHex(canon2Write(left)) === toHex(canon2Write(right));
  } catch {
    return false;
  }
}

function invalid(reason, checks) {
  return { status: "invalid", reason, checks };
}

/** The page's own verdict on the receipt view the console showed, from the bytes of its line and the keys
 *  pinned in this page ([{hex}]; the key id is recomputed from the key). `status` is `signed` (every check
 *  holds and a pinned key made the signature), `invalid` with `reason`, `unpinned` (the leaf and the path
 *  hold and no key is pinned to check the signature under), `unchecked` (everything but the signature
 *  holds and this browser has no Ed25519) or `unsigned` (no statement covers the receipt yet). Sends nothing. */
export async function pageVerdict(view, pins = [], { subtle } = {}) {
  if (!view || !view.bundle) {
    return { status: "unsigned", reason: (view && view.uncovered) || "no root statement covers this receipt yet", checks: {} };
  }
  const checks = { canonical: false, shown: false };
  let receipt;
  try {
    receipt = canon2Read(bytesOfBase64(view.raw && view.raw.b64));
  } catch (error) {
    return invalid(`the receipt's line is not canon/2${error && error.rule ? ` (${error.rule})` : ""}`, checks);
  }
  checks.canonical = true;
  checks.shown = sameDocument(view.event, receipt) && view.index === view.bundle.index;
  if (!checks.shown) return invalid("the receipt shown is not the one in the line's bytes", checks);
  const pinned = [];
  for (const pin of pins) {
    try {
      const raw = fromHex(pin.hex);
      if (raw.length === 32) pinned.push(raw);
    } catch {
      // a stored key that is not hex is no key
    }
  }
  let found;
  try {
    found = await bundleChecks({ ...view.bundle, receipt }, pinned, { subtle, keySource: "pinned" });
  } catch (error) {
    return invalid(`the bundle could not be checked: ${String(error && error.message ? error.message : error)}`, checks);
  }
  Object.assign(checks, found.checks);
  if (found.problem !== null) return invalid(found.problem, checks);
  const broken = STRUCTURAL.find(name => !checks[name]);
  if (broken) return invalid(REASONS[broken], checks);
  const key = fingerprint(view.bundle.statement.key_id);
  if (checks.pinned === null) return { status: "unpinned", reason: null, checks, key };
  if (!checks.pinned) return invalid(REASONS.pinned, checks);
  if (found.unavailable) return { status: "unchecked", reason: NO_ED25519, checks, key };
  if (!checks.signature) return invalid(REASONS.signature, checks);
  return { status: "signed", reason: null, checks, key };
}

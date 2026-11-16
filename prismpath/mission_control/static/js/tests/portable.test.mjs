// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The two portable modules the page's own verifier is built on, held to the frozen corpora the Python
// reference writes: canon/2 (canon2.mjs) to every case of conformance/canon2.json, and the RFC 6962 tree
// (merkle.mjs) to every prefix root of conformance/merkle_stream.json, batch and streaming, and to every
// merkle case of conformance/receipts.json, root and inclusion paths. run_vectors.mjs replays the same
// corpora; these tests are the client suite's copy, so CI's client job fails on a drift too.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { CANON2, Canon2Error, canon2Canonicalize, canon2Read, canon2Write, documentBytes } from "../../../../portable/canon2.mjs";
import { fromHex, leafHash, MerkleAccumulator, merkleRoot, merkleRootAndPaths, nodeHash, sha256, toHex, verifyLeaf }
  from "../../../../portable/merkle.mjs";

const PORTABLE = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "portable");
const corpus = name => JSON.parse(readFileSync(join(PORTABLE, "conformance", name), "utf-8"));

// The outcome of one canon/2 vector, or null when it agrees with the reference: the strict reader refuses
// with the reference's rule or reads the bytes as their own canonical form, and canonicalize gives the
// reference's canonical bytes, a fixed point, or the same refusal.
function canon2Problem(vector) {
  const bytes = fromHex(vector.hex);
  try {
    const document = canon2Read(bytes);
    if (vector.refuse !== undefined) return `read, the reference refuses it as ${vector.refuse}`;
    if (toHex(canon2Write(document)) !== vector.hex) return "the strict reader accepted bytes that are not canonical";
  } catch (error) {
    if (!(error instanceof Canon2Error)) return `crashed: ${error}`;
    if (vector.refuse === undefined) return `refused as ${error.rule}, the reference reads it`;
    if (error.rule !== vector.refuse) return `refused as ${error.rule}, want ${vector.refuse}`;
  }
  try {
    const written = canon2Canonicalize(bytes);
    if (vector.canonical_hex === undefined) return `canonicalized, the reference refuses it as ${vector.refuse}`;
    if (toHex(written) !== vector.canonical_hex) return `canonicalized to ${toHex(written)}`;
    if (toHex(canon2Write(canon2Read(written))) !== vector.canonical_hex) return "the canonical bytes are not a fixed point";
  } catch (error) {
    if (!(error instanceof Canon2Error)) return `canonicalize crashed: ${error}`;
    if (vector.canonical_hex !== undefined) return `canonicalize refused as ${error.rule}, the reference canonicalizes it`;
    if (error.rule !== vector.refuse) return `canonicalize refused as ${error.rule}, want ${vector.refuse}`;
  }
  return null;
}

test("canon2.mjs gives the reference's answer on every case of canon2.json", () => {
  const { cases } = corpus("canon2.json");
  assert.equal(cases.length, 87);
  const wrong = cases.map(vector => [vector.name, canon2Problem(vector)]).filter(([, problem]) => problem !== null);
  assert.deepEqual(wrong, []);
  assert.equal(cases.filter(vector => vector.refuse !== undefined).length, 74, "the refusals are all exercised");
});

test("a document is hashed only when it names canon/2", () => {
  assert.equal(new TextDecoder().decode(documentBytes({ encoding: CANON2, b: 1, a: [true, null] })),
               '{"a":[true,null],"b":1,"encoding":"canon/2"}');
  assert.throws(() => documentBytes({ a: 1 }), /canon\/1 is retired/);
  assert.throws(() => documentBytes({ encoding: "canon/3" }), /only canon\/2 is read/);
  assert.throws(() => documentBytes([1]), /canon\/1 is retired/);
  assert.throws(() => documentBytes({ encoding: CANON2, ratio: 0.5 }), error => error instanceof Canon2Error && error.rule === "float");
});

test("canon2.mjs is the kernel's canon/2 section, byte for byte", { skip: !existsSync(join(PORTABLE, "prismpath.mjs")) && "the product carries no kernel" }, () => {
  // One canon/2 in JavaScript: the page's module is the kernel's section copied out whole, so the two
  // cannot drift. The kernel stays one file because the bundle compiler inlines it.
  const section = text => {
    const begin = text.indexOf("// ------------------------------------------------------------------------------------- canon/2");
    const end = text.indexOf("\n}\n", text.indexOf("export function canon2Write(value) {"));
    assert.ok(begin >= 0 && end > begin, "the canon/2 section markers are present");
    return text.slice(begin, end + 3);
  };
  assert.equal(section(readFileSync(join(PORTABLE, "canon2.mjs"), "utf-8")),
               section(readFileSync(join(PORTABLE, "prismpath.mjs"), "utf-8")));
});

test("sha256 over bytes is the FIPS 180-4 digest", () => {
  assert.equal(toHex(sha256(new Uint8Array())), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(toHex(sha256(new TextEncoder().encode("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const million = new Uint8Array(1000000).fill(0x61);
  assert.equal(toHex(sha256(million)), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  for (const length of [55, 56, 63, 64, 65, 119, 120]) {
    assert.equal(sha256(new Uint8Array(length)).length, 32);
  }
});

test("merkle.mjs gives every prefix root of merkle_stream.json, batch and streaming", () => {
  const stream = corpus("merkle_stream.json");
  assert.equal(stream.scheme, "rfc6962-sha256");
  let checked = 0;
  for (const set of stream.sets) {
    assert.equal(set.roots.length, set.leaves.length + 1, set.name);
    assert.equal(set.roots[0], null);
    assert.equal(merkleRoot([]), null);
    const accumulator = new MerkleAccumulator();
    assert.equal(accumulator.root(), null);
    set.leaves.forEach((leaf, index) => {
      accumulator.add(leaf);
      assert.equal(accumulator.count, index + 1);
      assert.equal(accumulator.root(), set.roots[index + 1], `${set.name}: streaming root over ${index + 1}`);
      assert.equal(merkleRoot(set.leaves.slice(0, index + 1)), set.roots[index + 1], `${set.name}: batch root over ${index + 1}`);
      checked++;
    });
  }
  assert.equal(checked, 378);
});

test("merkle.mjs gives every root and inclusion path of the merkle cases in receipts.json", () => {
  const merkleCases = corpus("receipts.json").cases.filter(entry => entry.kind === "merkle");
  assert.equal(merkleCases.length, 14);
  for (const entry of merkleCases) {
    const [root, paths] = merkleRootAndPaths(entry.leaves);
    assert.equal(root ?? "", entry.root, entry.name);
    assert.deepEqual(paths, entry.paths, entry.name);
    entry.leaves.forEach((leaf, index) => {
      assert.ok(verifyLeaf(leaf, entry.paths[index], entry.root), `${entry.name}: leaf ${index}`);
      if (entry.paths[index].length) {
        assert.ok(!verifyLeaf("00".repeat(32), entry.paths[index], entry.root), `${entry.name}: a stranger leaf ${index}`);
      }
    });
  }
});

test("leaf and node hashes carry the RFC 6962 domain prefixes", () => {
  const empty = new Uint8Array();
  assert.equal(toHex(leafHash(empty)), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
  const left = leafHash(fromHex("00"));
  const right = leafHash(fromHex("10"));
  const joined = new Uint8Array([1, ...left, ...right]);
  assert.equal(toHex(nodeHash(left, right)), toHex(sha256(joined)));
});

test("hex is read as Python's bytes.fromhex reads it", () => {
  assert.deepEqual(Array.from(fromHex("0aFF")), [10, 255]);
  assert.deepEqual(Array.from(fromHex(" 0a ff\n")), [10, 255]);
  for (const bad of ["0", "0g", "0 a", "zz", 5, null]) {
    assert.throws(() => fromHex(bad), Error, String(bad));
  }
});

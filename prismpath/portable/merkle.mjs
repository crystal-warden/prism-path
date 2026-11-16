// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// merkle.mjs: the RFC 6962 Merkle tree every PrismPath audit log is rooted in (ledger_ots.MERKLE_SCHEME,
// rfc6962-sha256), as one dependency free ES module: SHA-256 over bytes, the leaf and node hashes with
// their domain prefixes, the root and inclusion paths over a list of leaves, folding a path to a root,
// and the streaming accumulator a deployment signs its roots from. A port of prismpath/ledgers/ledger_ots.py
// and root_statement.MerkleAccumulator, held to conformance/merkle_stream.json (every prefix root, batch
// and streaming) and to the merkle cases of conformance/receipts.json by run_vectors.mjs and the Mission
// Control client suite. `formal/Core/Merkle.lean` proves the accumulator equal to the tree for every list.
//
// Leaves and hashes are hex text, read as Python's bytes.fromhex reads it, so a leaf the reference refuses
// is refused here too. Everything is synchronous: the tree is checked where WebCrypto is absent as well.

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** SHA-256 (FIPS 180-4) of `data`, a Uint8Array, as a 32 byte Uint8Array. */
export function sha256(data) {
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
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  h.forEach((word, index) => outView.setUint32(index * 4, word));
  return out;
}

/** Lowercase hex of bytes. */
export function toHex(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

const ASCII_WHITESPACE = " \t\n\r\x0b\x0c";
const HEX_DIGIT = /^[0-9a-fA-F]$/;

/** The bytes of hex text as Python's bytes.fromhex reads them: two digits per byte, either case, ASCII
 *  whitespace allowed between bytes and never inside one. Throws on anything else, a non-string included. */
export function fromHex(text) {
  if (typeof text !== "string") throw new TypeError("hex must be text");
  const out = [];
  let index = 0;
  while (index < text.length) {
    if (ASCII_WHITESPACE.includes(text[index])) { index++; continue; }
    const high = text[index];
    const low = text[index + 1];
    if (!HEX_DIGIT.test(high) || low === undefined || !HEX_DIGIT.test(low)) {
      throw new RangeError(`non-hexadecimal number found in hex at position ${HEX_DIGIT.test(high) ? index + 1 : index}`);
    }
    out.push(parseInt(high + low, 16));
    index += 2;
  }
  return Uint8Array.from(out);
}

function prefixed(prefix, ...parts) {
  const joined = new Uint8Array(1 + parts.reduce((total, part) => total + part.length, 0));
  joined[0] = prefix;
  let at = 1;
  for (const part of parts) { joined.set(part, at); at += part.length; }
  return sha256(joined);
}

/** The hash of a Merkle leaf: SHA-256 of 0x00 and the leaf's bytes. */
export function leafHash(leaf) {
  return prefixed(LEAF_PREFIX, leaf);
}

/** The hash of an inner node: SHA-256 of 0x01, the left child's hash, then the right's. */
export function nodeHash(left, right) {
  return prefixed(NODE_PREFIX, left, right);
}

/** RFC 6962's k for a tree over `count` (at least 2) leaves: the largest power of two below it. */
function splitPoint(count) {
  let k = 1;
  while (k * 2 < count) k *= 2;
  return k;
}

function subtree(hashes) {
  if (hashes.length === 1) return [hashes[0], [[]]];
  const k = splitPoint(hashes.length);
  const [left, leftPaths] = subtree(hashes.slice(0, k));
  const [right, rightPaths] = subtree(hashes.slice(k));
  const paths = [...leftPaths.map(path => [...path, ["R", toHex(right)]]),
                 ...rightPaths.map(path => [...path, ["L", toHex(left)]])];
  return [nodeHash(left, right), paths];
}

/** The RFC 6962 tree over hex leaves: [root hex, a path per leaf], or [null, []] for no leaves. A path is
 *  the siblings from the leaf up, ["R", hex] when the sibling is on the right and ["L", hex] when on the
 *  left, exactly as ledger_ots.merkle_root_and_paths writes it. */
export function merkleRootAndPaths(leavesHex) {
  if (!leavesHex.length) return [null, []];
  const [root, paths] = subtree(leavesHex.map(leaf => leafHash(fromHex(leaf))));
  return [toHex(root), paths];
}

function subtreeRoot(hashes) {
  if (hashes.length === 1) return hashes[0];
  const k = splitPoint(hashes.length);
  return nodeHash(subtreeRoot(hashes.slice(0, k)), subtreeRoot(hashes.slice(k)));
}

/** The RFC 6962 root over hex leaves, or null for none, straight from the definition (RFC 6962 section
 *  2.1, MTH) rather than from the accumulator, so each checks the other. */
export function merkleRoot(leavesHex) {
  if (!leavesHex.length) return null;
  return toHex(subtreeRoot(leavesHex.map(leaf => leafHash(fromHex(leaf)))));
}

/** Whether `leafHex` sits under `rootHex` along `path`: its leaf hash folded with each sibling, the
 *  sibling on the left for "L" and on the right otherwise (ledger_ots.verify_leaf). */
export function verifyLeaf(leafHex, path, rootHex) {
  let current = leafHash(fromHex(leafHex));
  for (const [side, siblingHex] of path) {
    const sibling = fromHex(siblingHex);
    current = side === "R" ? nodeHash(current, sibling) : nodeHash(sibling, current);
  }
  return toHex(current) === rootHex;
}

/** The same root kept as leaves arrive (root_statement.MerkleAccumulator): the roots of the complete
 *  subtrees, one per set bit of the leaf count, merged by binary carry as a leaf is added and folded from
 *  the shortest up, each taller peak the left child, when the root is read. */
export class MerkleAccumulator {
  constructor() {
    this.peaks = [];   // [height, hash], tallest first
    this.count = 0;
  }

  add(leafHex) {
    let height = 0;
    let node = leafHash(fromHex(leafHex));
    while (this.peaks.length && this.peaks[this.peaks.length - 1][0] === height) {
      node = nodeHash(this.peaks.pop()[1], node);
      height++;
    }
    this.peaks.push([height, node]);
    this.count++;
  }

  /** The root over every leaf added so far, or null for none. */
  root() {
    if (!this.peaks.length) return null;
    let node = this.peaks[this.peaks.length - 1][1];
    for (let index = this.peaks.length - 2; index >= 0; index--) node = nodeHash(this.peaks[index][1], node);
    return toHex(node);
  }
}

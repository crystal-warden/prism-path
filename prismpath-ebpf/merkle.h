/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* merkle.h — the canonical receipt-trail Merkle root, shared so every harness that anchors a batch
 * (kernel data receipts AND loader migration receipts) uses ONE implementation and cannot drift.
 * The tree is RFC 6962's, the one every PrismPath ledger builds (prismpath/ledgers/ledger_ots.py,
 * prismpath-rs/src/merkle.rs): each leaf is sha256(receipt bytes), hashed into the tree as
 * sha256(0x00 || leaf); an inner node is sha256(0x01 || left || right); a tree over n leaves splits at
 * the largest power of two below n, and nothing is duplicated, so a batch and the same batch with its last
 * receipt repeated have different roots. The root is what a single OTS stamp anchors. (The tree before,
 * pairwise sha256 with the last node of an odd layer duplicated, is retired; roots recorded under it in
 * older evidence logs are of that tree.) */
#ifndef PPT_MERKLE_H
#define PPT_MERKLE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "ppt_common.h"

/* RFC 6962 MTH over `n` (>= 1) leaf hashes already prefixed with 0x00. */
static inline void merkle_subtree(uint8_t (*hashes)[32], int n, uint8_t out[32]) {
    if (n == 1) { memcpy(out, hashes[0], 32); return; }
    int k = 1;
    while (2 * k < n) k *= 2;
    uint8_t buf[65];
    buf[0] = 0x01;
    merkle_subtree(hashes, k, buf + 1);
    merkle_subtree(hashes + k, n - k, buf + 33);
    SHA256(buf, sizeof buf, out);
}

static inline void merkle_root(const struct ppt_receipt *r, int n, uint8_t root[32]) {
    if (n <= 0) { memset(root, 0, 32); return; }
    uint8_t (*leaves)[32] = malloc((size_t)n * 32);
    /* Every caller anchors this root in a receipt trail, so a null here must not be written
     * through and must never become a plausible-looking root over nothing. */
    if (!leaves) { fprintf(stderr, "merkle_root: out of memory for %d leaves\n", n); exit(1); }
    for (int i = 0; i < n; i++) {
        uint8_t buf[33];
        buf[0] = 0x00;
        SHA256((const unsigned char *)&r[i], sizeof(r[i]), buf + 1);
        SHA256(buf, sizeof buf, leaves[i]);
    }
    merkle_subtree(leaves, n, root);
    free(leaves);
}

#endif /* PPT_MERKLE_H */

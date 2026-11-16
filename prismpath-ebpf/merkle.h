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
 * older evidence logs are of that tree.)
 *
 * The root is computed in its streaming form, the one algorithm here: `struct ppt_merkle_acc` keeps the
 * peaks, the roots of the perfect subtrees the leaves so far fall into, one per set bit of the leaf count
 * (`peaks[h]` holds a subtree of 2^h leaves when bit h of `count` is set). Adding a leaf is binary counter
 * carry: the new leaf hash merges with the peak of each set low bit, the older peak as the left child, and
 * lands at the first clear bit. The root folds the peaks from the shortest up, each taller peak the left
 * child of what is folded so far. That is the same root as the tree (formal/Core/Merkle.lean,
 * `acc_root_eq_mth`), in fixed state: 64 peaks of 32 bytes and a 64-bit count, no heap and no recursion,
 * so the same code fits firmware and other targets with no allocator. The batch `merkle_root` over
 * receipts is the accumulator fed one receipt at a time.
 *
 * The SHA-256 is isolated behind three functions. By default they are OpenSSL's. A port with its own
 * SHA-256 (firmware, a hardware engine) defines PPT_MERKLE_SHA256_EXTERNAL and, before including this
 * header, the type `ppt_sha256_ctx` and
 *     void ppt_sha256_init(ppt_sha256_ctx *ctx);
 *     void ppt_sha256_update(ppt_sha256_ctx *ctx, const void *data, size_t len);
 *     void ppt_sha256_final(ppt_sha256_ctx *ctx, uint8_t out[32]);
 * and nothing else in this file touches a hash. A port that has no receipts (only the accumulator)
 * defines PPT_MERKLE_NO_RECEIPTS and the header needs nothing beyond <stdint.h>, <stddef.h> and
 * <string.h>. */
#ifndef PPT_MERKLE_H
#define PPT_MERKLE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef PPT_MERKLE_SHA256_EXTERNAL
#include <openssl/sha.h>
typedef SHA256_CTX ppt_sha256_ctx;
/* OpenSSL 3 marks the streaming SHA256_* calls deprecated in favour of EVP, which allocates its context;
 * these keep the context on the stack. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static inline void ppt_sha256_init(ppt_sha256_ctx *ctx) { SHA256_Init(ctx); }
static inline void ppt_sha256_update(ppt_sha256_ctx *ctx, const void *data, size_t len) { SHA256_Update(ctx, data, len); }
static inline void ppt_sha256_final(ppt_sha256_ctx *ctx, uint8_t out[32]) { SHA256_Final(out, ctx); }
#pragma GCC diagnostic pop
#endif

#define PPT_MERKLE_MAX_PEAKS 64

struct ppt_merkle_acc {
    uint8_t peaks[PPT_MERKLE_MAX_PEAKS][32];
    uint64_t count;   /* leaves added; bit h set = peaks[h] holds a subtree of 2^h leaves */
};

/* SHA-256(0x00 || leaf): the hash of a leaf's bytes. */
static inline void ppt_merkle_leaf_hash(const void *leaf, size_t len, uint8_t out[32]) {
    static const uint8_t prefix = 0x00;
    ppt_sha256_ctx ctx;
    ppt_sha256_init(&ctx);
    ppt_sha256_update(&ctx, &prefix, 1);
    ppt_sha256_update(&ctx, leaf, len);
    ppt_sha256_final(&ctx, out);
}

/* SHA-256(0x01 || left || right): the hash of an inner node. `out` may alias either child. */
static inline void ppt_merkle_node_hash(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) {
    static const uint8_t prefix = 0x01;
    ppt_sha256_ctx ctx;
    ppt_sha256_init(&ctx);
    ppt_sha256_update(&ctx, &prefix, 1);
    ppt_sha256_update(&ctx, left, 32);
    ppt_sha256_update(&ctx, right, 32);
    ppt_sha256_final(&ctx, out);
}

static inline void ppt_merkle_acc_init(struct ppt_merkle_acc *acc) {
    memset(acc, 0, sizeof *acc);
}

/* Add a leaf given as its leaf hash, SHA-256(0x00 || leaf). Returns 0, or -1 and adds nothing when the
 * count is already 2^64 - 1, the most 64 peaks hold. */
static inline int ppt_merkle_acc_add_leaf_hash(struct ppt_merkle_acc *acc, const uint8_t leaf_hash[32]) {
    if (acc->count == UINT64_MAX) return -1;
    uint8_t node[32];
    memcpy(node, leaf_hash, 32);
    unsigned height = 0;
    /* a count below 2^64 - 1 has a clear bit at or below 63, so height stays below 64 */
    while (acc->count & ((uint64_t)1 << height)) {
        ppt_merkle_node_hash(acc->peaks[height], node, node);
        height++;
    }
    memcpy(acc->peaks[height], node, 32);
    acc->count++;
    return 0;
}

/* Add a leaf given as its bytes. Returns 0, or -1 as ppt_merkle_acc_add_leaf_hash does. */
static inline int ppt_merkle_acc_add(struct ppt_merkle_acc *acc, const void *leaf, size_t len) {
    uint8_t hash[32];
    ppt_merkle_leaf_hash(leaf, len, hash);
    return ppt_merkle_acc_add_leaf_hash(acc, hash);
}

/* The root over the leaves added so far: writes it and returns 1, or for no leaves writes 32 zero bytes
 * and returns 0 (RFC 6962 has no root over nothing). */
static inline int ppt_merkle_acc_root(const struct ppt_merkle_acc *acc, uint8_t root[32]) {
    if (acc->count == 0) { memset(root, 0, 32); return 0; }
    unsigned height = 0;
    while (!(acc->count & ((uint64_t)1 << height))) height++;
    uint8_t node[32];
    memcpy(node, acc->peaks[height], 32);
    for (height++; height < PPT_MERKLE_MAX_PEAKS; height++)
        if (acc->count & ((uint64_t)1 << height)) ppt_merkle_node_hash(acc->peaks[height], node, node);
    memcpy(root, node, 32);
    return 1;
}

#ifndef PPT_MERKLE_NO_RECEIPTS
#include "ppt_common.h"

/* The root over `n` receipts, each leaf sha256(receipt bytes); 32 zero bytes for n <= 0. */
static inline void merkle_root(const struct ppt_receipt *r, int n, uint8_t root[32]) {
    struct ppt_merkle_acc acc;
    ppt_merkle_acc_init(&acc);
    for (int i = 0; i < n; i++) {
        uint8_t leaf[32];
        ppt_sha256_ctx ctx;
        ppt_sha256_init(&ctx);
        ppt_sha256_update(&ctx, &r[i], sizeof(r[i]));
        ppt_sha256_final(&ctx, leaf);
        /* n is an int, so the count never reaches 2^64 - 1 and the add cannot refuse */
        (void)ppt_merkle_acc_add(&acc, leaf, sizeof leaf);
    }
    ppt_merkle_acc_root(&acc, root);
}
#endif

#endif /* PPT_MERKLE_H */

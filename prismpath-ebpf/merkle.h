/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* merkle.h — the canonical receipt-trail Merkle root, shared so every harness that anchors a batch
 * (kernel data receipts AND loader migration receipts) uses ONE implementation and cannot drift.
 * Leaf = sha256(receipt bytes); pairwise sha256 to the root, duplicating the last node on an odd
 * layer. The root is what a single OTS stamp anchors. Extracted verbatim from receipts_selector.c. */
#ifndef PPT_MERKLE_H
#define PPT_MERKLE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "ppt_common.h"

static inline void merkle_root(const struct ppt_receipt *r, int n, uint8_t root[32]) {
    if (n <= 0) { memset(root, 0, 32); return; }
    uint8_t (*cur)[32] = malloc((size_t)n * 32);
    for (int i = 0; i < n; i++) SHA256((const unsigned char *)&r[i], sizeof(r[i]), cur[i]);
    int cnt = n;
    while (cnt > 1) {
        int half = (cnt + 1) / 2;
        uint8_t (*nx)[32] = malloc((size_t)half * 32);
        for (int i = 0; i < half; i++) {
            uint8_t buf[64];
            memcpy(buf, cur[2 * i], 32);
            memcpy(buf + 32, cur[(2 * i + 1 < cnt) ? 2 * i + 1 : 2 * i], 32);   /* dup last if odd */
            SHA256(buf, 64, nx[i]);
        }
        free(cur); cur = nx; cnt = half;
    }
    memcpy(root, cur[0], 32); free(cur);
}

#endif /* PPT_MERKLE_H */

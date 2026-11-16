/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* test_merkle.c — merkle.h's streaming root held to the tree and to the Python reference.
 *
 *   make test-merkle      (builds this twice and runs both against the frozen vectors)
 *
 * 1. The accumulator against RFC 6962's MTH written here from the RFC's text (recursive, test only) for
 *    every count from 0 to 1000 over fixed leaves.
 * 2. The Certificate Transparency known-answer vectors through the accumulator.
 * 3. The batch merkle_root over receipts against the same MTH over sha256(receipt) leaves.
 * 4. With a path argument: every prefix root of every set in the frozen cross-language vectors
 *    (prismpath/portable/conformance/merkle_stream.json, written by the Python reference).
 * 5. A count of 2^64 - 1 refuses the next leaf.
 *
 * Built with -DTEST_EXTERNAL_SHA256 the header's hash seam is replaced by a backend defined here (OpenSSL
 * underneath, counting finals), which shows a port can swap the SHA-256 and that the tree makes exactly
 * 2n - 1 hashes over n leaves through it and none any other way. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST_EXTERNAL_SHA256
#include <openssl/sha.h>
#define PPT_MERKLE_SHA256_EXTERNAL
typedef struct { SHA256_CTX inner; } ppt_sha256_ctx;
static unsigned long long g_finals;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static void ppt_sha256_init(ppt_sha256_ctx *ctx) { SHA256_Init(&ctx->inner); }
static void ppt_sha256_update(ppt_sha256_ctx *ctx, const void *data, size_t len) { SHA256_Update(&ctx->inner, data, len); }
static void ppt_sha256_final(ppt_sha256_ctx *ctx, uint8_t out[32]) { SHA256_Final(out, &ctx->inner); g_finals++; }
#pragma GCC diagnostic pop
#endif

#include "merkle.h"

static int g_failures;
#define CHECK(cond, ...) do { if (!(cond)) { g_failures++; fprintf(stderr, "FAIL: " __VA_ARGS__); fputc('\n', stderr); } } while (0)

/* The reference: RFC 6962 section 2.1 MTH over leaf byte strings, using OpenSSL's one-shot SHA256 so it
 * shares no code with the header. */
struct leaf { uint8_t *bytes; size_t len; };

static void ref_mth(const struct leaf *leaves, size_t n, uint8_t out[32]) {
    if (n == 1) {
        uint8_t *buf = malloc(leaves[0].len + 1);
        if (!buf) { perror("malloc"); exit(2); }
        buf[0] = 0x00;
        if (leaves[0].len) memcpy(buf + 1, leaves[0].bytes, leaves[0].len);
        SHA256(buf, leaves[0].len + 1, out);
        free(buf);
        return;
    }
    size_t k = 1;
    while (2 * k < n) k *= 2;
    uint8_t buf[65];
    buf[0] = 0x01;
    ref_mth(leaves, k, buf + 1);
    ref_mth(leaves + k, n - k, buf + 33);
    SHA256(buf, sizeof buf, out);
}

static void to_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) { out[2 * i] = digits[bytes[i] >> 4]; out[2 * i + 1] = digits[bytes[i] & 15]; }
    out[2 * len] = 0;
}

static int from_hex(const char *text, size_t chars, uint8_t *out) {
    if (chars % 2) return -1;
    for (size_t i = 0; i < chars / 2; i++) {
        unsigned value;
        if (sscanf(text + 2 * i, "%2x", &value) != 1) return -1;
        out[i] = (uint8_t)value;
    }
    return 0;
}

#ifdef TEST_EXTERNAL_SHA256
static int popcount64(uint64_t x) { int c = 0; while (x) { c += (int)(x & 1); x >>= 1; } return c; }
#endif

static void test_every_count_to_a_thousand(void) {
    enum { N = 1000 };
    static uint8_t bytes[N][32];
    static struct leaf leaves[N];
    for (uint32_t i = 0; i < N; i++) {
        uint8_t be[4] = { (uint8_t)(i >> 24), (uint8_t)(i >> 16), (uint8_t)(i >> 8), (uint8_t)i };
        SHA256(be, 4, bytes[i]);
        leaves[i].bytes = bytes[i];
        leaves[i].len = 32;
    }
    struct ppt_merkle_acc acc;
    ppt_merkle_acc_init(&acc);
    uint8_t root[32], want[32];
    CHECK(ppt_merkle_acc_root(&acc, root) == 0, "no leaves gave a root");
    for (size_t n = 1; n <= N; n++) {
#ifdef TEST_EXTERNAL_SHA256
        unsigned long long before = g_finals;
#endif
        CHECK(ppt_merkle_acc_add(&acc, leaves[n - 1].bytes, leaves[n - 1].len) == 0, "add refused at %zu", n);
        CHECK(ppt_merkle_acc_root(&acc, root) == 1, "no root at %zu", n);
#ifdef TEST_EXTERNAL_SHA256
        /* one leaf hash, one node hash per carry, one per fold step */
        unsigned long long carries = (unsigned long long)__builtin_ctzll((unsigned long long)n);
        CHECK(g_finals - before == 1 + carries + (unsigned long long)(popcount64(n) - 1),
              "%llu hashes for leaf %zu", g_finals - before, n);
#endif
        ref_mth(leaves, n, want);
        CHECK(memcmp(root, want, 32) == 0, "accumulator differs from the tree at %zu leaves", n);
        CHECK(acc.count == n, "count %llu at %zu", (unsigned long long)acc.count, n);
    }
}

static void test_known_answer_vectors(void) {
    static const char *inputs[8] = { "", "00", "10", "2021", "3031", "40414243", "5051525354555657",
                                     "606162636465666768696a6b6c6d6e6f" };
    static const char *roots[8] = {
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    };
    struct ppt_merkle_acc acc;
    ppt_merkle_acc_init(&acc);
    for (int i = 0; i < 8; i++) {
        uint8_t leaf[16], root[32];
        size_t len = strlen(inputs[i]) / 2;
        CHECK(from_hex(inputs[i], strlen(inputs[i]), leaf) == 0, "bad input %d", i);
        ppt_merkle_acc_add(&acc, leaf, len);
        ppt_merkle_acc_root(&acc, root);
        char hex[65];
        to_hex(root, 32, hex);
        CHECK(strcmp(hex, roots[i]) == 0, "known answer %d: %s", i + 1, hex);
    }
}

static void test_batch_over_receipts(void) {
    enum { N = 70 };
    static struct ppt_receipt receipts[N];
    static uint8_t bytes[N][32];
    static struct leaf leaves[N];
    for (int i = 0; i < N; i++) {
        memset(&receipts[i], 0, sizeof receipts[i]);
        receipts[i].seq = (uint64_t)i + 1;
        receipts[i].t_ns = 1000000ull * (uint64_t)i;
        receipts[i].policy_hash = 0x0123456789abcdefull ^ (uint64_t)i;
        receipts[i].prev_node = i % 5;
        receipts[i].event = i * 3;
        receipts[i].next_node = (i + 1) % 5;
        receipts[i].cause = i % 2;
        SHA256((const unsigned char *)&receipts[i], sizeof receipts[i], bytes[i]);
        leaves[i].bytes = bytes[i];
        leaves[i].len = 32;
    }
    uint8_t root[32], want[32], zero[32] = { 0 };
    merkle_root(receipts, 0, root);
    CHECK(memcmp(root, zero, 32) == 0, "no receipts gave a nonzero root");
    for (int n = 1; n <= N; n++) {
        merkle_root(receipts, n, root);
        ref_mth(leaves, (size_t)n, want);
        CHECK(memcmp(root, want, 32) == 0, "merkle_root differs from the tree at %d receipts", n);
    }
}

static void test_a_full_count_refuses(void) {
    struct ppt_merkle_acc acc;
    ppt_merkle_acc_init(&acc);
    acc.count = UINT64_MAX;
    for (int h = 0; h < PPT_MERKLE_MAX_PEAKS; h++) memset(acc.peaks[h], h, 32);
    uint8_t before[32], after[32];
    ppt_merkle_acc_root(&acc, before);
    CHECK(ppt_merkle_acc_add(&acc, "x", 1) == -1, "a full accumulator took a leaf");
    CHECK(acc.count == UINT64_MAX, "a refused add changed the count");
    ppt_merkle_acc_root(&acc, after);
    CHECK(memcmp(before, after, 32) == 0, "a refused add changed the root");
}

/* A reader for the one shape gen_merkle_stream_fixtures.py writes: each set has "leaves" (hex strings)
 * then "roots" (null or hex strings), json.dumps with sorted keys. */
static const char *skip_ws(const char *p) { while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t' || *p == ',') p++; return p; }

static int test_frozen_vectors(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *text = malloc((size_t)size + 1);
    if (!text || fread(text, 1, (size_t)size, f) != (size_t)size) { fclose(f); free(text); return -1; }
    text[size] = 0;
    fclose(f);

    int sets = 0, roots_checked = 0;
    const char *p = text;
    while ((p = strstr(p, "\"leaves\"")) != NULL) {
        enum { MAX = 4096 };
        static uint8_t buf[MAX][80];
        static size_t lens[MAX];
        size_t n = 0;
        p = strchr(p, '[');
        if (!p) break;
        p = skip_ws(p + 1);
        while (*p == '"') {
            const char *end = strchr(p + 1, '"');
            size_t chars = (size_t)(end - p - 1);
            CHECK(n < MAX && chars / 2 <= sizeof buf[0] && from_hex(p + 1, chars, buf[n]) == 0, "bad leaf in set %d", sets);
            lens[n++] = chars / 2;
            p = skip_ws(end + 1);
        }
        p = strstr(p, "\"roots\"");
        if (!p) break;
        p = skip_ws(strchr(p, '[') + 1);
        struct ppt_merkle_acc acc;
        ppt_merkle_acc_init(&acc);
        size_t count = 0;
        while (*p == '"' || *p == 'n') {
            uint8_t root[32];
            if (*p == 'n') {
                CHECK(count == 0 && ppt_merkle_acc_root(&acc, root) == 0, "null root after %zu leaves in set %d", count, sets);
                p = skip_ws(p + 4);
            } else {
                const char *end = strchr(p + 1, '"');
                uint8_t want[32];
                CHECK(count < n && (end - p - 1) == 64 && from_hex(p + 1, 64, want) == 0, "bad root in set %d", sets);
                ppt_merkle_acc_add(&acc, buf[count], lens[count]);
                count++;
                CHECK(ppt_merkle_acc_root(&acc, root) == 1 && memcmp(root, want, 32) == 0,
                      "set %d: root after %zu leaves differs from the Python reference", sets, count);
                roots_checked++;
                p = skip_ws(end + 1);
            }
        }
        CHECK(count == n, "set %d has %zu leaves and %zu roots", sets, n, count);
        sets++;
    }
    free(text);
    CHECK(sets == 3 && roots_checked == 8 + 300 + 70, "read %d sets and %d roots", sets, roots_checked);
    printf("  frozen vectors: %d sets, %d prefix roots equal to the Python reference\n", sets, roots_checked);
    return 0;
}

int main(int argc, char **argv) {
#ifdef TEST_EXTERNAL_SHA256
    printf("test_merkle (external SHA-256 backend)\n");
#else
    printf("test_merkle (OpenSSL SHA-256)\n");
#endif
    test_every_count_to_a_thousand();
    test_known_answer_vectors();
    test_batch_over_receipts();
    test_a_full_count_refuses();
    if (argc > 1 && test_frozen_vectors(argv[1]) != 0) g_failures++;
    printf("  state: %zu bytes (%d peaks of 32 bytes and a 64-bit count)\n", sizeof(struct ppt_merkle_acc), PPT_MERKLE_MAX_PEAKS);
    if (g_failures) { printf("FAILED: %d checks\n", g_failures); return 1; }
    printf("ok: every count 0..1000, the RFC 6962 known answers, the receipt batch%s\n",
           argc > 1 ? " and the frozen vectors" : "");
    return 0;
}

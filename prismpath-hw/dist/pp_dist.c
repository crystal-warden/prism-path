/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* pp_dist.c: the C core of policy distribution. See pp_dist.h. */
#include "pp_dist.h"

#include <string.h>

#include "monocypher-ed25519.h"
#include "pp_canon2.h"

/* ------------------------------------------------------------------ SHA-256 (FIPS 180-4) */

static const uint32_t pp_k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

#define PP_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void pp_sha256_block(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64], a, b, c, d, e, f, g, k;
    for (int t = 0; t < 16; t++)
        w[t] = (uint32_t)block[4 * t] << 24 | (uint32_t)block[4 * t + 1] << 16 | (uint32_t)block[4 * t + 2] << 8 |
               block[4 * t + 3];
    for (int t = 16; t < 64; t++) {
        uint32_t s0 = PP_ROR(w[t - 15], 7) ^ PP_ROR(w[t - 15], 18) ^ (w[t - 15] >> 3);
        uint32_t s1 = PP_ROR(w[t - 2], 17) ^ PP_ROR(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; k = h[7];
    for (int t = 0; t < 64; t++) {
        uint32_t t1 = k + (PP_ROR(e, 6) ^ PP_ROR(e, 11) ^ PP_ROR(e, 25)) + ((e & f) ^ (~e & g)) + pp_k256[t] + w[t];
        uint32_t t2 = (PP_ROR(a, 2) ^ PP_ROR(a, 13) ^ PP_ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
}

void pp_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t block[64];
    size_t i = 0;
    for (; i + 64 <= len; i += 64) pp_sha256_block(h, data + i);
    size_t rest = len - i;
    memset(block, 0, sizeof block);
    if (rest) memcpy(block, data + i, rest);
    block[rest] = 0x80;
    if (rest >= 56) {
        pp_sha256_block(h, block);
        memset(block, 0, sizeof block);
    }
    uint64_t bits = (uint64_t)len * 8;
    for (int b = 0; b < 8; b++) block[63 - b] = (uint8_t)(bits >> (8 * b));
    pp_sha256_block(h, block);
    for (int b = 0; b < 8; b++) {
        out[4 * b] = (uint8_t)(h[b] >> 24);
        out[4 * b + 1] = (uint8_t)(h[b] >> 16);
        out[4 * b + 2] = (uint8_t)(h[b] >> 8);
        out[4 * b + 3] = (uint8_t)h[b];
    }
}

/* ------------------------------------------------------------------ the kind table */

static const char *const pp_artifact_names[PP_ART_COUNT] = {
    "policy.core", "policy.ppt", "policy.spiral", "sandbox.profile", "egress.hosts", "gateway.routes",
    "net.dests", "net.edge", "cfs.table", "grant", "trust.widening", "trust.revocation", "trust.rotation"};
static const char *const pp_target_names[PP_TGT_COUNT] = {"agent", "cfs", "gateway", "host", "mesh", "xdp"};

const char *pp_artifact_name(pp_artifact artifact) {
    return (unsigned)artifact < PP_ART_COUNT ? pp_artifact_names[artifact] : NULL;
}

const char *pp_target_name(pp_target target) {
    return (unsigned)target < PP_TGT_COUNT ? pp_target_names[target] : NULL;
}

#define PP_BIT(kind) (1u << (kind))

/* A target row (kinds.TARGETS): what V5 admits, the trust kinds the machine applies, its body bound and its
 * own V11 check. This core has `mesh`. */
typedef struct {
    uint32_t uses;     /* a bit per pp_artifact */
    uint32_t applies;  /* the trust kinds its machine applies */
    long long body_bound;
    uint8_t (*check)(pp_artifact artifact, const uint8_t *body, size_t len);
} pp_row;

static int pp_is_trust(pp_artifact artifact) {
    return artifact == PP_ART_TRUST_WIDENING || artifact == PP_ART_TRUST_REVOCATION || artifact == PP_ART_TRUST_ROTATION;
}

static int pp_on_trust_stream(pp_artifact artifact) {
    return artifact == PP_ART_TRUST_REVOCATION || artifact == PP_ART_TRUST_ROTATION;
}

static uint8_t pp_read_widening(const uint8_t *body, size_t len);

/* `policy.ppt` on a mesh node: the node runs its own table parser and ignores `meta`, so the check is the image
 * check alone (kinds.check_mesh_table). A widening statement is read as its format (W4). */
static uint8_t pp_mesh_check(pp_artifact artifact, const uint8_t *body, size_t len) {
    if (artifact == PP_ART_POLICY_PPT) return pp_validate_image(body, len);
    if (artifact == PP_ART_TRUST_WIDENING) return pp_read_widening(body, len);
    return PP_CAUSE_TARGET_MISMATCH; /* unreachable: V5 admits nothing else */
}

static const pp_row *pp_row_of(pp_target kind) {
    static const pp_row mesh = {PP_BIT(PP_ART_POLICY_PPT), PP_BIT(PP_ART_TRUST_WIDENING), PP_MESH_TABLE_MAX, pp_mesh_check};
    return kind == PP_TGT_MESH ? &mesh : NULL;
}

/* ------------------------------------------------------------------ the sealed container (S2) */

uint8_t pp_unseal(const uint8_t *sealed, size_t len, const uint8_t **envelope, size_t *envelope_len,
                  pp_entry entries[PP_MAX_ENTRIES], size_t *n_entries) {
    if (len < 6 || len > PP_MAX_SEALED) return PP_CAUSE_BAD_FORMAT;
    if (memcmp(sealed, "PPDE", 4) != 0 || sealed[4] != 1) return PP_CAUSE_BAD_FORMAT;
    size_t count = sealed[5];
    if (count < 1 || count > PP_MAX_ENTRIES) return PP_CAUSE_BAD_FORMAT;
    size_t start = 6 + PP_ENTRY_SIZE * count;
    if (len < start + 2) return PP_CAUSE_BAD_FORMAT;
    size_t size = (size_t)sealed[start] | (size_t)sealed[start + 1] << 8;
    if (size < 1 || size > PP_MAX_ENVELOPE || len != start + 2 + size) return PP_CAUSE_BAD_FORMAT;
    for (size_t k = 0; k < count; k++) {
        memcpy(entries[k].key_id, sealed + 6 + PP_ENTRY_SIZE * k, 32);
        memcpy(entries[k].signature, sealed + 6 + PP_ENTRY_SIZE * k + 32, 64);
        if (k > 0 && memcmp(entries[k - 1].key_id, entries[k].key_id, 32) >= 0) return PP_CAUSE_BAD_FORMAT;
    }
    *envelope = sealed + start + 2;
    *envelope_len = size;
    *n_entries = count;
    return PP_CAUSE_NONE;
}

size_t pp_signed_message(const uint8_t *envelope, size_t len, uint8_t *out) {
    static const char head[] = "DSSEv1 35 application/vnd.prismpath.dist+json ";
    size_t at = sizeof head - 1;
    memcpy(out, head, at);
    char digits[8];
    size_t n = 0, v = len;
    do { digits[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (n) out[at++] = (uint8_t)digits[--n];
    out[at++] = ' ';
    memcpy(out + at, envelope, len);
    return at + len;
}

/* ------------------------------------------------------------------ the scanner (E1, E9) */

static int pp_hex_nibble(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* A string of 64 lower case hex digits at the cursor, into 32 bytes. */
static int pp_scan_hash(pp_c2 *c, uint8_t out[32]) {
    const uint8_t *s;
    size_t len;
    if (!pp_c2_plain_string(c, &s, &len) || len != 64) return 0;
    for (size_t k = 0; k < 32; k++) {
        int hi = pp_hex_nibble(s[2 * k]), lo = pp_hex_nibble(s[2 * k + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[k] = (uint8_t)(hi << 4 | lo);
    }
    return 1;
}

static int pp_is_stream(const uint8_t *s, size_t len) {
    if (len < 1 || len > PP_STREAM_MAX) return 0;
    for (size_t k = 0; k < len; k++) {
        uint8_t b = s[k];
        if (!((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '.' || b == '_' || b == '/' || b == '-')) return 0;
    }
    return 1;
}

static int pp_name_index(const uint8_t *s, size_t len, const char *const *names, int count) {
    for (int k = 0; k < count; k++)
        if (strlen(names[k]) == len && memcmp(names[k], s, len) == 0) return k;
    return -1;
}

static int pp_scan_int(pp_c2 *c, long long low, long long high, long long *out) {
    return pp_c2_int(c, out) && *out >= low && *out <= high;
}

static int pp_scan_fixed(pp_c2 *c, const char *text) {
    const uint8_t *s;
    size_t len;
    return pp_c2_plain_string(c, &s, &len) && strlen(text) == len && memcmp(s, text, len) == 0;
}

/* The members of the envelope in canonical order, on bytes pp_c2_check found canonical. */
static int pp_scan(pp_c2 *c, pp_envelope *e) {
    const uint8_t *s;
    size_t len;
    int depth;
    memset(e, 0, sizeof *e);
    if (!pp_c2_lit(c, "{\"artifact\":") || !pp_c2_plain_string(c, &s, &len)) return 0;
    int artifact = pp_name_index(s, len, pp_artifact_names, PP_ART_COUNT);
    if (artifact < 0) return 0; /* E8 */
    e->artifact = (pp_artifact)artifact;
    if (!pp_c2_lit(c, ",\"body_sha256\":") || !pp_scan_hash(c, e->body_sha256)) return 0;
    if (!pp_c2_lit(c, ",\"body_size\":") || !pp_scan_int(c, 0, PP_MAX_BODY, &e->body_size)) return 0;
    if (!pp_c2_lit(c, ",\"encoding\":") || !pp_scan_fixed(c, "canon/2")) return 0;
    if (!pp_c2_lit(c, ",\"expires\":") || !pp_scan_int(c, 0, PP_MAX_SEQ, &e->expires)) return 0;
    if (!pp_c2_lit(c, ",\"format\":") || !pp_scan_fixed(c, "prismpath.dist/1")) return 0;
    /* E9 as ruled: meta is an object, nests at most three levels, and ends inside the envelope */
    if (!pp_c2_lit(c, ",\"meta\":") || c->i >= c->n || c->p[c->i] != '{' || !pp_c2_skip(c, &depth) ||
        depth > PP_META_MAX_DEPTH)
        return 0;
    if (!pp_c2_lit(c, ",\"not_before\":") || !pp_scan_int(c, 0, PP_MAX_SEQ, &e->not_before)) return 0;
    if (!pp_c2_lit(c, ",\"policy_sha256\":") || !pp_scan_hash(c, e->policy_sha256)) return 0;
    if (!pp_c2_lit(c, ",\"release\":") || !pp_scan_hash(c, e->release)) return 0;
    if (!pp_c2_lit(c, ",\"replaces\":")) return 0;
    if (pp_c2_lit(c, "\"\"")) e->has_replaces = 0;
    else if (pp_scan_hash(c, e->replaces)) e->has_replaces = 1;
    else return 0;
    if (!pp_c2_lit(c, ",\"seq\":") || !pp_scan_int(c, 1, PP_MAX_SEQ, &e->seq)) return 0;
    if (!pp_c2_lit(c, ",\"stream\":") || !pp_c2_plain_string(c, &s, &len)) return 0;
    if (!(pp_is_stream(s, len) || (len == 6 && memcmp(s, "@trust", 6) == 0))) return 0;
    memcpy(e->stream, s, len);
    e->stream[len] = 0;
    if (!pp_c2_lit(c, ",\"targets\":[")) return 0;
    int last = -1;
    for (;;) {
        if (!pp_c2_plain_string(c, &s, &len)) return 0;
        int target = pp_name_index(s, len, pp_target_names, PP_TGT_COUNT);
        if (target <= last) return 0; /* unknown (E8), unsorted or repeated; the names are in sorted order */
        e->targets |= PP_BIT(target);
        last = target;
        if (pp_c2_lit(c, "]")) break;
        if (!pp_c2_lit(c, ",")) return 0;
    }
    if (!pp_c2_lit(c, ",\"widens\":")) return 0;
    if (pp_c2_lit(c, "true")) e->widens = 1;
    else if (!pp_c2_lit(c, "false")) return 0;
    return pp_c2_lit(c, "}") && c->i == c->n;
}

static const uint8_t pp_zero32[32];

uint8_t pp_read_envelope(const uint8_t *bytes, size_t len, pp_envelope *out) {
    if (len < 1 || len > PP_MAX_ENVELOPE) return PP_CAUSE_BAD_FORMAT;
    int form = pp_c2_check(bytes, len); /* E2: the reference reads the document before its members */
    if (form == PP_C2_NOT_CANONICAL) return PP_CAUSE_NOT_CANONICAL;
    if (form != PP_C2_OK) return PP_CAUSE_BAD_FORMAT;
    pp_c2 c = {bytes, len, 0, 1};
    if (!pp_scan(&c, out)) return PP_CAUSE_BAD_FORMAT;
    if (strcmp(out->stream, "@trust") == 0 &&
        (memcmp(out->policy_sha256, pp_zero32, 32) != 0 || memcmp(out->release, pp_zero32, 32) != 0))
        return PP_CAUSE_BAD_FORMAT;
    if (pp_is_trust(out->artifact) ? out->expires != 0 : out->expires <= out->not_before) return PP_CAUSE_BAD_FORMAT; /* E5 */
    pp_sha256(bytes, len, out->envelope_id);
    return PP_CAUSE_NONE;
}

/* W4: a widening statement, `from` a sorted list of hashes without repeats, as canonical canon/2. */
static uint8_t pp_read_widening(const uint8_t *body, size_t len) {
    int form = pp_c2_check(body, len);
    if (form == PP_C2_NOT_CANONICAL) return PP_CAUSE_NOT_CANONICAL;
    if (form != PP_C2_OK) return PP_CAUSE_BAD_FORMAT;
    pp_c2 c = {body, len, 0, 1};
    uint8_t last[32], hash[32];
    int have = 0;
    if (!pp_c2_lit(&c, "{\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-widening/1\",\"from\":["))
        return PP_CAUSE_BAD_FORMAT;
    if (!pp_c2_lit(&c, "]")) {
        for (;;) {
            if (!pp_scan_hash(&c, hash) || (have && memcmp(last, hash, 32) >= 0)) return PP_CAUSE_BAD_FORMAT;
            memcpy(last, hash, 32);
            have = 1;
            if (pp_c2_lit(&c, "]")) break;
            if (!pp_c2_lit(&c, ",")) return PP_CAUSE_BAD_FORMAT;
        }
    }
    return pp_c2_lit(&c, "}") && c.i == c.n ? PP_CAUSE_NONE : PP_CAUSE_BAD_FORMAT;
}

/* ------------------------------------------------------------------ the trust store (S3 to S5) */

static int pp_listed(const uint8_t (*list)[32], size_t n, const uint8_t id[32]) {
    for (size_t k = 0; k < n; k++)
        if (memcmp(list[k], id, 32) == 0) return 1;
    return 0;
}

uint8_t pp_counting(const pp_trust *trust, const pp_entry *entries, size_t n_entries, const uint8_t *message,
                    size_t message_len) {
    if (!trust->readable) return PP_CAUSE_UNKNOWN_KEY;
    size_t counting = 0;
    int revoked_verifies = 0, held_fails = 0;
    for (size_t k = 0; k < n_entries; k++) {
        const pp_key *key = NULL;
        for (size_t j = 0; j < trust->n_keys; j++)
            if (memcmp(trust->keys[j].id, entries[k].key_id, 32) == 0) key = &trust->keys[j];
        if (key == NULL) continue;
        if (crypto_ed25519_check(entries[k].signature, key->public_key, message, message_len) != 0) {
            held_fails = 1;
            continue;
        }
        if (pp_listed(trust->retired, trust->n_retired, key->id) ||
            pp_listed(trust->revoked_keys, trust->n_revoked_keys, key->id))
            revoked_verifies = 1;
        else if (key->role == PP_ROLE_AUTHORITY)
            counting++;
    }
    if (counting >= 1) return PP_CAUSE_NONE; /* S6: the threshold is 1 */
    if (revoked_verifies) return PP_CAUSE_SIG_REVOKED_KEY;
    return held_fails ? PP_CAUSE_SIG_INVALID : PP_CAUSE_UNKNOWN_KEY;
}

/* ------------------------------------------------------------------ the image check */

static uint16_t pp_u16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }

uint8_t pp_validate_image(const uint8_t *im, size_t len) {
    if (len < 28) return PP_CAUSE_IMAGE_TRUNCATED_HEADER;
    if (!(im[0] == 'P' && im[1] == 'P' && im[2] == 'T' && im[3] == 'M')) return PP_CAUSE_IMAGE_BAD_MAGIC;
    if (pp_u16(im + 4) != 1) return PP_CAUSE_IMAGE_BAD_VERSION;
    uint16_t fields = pp_u16(im + 6), atoms = pp_u16(im + 10), nodes = pp_u16(im + 12), edges = pp_u16(im + 14),
             words = pp_u16(im + 16);
    uint8_t flags = im[26], safe_node = im[27];
    uint8_t first = PP_CAUSE_NONE;
#define PP_FIRST(cause) do { if (first == PP_CAUSE_NONE) first = (cause); } while (0)
    if (safe_node && safe_node >= nodes) PP_FIRST(PP_CAUSE_IMAGE_SAFE_NODE_OOB);
    size_t need = 28 + 8u * atoms + 4u * nodes + 6u * edges + 2u * words;
    if (flags & 0x01) need += 2u * nodes;
    if (flags & 0x04) need += 4u * nodes;
    if (len != need) {
        PP_FIRST(PP_CAUSE_IMAGE_LENGTH_MISMATCH);
        return first;
    }
    size_t off = 28;
    for (uint16_t k = 0; k < atoms; k++, off += 8) {
        if (im[off + 2] > 6) PP_FIRST(PP_CAUSE_IMAGE_UNKNOWN_OP);
        if (im[off + 3] > 3) PP_FIRST(PP_CAUSE_IMAGE_UNKNOWN_TYPE);
        if (pp_u16(im + off) >= fields) PP_FIRST(PP_CAUSE_IMAGE_FIELD_INDEX_OOB);
    }
    off += 4u * nodes;
    for (uint16_t k = 0; k < edges; k++, off += 6) {
        if (pp_u16(im + off) >= nodes) PP_FIRST(PP_CAUSE_IMAGE_EDGE_TARGET_OOB);
        if ((uint32_t)pp_u16(im + off + 2) + pp_u16(im + off + 4) > words) PP_FIRST(PP_CAUSE_IMAGE_EDGE_PROG_OOB);
    }
    for (uint16_t k = 0; k < words; k++, off += 2) {
        uint16_t word = pp_u16(im + off);
        if (word >= 0x8000 && word > 0x8004) PP_FIRST(PP_CAUSE_IMAGE_UNKNOWN_OPCODE);
        if (word < 0x8000 && word >= atoms) PP_FIRST(PP_CAUSE_IMAGE_ATOM_INDEX_OOB);
    }
    if (flags & 0x01)
        for (uint16_t k = 0; k < nodes; k++, off += 2)
            if (pp_u16(im + off) > 0x3F) PP_FIRST(PP_CAUSE_IMAGE_NODE_ATTR_OOB);
#undef PP_FIRST
    return first;
}

/* ------------------------------------------------------------------ the verifier (V2 to V11) */

static long long pp_raised(const pp_trust *trust, const char *stream) {
    for (size_t k = 0; k < trust->n_floors; k++)
        if (strcmp(trust->floors[k].stream, stream) == 0) return trust->floors[k].seq;
    return 0;
}

/* V8: 0 to go on, else the cause; *unchanged for an envelope at its floor that changes nothing. */
static uint8_t pp_floor_check(const pp_envelope *e, const pp_trust *trust, const pp_pep *pep, int *unchanged) {
    *unchanged = 0;
    if (pp_on_trust_stream(e->artifact)) { /* R1, O1: one trust sequence, no step skipped */
        if (e->seq == trust->trust_seq + 1) return PP_CAUSE_NONE;
        if (e->seq == trust->trust_seq && trust->has_trust_id && memcmp(trust->trust_id, e->envelope_id, 32) == 0) {
            *unchanged = 1;
            return PP_CAUSE_NONE;
        }
        return PP_CAUSE_TRUST_REPLAY;
    }
    long long raised = pp_raised(trust, e->stream);
    long long floor = pep->floor_seq > raised ? pep->floor_seq : raised; /* Q2, Q3, and R4's raised floor */
    if (e->seq > floor) return PP_CAUSE_NONE;
    if (e->seq == pep->floor_seq && pep->floor_seq == floor &&
        pp_listed(pep->floor_ids, pep->n_floor_ids, e->envelope_id)) {
        *unchanged = 1;
        return PP_CAUSE_NONE;
    }
    return PP_CAUSE_SEQ_REPLAY;
}

static int pp_same(const uint8_t a[32], int has_a, const uint8_t b[32], int has_b) {
    return has_a == has_b && (!has_a || memcmp(a, b, 32) == 0);
}

void pp_verify(const uint8_t *sealed, size_t sealed_len, const uint8_t *body, size_t body_len,
               const pp_trust *trust, const pp_pep *pep, long long now, pp_verdict *out) {
    static uint8_t message[PP_MAX_ENVELOPE + 64];
    memset(out, 0, sizeof *out);
    const pp_row *row = pp_row_of(pep->kind);
    if (row == NULL) { out->cause = PP_CAUSE_TARGET_MISMATCH; return; } /* no PEP of an unbuilt kind */
    /* V2: the container reads, and the body fits the bounds (B9) */
    const uint8_t *envelope;
    size_t envelope_len, n_entries;
    pp_entry entries[PP_MAX_ENTRIES];
    if ((out->cause = pp_unseal(sealed, sealed_len, &envelope, &envelope_len, entries, &n_entries))) return;
    long long bound = pep->body_bound < row->body_bound ? pep->body_bound : row->body_bound;
    if ((long long)body_len > bound) { out->cause = PP_CAUSE_TOO_LARGE; return; }
    /* V3: the signatures, over the bytes as they came and before the scanner reads them (E9) */
    size_t message_len = pp_signed_message(envelope, envelope_len, message);
    if ((out->cause = pp_counting(trust, entries, n_entries, message, message_len))) return;
    /* V4: the envelope reads */
    pp_envelope *e = &out->envelope;
    if ((out->cause = pp_read_envelope(envelope, envelope_len, e))) return;
    out->has_envelope = 1;
    /* V5: for this kind, an artifact it uses or a trust kind it applies, on its stream or `@trust` */
    const char *stream = pp_on_trust_stream(e->artifact) ? "@trust" : pep->stream;
    if (!(e->targets & PP_BIT(pep->kind)) || strcmp(e->stream, stream) != 0 ||
        !((row->uses | row->applies) & PP_BIT(e->artifact))) {
        out->cause = PP_CAUSE_TARGET_MISMATCH;
        return;
    }
    /* V6: time, against the larger of the clock and the time floor (T1, T3, T4; X4) */
    long long time = now > trust->time_floor ? now : trust->time_floor;
    if (pep->has_clock && e->not_before - time > PP_SKEW) { out->cause = PP_CAUSE_NOT_YET_VALID; return; }
    if (e->expires && time >= e->expires) { out->cause = PP_CAUSE_EXPIRED; return; }
    out->has_time_floor = 1; /* V13 */
    out->time_floor = trust->time_floor > e->not_before ? trust->time_floor : e->not_before;
    /* V7: revocation */
    if (pp_listed(trust->revoked_envelopes, trust->n_revoked_envelopes, e->envelope_id) ||
        pp_listed(trust->revoked_policies, trust->n_revoked_policies, e->policy_sha256)) {
        out->cause = PP_CAUSE_REVOKED;
        return;
    }
    /* V8: the sequence */
    if ((out->cause = pp_floor_check(e, trust, pep, &out->unchanged)) || out->unchanged) return;
    /* V9: the body */
    uint8_t hash[32];
    pp_sha256(body, body_len, hash);
    if ((long long)body_len != e->body_size || memcmp(hash, e->body_sha256, 32) != 0) {
        out->cause = PP_CAUSE_BODY_MISMATCH;
        return;
    }
    /* V10: the release already staged at this seq agrees (E7) */
    const pp_staged *st = &pep->staged;
    if (!pp_on_trust_stream(e->artifact) && pep->has_staged && strcmp(st->stream, e->stream) == 0 && st->seq == e->seq &&
        !(memcmp(st->policy_sha256, e->policy_sha256, 32) == 0 && memcmp(st->release, e->release, 32) == 0 &&
          pp_same(st->replaces, st->has_replaces, e->replaces, e->has_replaces) && st->widens == e->widens)) {
        out->cause = PP_CAUSE_INCOMPLETE;
        return;
    }
    /* V11: the artifact's own check on this kind */
    out->cause = row->check(e->artifact, body, body_len);
}

/* ------------------------------------------------------------------ the frame binding (B6, B7, B9, B11) */

static uint32_t pp_u32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

void pp_assembler_init(pp_assembler *a, pp_admit_fn admit, void *context, int ordered, size_t limit,
                       long long body_bound) {
    memset(a, 0, sizeof *a);
    a->admit = admit;
    a->context = context;
    a->ordered = ordered;
    a->limit = limit;
    a->body_bound = body_bound;
}

/* The frame layouts of section 8.3: 0 when `frame` is one, else PP_CAUSE_FRAME_INVALID (frames.decode). */
static uint8_t pp_frame_reads(const uint8_t *f, size_t len, size_t limit) {
    if (len < 4 || len > limit || f[1] != 1) return PP_CAUSE_FRAME_INVALID;
    switch (f[0]) {
    case PP_FRAME_OFFER: return len == 26 ? 0 : PP_CAUSE_FRAME_INVALID;
    case PP_FRAME_CHUNK:
        if (len < 11 || (f[4] != 0 && f[4] != 1) || len != 11u + pp_u16(f + 9)) return PP_CAUSE_FRAME_INVALID;
        return 0;
    case PP_FRAME_STATE: return 0;
    case PP_FRAME_COMMIT:
    case PP_FRAME_ABORT: {
        size_t want = f[0] == PP_FRAME_COMMIT ? 46 : 44;
        if (len != want) return PP_CAUSE_FRAME_INVALID;
        uint64_t seq = 0;
        for (int k = 7; k >= 0; k--) seq = seq << 8 | f[20 + k];
        return seq <= (uint64_t)PP_MAX_SEQ ? 0 : PP_CAUSE_FRAME_INVALID;
    }
    case PP_FRAME_EPOCH: return len == 12 ? 0 : PP_CAUSE_FRAME_INVALID;
    default: return PP_CAUSE_FRAME_INVALID;
    }
}

/* Write `data` at `offset` of a part, counting the bytes that arrive for the first time. */
static uint8_t pp_part_put(uint8_t *buf, uint8_t *have, size_t part_len, size_t *missing, size_t *next, int ordered,
                           size_t offset, const uint8_t *data, size_t n) {
    if (offset + n > part_len) return PP_CAUSE_FRAME_INVALID; /* B6 */
    if (ordered && offset != *next) return PP_CAUSE_FRAME_INVALID; /* B11 */
    memcpy(buf + offset, data, n);
    for (size_t k = offset; k < offset + n; k++)
        if (!have[k]) { have[k] = 1; (*missing)--; }
    *next = offset + n;
    return 0;
}

static int pp_drop(pp_assembler *a, uint16_t transfer, uint8_t why, uint8_t *cause) {
    if (a->t.active && a->t.transfer == transfer) a->t.active = 0;
    *cause = why;
    return PP_ASM_DROPPED;
}

static int pp_body_whole(pp_assembler *a, uint16_t transfer, uint8_t *cause) {
    pp_transfer *t = &a->t;
    if (!t->body_open || t->body_missing) return PP_ASM_NONE;
    uint8_t hash[32];
    pp_sha256(t->body, t->body_len, hash);
    if (memcmp(hash, t->body_sha256, 32) != 0) return pp_drop(a, transfer, PP_CAUSE_FRAME_INVALID, cause); /* B6 */
    t->active = 0; /* the parts stay in the buffers for the caller to verify and stage */
    return PP_ASM_WHOLE;
}

int pp_assembler_receive(pp_assembler *a, const uint8_t *f, size_t len, uint32_t now_ms, uint8_t *cause) {
    pp_transfer *t = &a->t;
    *cause = 0;
    if ((*cause = pp_frame_reads(f, len, a->limit))) return PP_ASM_DROPPED;
    if (t->active && now_ms - t->started_ms > PP_TRANSFER_TIMEOUT_MS) t->active = 0; /* B7: dropped silently */
    uint16_t transfer = pp_u16(f + 2);
    if (f[0] == PP_FRAME_OFFER) {
        size_t sealed_len = pp_u16(f + 20), body_len = pp_u32(f + 22);
        if (t->active && t->transfer == transfer && memcmp(t->envelope_prefix, f + 4, 16) == 0 &&
            t->sealed_len == sealed_len && t->body_len == body_len)
            return PP_ASM_NONE; /* a repeated offer */
        if (sealed_len < 1 || sealed_len > PP_MAX_SEALED) return pp_drop(a, transfer, PP_CAUSE_FRAME_INVALID, cause);
        if ((long long)body_len > a->body_bound) return pp_drop(a, transfer, PP_CAUSE_TOO_LARGE, cause);
        if (body_len > PP_ASSEMBLER_BODY_MAX) return pp_drop(a, transfer, PP_CAUSE_TOO_LARGE, cause);
        memset(t, 0, sizeof *t);
        t->active = 1;
        t->transfer = transfer;
        memcpy(t->envelope_prefix, f + 4, 16);
        t->sealed_len = t->sealed_missing = sealed_len;
        t->body_len = body_len;
        t->started_ms = now_ms;
        return PP_ASM_NONE;
    }
    if (f[0] != PP_FRAME_CHUNK) return PP_ASM_CONTROL;
    if (!t->active || t->transfer != transfer) { *cause = PP_CAUSE_FRAME_INVALID; return PP_ASM_DROPPED; } /* no offer */
    size_t offset = pp_u32(f + 5), n = pp_u16(f + 9);
    const uint8_t *data = f + 11;
    uint8_t why;
    if (f[4] == 1) {
        if (!t->body_open) return PP_ASM_NONE; /* B9: no body is read before the envelope is admitted */
        if ((why = pp_part_put(t->body, t->body_have, t->body_len, &t->body_missing, &t->body_next, a->ordered, offset,
                               data, n)))
            return pp_drop(a, transfer, why, cause);
        return pp_body_whole(a, transfer, cause);
    }
    if (t->body_open) return PP_ASM_NONE; /* a repeat of a part already whole and admitted */
    if ((why = pp_part_put(t->sealed, t->sealed_have, t->sealed_len, &t->sealed_missing, &t->sealed_next, a->ordered,
                           offset, data, n)))
        return pp_drop(a, transfer, why, cause);
    if (t->sealed_missing) return PP_ASM_NONE;
    const uint8_t *envelope;
    size_t envelope_len, n_entries;
    pp_entry entries[PP_MAX_ENTRIES];
    uint8_t id[32];
    if (pp_unseal(t->sealed, t->sealed_len, &envelope, &envelope_len, entries, &n_entries))
        return pp_drop(a, transfer, PP_CAUSE_FRAME_INVALID, cause);
    pp_sha256(envelope, envelope_len, id);
    if (memcmp(id, t->envelope_prefix, 16) != 0) return pp_drop(a, transfer, PP_CAUSE_FRAME_INVALID, cause); /* B6 */
    long long body_size = 0;
    if ((why = a->admit(a->context, t->sealed, t->sealed_len, &body_size, t->body_sha256)))
        return pp_drop(a, transfer, why, cause);
    if ((size_t)body_size != t->body_len) return pp_drop(a, transfer, PP_CAUSE_FRAME_INVALID, cause);
    t->body_open = 1;
    t->body_missing = t->body_len;
    return pp_body_whole(a, transfer, cause);
}

/* ------------------------------------------------------------------ the state record (H1) */

static void pp_le64(uint8_t *p, uint64_t v) {
    for (int k = 0; k < 8; k++) p[k] = (uint8_t)(v >> (8 * k));
}

static void pp_prefix(uint8_t *out, const uint8_t hash[32], int present) {
    if (present) memcpy(out, hash, 16);
    else memset(out, 0, 16);
}

static long long pp_time(const pp_pep_machine *pep) {
    long long floor = pep->d.trust_reads ? pep->d.trust.time_floor : 0;
    return pep->now > floor ? pep->now : floor; /* T1 */
}

static int pp_state(const pp_pep_machine *pep) {
    if (pep->locked) return PP_ST_LOCKED;
    return pep->d.has_active && pep->d.trust_reads ? PP_ST_ACTIVE : PP_ST_NO_POLICY;
}

static void pp_persist(pp_pep_machine *pep) {
    if (pep->config.persist) pep->config.persist(pep->config.context, &pep->d);
}

/* Make one signed record, its counter durable first (H3), and put it in the outbox. */
static void pp_emit(pp_pep_machine *pep, uint8_t event, uint8_t cause) {
    static const char head[] = "DSSEv1 36 application/vnd.prismpath.dist-state ";
    uint8_t r[PP_RECORD_MAX], message[sizeof head + 8 + 148];
    pep->d.counter++;
    if (pep->d.provisioned) {
        pep->d.counter_reads = 1;
        pp_persist(pep);
    }
    const pp_durable *d = &pep->d;
    uint8_t stream_hash[32];
    pp_sha256((const uint8_t *)pep->d.stream, strlen(pep->d.stream), stream_hash);
    memcpy(r, "PPSR", 4);
    r[4] = 1;
    r[5] = event;
    r[6] = (uint8_t)(pp_state(pep) | (d->has_staged ? 0x80 : 0) | (pep->held ? 0x20 : 0)
#ifdef PPT_DEV_BUILD
                     | 0x40
#endif
    );
    r[7] = cause;
    uint8_t digest[32];
    pp_sha256(pep->instance_public, 32, digest);
    memcpy(r + 8, digest, 16);
    pp_le64(r + 24, d->counter);
    pp_le64(r + 32, (uint64_t)pp_time(pep));
    pp_le64(r + 40, pep->epoch);
    memcpy(r + 48, stream_hash, 16);
    pp_prefix(r + 64, d->active.policy_sha256, d->has_active);
    pp_prefix(r + 80, d->active.release, d->has_active);
    pp_le64(r + 96, (uint64_t)(d->has_active ? d->active.seq : 0));
    pp_le64(r + 104, (uint64_t)d->floor_seq);
    pp_prefix(r + 112, d->staged.release, d->has_staged);
    pp_le64(r + 128, (uint64_t)(d->has_staged ? d->staged.seq : 0));
    pp_le64(r + 136, (uint64_t)(d->trust_reads ? d->trust.trust_seq : 0));
    r[144] = r[145] = r[146] = r[147] = 0; /* no Facet body on mesh and cfs (H5), no extension (H10) */
    size_t at = sizeof head - 1;
    memcpy(message, head, at);
    memcpy(message + at, "148 ", 4);
    memcpy(message + at + 4, r, 148);
    crypto_ed25519_sign(r + 148, pep->instance_secret, message, at + 4 + 148);
    if (pep->n_out < PP_OUTBOX) {
        memcpy(pep->out[pep->n_out], r, PP_RECORD_MAX);
        pep->out_len[pep->n_out++] = PP_RECORD_MAX;
    }
}

/* ------------------------------------------------------------------ the machine (pep.py) */

/* A stream name into a buffer of PP_STREAM_MAX + 1 bytes, cut at the bound. */
static void pp_copy_stream(char *out, const char *stream) {
    size_t n = strlen(stream);
    if (n > PP_STREAM_MAX) n = PP_STREAM_MAX;
    memcpy(out, stream, n);
    out[n] = 0;
}

static void pp_runtime(pp_pep_machine *pep) {
    if (pep->config.runtime)
        pep->config.runtime(pep->config.context, pp_state(pep) == PP_ST_ACTIVE ? &pep->d.active : NULL);
}

static int pp_names(const pp_release *r, const char *stream, long long seq, const uint8_t policy[32]) {
    return strcmp(r->stream, stream) == 0 && r->seq == seq && memcmp(r->policy_sha256, policy, 32) == 0;
}

/* C3, RB2: time (T3 when `early`, T4) and revocation (V7) again for every envelope of `release`. */
static uint8_t pp_still_valid(const pp_pep_machine *pep, const pp_release *release, int early) {
    long long time = pp_time(pep);
    const pp_trust *t = &pep->d.trust;
    for (size_t k = 0; k < release->n; k++) {
        const pp_envelope *e = &release->held[k].envelope;
        if (early && pep->config.has_clock && e->not_before - time > PP_SKEW) return PP_CAUSE_NOT_YET_VALID;
        if (e->expires && time >= e->expires) return PP_CAUSE_EXPIRED;
        if (pp_listed(t->revoked_envelopes, t->n_revoked_envelopes, e->envelope_id) ||
            pp_listed(t->revoked_policies, t->n_revoked_policies, e->policy_sha256))
            return PP_CAUSE_REVOKED;
    }
    return PP_CAUSE_NONE;
}

static void pp_lapse(pp_pep_machine *pep, uint8_t cause) {
    pep->d.has_active = 0;
    pep->held = 0;
    pp_persist(pep);
    pp_runtime(pep);
    pp_emit(pep, PP_EV_LAPSED, cause);
}

/* X1, X6, X7: an active release past its expiry lapses, or under HOLD is held. */
static void pp_check_expiry(pp_pep_machine *pep) {
    if (!pep->d.has_active || pep->locked || !pep->d.trust_reads) return;
    if (pp_still_valid(pep, &pep->d.active, 0) != PP_CAUSE_EXPIRED) return;
    if (pep->config.expiry_hold) {
        if (pep->held) return;
        pep->held = 1;
        pp_emit(pep, PP_EV_HELD, PP_CAUSE_HELD);
        return;
    }
    pp_lapse(pep, PP_CAUSE_EXPIRED);
}

static void pp_begin(pp_pep_machine *pep, long long now) {
    pep->now = now;
    pep->n_out = 0;
    pp_check_expiry(pep);
}

/* C4: intent, floor (a commit only), the active record, the runtime, the clean up, each persisted. */
static void pp_flip(pp_pep_machine *pep, int rollback, const pp_release *release, const pp_release *previous) {
    pp_durable *d = &pep->d;
    d->pending = *release;
    d->has_pending = 1;
    d->pending_rollback = rollback;
    pp_persist(pep);
    if (!rollback) {
        d->floor_seq = release->seq;
        d->n_floor_ids = release->n;
        for (size_t k = 0; k < release->n; k++) memcpy(d->floor_ids[k], release->held[k].envelope.envelope_id, 32);
        pp_persist(pep);
    }
    pp_release next = *release;
    d->has_previous = previous != NULL;
    if (previous) d->previous = *previous;
    d->active = next;
    d->has_active = 1;
    pep->held = 0;
    if (d->has_staged && d->staged.seq <= next.seq) d->has_staged = 0;
    pp_persist(pep);
    pp_runtime(pep);
    d->has_pending = 0;
    pp_persist(pep);
    pp_emit(pep, rollback ? PP_EV_ROLLED_BACK : PP_EV_COMMITTED, 0);
}

int pp_pep_open(pp_pep_machine *pep, const pp_config *config, const pp_durable *durable, long long now) {
    memset(pep, 0, sizeof *pep);
    pep->config = *config;
    pep->now = now;
    if (pp_row_of(config->kind) == NULL) return -1;
    if (config->expiry_hold && config->kind != PP_TGT_MESH && config->kind != PP_TGT_CFS) return -1; /* X6 */
    crypto_ed25519_key_pair(pep->instance_secret, pep->instance_public, pep->config.instance_seed);
    if (durable == NULL || !durable->provisioned) {
        pep->d.trust_reads = 0;
        return 0; /* P1: nothing to believe yet */
    }
    pep->d = *durable;
    if (!pep->d.counter_reads) {
        /* a counter that cannot be read never repeats: the PEP locks and counts on from its time in microseconds */
        pep->d.counter = (uint64_t)pp_time(pep) * 1000000u;
        pep->locked = 1;
    }
    pep->d.trust.readable = pep->d.trust_reads;
    if (!pep->d.floor_reads) { /* Q5: a floor that cannot be read is none, and the PEP is locked */
        pep->locked = 1;
        pep->d.floor_seq = 0;
        pep->d.n_floor_ids = 0;
    }
    if (pep->locked) pep->d.has_active = pep->d.has_previous = pep->d.has_staged = pep->d.has_pending = 0;
    if (!pep->d.setting_reads) pep->locked = 1;
    else if (pep->d.expiry_hold != config->expiry_hold) return -1; /* X10 */
    uint8_t id[32];
    pp_sha256(pep->instance_public, 32, id);
    for (size_t k = 0; k < pep->d.trust.n_keys; k++)
        if (memcmp(pep->d.trust.keys[k].id, id, 32) == 0) return -1; /* K2 */
    if (pep->d.has_pending) { /* C4: finish or report an interrupted commit */
        pep->d.has_pending = 0;
        pp_persist(pep);
    }
    pp_runtime(pep);
    pep->n_out = 0;
    pp_check_expiry(pep);
    return 0;
}

void pp_pep_provision(pp_pep_machine *pep, const pp_trust *anchor, const char *stream, long long now) {
    pep->now = now;
    pep->n_out = 0;
    pp_durable *d = &pep->d;
    uint64_t counter = d->counter;
    memset(d, 0, sizeof *d);
    d->provisioned = d->setting_reads = d->trust_reads = d->floor_reads = d->counter_reads = 1;
    d->expiry_hold = pep->config.expiry_hold;
    d->trust = *anchor;
    d->trust.readable = 1;
    d->trust.trust_seq = 0;
    d->trust.time_floor = 0;
    pp_copy_stream(d->stream, stream);
    d->counter = counter;
    pep->locked = pep->held = 0;
    pep->commit_due = 0;
    pp_runtime(pep);
    pp_persist(pep);
    pp_emit(pep, PP_EV_PROVISIONED, 0);
}

static void pp_refuse(pp_pep_machine *pep, uint8_t cause) {
    pp_emit(pep, PP_EV_REFUSED, cause);
}

void pp_pep_stage(pp_pep_machine *pep, const uint8_t *sealed, size_t sealed_len, const uint8_t *body, size_t body_len,
                  long long now) {
    pp_begin(pep, now);
    pp_durable *d = &pep->d;
    if (pep->locked) { pp_refuse(pep, PP_CAUSE_FLOOR_LOST); return; }
    if (!d->provisioned) { pp_refuse(pep, PP_CAUSE_UNKNOWN_KEY); return; }
    static pp_pep view;
    static pp_verdict verdict;
    memset(&view, 0, sizeof view);
    view.kind = pep->config.kind;
    pp_copy_stream(view.stream, d->stream);
    view.floor_seq = d->floor_seq;
    view.n_floor_ids = d->n_floor_ids;
    memcpy(view.floor_ids, d->floor_ids, sizeof view.floor_ids);
    view.body_bound = PP_MAX_BODY;
    view.has_clock = pep->config.has_clock;
    if (d->has_staged) {
        view.has_staged = 1;
        pp_copy_stream(view.staged.stream, d->staged.stream);
        view.staged.seq = d->staged.seq;
        memcpy(view.staged.policy_sha256, d->staged.policy_sha256, 32);
        memcpy(view.staged.release, d->staged.release, 32);
        memcpy(view.staged.replaces, d->staged.replaces, 32);
        view.staged.has_replaces = d->staged.has_replaces;
        view.staged.widens = d->staged.widens;
    }
    pp_verify(sealed, sealed_len, body, body_len, &d->trust, &view, now, &verdict);
    if (verdict.has_time_floor && d->trust_reads && verdict.time_floor > d->trust.time_floor) {
        d->trust.time_floor = verdict.time_floor; /* V13, T1 */
        pp_persist(pep);
    }
    if (verdict.cause) { pp_refuse(pep, verdict.cause); return; }
    if (verdict.unchanged) { pp_emit(pep, PP_EV_BEAT, 0); return; } /* Q3 */
    const pp_envelope *e = &verdict.envelope;
    if (d->has_staged && strcmp(d->staged.stream, e->stream) == 0 && e->seq < d->staged.seq) {
        pp_refuse(pep, PP_CAUSE_SEQ_REPLAY); /* G2 */
        return;
    }
    if (!d->has_staged || d->staged.seq != e->seq) {
        memset(&d->staged, 0, sizeof d->staged);
        pp_copy_stream(d->staged.stream, e->stream);
        d->staged.seq = e->seq;
        memcpy(d->staged.policy_sha256, e->policy_sha256, 32);
        memcpy(d->staged.release, e->release, 32);
        memcpy(d->staged.replaces, e->replaces, 32);
        d->staged.has_replaces = e->has_replaces;
        d->staged.widens = e->widens;
        d->has_staged = 1;
    }
    size_t slot = d->staged.n;
    for (size_t k = 0; k < d->staged.n; k++)
        if (d->staged.held[k].envelope.artifact == e->artifact) slot = k;
    if (slot == d->staged.n) d->staged.n++;
    d->staged.held[slot].envelope = *e;
    d->staged.held[slot].body_len = body_len;
    memcpy(d->staged.held[slot].body, body, body_len); /* V2 held the body to the kind's bound */
    pp_persist(pep);
    pp_emit(pep, PP_EV_STAGED, 0);
}

static void pp_commit_now(pp_pep_machine *pep, const char *stream, long long seq, const uint8_t policy[32]) {
    pp_durable *d = &pep->d;
    if (pep->locked) { pp_refuse(pep, PP_CAUSE_FLOOR_LOST); return; }
    if (!d->trust_reads) { pp_refuse(pep, PP_CAUSE_UNKNOWN_KEY); return; }
    if (!d->has_staged || !pp_names(&d->staged, stream, seq, policy)) { pp_emit(pep, PP_EV_REFUSED, PP_CAUSE_NOT_STAGED); return; }
    int has_ppt = 0;
    for (size_t k = 0; k < d->staged.n; k++) has_ppt |= d->staged.held[k].envelope.artifact == PP_ART_POLICY_PPT;
    if (!has_ppt) { pp_refuse(pep, PP_CAUSE_INCOMPLETE); return; } /* C2: the mesh row needs policy.ppt */
    uint8_t cause = pp_still_valid(pep, &d->staged, 1); /* C3 */
    if (cause) {
        d->has_staged = 0;
        pp_persist(pep);
        pp_refuse(pep, cause);
        return;
    }
    static pp_release release, previous;
    release = d->staged;
    previous = d->active;
    pp_flip(pep, 0, &release, d->has_active ? &previous : NULL);
}

void pp_pep_commit(pp_pep_machine *pep, const char *stream, long long seq, const uint8_t policy_sha256[32],
                   uint16_t delay_ms, uint32_t now_ms, long long now) {
    pp_begin(pep, now);
    if (delay_ms == 0) {
        pp_commit_now(pep, stream, seq, policy_sha256);
        return;
    }
    pep->commit_due = 1; /* B8: active at the PEP's own time plus the delay, so a group flips together */
    pep->commit_due_ms = now_ms + delay_ms;
    pp_copy_stream(pep->due_stream, stream);
    pep->due_seq = seq;
    memcpy(pep->due_policy, policy_sha256, 32);
}

void pp_pep_tick(pp_pep_machine *pep, uint32_t now_ms, long long now) {
    pp_begin(pep, now);
    if (pep->commit_due && (int32_t)(now_ms - pep->commit_due_ms) >= 0) {
        pep->commit_due = 0;
        pp_commit_now(pep, pep->due_stream, pep->due_seq, pep->due_policy);
    }
}

void pp_pep_abort(pp_pep_machine *pep, const char *stream, long long seq, const uint8_t policy_sha256[32], long long now) {
    pp_begin(pep, now);
    if (!pep->d.has_staged || !pp_names(&pep->d.staged, stream, seq, policy_sha256)) {
        pp_emit(pep, PP_EV_BEAT, 0);
        return;
    }
    pep->d.has_staged = 0;
    pp_persist(pep);
    pp_emit(pep, PP_EV_ABORTED, 0);
}

/* RB3: a rollback to `kept` is covered only by a widening statement it holds whose `from` is empty or holds
 * the active policy hash, since a mesh node cannot decide larger (W2). */
static int pp_covers(const pp_pep_machine *pep, const pp_release *kept) {
    for (size_t k = 0; k < kept->n; k++) {
        if (kept->held[k].envelope.artifact != PP_ART_TRUST_WIDENING) continue;
        const uint8_t *body = kept->held[k].body;
        size_t len = kept->held[k].body_len;
        static const char head[] = "{\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-widening/1\",\"from\":[";
        pp_c2 c = {body, len, 0, 1};
        uint8_t hash[32];
        if (!pp_c2_lit(&c, head)) return 0;
        if (pp_c2_lit(&c, "]")) return 1; /* an empty `from` covers any rollback */
        for (;;) {
            if (!pp_scan_hash(&c, hash)) return 0;
            if (pep->d.has_active && memcmp(hash, pep->d.active.policy_sha256, 32) == 0) return 1;
            if (!pp_c2_lit(&c, ",")) return 0;
        }
    }
    return 0;
}

uint8_t pp_pep_rollback(pp_pep_machine *pep, long long now) {
    pp_begin(pep, now);
    pp_durable *d = &pep->d;
    if (pep->held) { pp_refuse(pep, PP_CAUSE_HELD); return 0; } /* X9 */
    if (pep->locked) { pp_refuse(pep, PP_CAUSE_FLOOR_LOST); return 0; }
    if (!d->trust_reads) { pp_refuse(pep, PP_CAUSE_UNKNOWN_KEY); return 0; }
    if (!d->has_previous) return PP_CAUSE_NOT_STAGED;
    uint8_t cause = pp_still_valid(pep, &d->previous, 0);
    if (cause) { pp_refuse(pep, cause); return 0; }
    if (!pp_covers(pep, &d->previous)) { pp_refuse(pep, PP_CAUSE_WIDENING_UNSIGNED); return 0; }
    static pp_release kept;
    kept = d->previous;
    pp_flip(pep, 1, &kept, NULL);
    return 0;
}

void pp_pep_record(pp_pep_machine *pep, uint8_t event, long long now) {
    pp_begin(pep, now);
    pp_emit(pep, event, 0);
}

void pp_pep_see_epoch(pp_pep_machine *pep, uint64_t epoch) {
    if (epoch > pep->epoch) pep->epoch = epoch;
}

uint8_t pp_pep_decide(pp_pep_machine *pep, int *held_mark, long long now) {
    pp_begin(pep, now);
    *held_mark = 0;
    if (pep->locked) return PP_CAUSE_FLOOR_LOST;
    if (pp_state(pep) != PP_ST_ACTIVE) return PP_CAUSE_POLICY_LAPSED;
    *held_mark = pep->held;
    return PP_CAUSE_NONE;
}

/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* pp_dist.c: the C core of policy distribution. See pp_dist.h. */
#include "pp_dist.h"

#include <stddef.h>
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
    "policy.core", "policy.ppt", "policy.spiral", "sandbox.profile", "egress.hosts", "agent.zones", "gateway.routes",
    "net.dests", "net.edge", "cfs.table", "grant", "trust.widening", "trust.revocation", "trust.rotation",
    "install.floor", "install.fallback", "install.ceiling", "install.trust", "operator.answer", "trust.controller",
    "trust.change", "install.change"};
static const char *const pp_target_names[PP_TGT_COUNT] = {"agent", "cfs", "gateway", "host", "mesh", "xdp"};

const char *pp_artifact_name(pp_artifact artifact) {
    return (unsigned)artifact < PP_ART_COUNT ? pp_artifact_names[artifact] : NULL;
}

const char *pp_target_name(pp_target target) {
    return (unsigned)target < PP_TGT_COUNT ? pp_target_names[target] : NULL;
}

#define PP_BIT(kind) (1u << (kind))

/* What a kind's own check (V11) is given: the artifact and its body, the store and the PEP it is checked for,
 * which a revocation is held against (R6), and the entries and the signed message a rotation's own rules read
 * (O2). */
struct pp_check_args {
    pp_artifact artifact;
    const pp_envelope *envelope;
    const uint8_t *body;
    size_t len;
    const pp_trust *trust;
    const pp_pep *pep;
    const pp_entry *entries;
    size_t n_entries;
    const uint8_t *message;
    size_t message_len;
};

/* A target row (kinds.TARGETS): what V5 admits, the trust kinds the machine applies, its body bound and its
 * own V11 check. This core has `mesh`. */
typedef struct {
    uint32_t uses;     /* a bit per pp_artifact */
    uint32_t applies;  /* the trust kinds its machine applies */
    long long body_bound;  /* the bound on the body of an artifact it uses (E6) */
    long long trust_bound; /* the bound on a trust body, PP_TRUST_BOUND on every kind (E6) */
    uint8_t (*check)(const struct pp_check_args *args);
} pp_row;

static int pp_is_trust(pp_artifact artifact) {
    return artifact == PP_ART_TRUST_WIDENING || artifact == PP_ART_TRUST_REVOCATION || artifact == PP_ART_TRUST_ROTATION ||
           artifact == PP_ART_TRUST_CONTROLLER || artifact == PP_ART_TRUST_CHANGE;
}

/* Section 21: the install kinds, and the set kind of each of the three that make a set. */
static int pp_is_install(pp_artifact artifact) {
    return (artifact >= PP_ART_INSTALL_FLOOR && artifact <= PP_ART_INSTALL_TRUST) || artifact == PP_ART_INSTALL_CHANGE;
}

static int pp_set_of(pp_artifact artifact) {
    return artifact == PP_ART_INSTALL_FLOOR ? PP_SET_FLOOR : artifact == PP_ART_INSTALL_FALLBACK ? PP_SET_FALLBACK
           : artifact == PP_ART_INSTALL_CEILING ? PP_SET_CEILING : -1;
}

uint8_t *pp_held_body(pp_release *release, size_t k) {
    return pp_is_trust(release->held[k].envelope.artifact) ? release->trust_body : release->artifact_body;
}

static int pp_on_trust_stream(pp_artifact artifact) {
    return artifact == PP_ART_TRUST_REVOCATION || artifact == PP_ART_TRUST_ROTATION || artifact == PP_ART_TRUST_CONTROLLER;
}

static uint8_t pp_read_widening(const uint8_t *body, size_t len);
static uint8_t pp_check_revocation(const uint8_t *body, size_t len, const pp_trust *trust);
static uint8_t pp_check_rotation(const struct pp_check_args *a);
static uint8_t pp_check_controller(const struct pp_check_args *a);
static int pp_install_names(const pp_install *r, const uint8_t id[32]);
static const pp_key *pp_held_key(const pp_trust *trust, const uint8_t id[32]);

/* `policy.ppt` on a mesh node: the node runs its own table parser and ignores `meta`, so the check is the image
 * check alone (kinds.check_mesh_table). A trust statement is read as its format (W4, section 10), and a revocation
 * list must hold every key the current one holds (R6). */
static uint8_t pp_mesh_check(const struct pp_check_args *a) {
    switch (a->artifact) {
    case PP_ART_POLICY_PPT: return pp_validate_image(a->body, a->len);
    case PP_ART_TRUST_WIDENING: return pp_read_widening(a->body, a->len);
    case PP_ART_TRUST_REVOCATION: return pp_check_revocation(a->body, a->len, a->trust);
    case PP_ART_TRUST_ROTATION: return pp_check_rotation(a);
    case PP_ART_TRUST_CONTROLLER: return pp_check_controller(a);
    default: return PP_CAUSE_TARGET_MISMATCH; /* unreachable: V5 admits nothing else */
    }
}

static uint16_t pp_u16(const uint8_t *p);

/* V11 for `cfs.table` (integrations/cfs/dist_kind.check_cfs_table): the body is the table before ImageSig, its header
 * holds what the app's kernel check holds it to, refused with the cause the app answers it with
 * (image:truncated-header), and the SHA-256 of the core image inside it is the envelope's policy hash
 * (image:sha256-mismatch). The app runs its kernel's own check of the PPT image before it hands a body here. */
static uint8_t pp_check_cfs_table(const pp_envelope *e, const uint8_t *body, size_t len) {
    if (len != PP_CFS_TABLE_MAX) return PP_CAUSE_IMAGE_TRUNCATED_HEADER;
    uint16_t image_len = pp_u16(body + PP_CFS_OFF_IMAGE_LEN), rules = pp_u16(body + PP_CFS_OFF_RULE_COUNT);
    uint16_t core_len = pp_u16(body + PP_CFS_OFF_CORE_LEN), flow_len = pp_u16(body + PP_CFS_OFF_FLOW_LEN);
    uint32_t version = (uint32_t)pp_u16(body + PP_CFS_OFF_VERSION) | (uint32_t)pp_u16(body + PP_CFS_OFF_VERSION + 2) << 16;
    if (image_len > PP_CFS_IMAGE_MAX || rules > PP_CFS_RULES_MAX || core_len < 1 || core_len > PP_CFS_CORE_MAX ||
        flow_len < 2 || flow_len > PP_CFS_FLOW_MAX || version == 0 || pp_u16(body + PP_CFS_OFF_CONTRACT) != 37 ||
        pp_u16(body + PP_CFS_OFF_NOMATCH) != 32)
        return PP_CAUSE_IMAGE_TRUNCATED_HEADER;
    uint8_t hash[32];
    pp_sha256(body + PP_CFS_OFF_CORE, core_len, hash);
    return memcmp(hash, e->policy_sha256, 32) == 0 ? PP_CAUSE_NONE : PP_CAUSE_IMAGE_SHA256_MISMATCH;
}

/* The cFS app takes the table of its own kind and the same trust kinds a mesh node does. */
static uint8_t pp_cfs_check(const struct pp_check_args *a) {
    switch (a->artifact) {
    case PP_ART_CFS_TABLE: return pp_check_cfs_table(a->envelope, a->body, a->len);
    case PP_ART_TRUST_WIDENING: return pp_read_widening(a->body, a->len);
    case PP_ART_TRUST_REVOCATION: return pp_check_revocation(a->body, a->len, a->trust);
    case PP_ART_TRUST_ROTATION: return pp_check_rotation(a);
    default: return PP_CAUSE_TARGET_MISMATCH; /* unreachable: V5 admits nothing else */
    }
}

static const pp_row *pp_row_of(pp_target kind) {
    static const pp_row mesh = {PP_BIT(PP_ART_POLICY_PPT),
                                PP_BIT(PP_ART_TRUST_WIDENING) | PP_BIT(PP_ART_TRUST_REVOCATION) | PP_BIT(PP_ART_TRUST_ROTATION) |
                                    PP_BIT(PP_ART_TRUST_CONTROLLER) | PP_BIT(PP_ART_TRUST_CHANGE),
                                PP_MESH_TABLE_MAX, PP_TRUST_BOUND, pp_mesh_check};
    static const pp_row cfs = {PP_BIT(PP_ART_CFS_TABLE),
                               PP_BIT(PP_ART_TRUST_WIDENING) | PP_BIT(PP_ART_TRUST_REVOCATION) | PP_BIT(PP_ART_TRUST_ROTATION),
                               PP_CFS_TABLE_MAX, PP_TRUST_BOUND, pp_cfs_check};
    if (kind == PP_TGT_MESH) return &mesh;
    return kind == PP_TGT_CFS && PP_TABLE_MAX >= PP_CFS_TABLE_MAX ? &cfs : NULL; /* a build that cannot hold its table */
}

/* The table artifact a release of `kind` decides with, and what `as` names it in an install set (IS3). */
static pp_artifact pp_table_artifact(pp_target kind) { return kind == PP_TGT_CFS ? PP_ART_CFS_TABLE : PP_ART_POLICY_PPT; }
static uint8_t pp_table_as(pp_target kind) { return kind == PP_TGT_CFS ? PP_AS_CFS_TABLE : PP_AS_POLICY_PPT; }

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

/* IS1, E11: what `as` may name: an artifact a release holds, the policy list of a ceiling (CL1), or `none`. */
static uint8_t pp_as_of(const uint8_t *s, size_t len) {
    static const char *const others[] = {"policy.core", "policy.spiral", "sandbox.profile", "egress.hosts",
                                         "agent.zones", "gateway.routes", "net.dests", "net.edge", "cfs.table"};
    if (len == 10 && memcmp(s, "policy.ppt", 10) == 0) return PP_AS_POLICY_PPT;
    if (len == 11 && memcmp(s, "policy.list", 11) == 0) return PP_AS_POLICY_LIST;
    if (len == 9 && memcmp(s, "cfs.table", 9) == 0) return PP_AS_CFS_TABLE;
    if (len == 4 && memcmp(s, "none", 4) == 0) return PP_AS_NONE;
    return pp_name_index(s, len, others, 9) >= 0 ? PP_AS_OTHER : PP_AS_ABSENT;
}

/* AF8, OP4: a rate, `allows` from 1 to 65535 in each `window` of 1 to 86400 seconds. */
static int pp_scan_rate(pp_c2 *c, long long *allows, long long *window) {
    return pp_c2_lit(c, "{\"allows\":") && pp_scan_int(c, 1, 65535, allows) && pp_c2_lit(c, ",\"window\":") &&
           pp_scan_int(c, 1, 86400, window) && pp_c2_lit(c, "}");
}

/* IS1: the `meta` of an install kind, read for `as`, `layout`, `command`, `rate` and `answer_rate`, each of its
 * form, and every other member skipped as E9 allows. `as` is required of a set and nothing of an install.trust, and
 * the floor's own members are on an action floor only. A member of the wrong form does not read (dist:bad-format). */
static int pp_scan_install_meta(pp_c2 *c, pp_envelope *e) {
    const uint8_t *s;
    size_t len;
    int depth, members = 0;
    if (!pp_c2_lit(c, "{")) return 0;
    while (!pp_c2_lit(c, "}")) {
        if (members && !pp_c2_lit(c, ",")) return 0;
        members++;
        if (!pp_c2_plain_string(c, &s, &len) || !pp_c2_lit(c, ":")) return 0;
        if (len == 2 && memcmp(s, "as", 2) == 0) {
            const uint8_t *v;
            size_t vlen;
            if (!pp_c2_plain_string(c, &v, &vlen) || (e->as = pp_as_of(v, vlen)) == PP_AS_ABSENT) return 0;
        } else if (len == 6 && memcmp(s, "layout", 6) == 0) {
            if (!pp_scan_hash(c, e->layout)) return 0;
            e->has_layout = 1;
        } else if (len == 7 && memcmp(s, "command", 7) == 0) {
            long long v;
            if (!pp_scan_int(c, 0, 255, &v)) return 0;
            e->command = (int)v;
            e->has_command = 1;
        } else if (len == 4 && memcmp(s, "rate", 4) == 0) {
            if (!pp_scan_rate(c, &e->rate_allows, &e->rate_window)) return 0;
            e->has_rate = 1;
        } else if (len == 11 && memcmp(s, "answer_rate", 11) == 0) {
            if (!pp_scan_rate(c, &e->answer_allows, &e->answer_window)) return 0;
            e->has_answer_rate = 1;
        } else if (!pp_c2_skip(c, &depth)) {
            return 0;
        }
    }
    if (e->artifact == PP_ART_OPERATOR_ANSWER) return 1;
    if (e->artifact == PP_ART_INSTALL_TRUST || e->artifact == PP_ART_INSTALL_CHANGE)
        return members == 0;                                              /* IS11, IS14: its meta is empty */
    if (e->as == PP_AS_ABSENT) return 0;                                  /* a set names its artifact in as */
    return e->artifact == PP_ART_INSTALL_FLOOR ||
           !(e->has_layout || e->has_command || e->has_rate || e->has_answer_rate); /* a floor's members on a floor */
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
    if (!pp_c2_lit(c, ",\"meta\":") || c->i >= c->n || c->p[c->i] != '{') return 0;
    size_t meta_at = c->i;
    if (!pp_c2_skip(c, &depth) || depth > PP_META_MAX_DEPTH) return 0;
    if (pp_is_install(e->artifact) || e->artifact == PP_ART_OPERATOR_ANSWER) { /* IS1: the members every reader reads */
        pp_c2 m = {c->p, c->i, meta_at, 1};
        if (!pp_scan_install_meta(&m, e)) return 0;
    }
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

/* E10 over one [as, body_sha256] pair, the release id of a set of one statement (IS1), or of a release of one
 * artifact: the SHA-256 of the canon/2 array [[name, body hash]]. */
static void pp_release_of_one(const char *name, const uint8_t body_sha256[32], uint8_t out[32]) {
    static const char hex[] = "0123456789abcdef";
    uint8_t text[8 + 32 + 64];
    size_t at = 0, n = strlen(name);
    memcpy(text, "[[\"", 3);
    at = 3;
    memcpy(text + at, name, n);
    at += n;
    memcpy(text + at, "\",\"", 3);
    at += 3;
    for (size_t b = 0; b < 32; b++) {
        text[at++] = (uint8_t)hex[body_sha256[b] >> 4];
        text[at++] = (uint8_t)hex[body_sha256[b] & 15];
    }
    memcpy(text + at, "\"]]", 3);
    at += 3;
    pp_sha256(text, at, out);
}

/* IS1, IS11: an install statement's own members. It is on a stream and not `@trust`. An install.trust carries 64
 * zeros for its policy hash and release and no `replaces`. A set names exactly one kind. The empty set has `as`
 * `none`, an empty body, 64 zeros for its policy hash and the release id of [none, the hash of no bytes]. A policy
 * list is a ceiling's, and its policy hash is the list's. */
static int pp_install_reads(const pp_envelope *e) {
    if (strcmp(e->stream, "@trust") == 0) return 0;
    if (e->artifact == PP_ART_INSTALL_TRUST)
        return memcmp(e->policy_sha256, pp_zero32, 32) == 0 && memcmp(e->release, pp_zero32, 32) == 0 &&
               !e->has_replaces;
    if (e->targets & (e->targets - 1)) return 0;
    if (e->artifact == PP_ART_INSTALL_CHANGE) return 1; /* IS14: its set is in its body, checked at V11 */
    if (e->as == PP_AS_NONE) {
        uint8_t nothing[32], release[32];
        pp_sha256((const uint8_t *)"", 0, nothing);
        pp_release_of_one("none", nothing, release);
        return e->body_size == 0 && memcmp(e->policy_sha256, pp_zero32, 32) == 0 && memcmp(e->release, release, 32) == 0;
    }
    if (e->as == PP_AS_POLICY_LIST)
        return e->artifact == PP_ART_INSTALL_CEILING && memcmp(e->policy_sha256, e->body_sha256, 32) == 0;
    return 1;
}

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
    if (pp_is_trust(out->artifact) || pp_is_install(out->artifact) ? out->expires != 0
                                                                    : out->expires <= out->not_before)
        return PP_CAUSE_BAD_FORMAT; /* E5, X4, IS1 */
    if (pp_is_install(out->artifact) && !pp_install_reads(out)) return PP_CAUSE_BAD_FORMAT;
    if (out->artifact == PP_ART_OPERATOR_ANSWER &&      /* OP2: one PEP, one escalation, at most 600 seconds */
        (out->expires - out->not_before > 600 || out->seq != 1 || memcmp(out->release, pp_zero32, 32) != 0 ||
         out->has_replaces || out->widens || strcmp(out->stream, "@trust") == 0 || (out->targets & (out->targets - 1))))
        return PP_CAUSE_BAD_FORMAT;
    pp_sha256(bytes, len, out->envelope_id);
    return PP_CAUSE_NONE;
}

/* W10: a change statement, `from` the one policy hash its release replaces and `basis` the table comparator, as
 * canonical canon/2. `from` is written to `from` when it reads. */
static uint8_t pp_read_change(const uint8_t *body, size_t len, uint8_t from[32]) {
    int form = pp_c2_check(body, len);
    if (form == PP_C2_NOT_CANONICAL) return PP_CAUSE_NOT_CANONICAL;
    if (form != PP_C2_OK) return PP_CAUSE_BAD_FORMAT;
    pp_c2 c = {body, len, 0, 1};
    if (!pp_c2_lit(&c, "{\"basis\":\"prismpath.table-compare/1\",\"encoding\":\"canon/2\","
                       "\"format\":\"prismpath.dist-change/1\",\"from\":") ||
        !pp_scan_hash(&c, from) || !pp_c2_lit(&c, "}") || c.i != c.n)
        return PP_CAUSE_BAD_FORMAT;
    return PP_CAUSE_NONE;
}

/* `trust.change` (V11, W10): the body reads, its `from` is the envelope's `replaces`, and the envelope does not
 * widen. One that says it widens, or replaces nothing, is dist:bad-format, since a first install widens. */
static uint8_t pp_check_change(const pp_envelope *e, const uint8_t *body, size_t len) {
    uint8_t from[32];
    uint8_t cause = pp_read_change(body, len, from);
    if (cause) return cause;
    return e->widens || !e->has_replaces || memcmp(from, e->replaces, 32) != 0 ? PP_CAUSE_BAD_FORMAT : PP_CAUSE_NONE;
}

/* IS14: an install change statement, `set` the kind of the set it carries, `from` the policy hash that set replaces
 * and `basis` the table comparator, as canonical canon/2. A ceiling's is dist:bad-format, since this core compares two
 * policy lists itself. The set kind is written to `set` and `from` to `from` when it reads. */
static uint8_t pp_read_install_change(const uint8_t *body, size_t len, int *set, uint8_t from[32]) {
    int form = pp_c2_check(body, len);
    if (form == PP_C2_NOT_CANONICAL) return PP_CAUSE_NOT_CANONICAL;
    if (form != PP_C2_OK) return PP_CAUSE_BAD_FORMAT;
    pp_c2 c = {body, len, 0, 1};
    if (!pp_c2_lit(&c, "{\"basis\":\"prismpath.table-compare/1\",\"encoding\":\"canon/2\","
                       "\"format\":\"prismpath.dist-install-change/1\",\"from\":") ||
        !pp_scan_hash(&c, from) || !pp_c2_lit(&c, ",\"set\":"))
        return PP_CAUSE_BAD_FORMAT;
    if (pp_c2_lit(&c, "\"install.floor\"")) *set = PP_SET_FLOOR;
    else if (pp_c2_lit(&c, "\"install.fallback\"")) *set = PP_SET_FALLBACK;
    else return PP_CAUSE_BAD_FORMAT;
    return pp_c2_lit(&c, "}") && c.i == c.n ? PP_CAUSE_NONE : PP_CAUSE_BAD_FORMAT;
}

/* `install.change` (V11, IS14): the body reads, its `from` is the envelope's `replaces`, the envelope does not widen,
 * and its policy hash is a set's and not the empty set's 64 zeros. Anything else is dist:bad-format. */
static uint8_t pp_check_install_change(const pp_envelope *e, const uint8_t *body, size_t len, int *set,
                                       uint8_t from[32]) {
    uint8_t cause = pp_read_install_change(body, len, set, from);
    if (cause) return cause;
    return e->widens || !e->has_replaces || memcmp(from, e->replaces, 32) != 0 ||
                   memcmp(e->policy_sha256, pp_zero32, 32) == 0
               ? PP_CAUSE_BAD_FORMAT
               : PP_CAUSE_NONE;
}

/* W4: a widening statement, `from` a sorted list of at most 64 hashes without repeats, as canonical canon/2. */
static uint8_t pp_read_widening(const uint8_t *body, size_t len) {
    int form = pp_c2_check(body, len);
    if (form == PP_C2_NOT_CANONICAL) return PP_CAUSE_NOT_CANONICAL;
    if (form != PP_C2_OK) return PP_CAUSE_BAD_FORMAT;
    pp_c2 c = {body, len, 0, 1};
    uint8_t last[32], hash[32];
    size_t n = 0;
    if (!pp_c2_lit(&c, "{\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-widening/1\",\"from\":["))
        return PP_CAUSE_BAD_FORMAT;
    if (!pp_c2_lit(&c, "]")) {
        for (;;) {
            if (!pp_scan_hash(&c, hash) || (n && memcmp(last, hash, 32) >= 0)) return PP_CAUSE_BAD_FORMAT;
            memcpy(last, hash, 32);
            n++;
            if (pp_c2_lit(&c, "]")) break;
            if (!pp_c2_lit(&c, ",")) return PP_CAUSE_BAD_FORMAT;
        }
    }
    if (!pp_c2_lit(&c, "}") || c.i != c.n) return PP_CAUSE_BAD_FORMAT;
    return n > PP_WIDENING_HASHES ? PP_CAUSE_TOO_LARGE : PP_CAUSE_NONE; /* W4: at most 64 hashes, so a release slot
                                                                         holds every statement it takes */
}

static int pp_listed(const uint8_t (*list)[32], size_t n, const uint8_t id[32]);

/* A revocation list as read (section 10): its three lists, sorted without repeats, and the floor it raises for one
 * stream. Counts past 64 are kept so R7 can be told from a list that does not read. */
typedef struct {
    uint8_t envelopes[PP_REVOCATION_ENTRIES][32], keys[PP_REVOCATION_ENTRIES][32], policies[PP_REVOCATION_ENTRIES][32];
    size_t n_envelopes, n_keys, n_policies, n_floors;
    long long floor;     /* the floor it raises for the stream asked about, 0 for none */
} pp_revocation_list;

/* A sorted list of hashes without repeats at the cursor, the first 64 kept in `list`, its count in *n. */
static int pp_hash_list(pp_c2 *c, uint8_t (*list)[32], size_t *n) {
    uint8_t last[32], hash[32];
    *n = 0;
    if (!pp_c2_lit(c, "[")) return 0;
    if (pp_c2_lit(c, "]")) return 1;
    for (;;) {
        if (!pp_scan_hash(c, hash) || (*n && memcmp(last, hash, 32) >= 0)) return 0;
        memcpy(last, hash, 32);
        if (*n < PP_REVOCATION_ENTRIES) memcpy(list[*n], hash, 32);
        (*n)++;
        if (pp_c2_lit(c, "]")) return 1;
        if (!pp_c2_lit(c, ",")) return 0;
    }
}

/* kinds.read_revocation: the list in `body`, `dist:too-large` past 64 entries a list or 16 streams (R7), and in
 * `out->floor` the floor it raises for `stream`. */
static uint8_t pp_read_revocation(const uint8_t *body, size_t len, const char *stream, pp_revocation_list *out) {
    int form = pp_c2_check(body, len);
    if (form == PP_C2_NOT_CANONICAL) return PP_CAUSE_NOT_CANONICAL;
    if (form != PP_C2_OK) return PP_CAUSE_BAD_FORMAT;
    pp_c2 c = {body, len, 0, 1};
    memset(out, 0, sizeof *out);
    if (!pp_c2_lit(&c, "{\"encoding\":\"canon/2\",\"envelopes\":") || !pp_hash_list(&c, out->envelopes, &out->n_envelopes))
        return PP_CAUSE_BAD_FORMAT;
    if (!pp_c2_lit(&c, ",\"floors\":{")) return PP_CAUSE_BAD_FORMAT;
    if (!pp_c2_lit(&c, "}")) {
        for (;;) {
            const uint8_t *s;
            size_t slen;
            long long seq;
            if (!pp_c2_plain_string(&c, &s, &slen) || !pp_is_stream(s, slen) || !pp_c2_lit(&c, ":") ||
                !pp_scan_int(&c, 1, PP_MAX_SEQ, &seq))
                return PP_CAUSE_BAD_FORMAT;
            out->n_floors++;
            if (stream && strlen(stream) == slen && memcmp(stream, s, slen) == 0) out->floor = seq;
            if (pp_c2_lit(&c, "}")) break;
            if (!pp_c2_lit(&c, ",")) return PP_CAUSE_BAD_FORMAT;
        }
    }
    if (!pp_c2_lit(&c, ",\"format\":\"prismpath.dist-revocation/1\",\"keys\":") || !pp_hash_list(&c, out->keys, &out->n_keys))
        return PP_CAUSE_BAD_FORMAT;
    if (!pp_c2_lit(&c, ",\"policies\":") || !pp_hash_list(&c, out->policies, &out->n_policies)) return PP_CAUSE_BAD_FORMAT;
    if (!pp_c2_lit(&c, "}") || c.i != c.n) return PP_CAUSE_BAD_FORMAT;
    if (out->n_envelopes > PP_REVOCATION_ENTRIES || out->n_keys > PP_REVOCATION_ENTRIES ||
        out->n_policies > PP_REVOCATION_ENTRIES || out->n_floors > PP_REVOCATION_FLOORS)
        return PP_CAUSE_TOO_LARGE; /* R7 */
    return PP_CAUSE_NONE;
}

/* V11 for a revocation: it reads as its format (R7), and it holds every key id the current list holds, since a key
 * once revoked stays revoked (R6, trust.check_revocation). */
static uint8_t pp_check_revocation(const uint8_t *body, size_t len, const pp_trust *trust) {
    static pp_revocation_list list;
    uint8_t cause = pp_read_revocation(body, len, NULL, &list);
    if (cause) return cause;
    for (size_t k = 0; k < trust->n_revoked_keys; k++)
        if (!pp_listed((const uint8_t (*)[32])list.keys, list.n_keys, trust->revoked_keys[k])) return PP_CAUSE_TRUST_REPLAY;
    return PP_CAUSE_NONE;
}

static const pp_key *pp_held_key(const pp_trust *trust, const uint8_t id[32]) {
    for (size_t k = 0; k < trust->n_keys; k++)
        if (memcmp(trust->keys[k].id, id, 32) == 0) return &trust->keys[k];
    return NULL;
}

/* ------------------------------------------------------------------ the trust store (S3 to S5) */

static int pp_listed(const uint8_t (*list)[32], size_t n, const uint8_t id[32]) {
    for (size_t k = 0; k < n; k++)
        if (memcmp(list[k], id, 32) == 0) return 1;
    return 0;
}

/* Section 11 (kinds.read_rotation): the new public key in `add` and the key id it retires, or none. */
static uint8_t pp_read_rotation(const uint8_t *body, size_t len, uint8_t add[32], int *has_retire, uint8_t retire[32]) {
    int form = pp_c2_check(body, len);
    if (form == PP_C2_NOT_CANONICAL) return PP_CAUSE_NOT_CANONICAL;
    if (form != PP_C2_OK) return PP_CAUSE_BAD_FORMAT;
    pp_c2 c = {body, len, 0, 1};
    if (!pp_c2_lit(&c, "{\"add\":") || !pp_scan_hash(&c, add) ||
        !pp_c2_lit(&c, ",\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-rotation/1\",\"retire\":"))
        return PP_CAUSE_BAD_FORMAT;
    if (pp_c2_lit(&c, "\"\"")) *has_retire = 0;
    else if (pp_scan_hash(&c, retire)) *has_retire = 1;
    else return PP_CAUSE_BAD_FORMAT;
    return pp_c2_lit(&c, "}") && c.i == c.n ? PP_CAUSE_NONE : PP_CAUSE_BAD_FORMAT;
}

/* O2 to O4 and K5 (trust.check_rotation), in its order: `add` is not the PEP's own instance key, a revoked key or
 * a key the store retired, `retire` names a key the store holds, the keys left that are not retired are at most
 * PP_MAX_KEYS (dist:too-large past that), and the entry under the added key verifies, so the rotation is signed
 * under the store it leaves and the store it makes. */
static uint8_t pp_check_rotation(const struct pp_check_args *a) {
    uint8_t add[32], retire[32], added_id[32];
    int has_retire = 0;
    uint8_t cause = pp_read_rotation(a->body, a->len, add, &has_retire, retire);
    if (cause) return cause;
    const pp_trust *t = a->trust;
    pp_sha256(add, 32, added_id);
    const pp_key *same = pp_held_key(t, added_id);
    if ((a->pep->has_instance_key_id && memcmp(added_id, a->pep->instance_key_id, 32) == 0) ||
        pp_listed(t->revoked_keys, t->n_revoked_keys, added_id) || pp_listed(t->retired, t->n_retired, added_id) ||
        (same && same->role != PP_ROLE_AUTHORITY) || (a->pep->install && pp_install_names(a->pep->install->record, added_id)))
        return PP_CAUSE_ROTATION_INVALID; /* O4, K4: never the controller key, an install or an operator key, held or retired */
    if (has_retire && pp_held_key(t, retire) == NULL) return PP_CAUSE_ROTATION_INVALID; /* O3 */
    size_t live = 0;
    int added_live = 0, retire_live = 0;
    for (size_t k = 0; k < t->n_keys; k++) {
        if (pp_listed(t->retired, t->n_retired, t->keys[k].id)) continue;
        live++;
        if (memcmp(t->keys[k].id, added_id, 32) == 0) added_live = 1;
        if (has_retire && memcmp(t->keys[k].id, retire, 32) == 0) retire_live = 1;
    }
    if (!added_live) live++;
    if (has_retire && (retire_live || memcmp(retire, added_id, 32) == 0)) live--;
    if (live > PP_MAX_KEYS) return PP_CAUSE_TOO_LARGE; /* K5: a ninth key */
    for (size_t k = 0; k < a->n_entries; k++)
        if (memcmp(a->entries[k].key_id, added_id, 32) == 0)
            return crypto_ed25519_check(a->entries[k].signature, add, a->message, a->message_len) == 0
                       ? PP_CAUSE_NONE : PP_CAUSE_ROTATION_INVALID; /* O2 */
    return PP_CAUSE_ROTATION_INVALID;
}

/* K7 (kinds.read_controller): the controller's public key in `key`. */
static uint8_t pp_read_controller(const uint8_t *body, size_t len, uint8_t key[32]) {
    int form = pp_c2_check(body, len);
    if (form == PP_C2_NOT_CANONICAL) return PP_CAUSE_NOT_CANONICAL;
    if (form != PP_C2_OK) return PP_CAUSE_BAD_FORMAT;
    pp_c2 c = {body, len, 0, 1};
    if (!pp_c2_lit(&c, "{\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-controller/1\",\"key\":") ||
        !pp_scan_hash(&c, key) || !pp_c2_lit(&c, "}") || c.i != c.n)
        return PP_CAUSE_BAD_FORMAT;
    return PP_CAUSE_NONE;
}

/* K6: the controller key the store holds and has not retired, or NULL. */
static const pp_key *pp_controller_of(const pp_trust *t) {
    for (size_t k = 0; k < t->n_keys; k++)
        if (t->keys[k].role == PP_ROLE_CONTROLLER && !pp_listed(t->retired, t->n_retired, t->keys[k].id)) return &t->keys[k];
    return NULL;
}

/* K7, K4, K5 (trust.check_controller): naming the held controller key passes. Otherwise `key` is never the PEP's own
 * instance key, a revoked key, a key held in another role or retired, the controller key replaced before included,
 * or an install or an operator key the PEP holds or retired (dist:rotation-invalid), and a store that would then
 * hold a ninth key that is not retired is dist:too-large. */
static uint8_t pp_check_controller(const struct pp_check_args *a) {
    uint8_t key[32], id[32];
    uint8_t cause = pp_read_controller(a->body, a->len, key);
    if (cause) return cause;
    const pp_trust *t = a->trust;
    pp_sha256(key, 32, id);
    const pp_key *held = pp_controller_of(t), *same = pp_held_key(t, id);
    if (held && memcmp(held->id, id, 32) == 0) return PP_CAUSE_NONE;
    if ((a->pep->has_instance_key_id && memcmp(id, a->pep->instance_key_id, 32) == 0) ||
        pp_listed(t->revoked_keys, t->n_revoked_keys, id) || pp_listed(t->retired, t->n_retired, id) ||
        (same && same->role != PP_ROLE_CONTROLLER) || (a->pep->install && pp_install_names(a->pep->install->record, id)))
        return PP_CAUSE_ROTATION_INVALID;
    size_t live = 1; /* the key named */
    for (size_t k = 0; k < t->n_keys; k++)
        if (!pp_listed(t->retired, t->n_retired, t->keys[k].id) && &t->keys[k] != held) live++;
    return live > PP_MAX_KEYS ? PP_CAUSE_TOO_LARGE : PP_CAUSE_NONE;
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

/* ------------------------------------------------------------------ the install record's keys (IS2, IS11, OP1) */

static int pp_ikey_listed(const pp_ikey *keys, size_t n, const uint8_t id[32]) {
    for (size_t k = 0; k < n; k++)
        if (memcmp(keys[k].id, id, 32) == 0) return 1;
    return 0;
}

/* K4: an install or operator key the record holds, or an id it retired. */
static int pp_install_names(const pp_install *r, const uint8_t id[32]) {
    return r != NULL && (pp_ikey_listed(r->keys, r->n_keys, id) || pp_ikey_listed(r->operators, r->n_operators, id) ||
                         pp_listed(r->retired, r->n_retired, id));
}

/* IS2, S3 to S5 for the role install: signed when at least the install threshold of entries name install keys and
 * verify. Otherwise sig:revoked-key when an entry names a retired install or operator id, sig:invalid when one
 * names a held key and does not verify, and dist:unknown-key (install.Record.counting). With `operator`, one
 * signature by an operator key is enough (OP1). */
static uint8_t pp_role_counting(const pp_install *r, int operator, const pp_entry *entries, size_t n_entries,
                                const uint8_t *message, size_t message_len) {
    if (r == NULL) return PP_CAUSE_UNKNOWN_KEY;
    const pp_ikey *keys = operator ? r->operators : r->keys;
    size_t n_keys = operator ? r->n_operators : r->n_keys;
    long long need = operator ? 1 : r->threshold, counted = 0;
    int held_fails = 0, retired = 0;
    for (size_t k = 0; k < n_entries; k++) {
        if (pp_listed(r->retired, r->n_retired, entries[k].key_id)) retired = 1;
        for (size_t j = 0; j < n_keys; j++) {
            if (memcmp(keys[j].id, entries[k].key_id, 32) != 0) continue;
            if (crypto_ed25519_check(entries[k].signature, keys[j].public_key, message, message_len) == 0) counted++;
            else held_fails = 1;
        }
    }
    if (n_keys && counted >= need) return PP_CAUSE_NONE;
    if (retired) return PP_CAUSE_SIG_REVOKED_KEY;
    return held_fails ? PP_CAUSE_SIG_INVALID : PP_CAUSE_UNKNOWN_KEY;
}

/* A sorted list of public keys without repeats, at most `max` kept, its count in *n (past `max` still counted). */
static int pp_key_list(pp_c2 *c, uint8_t (*out)[32], size_t max, size_t *n) {
    uint8_t last[32], key[32];
    *n = 0;
    if (!pp_c2_lit(c, "[")) return 0;
    if (pp_c2_lit(c, "]")) return 1;
    for (;;) {
        if (!pp_scan_hash(c, key) || (*n && memcmp(last, key, 32) >= 0)) return 0;
        memcpy(last, key, 32);
        if (*n < max) memcpy(out[*n], key, 32);
        (*n)++;
        if (pp_c2_lit(c, "]")) return 1;
        if (!pp_c2_lit(c, ",")) return 0;
    }
}

typedef struct {
    uint8_t keys[PP_INSTALL_KEYS][32];
    size_t n_keys;
    uint8_t operators[PP_OPERATOR_KEYS][32];
    size_t n_operators;
    long long threshold;
} pp_install_trust_body;

/* P2, P4 (trust.read_anchor): a trust anchor, /1 or /2, in canonical canon/2. The `keys` object maps each key id to
 * {public, role}, every role `authority` and every id its key's; the threshold is 1 (S6). A /2 anchor carries its
 * controller key, which is apart from every other key it names, and `fresh`, which this core holds to 0. */
uint8_t pp_read_anchor(const uint8_t *bytes, size_t len, pp_trust *trust, pp_install_anchor *install,
                       char stream[PP_STREAM_MAX + 1], pp_target *target, uint8_t fingerprint[32]) {
    int form = pp_c2_check(bytes, len);
    if (form == PP_C2_NOT_CANONICAL) return PP_CAUSE_NOT_CANONICAL;
    if (form != PP_C2_OK) return PP_CAUSE_BAD_FORMAT;
    pp_c2 c = {bytes, len, 0, 1};
    memset(trust, 0, sizeof *trust);
    memset(install, 0, sizeof *install);
    const uint8_t *s;
    size_t n;
    long long v;
    int v2 = 0;
    uint8_t controller[32];
    if (!pp_c2_lit(&c, "{")) return PP_CAUSE_BAD_FORMAT;
    if (pp_c2_lit(&c, "\"controller\":")) { /* /2 */
        if (!pp_scan_hash(&c, controller) || !pp_c2_lit(&c, ",")) return PP_CAUSE_BAD_FORMAT;
        v2 = 1;
    }
    if (!pp_c2_lit(&c, "\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-trust/")) return PP_CAUSE_BAD_FORMAT;
    if (!pp_c2_lit(&c, v2 ? "2\"," : "1\",")) return PP_CAUSE_BAD_FORMAT;
    if (v2) {
        if (!pp_c2_lit(&c, "\"fresh\":") || !pp_c2_int(&c, &v) || v < 0 || !pp_c2_lit(&c, ",")) return PP_CAUSE_BAD_FORMAT;
        if (v != 0) return PP_CAUSE_BAD_FORMAT; /* H16 is not built in this core, so freshness cannot be honoured */
        if (pp_c2_lit(&c, "\"install\":")) {
            if (!pp_c2_lit(&c, "{\"domain\":") || !pp_scan_hash(&c, install->domain) || !pp_c2_lit(&c, ",\"keys\":") ||
                !pp_key_list(&c, install->keys, PP_INSTALL_KEYS, &install->n_keys) ||
                !pp_c2_lit(&c, ",\"operators\":") ||
                !pp_key_list(&c, install->operators, PP_OPERATOR_KEYS, &install->n_operators) ||
                !pp_c2_lit(&c, ",\"seq\":") || !pp_c2_int(&c, &install->seq) || install->seq < 0 ||
                !pp_c2_lit(&c, ",\"threshold\":") || !pp_c2_int(&c, &install->threshold) || !pp_c2_lit(&c, "},"))
                return PP_CAUSE_BAD_FORMAT;
            if (install->n_keys < 1 || install->n_keys > PP_INSTALL_KEYS || install->n_operators > PP_OPERATOR_KEYS ||
                install->threshold < 1 || install->threshold > (long long)install->n_keys)
                return PP_CAUSE_BAD_FORMAT;
            install->present = 1;
        }
    }
    if (!pp_c2_lit(&c, "\"keys\":{")) return PP_CAUSE_BAD_FORMAT;
    if (!pp_c2_lit(&c, "}")) {
        for (;;) {
            uint8_t id[32], public_key[32], own[32];
            if (trust->n_keys >= PP_MAX_KEYS) return PP_CAUSE_BAD_FORMAT; /* K5 */
            if (!pp_scan_hash(&c, id) || !pp_c2_lit(&c, ":{\"public\":") || !pp_scan_hash(&c, public_key) ||
                !pp_c2_lit(&c, ",\"role\":\"authority\"}"))
                return PP_CAUSE_BAD_FORMAT; /* P4: every entry an authority key */
            pp_sha256(public_key, 32, own);
            if (memcmp(own, id, 32) != 0) return PP_CAUSE_BAD_FORMAT;
            pp_key *key = &trust->keys[trust->n_keys++];
            memcpy(key->id, id, 32);
            memcpy(key->public_key, public_key, 32);
            key->role = PP_ROLE_AUTHORITY;
            if (pp_c2_lit(&c, "}")) break;
            if (!pp_c2_lit(&c, ",")) return PP_CAUSE_BAD_FORMAT;
        }
    }
    if (trust->n_keys == 0) return PP_CAUSE_BAD_FORMAT;
    if (!pp_c2_lit(&c, ",\"stream\":") || !pp_c2_plain_string(&c, &s, &n) || !pp_is_stream(s, n)) return PP_CAUSE_BAD_FORMAT;
    memcpy(stream, s, n);
    stream[n] = 0;
    if (!pp_c2_lit(&c, ",\"target\":") || !pp_c2_plain_string(&c, &s, &n)) return PP_CAUSE_BAD_FORMAT;
    int kind = pp_name_index(s, n, pp_target_names, PP_TGT_COUNT);
    if (kind < 0 || !pp_c2_lit(&c, ",\"threshold\":1}") || c.i != c.n) return PP_CAUSE_BAD_FORMAT;
    *target = (pp_target)kind;
    if (v2) { /* K4, K6: the controller key is in no other role */
        uint8_t id[32];
        pp_sha256(controller, 32, id);
        for (size_t k = 0; k < trust->n_keys; k++)
            if (memcmp(trust->keys[k].id, id, 32) == 0) return PP_CAUSE_BAD_FORMAT;
        for (size_t k = 0; k < install->n_keys; k++)
            if (memcmp(install->keys[k], controller, 32) == 0) return PP_CAUSE_BAD_FORMAT;
        for (size_t k = 0; k < install->n_operators; k++)
            if (memcmp(install->operators[k], controller, 32) == 0) return PP_CAUSE_BAD_FORMAT;
    }
    pp_sha256(bytes, len, fingerprint);
    memcpy(install->fingerprint, fingerprint, 32);
    trust->readable = 1;
    return PP_CAUSE_NONE;
}

/* IS11: an install trust statement, the sorted install `keys` (1 to 4, dist:too-large past 4), the sorted
 * `operators` (0 to 4) and the install `threshold`, from 1 to the number of keys (kinds.read_install_trust). */
static uint8_t pp_read_install_trust(const uint8_t *body, size_t len, pp_install_trust_body *out) {
    int form = pp_c2_check(body, len);
    if (form == PP_C2_NOT_CANONICAL) return PP_CAUSE_NOT_CANONICAL;
    if (form != PP_C2_OK) return PP_CAUSE_BAD_FORMAT;
    pp_c2 c = {body, len, 0, 1};
    memset(out, 0, sizeof *out);
    if (!pp_c2_lit(&c, "{\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-install-trust/1\",\"keys\":") ||
        !pp_key_list(&c, out->keys, PP_INSTALL_KEYS, &out->n_keys) || !pp_c2_lit(&c, ",\"operators\":") ||
        !pp_key_list(&c, out->operators, PP_OPERATOR_KEYS, &out->n_operators) || !pp_c2_lit(&c, ",\"threshold\":") ||
        !pp_c2_int(&c, &out->threshold) || !pp_c2_lit(&c, "}") || c.i != c.n || out->n_keys == 0)
        return PP_CAUSE_BAD_FORMAT;
    if (out->n_keys > PP_INSTALL_KEYS || out->n_operators > PP_OPERATOR_KEYS) return PP_CAUSE_TOO_LARGE;
    if (out->threshold < 1 || out->threshold > (long long)out->n_keys) return PP_CAUSE_BAD_FORMAT;
    return PP_CAUSE_NONE;
}

/* CL1: a policy list, the sorted body hashes of the tables qualified for the kind, at most 64 (dist:too-large past
 * that), into `out` and its count. */
static uint8_t pp_read_ceiling(const uint8_t *body, size_t len, uint8_t (*out)[32], size_t *n) {
    int form = pp_c2_check(body, len);
    if (form == PP_C2_NOT_CANONICAL) return PP_CAUSE_NOT_CANONICAL;
    if (form != PP_C2_OK) return PP_CAUSE_BAD_FORMAT;
    pp_c2 c = {body, len, 0, 1};
    if (!pp_c2_lit(&c, "{\"bodies\":") || !pp_key_list(&c, out, PP_CEILING_BODIES, n) ||
        !pp_c2_lit(&c, ",\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-ceiling/1\"}") || c.i != c.n)
        return PP_CAUSE_BAD_FORMAT;
    return *n > PP_CEILING_BODIES ? PP_CAUSE_TOO_LARGE : PP_CAUSE_NONE;
}

/* The canonical body of a policy list of `n` hashes, written into `out` (room for 64), and its length. */
static size_t pp_ceiling_body(const uint8_t (*hashes)[32], size_t n, uint8_t *out) {
    static const char hex[] = "0123456789abcdef";
    size_t at = 0;
    memcpy(out, "{\"bodies\":[", 11);
    at = 11;
    for (size_t k = 0; k < n; k++) {
        if (k) out[at++] = ',';
        out[at++] = '"';
        for (size_t b = 0; b < 32; b++) {
            out[at++] = (uint8_t)hex[hashes[k][b] >> 4];
            out[at++] = (uint8_t)hex[hashes[k][b] & 15];
        }
        out[at++] = '"';
    }
    static const char tail[] = "],\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-ceiling/1\"}";
    memcpy(out + at, tail, sizeof tail - 1);
    return at + sizeof tail - 1;
}
#define PP_CEILING_BODY_MAX (11 + PP_CEILING_BODIES * 67 + 64)

/* IS11 beyond its signatures (install.check_trust): no key in both lists; no key it adds is the PEP's instance key,
 * a key the trust store holds, has retired or revoked, a retired install or operator id, an operator key added to
 * `keys` or an install key added to `operators` (dist:rotation-invalid); every key it adds signs it (O2); and a
 * `widens` false that adds a key or lowers the threshold is dist:widening-unsigned. *widened says it widens. */
static uint8_t pp_check_install_trust(const pp_install *r, const pp_install_trust_body *b, const pp_entry *entries,
                                      size_t n_entries, const uint8_t *message, size_t message_len, int widens,
                                      const pp_pep *pep, int *widened) {
    const pp_trust *t = pep->install ? pep->install->trust : NULL;
    int added = 0;
    for (size_t k = 0; k < b->n_keys; k++)
        for (size_t j = 0; j < b->n_operators; j++)
            if (memcmp(b->keys[k], b->operators[j], 32) == 0) return PP_CAUSE_ROTATION_INVALID;
    for (size_t k = 0; k < b->n_keys + b->n_operators; k++) {
        int is_key = k < b->n_keys;
        const uint8_t *public_key = is_key ? b->keys[k] : b->operators[k - b->n_keys];
        uint8_t id[32];
        pp_sha256(public_key, 32, id);
        if (pp_ikey_listed(is_key ? r->keys : r->operators, is_key ? r->n_keys : r->n_operators, id)) continue;
        added = 1;
        if ((pep->has_instance_key_id && memcmp(id, pep->instance_key_id, 32) == 0) ||
            (t && (pp_held_key(t, id) || pp_listed(t->retired, t->n_retired, id) ||
                   pp_listed(t->revoked_keys, t->n_revoked_keys, id))) ||
            pp_listed(r->retired, r->n_retired, id) ||
            pp_ikey_listed(is_key ? r->operators : r->keys, is_key ? r->n_operators : r->n_keys, id))
            return PP_CAUSE_ROTATION_INVALID;
        int signs = 0;
        for (size_t e = 0; e < n_entries; e++)
            if (memcmp(entries[e].key_id, id, 32) == 0)
                signs = crypto_ed25519_check(entries[e].signature, public_key, message, message_len) == 0;
        if (!signs) return PP_CAUSE_ROTATION_INVALID;
    }
    *widened = added || b->threshold < r->threshold;
    if (!widens && *widened) return PP_CAUSE_WIDENING_UNSIGNED;
    return PP_CAUSE_NONE;
}

/* ------------------------------------------------------------------ the image check */

static uint16_t pp_u16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t pp_u32(const uint8_t *p);

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

/* ------------------------------------------------------------------ the table, read for a decision and for AF9 */

/* The parts of a `.ppt` image pp_validate_image passed (policy_pack.read_ppt_header). */
typedef struct {
    const uint8_t *im;
    uint16_t fields, atoms, nodes, edges, words, start;
    size_t atoms_at, nodes_at, edges_at, words_at;
} pp_table;

static int pp_table_read(const uint8_t *im, size_t len, pp_table *t) {
    if (pp_validate_image(im, len)) return 0;
    t->im = im;
    t->fields = pp_u16(im + 6);
    t->atoms = pp_u16(im + 10);
    t->nodes = pp_u16(im + 12);
    t->edges = pp_u16(im + 14);
    t->words = pp_u16(im + 16);
    t->start = pp_u16(im + 18);
    t->atoms_at = 28;
    t->nodes_at = t->atoms_at + 8u * t->atoms;
    t->edges_at = t->nodes_at + 4u * t->nodes;
    t->words_at = t->edges_at + 6u * t->edges;
    for (uint16_t node = 0; node < t->nodes; node++) /* every node's edges inside the edge table */
        if ((uint32_t)pp_u16(im + t->nodes_at + 4u * node) + pp_u16(im + t->nodes_at + 4u * node + 2) > t->edges) return 0;
    return t->start < t->nodes;
}

static int32_t pp_i32(const uint8_t *p) { return (int32_t)pp_u32(p); }

/* ppt_eval.h eval_atom, line for line, over a register file of 4 bytes then 8 per field. -1 for a register the
 * file does not hold. */
static int pp_eval_atom(const pp_table *t, uint16_t index, const uint8_t *regs, size_t regs_len) {
    const uint8_t *atom = t->im + t->atoms_at + 8u * index;
    uint16_t field = pp_u16(atom);
    uint8_t op = atom[2], aty = atom[3];
    int32_t aval = pp_i32(atom + 4);
    if (4u + 8u * ((size_t)field + 1) > regs_len) return -1;
    int32_t rty = pp_i32(regs + 4 + 8u * field), rval = pp_i32(regs + 8 + 8u * field);
    int lnum = rty == 1 || rty == 2, rnum = aty == 1 || aty == 2, eq;
    switch (op) {
    case 0: case 1:
        if (lnum && rnum) eq = rval == aval;
        else if (rty == 3 && aty == 3) eq = rval == aval;
        else eq = rty == 0 && aty == 0;
        return op == 0 ? eq : !eq;
    case 2: return lnum && rnum && rval < aval;
    case 3: return lnum && rnum && rval <= aval;
    case 4: return lnum && rnum && rval > aval;
    case 5: return lnum && rnum && rval >= aval;
    case 6: return rty == 0 ? 0 : rval != 0;
    }
    return -1;
}

/* One edge program, folded on a stack of at most PP_FLOOR_WALK: 1, 0, or -1 when it does not run. */
static int pp_eval_program(const pp_table *t, uint16_t offset, uint16_t count, const uint8_t *regs, size_t regs_len) {
    uint8_t stack[PP_FLOOR_WALK];
    int sp = 0;
    for (uint16_t k = 0; k < count; k++) {
        uint16_t word = pp_u16(t->im + t->words_at + 2u * ((size_t)offset + k));
        if (word < 0x8000 || word == 0x8003 || word == 0x8004) {
            if (sp >= PP_FLOOR_WALK) return -1;
            int v = word < 0x8000 ? pp_eval_atom(t, word, regs, regs_len) : word == 0x8003;
            if (v < 0) return -1;
            stack[sp++] = (uint8_t)v;
        } else if (word == 0x8000) {
            if (sp < 1) return -1;
            stack[sp - 1] = !stack[sp - 1];
        } else {
            if (sp < 2) return -1;
            sp--;
            stack[sp - 1] = word == 0x8001 ? (stack[sp - 1] && stack[sp]) : (stack[sp - 1] || stack[sp]);
        }
    }
    return sp == 1 ? stack[0] : -1;
}

/* The index of the first edge of the start node whose program holds, -1 when none does, -2 when the table cannot
 * be asked (mesh.evaluate). */
static int pp_eval_table(const uint8_t *im, size_t len, const uint8_t *regs, size_t regs_len) {
    pp_table t;
    if (!pp_table_read(im, len, &t)) return -2;
    const uint8_t *node = im + t.nodes_at + 4u * t.start;
    uint16_t first = pp_u16(node), count = pp_u16(node + 2);
    for (uint16_t k = 0; k < count; k++) {
        const uint8_t *edge = im + t.edges_at + 6u * ((size_t)first + k);
        int v = pp_eval_program(&t, pp_u16(edge + 2), pp_u16(edge + 4), regs, regs_len);
        if (v < 0) return -2;
        if (v) return k;
    }
    return -1;
}

static const pp_layout_field *pp_layout_field_of(const pp_layout *layout, uint16_t reg) {
    for (size_t k = 0; k < layout->n; k++)
        if (layout->fields[k].reg == reg) return &layout->fields[k];
    return NULL;
}

/* The conjuncts of the whole rule of one edge program in one postfix pass (floor._program, _tree_conjuncts): each
 * stack entry names a run of a second stack that holds the atoms joined to it by `and` alone. An `and` joins the
 * runs of its operands, which lie side by side; a `not` or an `or` empties its run. Every atom the program reads
 * is held to the layout as it is met. 0 for a program that does not read, holds a field the layout does not label
 * or marks the proposer's, or is deeper than PP_FLOOR_WALK; else the conjunct atoms in `conj` and their count. */
static int pp_floor_conjuncts(const pp_table *t, uint16_t offset, uint16_t count, const pp_layout *layout,
                              uint16_t conj[PP_FLOOR_WALK], size_t *n_conj) {
    uint16_t start[PP_FLOOR_WALK], run[PP_FLOOR_WALK];
    size_t sp = 0, len = 0;
    for (uint16_t k = 0; k < count; k++) {
        uint16_t word = pp_u16(t->im + t->words_at + 2u * ((size_t)offset + k));
        if (word < 0x8000 || word == 0x8003 || word == 0x8004) {
            if (sp >= PP_FLOOR_WALK) return 0;
            start[sp] = (uint16_t)len;
            run[sp] = 0;
            if (word < 0x8000) {
                const pp_layout_field *f = pp_layout_field_of(layout, pp_u16(t->im + t->atoms_at + 8u * word));
                if (f == NULL || f->role == PP_ROLE_PROPOSER || len >= PP_FLOOR_WALK) return 0; /* AF10 */
                conj[len++] = word;
                run[sp] = 1;
            }
            sp++;
        } else if (word == 0x8000) {
            if (sp < 1) return 0;
            len = start[sp - 1];
            run[sp - 1] = 0;
        } else {
            if (sp < 2) return 0;
            sp--;
            if (word == 0x8001) run[sp - 1] = (uint16_t)(run[sp - 1] + run[sp]);
            else {
                len = start[sp - 1];
                run[sp - 1] = 0;
            }
        }
    }
    if (sp != 1) return 0;
    *n_conj = run[0];
    return 1;
}

/* A cfs.table's PPT image inside its body, or NULL for a body that is not a table of the kind's size. */
static const uint8_t *pp_cfs_image(const uint8_t *body, size_t len, size_t *image_len) {
    if (len != PP_CFS_TABLE_MAX || pp_u16(body + PP_CFS_OFF_IMAGE_LEN) > PP_CFS_IMAGE_MAX) return NULL;
    *image_len = pp_u16(body + PP_CFS_OFF_IMAGE_LEN);
    return body + PP_CFS_OFF_IMAGE;
}

/* The action of rule `k` of a cfs.table, 0 allow, 1 refuse, 2 escalate (PP_KIND_* of the app), and its cause. */
static uint8_t pp_cfs_rule(const uint8_t *body, int k, uint16_t *cause) {
    *cause = pp_u16(body + PP_CFS_OFF_RULES + 4u * (unsigned)k + 2);
    return body[PP_CFS_OFF_RULES + 4u * (unsigned)k];
}

/* AF9 over the edges of the start node of `image`. `cfs_body`, when given, is the cfs.table the image is inside: an
 * edge whose rule refuses is silent and so is never a floor rule, the rules are the edges one for one, and the
 * table's own no-match outcome is the refusal its check holds it to. */
static uint8_t pp_floor_narrow_in(const uint8_t *image, size_t len, const pp_layout *layout, int command,
                                  const uint8_t *cfs_body) {
    pp_table t;
    const pp_layout_field *labelled = NULL;
    for (size_t k = 0; k < layout->n; k++)
        if (layout->fields[k].role == PP_ROLE_COMMAND) labelled = &layout->fields[k];
    if (labelled == NULL || command != labelled->reg || !pp_table_read(image, len, &t)) return PP_CAUSE_FLOOR_BROAD;
    for (uint16_t node = 0; node < t.nodes; node++)  /* AF9: one decision node, the start node */
        if (node != t.start && pp_u16(image + t.nodes_at + 4u * node + 2)) return PP_CAUSE_FLOOR_BROAD;
    uint16_t first = pp_u16(image + t.nodes_at + 4u * t.start), edges = pp_u16(image + t.nodes_at + 4u * t.start + 2);
    if (cfs_body && edges != pp_u16(cfs_body + PP_CFS_OFF_RULE_COUNT)) return PP_CAUSE_FLOOR_BROAD;
    size_t rules = 0;
    for (uint16_t k = 0; k < edges; k++) {
        uint16_t rule_cause;
        if (cfs_body && pp_cfs_rule(cfs_body, k, &rule_cause) == 1) continue; /* a refusing rule: the floor is silent */
        rules++;
        const uint8_t *edge = image + t.edges_at + 6u * ((size_t)first + k);
        uint16_t conj[PP_FLOOR_WALK];
        size_t n = 0;
        if (!pp_floor_conjuncts(&t, pp_u16(edge + 2), pp_u16(edge + 4), layout, conj, &n)) return PP_CAUSE_FLOOR_BROAD;
        int names_command = 0;
        for (size_t j = 0; j < n; j++) {
            const uint8_t *atom = image + t.atoms_at + 8u * conj[j];
            names_command |= pp_u16(atom) == labelled->reg && atom[2] == 0 && atom[3] == 2; /* AF9: one action */
        }
        if (!names_command) return PP_CAUSE_FLOOR_BROAD;
        for (size_t f = 0; f < layout->n; f++) {           /* AF9: every parameter bounded from both sides */
            const pp_layout_field *field = &layout->fields[f];
            if (field->role != PP_ROLE_PARAMETER) continue;
            int has_low = 0, has_high = 0;
            long long low = 0, high = 0;
            for (size_t j = 0; j < n; j++) {
                const uint8_t *atom = image + t.atoms_at + 8u * conj[j];
                if (pp_u16(atom) != field->reg || atom[3] != 2) continue;
                long long value = pp_i32(atom + 4);
                uint8_t op = atom[2];
                if (op == 0 || op == 5 || op == 4) {
                    long long bound = value + (op == 4);
                    if (!has_low || bound > low) low = bound;
                    has_low = 1;
                }
                if (op == 0 || op == 3 || op == 2) {
                    long long bound = value - (op == 2);
                    if (!has_high || bound < high) high = bound;
                    has_high = 1;
                }
            }
            if (!has_low || !has_high || (low <= field->min && high >= field->max)) return PP_CAUSE_FLOOR_BROAD;
        }
    }
    if (rules == 0 || rules > PP_FLOOR_RULES) return PP_CAUSE_FLOOR_BROAD;
    return PP_CAUSE_NONE;
}

uint8_t pp_floor_narrow(const uint8_t *image, size_t len, const pp_layout *layout, int command) {
    return pp_floor_narrow_in(image, len, layout, command, NULL);
}

/* AF10: every independent field the edge `k` of the start node tests has a value no older than its bound. */
static int pp_floor_fresh(const uint8_t *image, size_t len, int k, const pp_layout *layout, const uint32_t *ages,
                          size_t n_ages) {
    pp_table t;
    if (layout == NULL || !pp_table_read(image, len, &t)) return 0;
    const uint8_t *edge = image + t.edges_at + 6u * ((size_t)pp_u16(image + t.nodes_at + 4u * t.start) + (size_t)k);
    uint16_t offset = pp_u16(edge + 2), count = pp_u16(edge + 4);
    for (uint16_t w = 0; w < count; w++) {
        uint16_t word = pp_u16(image + t.words_at + 2u * ((size_t)offset + w));
        if (word >= 0x8000) continue;
        uint16_t reg = pp_u16(image + t.atoms_at + 8u * word);
        const pp_layout_field *f = pp_layout_field_of(layout, reg);
        if (f == NULL || f->role != PP_ROLE_INDEPENDENT) continue;
        if (ages == NULL || reg >= n_ages || ages[reg] == PP_AGE_NONE || ages[reg] > f->stale) return 0;
    }
    return 1;
}

/* OP2: an operator's answer, `answer` `allow` or `refuse`, `pep` the PEP id of H1 in 32 lower case hex digits and
 * `receipt` the SHA-256 of the receipt of the escalation it answers (kinds.read_answer). */
static uint8_t pp_read_answer(const uint8_t *body, size_t len, int *allow, uint8_t pep[16], uint8_t receipt[32]) {
    int form = pp_c2_check(body, len);
    if (form == PP_C2_NOT_CANONICAL) return PP_CAUSE_NOT_CANONICAL;
    if (form != PP_C2_OK) return PP_CAUSE_BAD_FORMAT;
    pp_c2 c = {body, len, 0, 1};
    const uint8_t *s;
    size_t n;
    if (!pp_c2_lit(&c, "{\"answer\":\"")) return PP_CAUSE_BAD_FORMAT;
    if (pp_c2_lit(&c, "allow\"")) *allow = 1;
    else if (pp_c2_lit(&c, "refuse\"")) *allow = 0;
    else return PP_CAUSE_BAD_FORMAT;
    if (!pp_c2_lit(&c, ",\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-answer/1\",\"pep\":") ||
        !pp_c2_plain_string(&c, &s, &n) || n != 32)
        return PP_CAUSE_BAD_FORMAT;
    for (size_t k = 0; k < 16; k++) {
        int hi = pp_hex_nibble(s[2 * k]), lo = pp_hex_nibble(s[2 * k + 1]);
        if (hi < 0 || lo < 0) return PP_CAUSE_BAD_FORMAT;
        pep[k] = (uint8_t)(hi << 4 | lo);
    }
    if (!pp_c2_lit(&c, ",\"receipt\":") || !pp_scan_hash(&c, receipt) || !pp_c2_lit(&c, "}") || c.i != c.n)
        return PP_CAUSE_BAD_FORMAT;
    return PP_CAUSE_NONE;
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

/* CL1: a table whose body hash is on the held ceiling's list, or any table when no ceiling is held. */
static int pp_inside(const pp_install_view *view, const uint8_t body_sha256[32]) {
    return view == NULL || !view->has_ceiling || pp_listed(view->ceiling, view->n_ceiling, body_sha256);
}

/* IS5 (verify._verify_install): an install statement through V5 to V11 with the differences section 21 gives
 * them, once V3 counted the install keys against the install threshold. */
static void pp_verify_install(const pp_envelope *e, const pp_entry *entries, size_t n_entries, const uint8_t *message,
                              size_t message_len, const uint8_t *body, size_t body_len, const pp_trust *trust,
                              const pp_pep *pep, long long now, uint8_t installed, pp_verdict *out) {
    const pp_install_view *view = pep->install;
    const pp_install *r = view ? view->record : NULL;
    const pp_row *row = pp_row_of(pep->kind);
    if (r == NULL) { out->cause = PP_CAUSE_UNKNOWN_KEY; return; }
    if (installed) { out->cause = installed; return; }
    /* V5: on the PEP's own stream, by provisioning or, where the install threshold is 2 or more, in a message (IS4),
     * and a set in the form of its kind (IS3): a `mesh` floor or fallback policy is a policy.ppt, its ceiling a list */
    int set = pp_set_of(e->artifact);
    int change = e->artifact == PP_ART_INSTALL_CHANGE;
    if ((view->message && r->threshold < 2) || strcmp(e->stream, pep->stream) != 0) {
        out->cause = PP_CAUSE_TARGET_MISMATCH;
        return;
    }
    if (change && (!(e->targets & PP_BIT(pep->kind)) || pep->kind != PP_TGT_MESH)) {
        out->cause = PP_CAUSE_TARGET_MISMATCH; /* IS14: of the kinds this core has, only mesh takes it */
        return;
    }
    if (set >= 0 && (!(e->targets & PP_BIT(pep->kind)) ||
                     !(e->as == PP_AS_NONE || e->as == (set == PP_SET_CEILING ? PP_AS_POLICY_LIST : pp_table_as(pep->kind))))) {
        out->cause = PP_CAUSE_TARGET_MISMATCH;
        return;
    }
    out->trust_bounded = set < 0 || e->as == PP_AS_POLICY_LIST;
    long long artifact_bound = pep->body_bound < row->body_bound ? pep->body_bound : row->body_bound;
    long long bound = out->trust_bounded ? row->trust_bound : artifact_bound;
    if (e->body_size > bound || (long long)body_len > bound) { out->cause = PP_CAUSE_TOO_LARGE; return; }
    /* V6: T3 where the PEP has a clock; an install statement never raises the time floor (T1, V13), and V7 is never
     * read against an install kind (IS7) */
    long long time = trust->readable && trust->time_floor > now ? trust->time_floor : now;
    if (pep->has_clock && e->not_before - time > PP_SKEW) { out->cause = PP_CAUSE_NOT_YET_VALID; return; }
    /* V8: IS6, IS11. An install change statement's set is in its body, so its V8 follows V9 */
    if (change) {
    } else if (set < 0) {
        if (e->seq == r->trust_seq && memcmp(e->envelope_id, r->trust_id, 32) == 0) { out->unchanged = 1; return; }
        if (e->seq != r->trust_seq + 1) { out->cause = PP_CAUSE_TRUST_REPLAY; return; }
    } else {
        const pp_install_slot *slot = &r->sets[set];
        if (slot->seq && e->seq == slot->seq && memcmp(e->envelope_id, slot->envelope_id, 32) == 0) {
            out->unchanged = 1;
            return;
        }
        if (e->seq <= slot->seq || (view->staged[set] && e->seq < view->staged[set]->seq) ||
            (view->change[set] && e->seq < view->change[set]->seq)) {
            out->cause = PP_CAUSE_SEQ_REPLAY; /* IS4, G2 */
            return;
        }
    }
    /* V9: the body */
    uint8_t hash[32];
    pp_sha256(body, body_len, hash);
    if ((long long)body_len != e->body_size || memcmp(hash, e->body_sha256, 32) != 0) {
        out->cause = PP_CAUSE_BODY_MISMATCH;
        return;
    }
    if (change) { /* IS14: V11, then V8 against the kind its body names, then V10 against what is staged of it */
        if ((out->cause = pp_check_install_change(e, body, body_len, &out->change_set, out->change_from))) return;
        int k = out->change_set;
        const pp_change *ch = view->change[k];
        if (e->seq <= r->sets[k].seq || (view->staged[k] && e->seq < view->staged[k]->seq) || (ch && e->seq < ch->seq)) {
            out->cause = PP_CAUSE_SEQ_REPLAY;
            return;
        }
        if (ch && ch->seq == e->seq && memcmp(ch->envelope_id, e->envelope_id, 32) == 0) { out->unchanged = 1; return; }
        const pp_envelope *with = view->staged[k];
        if ((ch && ch->seq == e->seq) ||
            (with && with->seq == e->seq &&
             (memcmp(with->policy_sha256, e->policy_sha256, 32) != 0 || memcmp(with->release, e->release, 32) != 0 ||
              !pp_same(with->replaces, with->has_replaces, e->replaces, e->has_replaces) || with->widens)))
            out->cause = PP_CAUSE_INCOMPLETE; /* V10: one change statement for one set */
        return;
    }
    /* V10: a set at the seq of the one staged is that set: the same members, and a `mesh` set is one statement */
    const pp_change *carried = set >= 0 ? view->change[set] : NULL;
    if (carried && carried->seq == e->seq &&
        (memcmp(carried->policy_sha256, e->policy_sha256, 32) != 0 || memcmp(carried->release, e->release, 32) != 0 ||
         !e->has_replaces || memcmp(carried->from, e->replaces, 32) != 0 || e->widens)) {
        out->cause = PP_CAUSE_INCOMPLETE; /* V10: the set its change statement was staged for (IS15) */
        return;
    }
    const pp_envelope *st = set >= 0 ? view->staged[set] : NULL;
    if (st && st->seq == e->seq &&
        (memcmp(st->policy_sha256, e->policy_sha256, 32) != 0 || memcmp(st->release, e->release, 32) != 0 ||
         !pp_same(st->replaces, st->has_replaces, e->replaces, e->has_replaces) || st->widens != e->widens ||
         st->has_rate != e->has_rate || st->rate_allows != e->rate_allows || st->rate_window != e->rate_window ||
         st->has_answer_rate != e->has_answer_rate || st->answer_allows != e->answer_allows ||
         st->answer_window != e->answer_window || memcmp(st->envelope_id, e->envelope_id, 32) != 0)) {
        out->cause = PP_CAUSE_INCOMPLETE;
        return;
    }
    /* V11: the check of the artifact `as` names, then the narrowness of an action floor (AF9, AF10), then the
     * ceiling (CL3). The empty set has no check beyond IS1 */
    if (set < 0) {
        static pp_install_trust_body b;
        if ((out->cause = pp_read_install_trust(body, body_len, &b))) return;
        out->cause = pp_check_install_trust(r, &b, entries, n_entries, message, message_len, e->widens, pep,
                                            &out->install_widens);
        return;
    }
    if (e->as == PP_AS_NONE) return;
    if (e->as == PP_AS_POLICY_LIST) {
        static uint8_t hashes[PP_CEILING_BODIES][32];
        size_t n = 0;
        out->cause = pp_read_ceiling(body, body_len, hashes, &n);
        return;
    }
    int cfs = pep->kind == PP_TGT_CFS;
    if ((out->cause = cfs ? pp_check_cfs_table(e, body, body_len) : pp_validate_image(body, body_len))) return;
    if (pep->table_check && (out->cause = pep->table_check(pep->table_context, body, body_len))) return;
    if (set == PP_SET_FLOOR) {
        if (view->layout == NULL || !e->has_layout || memcmp(e->layout, view->layout->sha256, 32) != 0) {
            out->cause = PP_CAUSE_TARGET_MISMATCH; /* AF10: the layout the PEP was built with, or no table floor */
            return;
        }
        int command = e->has_command ? e->command : -1;
        if (cfs) {
            size_t image_len = 0;
            const uint8_t *image = pp_cfs_image(body, body_len, &image_len);
            int escalates = 0;
            for (uint16_t k = 0; k < pp_u16(body + PP_CFS_OFF_RULE_COUNT); k++) {
                uint16_t rule_cause;
                escalates |= pp_cfs_rule(body, k, &rule_cause) == 2;
            }
            escalates |= e->has_rate; /* AF8: past its rate the floor escalates an override */
            if (escalates && !e->has_answer_rate) { out->cause = PP_CAUSE_BAD_FORMAT; return; } /* OP4 */
            if ((out->cause = pp_floor_narrow_in(image, image_len, view->layout, command, body))) return;
        } else if ((out->cause = pp_floor_narrow(body, body_len, view->layout, command))) {
            return;
        }
    }
    if (!pp_inside(view, e->body_sha256)) out->cause = PP_CAUSE_ABOVE_CEILING;
    (void)now;
}

/* OP2 (verify._verify_answer): an operator.answer through V2 to V6 and V9, once V3 counted one operator key (OP1). V5
 * takes it on the PEP's own stream for its own kind, only on cfs, the one kind with escalation this core builds, and
 * an install threshold of 2 or more. V6 holds it to its own time and never raises the time floor (V13). V11 reads
 * its body. Whether it names this PEP and an open escalation is the machine's (dist:answer-unbound). */
static void pp_verify_answer(const pp_envelope *e, const uint8_t *body, size_t body_len, const pp_trust *trust,
                             const pp_pep *pep, long long now, uint8_t answering, pp_verdict *out) {
    const pp_install *r = pep->install ? pep->install->record : NULL;
    const pp_row *row = pp_row_of(pep->kind);
    if (answering) { out->cause = answering; return; }
    if (pep->kind != PP_TGT_CFS || r == NULL || r->threshold < 2 || strcmp(e->stream, pep->stream) != 0 ||
        e->targets != PP_BIT(pep->kind)) {
        out->cause = PP_CAUSE_TARGET_MISMATCH;
        return;
    }
    out->trust_bounded = 1;
    if (e->body_size > row->trust_bound) { out->cause = PP_CAUSE_TOO_LARGE; return; }
    long long time = trust->readable && trust->time_floor > now ? trust->time_floor : now;
    if (pep->has_clock && e->not_before - time > PP_SKEW) { out->cause = PP_CAUSE_NOT_YET_VALID; return; }
    if (time >= e->expires) { out->cause = PP_CAUSE_EXPIRED; return; }
    uint8_t hash[32];
    pp_sha256(body, body_len, hash);
    if ((long long)body_len != e->body_size || memcmp(hash, e->body_sha256, 32) != 0) {
        out->cause = PP_CAUSE_BODY_MISMATCH;
        return;
    }
    int allow;
    uint8_t id[16], receipt[32];
    out->cause = pp_read_answer(body, body_len, &allow, id, receipt);
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
    long long artifact_bound = pep->body_bound < row->body_bound ? pep->body_bound : row->body_bound;
    if ((long long)body_len > (artifact_bound > row->trust_bound ? artifact_bound : row->trust_bound)) {
        out->cause = PP_CAUSE_TOO_LARGE; /* E6: no body past the larger of the two bounds is read */
        return;
    }
    /* V3: the signatures, over the bytes as they came and before the scanner reads them (E9). K4: every role under
     * which the envelope is signed is found, the authority's in the trust store and the install and operator keys'
     * in the install record, and V3 fails only when there is none */
    size_t message_len = pp_signed_message(envelope, envelope_len, message);
    const pp_install *record = pep->install ? pep->install->record : NULL;
    uint8_t authority = pp_counting(trust, entries, n_entries, message, message_len);
    uint8_t installed = pp_role_counting(record, 0, entries, n_entries, message, message_len);
    uint8_t answering = pp_role_counting(record, 1, entries, n_entries, message, message_len);
    pp_envelope *e = &out->envelope;
    if (authority && installed && answering) {
        /* OP1: an answer on a kind with no escalation, or where the install threshold is 1, is dist:target-mismatch
         * whatever its signatures. Read only to name that cause, and nothing read is trusted
         * (verify._answer_out_of_place) */
        if (pp_read_envelope(envelope, envelope_len, e) == PP_CAUSE_NONE && e->artifact == PP_ART_OPERATOR_ANSWER &&
            (pep->kind != PP_TGT_CFS || record == NULL || record->threshold < 2)) {
            memset(e, 0, sizeof *e);
            out->cause = PP_CAUSE_TARGET_MISMATCH;
            return;
        }
        memset(e, 0, sizeof *e);
        out->cause = authority == PP_CAUSE_UNKNOWN_KEY && record ? (installed != PP_CAUSE_UNKNOWN_KEY ? installed : answering)
                                                                : authority;
        return;
    }
    /* V4: the envelope reads */
    if ((out->cause = pp_read_envelope(envelope, envelope_len, e))) return;
    out->has_envelope = 1;
    /* V5, K4: the role the artifact needs is one it is signed under. An install kind is checked on its own path, and
     * the C core reads an answer only on cfs, which has escalation (OP1) */
    if (pp_is_install(e->artifact)) {
        pp_verify_install(e, entries, n_entries, message, message_len, body, body_len, trust, pep, now, installed, out);
        return;
    }
    if (e->artifact == PP_ART_OPERATOR_ANSWER) {
        pp_verify_answer(e, body, body_len, trust, pep, now, answering, out);
        return;
    }
    if ((out->cause = authority)) return;
    /* V5: for this kind, an artifact it uses or a trust kind it applies, on its stream or `@trust`. A revocation or
     * a rotation is for every PEP whatever `targets` says, since one trust sequence counts the same for all (R1) */
    const char *stream = pp_on_trust_stream(e->artifact) ? "@trust" : pep->stream;
    if (!(pp_on_trust_stream(e->artifact) || (e->targets & PP_BIT(pep->kind))) || strcmp(e->stream, stream) != 0 ||
        !((row->uses | row->applies) & PP_BIT(e->artifact))) {
        out->cause = PP_CAUSE_TARGET_MISMATCH;
        return;
    }
    out->trust_bounded = pp_is_trust(e->artifact);
    /* ...then the signed size against the bound of that artifact, before any body is read (E6, B9) */
    if (e->body_size > (pp_is_trust(e->artifact) ? row->trust_bound : artifact_bound)) {
        out->cause = PP_CAUSE_TOO_LARGE;
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
    struct pp_check_args args = {e->artifact, e, body, body_len, trust, pep, entries, n_entries, message, message_len};
    out->cause = e->artifact == PP_ART_TRUST_CHANGE ? pp_check_change(e, body, body_len) : row->check(&args);
    if (!out->cause && e->artifact == pp_table_artifact(pep->kind) && pep->table_check)
        out->cause = pep->table_check(pep->table_context, body, body_len); /* V11: the PEP's own check of its table */
    /* CL2: the table of a release is on the held ceiling's list */
    if (!out->cause && e->artifact == pp_table_artifact(pep->kind) && !pp_inside(pep->install, e->body_sha256))
        out->cause = PP_CAUSE_ABOVE_CEILING;
}

/* ------------------------------------------------------------------ the frame binding (B6, B7, B9, B11) */

static uint32_t pp_u32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

void pp_assembler_init(pp_assembler *a, pp_admit_fn admit, void *context, int ordered, size_t limit,
                       long long artifact_bound) {
    memset(a, 0, sizeof *a);
    a->admit = admit;
    a->context = context;
    a->ordered = ordered;
    a->limit = limit;
    a->artifact_bound = artifact_bound;
    a->trust_bound = PP_TRUST_BOUND;
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
    case PP_FRAME_EPOCH: /* H9: one controller statement */
        return len == 4 + PP_STATEMENT_SIZE || len == 4 + PP_FRESH_STATEMENT_SIZE ? 0 : PP_CAUSE_FRAME_INVALID;
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
        if (!(have[k / 8] & (1u << (k % 8)))) { have[k / 8] |= (uint8_t)(1u << (k % 8)); (*missing)--; }
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

int pp_frame_names(const uint8_t *f, size_t len, const char *stream, long long seq, const uint8_t policy_sha256[32]) {
    if ((len != 46 && len != 44) || (f[0] != PP_FRAME_COMMIT && f[0] != PP_FRAME_ABORT)) return 0;
    uint8_t hash[32];
    uint64_t at = 0;
    pp_sha256((const uint8_t *)stream, strlen(stream), hash);
    for (int k = 7; k >= 0; k--) at = at << 8 | f[20 + k];
    return memcmp(f + 4, hash, 16) == 0 && at == (uint64_t)seq && memcmp(f + 28, policy_sha256, 16) == 0;
}

uint16_t pp_frame_delay(const uint8_t *f, size_t len) {
    return len == 46 && f[0] == PP_FRAME_COMMIT ? pp_u16(f + 44) : 0;
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
        long long larger = a->artifact_bound > a->trust_bound ? a->artifact_bound : a->trust_bound;
        if ((long long)body_len > larger || body_len > PP_ASSEMBLER_BODY_MAX) /* E6: past both bounds */
            return pp_drop(a, transfer, PP_CAUSE_TOO_LARGE, cause);
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
    int trust_bounded = 0;
    if ((why = a->admit(a->context, t->sealed, t->sealed_len, &body_size, t->body_sha256, &trust_bounded)))
        return pp_drop(a, transfer, why, cause);
    if ((size_t)body_size != t->body_len) return pp_drop(a, transfer, PP_CAUSE_FRAME_INVALID, cause);
    if (body_size > (trust_bounded ? a->trust_bound : a->artifact_bound)) /* E6: the artifact's own bound */
        return pp_drop(a, transfer, PP_CAUSE_TOO_LARGE, cause);
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

static int pp_set_part(int kind) { return PP_PART_SET_FLOOR << kind; }

/* 0 when every write of `parts` took (AF8, OP3, H3). */
static int pp_persist(pp_pep_machine *pep, int parts) {
    return pep->config.persist ? pep->config.persist(pep->config.context, &pep->d, parts) : 0;
}

/* The install record the PEP decides with: held and read (IS10). */
static int pp_has_record(const pp_pep_machine *pep) { return pep->d.has_install && !pep->record_lost; }

/* The set of `kind` the PEP holds and reads, or NULL. */
static const pp_statement *pp_held_set(const pp_pep_machine *pep, int kind) {
    if (!pp_has_record(pep) || !pep->d.install.sets[kind].held || pep->set_lost[kind] || !pep->d.sets[kind].has_held)
        return NULL;
    return &pep->d.sets[kind].held;
}

/* IS10: a ceiling the PEP held and no longer reads, so it stages, commits and rolls back nothing. */
static int pp_ceiling_lost(const pp_pep_machine *pep) {
    return pep->set_lost[PP_SET_CEILING] || (pep->record_lost && pep->d.ceiling_mark);
}

/* FB1, FB2, FB6: the fallback policy decides while no release does, in no-policy and in locked, never on hold. */
static int pp_fallback_decides(const pp_pep_machine *pep) {
    return pp_held_set(pep, PP_SET_FALLBACK) != NULL && !pep->held && pp_state(pep) != PP_ST_ACTIVE;
}

void pp_pep_install_id(const pp_pep_machine *pep, uint8_t out[16]) {
    uint8_t text[160], hash[32];
    memset(text, 0, sizeof text);
    memset(out, 0, 16);
    if (!pp_has_record(pep)) return;
    const pp_install *r = &pep->d.install;
    for (int k = 0; k < PP_SETS; k++)
        if (pp_held_set(pep, k)) {
            memcpy(text + 40 * k, r->sets[k].set_id, 32);
            pp_le64(text + 40 * k + 32, (uint64_t)r->sets[k].seq);
        }
    pp_le64(text + 120, (uint64_t)r->trust_seq);
    memcpy(text + 128, r->trust_id, 32);
    pp_sha256(text, sizeof text, hash);
    memcpy(out, hash, 16);
}

/* Make one signed record, its counter durable first (H3), and put it in the outbox. A PEP that holds an install
 * record, or lost the one it held, carries the type 3 entry of H10, with `subject` on the events it names. */
static void pp_emit_about(pp_pep_machine *pep, uint8_t event, uint8_t cause, uint8_t subject);
static void pp_emit(pp_pep_machine *pep, uint8_t event, uint8_t cause) { pp_emit_about(pep, event, cause, 0); }

static void pp_emit_about(pp_pep_machine *pep, uint8_t event, uint8_t cause, uint8_t subject) {
    static const char head[] = "DSSEv1 36 application/vnd.prismpath.dist-state ";
    uint8_t r[PP_RECORD_MAX], message[sizeof head + 8 + PP_RECORD_MAX];
    pep->d.counter++;
    if (pep->d.provisioned) {
        pep->d.counter_reads = 1;
        pp_persist(pep, PP_PART_COUNTER);
    }
    const pp_durable *d = &pep->d;
    uint8_t stream_hash[32];
    pp_sha256((const uint8_t *)pep->d.stream, strlen(pep->d.stream), stream_hash);
    memcpy(r, "PPSR", 4);
    r[4] = 1;
    r[5] = event;
    r[6] = (uint8_t)(pp_state(pep) | (d->has_staged ? 0x80 : 0) | (pep->held ? 0x20 : 0) |
                     (pp_fallback_decides(pep) ? 0x10 : 0)
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
    long long raised = d->trust_reads ? pp_raised(&d->trust, d->stream) : 0;
    pp_le64(r + 104, (uint64_t)(d->floor_seq > raised ? d->floor_seq : raised)); /* H1, R4: the floor V8 holds */
    pp_prefix(r + 112, d->staged.release, d->has_staged);
    pp_le64(r + 128, (uint64_t)(d->has_staged ? d->staged.seq : 0));
    pp_le64(r + 136, (uint64_t)(d->trust_reads ? d->trust.trust_seq : 0));
    r[144] = r[145] = 0; /* no Facet body on mesh and cfs (H5) */
    size_t x = 0;
    if (d->has_install || pep->record_lost) { /* H10: type 3, 27 bytes */
        uint8_t *entry = r + 148;
        entry[0] = 3;
        entry[1] = PP_INSTALL_ENTRY;
        entry[2] = 0;
        pp_pep_install_id(pep, entry + 3);
        uint16_t low = (uint16_t)(pp_has_record(pep) ? d->install.trust_seq : 0);
        entry[19] = (uint8_t)low;
        entry[20] = (uint8_t)(low >> 8);
        int about = event == PP_EV_STAGED || event == PP_EV_REFUSED || event == PP_EV_ANSWERED ||
                    event == PP_EV_INSTALL_APPLIED || event == PP_EV_INSTALL_WIDENED;
        entry[21] = about ? subject : 0;
        for (int k = 0; k < 4; k++) {
            entry[22 + k] = (uint8_t)(d->floor_answers >> (8 * k));
            entry[26 + k] = (uint8_t)(d->floor_overrides >> (8 * k));
        }
        x = 3 + PP_INSTALL_ENTRY;
    }
    r[146] = (uint8_t)x;
    r[147] = (uint8_t)(x >> 8);
    size_t signed_len = 148 + x, at = sizeof head - 1;
    memcpy(message, head, at);
    message[at++] = (uint8_t)('0' + signed_len / 100);
    message[at++] = (uint8_t)('0' + signed_len / 10 % 10);
    message[at++] = (uint8_t)('0' + signed_len % 10);
    message[at++] = ' ';
    memcpy(message + at, r, signed_len);
    crypto_ed25519_sign(r + signed_len, pep->instance_secret, message, at + signed_len);
    if (pep->n_out < PP_OUTBOX) {
        memcpy(pep->out[pep->n_out], r, signed_len + 64);
        pep->out_len[pep->n_out++] = signed_len + 64;
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
        pep->config.runtime(pep->config.context, pp_state(pep) == PP_ST_ACTIVE ? &pep->d.active : NULL,
                            pp_fallback_decides(pep) ? pp_held_set(pep, PP_SET_FALLBACK) : NULL); /* FB1 */
}

static int pp_names(const pp_release *r, const char *stream, long long seq, const uint8_t policy[32]) {
    return strcmp(r->stream, stream) == 0 && r->seq == seq && memcmp(r->policy_sha256, policy, 32) == 0;
}

static uint8_t pp_counts(const pp_trust *trust, const pp_artifact_held *held);

/* C3, RB2: time (T3 when `early`, T4) and revocation (V7) again for every envelope of `release`, and at a commit
 * (`early`) a counting signature again (V3), since a rotation may have retired its key. */
static uint8_t pp_still_valid(const pp_pep_machine *pep, const pp_release *release, int early) {
    long long time = pp_time(pep);
    const pp_trust *t = &pep->d.trust;
    for (size_t k = 0; k < release->n; k++) {
        const pp_envelope *e = &release->held[k].envelope;
        uint8_t counted = early ? pp_counts(t, &release->held[k]) : PP_CAUSE_NONE;
        if (counted) return counted;
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
    pp_persist(pep, PP_PART_ACTIVE);
    pp_runtime(pep);
    pp_emit(pep, pp_held_set(pep, PP_SET_FALLBACK) ? PP_EV_FALLBACK : PP_EV_LAPSED, cause); /* FB3 */
}

/* R5, O3: a held key in the authority role that is not revoked signs the sealed envelope. A retired key still
 * holds up a release already active under it (trust.holds_up). */
static int pp_holds_up(const pp_trust *trust, const pp_artifact_held *held) {
    static uint8_t message[PP_MAX_ENVELOPE + 64];
    const uint8_t *envelope;
    size_t envelope_len, n_entries;
    pp_entry entries[PP_MAX_ENTRIES];
    if (pp_unseal(held->sealed, held->sealed_len, &envelope, &envelope_len, entries, &n_entries)) return 0;
    size_t message_len = pp_signed_message(envelope, envelope_len, message);
    for (size_t k = 0; k < n_entries; k++) {
        const pp_key *key = pp_held_key(trust, entries[k].key_id);
        if (key == NULL || key->role != PP_ROLE_AUTHORITY ||
            pp_listed(trust->revoked_keys, trust->n_revoked_keys, key->id))
            continue;
        if (crypto_ed25519_check(entries[k].signature, key->public_key, message, message_len) == 0) return 1;
    }
    return 0;
}

/* S3 to S5 again for one held envelope: the cause its signatures give under the store as it is now. */
static uint8_t pp_counts(const pp_trust *trust, const pp_artifact_held *held) {
    static uint8_t message[PP_MAX_ENVELOPE + 64];
    const uint8_t *envelope;
    size_t envelope_len, n_entries;
    pp_entry entries[PP_MAX_ENTRIES];
    if (pp_unseal(held->sealed, held->sealed_len, &envelope, &envelope_len, entries, &n_entries)) return PP_CAUSE_BAD_FORMAT;
    size_t message_len = pp_signed_message(envelope, envelope_len, message);
    return pp_counting(trust, entries, n_entries, message, message_len);
}

/* R5: a release still stands when no envelope of it is listed by id or policy hash, its seq is not below a floor
 * a revocation raised, and every envelope of it is still signed. A key that was only retired still holds up a
 * release already active under it (O3), and a staged release needs a counting signature (S5), as at commit. */
static int pp_stands(const pp_pep_machine *pep, const pp_release *release, int active) {
    const pp_trust *t = &pep->d.trust;
    if (release->seq < pp_raised(t, release->stream)) return 0;
    for (size_t k = 0; k < release->n; k++) {
        if (pp_listed(t->revoked_envelopes, t->n_revoked_envelopes, release->held[k].envelope.envelope_id) ||
            pp_listed(t->revoked_policies, t->n_revoked_policies, release->policy_sha256) ||
            !(active ? pp_holds_up(t, &release->held[k]) : pp_counts(t, &release->held[k]) == PP_CAUSE_NONE))
            return 0;
    }
    return 1;
}

static void pp_drop_fallen_staged(pp_pep_machine *pep) {
    if (pep->d.has_staged && pep->d.trust_reads && !pp_stands(pep, &pep->d.staged, 0)) {
        pep->d.has_staged = 0;
        pp_persist(pep, PP_PART_STAGED);
    }
}

/* H16: freshness is on and the PEP's time passed the kept fresh statement's `expires` plus SKEW. */
static int pp_stale(const pp_pep_machine *pep) {
    return pep->d.trust.fresh > 0 && pep->d.has_kept && pp_time(pep) > (long long)pep->d.kept_expires + PP_SKEW;
}

/* A table on the list of a ceiling statement, or any table for none. */
static int pp_on_list(const pp_statement *ceiling, const uint8_t body_sha256[32]) {
    return ceiling == NULL || pp_listed((const uint8_t (*)[32])ceiling->body, ceiling->body_len / 32, body_sha256);
}

/* The table of the active release, its body hash in `hash`, or 0 when none is active. */
static int pp_active_hash(const pp_pep_machine *pep, uint8_t hash[32]) {
    const pp_durable *d = &pep->d;
    if (!d->has_active) return 0;
    for (size_t k = 0; k < d->active.n; k++)
        if (!pp_is_trust(d->active.held[k].envelope.artifact)) {
            memcpy(hash, d->active.held[k].envelope.body_sha256, 32);
            return 1;
        }
    return 0;
}

/* What every entry point and the tick run first (pep._check_active): an active release that no longer stands lapses
 * with dist:revoked (R5, X8), one above the held ceiling with dist:above-ceiling (CL3), also when a power loss came
 * between the ceiling and its lapse, and an expired one lapses or under HOLD is held (X1, X6, X7). */
static void pp_check_expiry(pp_pep_machine *pep) {
    if (!pep->d.has_active || pep->locked || !pep->d.trust_reads) return;
    if (!pp_stands(pep, &pep->d.active, 1)) {
        pp_lapse(pep, PP_CAUSE_REVOKED);
        return;
    }
    uint8_t active_hash[32];
    if (pp_active_hash(pep, active_hash) && !pp_on_list(pp_held_set(pep, PP_SET_CEILING), active_hash)) {
        pp_lapse(pep, PP_CAUSE_ABOVE_CEILING);
        return;
    }
    if (pp_still_valid(pep, &pep->d.active, 0) != PP_CAUSE_EXPIRED && !pp_stale(pep)) return;
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
    pep->answer.applied = 0;
    pp_check_expiry(pep);
}

/* C4: intent, floor (a commit only), then the releases one part at a time in a fixed order, previous, active,
 * staged, then the runtime and the clean up, each persisted. A commit makes the staged release active and keeps
 * the active one as the previous (RB1); a rollback makes the previous one active and keeps none. The releases
 * move in place, so nothing is copied but the one that moves.
 *
 * The order is what a power loss between two parts leaves. After the previous part alone the old release is
 * still active, its previous is itself, and the staged release is still there to commit again, which Q3 lets
 * through since the floor names it. After the active part the new release is active with its right previous,
 * and the staged release left beside it is dropped at the restart (G2). The staged part goes last, so the
 * release being committed is never lost before it is active. A rollback loses at most the rollback itself. */
/* L2: mark the stream a release is committed on, in the anchor part, before the commit. Past PP_LEGACY_STREAMS
 * streams the older forms are refused on every stream. */
static void pp_mark_legacy(pp_pep_machine *pep) {
    pp_durable *d = &pep->d;
    uint8_t hash[32];
    pp_sha256((const uint8_t *)d->stream, strlen(d->stream), hash);
    if (d->legacy_all) return;
    for (size_t k = 0; k < d->n_legacy; k++)
        if (memcmp(d->legacy[k], hash, 16) == 0) return;
    if (d->n_legacy == PP_LEGACY_STREAMS) d->legacy_all = 1;
    else memcpy(d->legacy[d->n_legacy++], hash, 16);
    pp_persist(pep, PP_PART_ANCHOR);
}

uint8_t pp_pep_legacy(const pp_pep_machine *pep, const char *stream) {
    const pp_durable *d = &pep->d;
    uint8_t hash[32];
    if (d->legacy_all || d->install_mark) return PP_CAUSE_LEGACY_REFUSED; /* IS9: every stream */
    pp_sha256((const uint8_t *)stream, strlen(stream), hash);
    for (size_t k = 0; k < d->n_legacy; k++)
        if (memcmp(d->legacy[k], hash, 16) == 0) return PP_CAUSE_LEGACY_REFUSED;
    return PP_CAUSE_NONE;
}

static void pp_flip(pp_pep_machine *pep, int rollback) {
    pp_durable *d = &pep->d;
    if (!rollback) pp_mark_legacy(pep);
    const pp_release *next = rollback ? &d->previous : &d->staged;
    d->has_pending = 1;
    d->pending_rollback = rollback;
    memcpy(d->pending_release, next->release, 32);
    d->pending_seq = next->seq;
    pp_persist(pep, PP_PART_PENDING);
    if (!rollback) {
        d->floor_seq = d->staged.seq;
        d->n_floor_ids = d->staged.n;
        for (size_t k = 0; k < d->staged.n; k++) memcpy(d->floor_ids[k], d->staged.held[k].envelope.envelope_id, 32);
        pp_persist(pep, PP_PART_FLOOR);
        d->has_previous = d->has_active;
        if (d->has_active) d->previous = d->active;
        d->active = d->staged;
        d->has_staged = 0; /* the staged release is the active one now (staged.seq <= active.seq) */
    } else {
        d->active = d->previous;
        d->has_previous = 0;
    }
    d->has_active = 1;
    pep->held = 0;
    pp_persist(pep, PP_PART_PREVIOUS);
    pp_persist(pep, PP_PART_ACTIVE);
    pp_persist(pep, PP_PART_STAGED);
    pp_runtime(pep);
    d->has_pending = 0;
    pp_persist(pep, PP_PART_PENDING);
    pp_emit(pep, rollback ? PP_EV_ROLLED_BACK : PP_EV_COMMITTED, 0);
}

/* IS10 at a start: an install record no copy of which reads is lost, and the PEP holds no set; each set the record
 * names is the statement of the set part whose envelope id it names, held or, after a power loss between the record
 * and the set part, still staged, and its body has the signed hash (pp_durable_unpack held it to that). A set
 * no copy holds is lost: event refused with dist:install-lost, and it leaves the install id. */
static void pp_open_install(pp_pep_machine *pep) {
    pp_durable *d = &pep->d;
    if (d->install_mark && !d->install_reads) {
        pep->record_lost = 1;
        d->has_install = 0;
        pp_emit(pep, PP_EV_REFUSED, PP_CAUSE_INSTALL_LOST);
        return;
    }
    if (!d->has_install) return;
    for (int k = 0; k < PP_SETS; k++) {
        const pp_install_slot *slot = &d->install.sets[k];
        pp_install_set *set = &d->sets[k];
        if (!slot->held) {
            if (set->has_held) { /* a withdrawal cut off after its record */
                set->has_held = 0;
                pp_persist(pep, pp_set_part(k));
            }
            continue;
        }
        if (set->has_held && memcmp(set->held.envelope.envelope_id, slot->envelope_id, 32) == 0) continue;
        if (set->has_staged && memcmp(set->staged.envelope.envelope_id, slot->envelope_id, 32) == 0) {
            set->held = set->staged; /* an apply cut off between the record and the set part */
            set->has_held = 1;
            set->has_staged = 0;
            pp_persist(pep, pp_set_part(k));
            continue;
        }
        pep->set_lost[k] = 1;
        pp_emit_about(pep, PP_EV_REFUSED, PP_CAUSE_INSTALL_LOST, (uint8_t)(k + 1));
    }
}

int pp_pep_open(pp_pep_machine *pep, const pp_config *config, const pp_durable *durable, long long now) {
    if (durable == &pep->d) { /* opened from its own durable state, read in place: clear all but that */
        size_t at = offsetof(pp_pep_machine, d), after = at + sizeof pep->d;
        memset(pep, 0, at);
        memset((uint8_t *)pep + after, 0, sizeof *pep - after);
    } else {
        memset(pep, 0, sizeof *pep);
    }
    pep->config = *config;
    pep->now = now;
    if (pp_row_of(config->kind) == NULL) return -1;
    if (config->expiry_hold && config->kind != PP_TGT_MESH && config->kind != PP_TGT_CFS) return -1; /* X6 */
    crypto_ed25519_key_pair(pep->instance_secret, pep->instance_public, pep->config.instance_seed);
    if (durable == NULL || !durable->provisioned) {
        memset(&pep->d, 0, sizeof pep->d);
        return 0; /* P1: nothing to believe yet */
    }
    if (durable != &pep->d) pep->d = *durable;
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
        pp_persist(pep, PP_PART_PENDING);
    }
    if (pep->d.has_staged && pep->d.has_active && pep->d.staged.seq <= pep->d.active.seq) {
        pep->d.has_staged = 0; /* a commit cut off after its active part left the release staged as well */
        pp_persist(pep, PP_PART_STAGED);
    }
    if (pep->d.has_kept) { /* H16: the kept statement is checked again under the controller key, or is none */
        pp_controller_statement st;
        size_t kept_len = pep->d.kept[37] ? PP_FRESH_STATEMENT_SIZE : PP_STATEMENT_SIZE;
        if (pep->d.trust.fresh <= 0 || pp_statement_verify(pep->d.kept, kept_len, pp_pep_controller_key(pep), &st) ||
            !st.fresh || st.expires != pep->d.kept_expires)
            pep->d.has_kept = 0;
    }
    pep->n_out = 0;
    pep->message = 1;
    if (!pep->d.rates_reads) { /* AF8, OP4: counts no copy holds start every window spent, never a fresh allowance */
        long long time = pp_time(pep);
        for (int k = 0; k < PP_FLOOR_RULES; k++) {
            pep->d.rate_start[k] = time;
            pep->d.rate_count[k] = PP_RATE_SPENT;
        }
        pep->d.answer_start = time;
        pep->d.answer_count = PP_RATE_SPENT;
        pep->d.rates_reads = pp_persist(pep, PP_PART_RATES) == 0;
    }
    /* P1, IS9, IS10: an anchor part that does not read locked the PEP above and keeps its marks; it is reported here,
     * or by pp_open_install when the install record is lost with it */
    if (!pep->d.setting_reads && pep->d.install_reads) pp_emit(pep, PP_EV_REFUSED, PP_CAUSE_INSTALL_LOST);
    pp_open_install(pep);
    pp_drop_fallen_staged(pep); /* R5 and X1 before the runtime, so a release that fell while down never runs */
    int was_active = pep->d.has_active;
    pp_check_expiry(pep);
    pp_runtime(pep);
    if (!(was_active && !pep->d.has_active) && pp_fallback_decides(pep)) /* FB3: a start with nothing committed */
        pp_emit(pep, PP_EV_FALLBACK, pep->locked ? PP_CAUSE_FLOOR_LOST : PP_CAUSE_FALLBACK);
    return 0;
}

static uint8_t pp_stage_one(pp_pep_machine *pep, const uint8_t *sealed, size_t sealed_len, const uint8_t *body,
                            size_t body_len);

static int pp_key_in(const uint8_t (*keys)[32], size_t n, const uint8_t id[32]) {
    for (size_t k = 0; k < n; k++) {
        uint8_t other[32];
        pp_sha256(keys[k], 32, other);
        if (memcmp(other, id, 32) == 0) return 1;
    }
    return 0;
}

/* P2 step 3, P4, K4: the anchor's keys are apart from each other, from the instance key and from what the PEP holds
 * in another role or retired (pep._check_roles), and its install member is of its form and for the domain the PEP
 * was built with. */
static uint8_t pp_check_anchor(const pp_pep_machine *pep, const pp_trust *anchor, const pp_install_anchor *in) {
    const pp_durable *d = &pep->d;
    const pp_install *held = pp_has_record(pep) ? &d->install : NULL;
    uint8_t instance[32];
    pp_sha256(pep->instance_public, 32, instance);
    size_t controllers = 0;
    for (size_t k = 0; k < anchor->n_keys; k++) {
        if (memcmp(anchor->keys[k].id, instance, 32) == 0 || pp_install_names(held, anchor->keys[k].id))
            return PP_CAUSE_ROTATION_INVALID; /* K2, K4 */
        for (size_t j = 0; j < k; j++)
            if (memcmp(anchor->keys[j].id, anchor->keys[k].id, 32) == 0) return PP_CAUSE_ROTATION_INVALID; /* K4 */
        controllers += anchor->keys[k].role == PP_ROLE_CONTROLLER;
    }
    if (controllers > 1 || anchor->fresh < 0) return PP_CAUSE_BAD_FORMAT; /* K6, P4 */
    if (in == NULL || !in->present) return PP_CAUSE_NONE;
    if (in->n_keys < 1 || in->n_keys > PP_INSTALL_KEYS || in->n_operators > PP_OPERATOR_KEYS || in->threshold < 1 ||
        in->threshold > (long long)in->n_keys || in->seq < 0)
        return PP_CAUSE_BAD_FORMAT;
    for (size_t k = 0; k < in->n_keys + in->n_operators; k++) {
        int is_key = k < in->n_keys;
        uint8_t id[32];
        pp_sha256(is_key ? in->keys[k] : in->operators[k - in->n_keys], 32, id);
        if (memcmp(id, instance, 32) == 0 || pp_held_key(anchor, id) || (is_key && pp_key_in(in->operators, in->n_operators, id)))
            return PP_CAUSE_ROTATION_INVALID;
        if (d->trust_reads && (pp_held_key(&d->trust, id) || pp_listed(d->trust.retired, d->trust.n_retired, id)))
            return PP_CAUSE_ROTATION_INVALID;
        if (held && ((is_key && (pp_ikey_listed(held->operators, held->n_operators, id))) ||
                     (!is_key && pp_ikey_listed(held->keys, held->n_keys, id)) ||
                     pp_listed(held->retired, held->n_retired, id)))
            return PP_CAUSE_ROTATION_INVALID;
    }
    if (!pep->config.has_domain || memcmp(in->domain, pep->config.domain_sha256, 32) != 0)
        return PP_CAUSE_TARGET_MISMATCH; /* P4, CL4 */
    return PP_CAUSE_NONE;
}

/* IS6, P4 (pep._provisioned_record): the install record a provisioning leaves in `out`, *has 0 for none. An anchor
 * with no install member leaves the held one. One whose install trust sequence is below the held one is refused,
 * one at the same number brings the same key set, and one above it may bring another: every key it leaves out is
 * retired, and only a key set that shares no key with the held one starts the install sequences again and drops the
 * held sets. The install trust id becomes the anchor's fingerprint. *keeps says the held sets stay. */
static uint8_t pp_next_record(const pp_pep_machine *pep, const pp_install_anchor *in, pp_install *out, int *has,
                              int *keeps) {
    const pp_install *held = pp_has_record(pep) ? &pep->d.install : NULL;
    *keeps = 1;
    if (in == NULL || !in->present) {
        *has = held != NULL;
        if (held) *out = *held;
        return PP_CAUSE_NONE;
    }
    static pp_install part; /* off the stack: a record is about a kilobyte */
    memset(&part, 0, sizeof part);
    part.n_keys = in->n_keys;
    for (size_t k = 0; k < in->n_keys; k++) {
        memcpy(part.keys[k].public_key, in->keys[k], 32);
        pp_sha256(in->keys[k], 32, part.keys[k].id);
    }
    part.n_operators = in->n_operators;
    for (size_t k = 0; k < in->n_operators; k++) {
        memcpy(part.operators[k].public_key, in->operators[k], 32);
        pp_sha256(in->operators[k], 32, part.operators[k].id);
    }
    part.threshold = in->threshold;
    part.trust_seq = in->seq;
    memcpy(part.trust_id, in->fingerprint, 32);
    memcpy(part.domain, in->domain, 32);
    *has = 1;
    if (held == NULL) {
        *out = part;
        *keeps = 0;
        return PP_CAUSE_NONE;
    }
    if (part.trust_seq < held->trust_seq) return PP_CAUSE_TRUST_REPLAY;
    int same = part.n_keys == held->n_keys && part.n_operators == held->n_operators && part.threshold == held->threshold;
    for (size_t k = 0; same && k < part.n_keys; k++) same = pp_ikey_listed(held->keys, held->n_keys, part.keys[k].id);
    for (size_t k = 0; same && k < part.n_operators; k++)
        same = pp_ikey_listed(held->operators, held->n_operators, part.operators[k].id);
    if (part.trust_seq == held->trust_seq) {
        if (!same) return PP_CAUSE_TRUST_REPLAY;
        *out = *held;
        memcpy(out->trust_id, in->fingerprint, 32);
        memcpy(out->domain, in->domain, 32);
        return PP_CAUSE_NONE;
    }
    int shares = 0;
    for (size_t k = 0; k < part.n_keys; k++) shares |= pp_ikey_listed(held->keys, held->n_keys, part.keys[k].id);
    memcpy(part.retired, held->retired, sizeof part.retired);
    part.n_retired = held->n_retired;
    for (size_t k = 0; k < held->n_keys + held->n_operators; k++) { /* sorted within the provisioning, as _retire */
        const uint8_t *id = k < held->n_keys ? held->keys[k].id : held->operators[k - held->n_keys].id;
        if (pp_ikey_listed(part.keys, part.n_keys, id) || pp_ikey_listed(part.operators, part.n_operators, id) ||
            pp_listed((const uint8_t (*)[32])part.retired, part.n_retired, id))
            continue;
        if (part.n_retired == PP_INSTALL_RETIRED) {
            memmove(part.retired[0], part.retired[1], (PP_INSTALL_RETIRED - 1) * 32);
            part.n_retired--;
        }
        memcpy(part.retired[part.n_retired++], id, 32);
    }
    if (shares) memcpy(part.sets, held->sets, sizeof part.sets);
    *keeps = shares;
    *out = part;
    return PP_CAUSE_NONE;
}

static const char *pp_as_name(uint8_t as);
static void pp_install_take_trust(pp_install *r, const pp_envelope *e, const uint8_t *body, size_t len);
static uint8_t pp_read_ceiling(const uint8_t *body, size_t len, uint8_t (*out)[32], size_t *n);
static uint8_t pp_set_refusal(const pp_pep_machine *pep, const pp_install *r, const pp_statement *const held_sets[PP_SETS],
                              const pp_change *change, const pp_statement *st, int kind, int ceiling_lost, int *larger_out);

/* P2 step 3 (pep._precheck): every install statement the engineer brings verifies under the install record the
 * provisioning leaves (`next`, *has and *keeps as pp_next_record left them) and the anchor's store, whose time floor
 * is its own, before anything changes. The statements are taken in order as pp_stage_one then stages them: each
 * against the record as the ones before it leave it, the sets staged so far (V10) and the ceiling then held (CL3),
 * and a set that is whole is held to pp_set_refusal, as pp_apply_set holds it. Any refusal refuses the provisioning
 * but dist:seq-replay, a set the PEP already holds at or above its `seq`, which is refused and leaves the
 * provisioning to go on (case 170, IS6). */
static uint8_t pp_precheck(const pp_pep_machine *pep, const pp_trust *anchor, const char *stream, const pp_install *next,
                           int has, int keeps, const pp_brought *brought, size_t n_brought, long long now) {
    static pp_install record;
    static pp_pep view;
    static pp_install_view iview;
    static pp_verdict verdict;
    static pp_statement one, made[PP_SETS]; /* the set being checked, and each set the statements before it applied */
    static pp_envelope pending[PP_SETS];    /* each set staged and not yet whole (IS4, G2) */
    static pp_change changes[PP_SETS];      /* each install change statement staged (IS15) */
    if (n_brought == 0) return PP_CAUSE_NONE;
    if (!has) return PP_CAUSE_BAD_FORMAT; /* install statements with an anchor that holds no install keys */
    record = *next;
    const pp_statement *held_sets[PP_SETS];
    int has_pending[PP_SETS], has_change[PP_SETS];
    for (int k = 0; k < PP_SETS; k++) {
        held_sets[k] = keeps && record.sets[k].held && !pep->set_lost[k] && pep->d.sets[k].has_held
                           ? &pep->d.sets[k].held : NULL;
        has_pending[k] = has_change[k] = 0;
    }
    /* IS10: the provisioning keeps a lost ceiling lost while the record it leaves still names it */
    int ceiling_lost = keeps && pep->set_lost[PP_SET_CEILING] && record.sets[PP_SET_CEILING].held;
    for (size_t k = 0; k < n_brought; k++) {
        memset(&view, 0, sizeof view);
        memset(&iview, 0, sizeof iview);
        view.kind = pep->config.kind;
        pp_copy_stream(view.stream, stream);
        view.body_bound = PP_MAX_BODY;
        view.has_clock = pep->config.has_clock;
        view.has_instance_key_id = 1;
        pp_sha256(pep->instance_public, 32, view.instance_key_id);
        view.table_check = pep->config.table_check;
        view.table_context = pep->config.context;
        iview.record = &record;
        for (int j = 0; j < PP_SETS; j++) {
            iview.staged[j] = has_pending[j] ? &pending[j] : NULL;
            iview.change[j] = has_change[j] ? &changes[j] : NULL;
        }
        if (held_sets[PP_SET_CEILING]) {
            iview.has_ceiling = 1;
            iview.ceiling = (const uint8_t (*)[32])held_sets[PP_SET_CEILING]->body;
            iview.n_ceiling = held_sets[PP_SET_CEILING]->body_len / 32;
        }
        iview.layout = pep->config.layout;
        iview.trust = anchor;
        view.install = &iview;
        pp_verify(brought[k].sealed, brought[k].sealed_len, brought[k].body, brought[k].body_len, anchor, &view, now,
                  &verdict);
        const pp_envelope *e = &verdict.envelope;
        if (!verdict.has_envelope || !pp_is_install(e->artifact)) return PP_CAUSE_BAD_FORMAT;
        if (verdict.cause == PP_CAUSE_SEQ_REPLAY) continue; /* case 170: refused, the provisioning goes on */
        if (verdict.cause) return verdict.cause;
        if (verdict.unchanged) continue;
        if (e->artifact == PP_ART_INSTALL_TRUST) { /* IS11: the statements after it verify under it */
            pp_install_take_trust(&record, e, brought[k].body, brought[k].body_len);
            continue;
        }
        if (e->artifact == PP_ART_INSTALL_CHANGE) { /* IS15, as pp_stage_change holds it */
            int kind = verdict.change_set;
            const pp_statement *held = held_sets[kind];
            if (held == NULL || memcmp(verdict.change_from, held->envelope.policy_sha256, 32) != 0)
                return PP_CAUSE_WIDENING_UNSIGNED;
            if (has_pending[kind] && pending[kind].seq != e->seq) has_pending[kind] = 0; /* G2 */
            has_change[kind] = 1;
            memset(&changes[kind], 0, sizeof changes[kind]);
            changes[kind].seq = e->seq;
            memcpy(changes[kind].policy_sha256, e->policy_sha256, 32);
            memcpy(changes[kind].release, e->release, 32);
            memcpy(changes[kind].from, verdict.change_from, 32);
            memcpy(changes[kind].envelope_id, e->envelope_id, 32);
            continue;
        }
        int kind = pp_set_of(e->artifact);
        if (has_change[kind] && changes[kind].seq != e->seq) has_change[kind] = 0; /* G2 */
        memset(&one, 0, sizeof one);
        one.envelope = *e;
        if (e->as == PP_AS_POLICY_LIST) {
            size_t n = 0;
            pp_read_ceiling(brought[k].body, brought[k].body_len, (uint8_t (*)[32])one.body, &n);
            one.body_len = 32 * n;
        } else {
            one.body_len = brought[k].body_len;
            memcpy(one.body, brought[k].body, brought[k].body_len);
        }
        uint8_t release[32];
        pp_release_of_one(pp_as_name(e->as), e->body_sha256, release);
        if (memcmp(release, e->release, 32) != 0) { /* not whole: staged, and applied by nothing here */
            pending[kind] = *e;
            has_pending[kind] = 1;
            continue;
        }
        int larger = 0;
        uint8_t cause = pp_set_refusal(pep, &record, held_sets, has_change[kind] ? &changes[kind] : NULL, &one, kind,
                                       ceiling_lost, &larger);
        if (cause == PP_CAUSE_SEQ_REPLAY) continue;
        if (cause) return cause;
        int empty = e->as == PP_AS_NONE;
        pp_install_slot *slot = &record.sets[kind]; /* as pp_apply_set leaves the record */
        slot->seq = e->seq;
        slot->held = !empty;
        memcpy(slot->envelope_id, e->envelope_id, 32);
        pp_sha256(e->envelope_id, 32, slot->set_id);
        memcpy(slot->policy_sha256, e->policy_sha256, 32);
        memcpy(slot->body_sha256, e->body_sha256, 32);
        made[kind] = one;
        held_sets[kind] = empty ? NULL : &made[kind];
        has_pending[kind] = has_change[kind] = 0;
        if (kind == PP_SET_CEILING) ceiling_lost = 0;
    }
    return PP_CAUSE_NONE;
}

uint8_t pp_pep_provision_install(pp_pep_machine *pep, const pp_trust *anchor, const pp_install_anchor *install,
                                 const char *stream, const pp_brought *brought, size_t n_brought, long long now) {
    static pp_install next;
    pep->now = now;
    pep->n_out = 0;
    pep->stood_out = 0;
    int has = 0, keeps = 1;
    uint8_t cause = pp_check_anchor(pep, anchor, install);
    if (!cause) cause = pp_next_record(pep, install, &next, &has, &keeps);
    if (cause) return cause;
    cause = pp_precheck(pep, anchor, stream, &next, has, keeps, brought, n_brought, now);
    if (cause) return cause;
    pp_durable *d = &pep->d;
    uint64_t counter = d->counter;
    /* what no provisioning clears: the marks of the anchor part, the counts of H10 and AF8, and the held sets the
     * new record keeps (P3, P4, IS6, IS9) */
    int install_mark = d->install_mark || has, legacy_all = d->legacy_all;
    size_t n_legacy = d->n_legacy;
    uint8_t legacy[PP_LEGACY_STREAMS][16];
    memcpy(legacy, d->legacy, sizeof legacy);
    uint32_t answers = d->floor_answers, overrides = d->floor_overrides;
    long long rate_start[PP_FLOOR_RULES];
    uint32_t rate_count[PP_FLOOR_RULES];
    memcpy(rate_start, d->rate_start, sizeof rate_start);
    memcpy(rate_count, d->rate_count, sizeof rate_count);
    int lost[PP_SETS];
    for (int k = 0; k < PP_SETS; k++) {
        lost[k] = pep->set_lost[k];
        if (!keeps || !has) d->sets[k].has_held = 0;
        d->sets[k].has_staged = d->sets[k].has_change = 0;
    }
    memset(d, 0, offsetof(pp_durable, sets)); /* the held statements, the last member, stay where they are */
    d->provisioned = d->setting_reads = d->trust_reads = d->floor_reads = d->counter_reads = 1;
    d->install_reads = d->rates_reads = 1;
    for (int k = 0; k < PP_SETS; k++) d->set_reads[k] = 1;
    d->expiry_hold = pep->config.expiry_hold;
    d->trust = *anchor;
    d->trust.readable = 1;
    d->trust.trust_seq = 0;
    d->trust.time_floor = 0;
    d->trust.key_seq = 0; /* K6: the anchor names the first controller key at key sequence 0 */
    pp_copy_stream(d->stream, stream);
    d->counter = counter;
    d->install_mark = install_mark;
    d->legacy_all = legacy_all;
    d->n_legacy = n_legacy;
    memcpy(d->legacy, legacy, sizeof legacy);
    d->floor_answers = answers;
    d->floor_overrides = overrides;
    memcpy(d->rate_start, rate_start, sizeof rate_start);
    memcpy(d->rate_count, rate_count, sizeof rate_count);
    d->has_install = has;
    if (has) d->install = next;
    pep->record_lost = 0;
    for (int k = 0; k < PP_SETS; k++) {
        pep->set_lost[k] = has && keeps ? lost[k] && next.sets[k].held : 0;
        if (has && !keeps) memset(&d->install.sets[k], 0, sizeof d->install.sets[k]);
    }
    d->ceiling_mark = has && d->install.sets[PP_SET_CEILING].held;
    pep->locked = pep->held = 0;
    pep->commit_due = 0;
    pep->epoch = 0;      /* H15, P3 */
    pep->time_taken = 0; /* H16: the kept statement went with the parts cleared above */
    pp_runtime(pep);
    if (pp_persist(pep, PP_PARTS) != 0) {
        /* AF8, OP3, P1: a provisioning whose state did not save is not acted on. What the store holds is not what
         * the PEP now holds, so it is locked, stages nothing it brought, and the cause says why */
        pep->locked = 1;
        return PP_CAUSE_SAVE_FAILED;
    }
    pep->message = 0;
    size_t kept = 0; /* P3: provisioning reports as its own event, and a statement it brought that was refused keeps its
                      * record, the last one its staging made */
    for (size_t k = 0; k < n_brought; k++) {
        pep->n_out = kept;
        if (pp_stage_one(pep, brought[k].sealed, brought[k].sealed_len, brought[k].body, brought[k].body_len) &&
            pep->n_out > kept) {
            size_t last = pep->n_out - 1;
            if (last != kept) {
                memcpy(pep->out[kept], pep->out[last], pep->out_len[last]);
                pep->out_len[kept] = pep->out_len[last];
            }
            kept++;
        }
    }
    pep->message = 1;
    pep->n_out = kept;
    pp_emit(pep, PP_EV_PROVISIONED, pep->stood_out ? PP_CAUSE_INSTALL_WIDENED : 0);
    if (n_brought) pp_runtime(pep); /* FB1: a fallback policy brought decides at once */
    return PP_CAUSE_NONE;
}

void pp_pep_provision(pp_pep_machine *pep, const pp_trust *anchor, const char *stream, long long now) {
    (void)pp_pep_provision_install(pep, anchor, NULL, stream, NULL, 0, now);
}

uint8_t pp_pep_install_provision(pp_pep_machine *pep, const pp_brought *brought, size_t n_brought, long long now) {
    pp_begin(pep, now);
    if (pep->record_lost) return PP_CAUSE_INSTALL_LOST;
    if (!pep->d.provisioned || !pp_has_record(pep)) return PP_CAUSE_UNKNOWN_KEY;
    pep->message = 0;
    for (size_t k = 0; k < n_brought; k++)
        (void)pp_stage_one(pep, brought[k].sealed, brought[k].sealed_len, brought[k].body, brought[k].body_len);
    pep->message = 1;
    return PP_CAUSE_NONE;
}

/* trust.apply_revocation: the store after a verified revocation at the next trust sequence (R1). The PEP holds this
 * list and no other, so what it refuses is bounded by R7 (R2, R6), and a floor the list raises is kept for the
 * PEP's own stream and only rises (R4). */
static uint8_t pp_apply_revocation(pp_pep_machine *pep, const pp_envelope *e, const uint8_t *body, size_t len) {
    static pp_revocation_list list;
    pp_trust *t = &pep->d.trust;
    uint8_t cause = pp_read_revocation(body, len, pep->d.stream, &list); /* V11 read it and held it to R6 and R7 */
    if (cause) return cause;   /* the store is left exactly as it was */
    memcpy(t->revoked_envelopes, list.envelopes, 32 * list.n_envelopes);
    memcpy(t->revoked_keys, list.keys, 32 * list.n_keys);
    memcpy(t->revoked_policies, list.policies, 32 * list.n_policies);
    t->n_revoked_envelopes = list.n_envelopes;
    t->n_revoked_keys = list.n_keys;
    t->n_revoked_policies = list.n_policies;
    long long raised = pp_raised(t, pep->d.stream);
    if (list.floor > raised) raised = list.floor;
    t->n_floors = 0;
    if (raised) {
        pp_copy_stream(t->floors[0].stream, pep->d.stream);
        t->floors[0].seq = raised;
        t->n_floors = 1;
    }
    t->trust_seq = e->seq;
    memcpy(t->trust_id, e->envelope_id, 32);
    t->has_trust_id = 1;
    pp_persist(pep, PP_PART_TRUST);
    return 0;
}

/* trust.apply_rotation: the store after a verified rotation at the next trust sequence (O1). The one it names is
 * retired (O3), its id kept in order, oldest first, and a seventeenth retired id forgets the oldest and its key
 * (K5). Only then is the new key held in the authority role, so a store at its bound of 8 keys that count and 16
 * retired has the slot the forgotten key freed. */
static void pp_apply_rotation(pp_pep_machine *pep, const pp_envelope *e, const uint8_t *body, size_t len) {
    pp_trust *t = &pep->d.trust;
    uint8_t add[32], retire[32], id[32];
    int has_retire = 0;
    pp_read_rotation(body, len, add, &has_retire, retire); /* V11 read it and held it to O2 to O4 and K5 */
    if (has_retire && !pp_listed((const uint8_t (*)[32])t->retired, t->n_retired, retire)) {
        if (t->n_retired == PP_MAX_RETIRED) { /* K5: forget the oldest retired id and its key */
            for (size_t k = 0; k < t->n_keys; k++)
                if (memcmp(t->keys[k].id, t->retired[0], 32) == 0) {
                    memmove(&t->keys[k], &t->keys[k + 1], (t->n_keys - k - 1) * sizeof t->keys[0]);
                    t->n_keys--;
                    break;
                }
            memmove(t->retired[0], t->retired[1], (PP_MAX_RETIRED - 1) * 32);
            t->n_retired--;
        }
        memcpy(t->retired[t->n_retired++], retire, 32);
    }
    pp_sha256(add, 32, id);
    pp_key *held = (pp_key *)pp_held_key(t, id);
    if (held == NULL && t->n_keys < PP_MAX_HELD_KEYS) held = &t->keys[t->n_keys++];
    if (held != NULL) {
        memcpy(held->id, id, 32);
        memcpy(held->public_key, add, 32);
        held->role = PP_ROLE_AUTHORITY;
    }
    t->trust_seq = e->seq;
    memcpy(t->trust_id, e->envelope_id, 32);
    t->has_trust_id = 1;
    pp_persist(pep, PP_PART_TRUST);
}

/* trust.apply_controller: the store after a verified `trust.controller` at the next trust sequence (K7). The key
 * named becomes the controller key and the one it replaces is retired, a seventeenth retired id forgetting the
 * oldest and its key (K5). A key that is already the controller key stays. Either way the envelope's `seq` is the
 * key sequence, and the epoch id starts again at 0 (H15). */
static void pp_apply_controller(pp_pep_machine *pep, const pp_envelope *e, const uint8_t *body, size_t len) {
    pp_trust *t = &pep->d.trust;
    uint8_t key[32], id[32];
    (void)pp_read_controller(body, len, key); /* V11 read it and held it to K7 */
    pp_sha256(key, 32, id);
    const pp_key *held = pp_controller_of(t);
    if (held == NULL || memcmp(held->id, id, 32) != 0) {
        if (held != NULL) {
            if (t->n_retired == PP_MAX_RETIRED) { /* K5: forget the oldest retired id and its key */
                for (size_t k = 0; k < t->n_keys; k++)
                    if (memcmp(t->keys[k].id, t->retired[0], 32) == 0) {
                        if (&t->keys[k] < held) held--;
                        memmove(&t->keys[k], &t->keys[k + 1], (t->n_keys - k - 1) * sizeof t->keys[0]);
                        t->n_keys--;
                        break;
                    }
                memmove(t->retired[0], t->retired[1], (PP_MAX_RETIRED - 1) * 32);
                t->n_retired--;
            }
            memcpy(t->retired[t->n_retired++], held->id, 32);
        }
        if (t->n_keys < PP_MAX_HELD_KEYS) {
            pp_key *added = &t->keys[t->n_keys++];
            memcpy(added->id, id, 32);
            memcpy(added->public_key, key, 32);
            added->role = PP_ROLE_CONTROLLER;
        }
    }
    t->key_seq = e->seq;
    t->trust_seq = e->seq;
    memcpy(t->trust_id, e->envelope_id, 32);
    t->has_trust_id = 1;
    pp_persist(pep, PP_PART_TRUST);
    pep->epoch = 0;
}

static void pp_refuse(pp_pep_machine *pep, uint8_t cause) {
    pp_emit(pep, PP_EV_REFUSED, cause);
}

/* W4: `kept` holds a widening statement whose `from` is empty or holds the active policy hash (widening.covers). */
static int pp_covers(const pp_pep_machine *pep, const pp_release *kept) {
    for (size_t k = 0; k < kept->n; k++) {
        if (kept->held[k].envelope.artifact != PP_ART_TRUST_WIDENING) continue;
        const uint8_t *body = pp_held_body((pp_release *)kept, k);
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

/* W11: `with` holds a change statement whose `from` is the active policy hash, so none stands for a first install. */
static int pp_changes(const pp_pep_machine *pep, const pp_release *with) {
    if (!pep->d.has_active) return 0;
    for (size_t k = 0; k < with->n; k++) {
        if (with->held[k].envelope.artifact != PP_ART_TRUST_CHANGE) continue;
        uint8_t from[32];
        if (pp_read_change(pp_held_body((pp_release *)with, k), with->held[k].body_len, from)) return 0;
        return memcmp(from, pep->d.active.policy_sha256, 32) == 0;
    }
    return 0;
}

/* The active release's table, or NULL when there is none. */
static const uint8_t *pp_active_table(const pp_pep_machine *pep, size_t *len) {
    const pp_durable *d = &pep->d;
    if (!d->has_active) return NULL;
    for (size_t k = 0; k < d->active.n; k++)
        if (!pp_is_trust(d->active.held[k].envelope.artifact)) {
            *len = d->active.held[k].body_len;
            return pp_held_body((pp_release *)&d->active, k);
        }
    return NULL;
}

/* V12 on a kind that cannot decide (W2, W3, W6): a release is larger unless its `widens` is false and its
 * `replaces` is the active policy hash, and a larger one needs a widening statement of the same release, staged
 * before it, that covers the node (widening.check). The node still compares the table: one that is not byte for
 * byte the active table is larger, and when its `widens` is false the signer's word is wrong and no statement
 * saves it. `table` is the staged table, or NULL when the envelope judged carries none. */
static uint8_t pp_widening(const pp_pep_machine *pep, int widens, const uint8_t replaces[32], int has_replaces,
                           const pp_release *with, const uint8_t *table, size_t table_len) {
    const pp_durable *d = &pep->d;
    size_t active_len = 0;
    const uint8_t *active = pp_active_table(pep, &active_len);
    /* Going from no policy to any is a comparison every PEP makes, so a first install is larger and one that says
     * it does not widen is refused even with a statement (W6), as another table is. */
    int changed = !d->has_active ||
                  (pep->config.kind == PP_TGT_MESH && table != NULL && active != NULL &&
                   (table_len != active_len || memcmp(table, active, table_len) != 0)); /* W2: cfs compares nothing */
    int larger = changed || widens || !has_replaces || memcmp(replaces, d->active.policy_sha256, 32) != 0;
    if (!larger) return PP_CAUSE_NONE;
    /* W11: a change statement the authority signed stands in place of a widening statement for a release that says
     * it does not widen and replaces the active policy. The node compares nothing more than W2 does. */
    if (!widens && d->has_active && has_replaces && memcmp(replaces, d->active.policy_sha256, 32) == 0 && with != NULL &&
        pp_changes(pep, with))
        return PP_CAUSE_NONE;
    if (changed && !widens) return PP_CAUSE_WIDENING_UNSIGNED; /* W6 */
    return with != NULL && pp_covers(pep, with) ? PP_CAUSE_NONE : PP_CAUSE_WIDENING_UNSIGNED;
}

void pp_pep_view(const pp_pep_machine *pep, pp_pep *out) {
    const pp_durable *d = &pep->d;
    memset(out, 0, sizeof *out);
    out->kind = pep->config.kind;
    pp_copy_stream(out->stream, d->stream);
    out->floor_seq = d->floor_seq;
    out->n_floor_ids = d->n_floor_ids;
    memcpy(out->floor_ids, d->floor_ids, sizeof out->floor_ids);
    out->body_bound = PP_MAX_BODY;
    out->has_clock = pep->config.has_clock;
    out->has_instance_key_id = 1;
    pp_sha256(pep->instance_public, 32, out->instance_key_id);
    out->table_check = pep->config.table_check;
    out->table_context = pep->config.context;
    if (pp_has_record(pep)) { /* section 21: the install part, a view the machine keeps */
        pp_install_view *v = (pp_install_view *)&pep->install_view;
        memset(v, 0, sizeof *v);
        v->record = &d->install;
        for (int k = 0; k < PP_SETS; k++) {
            v->staged[k] = d->sets[k].has_staged ? &d->sets[k].staged.envelope : NULL;
            v->change[k] = d->sets[k].has_change ? &d->sets[k].change : NULL;
        }
        v->message = pep->message;
        const pp_statement *ceiling = pp_held_set(pep, PP_SET_CEILING);
        if (ceiling) {
            v->has_ceiling = 1;
            v->ceiling = (const uint8_t (*)[32])ceiling->body;
            v->n_ceiling = ceiling->body_len / 32;
        }
        v->layout = pep->config.layout;
        v->trust = d->trust_reads ? &d->trust : NULL;
        out->install = v;
    }
    if (d->has_staged) {
        out->has_staged = 1;
        pp_copy_stream(out->staged.stream, d->staged.stream);
        out->staged.seq = d->staged.seq;
        memcpy(out->staged.policy_sha256, d->staged.policy_sha256, 32);
        memcpy(out->staged.release, d->staged.release, 32);
        memcpy(out->staged.replaces, d->staged.replaces, 32);
        out->staged.has_replaces = d->staged.has_replaces;
        out->staged.widens = d->staged.widens;
    }
}

static int pp_on_trust_stream(pp_artifact artifact);

static const char *pp_as_name(uint8_t as) {
    return as == PP_AS_POLICY_PPT ? "policy.ppt" : as == PP_AS_POLICY_LIST ? "policy.list"
           : as == PP_AS_CFS_TABLE ? "cfs.table" : "none";
}

/* A held statement's body as its bytes: a table as kept, a policy list written again from its hashes (CL1). */
static const uint8_t *pp_statement_body(const pp_statement *st, size_t *len) {
    static uint8_t list[PP_CEILING_BODY_MAX];
    if (st->envelope.as != PP_AS_POLICY_LIST) {
        *len = st->body_len;
        return st->body;
    }
    *len = pp_ceiling_body((const uint8_t (*)[32])st->body, st->body_len / 32, list);
    return list;
}

const uint8_t *pp_statement_bytes(const pp_statement *st, size_t *len) { return pp_statement_body(st, len); }

static void pp_lapse(pp_pep_machine *pep, uint8_t cause);

/* IS4, IS6, IS12, CL3 (pep._set_refusal): what applying the whole set `st` of `kind` over the record `r` meets, the
 * cause or 0, and in *larger whether it enlarges what is held. `held[k]` is the set of kind k the record holds and
 * reads, NULL for none, and `change` the install change statement staged for `kind`, NULL for none. It is held to its
 * `seq` again, to the ceiling `held` holds (an action floor and a fallback policy inside it, and a ceiling the held
 * ones are inside), and to the widening rule of IS12, on which a `mesh` PEP compares bytes and lists and takes
 * `widens` false only when `replaces` is the policy hash of the set it holds, and a ceiling after a lost one,
 * `ceiling_lost`, is larger unless it is the lost one sent again byte for byte (IS10). pp_apply_set and the
 * provisioning precheck both ask it. */
static uint8_t pp_set_refusal(const pp_pep_machine *pep, const pp_install *r, const pp_statement *const held_sets[PP_SETS],
                              const pp_change *change, const pp_statement *st, int kind, int ceiling_lost, int *larger_out) {
    const pp_envelope *e = &st->envelope;
    uint8_t cause = PP_CAUSE_NONE;
    int empty = e->as == PP_AS_NONE;
    const pp_statement *held = held_sets[kind], *ceiling = held_sets[PP_SET_CEILING];
    int lost = kind == PP_SET_CEILING && ceiling_lost; /* IS10: a ceiling after a lost one */
    *larger_out = 0;
    if (e->seq <= r->sets[kind].seq) cause = PP_CAUSE_SEQ_REPLAY;
    else if (kind != PP_SET_CEILING && !empty && !pp_on_list(ceiling, e->body_sha256)) cause = PP_CAUSE_ABOVE_CEILING;
    else if (kind == PP_SET_CEILING && !empty) {
        for (int other = 0; other < PP_SET_CEILING; other++) {
            const pp_statement *one = held_sets[other];
            if (one && !pp_on_list(st, one->envelope.body_sha256)) cause = PP_CAUSE_ABOVE_CEILING; /* narrow those first */
        }
    }
    int larger = 0;
    /* IS15: a change statement staged for this set, from the held set's policy hash, stands for its table */
    int carried = !cause && kind != PP_SET_CEILING && !empty && held != NULL && change != NULL &&
                  change->seq == e->seq && !e->widens && e->has_replaces &&
                  memcmp(e->replaces, held->envelope.policy_sha256, 32) == 0 &&
                  memcmp(change->from, held->envelope.policy_sha256, 32) == 0;
    if (!cause) {
        if (lost) /* IS10, IS12: all but a byte for byte resend of the set the record names, the empty one too */
            larger = !(r->sets[kind].held && !empty && memcmp(e->body_sha256, r->sets[kind].body_sha256, 32) == 0);
        else if (kind == PP_SET_CEILING) {
            if (empty) larger = held != NULL;
            else if (held != NULL)
                for (size_t k = 0; k < st->body_len / 32; k++)
                    larger |= !pp_on_list(held, st->body + 32 * k); /* a hash the list before did not hold */
        } else if (!empty) {
            /* IS12: a mesh PEP compares bytes, and a cfs PEP takes the signers' word beyond the replaces test */
            larger = held == NULL || (pep->config.kind == PP_TGT_MESH && !carried &&
                                      (held->body_len != st->body_len || memcmp(held->body, st->body, st->body_len) != 0));
            if (carried && kind == PP_SET_FLOOR &&
                (held->envelope.has_layout != e->has_layout || held->envelope.has_command != e->has_command ||
                 (e->has_layout && memcmp(held->envelope.layout, e->layout, 32) != 0) ||
                 (e->has_command && held->envelope.command != e->command)))
                larger = 1; /* IS15: the table read with another layout or command register (AF9, AF10) */
            const pp_envelope *before = held ? &held->envelope : NULL;
            if (kind == PP_SET_FLOOR && before && before->has_rate &&
                (!e->has_rate || e->rate_allows > before->rate_allows || e->rate_window < before->rate_window))
                larger = 1; /* AF8, IS12: a looser rate, or one removed */
            if (kind == PP_SET_FLOOR && before && before->has_answer_rate &&
                (!e->has_answer_rate || e->answer_allows > before->answer_allows ||
                 e->answer_window < before->answer_window))
                larger = 1; /* OP4, IS12: a looser answer_rate, or one removed */
        }
        if (!e->widens && (larger || !pp_same(e->replaces, e->has_replaces, r->sets[kind].policy_sha256,
                                              r->sets[kind].held)))
            cause = PP_CAUSE_WIDENING_UNSIGNED;
    }
    *larger_out = larger;
    return cause;
}

/* IS4, IS6, IS12, CL3 (pep._apply_set): apply the whole set staged of `kind`, held first to pp_set_refusal over the
 * record and the sets the PEP holds now. The record goes first and the set part after, both durable before the
 * event, `install-widened` for a set that stands out and `install-applied` otherwise. A ceiling the active release
 * is above lapses it (CL3), and a fallback policy that now decides is run (FB8). */
static uint8_t pp_apply_set(pp_pep_machine *pep, int kind) {
    pp_durable *d = &pep->d;
    pp_install *r = &d->install;
    pp_install_set *set = &d->sets[kind];
    const pp_statement *st = &set->staged;
    const pp_envelope *e = &st->envelope;
    uint8_t subject = (uint8_t)(kind + 1);
    int empty = e->as == PP_AS_NONE, larger = 0;
    const pp_statement *held_sets[PP_SETS];
    for (int k = 0; k < PP_SETS; k++) held_sets[k] = pp_held_set(pep, k);
    uint8_t cause = pp_set_refusal(pep, r, held_sets, set->has_change ? &set->change : NULL, st, kind,
                                   pp_ceiling_lost(pep), &larger);
    if (cause) {
        set->has_staged = set->has_change = 0;
        pp_persist(pep, pp_set_part(kind));
        pp_emit_about(pep, PP_EV_REFUSED, cause, subject);
        return cause;
    }
    uint8_t active_hash[32];
    /* CL3: a ceiling that narrows below the active release is no widening; the release lapses and says so itself */
    int lapses = kind == PP_SET_CEILING && !empty && pp_active_hash(pep, active_hash) && !pp_on_list(st, active_hash);
    int stands_out = e->widens || larger; /* IS12: only a set that extends or enlarges scope */
    int before = pp_fallback_decides(pep);
    if (!d->install_mark) { /* IS9: before the first install statement is applied */
        d->install_mark = 1;
        pp_persist(pep, PP_PART_ANCHOR);
    }
    pp_install_slot *slot = &r->sets[kind];
    slot->seq = e->seq;
    slot->held = !empty;
    memcpy(slot->envelope_id, e->envelope_id, 32);
    pp_sha256(e->envelope_id, 32, slot->set_id); /* IS1: the set id over its one envelope id */
    memcpy(slot->policy_sha256, e->policy_sha256, 32);
    memcpy(slot->body_sha256, e->body_sha256, 32);
    pp_persist(pep, PP_PART_INSTALL);
    if (!empty) set->held = *st;
    set->has_held = !empty;
    set->has_staged = set->has_change = 0;
    pp_persist(pep, pp_set_part(kind));
    pep->set_lost[kind] = 0;
    if (pep->config.applied) { /* RC4: durable, and before its event */
        size_t body_len = 0;
        const uint8_t *body = pp_statement_body(st, &body_len);
        pep->config.applied(pep->config.context, st->sealed, st->sealed_len, body, body_len);
    }
    if (kind == PP_SET_CEILING && d->ceiling_mark != !empty) { /* IS10: the mark of a ceiling held */
        d->ceiling_mark = !empty;
        pp_persist(pep, PP_PART_ANCHOR);
    }
    pep->stood_out |= stands_out;
    pp_emit_about(pep, stands_out ? PP_EV_INSTALL_WIDENED : PP_EV_INSTALL_APPLIED,
                  stands_out ? PP_CAUSE_INSTALL_WIDENED : 0, subject);
    if (lapses) pp_lapse(pep, PP_CAUSE_ABOVE_CEILING); /* CL3, as under R5 */
    else if (kind == PP_SET_FALLBACK && (before || pp_fallback_decides(pep))) pp_runtime(pep); /* FB8 */
    return PP_CAUSE_NONE;
}

/* IS11: apply a verified install.trust at once, durably before its event. Its keys, operators and threshold replace
 * the held ones, every key it leaves out is retired, oldest first and the ninth forgetting the oldest, and its seq
 * and envelope id are the install trust sequence and id. */
static void pp_install_take_trust(pp_install *r, const pp_envelope *e, const uint8_t *body, size_t len) {
    static pp_install_trust_body b;
    pp_read_install_trust(body, len, &b); /* V11 read it */
    uint8_t dropped[PP_INSTALL_KEYS + PP_OPERATOR_KEYS][32];
    size_t n_dropped = 0;
    for (size_t k = 0; k < r->n_keys + r->n_operators; k++) {
        const uint8_t *id = k < r->n_keys ? r->keys[k].id : r->operators[k - r->n_keys].id;
        int kept = 0;
        for (size_t j = 0; j < b.n_keys + b.n_operators; j++) {
            uint8_t other[32];
            pp_sha256(j < b.n_keys ? b.keys[j] : b.operators[j - b.n_keys], 32, other);
            kept |= memcmp(other, id, 32) == 0;
        }
        if (!kept && !pp_listed((const uint8_t (*)[32])r->retired, r->n_retired, id)) memcpy(dropped[n_dropped++], id, 32);
    }
    for (size_t k = 1; k < n_dropped; k++) /* sorted, as install._retire appends them */
        for (size_t j = k; j > 0 && memcmp(dropped[j - 1], dropped[j], 32) > 0; j--) {
            uint8_t swap[32];
            memcpy(swap, dropped[j], 32);
            memcpy(dropped[j], dropped[j - 1], 32);
            memcpy(dropped[j - 1], swap, 32);
        }
    for (size_t k = 0; k < n_dropped; k++) {
        if (r->n_retired == PP_INSTALL_RETIRED) {
            memmove(r->retired[0], r->retired[1], (PP_INSTALL_RETIRED - 1) * 32);
            r->n_retired--;
        }
        memcpy(r->retired[r->n_retired++], dropped[k], 32);
    }
    r->n_keys = b.n_keys;
    for (size_t k = 0; k < b.n_keys; k++) {
        memcpy(r->keys[k].public_key, b.keys[k], 32);
        pp_sha256(b.keys[k], 32, r->keys[k].id);
    }
    r->n_operators = b.n_operators;
    for (size_t k = 0; k < b.n_operators; k++) {
        memcpy(r->operators[k].public_key, b.operators[k], 32);
        pp_sha256(b.operators[k], 32, r->operators[k].id);
    }
    r->threshold = b.threshold;
    r->trust_seq = e->seq;
    memcpy(r->trust_id, e->envelope_id, 32);
}

static void pp_apply_install_trust(pp_pep_machine *pep, const pp_envelope *e, const uint8_t *sealed,
                                   size_t sealed_len, const uint8_t *body, size_t len, int widened) {
    pp_install_take_trust(&pep->d.install, e, body, len);
    if (!pep->d.install_mark) {
        pep->d.install_mark = 1;
        pp_persist(pep, PP_PART_ANCHOR);
    }
    pp_persist(pep, PP_PART_INSTALL);
    if (pep->config.applied) pep->config.applied(pep->config.context, sealed, sealed_len, body, len); /* RC4 */
    widened |= e->widens;
    pep->stood_out |= widened;
    pp_emit_about(pep, widened ? PP_EV_INSTALL_WIDENED : PP_EV_INSTALL_APPLIED, widened ? PP_CAUSE_INSTALL_WIDENED : 0,
                  PP_SUBJECT_TRUST);
}

/* IS15: an install change statement is staged before the set it carries, durably, with event staged whose subject is
 * that set's kind. One on a PEP that holds no set of the kind, or whose `from` is not the held set's policy hash, is
 * dist:widening-unsigned, and the rule is held again when the set is applied. */
static uint8_t pp_stage_change(pp_pep_machine *pep, const pp_verdict *v) {
    const pp_envelope *e = &v->envelope;
    int kind = v->change_set;
    uint8_t subject = (uint8_t)(kind + 1);
    const pp_statement *held = pp_held_set(pep, kind);
    if (held == NULL || memcmp(v->change_from, held->envelope.policy_sha256, 32) != 0) {
        pp_emit_about(pep, PP_EV_REFUSED, PP_CAUSE_WIDENING_UNSIGNED, subject);
        return PP_CAUSE_WIDENING_UNSIGNED;
    }
    pp_install_set *set = &pep->d.sets[kind];
    if (set->has_staged && set->staged.envelope.seq != e->seq) set->has_staged = 0; /* G2: the set it replaces */
    set->has_change = 1;
    set->change.seq = e->seq;
    memcpy(set->change.policy_sha256, e->policy_sha256, 32);
    memcpy(set->change.release, e->release, 32);
    memcpy(set->change.from, v->change_from, 32);
    memcpy(set->change.envelope_id, e->envelope_id, 32);
    pp_persist(pep, pp_set_part(kind));
    pp_emit_about(pep, PP_EV_STAGED, 0, subject);
    return PP_CAUSE_NONE;
}

/* IS4: a statement of a set is staged durably, as G1 stages an envelope, with event staged and its subject, a set at
 * a higher seq replacing the one staged of its kind, and the set is applied when it is whole: when the release id of
 * E10 over its [as, body_sha256] is the signed release. A list is kept as its hashes. */
static uint8_t pp_stage_install(pp_pep_machine *pep, const pp_verdict *v, const uint8_t *sealed, size_t sealed_len,
                                const uint8_t *body, size_t body_len) {
    const pp_envelope *e = &v->envelope;
    if (e->artifact == PP_ART_INSTALL_TRUST) {
        pp_apply_install_trust(pep, e, sealed, sealed_len, body, body_len, v->install_widens);
        return PP_CAUSE_NONE;
    }
    if (e->artifact == PP_ART_INSTALL_CHANGE) return pp_stage_change(pep, v);
    int kind = pp_set_of(e->artifact);
    pp_install_set *set = &pep->d.sets[kind];
    if (set->has_change && set->change.seq != e->seq) set->has_change = 0; /* G2: a set at another seq replaces it */
    pp_statement *st = &set->staged;
    memset(st, 0, sizeof *st);
    st->envelope = *e;
    st->sealed_len = sealed_len;
    memcpy(st->sealed, sealed, sealed_len);
    if (e->as == PP_AS_POLICY_LIST) {
        size_t n = 0;
        pp_read_ceiling(body, body_len, (uint8_t (*)[32])st->body, &n); /* V11 read it: at most 64 */
        st->body_len = 32 * n;
    } else {
        st->body_len = body_len;
        memcpy(st->body, body, body_len); /* V5 held it to the table bound */
    }
    set->has_staged = 1;
    pp_persist(pep, pp_set_part(kind));
    pp_emit_about(pep, PP_EV_STAGED, 0, (uint8_t)(kind + 1));
    uint8_t release[32];
    pp_release_of_one(pp_as_name(e->as), e->body_sha256, release);
    return memcmp(release, e->release, 32) == 0 ? pp_apply_set(pep, kind) : PP_CAUSE_NONE;
}

static uint8_t pp_subject_of(const pp_envelope *e) {
    if (e->artifact == PP_ART_INSTALL_TRUST) return PP_SUBJECT_TRUST;
    if (e->artifact == PP_ART_OPERATOR_ANSWER) return PP_SUBJECT_ANSWER;
    return pp_set_of(e->artifact) >= 0 ? (uint8_t)(pp_set_of(e->artifact) + 1) : 0;
}

void pp_pep_id(const pp_pep_machine *pep, uint8_t out[16]) {
    uint8_t digest[32];
    pp_sha256(pep->instance_public, 32, digest);
    memcpy(out, digest, 16);
}

/* A fixed window of the PEP's own time (AF8, OP4): a new one starts once `window` seconds passed since its start.
 * A time before the start, a clock set back, keeps the window and its count, so it never grants a fresh allowance.
 * A spent count (PP_RATE_SPENT, from a lost part) reads as `allows`. */
static void pp_window(long long *start, uint32_t *count, long long window, long long allows, long long time) {
    if (*count == 0 || time >= *start + window) {
        *start = time;
        *count = 0;
    }
    if (*count > (uint32_t)allows) *count = (uint32_t)allows;
}

/* OP2 to OP4 (pep._apply_answer): an answer that verified names this PEP's id and an open escalation the action floor
 * made under the floor it still holds, no older than 600 seconds and not answered, dist:answer-unbound otherwise. An
 * `allow` past the signed answer_rate is dist:floor-rate and the escalation stays open. Otherwise the count and the
 * escalation, written as answered, are durable before the PEP acts, the answer is the caller's in pep->answer, and
 * the PEP sends `answered` with subject 5. */
static uint8_t pp_apply_answer(pp_pep_machine *pep, const pp_envelope *e, const uint8_t *body, size_t len) {
    pp_durable *d = &pep->d;
    int allow = 0;
    uint8_t id[16], own[16], receipt[32];
    (void)pp_read_answer(body, len, &allow, id, receipt); /* V11 read it */
    pp_pep_id(pep, own);
    const pp_statement *floor = pp_held_set(pep, PP_SET_FLOOR);
    long long time = pp_time(pep);
    pp_escalation *one = NULL;
    if (memcmp(id, own, 16) == 0 && floor && memcmp(floor->envelope.policy_sha256, e->policy_sha256, 32) == 0)
        for (size_t k = 0; k < d->n_open && one == NULL; k++) {
            pp_escalation *open = &d->open[k];
            if (!open->answered && memcmp(open->receipt, receipt, 32) == 0 &&
                memcmp(open->policy_sha256, floor->envelope.policy_sha256, 32) == 0 && time >= open->at &&
                time - open->at <= PP_ANSWER_LIFE)
                one = open;
        }
    if (one == NULL) {
        pp_emit_about(pep, PP_EV_REFUSED, PP_CAUSE_ANSWER_UNBOUND, PP_SUBJECT_ANSWER);
        return PP_CAUSE_ANSWER_UNBOUND;
    }
    if (allow) {
        const pp_envelope *fe = &floor->envelope;
        if (fe->has_answer_rate)
            pp_window(&d->answer_start, &d->answer_count, fe->answer_window, fe->answer_allows, time);
        if (!fe->has_answer_rate || d->answer_count >= (uint32_t)fe->answer_allows) {
            pp_emit_about(pep, PP_EV_REFUSED, PP_CAUSE_FLOOR_RATE, PP_SUBJECT_ANSWER); /* OP4: it stays open */
            return PP_CAUSE_FLOOR_RATE;
        }
        d->answer_count++;
    }
    one->answered = 1;
    if (pp_persist(pep, PP_PART_RATES) != 0 && allow) { /* OP3, OP4: before the PEP acts on it */
        /* an allow whose count and answered mark are not durable is not acted on: it is refused with
           dist:save-failed, the count stays spent and the escalation stays open. A refuse acted on twice lets nothing
           through */
        one->answered = 0;
        pp_emit_about(pep, PP_EV_REFUSED, PP_CAUSE_SAVE_FAILED, PP_SUBJECT_ANSWER);
        return PP_CAUSE_SAVE_FAILED;
    }
    pep->answer.applied = 1;
    pep->answer.allow = allow;
    pep->answer.cause = one->cause;
    memcpy(pep->answer.envelope_id, e->envelope_id, 32);
    memcpy(pep->answer.receipt, receipt, 32);
    memcpy(pep->answer.policy_sha256, one->policy_sha256, 32);
    pep->answer.request_len = one->request_len;
    memcpy(pep->answer.request, one->request, one->request_len);
    pep->answer.command_len = one->command_len;
    memcpy(pep->answer.command, one->command, one->command_len);
    pp_emit_about(pep, PP_EV_ANSWERED, 0, PP_SUBJECT_ANSWER);
    return PP_CAUSE_NONE;
}

uint8_t pp_pep_escalated(pp_pep_machine *pep, const uint8_t receipt_sha256[32], const uint8_t *request, size_t len,
                         const uint8_t *command, size_t command_len) {
    pp_durable *d = &pep->d;
    if (!pep->escalating || len > PP_REQUEST_MAX || command_len > PP_COMMAND_MAX || (command_len && !command))
        return PP_CAUSE_NOT_STAGED;
    pep->escalating = 0;
    size_t kept = 0;
    for (size_t k = 0; k < d->n_open; k++) /* the answered ones go, and the oldest past eight */
        if (!d->open[k].answered) d->open[kept++] = d->open[k];
    size_t from = kept > PP_OPEN_ESCALATIONS - 1 ? kept - (PP_OPEN_ESCALATIONS - 1) : 0;
    memmove(d->open, d->open + from, (kept - from) * sizeof d->open[0]);
    d->n_open = kept - from;
    pp_escalation *one = &d->open[d->n_open++];
    memset(one, 0, sizeof *one);
    memcpy(one->receipt, receipt_sha256, 32);
    memcpy(one->policy_sha256, pep->escalating_policy, 32);
    one->cause = pep->escalating_cause;
    one->at = pp_time(pep);
    one->request_len = (uint8_t)len;
    memcpy(one->request, request, len);
    one->command_len = (uint8_t)command_len;
    if (command_len) memcpy(one->command, command, command_len);
    pp_persist(pep, PP_PART_RATES);
    return PP_CAUSE_NONE;
}

/* G1, G2 and section 21: one sealed envelope and its body verified and held, and the cause it was refused with. */
static uint8_t pp_stage_one(pp_pep_machine *pep, const uint8_t *sealed, size_t sealed_len, const uint8_t *body,
                            size_t body_len) {
    pp_durable *d = &pep->d;
    if (!d->provisioned) { pp_refuse(pep, PP_CAUSE_UNKNOWN_KEY); return PP_CAUSE_UNKNOWN_KEY; }
    if (pep->locked && !pp_has_record(pep) && !pep->record_lost) {
        pp_refuse(pep, PP_CAUSE_FLOOR_LOST);
        return PP_CAUSE_FLOOR_LOST;
    }
    static pp_pep view;
    static pp_verdict verdict;
    pp_pep_view(pep, &view);
    pp_verify(sealed, sealed_len, body, body_len, &d->trust, &view, pep->now, &verdict);
    const pp_envelope *e = verdict.has_envelope ? &verdict.envelope : NULL;
    int installing = e && pp_is_install(e->artifact);
    int answer = e && e->artifact == PP_ART_OPERATOR_ANSWER;
    uint8_t subject = e ? pp_subject_of(e) : 0, cause = verdict.cause;
    if (e && e->artifact == PP_ART_INSTALL_CHANGE) { /* H10: the set an install change statement carries, or none */
        int k;
        uint8_t from[32];
        subject = pp_read_install_change(body, body_len, &k, from) ? 0 : (uint8_t)(k + 1);
    }
    if (pep->record_lost && (e == NULL || !pp_on_trust_stream(e->artifact))) cause = PP_CAUSE_INSTALL_LOST; /* IS10 */
    else if (pep->locked && !installing && !answer)
        cause = PP_CAUSE_FLOOR_LOST; /* Q5: a locked PEP still takes install statements and answers */
    else if (pp_ceiling_lost(pep) && e && !pp_on_trust_stream(e->artifact) && e->artifact != PP_ART_INSTALL_CEILING &&
             e->artifact != PP_ART_INSTALL_TRUST && e->artifact != PP_ART_OPERATOR_ANSWER)
        cause = PP_CAUSE_INSTALL_LOST; /* IS10: frozen until a ceiling is held again */
    else if (verdict.has_time_floor && d->trust_reads && verdict.time_floor > d->trust.time_floor) {
        d->trust.time_floor = verdict.time_floor; /* V13, T1 */
        pp_persist(pep, PP_PART_TRUST);
    }
    if (cause) { pp_emit_about(pep, PP_EV_REFUSED, cause, subject); return cause; }
    if (verdict.unchanged) { pp_emit(pep, PP_EV_BEAT, 0); return PP_CAUSE_NONE; } /* Q3, R1, IS6 */
    if (installing) return pp_stage_install(pep, &verdict, sealed, sealed_len, body, body_len);
    if (answer) return pp_apply_answer(pep, e, body, body_len);
    if (e->artifact == PP_ART_TRUST_REVOCATION) {
        uint8_t cause = pp_apply_revocation(pep, e, body, body_len); /* B2: applied when it verifies, durable before reported (R3) */
        if (cause) { pp_refuse(pep, cause); return cause; }
        pp_drop_fallen_staged(pep);
        pp_check_expiry(pep);
        pp_emit(pep, PP_EV_TRUST_APPLIED, 0);
        return PP_CAUSE_NONE;
    }
    if (e->artifact == PP_ART_TRUST_ROTATION) {
        pp_apply_rotation(pep, e, body, body_len); /* B2, O3: applied when it verifies, durable before reported */
        pp_drop_fallen_staged(pep);                /* S5: a staged release needs a counting signature */
        pp_emit(pep, PP_EV_TRUST_APPLIED, 0);
        return PP_CAUSE_NONE;
    }
    if (e->artifact == PP_ART_TRUST_CONTROLLER) {
        pp_apply_controller(pep, e, body, body_len); /* B2, K7: applied when it verifies, durable before reported */
        pp_check_expiry(pep);
        pp_emit(pep, PP_EV_TRUST_APPLIED, 0);
        return PP_CAUSE_NONE;
    }
    if (d->has_staged && strcmp(d->staged.stream, e->stream) == 0 && e->seq < d->staged.seq) {
        pp_refuse(pep, PP_CAUSE_SEQ_REPLAY); /* G2 */
        return PP_CAUSE_SEQ_REPLAY;
    }
    if (e->artifact == PP_ART_TRUST_WIDENING || e->artifact == PP_ART_TRUST_CHANGE) {
        /* W11: a release carries one statement, a widening statement or a change statement, never both */
        pp_artifact other = e->artifact == PP_ART_TRUST_CHANGE ? PP_ART_TRUST_WIDENING : PP_ART_TRUST_CHANGE;
        if (d->has_staged && strcmp(d->staged.stream, e->stream) == 0 && d->staged.seq == e->seq)
            for (size_t k = 0; k < d->staged.n; k++)
                if (d->staged.held[k].envelope.artifact == other) {
                    pp_refuse(pep, PP_CAUSE_BAD_FORMAT);
                    return PP_CAUSE_BAD_FORMAT;
                }
    }
    if (e->artifact == PP_ART_TRUST_CHANGE) { /* W11: a change statement never stands for a first install */
        uint8_t from[32];
        if (!d->has_active || pp_read_change(body, body_len, from) || memcmp(from, d->active.policy_sha256, 32) != 0) {
            pp_refuse(pep, PP_CAUSE_WIDENING_UNSIGNED);
            return PP_CAUSE_WIDENING_UNSIGNED;
        }
    }
    if (e->artifact != PP_ART_TRUST_WIDENING && e->artifact != PP_ART_TRUST_CHANGE) {
        int same = d->has_staged && strcmp(d->staged.stream, e->stream) == 0 && d->staged.seq == e->seq;
        int table = !pp_is_trust(e->artifact); /* the kind's table (V5 admits nothing else here) */
        uint8_t cause = pp_widening(pep, e->widens, e->replaces, e->has_replaces, same ? &d->staged : NULL,
                                    table ? body : NULL, table ? body_len : 0);
        if (cause) { pp_refuse(pep, cause); return cause; } /* V12 */
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
    d->staged.held[slot].sealed_len = sealed_len;
    memcpy(d->staged.held[slot].sealed, sealed, sealed_len);
    d->staged.held[slot].body_len = body_len;
    memcpy(pp_held_body(&d->staged, slot), body, body_len); /* V5 held the signed size to the artifact's bound */
    pp_persist(pep, PP_PART_STAGED);
    pp_emit(pep, PP_EV_STAGED, 0);
    return PP_CAUSE_NONE;
}

void pp_pep_stage(pp_pep_machine *pep, const uint8_t *sealed, size_t sealed_len, const uint8_t *body, size_t body_len,
                  long long now) {
    pp_begin(pep, now);
    pep->message = 1;
    (void)pp_stage_one(pep, sealed, sealed_len, body, body_len);
}

/* The table `release` holds, or NULL when it holds none. */
static const uint8_t *pp_release_table(const pp_release *release, size_t *len) {
    for (size_t k = 0; k < release->n; k++)
        if (!pp_is_trust(release->held[k].envelope.artifact)) {
            *len = release->held[k].body_len;
            return pp_held_body((pp_release *)release, k);
        }
    return NULL;
}

/* C2, E10: the artifacts staged, trust kinds left out, are the whole release the authority signed. Their release
 * id, the SHA-256 of the canon/2 array of sorted [artifact, body_sha256] pairs, computed again over what is staged,
 * is the `release` the envelopes carry, so a transport that withholds an artifact of a signed release cannot commit
 * the rest (pep._whole). */
static int pp_whole(const pp_release *staged) {
    static const char hex[] = "0123456789abcdef";
    const pp_envelope *pairs[2];
    size_t n = 0;
    for (size_t k = 0; k < staged->n; k++)
        if (!pp_is_trust(staged->held[k].envelope.artifact)) pairs[n++] = &staged->held[k].envelope;
    if (n == 0) return 0;
    if (n == 2 && strcmp(pp_artifact_name(pairs[0]->artifact), pp_artifact_name(pairs[1]->artifact)) > 0) {
        const pp_envelope *first = pairs[0];
        pairs[0] = pairs[1];
        pairs[1] = first;
    }
    uint8_t text[2 + 2 * (4 + 32 + 64 + 3)];
    size_t at = 0;
    text[at++] = '[';
    for (size_t i = 0; i < n; i++) {
        const char *name = pp_artifact_name(pairs[i]->artifact);
        size_t name_len = strlen(name);
        if (i) text[at++] = ',';
        text[at++] = '[';
        text[at++] = '"';
        memcpy(text + at, name, name_len);
        at += name_len;
        memcpy(text + at, "\",\"", 3);
        at += 3;
        for (size_t b = 0; b < 32; b++) {
            text[at++] = (uint8_t)hex[pairs[i]->body_sha256[b] >> 4];
            text[at++] = (uint8_t)hex[pairs[i]->body_sha256[b] & 15];
        }
        text[at++] = '"';
        text[at++] = ']';
    }
    text[at++] = ']';
    uint8_t id[32];
    pp_sha256(text, at, id);
    return memcmp(id, staged->release, 32) == 0;
}

/* What a commit of the named staged release answers now, with nothing changed: 0 to flip, else the cause, with
 * `drops` set for a C3 or CL2 failure, which drops the staged release. One function for the commit and for
 * pp_pep_commit_check, so the two cannot answer apart. */
static uint8_t pp_commit_cause(const pp_pep_machine *pep, const char *stream, long long seq, const uint8_t policy[32],
                               int *drops) {
    const pp_durable *d = &pep->d;
    *drops = 0;
    if (pep->record_lost || pp_ceiling_lost(pep)) return PP_CAUSE_INSTALL_LOST; /* IS10 */
    if (pep->locked) return PP_CAUSE_FLOOR_LOST;
    if (!d->trust_reads) return PP_CAUSE_UNKNOWN_KEY;
    if (!d->has_staged || !pp_names(&d->staged, stream, seq, policy)) return PP_CAUSE_NOT_STAGED;
    int has_table = 0;
    for (size_t k = 0; k < d->staged.n; k++) has_table |= !pp_is_trust(d->staged.held[k].envelope.artifact);
    if (!has_table || !pp_whole(&d->staged)) return PP_CAUSE_INCOMPLETE; /* C2: the row needs its table */
    uint8_t cause = pp_still_valid(pep, &d->staged, 1); /* C3 */
    size_t table_len = 0;
    const uint8_t *table = pp_release_table(&d->staged, &table_len);
    uint8_t hash[32];
    if (table) pp_sha256(table, table_len, hash);
    if (!cause && table && !pp_on_list(pp_held_set(pep, PP_SET_CEILING), hash))
        cause = PP_CAUSE_ABOVE_CEILING; /* CL2: the ceiling may have changed since it was staged */
    if (cause) {
        *drops = 1;
        return cause;
    }
    /* V12 again, against what is active now */
    return pp_widening(pep, d->staged.widens, d->staged.replaces, d->staged.has_replaces, &d->staged, table, table_len);
}

static void pp_commit_now(pp_pep_machine *pep, const char *stream, long long seq, const uint8_t policy[32]) {
    int drops = 0;
    uint8_t cause = pp_commit_cause(pep, stream, seq, policy, &drops);
    if (cause) {
        if (drops) {
            pep->d.has_staged = 0;
            pp_persist(pep, PP_PART_STAGED);
        }
        pp_refuse(pep, cause);
        return;
    }
    pp_flip(pep, 0);
}

uint8_t pp_pep_commit_check(pp_pep_machine *pep, const char *stream, long long seq, const uint8_t policy_sha256[32],
                            long long now) {
    int drops = 0;
    pep->now = now;
    return pp_commit_cause(pep, stream, seq, policy_sha256, &drops);
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
    pp_persist(pep, PP_PART_STAGED);
    pp_emit(pep, PP_EV_ABORTED, 0);
}

/* What a rollback answers now, with nothing changed: 0 to flip, else the cause, with `drops` for a kept release above
 * the ceiling, which is dropped (CL2, RB2). PP_CAUSE_NOT_STAGED when nothing is kept, which writes no record. */
static uint8_t pp_rollback_cause(const pp_pep_machine *pep, int *drops) {
    const pp_durable *d = &pep->d;
    *drops = 0;
    if (pep->held) return PP_CAUSE_HELD; /* X9 */
    if (pep->record_lost || pp_ceiling_lost(pep)) return PP_CAUSE_INSTALL_LOST; /* IS10 */
    if (pep->locked) return PP_CAUSE_FLOOR_LOST;
    if (!d->trust_reads) return PP_CAUSE_UNKNOWN_KEY;
    if (!d->has_previous) return PP_CAUSE_NOT_STAGED;
    uint8_t cause = pp_still_valid(pep, &d->previous, 1); /* RB2: what a commit checks, as it is active anew */
    if (!cause && d->previous.seq < pp_raised(&d->trust, d->previous.stream)) cause = PP_CAUSE_SEQ_REPLAY; /* R4 */
    size_t kept_len = 0;
    const uint8_t *kept = pp_release_table(&d->previous, &kept_len);
    uint8_t kept_hash[32];
    if (kept) pp_sha256(kept, kept_len, kept_hash);
    if (!cause && kept && !pp_on_list(pp_held_set(pep, PP_SET_CEILING), kept_hash)) {
        *drops = 1;
        return PP_CAUSE_ABOVE_CEILING;
    }
    if (cause) return cause;
    int same = d->has_active && memcmp(d->previous.release, d->active.release, 32) == 0; /* RB3: never larger */
    if (same) return PP_CAUSE_NONE;
    /* RB3: W1 to W7 as at a commit, so a kept table that says it does not widen is refused (W6) */
    return pp_widening(pep, d->previous.widens, d->previous.replaces, d->previous.has_replaces, &d->previous, kept,
                       kept_len);
}

uint8_t pp_pep_rollback(pp_pep_machine *pep, long long now) {
    pp_begin(pep, now);
    int drops = 0;
    uint8_t cause = pp_rollback_cause(pep, &drops);
    if (cause == PP_CAUSE_NOT_STAGED) return PP_CAUSE_NOT_STAGED;
    if (drops) {
        pep->d.has_previous = 0; /* CL2, RB2: a kept release above the ceiling is dropped */
        pp_persist(pep, PP_PART_PREVIOUS);
    }
    if (cause) { pp_refuse(pep, cause); return 0; }
    pp_flip(pep, 1);
    return 0;
}

uint8_t pp_pep_rollback_check(pp_pep_machine *pep, long long now) {
    int drops = 0;
    pep->now = now;
    return pp_rollback_cause(pep, &drops);
}

void pp_pep_refuse(pp_pep_machine *pep, uint8_t cause, long long now) {
    pp_begin(pep, now);
    pp_refuse(pep, cause);
}

void pp_pep_record(pp_pep_machine *pep, uint8_t event, long long now) {
    pp_begin(pep, now);
    pp_emit(pep, event, 0);
}

void pp_pep_save_time(pp_pep_machine *pep, long long now) {
    if (!pep->d.provisioned || !pep->d.trust_reads || now <= pep->d.trust.time_floor) return;
    pep->d.trust.time_floor = now;
    pp_persist(pep, PP_PART_TRUST);
}

/* ------------------------------------------------------------------ the controller statement (H9, H16) */

static uint64_t pp_rd64(const uint8_t *p) {
    uint64_t v = 0;
    for (int k = 7; k >= 0; k--) v = v << 8 | p[k];
    return v;
}

uint8_t pp_statement_verify(const uint8_t *data, size_t len, const uint8_t *public_key, pp_controller_statement *out) {
    static const char head[] = "DSSEv1 36 application/vnd.prismpath.dist-epoch ";
    uint8_t message[sizeof head + 4 + PP_FRESH_STATEMENT_SIZE];
    memset(out, 0, sizeof *out);
    if ((len != PP_STATEMENT_SIZE && len != PP_FRESH_STATEMENT_SIZE) || memcmp(data, "PPEP", 4) != 0 || data[4] != 1 ||
        data[37] > 1 || len != (data[37] ? PP_FRESH_STATEMENT_SIZE : PP_STATEMENT_SIZE))
        return PP_CAUSE_BAD_FORMAT;
    out->key_seq = pp_rd64(data + 5);
    memcpy(out->stream, data + 13, 16);
    out->epoch = pp_rd64(data + 29);
    out->fresh = data[37];
    if (out->fresh) {
        out->trust_seq = pp_rd64(data + 38);
        out->stream_seq = pp_rd64(data + 46);
        out->expires = pp_rd64(data + 54);
    }
    if (public_key == NULL) return PP_CAUSE_SIG_INVALID; /* K6: no key to check it against */
    size_t unsigned_len = len - 64, at = sizeof head - 1;
    memcpy(message, head, at);
    message[at++] = (uint8_t)('0' + unsigned_len / 10);
    message[at++] = (uint8_t)('0' + unsigned_len % 10);
    message[at++] = ' ';
    memcpy(message + at, data, unsigned_len);
    return crypto_ed25519_check(data + unsigned_len, public_key, message, at + unsigned_len) == 0 ? PP_CAUSE_NONE
                                                                                                 : PP_CAUSE_SIG_INVALID;
}

const uint8_t *pp_pep_controller_key(const pp_pep_machine *pep) {
    const pp_trust *t = &pep->d.trust;
    if (!pep->d.trust_reads) return NULL;
    const pp_key *held = pp_controller_of(t);
    return held && !pp_listed(t->revoked_keys, t->n_revoked_keys, held->id) ? held->public_key : NULL;
}

/* H16 (pep._freshen): a fresh statement has `fresh` 1, a trust sequence not below the PEP's, a stream seq not below
 * its floor, an `expires` later than the kept one's and at most `fresh` plus SKEW ahead of the PEP's time. A PEP with
 * no clock takes, from the first statement of a start that passes every check before the ahead test, its `expires`
 * less `fresh` as a raise of its time floor (T1). The kept statement is written before it counts, and a newer one
 * only once the kept one has used half its life. An `expires` past PP_MAX_SEQ gives nothing, since no time floor
 * holds it. */
static void pp_freshen(pp_pep_machine *pep, const pp_controller_statement *st, const uint8_t *data, size_t len) {
    pp_durable *d = &pep->d;
    pp_trust *t = &d->trust;
    long long raised = pp_raised(t, d->stream), floor = d->floor_seq > raised ? d->floor_seq : raised;
    if (!st->fresh || st->expires > (uint64_t)PP_MAX_SEQ || st->trust_seq < (uint64_t)t->trust_seq ||
        st->stream_seq < (uint64_t)floor)
        return;
    if (d->has_kept && st->expires <= d->kept_expires) return;
    long long expires = (long long)st->expires;
    if (!pep->config.has_clock && !pep->time_taken) {
        pep->time_taken = 1; /* once per start, from no other statement */
        if (expires - t->fresh > t->time_floor) {
            t->time_floor = expires - t->fresh;
            pp_persist(pep, PP_PART_TRUST);
        }
    }
    long long time = pp_time(pep);
    if (expires - time > t->fresh + PP_SKEW) return;
    if (d->has_kept && 2 * (time - d->kept_at) < (long long)d->kept_expires - d->kept_at) return;
    memset(d->kept, 0, sizeof d->kept);
    memcpy(d->kept, data, len);
    d->kept_expires = st->expires;
    d->kept_at = time;
    d->has_kept = 1;
    pp_persist(pep, PP_PART_FRESH);
}

int pp_pep_take_statement(pp_pep_machine *pep, const uint8_t *data, size_t len, long long now) {
    pp_controller_statement st;
    uint8_t stream_hash[32];
    pep->now = now;
    pep->n_out = 0; /* H9: a statement sends no record, whatever it says */
    if (!pep->d.provisioned || pep->locked || !pep->d.trust_reads || !pep->d.stream[0]) return 0;
    if (pp_statement_verify(data, len, pp_pep_controller_key(pep), &st)) return 0;
    pp_sha256((const uint8_t *)pep->d.stream, strlen(pep->d.stream), stream_hash);
    if (memcmp(st.stream, stream_hash, 16) != 0 || st.key_seq != (uint64_t)pep->d.trust.key_seq) return 0;
    int taken = st.epoch > pep->epoch;
    if (taken) pep->epoch = st.epoch; /* H9: never lowered */
    if (pep->d.trust.fresh > 0) pp_freshen(pep, &st, data, len);
    return taken;
}

uint8_t pp_pep_decide(pp_pep_machine *pep, int *held_mark, long long now) {
    pp_begin(pep, now);
    *held_mark = 0;
    if (pp_fallback_decides(pep)) return PP_CAUSE_NONE; /* FB1: the fallback policy decides */
    if (pep->locked) return PP_CAUSE_FLOOR_LOST;
    if (pp_state(pep) != PP_ST_ACTIVE) return PP_CAUSE_POLICY_LAPSED;
    *held_mark = pep->held;
    return PP_CAUSE_NONE;
}

/* One table's answer to a request on `kind`, and the edge of its start node that decided (-1 for none). A mesh table
 * allows by a matching edge and refuses with route:no-matching-edge otherwise, also when it cannot be asked. A cfs
 * table answers with the rule of its matching edge, allow, refuse or escalate with the rule's cause, and refuses
 * with its own no-match cause when no edge matches. */
static int pp_table_answer(pp_target kind, const uint8_t *table, size_t len, const uint8_t *regs, size_t regs_len,
                           uint8_t *outcome, uint8_t *cause) {
    *outcome = PP_OUT_REFUSE;
    *cause = PP_CAUSE_NO_MATCHING_EDGE;
    if (kind != PP_TGT_CFS) {
        int k = pp_eval_table(table, len, regs, regs_len);
        if (k < 0) return -1;
        *outcome = PP_OUT_ALLOW;
        *cause = PP_CAUSE_NONE;
        return k;
    }
    size_t image_len = 0;
    const uint8_t *image = pp_cfs_image(table, len, &image_len);
    int k = image ? pp_eval_table(image, image_len, regs, regs_len) : -2;
    if (k == -1) *cause = (uint8_t)pp_u16(table + PP_CFS_OFF_NOMATCH);
    if (k < 0 || k >= (int)pp_u16(table + PP_CFS_OFF_RULE_COUNT)) return -1;
    uint16_t rule_cause;
    uint8_t action = pp_cfs_rule(table, k, &rule_cause);
    *outcome = action == 0 ? PP_OUT_ALLOW : action == 2 ? PP_OUT_ESCALATE : PP_OUT_REFUSE;
    *cause = action == 0 ? PP_CAUSE_NONE : (uint8_t)rule_cause;
    return k;
}

void pp_pep_ask(pp_pep_machine *pep, const uint8_t *regs, size_t regs_len, const uint32_t *ages, long long now,
                pp_decision *out) {
    pp_begin(pep, now);
    memset(out, 0, sizeof *out);
    out->decided_rule = out->would_rule = -1;
    pep->escalating = 0;
    pp_durable *d = &pep->d;
    pp_target kind = pep->config.kind;
    size_t n_ages = ages && regs_len >= 4 ? (regs_len - 4) / 8 : 0;
    /* what decides with no floor: the active release, the fallback policy, or the refusal of X3 */
    const uint8_t *table = NULL, *policy = NULL;
    size_t table_len = 0;
    uint8_t basis = PP_BASIS_NONE;
    if (pp_state(pep) == PP_ST_ACTIVE && !pep->locked) {
        table = pp_release_table(&d->active, &table_len);
        policy = d->active.policy_sha256;
        basis = PP_BASIS_RELEASE;
    } else if (pp_fallback_decides(pep)) {
        const pp_statement *fallback = pp_held_set(pep, PP_SET_FALLBACK);
        table = fallback->body;
        table_len = fallback->body_len;
        policy = fallback->envelope.policy_sha256;
        basis = PP_BASIS_FALLBACK;
    }
    uint8_t outcome = PP_OUT_REFUSE, cause = pep->locked ? PP_CAUSE_FLOOR_LOST : PP_CAUSE_POLICY_LAPSED;
    int decided = table ? pp_table_answer(kind, table, table_len, regs, regs_len, &outcome, &cause) : -1;
    out->held_mark = basis == PP_BASIS_RELEASE && pep->held;
    /* AF1, AF2: the action floor first. It allows, on cfs it also escalates with its rule's cause, and it is silent
     * on a refusal, on a request it cannot read and when an independent field it tests is stale (AF10) */
    const pp_statement *floor = pp_held_set(pep, PP_SET_FLOOR);
    uint8_t floor_outcome = PP_OUT_REFUSE, floor_cause = 0;
    int k = floor ? pp_table_answer(kind, floor->body, floor->body_len, regs, regs_len, &floor_outcome, &floor_cause) : -1;
    size_t image_len = floor ? floor->body_len : 0;
    const uint8_t *image = !floor ? NULL : kind == PP_TGT_CFS ? pp_cfs_image(floor->body, floor->body_len, &image_len)
                                                             : floor->body;
    if (k >= 0 && floor_outcome != PP_OUT_REFUSE && image &&
        pp_floor_fresh(image, image_len, k, pep->config.layout, ages, n_ages)) {
        int override = !(table && outcome == PP_OUT_ALLOW); /* AF7 */
        int answers = 1, unsaved = 0;
        const pp_envelope *fe = &floor->envelope;
        if (floor_outcome == PP_OUT_ALLOW && override && fe->has_rate && k < PP_FLOOR_RULES) {
            /* AF8: overrides counted per rule in fixed windows of the PEP's time */
            pp_window(&d->rate_start[k], &d->rate_count[k], fe->rate_window, fe->rate_allows, pp_time(pep));
            int spent = d->rate_count[k] >= (uint32_t)fe->rate_allows;
            if (!spent) {
                d->rate_count[k]++;
                unsaved = pp_persist(pep, PP_PART_RATES) != 0; /* saved before the PEP acts on it */
            }
            if (unsaved) {
                /* an override whose count is not durable is refused by the floor, and the count stays spent */
                floor_outcome = PP_OUT_REFUSE;
                floor_cause = PP_CAUSE_SAVE_FAILED;
                out->rule = k;
                out->window = d->rate_start[k];
                out->count = d->rate_count[k];
            } else if (spent) {
                /* past the rate: escalated with dist:floor-rate where the kind escalates, else the release decides */
                if (kind == PP_TGT_CFS) {
                    floor_outcome = PP_OUT_ESCALATE;
                    floor_cause = PP_CAUSE_FLOOR_RATE;
                    out->rate_escalated = 1; /* RC3: the spent window, for the run's rates */
                    out->rule = k;
                    out->window = d->rate_start[k];
                    out->count = d->rate_count[k];
                } else {
                    answers = 0;
                }
            } else {
                out->counted = 1;
                out->rule = k;
                out->window = d->rate_start[k];
                out->count = d->rate_count[k];
            }
        }
        if (answers) {
            if (!unsaved) {
                if (d->floor_answers < 0xFFFFFFFFu) d->floor_answers++;
                if (override && d->floor_overrides < 0xFFFFFFFFu) d->floor_overrides++;
                pp_persist(pep, PP_PART_COUNTER); /* H10: with the counter, so no count goes down */
            }
            out->outcome = floor_outcome;
            out->cause = floor_outcome == PP_OUT_ALLOW ? PP_CAUSE_FLOOR_ALLOWED : floor_cause; /* RC3 */
            out->basis = PP_BASIS_FLOOR;
            out->has_policy = 1;
            memcpy(out->policy_sha256, fe->policy_sha256, 32);
            out->held_mark = pep->held;
            out->override = override;
            out->decided_rule = k;
            out->would_rule = decided;
            if (floor_outcome == PP_OUT_ESCALATE) { /* OP3: an escalation pp_pep_escalated may open */
                pep->escalating = 1;
                memcpy(pep->escalating_policy, fe->policy_sha256, 32);
                pep->escalating_cause = floor_cause;
            }
            out->would = table ? outcome : PP_OUT_NONE;
            out->would_cause = table ? cause : 0;
            if (table) {
                out->has_would_policy = 1;
                memcpy(out->would_policy, policy, 32);
            }
            return;
        }
        out->counted = 0;
        out->rate_escalated = 0;
    }
    out->outcome = outcome;
    out->decided_rule = decided;
    out->cause = cause;
    out->basis = basis;
    if (policy) {
        out->has_policy = 1;
        memcpy(out->policy_sha256, policy, 32);
    }
}

/* ------------------------------------------------------------------ the durable state, part by part */

typedef struct {
    uint8_t *p;
    const uint8_t *q;
    size_t n, i;
    int ok;
} pp_io;

static void pp_io_bytes(pp_io *io, void *data, size_t len) {
    if (!io->ok || io->i + len > io->n) { io->ok = 0; return; }
    if (io->p) memcpy(io->p + io->i, data, len);
    else memcpy(data, io->q + io->i, len);
    io->i += len;
}

/* A count followed by that many items of `size` bytes, at most `max`. */
static void pp_io_array(pp_io *io, void *items, size_t *count, size_t size, size_t max) {
    uint32_t n = (uint32_t)*count;
    pp_io_bytes(io, &n, sizeof n);
    if (!io->ok || n > max) { io->ok = 0; return; }
    *count = n;
    pp_io_bytes(io, items, size * n);
}

static void pp_io_release(pp_io *io, pp_release *r) {
    pp_io_bytes(io, r->stream, sizeof r->stream);
    pp_io_bytes(io, &r->seq, sizeof r->seq);
    pp_io_bytes(io, r->policy_sha256, 32);
    pp_io_bytes(io, r->release, 32);
    pp_io_bytes(io, r->replaces, 32);
    pp_io_bytes(io, &r->has_replaces, sizeof r->has_replaces);
    pp_io_bytes(io, &r->widens, sizeof r->widens);
    uint32_t n = (uint32_t)r->n;
    pp_io_bytes(io, &n, sizeof n);
    if (!io->ok || n > 2) { io->ok = 0; return; }
    r->n = n;
    for (size_t k = 0; k < r->n; k++) {
        pp_artifact_held *h = &r->held[k];
        pp_io_bytes(io, &h->envelope, sizeof h->envelope);
        uint32_t sl = (uint32_t)h->sealed_len, bl = (uint32_t)h->body_len;
        pp_io_bytes(io, &sl, sizeof sl);
        pp_io_bytes(io, &bl, sizeof bl);
        size_t room = pp_is_trust(h->envelope.artifact) ? PP_WIDENING_MAX : PP_RELEASE_BODY_MAX;
        if (!io->ok || sl > PP_MAX_SEALED || bl > room) { io->ok = 0; return; }
        h->sealed_len = sl;
        h->body_len = bl;
        pp_io_bytes(io, h->sealed, sl);
        pp_io_bytes(io, pp_held_body(r, k), bl);
    }
}

static void pp_io_u32(pp_io *io, uint32_t *v) { pp_io_bytes(io, v, sizeof *v); }

/* A held statement: the sealed envelope and the body only. Unpacking reads the envelope again from the sealed bytes
 * and holds the body to its signed hash (IS10), so a copy with a byte changed does not read and the next copy is
 * used. A policy list is kept as its hashes and written again to be hashed. */
static void pp_io_statement(pp_io *io, pp_statement *st) {
    uint32_t sl = (uint32_t)st->sealed_len, bl = (uint32_t)st->body_len;
    pp_io_u32(io, &sl);
    pp_io_u32(io, &bl);
    if (!io->ok || sl > PP_MAX_SEALED || bl > PP_INSTALL_BODY_MAX) { io->ok = 0; return; }
    st->sealed_len = sl;
    st->body_len = bl;
    pp_io_bytes(io, st->sealed, sl);
    pp_io_bytes(io, st->body, bl);
    if (!io->ok || io->p) return;
    const uint8_t *envelope;
    size_t envelope_len, n_entries;
    pp_entry entries[PP_MAX_ENTRIES];
    if (pp_unseal(st->sealed, st->sealed_len, &envelope, &envelope_len, entries, &n_entries) ||
        pp_read_envelope(envelope, envelope_len, &st->envelope) || !pp_is_install(st->envelope.artifact)) {
        io->ok = 0;
        return;
    }
    size_t len = 0;
    uint8_t hash[32];
    const uint8_t *body = pp_statement_body(st, &len);
    pp_sha256(body, len, hash);
    if ((long long)len != st->envelope.body_size || memcmp(hash, st->envelope.body_sha256, 32) != 0) io->ok = 0;
}

static void pp_io_ikeys(pp_io *io, pp_ikey *keys, size_t *n, size_t max) {
    uint32_t count = (uint32_t)*n;
    pp_io_u32(io, &count);
    if (!io->ok || count > max) { io->ok = 0; return; }
    *n = count;
    for (size_t k = 0; k < count; k++) {
        pp_io_bytes(io, keys[k].public_key, 32);
        if (!io->p) pp_sha256(keys[k].public_key, 32, keys[k].id);
    }
}

/* OP3: the open escalations, the last of the rates part. A part a build wrote before an escalation kept its command
 * holds items of the older layout, a prefix of this one padded to its alignment, which read with no command, so the
 * caller carries none of them out and never guesses one. The two layouts differ in size, so a count reads as one of
 * them by the bytes that follow it. */
typedef struct {
    char c;
    pp_escalation e;
} pp_escalation_align;
#define PP_ESCALATION_ALIGN offsetof(pp_escalation_align, e)
#define PP_ESCALATION_OLDER                                                                                            \
    ((offsetof(pp_escalation, command_len) + PP_ESCALATION_ALIGN - 1) / PP_ESCALATION_ALIGN * PP_ESCALATION_ALIGN)
_Static_assert(PP_ESCALATION_OLDER < sizeof(pp_escalation), "the older layout is shorter");
static void pp_io_open(pp_io *io, pp_durable *d) {
    uint32_t n = 0;
    if (!io->p && io->ok && io->i + sizeof n <= io->n) {
        memcpy(&n, io->q + io->i, sizeof n);
        if (n > 0 && n <= PP_OPEN_ESCALATIONS && io->n - io->i - sizeof n == (size_t)n * PP_ESCALATION_OLDER) {
            io->i += sizeof n;
            d->n_open = n;
            for (size_t k = 0; k < n; k++) {
                memset(&d->open[k], 0, sizeof d->open[k]);
                pp_io_bytes(io, &d->open[k], PP_ESCALATION_OLDER);
                d->open[k].command_len = 0; /* the older layout's padding, never a command */
                memset(d->open[k].command, 0, sizeof d->open[k].command);
            }
            return;
        }
    }
    pp_io_array(io, d->open, &d->n_open, sizeof d->open[0], PP_OPEN_ESCALATIONS);
}

/* The parts' tags are their bit's index, so a part read under another name never reads. */
static int pp_part_index(int part) {
    for (int k = 0; k < PP_PART_COUNT; k++)
        if (part == 1 << k) return k;
    return -1;
}

static void pp_io_part(pp_io *io, pp_durable *d, int part) {
    int index = pp_part_index(part);
    uint8_t tag[4] = {'P', 'P', 'D', (uint8_t)index};
    pp_io_bytes(io, tag, 4);
    if (index < 0 || !(tag[0] == 'P' && tag[1] == 'P' && tag[2] == 'D' && tag[3] == (uint8_t)index)) io->ok = 0;
    pp_trust *t = &d->trust;
    switch (part) {
    case PP_PART_ANCHOR:
        pp_io_bytes(io, &d->provisioned, sizeof(int));
        pp_io_bytes(io, &d->expiry_hold, sizeof(int));
        pp_io_bytes(io, d->stream, sizeof d->stream);
        pp_io_bytes(io, &d->install_mark, sizeof(int));
        pp_io_bytes(io, &d->ceiling_mark, sizeof(int));
        pp_io_bytes(io, &d->legacy_all, sizeof(int));
        pp_io_array(io, d->legacy, &d->n_legacy, 16, PP_LEGACY_STREAMS);
        break;
    case PP_PART_COUNTER:
        pp_io_bytes(io, &d->counter, sizeof d->counter);
        pp_io_u32(io, &d->floor_answers);
        pp_io_u32(io, &d->floor_overrides);
        break;
    case PP_PART_TRUST:
        pp_io_array(io, t->keys, &t->n_keys, sizeof t->keys[0], PP_MAX_HELD_KEYS);
        pp_io_array(io, t->retired, &t->n_retired, 32, PP_MAX_RETIRED);
        pp_io_array(io, t->revoked_keys, &t->n_revoked_keys, 32, PP_MAX_LIST);
        pp_io_array(io, t->revoked_envelopes, &t->n_revoked_envelopes, 32, PP_MAX_LIST);
        pp_io_array(io, t->revoked_policies, &t->n_revoked_policies, 32, PP_MAX_LIST);
        pp_io_array(io, t->floors, &t->n_floors, sizeof t->floors[0], PP_MAX_FLOORS);
        pp_io_bytes(io, &t->trust_seq, sizeof t->trust_seq);
        pp_io_bytes(io, t->trust_id, 32);
        pp_io_bytes(io, &t->has_trust_id, sizeof t->has_trust_id);
        pp_io_bytes(io, &t->time_floor, sizeof t->time_floor);
        pp_io_bytes(io, &t->key_seq, sizeof t->key_seq);
        pp_io_bytes(io, &t->fresh, sizeof t->fresh);
        break;
    case PP_PART_FLOOR:
        pp_io_bytes(io, &d->floor_seq, sizeof d->floor_seq);
        pp_io_array(io, d->floor_ids, &d->n_floor_ids, 32, PP_MAX_FLOOR_IDS);
        break;
    case PP_PART_ACTIVE: pp_io_bytes(io, &d->has_active, sizeof(int)); if (d->has_active) pp_io_release(io, &d->active); break;
    case PP_PART_PREVIOUS: pp_io_bytes(io, &d->has_previous, sizeof(int)); if (d->has_previous) pp_io_release(io, &d->previous); break;
    case PP_PART_STAGED: pp_io_bytes(io, &d->has_staged, sizeof(int)); if (d->has_staged) pp_io_release(io, &d->staged); break;
    case PP_PART_PENDING:
        pp_io_bytes(io, &d->has_pending, sizeof(int));
        pp_io_bytes(io, &d->pending_rollback, sizeof(int));
        pp_io_bytes(io, d->pending_release, 32);
        pp_io_bytes(io, &d->pending_seq, sizeof d->pending_seq);
        break;
    case PP_PART_INSTALL: {
        pp_install *r = &d->install;
        pp_io_bytes(io, &d->has_install, sizeof(int));
        if (!io->ok || !d->has_install) break;
        pp_io_ikeys(io, r->keys, &r->n_keys, PP_INSTALL_KEYS);
        pp_io_bytes(io, &r->threshold, sizeof r->threshold);
        pp_io_ikeys(io, r->operators, &r->n_operators, PP_OPERATOR_KEYS);
        pp_io_array(io, r->retired, &r->n_retired, 32, PP_INSTALL_RETIRED);
        pp_io_bytes(io, &r->trust_seq, sizeof r->trust_seq);
        pp_io_bytes(io, r->trust_id, 32);
        pp_io_bytes(io, r->domain, 32);
        for (int k = 0; k < PP_SETS; k++) {
            pp_install_slot *slot = &r->sets[k];
            pp_io_bytes(io, &slot->seq, sizeof slot->seq);
            pp_io_bytes(io, &slot->held, sizeof slot->held);
            pp_io_bytes(io, slot->body_sha256, 32);
            pp_io_bytes(io, slot->envelope_id, 32);
            pp_io_bytes(io, slot->policy_sha256, 32);
            if (!io->p) { /* IS1: a mesh set is one statement, so its set id is the hash of that envelope id */
                memset(slot->set_id, 0, 32);
                if (slot->seq > 0) pp_sha256(slot->envelope_id, 32, slot->set_id);
            }
        }
        if (io->ok && (r->n_keys < 1 || r->threshold < 1 || r->threshold > (long long)r->n_keys)) io->ok = 0;
        break;
    }
    case PP_PART_RATES:
        for (int k = 0; k < PP_FLOOR_RULES; k++) {
            pp_io_bytes(io, &d->rate_start[k], sizeof d->rate_start[k]);
            pp_io_u32(io, &d->rate_count[k]);
        }
        pp_io_bytes(io, &d->answer_start, sizeof d->answer_start); /* OP4, OP3 */
        pp_io_u32(io, &d->answer_count);
        pp_io_open(io, d);
        if (io->ok && !io->p)
            for (size_t k = 0; k < d->n_open; k++)
                if (d->open[k].request_len > PP_REQUEST_MAX || d->open[k].answered > 1 ||
                    d->open[k].command_len > PP_COMMAND_MAX)
                    io->ok = 0;
        break;
    case PP_PART_SET_FLOOR: case PP_PART_SET_FALLBACK: case PP_PART_SET_CEILING: {
        pp_install_set *set = &d->sets[index - pp_part_index(PP_PART_SET_FLOOR)];
        pp_io_bytes(io, &set->has_held, sizeof(int));
        pp_io_bytes(io, &set->has_staged, sizeof(int));
        if (io->ok && set->has_held) pp_io_statement(io, &set->held);
        if (io->ok && set->has_staged) pp_io_statement(io, &set->staged);
        pp_io_bytes(io, &set->has_change, sizeof(int));
        if (io->ok && set->has_change) { /* IS15: the change statement staged, as V10 and IS15 hold it */
            pp_io_bytes(io, &set->change.seq, sizeof set->change.seq);
            pp_io_bytes(io, set->change.policy_sha256, 32);
            pp_io_bytes(io, set->change.release, 32);
            pp_io_bytes(io, set->change.from, 32);
            pp_io_bytes(io, set->change.envelope_id, 32);
        }
        break;
    }
    case PP_PART_FRESH:
        pp_io_bytes(io, &d->has_kept, sizeof(int));
        if (io->ok && d->has_kept) {
            pp_io_bytes(io, d->kept, sizeof d->kept);
            pp_io_bytes(io, &d->kept_expires, sizeof d->kept_expires);
            pp_io_bytes(io, &d->kept_at, sizeof d->kept_at);
        }
        break;
    default: io->ok = 0;
    }
}

size_t pp_durable_pack(const pp_durable *d, int part, uint8_t *out, size_t room) {
    pp_io io = {out, NULL, room, 0, 1};
    pp_io_part(&io, (pp_durable *)d, part); /* packing only reads d */
    return io.ok ? io.i : 0;
}

/* What a part that is absent or does not read leaves: a part that must read for the PEP to decide reads as lost. */
static void pp_part_lost(pp_durable *d, int part, int absent) {
    switch (part) {
    case PP_PART_ANCHOR:
        d->provisioned = !absent; /* no anchor: never provisioned (P1) */
        d->setting_reads = 0;
        if (!absent) { /* one that does not read: locked, and every mark it held kept set (IS9, IS10) */
            d->install_mark = d->ceiling_mark = d->legacy_all = 1;
            d->n_legacy = 0;
            d->stream[0] = 0;
        }
        break;
    case PP_PART_COUNTER: d->counter_reads = 0; break;
    case PP_PART_TRUST: d->trust_reads = 0; break;
    case PP_PART_FLOOR: d->floor_reads = 0; break;
    case PP_PART_ACTIVE: d->has_active = 0; break;
    case PP_PART_PREVIOUS: d->has_previous = 0; break;
    case PP_PART_STAGED: d->has_staged = 0; break;
    case PP_PART_PENDING: d->has_pending = !absent; break; /* an intent that does not read is an interrupted one */
    case PP_PART_INSTALL: d->install_reads = 0; d->has_install = 0; break; /* IS10: lost when the anchor marks one */
    case PP_PART_RATES:
        d->rates_reads = 0;
        memset(d->rate_count, 0, sizeof d->rate_count);
        d->answer_count = 0;
        d->n_open = 0; /* an escalation no copy holds can be answered no more */
        break;
    case PP_PART_SET_FLOOR: case PP_PART_SET_FALLBACK: case PP_PART_SET_CEILING: {
        pp_install_set *set = &d->sets[pp_part_index(part) - pp_part_index(PP_PART_SET_FLOOR)];
        set->has_held = set->has_staged = set->has_change = 0;
        break;
    }
    case PP_PART_FRESH: d->has_kept = 0; break; /* H16: none kept, so none counts */
    }
}

int pp_durable_unpack(pp_durable *out, int part, const uint8_t *bytes, size_t len) {
    if (bytes == NULL) {
        pp_part_lost(out, part, 1);
        return 0;
    }
    pp_io io = {NULL, bytes, len, 0, 1};
    pp_io_part(&io, out, part);
    if (!io.ok || io.i != len) {
        pp_part_lost(out, part, 0);
        return -1;
    }
    switch (part) {
    case PP_PART_ANCHOR: out->setting_reads = 1; break;
    case PP_PART_COUNTER: out->counter_reads = 1; break;
    case PP_PART_TRUST: out->trust_reads = out->trust.readable = 1; break;
    case PP_PART_FLOOR: out->floor_reads = 1; break;
    case PP_PART_INSTALL: out->install_reads = 1; break;
    case PP_PART_RATES: out->rates_reads = 1; break;
    }
    return 0;
}

void pp_durable_held(pp_durable *d, int held) {
    if (!(held & PP_PART_ANCHOR) && (held & PP_PARTS & ~PP_PART_ANCHOR)) pp_part_lost(d, PP_PART_ANCHOR, 0);
}

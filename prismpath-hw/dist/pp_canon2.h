/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* pp_canon2.h: the canon/2 reader of the C core of policy distribution (spec-policy-distribution.md, E2),
 * the twin of prismpath/kernel/canon2.py and prismpath-rs/src/canon2.rs. No allocation, depth at most 128.
 *
 * pp_c2_check classifies bytes the way the reference reader does, reading left to right: PP_C2_INVALID for
 * bytes that are not canon/2 (strict UTF-8, integers within plus or minus 2^53 minus 1 with no fraction,
 * exponent or negative zero, no key twice in an object, no lone surrogate escape, nesting at most 128),
 * PP_C2_NOT_CANONICAL for canon/2 in another spelling (whitespace, members out of UTF-16 key order, an
 * escape the canonical form does not write), and PP_C2_OK for the canonical bytes of a value.
 *
 * The cursor functions then read canonical bytes member by member, as the envelope scanner of E9 does. They
 * are called only on bytes pp_c2_check answered PP_C2_OK for, so a canonical string with no escape is its
 * raw bytes, and every value is well formed. */
#ifndef PP_CANON2_H
#define PP_CANON2_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PP_C2_OK 0
#define PP_C2_NOT_CANONICAL 1
#define PP_C2_INVALID 2
#define PP_C2_MAX_DEPTH 128
#define PP_C2_EXACT_LIMIT 9007199254740991LL /* 2^53 - 1 */

typedef struct {
    const uint8_t *p;
    size_t n, i;
    int canonical; /* cleared when a legal spelling other than the canonical one is met */
} pp_c2;

/* ------------------------------------------------------------------ strings, as UTF-16 code units */

/* One UTF-8 scalar at p[i], strict (no overlong form, no surrogate, at most U+10FFFF), or -1. */
static int32_t pp_c2_utf8(const uint8_t *p, size_t n, size_t *i) {
    uint8_t b = p[*i];
    int32_t cp;
    size_t len;
    if (b < 0x80) { *i += 1; return b; }
    if (b >= 0xC2 && b <= 0xDF) { len = 2; cp = b & 0x1F; }
    else if (b >= 0xE0 && b <= 0xEF) { len = 3; cp = b & 0x0F; }
    else if (b >= 0xF0 && b <= 0xF4) { len = 4; cp = b & 0x07; }
    else return -1;
    if (*i + len > n) return -1;
    for (size_t k = 1; k < len; k++) {
        if ((p[*i + k] & 0xC0) != 0x80) return -1;
        cp = (cp << 6) | (p[*i + k] & 0x3F);
    }
    if ((len == 3 && cp < 0x800) || (len == 4 && (cp < 0x10000 || cp > 0x10FFFF))) return -1;
    if (cp >= 0xD800 && cp <= 0xDFFF) return -1;
    *i += len;
    return cp;
}

static int pp_c2_hex4(const uint8_t *p, size_t n, size_t at, uint32_t *out, int *lower) {
    uint32_t v = 0;
    if (at + 4 > n) return 0;
    for (size_t k = 0; k < 4; k++) {
        uint8_t c = p[at + k];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') { v |= (uint32_t)(c - 'A' + 10); *lower = 0; }
        else return 0;
    }
    *out = v;
    return 1;
}

/* The canonical writer escapes `"` and `\`, writes \b \t \n \f \r for those, \u00xx in lower case for the other
 * controls, and every other character raw. */
static int pp_c2_canonical_escape(int32_t cp, uint8_t escape, int lower) {
    switch (cp) {
    case '"': return escape == '"';
    case '\\': return escape == '\\';
    case 0x08: return escape == 'b';
    case 0x09: return escape == 't';
    case 0x0A: return escape == 'n';
    case 0x0C: return escape == 'f';
    case 0x0D: return escape == 'r';
    default: return cp < 0x20 && escape == 'u' && lower;
    }
}

/* Read one string whose opening quote is at c->i. Leaves c->i after the closing quote. */
static int pp_c2_string(pp_c2 *c) {
    const uint8_t *p = c->p;
    size_t n = c->n, i = c->i + 1;
    for (;;) {
        if (i >= n) return PP_C2_INVALID;
        uint8_t b = p[i];
        if (b == '"') { c->i = i + 1; return PP_C2_OK; }
        if (b < 0x20) return PP_C2_INVALID;
        if (b != '\\') {
            if (pp_c2_utf8(p, n, &i) < 0) return PP_C2_INVALID;
            continue;
        }
        if (i + 1 >= n) return PP_C2_INVALID;
        uint8_t e = p[i + 1];
        int32_t cp;
        int lower = 1;
        switch (e) {
        case '"': cp = '"'; i += 2; break;
        case '\\': cp = '\\'; i += 2; break;
        case '/': cp = '/'; i += 2; break;
        case 'b': cp = 0x08; i += 2; break;
        case 'f': cp = 0x0C; i += 2; break;
        case 'n': cp = 0x0A; i += 2; break;
        case 'r': cp = 0x0D; i += 2; break;
        case 't': cp = 0x09; i += 2; break;
        case 'u': {
            uint32_t hi, lo;
            if (!pp_c2_hex4(p, n, i + 2, &hi, &lower)) return PP_C2_INVALID;
            if (hi >= 0xDC00 && hi <= 0xDFFF) return PP_C2_INVALID; /* a lone low surrogate */
            if (hi >= 0xD800 && hi <= 0xDBFF) {
                if (!(i + 12 <= n && p[i + 6] == '\\' && p[i + 7] == 'u' && pp_c2_hex4(p, n, i + 8, &lo, &lower) &&
                      lo >= 0xDC00 && lo <= 0xDFFF))
                    return PP_C2_INVALID;
                c->canonical = 0; /* a supplementary character is written raw */
                i += 12;
                continue;
            }
            cp = (int32_t)hi;
            i += 6;
            break;
        }
        default: return PP_C2_INVALID;
        }
        if (!pp_c2_canonical_escape(cp, e, lower)) c->canonical = 0;
    }
}

/* The next UTF-16 code unit of the string whose opening quote is at *at, -1 at its end. *pending holds the low
 * half of a supplementary character. The string is known to be valid. */
static int32_t pp_c2_unit(const uint8_t *p, size_t n, size_t *at, int32_t *pending) {
    if (*pending >= 0) { int32_t u = *pending; *pending = -1; return u; }
    size_t i = *at;
    uint8_t b = p[i];
    if (b == '"') return -1;
    int32_t cp;
    if (b != '\\') {
        cp = pp_c2_utf8(p, n, &i);
    } else {
        uint8_t e = p[i + 1];
        uint32_t v = 0;
        int lower = 1;
        switch (e) {
        case 'b': cp = 0x08; i += 2; break;
        case 'f': cp = 0x0C; i += 2; break;
        case 'n': cp = 0x0A; i += 2; break;
        case 'r': cp = 0x0D; i += 2; break;
        case 't': cp = 0x09; i += 2; break;
        case 'u':
            pp_c2_hex4(p, n, i + 2, &v, &lower);
            i += 6;
            if (v >= 0xD800 && v <= 0xDBFF) {
                uint32_t lo = 0;
                pp_c2_hex4(p, n, i + 2, &lo, &lower);
                i += 6;
                *pending = (int32_t)lo;
            }
            cp = (int32_t)v;
            break;
        default: cp = e; i += 2; break;
        }
        *at = i;
        return cp;
    }
    *at = i;
    if (cp >= 0x10000) {
        cp -= 0x10000;
        *pending = 0xDC00 + (cp & 0x3FF);
        return 0xD800 + (cp >> 10);
    }
    return cp;
}

/* The order of two keys by UTF-16 code units, each given by the offset of its opening quote. */
static int pp_c2_key_cmp(const uint8_t *p, size_t n, size_t a, size_t b) {
    int32_t pa = -1, pb = -1;
    a++; b++;
    for (;;) {
        int32_t ua = pp_c2_unit(p, n, &a, &pa), ub = pp_c2_unit(p, n, &b, &pb);
        if (ua != ub) return ua < ub ? -1 : 1;
        if (ua < 0) return 0;
    }
}

/* ------------------------------------------------------------------ values */

static void pp_c2_ws(pp_c2 *c) {
    size_t start = c->i;
    while (c->i < c->n && (c->p[c->i] == ' ' || c->p[c->i] == '\t' || c->p[c->i] == '\n' || c->p[c->i] == '\r')) c->i++;
    if (c->i != start) c->canonical = 0;
}

static int pp_c2_number(pp_c2 *c) {
    const uint8_t *p = c->p;
    size_t i = c->i, n = c->n;
    int negative = 0;
    if (p[i] == '-') { negative = 1; i++; }
    if (i >= n || p[i] < '0' || p[i] > '9') return PP_C2_INVALID;
    size_t start = i;
    if (p[i] == '0') i++;
    else while (i < n && p[i] >= '0' && p[i] <= '9') i++;
    size_t digits = i - start;
    int fraction = 0;
    if (i < n && p[i] == '.') {
        i++;
        size_t f = i;
        while (i < n && p[i] >= '0' && p[i] <= '9') i++;
        if (i == f) return PP_C2_INVALID;
        fraction = 1;
    }
    if (i < n && (p[i] == 'e' || p[i] == 'E')) {
        i++;
        if (i < n && (p[i] == '+' || p[i] == '-')) i++;
        size_t f = i;
        while (i < n && p[i] >= '0' && p[i] <= '9') i++;
        if (i == f) return PP_C2_INVALID;
        fraction = 1;
    }
    if (fraction) return PP_C2_INVALID;
    if (negative && digits == 1 && p[start] == '0') return PP_C2_INVALID;
    if (digits > 16) return PP_C2_INVALID;
    long long v = 0;
    for (size_t k = start; k < start + digits; k++) v = v * 10 + (p[k] - '0');
    if (v > PP_C2_EXACT_LIMIT) return PP_C2_INVALID;
    c->i = i;
    return PP_C2_OK;
}

static int pp_c2_value(pp_c2 *c, int depth);

/* Skip a value already known valid, for the rescan of an object's earlier keys. */
static void pp_c2_skip_valid(pp_c2 *c) {
    pp_c2 copy = *c;
    pp_c2_value(&copy, 0);
    c->i = copy.i;
}

/* Whether the key at `key` equals a key of this object before it. `start` is the offset after its '{'. */
static int pp_c2_key_repeated(const pp_c2 *c, size_t start, size_t key) {
    pp_c2 scan = {c->p, c->n, start, 1};
    for (;;) {
        pp_c2_ws(&scan);
        if (scan.i == key) return 0;
        size_t this_key = scan.i;
        pp_c2_string(&scan);
        if (pp_c2_key_cmp(c->p, c->n, this_key, key) == 0) return 1;
        pp_c2_ws(&scan);
        scan.i++; /* ':' */
        pp_c2_ws(&scan);
        pp_c2_skip_valid(&scan);
        pp_c2_ws(&scan);
        scan.i++; /* ',' */
    }
}

static int pp_c2_value(pp_c2 *c, int depth) {
    pp_c2_ws(c);
    if (c->i >= c->n) return PP_C2_INVALID;
    const uint8_t *p = c->p;
    uint8_t b = p[c->i];
    static const char *const words[3] = {"null", "true", "false"};
    for (int w = 0; w < 3; w++) {
        size_t len = strlen(words[w]);
        if (c->i + len <= c->n && memcmp(p + c->i, words[w], len) == 0) { c->i += len; return PP_C2_OK; }
    }
    if (b == '"') return pp_c2_string(c);
    if (b == '-' || (b >= '0' && b <= '9')) return pp_c2_number(c);
    if (b != '[' && b != '{') return PP_C2_INVALID;
    if (depth + 1 > PP_C2_MAX_DEPTH) return PP_C2_INVALID;
    c->i++;
    pp_c2_ws(c);
    uint8_t close = b == '[' ? ']' : '}';
    if (c->i < c->n && p[c->i] == close) { c->i++; return PP_C2_OK; }
    size_t start = c->i, last_key = 0;
    int have_last = 0, sorted = 1;
    for (;;) {
        int r;
        if (b == '{') {
            pp_c2_ws(c);
            if (c->i >= c->n || p[c->i] != '"') return PP_C2_INVALID;
            size_t key = c->i;
            if ((r = pp_c2_string(c)) != PP_C2_OK) return r;
            if (have_last) {
                int order = pp_c2_key_cmp(p, c->n, last_key, key);
                if (order == 0) return PP_C2_INVALID;
                if (order > 0) sorted = 0;
                if (!sorted) {
                    c->canonical = 0;
                    if (pp_c2_key_repeated(c, start, key)) return PP_C2_INVALID;
                }
            }
            last_key = key;
            have_last = 1;
            pp_c2_ws(c);
            if (c->i >= c->n || p[c->i] != ':') return PP_C2_INVALID;
            c->i++;
        }
        if ((r = pp_c2_value(c, depth + 1)) != PP_C2_OK) return r;
        pp_c2_ws(c);
        if (c->i >= c->n) return PP_C2_INVALID;
        if (p[c->i] == close) { c->i++; return PP_C2_OK; }
        if (p[c->i] != ',') return PP_C2_INVALID;
        c->i++;
    }
}

/* Classify `len` bytes as canonical canon/2, canon/2 in another spelling, or not canon/2. */
static int pp_c2_check(const uint8_t *bytes, size_t len) {
    pp_c2 c = {bytes, len, 0, 1};
    for (size_t i = 0; i < len;) /* strict UTF-8 first, as the reference decodes the bytes before it reads */
        if (pp_c2_utf8(bytes, len, &i) < 0) return PP_C2_INVALID;
    int r = pp_c2_value(&c, 0);
    if (r != PP_C2_OK) return r;
    pp_c2_ws(&c);
    if (c.i != len) return PP_C2_INVALID;
    return c.canonical ? PP_C2_OK : PP_C2_NOT_CANONICAL;
}

/* ------------------------------------------------------------------ the cursor over canonical bytes */

/* Expect the literal bytes `text` at the cursor. */
static int pp_c2_lit(pp_c2 *c, const char *text) {
    size_t len = strlen(text);
    if (c->i + len > c->n || memcmp(c->p + c->i, text, len) != 0) return 0;
    c->i += len;
    return 1;
}

/* A string at the cursor with no escape: its bytes in *s and their length in *len. */
static int pp_c2_plain_string(pp_c2 *c, const uint8_t **s, size_t *len) {
    if (c->i >= c->n || c->p[c->i] != '"') return 0;
    size_t j = c->i + 1;
    while (j < c->n && c->p[j] != '"') {
        if (c->p[j] == '\\') return 0;
        j++;
    }
    if (j >= c->n) return 0;
    *s = c->p + c->i + 1;
    *len = j - c->i - 1;
    c->i = j + 1;
    return 1;
}

/* An integer at the cursor. */
static int pp_c2_int(pp_c2 *c, long long *out) {
    size_t i = c->i;
    int negative = 0;
    if (i < c->n && c->p[i] == '-') { negative = 1; i++; }
    if (i >= c->n || c->p[i] < '0' || c->p[i] > '9') return 0;
    long long v = 0;
    while (i < c->n && c->p[i] >= '0' && c->p[i] <= '9') v = v * 10 + (c->p[i++] - '0');
    *out = negative ? -v : v;
    c->i = i;
    return 1;
}

/* Skip any value at the cursor, reporting the deepest nesting of arrays and objects it holds (1 for an object
 * holding only scalars). */
static int pp_c2_skip(pp_c2 *c, int *depth) {
    pp_c2 probe = *c;
    int deepest = 0, level = 0;
    if (pp_c2_value(&probe, 0) != PP_C2_OK) return 0;
    for (size_t i = c->i; i < probe.i; i++) {
        uint8_t b = c->p[i];
        if (b == '"') { /* skip the string, escapes included */
            i++;
            while (c->p[i] != '"') i += c->p[i] == '\\' ? 2 : 1;
        } else if (b == '{' || b == '[') {
            if (++level > deepest) deepest = level;
        } else if (b == '}' || b == ']') {
            level--;
        }
    }
    *depth = deepest;
    c->i = probe.i;
    return 1;
}

#endif /* PP_CANON2_H */

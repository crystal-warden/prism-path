// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* Baked spiral-sidecar consumer (v1) — the small-target half of "one profile, two
 * materializations". Parses the signed pack's `<ppt>.spiral` blob (already integrity-checked
 * via the manifest hash before it reaches this code) and answers the three questions a
 * transmitting node has: reading -> symbols (quantize), symbols -> n (cell map), n -> band
 * (two integer compares per band). No routing, no evaluation, no trig — table lookups only. */
#pragma once
#include <stdint.h>
#include <string.h>

#define SSC_MAX_NODES   4
#define SSC_MAX_FIELDS  4
#define SSC_MAX_CELLS  16
#define SSC_MAX_BANDS   8
#define SSC_MAX_SIZE  256
#define SSC_NAME_MAX   24

typedef struct {                    /* one numeric cell: [lo, hi] with open-bound flags */
    int32_t lo, hi, rep;
    uint8_t lo_open, hi_open;
} ssc_cell_t;

typedef struct {
    char    name[SSC_NAME_MAX];
    uint8_t kind;                   /* 0 numeric, 1 boolean */
    uint16_t n;
    ssc_cell_t cells[SSC_MAX_CELLS];
} ssc_field_t;

typedef struct {
    uint32_t base, width;
    char route[SSC_NAME_MAX];       /* "" = unrouted */
} ssc_band_t;

typedef struct {
    char       name[SSC_NAME_MAX];
    uint8_t    k;
    ssc_field_t fields[SSC_MAX_FIELDS];
    uint16_t   n_bands;
    ssc_band_t bands[SSC_MAX_BANDS];
    uint32_t   size;
    uint32_t   cell_n[SSC_MAX_SIZE];  /* row-major linear cell index -> n */
} ssc_node_t;

typedef struct {
    uint16_t  n_nodes;
    ssc_node_t nodes[SSC_MAX_NODES];
} ssc_t;

static inline uint16_t ssc_rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t ssc_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Parse the v1 blob. Returns 0, or a negative stage code for truncation/cap/format faults. */
static int ssc_parse(const uint8_t *d, uint32_t len, ssc_t *out) {
    if (len < 8 || ssc_rd32(d) != 0x4C535050u || ssc_rd16(d + 4) != 1) return -1;
    uint32_t off = 6;
    out->n_nodes = ssc_rd16(d + off); off += 2;
    if (out->n_nodes > SSC_MAX_NODES) return -2;
    for (uint16_t ni = 0; ni < out->n_nodes; ni++) {
        ssc_node_t *N = &out->nodes[ni];
        uint8_t nl = d[off++];
        if (nl >= SSC_NAME_MAX || off + nl > len) return -3;
        memcpy(N->name, d + off, nl); N->name[nl] = 0; off += nl;
        N->k = d[off]; off += 2;                       /* k + pad */
        if (N->k > SSC_MAX_FIELDS) return -4;
        for (uint8_t fi = 0; fi < N->k; fi++) {
            ssc_field_t *F = &N->fields[fi];
            uint8_t fl = d[off++];
            if (fl >= SSC_NAME_MAX || off + fl > len) return -5;
            memcpy(F->name, d + off, fl); F->name[fl] = 0; off += fl;
            F->kind = d[off]; F->n = ssc_rd16(d + off + 1); off += 3;
            if (F->n > SSC_MAX_CELLS) return -6;
            if (F->kind == 0) {
                for (uint16_t ci = 0; ci < F->n; ci++) {
                    if (off + 13 > len) return -7;
                    uint8_t flags = d[off];
                    F->cells[ci].lo_open = flags & 1; F->cells[ci].hi_open = (flags >> 1) & 1;
                    F->cells[ci].lo = (int32_t)ssc_rd32(d + off + 1);
                    F->cells[ci].hi = (int32_t)ssc_rd32(d + off + 5);
                    F->cells[ci].rep = (int32_t)ssc_rd32(d + off + 9);
                    off += 13;
                }
            }
        }
        N->n_bands = ssc_rd16(d + off); off += 2;
        if (N->n_bands > SSC_MAX_BANDS) return -8;
        for (uint16_t bi = 0; bi < N->n_bands; bi++) {
            if (off + 9 > len) return -9;
            N->bands[bi].base = ssc_rd32(d + off); N->bands[bi].width = ssc_rd32(d + off + 4);
            uint8_t rl = d[off + 8]; off += 9;
            if (rl >= SSC_NAME_MAX || off + rl > len) return -10;
            memcpy(N->bands[bi].route, d + off, rl); N->bands[bi].route[rl] = 0; off += rl;
        }
        if (off + 4 > len) return -11;
        N->size = ssc_rd32(d + off); off += 4;
        if (N->size > SSC_MAX_SIZE || off + 4u * N->size > len) return -12;
        for (uint32_t i = 0; i < N->size; i++) { N->cell_n[i] = ssc_rd32(d + off); off += 4; }
    }
    return 0;
}

/* reading value -> the field's symbol. -1 when the value falls outside every cell. */
static int ssc_quantize(const ssc_field_t *F, int32_t v) {
    if (F->kind == 1) return v ? 1 : 0;
    for (uint16_t i = 0; i < F->n; i++) {
        const ssc_cell_t *c = &F->cells[i];
        if ((c->lo_open || v >= c->lo) && (c->hi_open || v <= c->hi)) return (int)i;
    }
    return -1;
}

/* symbols -> n via the row-major cell map. */
static int32_t ssc_n(const ssc_node_t *N, const int *syms) {
    uint32_t lin = 0;
    for (uint8_t f = 0; f < N->k; f++) {
        if (syms[f] < 0) return -1;
        lin = lin * N->fields[f].n + (uint32_t)syms[f];
    }
    return lin < N->size ? (int32_t)N->cell_n[lin] : -1;
}

/* n -> band id: two integer compares per band (the Level M atom, as data). */
static int ssc_band(const ssc_node_t *N, uint32_t n) {
    for (uint16_t b = 0; b < N->n_bands; b++)
        if (n >= N->bands[b].base && n < N->bands[b].base + N->bands[b].width) return (int)b;
    return -1;
}

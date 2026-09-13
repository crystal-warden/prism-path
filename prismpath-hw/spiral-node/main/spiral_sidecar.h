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
    uint16_t n_cells;
    ssc_cell_t cells[SSC_MAX_CELLS];
} ssc_field_t;

typedef struct {
    uint32_t base, width;
    char route[SSC_NAME_MAX];       /* "" = unrouted */
} ssc_band_t;

typedef struct {
    char       name[SSC_NAME_MAX];
    uint8_t    n_fields;
    ssc_field_t fields[SSC_MAX_FIELDS];
    uint16_t   n_bands;
    ssc_band_t bands[SSC_MAX_BANDS];
    uint32_t   size;
    uint32_t   cell_n[SSC_MAX_SIZE];  /* row-major linear cell index -> the joint spiral index */
} ssc_node_t;

typedef struct {
    uint16_t  n_nodes;
    ssc_node_t nodes[SSC_MAX_NODES];
} ssc_t;

static inline uint16_t ssc_rd16(const uint8_t *bytes) { return (uint16_t)(bytes[0] | (bytes[1] << 8)); }
static inline uint32_t ssc_rd32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

/* Parse the v1 blob. Returns 0, or a negative stage code for truncation/cap/format faults. */
static int ssc_parse(const uint8_t *blob, uint32_t len, ssc_t *out) {
    if (len < 8 || ssc_rd32(blob) != 0x4C535050u || ssc_rd16(blob + 4) != 1) return -1;
    uint32_t off = 6;
    out->n_nodes = ssc_rd16(blob + off); off += 2;
    if (out->n_nodes > SSC_MAX_NODES) return -2;
    for (uint16_t ni = 0; ni < out->n_nodes; ni++) {
        ssc_node_t *node = &out->nodes[ni];
        uint8_t nl = blob[off++];
        if (nl >= SSC_NAME_MAX || off + nl > len) return -3;
        memcpy(node->name, blob + off, nl); node->name[nl] = 0; off += nl;
        node->n_fields = blob[off]; off += 2;                       /* n_fields + pad */
        if (node->n_fields > SSC_MAX_FIELDS) return -4;
        for (uint8_t fi = 0; fi < node->n_fields; fi++) {
            ssc_field_t *field = &node->fields[fi];
            uint8_t fl = blob[off++];
            if (fl >= SSC_NAME_MAX || off + fl > len) return -5;
            memcpy(field->name, blob + off, fl); field->name[fl] = 0; off += fl;
            field->kind = blob[off]; field->n_cells = ssc_rd16(blob + off + 1); off += 3;
            if (field->n_cells > SSC_MAX_CELLS) return -6;
            if (field->kind == 0) {
                for (uint16_t ci = 0; ci < field->n_cells; ci++) {
                    if (off + 13 > len) return -7;
                    uint8_t flags = blob[off];
                    field->cells[ci].lo_open = flags & 1; field->cells[ci].hi_open = (flags >> 1) & 1;
                    field->cells[ci].lo = (int32_t)ssc_rd32(blob + off + 1);
                    field->cells[ci].hi = (int32_t)ssc_rd32(blob + off + 5);
                    field->cells[ci].rep = (int32_t)ssc_rd32(blob + off + 9);
                    off += 13;
                }
            }
        }
        node->n_bands = ssc_rd16(blob + off); off += 2;
        if (node->n_bands > SSC_MAX_BANDS) return -8;
        for (uint16_t bi = 0; bi < node->n_bands; bi++) {
            if (off + 9 > len) return -9;
            node->bands[bi].base = ssc_rd32(blob + off); node->bands[bi].width = ssc_rd32(blob + off + 4);
            uint8_t rl = blob[off + 8]; off += 9;
            if (rl >= SSC_NAME_MAX || off + rl > len) return -10;
            memcpy(node->bands[bi].route, blob + off, rl); node->bands[bi].route[rl] = 0; off += rl;
        }
        if (off + 4 > len) return -11;
        node->size = ssc_rd32(blob + off); off += 4;
        if (node->size > SSC_MAX_SIZE || off + 4u * node->size > len) return -12;
        for (uint32_t cell_index = 0; cell_index < node->size; cell_index++) {
            node->cell_n[cell_index] = ssc_rd32(blob + off); off += 4;
        }
    }
    return 0;
}

/* reading value -> the field's symbol. -1 when the value falls outside every cell. */
static int ssc_quantize(const ssc_field_t *field, int32_t reading) {
    if (field->kind == 1) return reading ? 1 : 0;
    for (uint16_t cell_index = 0; cell_index < field->n_cells; cell_index++) {
        const ssc_cell_t *cell = &field->cells[cell_index];
        if ((cell->lo_open || reading >= cell->lo) && (cell->hi_open || reading <= cell->hi)) return (int)cell_index;
    }
    return -1;
}

/* symbols -> n via the row-major cell map. */
static int32_t ssc_n(const ssc_node_t *node, const int *syms) {
    uint32_t lin = 0;
    for (uint8_t field_index = 0; field_index < node->n_fields; field_index++) {
        if (syms[field_index] < 0) return -1;
        lin = lin * node->fields[field_index].n_cells + (uint32_t)syms[field_index];
    }
    return lin < node->size ? (int32_t)node->cell_n[lin] : -1;
}

/* n -> band id: two integer compares per band (the Level M atom, as data). */
static int ssc_band(const ssc_node_t *node, uint32_t spiral_index) {
    for (uint16_t band_index = 0; band_index < node->n_bands; band_index++)
        if (spiral_index >= node->bands[band_index].base &&
            spiral_index < node->bands[band_index].base + node->bands[band_index].width) return (int)band_index;
    return -1;
}

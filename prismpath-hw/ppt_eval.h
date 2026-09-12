// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_eval.h: the embedded PPT v1 evaluator, one copy for every firmware.
 *
 * interp.c is the reference (malloc, stdio, exits on a bad image). This header is the same
 * evaluator written for a microcontroller: no allocation, the table image and the register file
 * live in static buffers sized by three macros, and every failure is a return code the caller
 * turns into a cause. interp_hdr.c drives it on the host with the same command line as interp.c,
 * so `make cert` certifies both against the frozen conformance corpus. A firmware includes this
 * file instead of carrying its own copy; eval_copies_check.py lists which firmwares have been
 * converted and which still carry a local copy pending a hardware recertification.
 *
 * Define before including (defaults suit the vision class tables):
 *   TBL_MAX          bytes of table image the firmware holds            (default 8192)
 *   PPT_MAX_FIELDS   field registers                                    (default 128)
 *   STACK_MAX        operand stack depth of one edge program            (default 256)
 *
 * The register file is `regs`: a 4 byte prefix (the node id in the regs.bin file format) then
 * 8 bytes per field, i32 type and i32 value, the layout the table image indexes directly.
 *
 * parse_table return codes: 0 ok, 1 bad magic or version, 3 short or truncated image or start
 * node out of range, 4 caps exceeded (fields, stack or bytes beyond what this firmware holds).
 * eval error codes written to *err: 7 operand stack overflow, 8 unknown opcode. */
#pragma once
#include <stdint.h>
#include <string.h>

#ifndef TBL_MAX
#define TBL_MAX 8192
#endif
#ifndef PPT_MAX_FIELDS
#define PPT_MAX_FIELDS 128
#endif
#ifndef STACK_MAX
#define STACK_MAX 256
#endif
#ifndef REGS_MAX
#define REGS_MAX (4 + 8 * PPT_MAX_FIELDS)
#endif

enum { TY_NONE = 0, TY_BOOL = 1, TY_INT = 2, TY_STR = 3 };
enum { OP_EQ = 0, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_TRUTHY };
enum { OPC_NOT = 0x8000, OPC_AND, OPC_OR, OPC_TRUE, OPC_FALSE };
#define PPT_MAGIC 0x4D545050u
#define PPT_VISITS_NONE 0xFFFFu

static uint8_t tbl[TBL_MAX]; static uint8_t regs[REGS_MAX];
static uint16_t n_fields, n_interns, n_atoms, n_nodes, n_edges, prog_len, start_node, visits_idx, max_steps, max_stack, tbl_flags;
static uint16_t atoms_off, nodes_off, edges_off, prog_off_base;

static inline uint16_t rd16b(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static inline int32_t rd32(const uint8_t *p) { int32_t v; memcpy(&v, p, 4); return v; }
static inline void wr32(uint8_t *p, int32_t v) { memcpy(p, &v, 4); }

/* parse the image already copied into tbl; len is the number of bytes the caller placed there */
static inline uint8_t parse_table(uint16_t len) {
    if (len < 28) return 3;
    if ((uint32_t)rd32(tbl) != PPT_MAGIC || rd16b(tbl + 4) != 1) return 1;
    n_fields = rd16b(tbl + 6); n_interns = rd16b(tbl + 8); n_atoms = rd16b(tbl + 10); n_nodes = rd16b(tbl + 12);
    n_edges = rd16b(tbl + 14); prog_len = rd16b(tbl + 16); start_node = rd16b(tbl + 18); visits_idx = rd16b(tbl + 20);
    max_steps = rd16b(tbl + 22); max_stack = rd16b(tbl + 24); tbl_flags = rd16b(tbl + 26);
    uint32_t need = 28u + 8u * n_atoms + 4u * n_nodes + 6u * n_edges + 2u * prog_len;
    if (tbl_flags & 1u) need += 2u * n_nodes;                     /* the optional per node color section */
    if (need > TBL_MAX || n_fields > PPT_MAX_FIELDS || max_stack > STACK_MAX) return 4;
    if (need > len) return 3;
    if (n_nodes == 0 || start_node >= n_nodes) return 3;
    atoms_off = 28; nodes_off = (uint16_t)(atoms_off + 8u * n_atoms); edges_off = (uint16_t)(nodes_off + 4u * n_nodes);
    prog_off_base = (uint16_t)(edges_off + 6u * n_edges);
    return 0;
}

/* atoms are the parallel comparators over the register file; interp.c eval_atom, line for line */
static inline uint8_t eval_atom(uint16_t atom_idx) {
    const uint8_t *a = tbl + atoms_off + 8 * (uint32_t)atom_idx;
    uint16_t field = rd16b(a); uint8_t op = a[2], aty = a[3]; int32_t aval = rd32(a + 4);
    const uint8_t *r = regs + 4 + 8 * (uint32_t)field; int32_t rty = rd32(r), rval = rd32(r + 4);
    uint8_t lnum = (rty == TY_BOOL || rty == TY_INT), rnum = (aty == TY_BOOL || aty == TY_INT);
    switch (op) {
    case OP_EQ: case OP_NE: { uint8_t eq;
        if (lnum && rnum) eq = (rval == aval); else if (rty == TY_STR && aty == TY_STR) eq = (rval == aval);
        else if (rty == TY_NONE && aty == TY_NONE) eq = 1; else eq = 0;
        return op == OP_EQ ? eq : (uint8_t)!eq; }
    case OP_LT: case OP_LE: case OP_GT: case OP_GE:
        if (!(lnum && rnum)) return 0;                               /* totality: non numeric is unsatisfied */
        switch (op) { case OP_LT: return rval < aval; case OP_LE: return rval <= aval; case OP_GT: return rval > aval; default: return rval >= aval; }
    case OP_TRUTHY: return rty == TY_NONE ? 0 : (rval != 0);        /* BOOL value; INT != 0; STR id != 0 */
    }
    return 0;
}

/* one edge's program folds atom results on a small stack; the result is the top of stack */
static inline int8_t eval_prog(uint16_t e_prog_off, uint16_t e_prog_cnt, uint8_t *err) {
    uint8_t stack[STACK_MAX]; int16_t sp = 0;
    for (uint16_t i = 0; i < e_prog_cnt; i++) {
        uint16_t w = rd16b(tbl + prog_off_base + 2 * (uint32_t)(e_prog_off + i));
        if (w < 0x8000) { if (sp >= STACK_MAX) { *err = 7; return 0; } stack[sp++] = eval_atom(w); }
        else switch (w) {
        case OPC_NOT:   stack[sp - 1] = (uint8_t)!stack[sp - 1]; break;
        case OPC_AND:   sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] && stack[sp]); break;
        case OPC_OR:    sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] || stack[sp]); break;
        case OPC_TRUE:  if (sp >= STACK_MAX) { *err = 7; return 0; } stack[sp++] = 1; break;
        case OPC_FALSE: if (sp >= STACK_MAX) { *err = 7; return 0; } stack[sp++] = 0; break;
        default: *err = 8; return 0;
        }
    }
    return (int8_t)stack[0];
}

/* the priority encoder: the first edge whose program is true wins; -1 when none (or on error) */
static inline int8_t evaluate(uint16_t node, uint16_t *out_target, uint8_t *err) {
    const uint8_t *n = tbl + nodes_off + 4 * (uint32_t)node; uint16_t edge_off = rd16b(n), edge_cnt = rd16b(n + 2);
    for (uint16_t i = 0; i < edge_cnt; i++) {
        const uint8_t *e = tbl + edges_off + 6 * (uint32_t)(edge_off + i);
        if (eval_prog(rd16b(e + 2), rd16b(e + 4), err)) { *out_target = rd16b(e); return (int8_t)i; }
        if (*err) return -1;
    }
    return -1;
}

static inline uint16_t node_edge_count(uint16_t node) { return rd16b(tbl + nodes_off + 4 * (uint32_t)node + 2); }
static inline void set_reg(uint16_t reg, int32_t v) { wr32(regs + 4 + 8 * (uint32_t)reg, TY_INT); wr32(regs + 8 + 8 * (uint32_t)reg, v); }
static inline void set_reg_typed(uint16_t reg, int32_t ty, int32_t v) { wr32(regs + 4 + 8 * (uint32_t)reg, ty); wr32(regs + 8 + 8 * (uint32_t)reg, v); }
static inline int32_t get_reg(uint16_t reg) { return rd32(regs + 8 + 8 * (uint32_t)reg); }

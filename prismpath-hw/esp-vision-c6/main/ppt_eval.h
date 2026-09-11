// ppt_eval.h: the byte exact evaluator, copied from esp-vision-node/main/vision_core.h (the fusion pod lineage).
// The relay is RISC-V: the same table image, the same code, the fifth instruction set for the conformance table.
#pragma once
#include <string.h>
#include <stdint.h>

// ---------------------------------------------------------------- the evaluator (byte exact copy)
#define TBL_MAX   8192
#define REGS_MAX  (4 + 8 * 128)
#define STACK_MAX 256
enum { TY_NONE = 0, TY_BOOL = 1, TY_INT = 2, TY_STR = 3 };
enum { OP_EQ = 0, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_TRUTHY };
static uint8_t tbl[TBL_MAX]; static uint8_t regs[REGS_MAX];
static uint16_t n_fields, n_atoms, n_nodes, n_edges, prog_len, start_node, max_steps;
static uint16_t atoms_off, nodes_off, edges_off, prog_off_base;
static uint16_t rd16b(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static int32_t rd32(const uint8_t *p) { int32_t v; memcpy(&v, p, 4); return v; }
static void wr32(uint8_t *p, int32_t v) { memcpy(p, &v, 4); }
static uint8_t parse_table(uint16_t len) {
    if (len < 28) return 3;
    if (rd32(tbl) != (int32_t)0x4D545050L || rd16b(tbl + 4) != 1) return 1;
    n_fields = rd16b(tbl + 6); n_atoms = rd16b(tbl + 10); n_nodes = rd16b(tbl + 12);
    n_edges = rd16b(tbl + 14); prog_len = rd16b(tbl + 16); start_node = rd16b(tbl + 18); max_steps = rd16b(tbl + 22);
    atoms_off = 28; nodes_off = atoms_off + 8 * n_atoms; edges_off = nodes_off + 4 * n_nodes; prog_off_base = edges_off + 6 * n_edges;
    if (prog_off_base + 2 * prog_len != len) return 3;
    return 0;
}
static uint8_t eval_atom(uint16_t atom_idx) {
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
        if (!(lnum && rnum)) return 0;
        switch (op) { case OP_LT: return rval < aval; case OP_LE: return rval <= aval; case OP_GT: return rval > aval; default: return rval >= aval; }
    case OP_TRUTHY: return rty == TY_NONE ? 0 : (rval != 0);
    }
    return 0;
}
static int8_t eval_prog(uint16_t e_prog_off, uint16_t e_prog_cnt, uint8_t *err) {
    uint8_t stack[STACK_MAX]; int16_t sp = 0;
    for (uint16_t i = 0; i < e_prog_cnt; i++) {
        uint16_t w = rd16b(tbl + prog_off_base + 2 * (uint32_t)(e_prog_off + i));
        if (w < 0x8000) { if (sp >= STACK_MAX) { *err = 7; return 0; } stack[sp++] = eval_atom(w); }
        else switch (w) {
        case 0x8000: stack[sp - 1] = (uint8_t)!stack[sp - 1]; break;
        case 0x8001: sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] && stack[sp]); break;
        case 0x8002: sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] || stack[sp]); break;
        case 0x8003: if (sp >= STACK_MAX) { *err = 7; return 0; } stack[sp++] = 1; break;
        case 0x8004: if (sp >= STACK_MAX) { *err = 7; return 0; } stack[sp++] = 0; break;
        default: *err = 8; return 0;
        }
    }
    return (int8_t)stack[0];
}
static int8_t evaluate(uint16_t node, uint16_t *out_target, uint8_t *err) {
    const uint8_t *n = tbl + nodes_off + 4 * (uint32_t)node; uint16_t edge_off = rd16b(n), edge_cnt = rd16b(n + 2);
    for (uint16_t i = 0; i < edge_cnt; i++) {
        const uint8_t *e = tbl + edges_off + 6 * (uint32_t)(edge_off + i);
        if (eval_prog(rd16b(e + 2), rd16b(e + 4), err)) { *out_target = rd16b(e); return (int8_t)i; }
        if (*err) return -1;
    }
    return -1;
}
static uint16_t node_edge_count(uint16_t node) { return rd16b(tbl + nodes_off + 4 * (uint32_t)node + 2); }
static void set_reg(uint16_t reg, int32_t v) { wr32(regs + 4 + 8 * (uint32_t)reg, TY_INT); wr32(regs + 8 + 8 * (uint32_t)reg, v); }
static int32_t get_reg(uint16_t reg) { return rd32(regs + 8 + 8 * (uint32_t)reg); }

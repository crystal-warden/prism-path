// vision_core.h: the front end, the byte exact evaluator, the wire encoder. Shared by replay and live.
#pragma once
#include <stdbool.h>
static bool refreshed;   // set by front_end on the frame the background was replaced
#define W 320
#define H 240
#define R 6
#define C 8
#define CW (W / C)
#define CH (H / R)
#define MOTION_ON 16
#define BACK_ON 24
#define JUMP_CELLS 32
#define JUMP_FRAMES 5
#define SCENE_CELLS ((R * C) * 3 / 4)
#define SCENE_FRAMES 20
static const uint8_t DOOR_R[] = {2, 3}; static const uint8_t DOOR_C0 = 2, DOOR_C1 = 7;   // cells 22 to 37

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

// ---------------------------------------------------------------- the front end (matches frontend.py)
static uint8_t *cur, *prev, *background; static uint32_t frame_n = 0;
static int32_t dep_hist[JUMP_FRAMES + 1]; static int dep_n = 0; static int32_t departed_still = 0; static bool unstable = false, scene_changed = false;
static int32_t m_cell[R][C], b_cell[R][C];
static void cell_mad(const uint8_t *a, const uint8_t *b, int32_t out[R][C]) {
    for (int r = 0; r < R; r++) for (int c = 0; c < C; c++) {
        uint32_t s = 0;
        for (int y = r * CH; y < (r + 1) * CH; y++) {
            const uint8_t *pa = a + y * W + c * CW, *pb = b + y * W + c * CW;
            for (int x = 0; x < CW; x++) { int d = (int)pa[x] - (int)pb[x]; s += (uint32_t)(d < 0 ? -d : d); }
        }
        out[r][c] = (int32_t)(s / (CW * CH));
    }
}
static void adopt_normal(void) { memcpy(background, cur, W * H); refreshed = true; scene_changed = false; departed_still = 0; unstable = false; dep_n = 0; }
static void front_end(int32_t *motion_cells, int32_t *dark, int32_t *step, int32_t *door_hit, int32_t *scene) {
    if (frame_n == 0) { memcpy(prev, cur, W * H); memcpy(background, cur, W * H); dep_n = 0; departed_still = 0; unstable = false; scene_changed = false; }
    cell_mad(cur, prev, m_cell); cell_mad(cur, background, b_cell);
    int32_t mc = 0, departed = 0; uint32_t sum = 0;
    for (int r = 0; r < R; r++) for (int c = 0; c < C; c++) { if (m_cell[r][c] >= MOTION_ON) mc++; if (b_cell[r][c] >= BACK_ON) departed++; }
    for (uint32_t i = 0; i < W * H; i++) sum += cur[i];
    *motion_cells = mc; *dark = (int32_t)(sum / (W * H));
    // the step: departed rose by JUMP_CELLS or more within JUMP_FRAMES frames (dep_hist holds the last JUMP_FRAMES + 1 counts)
    if (dep_n < JUMP_FRAMES + 1) dep_hist[dep_n++] = departed; else { memmove(dep_hist, dep_hist + 1, JUMP_FRAMES * sizeof dep_hist[0]); dep_hist[JUMP_FRAMES] = departed; }
    *step = (dep_n > JUMP_FRAMES && departed - dep_hist[0] >= JUMP_CELLS);
    if (*step) unstable = true;
    if (unstable && departed < SCENE_CELLS / 2) { unstable = false; departed_still = 0; }
    departed_still = (unstable && mc == 0 && departed >= SCENE_CELLS) ? departed_still + 1 : 0;
    if (departed_still >= SCENE_FRAMES) scene_changed = true;
    *scene = scene_changed ? 1 : 0;
    int32_t dh = 0;
    for (unsigned k = 0; k < sizeof DOOR_R; k++) for (int c = DOOR_C0; c <= DOOR_C1; c++)
        if (m_cell[DOOR_R[k]][c] >= MOTION_ON && b_cell[DOOR_R[k]][c] >= BACK_ON) dh = 1;
    *door_hit = dh;
    frame_n++;
    refreshed = false;                                   // no refresh clock (T2): the normal changes only through adopt_normal()
    memcpy(prev, cur, W * H);
}
static void set_reg(uint16_t reg, int32_t v) { wr32(regs + 4 + 8 * (uint32_t)reg, TY_INT); wr32(regs + 8 + 8 * (uint32_t)reg, v); }
static int32_t get_reg(uint16_t reg) { return rd32(regs + 8 + 8 * (uint32_t)reg); }

static void usb_write_all(const uint8_t *p, size_t n) {
    while (n) { size_t piece = n < 2048 ? n : 2048; int w = usb_serial_jtag_write_bytes(p, piece, pdMS_TO_TICKS(1000)); if (w <= 0) { vTaskDelay(1); continue; } p += w; n -= w; }
}
static void usb_read_all(uint8_t *p, size_t n) {
    while (n) { int r = usb_serial_jtag_read_bytes(p, n, pdMS_TO_TICKS(1000)); if (r <= 0) continue; p += r; n -= r; }
}
static void vision_core_init(void) {
    prev = heap_caps_malloc(W * H, MALLOC_CAP_SPIRAM); background = heap_caps_malloc(W * H, MALLOC_CAP_SPIRAM);
    memcpy(tbl, POLICY_TABLE, POLICY_TABLE_LEN);
    uint8_t rc = parse_table(POLICY_TABLE_LEN);
    if (rc) { printf("table parse failed rc=%u\n", rc); while (1) vTaskDelay(1000); }
}
static void decide(int32_t motion_cells, int32_t dark, int32_t step, int32_t door_hit, int32_t scene, uint16_t *out_node, uint16_t *out_steps) {
    memset(regs, 0, sizeof regs);
    #define SETM(r, c) set_reg(REG_m_##r##c, m_cell[r][c]); set_reg(REG_b_##r##c, b_cell[r][c]);
    SETM(0,0) SETM(0,1) SETM(0,2) SETM(0,3) SETM(0,4) SETM(0,5) SETM(0,6) SETM(0,7)
    SETM(1,0) SETM(1,1) SETM(1,2) SETM(1,3) SETM(1,4) SETM(1,5) SETM(1,6) SETM(1,7)
    SETM(2,0) SETM(2,1) SETM(2,2) SETM(2,3) SETM(2,4) SETM(2,5) SETM(2,6) SETM(2,7)
    SETM(3,0) SETM(3,1) SETM(3,2) SETM(3,3) SETM(3,4) SETM(3,5) SETM(3,6) SETM(3,7)
    SETM(4,0) SETM(4,1) SETM(4,2) SETM(4,3) SETM(4,4) SETM(4,5) SETM(4,6) SETM(4,7)
    SETM(5,0) SETM(5,1) SETM(5,2) SETM(5,3) SETM(5,4) SETM(5,5) SETM(5,6) SETM(5,7)
    set_reg(REG_motion_cells, motion_cells); set_reg(REG_dark, dark); set_reg(REG_step, step); set_reg(REG_door_hit, door_hit); set_reg(REG_scene_changed, scene);
    uint16_t node = start_node, target = 0, steps = 0; uint8_t err = 0;
    while (steps < max_steps && node_edge_count(node) > 0) { int8_t e = evaluate(node, &target, &err); if (e < 0 || err) break; node = target; steps++; }
    *out_node = node; *out_steps = steps;
}
static uint16_t encode_reading(uint8_t *wirebuf, size_t buflen) {
    memset(wirebuf, 0, buflen); bitacc_t acc = { wirebuf, 0 };
    for (int i = 0; i < WIRE_N_FIELDS; i++) {
        int32_t v = get_reg(WIRE_FIELDS[i].reg); uint32_t sym = 0;
        for (int k = 0; k < WIRE_FIELDS[i].n_cuts; k++) if (v >= WIRE_FIELDS[i].cut[k]) sym = k + 1;
        zeck_encode(&acc, (uint64_t)sym + 1);
    }
    return (uint16_t)((acc.bitpos + 7u) >> 3);
}
static bool background_moved(const uint8_t *since) {
    static int32_t d[R][C]; cell_mad(background, since, d);
    for (int r = 0; r < R; r++) for (int c = 0; c < C; c++) if (d[r][c] >= BACK_ON) return true;
    return false;
}

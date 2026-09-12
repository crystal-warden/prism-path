// vision_core.h: the front end, the byte exact evaluator, the wire encoder. Shared by replay and live.
#pragma once
#include <stdbool.h>
static bool refreshed;   // set by front_end on the frame the background was replaced
// T6: the same policy, grid and wire over more pixels; VISION_VGA builds the front end at 640 by 480 (cells 80 by 60)
#ifdef VISION_VGA
#define W 640
#define H 480
#else
#define W 320
#define H 240
#endif
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

// ---------------------------------------------------------------- the evaluator: the shared embedded evaluator
// (prismpath-hw/ppt_eval.h), the one every firmware includes and interp_hdr.c certifies on the host; caps set here.
#define TBL_MAX        8192
#define PPT_MAX_FIELDS 128
#define STACK_MAX      256
#include "../../ppt_eval.h"

// ---------------------------------------------------------------- the front end (matches frontend.py)
static uint8_t *cur, *prev, *background; static uint32_t frame_n = 0;
static int32_t dep_hist[JUMP_FRAMES + 1]; static int dep_n = 0; static int32_t departed_still = 0; static bool unstable = false, scene_changed = false;
#define CLEAN_FRAMES 20
static int32_t clean_run = 0; static bool normal_set = false; static uint16_t normal_id = 0;
// the normal's id: FNV-1a over the background pixels, folded to 16 bits; every reading and keyframe names it
static uint16_t normal_hash(void) { uint32_t h = 2166136261u; for (uint32_t i = 0; i < W * H; i++) { h ^= background[i]; h *= 16777619u; } return (uint16_t)(h ^ (h >> 16)); }
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
static void adopt_normal(void) { memcpy(background, cur, W * H); normal_id = normal_hash(); normal_set = true; refreshed = true; scene_changed = false; departed_still = 0; unstable = false; dep_n = 0; clean_run = 0; }
static void front_end(int32_t *motion_cells, int32_t *dark, int32_t *step, int32_t *door_hit, int32_t *scene) {
    if (frame_n == 0) { memcpy(prev, cur, W * H); memcpy(background, cur, W * H); dep_n = 0; departed_still = 0; unstable = false; scene_changed = false; clean_run = 0; normal_set = false; normal_id = normal_hash(); }
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
    for (int k = 0; k < DOOR_N; k++) { int r = DOOR_CELLS[k][0], c = DOOR_CELLS[k][1]; if (m_cell[r][c] >= MOTION_ON && b_cell[r][c] >= BACK_ON) dh = 1; }
    *door_hit = dh;
    frame_n++;
    // the anchored normal: until the first clean stretch has passed, the background follows the frame (so b equals m)
    // and the first CLEAN_FRAMES frames with no motion end the search; that frame is the normal
    if (!normal_set) {
        clean_run = (mc == 0) ? clean_run + 1 : 0;
        if (clean_run >= CLEAN_FRAMES) adopt_normal(); else { memcpy(background, cur, W * H); normal_id = normal_hash(); }
    }
    refreshed = false;                                   // no refresh clock (T2): the normal changes only through adopt_normal()
    memcpy(prev, cur, W * H);
}

static void usb_write_all(const uint8_t *p, size_t n) {
    while (n) { size_t piece = n < 2048 ? n : 2048; int w = usb_serial_jtag_write_bytes(p, piece, pdMS_TO_TICKS(1000)); if (w <= 0) { vTaskDelay(1); continue; } p += w; n -= w; }
}
static void usb_read_all(uint8_t *p, size_t n) {
    while (n) { int r = usb_serial_jtag_read_bytes(p, n, pdMS_TO_TICKS(1000)); if (r <= 0) continue; p += r; n -= r; }
}
static void codebook_from_header(void);
static void vision_core_init(void) {
    prev = heap_caps_malloc(W * H, MALLOC_CAP_SPIRAM); background = heap_caps_malloc(W * H, MALLOC_CAP_SPIRAM);
    memcpy(tbl, POLICY_TABLE, POLICY_TABLE_LEN);
    uint8_t rc = parse_table(POLICY_TABLE_LEN);
    if (rc) { printf("table parse failed rc=%u\n", rc); while (1) vTaskDelay(1000); }
    codebook_from_header();
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
// the codebook in RAM: initialised from the generated header, replaced by a signed pack at a policy swap
#define CB_MAX_CUTS 4
#define CB_MAX_FIELDS 128
typedef struct { uint16_t reg; uint8_t n_cuts; int32_t cut[CB_MAX_CUTS]; } cb_field_t;
static cb_field_t wire_fields[CB_MAX_FIELDS]; static int wire_n = 0; static uint32_t esc_mask = 0; static uint32_t policy_version = 1;
static void codebook_from_header(void) {
    wire_n = WIRE_N_FIELDS;
    for (int i = 0; i < WIRE_N_FIELDS; i++) { wire_fields[i].reg = WIRE_FIELDS[i].reg; wire_fields[i].n_cuts = WIRE_FIELDS[i].n_cuts; for (int k = 0; k < CB_MAX_CUTS; k++) wire_fields[i].cut[k] = k < WIRE_MAX_CUTS ? WIRE_FIELDS[i].cut[k] : 0x7fffffff; }
    esc_mask = 0; for (int n = 0; n < POLICY_N_NODES; n++) { const char *nm = POLICY_NODE_NAMES[n]; if (!strcmp(nm, "tamper") || !strcmp(nm, "evidence") || !strcmp(nm, "door") || !strcmp(nm, "scene_changed")) esc_mask |= 1u << n; }
}
static uint16_t encode_reading(uint8_t *wirebuf, size_t buflen) {
    memset(wirebuf, 0, buflen); bitacc_t acc = { wirebuf, 0 };
    for (int i = 0; i < wire_n; i++) {
        int32_t v = get_reg(wire_fields[i].reg); uint32_t sym = 0;
        for (int k = 0; k < wire_fields[i].n_cuts; k++) if (v >= wire_fields[i].cut[k]) sym = k + 1;
        zeck_encode(&acc, (uint64_t)sym + 1);
    }
    return (uint16_t)((acc.bitpos + 7u) >> 3);
}
static bool background_moved(const uint8_t *since) {
    static int32_t d[R][C]; cell_mad(background, since, d);
    for (int r = 0; r < R; r++) for (int c = 0; c < C; c++) if (d[r][c] >= BACK_ON) return true;
    return false;
}

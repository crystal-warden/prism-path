// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// vision_core.h: the front end, the byte exact evaluator, the wire encoder. Shared by replay and live.
/* Note: all front end state variables are single-instance statics for the embedded vision node. */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/usb_serial_jtag.h"
#include "vision_policy.h"
#include "../../codec-bench/zeck.h"

static bool refreshed;   /* Set by front_end on the frame the background was replaced. */

/* Geometry macros for spatial grid partition and frame resolution. */
#ifdef VISION_VGA
#define FRAME_W 640                  /* Frame width in pixels for VGA resolution mode. */
#define FRAME_H 480                  /* Frame height in pixels for VGA resolution mode. */
#else
#define FRAME_W 320                  /* Frame width in pixels for QVGA resolution mode. */
#define FRAME_H 240                  /* Frame height in pixels for QVGA resolution mode. */
#endif
#define GRID_ROWS 6                  /* Number of vertical grid rows in spatial cell partition. */
#define GRID_COLS 8                  /* Number of horizontal grid columns in spatial cell partition. */
#define CELL_W (FRAME_W / GRID_COLS) /* Cell width in pixels derived from frame geometry. */
#define CELL_H (FRAME_H / GRID_ROWS) /* Cell height in pixels derived from frame geometry. */

/* Backward compatibility aliases for existing geometry identifiers. */
#define W FRAME_W
#define H FRAME_H
#define R GRID_ROWS
#define C GRID_COLS
#define CW CELL_W
#define CH CELL_H

/* Front end motion, background, and scene detection threshold constants. */
#define MOTION_ON 16                 /* Threshold for cell mean absolute difference to count as motion. */
#define BACK_ON 24                   /* Threshold for cell mean absolute difference against background. */
#define JUMP_CELLS 32                /* Cell count jump threshold indicating sudden scene step movement. */
#define JUMP_FRAMES 5                /* Window length in frames over which step movement is measured. */
#define SCENE_CELLS ((GRID_ROWS * GRID_COLS) * 3 / 4) /* Minimum cell threshold for scene change determination. */
#define SCENE_FRAMES 20              /* Frame count threshold of still departed pixels to trigger scene change. */
#define CLEAN_FRAMES 20              /* Consecutive motion-free frames required to adopt anchored normal. */

/* FNV-1a 32-bit hash constants for background normal fingerprinting. */
#define FNV_OFFSET_BASIS 2166136261u /* FNV-1a 32-bit initial offset basis constant. */
#define FNV_PRIME 16777619u          /* FNV-1a 32-bit prime multiplier constant. */
#define FNV_HASH_FOLD_SHIFT 16       /* Shift value to fold 32-bit FNV hash into 16-bit identifier. */

/* Front end state calculation thresholds. */
#define SCENE_UNSTABLE_DIVISOR 2     /* Divisor for scene cell count threshold to reset unstable state. */

/* Codebook and wire encoding constants. */
#define CUT_UNSET_FILL 0x7fffffff    /* Fill sentinel value (INT32_MAX) for unused cut points. */
#define ZECK_SYMBOL_OFFSET 1         /* Symbol offset for Zeckendorf integer encoding. */
#define BITS_PER_BYTE_MASK 7u        /* Bit mask for rounding bit position to byte boundary. */
#define BITS_TO_BYTES_SHIFT 3        /* Bit shift to convert bit count to byte count. */

/* ---------------------------------------------------------------- the evaluator: the shared embedded evaluator
   (prismpath-hw/ppt_eval.h), the one every firmware includes and interp_hdr.c certifies on the host; caps set here. */
#define TBL_MAX        8192
#define PPT_MAX_FIELDS 128
#define STACK_MAX      256
#include "../../ppt_eval.h"

/* ---------------------------------------------------------------- the front end (matches frontend.py) */
static uint8_t *cur;
static uint8_t *prev;
static uint8_t *background;
static uint32_t frame_n = 0;
static int32_t departed_history[JUMP_FRAMES + 1];
static int departed_history_len = 0;
static int32_t departed_still = 0;
static bool unstable = false;
static bool scene_changed = false;
static int32_t clean_run = 0;
static bool normal_set = false;
static uint16_t normal_id = 0;

/* The normal's id: FNV-1a over the background pixels, folded to 16 bits; every reading and keyframe names it. */
static uint16_t normal_hash(void)
{
    uint32_t fnv = FNV_OFFSET_BASIS;
    for (uint32_t i = 0; i < FRAME_W * FRAME_H; i++) {
        fnv ^= background[i];
        fnv *= FNV_PRIME;
    }
    return (uint16_t)(fnv ^ (fnv >> FNV_HASH_FOLD_SHIFT));
}

static int32_t motion_mad[GRID_ROWS][GRID_COLS];
static int32_t background_mad[GRID_ROWS][GRID_COLS];

/* A cell MAD value represents the mean absolute difference in gray levels (0 to 255)
   over CELL_W * CELL_H pixels between two frames. Thresholds like MOTION_ON (16) and
   BACK_ON (24) are evaluated in these MAD units. */
static void cell_mad(const uint8_t *frame_a, const uint8_t *frame_b, int32_t out[GRID_ROWS][GRID_COLS])
{
    for (int row = 0; row < GRID_ROWS; row++) {
        for (int col = 0; col < GRID_COLS; col++) {
            uint32_t abs_diff_sum = 0;
            for (int y_pos = row * CELL_H; y_pos < (row + 1) * CELL_H; y_pos++) {
                const uint8_t *pa = frame_a + y_pos * FRAME_W + col * CELL_W;
                const uint8_t *pb = frame_b + y_pos * FRAME_W + col * CELL_W;
                for (int x_pos = 0; x_pos < CELL_W; x_pos++) {
                    int diff = (int)pa[x_pos] - (int)pb[x_pos];
                    abs_diff_sum += (uint32_t)(diff < 0 ? -diff : diff);
                }
            }
            out[row][col] = (int32_t)(abs_diff_sum / (CELL_W * CELL_H));
        }
    }
}

static void adopt_normal(void)
{
    memcpy(background, cur, FRAME_W * FRAME_H);
    normal_id = normal_hash();
    normal_set = true;
    refreshed = true;
    scene_changed = false;
    departed_still = 0;
    unstable = false;
    departed_history_len = 0;
    clean_run = 0;
}

static void front_end(int32_t *motion_cells, int32_t *dark, int32_t *step, int32_t *door_hit, int32_t *scene)
{
    if (frame_n == 0) {
        memcpy(prev, cur, FRAME_W * FRAME_H);
        memcpy(background, cur, FRAME_W * FRAME_H);
        departed_history_len = 0;
        departed_still = 0;
        unstable = false;
        scene_changed = false;
        clean_run = 0;
        normal_set = false;
        normal_id = normal_hash();
    }
    cell_mad(cur, prev, motion_mad);
    cell_mad(cur, background, background_mad);
    int32_t motion_cell_count = 0;
    int32_t departed = 0;
    uint32_t sum = 0;
    for (int row = 0; row < GRID_ROWS; row++) {
        for (int col = 0; col < GRID_COLS; col++) {
            if (motion_mad[row][col] >= MOTION_ON) {
                motion_cell_count++;
            }
            if (background_mad[row][col] >= BACK_ON) {
                departed++;
            }
        }
    }
    for (uint32_t i = 0; i < FRAME_W * FRAME_H; i++) {
        sum += cur[i];
    }
    *motion_cells = motion_cell_count;
    *dark = (int32_t)(sum / (FRAME_W * FRAME_H));
    /* The step: departed rose by JUMP_CELLS or more within JUMP_FRAMES frames (departed_history holds the last JUMP_FRAMES + 1 counts). */
    if (departed_history_len < JUMP_FRAMES + 1) {
        departed_history[departed_history_len++] = departed;
    } else {
        memmove(departed_history, departed_history + 1, JUMP_FRAMES * sizeof(departed_history[0]));
        departed_history[JUMP_FRAMES] = departed;
    }
    *step = (departed_history_len > JUMP_FRAMES && departed - departed_history[0] >= JUMP_CELLS);
    if (*step) {
        unstable = true;
    }
    if (unstable && departed < SCENE_CELLS / SCENE_UNSTABLE_DIVISOR) {
        unstable = false;
        departed_still = 0;
    }
    departed_still = (unstable && motion_cell_count == 0 && departed >= SCENE_CELLS) ? departed_still + 1 : 0;
    if (departed_still >= SCENE_FRAMES) {
        scene_changed = true;
    }
    *scene = scene_changed ? 1 : 0;
    int32_t door_cell_hit = 0;
    for (int door_index = 0; door_index < DOOR_N; door_index++) {
        int row = DOOR_CELLS[door_index][0];
        int col = DOOR_CELLS[door_index][1];
        if (motion_mad[row][col] >= MOTION_ON && background_mad[row][col] >= BACK_ON) {
            door_cell_hit = 1;
        }
    }
    *door_hit = door_cell_hit;
    frame_n++;
    /* The anchored normal: until the first clean stretch has passed, the background follows the frame (so b equals m)
       and the first CLEAN_FRAMES frames with no motion end the search; that frame is the normal. */
    if (!normal_set) {
        clean_run = (motion_cell_count == 0) ? clean_run + 1 : 0;
        if (clean_run >= CLEAN_FRAMES) {
            adopt_normal();
        } else {
            memcpy(background, cur, FRAME_W * FRAME_H);
            normal_id = normal_hash();
        }
    }
    refreshed = false; /* No refresh clock (T2): the normal changes only through adopt_normal(). */
    memcpy(prev, cur, FRAME_W * FRAME_H);
}

static void usb_write_all(const uint8_t *p, size_t n)
{
    while (n) {
        size_t piece = n < 2048 ? n : 2048;
        int w = usb_serial_jtag_write_bytes(p, piece, pdMS_TO_TICKS(1000));
        if (w <= 0) {
            vTaskDelay(1);
            continue;
        }
        p += w;
        n -= w;
    }
}

static void usb_read_all(uint8_t *p, size_t n)
{
    while (n) {
        int r = usb_serial_jtag_read_bytes(p, n, pdMS_TO_TICKS(1000));
        if (r <= 0) {
            continue;
        }
        p += r;
        n -= r;
    }
}

static void codebook_from_header(void);

static void vision_core_init(void)
{
    prev = heap_caps_malloc(FRAME_W * FRAME_H, MALLOC_CAP_SPIRAM);
    background = heap_caps_malloc(FRAME_W * FRAME_H, MALLOC_CAP_SPIRAM);
    memcpy(tbl, POLICY_TABLE, POLICY_TABLE_LEN);
    uint8_t rc = parse_table(POLICY_TABLE_LEN);
    if (rc) {
        printf("table parse failed rc=%u\n", rc);
        while (1) {
            vTaskDelay(1000);
        }
    }
    codebook_from_header();
}

static void decide(int32_t motion_cells, int32_t dark, int32_t step, int32_t door_hit, int32_t scene, uint16_t *out_node, uint16_t *out_steps)
{
    memset(regs, 0, sizeof(regs));
    #define SETM(r, c) set_reg(REG_m_##r##c, motion_mad[r][c]); set_reg(REG_b_##r##c, background_mad[r][c]);
    SETM(0,0) SETM(0,1) SETM(0,2) SETM(0,3) SETM(0,4) SETM(0,5) SETM(0,6) SETM(0,7)
    SETM(1,0) SETM(1,1) SETM(1,2) SETM(1,3) SETM(1,4) SETM(1,5) SETM(1,6) SETM(1,7)
    SETM(2,0) SETM(2,1) SETM(2,2) SETM(2,3) SETM(2,4) SETM(2,5) SETM(2,6) SETM(2,7)
    SETM(3,0) SETM(3,1) SETM(3,2) SETM(3,3) SETM(3,4) SETM(3,5) SETM(3,6) SETM(3,7)
    SETM(4,0) SETM(4,1) SETM(4,2) SETM(4,3) SETM(4,4) SETM(4,5) SETM(4,6) SETM(4,7)
    SETM(5,0) SETM(5,1) SETM(5,2) SETM(5,3) SETM(5,4) SETM(5,5) SETM(5,6) SETM(5,7)
    #undef SETM
    set_reg(REG_motion_cells, motion_cells);
    set_reg(REG_dark, dark);
    set_reg(REG_step, step);
    set_reg(REG_door_hit, door_hit);
    set_reg(REG_scene_changed, scene);
    uint16_t node = start_node;
    uint16_t target = 0;
    uint16_t steps = 0;
    uint8_t err = 0;
    while (steps < max_steps && node_edge_count(node) > 0) {
        int8_t edge_matched = evaluate(node, &target, &err);
        if (edge_matched < 0 || err) {
            break;
        }
        node = target;
        steps++;
    }
    *out_node = node;
    *out_steps = steps;
}

/* The codebook in RAM: initialised from the generated header, replaced by a signed pack at a policy swap. */
#define CB_MAX_CUTS 4
#define CB_MAX_FIELDS 128
typedef struct {
    uint16_t reg;
    uint8_t n_cuts;
    int32_t cut[CB_MAX_CUTS];
} cb_field_t;

static cb_field_t wire_fields[CB_MAX_FIELDS];
static int wire_n = 0;
static uint32_t esc_mask = 0;
static uint32_t policy_version = 1;

static void codebook_from_header(void)
{
    wire_n = WIRE_N_FIELDS;
    for (int field_index = 0; field_index < WIRE_N_FIELDS; field_index++) {
        wire_fields[field_index].reg = WIRE_FIELDS[field_index].reg;
        wire_fields[field_index].n_cuts = WIRE_FIELDS[field_index].n_cuts;
        for (int cut_index = 0; cut_index < CB_MAX_CUTS; cut_index++) {
            wire_fields[field_index].cut[cut_index] = cut_index < WIRE_MAX_CUTS ? WIRE_FIELDS[field_index].cut[cut_index] : CUT_UNSET_FILL;
        }
    }
    esc_mask = 0;
    for (int node_index = 0; node_index < POLICY_N_NODES; node_index++) {
        const char *node_name = POLICY_NODE_NAMES[node_index];
        if (!strcmp(node_name, "tamper") || !strcmp(node_name, "evidence") || !strcmp(node_name, "door") || !strcmp(node_name, "scene_changed")) {
            esc_mask |= 1u << node_index;
        }
    }
}

static uint16_t encode_reading(uint8_t *wirebuf, size_t buflen)
{
    memset(wirebuf, 0, buflen);
    bitacc_t acc = { wirebuf, 0 };
    for (int field_index = 0; field_index < wire_n; field_index++) {
        int32_t val = get_reg(wire_fields[field_index].reg);
        uint32_t sym = 0;
        for (int cut_index = 0; cut_index < wire_fields[field_index].n_cuts; cut_index++) {
            if (val >= wire_fields[field_index].cut[cut_index]) {
                sym = cut_index + 1;
            }
        }
        zeck_encode(&acc, (uint64_t)sym + ZECK_SYMBOL_OFFSET);
    }
    return (uint16_t)((acc.bitpos + BITS_PER_BYTE_MASK) >> BITS_TO_BYTES_SHIFT);
}

static bool background_moved(const uint8_t *since)
{
    static int32_t diff_grid[GRID_ROWS][GRID_COLS];
    cell_mad(background, since, diff_grid);
    for (int row = 0; row < GRID_ROWS; row++) {
        for (int col = 0; col < GRID_COLS; col++) {
            if (diff_grid[row][col] >= BACK_ON) {
                return true;
            }
        }
    }
    return false;
}

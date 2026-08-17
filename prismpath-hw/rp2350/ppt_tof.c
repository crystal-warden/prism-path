// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_tof.c — on-device sensor -> decision demo on the RP2350.
 *
 * Beyond the substrate cert (where the host feeds register values), here the MCU reads a real
 * VL53L0X time-of-flight sensor over I2C, forms the field vector itself, and runs a signed Level M
 * policy ON-DEVICE — distance drives a routed proximity band, live. Same compiler, same .ppt format,
 * same byte-exact evaluator as every other substrate; the table is baked into flash
 * (table_proximity.h) instead of streamed. Wave your hand at the sensor, the decision changes.
 *
 * Reports each decision over USB-CDC and mirrors the band on the on-board LED.
 */
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "vl53l0x.h"
#include "table_proximity.h"

#define I2C_PORT  i2c0
#define SDA_PIN   4
#define SCL_PIN   5
#define TBL_MAX   640
#define REGS_MAX  (4 + 8 * 24)
#define STACK_MAX 64

enum { TY_NONE = 0, TY_BOOL = 1, TY_INT = 2, TY_STR = 3 };
enum { OP_EQ = 0, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_TRUTHY };

static uint8_t tbl[TBL_MAX];
static uint8_t regs[REGS_MAX];
static uint16_t n_fields, n_atoms, n_nodes, n_edges, prog_len;
static uint16_t atoms_off, nodes_off, edges_off, prog_off_base;

/* ---- the evaluator core (interp.c / ppt_rp2350.c, byte-exact) ---- */
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static int32_t rd32(const uint8_t *p) { int32_t v; memcpy(&v, p, 4); return v; }

static uint8_t parse_table(uint16_t len) {
    if (len < 28) return 3;
    if (rd32(tbl) != (int32_t)0x4D545050L || rd16(tbl + 4) != 1) return 1;
    n_fields = rd16(tbl + 6);
    n_atoms  = rd16(tbl + 10);
    n_nodes  = rd16(tbl + 12);
    n_edges  = rd16(tbl + 14);
    prog_len = rd16(tbl + 16);
    atoms_off = 28;
    nodes_off = atoms_off + 8 * n_atoms;
    edges_off = nodes_off + 4 * n_nodes;
    prog_off_base = edges_off + 6 * n_edges;
    return (prog_off_base + 2 * prog_len != len) ? 3 : 0;
}
static uint8_t eval_atom(uint16_t atom_idx) {
    const uint8_t *a = tbl + atoms_off + 8 * (uint32_t)atom_idx;
    uint16_t field = rd16(a);
    uint8_t op = a[2], aty = a[3];
    int32_t aval = rd32(a + 4);
    const uint8_t *r = regs + 4 + 8 * (uint32_t)field;
    int32_t rty = rd32(r), rval = rd32(r + 4);
    uint8_t lnum = (rty == TY_BOOL || rty == TY_INT);
    uint8_t rnum = (aty == TY_BOOL || aty == TY_INT);
    switch (op) {
    case OP_EQ: case OP_NE: {
        uint8_t eq;
        if (lnum && rnum)                          eq = (rval == aval);
        else if (rty == TY_STR && aty == TY_STR)   eq = (rval == aval);
        else if (rty == TY_NONE && aty == TY_NONE) eq = 1;
        else                                       eq = 0;
        return op == OP_EQ ? eq : (uint8_t)!eq;
    }
    case OP_LT: case OP_LE: case OP_GT: case OP_GE:
        if (!(lnum && rnum)) return 0;
        switch (op) {
        case OP_LT: return rval <  aval;
        case OP_LE: return rval <= aval;
        case OP_GT: return rval >  aval;
        default:    return rval >= aval;
        }
    case OP_TRUTHY: return rty == TY_NONE ? 0 : (rval != 0);
    }
    return 0;
}
static int8_t eval_prog(uint16_t e_prog_off, uint16_t e_prog_cnt, uint8_t *err) {
    uint8_t stack[STACK_MAX];
    int8_t sp = 0;
    for (uint16_t i = 0; i < e_prog_cnt; i++) {
        uint16_t w = rd16(tbl + prog_off_base + 2 * (uint32_t)(e_prog_off + i));
        if (w < 0x8000) {
            if (sp >= STACK_MAX) { *err = 7; return 0; }
            stack[sp++] = eval_atom(w);
        } else switch (w) {
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
    const uint8_t *n = tbl + nodes_off + 4 * (uint32_t)node;
    uint16_t edge_off = rd16(n), edge_cnt = rd16(n + 2);
    for (uint16_t i = 0; i < edge_cnt; i++) {
        const uint8_t *e = tbl + edges_off + 6 * (uint32_t)(edge_off + i);
        if (eval_prog(rd16(e + 2), rd16(e + 4), err)) { *out_target = rd16(e); return (int8_t)i; }
        if (*err) return -1;
    }
    return -1;
}

/* ---- the demo ---- */
static const char *BANDS[] = {"contact", "near", "mid", "far"};

/* Connectivity check: print every device that ACKs on the bus. VL53L0X should appear at 0x29. */
static void scan_i2c(void) {
    printf("i2c scan (SDA=GP%d SCL=GP%d):", SDA_PIN, SCL_PIN);
    int found = 0;
    for (uint8_t a = 0x08; a < 0x78; a++) {
        uint8_t d;
        if (i2c_read_blocking(I2C_PORT, a, &d, 1, false) >= 0) { printf(" 0x%02x", a); found++; }
    }
    printf("  -> %d device%s%s\r\n", found, found == 1 ? "" : "s",
           found == 0 ? "  (check power + SDA/SCL pins)" : "");
}

int main(void) {
    stdio_init_all();                                   /* USB-CDC for the running report */
    i2c_init(I2C_PORT, 100 * 1000);                     /* 100 kHz: tolerant of weak/no pull-ups */
    gpio_set_function(SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(SDA_PIN);
    gpio_pull_up(SCL_PIN);
    sleep_ms(1500);                                     /* let USB-CDC enumerate before the scan line */
    scan_i2c();
#ifdef PICO_DEFAULT_LED_PIN
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
#endif

    vl53l0x_t tof;
    bool sensor_ok = vl53l0x_init(&tof, I2C_PORT, VL53L0X_ADDR);

    memcpy(tbl, PROX_TABLE, PROX_TABLE_LEN);            /* bake the signed policy into RAM */
    uint8_t rc = parse_table(PROX_TABLE_LEN);
    memset(regs, 0, sizeof(regs));
    regs[4] = TY_INT;                                   /* field 0 (dist_mm) is an int */

    for (;;) {
        if (rc != 0) { printf("table parse rc=%d (firmware issue)\r\n", rc); sleep_ms(1000); continue; }
        if (!sensor_ok) {
            scan_i2c();                                          /* live bus scan — fiddle wires */
            sensor_ok = vl53l0x_init(&tof, I2C_PORT, VL53L0X_ADDR);   /* retry without reflashing */
            printf(sensor_ok ? "  VL53L0X up at 0x29 -> starting demo\r\n"
                             : "  VL53L0X (0x29) not answering yet...\r\n");
            sleep_ms(800);
            continue;
        }
        uint16_t d = vl53l0x_read_range_single(&tof);
        int32_t v = (int32_t)d;
        memcpy(regs + 8, &v, 4);                        /* field 0 value = distance */
        uint8_t err = 0;
        uint16_t target = 0;
        int8_t e = evaluate(0, &target, &err);
        int band = (e >= 0 && e < 4) ? e : -1;
#ifdef PICO_DEFAULT_LED_PIN
        gpio_put(PICO_DEFAULT_LED_PIN, band == 0 || band == 1);   /* lit when something is near */
#endif
        printf("dist=%5u mm  ->  band %d (%s)\r\n", d, band, band >= 0 ? BANDS[band] : "err");
        sleep_ms(120);
    }
}

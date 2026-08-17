// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_fusion.c — the 2-field fusion pod: two independent analog fields (pot + photoresistor) fused into
 * one on-device decision by a baked Level M policy, shown as an RGB LED color.
 *
 * Field 0 `level` = potentiometer on GPIO15 (ADC2_CH3). Field 1 `light` = photoresistor on GPIO34
 * (ADC1_CH6). The evaluator core is a BYTE-EXACT copy of interp.c / ppt_esp32.c. The winning edge is the
 * verdict: alert (red) fires only when BOTH fields say so (knob high AND dark) — a fused region neither
 * field reaches alone; warn (amber) when either alone; ok (green) otherwise. Console left on for status.
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_adc/adc_oneshot.h"
#include "fusion_table.h"

#define LEVEL_ADC_UNIT  ADC_UNIT_2
#define LEVEL_ADC_CHAN  ADC_CHANNEL_3     /* GPIO15 = ADC2_CH3 (pot) */
#define LIGHT_ADC_UNIT  ADC_UNIT_1
#define LIGHT_ADC_CHAN  ADC_CHANNEL_6     /* GPIO34 = ADC1_CH6 (photoresistor) */
#define LED_R  25
#define LED_G  26
#define LED_B  27
#define RGB_COMMON_ANODE 0                /* set to 1 if the LED's long leg goes to 3V3, not GND */

#define TBL_MAX   640
#define REGS_MAX  (4 + 8 * 24)
#define STACK_MAX 64

enum { TY_NONE = 0, TY_BOOL = 1, TY_INT = 2, TY_STR = 3 };
enum { OP_EQ = 0, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_TRUTHY };

static uint8_t tbl[TBL_MAX];
static uint8_t regs[REGS_MAX];
static uint16_t n_fields, n_atoms, n_nodes, n_edges, prog_len;
static uint16_t atoms_off, nodes_off, edges_off, prog_off_base;

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static int32_t rd32(const uint8_t *p) { int32_t v; memcpy(&v, p, 4); return v; }
static void wr32(uint8_t *p, int32_t v) { memcpy(p, &v, 4); }

static uint8_t parse_table(uint16_t len) {
    if (len < 28) return 3;
    if (rd32(tbl) != (int32_t)0x4D545050L || rd16(tbl + 4) != 1) return 1;
    n_fields = rd16(tbl + 6); n_atoms = rd16(tbl + 10); n_nodes = rd16(tbl + 12);
    n_edges = rd16(tbl + 14); prog_len = rd16(tbl + 16);
    atoms_off = 28;
    nodes_off = atoms_off + 8 * n_atoms;
    edges_off = nodes_off + 4 * n_nodes;
    prog_off_base = edges_off + 6 * n_edges;
    if (prog_off_base + 2 * prog_len != len) return 3;
    return 0;
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
    case OP_TRUTHY:
        return rty == TY_NONE ? 0 : (rval != 0);
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

/* ---------------------------------------------------------------- I/O */
static adc_oneshot_unit_handle_t adc1, adc2;

static void adc_setup(void) {
    adc_oneshot_unit_init_cfg_t u1 = { .unit_id = ADC_UNIT_1 };
    adc_oneshot_unit_init_cfg_t u2 = { .unit_id = ADC_UNIT_2 };
    adc_oneshot_new_unit(&u1, &adc1);
    adc_oneshot_new_unit(&u2, &adc2);
    adc_oneshot_chan_cfg_t c = { .atten = ADC_ATTEN_DB_12, .bitwidth = ADC_BITWIDTH_12 };
    adc_oneshot_config_channel(adc1, LIGHT_ADC_CHAN, &c);
    adc_oneshot_config_channel(adc2, LEVEL_ADC_CHAN, &c);
}

static void rgb_setup(void) {
    gpio_config_t g = { .pin_bit_mask = (1ULL << LED_R) | (1ULL << LED_G) | (1ULL << LED_B),
                        .mode = GPIO_MODE_OUTPUT };
    gpio_config(&g);
}

static void rgb(uint8_t r, uint8_t g, uint8_t b) {
#if RGB_COMMON_ANODE
    r = !r; g = !g; b = !b;                 /* common-anode: drive low to light */
#endif
    gpio_set_level(LED_R, r);
    gpio_set_level(LED_G, g);
    gpio_set_level(LED_B, b);
}

/* verdict (winning edge index) -> RGB + name */
static void show(int8_t edge, const char **name) {
    switch (edge) {
    case 0: rgb(1, 0, 0); *name = "ALERT (red)";  break;   /* high AND dark */
    case 1: case 2: rgb(1, 1, 0); *name = "warn (amber)"; break;
    case 3: rgb(0, 1, 0); *name = "ok (green)";   break;
    default: rgb(0, 0, 0); *name = "none";        break;
    }
}

void app_main(void) {
    adc_setup();
    rgb_setup();
    rgb(0, 0, 0);
    uint8_t rc = (FUSION_TABLE_LEN <= TBL_MAX)
                 ? (memcpy(tbl, FUSION_TABLE, FUSION_TABLE_LEN), parse_table(FUSION_TABLE_LEN)) : 2;
    if (rc) { printf("\n[pod] table parse FAILED rc=%u\n", rc); while (1) vTaskDelay(pdMS_TO_TICKS(1000)); }
    printf("\n[pod] 2-field fusion policy loaded (%u bytes, %u fields). level=pot(GPIO15) light=LDR(GPIO34).\n",
           FUSION_TABLE_LEN, n_fields);

    while (1) {
        int level = 0, light = 0;
        adc_oneshot_read(adc2, LEVEL_ADC_CHAN, &level);
        adc_oneshot_read(adc1, LIGHT_ADC_CHAN, &light);
        wr32(regs, 0);                                   /* node 0 = classify */
        wr32(regs + 4, TY_INT); wr32(regs + 8, level);   /* field 0 = level */
        wr32(regs + 12, TY_INT); wr32(regs + 16, light); /* field 1 = light */
        uint8_t err = 0; uint16_t target = 0;
        int8_t edge = evaluate(0, &target, &err);
        const char *name = "?";
        if (err) { printf("[pod] eval error %u\n", err); rgb(0, 0, 0); }
        else { show(edge, &name); printf("[pod] level=%4d light=%4d -> %s\n", level, light, name); }
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

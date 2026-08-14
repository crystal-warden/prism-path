/* ppt_pot.c — the fusion-pod first light: an analog field (potentiometer on GPIO34) decided on-device
 * by a baked Level M policy, driving the onboard LED (GPIO2) brightness by band.
 *
 * The evaluator core is a BYTE-EXACT copy of interp.c / ppt_esp32.c: atoms are comparators over the
 * field register file, each edge's RPN program folds atom results, first true edge wins. Only the I/O
 * differs: read the ADC, set field 0 = knob, run the baked table, map the winning edge (the band) to a
 * PWM duty. Turning the knob steps the LED through four discrete levels at the policy's exact thresholds
 * (1024/2048/3072) — a decided band, not a smooth fade. Console left on UART0 for a readable status.
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/ledc.h"
#include "esp_adc/adc_oneshot.h"
#include "pot_table.h"

#define POT_ADC_UNIT   ADC_UNIT_2
#define POT_ADC_CHAN   ADC_CHANNEL_3      /* GPIO15 = ADC2_CH3 (ADC2 is free — no Wi-Fi here) */
#define LED_GPIO       2
#define TBL_MAX        640
#define REGS_MAX       (4 + 8 * 24)
#define STACK_MAX      64

enum { TY_NONE = 0, TY_BOOL = 1, TY_INT = 2, TY_STR = 3 };
enum { OP_EQ = 0, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_TRUTHY };

static uint8_t tbl[TBL_MAX];
static uint8_t regs[REGS_MAX];
static uint16_t n_fields, n_atoms, n_nodes, n_edges, prog_len;
static uint16_t atoms_off, nodes_off, edges_off, prog_off_base;

/* ------------------------------------------------------- buffer readers (little-endian, in place) */
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static int32_t rd32(const uint8_t *p) { int32_t v; memcpy(&v, p, 4); return v; }
static void wr32(uint8_t *p, int32_t v) { memcpy(p, &v, 4); }

/* --------------------------------------------------------- table load */
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
    if (prog_off_base + 2 * prog_len != len) return 3;
    return 0;
}

/* ------------------------------------------- the evaluator core (interp.c, byte-exact) */
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

/* ---------------------------------------------------------------- I/O setup */
static adc_oneshot_unit_handle_t adc;

static void adc_setup(void) {
    adc_oneshot_unit_init_cfg_t ucfg = { .unit_id = POT_ADC_UNIT };
    adc_oneshot_new_unit(&ucfg, &adc);
    adc_oneshot_chan_cfg_t ccfg = { .atten = ADC_ATTEN_DB_12, .bitwidth = ADC_BITWIDTH_12 };
    adc_oneshot_config_channel(adc, POT_ADC_CHAN, &ccfg);
}

static void led_setup(void) {
    ledc_timer_config_t t = { .speed_mode = LEDC_LOW_SPEED_MODE, .duty_resolution = LEDC_TIMER_8_BIT,
                              .timer_num = LEDC_TIMER_0, .freq_hz = 5000, .clk_cfg = LEDC_AUTO_CLK };
    ledc_timer_config(&t);
    ledc_channel_config_t c = { .gpio_num = LED_GPIO, .speed_mode = LEDC_LOW_SPEED_MODE,
                                .channel = LEDC_CHANNEL_0, .timer_sel = LEDC_TIMER_0, .duty = 0, .hpoint = 0 };
    ledc_channel_config(&c);
}

static void led_set(uint8_t duty) {
    ledc_set_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, duty);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0);
}

/* band (winning edge index) -> LED brightness: four discrete levels */
static const uint8_t BAND_DUTY[4] = { 0, 24, 96, 255 };
static const char *BAND_NAME[4] = { "q0", "q1", "q2", "q3" };

void app_main(void) {
    adc_setup();
    led_setup();
    uint8_t rc = (POT_TABLE_LEN <= TBL_MAX) ? (memcpy(tbl, POT_TABLE, POT_TABLE_LEN), parse_table(POT_TABLE_LEN)) : 2;
    if (rc) { printf("\n[pot] table parse FAILED rc=%u\n", rc); while (1) vTaskDelay(pdMS_TO_TICKS(1000)); }
    printf("\n[pot] policy loaded (%u bytes, %u fields). Turn the knob — LED steps at 1024/2048/3072.\n",
           POT_TABLE_LEN, n_fields);

    while (1) {
        int raw = 0;
        adc_oneshot_read(adc, POT_ADC_CHAN, &raw);
        wr32(regs, 0);                                   /* node 0 = classify (start) */
        wr32(regs + 4, TY_INT);                          /* field 0 (knob) type */
        wr32(regs + 8, raw);                             /* field 0 value */
        uint8_t err = 0; uint16_t target = 0;
        int8_t band = evaluate(0, &target, &err);
        if (err) { printf("[pot] eval error %u\n", err); led_set(0); }
        else if (band < 0 || band > 3) { printf("[pot] knob=%4d no band\n", raw); led_set(0); }
        else {
            led_set(BAND_DUTY[band]);
            printf("[pot] knob=%4d -> band %d (%s)\n", raw, band, BAND_NAME[band]);
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

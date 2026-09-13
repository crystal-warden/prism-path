// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_esp32.c — the PPT v1 table interpreter on an ESP32-C6 (single-core RISC-V + Wi-Fi 6 / 802.15.4):
 * the wireless-capable RISC-V MCU substrate, and the intended node of the edge decision-fusion mesh.
 *
 * The evaluator core below is a BYTE-EXACT copy of interp.c / ppt_uno.c / ppt_rp2350.c: atoms are
 * comparators over the field register file, each edge's RPN program folds atom results, first true
 * edge wins. ESP32-C6 is little-endian RISC-V, same as the .ppt format, so rd16/rd32 read in place.
 * Only the I/O layer differs: the ESP-IDF UART driver on UART0 (the CP2102 bridge), with the console
 * and all logging disabled (sdkconfig.defaults) so nothing corrupts the binary wire.
 *
 * Same protocol as the AVR / RP2350 (host drives; one reply per request):
 *   'I'                          -> 'i' + u8 len + ident string
 *   'L' + u16 len + <ppt bytes>  -> 'l' (loaded) | 'E' + u8 code
 *   'V' + u16 len + <regs bytes> -> 'M' + u8 edge + u16 target | 'N' (none) | 'E' + u8 code
 *
 * Error codes: 1 bad-magic/version 2 too-big 3 length-mismatch 4 bad-node 5 bad-regs-len
 *              6 no-table 7 stack-overflow 8 bad-opcode
 */
#include <stdint.h>
#include <string.h>
#include "sdkconfig.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define UART      UART_NUM_0
#define UART_BAUD 115200
#define TBL_MAX   640
#define REGS_MAX  (4 + 8 * 24)
#define STACK_MAX 64

enum { TY_NONE = 0, TY_BOOL = 1, TY_INT = 2, TY_STR = 3 };
enum { OP_EQ = 0, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_TRUTHY };

static uint8_t tbl[TBL_MAX];
static uint8_t regs[REGS_MAX];
static uint16_t n_fields, n_atoms, n_nodes, n_edges, prog_len;
static uint16_t atoms_off, nodes_off, edges_off, prog_off_base;
static uint8_t loaded = 0;

/* ---------------------------------------------------------------- uart I/O (UART0, driver) */
static uint8_t rx(void) {
    uint8_t byte;
    while (uart_read_bytes(UART, &byte, 1, portMAX_DELAY) != 1) { /* retry */ }
    return byte;
}
static void tx(uint8_t byte) { uart_write_bytes(UART, (const char *)&byte, 1); }
static void tx_flush(void) { uart_wait_tx_done(UART, portMAX_DELAY); }
static uint16_t get_u16(void) {
    uint16_t lo = rx();
    return lo | ((uint16_t)rx() << 8);
}

/* ------------------------------------------------------- buffer readers */
static uint16_t rd16(const uint8_t *bytes) { return (uint16_t)(bytes[0] | ((uint16_t)bytes[1] << 8)); }
static int32_t rd32(const uint8_t *bytes) {
    int32_t value;
    memcpy(&value, bytes, 4);
    return value;
}

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
    uint16_t need = prog_off_base + 2 * prog_len;
    if (need != len) return 3;
    return 0;
}

/* ------------------------------------------- the evaluator core: a local copy of interp.c's core, pending conversion to ../ppt_eval.h (eval_copies_check.py) */
static uint8_t eval_atom(uint16_t atom_idx) {
    const uint8_t *atom = tbl + atoms_off + 8 * (uint32_t)atom_idx;
    uint16_t field = rd16(atom);
    uint8_t op = atom[2], aty = atom[3];
    int32_t aval = rd32(atom + 4);
    const uint8_t *reg = regs + 4 + 8 * (uint32_t)field;
    int32_t rty = rd32(reg), rval = rd32(reg + 4);
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
    for (uint16_t word_index = 0; word_index < e_prog_cnt; word_index++) {
        uint16_t word = rd16(tbl + prog_off_base + 2 * (uint32_t)(e_prog_off + word_index));
        if (word < 0x8000) {
            if (sp >= STACK_MAX) { *err = 7; return 0; }
            stack[sp++] = eval_atom(word);
        } else switch (word) {
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
    const uint8_t *node_entry = tbl + nodes_off + 4 * (uint32_t)node;
    uint16_t edge_off = rd16(node_entry), edge_cnt = rd16(node_entry + 2);
    for (uint16_t edge_index = 0; edge_index < edge_cnt; edge_index++) {
        const uint8_t *edge_entry = tbl + edges_off + 6 * (uint32_t)(edge_off + edge_index);
        if (eval_prog(rd16(edge_entry + 2), rd16(edge_entry + 4), err)) {
            *out_target = rd16(edge_entry);
            return (int8_t)edge_index;
        }
        if (*err) return -1;
    }
    return -1;
}

/* ---------------------------------------------------------------- main loop */
/* Ident derives from the target + ISA at compile time — one firmware certifies whichever ESP chip is
 * flashed: esp32c6 (RISC-V), esp32 (Xtensa), etc. */
#if defined(__riscv)
#define ISA_TAG "riscv"
#elif defined(__XTENSA__)
#define ISA_TAG "xtensa"
#else
#define ISA_TAG "unknown"
#endif
static const char IDENT[] = "ppt-" CONFIG_IDF_TARGET "/1 " CONFIG_IDF_TARGET "-" ISA_TAG " PPTM-v1";

static void uart_setup(void) {
    const uart_config_t cfg = {
        .baud_rate = UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    uart_driver_install(UART, 1024, 0, 0, NULL, 0);
    uart_param_config(UART, &cfg);
    /* With the console disabled, IDF doesn't route UART0 to pins — set them explicitly to the
     * chip's default UART0 pads (where the USB-UART bridge is wired). */
#if CONFIG_IDF_TARGET_ESP32
    uart_set_pin(UART, 1, 3, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);       /* ESP32: TX=GPIO1 RX=GPIO3 */
#elif CONFIG_IDF_TARGET_ESP32C6
    uart_set_pin(UART, 16, 17, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);     /* ESP32-C6: TX=GPIO16 RX=GPIO17 */
#else
    uart_set_pin(UART, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
#endif
}

void app_main(void) {
    uart_setup();
    for (;;) {
        uint8_t cmd = rx();
        if (cmd == 'I') {
            tx('i');
            tx((uint8_t)(sizeof(IDENT) - 1));
            for (uint8_t byte_index = 0; byte_index < sizeof(IDENT) - 1; byte_index++) tx((uint8_t)IDENT[byte_index]);
            tx_flush();
        } else if (cmd == 'L') {
            uint16_t len = get_u16();
            if (len > TBL_MAX) {
                for (uint16_t byte_index = 0; byte_index < len; byte_index++) (void)rx();
                tx('E'); tx(2); tx_flush();
                continue;
            }
            for (uint16_t byte_index = 0; byte_index < len; byte_index++) tbl[byte_index] = rx();
            uint8_t rc = parse_table(len);
            loaded = (rc == 0);
            if (rc) { tx('E'); tx(rc); }
            else    { tx('l'); }
            tx_flush();
        } else if (cmd == 'V') {
            uint16_t len = get_u16();
            if (len > REGS_MAX) {
                for (uint16_t byte_index = 0; byte_index < len; byte_index++) (void)rx();
                tx('E'); tx(5); tx_flush();
                continue;
            }
            for (uint16_t byte_index = 0; byte_index < len; byte_index++) regs[byte_index] = rx();
            if (!loaded) { tx('E'); tx(6); tx_flush(); continue; }
            if (len != 4 + 8 * (uint32_t)n_fields) { tx('E'); tx(5); tx_flush(); continue; }
            uint16_t node = (uint16_t)rd32(regs);
            if (node >= n_nodes) { tx('E'); tx(4); tx_flush(); continue; }
            uint8_t err = 0;
            uint16_t target = 0;
            int8_t matched_edge = evaluate(node, &target, &err);
            if (err)        { tx('E'); tx(err); }
            else if (matched_edge < 0) { tx('N'); }
            else {
                tx('M');
                tx((uint8_t)matched_edge);
                tx((uint8_t)(target & 0xFF));
                tx((uint8_t)(target >> 8));
            }
            tx_flush();
        }
    }
}

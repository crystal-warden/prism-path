/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Crystal Warden Supply Chain Labs LLC
 *
 * OPA WebAssembly on an RP2350 (Pico 2 W): the module opa build -t wasm produced for the comparison
 * policy network_admission is embedded in flash and executed by the wasm3 interpreter. Binary protocol
 * over native USB-CDC, the same shape as the PPT certification firmware so the same host driver style
 * replays the A3 corpus:
 *   'I'                     -> 'i' len ident
 *   'V' u16 len <json>      -> 'M' u16 len <result json>   or  'E' u16 len <error text>
 *   'S'                     -> 's' u16 len <json stats: linear memory bytes, heap in use, heap high water>
 *   'L' u8 idx              -> 'l' after the module idx (0 network_admission, 1 sensor_interlock) is the open one
 * Both compiled modules live in flash; one runtime is open at a time (the RP2350 has 520 KB of SRAM).
 * This is the comparator's honest attempt for dimension A3 (PREREGISTRATION.md section 5).
 */
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/stdio_usb.h"
#include "opa_wasm_eval.h"
#include "wasm_network_admission.h"
#include "wasm_sensor_interlock.h"

static const struct { const char *name; const uint8_t *bytes; uint32_t len; } MODULES[] = {
    {"network_admission", wasm_network_admission, 0}, {"sensor_interlock", wasm_sensor_interlock, 0}};
static uint32_t module_len(int i) { return i == 0 ? wasm_network_admission_len : wasm_sensor_interlock_len; }

#ifndef ISA_NAME
#define ISA_NAME "rp2350-arm"
#endif
#define STACK_BYTES (24 * 1024)

static uint8_t inbuf[2048];
static char outbuf[2048];
static size_t heap_high = 0;

static void put_frame(char tag, const char *data, size_t n) {
    putchar_raw(tag); putchar_raw(n & 0xff); putchar_raw((n >> 8) & 0xff);
    for (size_t i = 0; i < n; i++) putchar_raw(data[i]);
    stdio_flush();
}
static int read_exact(uint8_t *dst, size_t n) {
    for (size_t i = 0; i < n; i++) { int c = getchar_timeout_us(2000000); if (c < 0) return -1; dst[i] = (uint8_t)c; }
    return 0;
}
static void track_heap(void) { struct mallinfo mi = mallinfo(); if ((size_t)mi.uordblks > heap_high) heap_high = mi.uordblks; }

int main(void) {
    stdio_usb_init();
    while (!stdio_usb_connected()) sleep_ms(50);
    int cur = 0;
    opa_wasm_t *w = opa_wasm_open(MODULES[cur].bytes, module_len(cur), STACK_BYTES);
    track_heap();
    for (;;) {
        int c = getchar_timeout_us(100000);
        if (c < 0) continue;
        if (c == 'I') {
            int n = snprintf(outbuf, sizeof outbuf, "opa-wasm3-rp2350/1 %s opa-abi-%s wasm3 module=%s/%u", ISA_NAME, w ? opa_wasm_abi(w) : "?", MODULES[cur].name, (unsigned)module_len(cur));
            putchar_raw('i'); putchar_raw(n); for (int i = 0; i < n; i++) putchar_raw(outbuf[i]); stdio_flush();
        } else if (c == 'S') {
            struct mallinfo mi = mallinfo();
            int n = snprintf(outbuf, sizeof outbuf, "{\"linear_memory_bytes\":%u,\"heap_in_use\":%u,\"heap_high_water\":%u,\"stack_bytes\":%u,\"open_ok\":%s}",
                             w ? opa_wasm_memory_bytes(w) : 0, (unsigned)mi.uordblks, (unsigned)heap_high, (unsigned)STACK_BYTES, w ? "true" : "false");
            put_frame('s', outbuf, n);
        } else if (c == 'L') {
            int idx = getchar_timeout_us(2000000);
            if (idx < 0 || idx > 1) { put_frame('E', "bad module", 10); continue; }
            if (idx != cur || !w) { opa_wasm_close(w); cur = idx; w = opa_wasm_open(MODULES[cur].bytes, module_len(cur), STACK_BYTES); track_heap(); }
            if (!w) { const char *e = opa_wasm_error(); put_frame('E', e, strlen(e)); continue; }
            put_frame('l', MODULES[cur].name, strlen(MODULES[cur].name));
        } else if (c == 'V') {
            uint8_t lb[2]; if (read_exact(lb, 2)) continue;
            size_t n = lb[0] | (lb[1] << 8);
            if (n >= sizeof inbuf || read_exact(inbuf, n)) { put_frame('E', "frame", 5); continue; }
            if (!w) { const char *e = opa_wasm_error(); put_frame('E', e, strlen(e)); continue; }
            const char *res = opa_wasm_eval(w, (const char *)inbuf, n);
            track_heap();
            if (!res) { const char *e = opa_wasm_error(); put_frame('E', e, strlen(e)); continue; }
            put_frame('M', res, strlen(res));
        }
    }
}

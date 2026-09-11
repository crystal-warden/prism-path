// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// relay_replay: conformance of the relay's evaluator on RISC-V. The host sends field triples over native USB,
// the relay walks the same table image the air relay carries (hop_policy.h) with the same evaluator
// (ppt_eval.h) and returns the route and step count for each, to be compared with the host engine.
//   in:  "RPL2" | n u32 | (give_up_run i32, retry_pct i32, backoff i32) x n
//   out: "RES2" | n u32 | (route u16, steps u16) x n
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/usb_serial_jtag.h"
#include "hop_policy.h"
#include "ppt_eval.h"
static void usb_write_all(const uint8_t *p, size_t n) { while (n) { int w = usb_serial_jtag_write_bytes(p, n < 2048 ? n : 2048, pdMS_TO_TICKS(1000)); if (w <= 0) { vTaskDelay(1); continue; } p += w; n -= w; } }
static void usb_read_all(uint8_t *p, size_t n) { while (n) { int r = usb_serial_jtag_read_bytes(p, n, pdMS_TO_TICKS(1000)); if (r <= 0) continue; p += r; n -= r; } }
void app_main(void)
{
    usb_serial_jtag_driver_config_t ucfg = { .tx_buffer_size = 16384, .rx_buffer_size = 16384 }; ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&ucfg));
    memcpy(tbl, POLICY_TABLE, POLICY_TABLE_LEN); uint8_t rc = parse_table(POLICY_TABLE_LEN);
    while (1) {
        uint8_t hdr[8]; usb_read_all(hdr, 4);
        if (memcmp(hdr, "RPL2", 4) != 0) continue;
        usb_read_all(hdr + 4, 4); uint32_t n; memcpy(&n, hdr + 4, 4);
        uint8_t out[8]; memcpy(out, "RES2", 4); memcpy(out + 4, &n, 4); usb_write_all(out, 8);
        for (uint32_t i = 0; i < n; i++) {
            int32_t f[3]; usb_read_all((uint8_t *)f, 12);
            uint16_t node = 0xffff, steps = 0;
            if (rc == 0) {
                memset(regs, 0, sizeof regs); set_reg(REG_give_up_run, f[0]); set_reg(REG_retry_pct, f[1]); set_reg(REG_backoff, f[2]);
                uint16_t target = 0; uint8_t err = 0; node = start_node;
                while (steps < max_steps && node_edge_count(node) > 0) { int8_t e = evaluate(node, &target, &err); if (e < 0 || err) break; node = target; steps++; }
            }
            uint8_t r[4]; memcpy(r, &node, 2); memcpy(r + 2, &steps, 2); usb_write_all(r, 4);
        }
    }
}

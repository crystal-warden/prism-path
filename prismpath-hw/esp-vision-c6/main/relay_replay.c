// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// relay_replay: conformance of the relay's evaluator on RISC-V. The host sends field triples over native USB,
// the relay walks the same table image the air relay carries (hop_policy.h) with the same evaluator
// (ppt_eval.h) and returns the route and step count for each, to be compared with the host engine.
//   in:  "RPL2" | n u32 | (give_up_run i32, retry_pct i32, backoff i32) x n
//   out: "RES2" | n u32 | (target u16, steps u16) x n
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/usb_serial_jtag.h"
#include "hop_policy.h"
#include "ppt_eval.h"
static void usb_write_all(const uint8_t *bytes, size_t remaining) { while (remaining) { int written = usb_serial_jtag_write_bytes(bytes, remaining < 2048 ? remaining : 2048, pdMS_TO_TICKS(1000)); if (written <= 0) { vTaskDelay(1); continue; } bytes += written; remaining -= written; } }
static void usb_read_all(uint8_t *bytes, size_t remaining) { while (remaining) { int read_count = usb_serial_jtag_read_bytes(bytes, remaining, pdMS_TO_TICKS(1000)); if (read_count <= 0) continue; bytes += read_count; remaining -= read_count; } }
void app_main(void)
{
    usb_serial_jtag_driver_config_t ucfg = { .tx_buffer_size = 16384, .rx_buffer_size = 16384 }; ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&ucfg));
    memcpy(tbl, POLICY_TABLE, POLICY_TABLE_LEN); uint8_t rc = parse_table(POLICY_TABLE_LEN);
    // A table that does not parse makes every vector answer 0xffff, which reads like a failed conformance run
    // rather than a broken build. Say so on the console (UART on this board, so the USB data channel stays clean).
    if (rc) printf("relay_replay: table parse failed rc=%u, every vector will answer 0xffff\n", rc);
    while (1) {
        uint8_t hdr[8]; usb_read_all(hdr, 4);
        if (memcmp(hdr, "RPL2", 4) != 0) continue;
        usb_read_all(hdr + 4, 4); uint32_t vector_count; memcpy(&vector_count, hdr + 4, 4);
        uint8_t out[8]; memcpy(out, "RES2", 4); memcpy(out + 4, &vector_count, 4); usb_write_all(out, 8);
        for (uint32_t vector_index = 0; vector_index < vector_count; vector_index++) {
            int32_t fields[3]; usb_read_all((uint8_t *)fields, 12);
            uint16_t node = 0xffff, steps = 0;
            if (rc == 0) {
                memset(regs, 0, sizeof regs); set_reg(REG_give_up_run, fields[0]); set_reg(REG_retry_pct, fields[1]); set_reg(REG_backoff, fields[2]);
                uint16_t target = 0; uint8_t err = 0; node = start_node;
                while (steps < max_steps && node_edge_count(node) > 0) { int8_t matched_edge = evaluate(node, &target, &err); if (matched_edge < 0 || err) break; node = target; steps++; }
            }
            uint8_t reply[4]; memcpy(reply, &node, 2); memcpy(reply + 2, &steps, 2); usb_write_all(reply, 4);
        }
    }
}

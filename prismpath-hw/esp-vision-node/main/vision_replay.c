// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// replay: the conformance harness. The host feeds recorded frames over native USB; the node runs the C
// front end (the same integer arithmetic as frontend.py), fills the policy's registers, evaluates the
// compiled table with the byte exact evaluator every substrate certifies, quantizes and Zeckendorf codes
// the reading exactly as prismpath.telemetry does, and returns fields, decision, wire bytes and timings.
//   host -> node: "RPL1" | seq u32 | len u32 | payload[len]   (320x240 grayscale)
//   node -> host: "RES1" | seq u32 | t_fe u32 | t_pol u32 | t_enc u32 | node u16 | steps u16 |
//                 n_fields u16 | field[n_fields] i32 (wire order) | wire_len u16 | wire[wire_len]
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "driver/usb_serial_jtag.h"
#include "vision_policy.h"
#include "../../codec-bench/zeck.h"

#include "vision_core.h"
static const char *TAG = "replay";
// ---------------------------------------------------------------- USB framing
typedef struct __attribute__((packed)) { char magic[4]; uint32_t seq; uint32_t t_fe, t_pol, t_enc; uint16_t node, steps, n_fields; } res_hdr_t;

void app_main(void)
{
    cur = heap_caps_malloc(W * H, MALLOC_CAP_SPIRAM); vision_core_init();
    usb_serial_jtag_driver_config_t ucfg = { .tx_buffer_size = 16384, .rx_buffer_size = 16384 };
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&ucfg));
    ESP_LOGI(TAG, "replay ready: %u B table, %u fields, %u nodes, start %u", POLICY_TABLE_LEN, n_fields, n_nodes, start_node);
    static int32_t fields[WIRE_N_FIELDS]; static uint8_t wirebuf[256];
    uint8_t hdr[12];
    while (1) {
        usb_read_all(hdr, 4);
        if (memcmp(hdr, "RPL1", 4) != 0) continue;
        usb_read_all(hdr + 4, 8);
        uint32_t seq, len; memcpy(&seq, hdr + 4, 4); memcpy(&len, hdr + 8, 4);
        if (len != W * H) { ESP_LOGE(TAG, "bad len %lu", (unsigned long)len); continue; }
        usb_read_all(cur, len);
        if (seq == 0) frame_n = 0;   // a clip starts at seq 0: fresh previous frame and background, like a fresh Frontend() on the host
        int64_t t0 = esp_timer_get_time();
        int32_t motion_cells, dark, step, door_hit; front_end(&motion_cells, &dark, &step, &door_hit);
        uint16_t node, steps; int64_t t1, t2;
        { memset(regs, 0, sizeof regs); }
        decide(motion_cells, dark, step, door_hit, &node, &steps); t1 = esp_timer_get_time();   // decide includes register fill
        t2 = t1;
        uint16_t wire_len = encode_reading(wirebuf, sizeof wirebuf);
        for (int i = 0; i < WIRE_N_FIELDS; i++) fields[i] = get_reg(WIRE_FIELDS[i].reg);
        int64_t t3 = esp_timer_get_time();
        res_hdr_t rh = { {'R','E','S','1'}, seq, (uint32_t)(t1 - t0), (uint32_t)(t2 - t1), (uint32_t)(t3 - t2), node, steps, WIRE_N_FIELDS };
        usb_write_all((const uint8_t *)&rh, sizeof rh);
        usb_write_all((const uint8_t *)fields, sizeof fields);
        usb_write_all((const uint8_t *)&wire_len, 2);
        usb_write_all(wirebuf, wire_len);
    }
}

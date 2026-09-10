// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// relay_host: 802.15.4 in, native USB out. Sub frames are reassembled into the original ESP-NOW payload
// and forwarded as "ENF1" | t_rx u64 | len u16 | payload, the record the host already reads. No console
// on USB (the UART console pins are not brought to USB on the XIAO), so the data channel is clean.
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_timer.h"
#include "driver/usb_serial_jtag.h"
#include "hop.h"
typedef struct { uint64_t t; uint8_t len; uint8_t d[128]; } rx_t;
static QueueHandle_t q;
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *info)
{
    (void)info; rx_t r; r.t = (uint64_t)esp_timer_get_time(); r.len = frame[0]; memcpy(r.d, frame, frame[0] + 1);
    esp_ieee802154_receive_handle_done(frame); BaseType_t w = pdFALSE; xQueueSendFromISR(q, &r, &w);
}
void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_info) { (void)frame; (void)ack_info; if (ack) esp_ieee802154_receive_handle_done(ack); }
void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) { (void)frame; (void)error; }
static void usb_write_all(const uint8_t *p, size_t n) { while (n) { int w = usb_serial_jtag_write_bytes(p, n < 2048 ? n : 2048, pdMS_TO_TICKS(1000)); if (w <= 0) { vTaskDelay(1); continue; } p += w; n -= w; } }
void app_main(void)
{
    xiao_antenna_internal();
    q = xQueueCreate(64, sizeof(rx_t));
    usb_serial_jtag_driver_config_t ucfg = { .tx_buffer_size = 16384, .rx_buffer_size = 256 }; ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&ucfg));
    hop_radio_init(0x0002, true, true);
    static uint8_t asm_buf[256]; uint16_t asm_id = 0xffff; uint8_t asm_have = 0, asm_total = 0; uint16_t asm_len = 0; uint64_t asm_t = 0;
    rx_t r;
    while (1) {
        if (xQueueReceive(q, &r, portMAX_DELAY) != pdTRUE) continue;
        // r.d[0] = length incl. FCS; MHR at r.d[1..9]; payload after; the FCS is not delivered
        int plen = (int)r.d[0] - 2 - MHR_LEN; const uint8_t *p = r.d + 1 + MHR_LEN;
        if (plen < SUB_HDR || p[0] != 'S') continue;
        uint16_t id = p[1] | (p[2] << 8); uint8_t idx = p[3], total = p[4]; int n = plen - SUB_HDR;
        if (id != asm_id) { asm_id = id; asm_have = 0; asm_total = total; asm_len = 0; asm_t = r.t; }
        if (idx != asm_have || (size_t)idx * SUB_DATA + n > sizeof asm_buf) { asm_id = 0xffff; continue; }   // out of order: drop the payload
        memcpy(asm_buf + (size_t)idx * SUB_DATA, p + SUB_HDR, n); asm_len = (uint16_t)(idx * SUB_DATA + n); asm_have++;
        if (asm_have == asm_total) {
            uint8_t hdr[14]; memcpy(hdr, "ENF1", 4); memcpy(hdr + 4, &asm_t, 8); memcpy(hdr + 12, &asm_len, 2);
            usb_write_all(hdr, sizeof hdr); usb_write_all(asm_buf, asm_len); asm_id = 0xffff;
        }
    }
}

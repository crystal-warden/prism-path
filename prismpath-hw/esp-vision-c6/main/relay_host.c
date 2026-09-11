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
#include "freertos/semphr.h"
#include "esp_rom_sys.h"
#include "hop.h"
typedef struct { uint64_t t; uint8_t len; uint8_t d[128]; } rx_t;
static QueueHandle_t q; static SemaphoreHandle_t txdone; static volatile bool last_acked;
// received signal strength on the hop, summed in the receive callback and emitted every two seconds as
// "RSS1" | t u64 | n u16 | sum i32 | min i8 | max i8, the instrument for range and attenuation tests
static volatile uint16_t rssi_n = 0; static volatile int32_t rssi_sum = 0; static volatile int8_t rssi_min = 127, rssi_max = -128;
#define RSSI_US 2000000
// a pending command: "CMD1" | nid u16 | len u8 | data[len] read from USB becomes 'C' | nid | data on the hop
static uint8_t cmd[32]; static uint8_t cmd_len = 0; static bool cmd_pending = false; static uint16_t cmd_tries = 0;
#define CMD_MAX_TRIES 200
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *info)
{
    rx_t r; r.t = (uint64_t)esp_timer_get_time(); r.len = frame[0]; memcpy(r.d, frame, frame[0] + 1);
    if (info) { rssi_n++; rssi_sum += info->rssi; if (info->rssi < rssi_min) rssi_min = info->rssi; if (info->rssi > rssi_max) rssi_max = info->rssi; }
    esp_ieee802154_receive_handle_done(frame); BaseType_t w = pdFALSE; xQueueSendFromISR(q, &r, &w);
}
void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_info) { (void)frame; (void)ack_info; last_acked = (ack != NULL); if (ack) esp_ieee802154_receive_handle_done(ack); BaseType_t w = pdFALSE; xSemaphoreGiveFromISR(txdone, &w); }
void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) { (void)frame; (void)error; last_acked = false; BaseType_t w = pdFALSE; xSemaphoreGiveFromISR(txdone, &w); }
static void usb_write_all(const uint8_t *p, size_t n) { while (n) { int w = usb_serial_jtag_write_bytes(p, n < 2048 ? n : 2048, pdMS_TO_TICKS(1000)); if (w <= 0) { vTaskDelay(1); continue; } p += w; n -= w; } }
static void emit(const uint8_t *payload, uint16_t len) { uint64_t t = (uint64_t)esp_timer_get_time(); uint8_t hdr[14]; memcpy(hdr, "ENF1", 4); memcpy(hdr + 4, &t, 8); memcpy(hdr + 12, &len, 2); usb_write_all(hdr, sizeof hdr); usb_write_all(payload, len); }
static void poll_usb(void)
{
    static uint8_t ib[64]; static int ib_n = 0; uint8_t tmp[32];
    int r = usb_serial_jtag_read_bytes(tmp, sizeof tmp, 0); if (r <= 0) return;
    for (int i = 0; i < r; i++) {
        if (ib_n < (int)sizeof ib) ib[ib_n++] = tmp[i];
        if (ib_n >= 7 && memcmp(ib, "CMD1", 4) == 0) {
            int len = ib[6];
            if (ib_n >= 7 + len) { cmd[0] = 'C'; cmd[1] = ib[4]; cmd[2] = ib[5]; memcpy(cmd + 3, ib + 7, len); cmd_len = (uint8_t)(3 + len); cmd_pending = true; cmd_tries = 0; ib_n = 0; }
        } else if (ib_n >= 4 && memcmp(ib, "CMD1", 4) != 0) ib_n = 0;   // resync on anything that is not a command
    }
}
// the air relay listens for a few milliseconds right after it hears our ack: send the pending command then
static void send_cmd(void)
{
    static uint8_t frame[64]; static uint8_t seq = 0;
    esp_rom_delay_us(400);   // let the hardware ack go out and the air relay open its window
    hop_build(frame, seq++, HOP_HOST_ADDR, HOP_AIR_ADDR, cmd, cmd_len); last_acked = false;
    if (esp_ieee802154_transmit(frame, false) != ESP_OK) return;
    if (xSemaphoreTake(txdone, pdMS_TO_TICKS(12)) == pdTRUE && last_acked) {
        uint8_t rec[9]; memcpy(rec, "ACK1", 4); rec[4] = cmd[1]; rec[5] = cmd[2]; rec[6] = cmd[3]; memcpy(rec + 7, &cmd_tries, 2); emit(rec, sizeof rec); cmd_pending = false;
    } else if (++cmd_tries >= CMD_MAX_TRIES) { uint8_t rec[9]; memcpy(rec, "NAK1", 4); rec[4] = cmd[1]; rec[5] = cmd[2]; rec[6] = cmd[3]; memcpy(rec + 7, &cmd_tries, 2); emit(rec, sizeof rec); cmd_pending = false; }
    esp_ieee802154_receive();
}
void app_main(void)
{
    xiao_antenna_internal();
    q = xQueueCreate(64, sizeof(rx_t)); txdone = xSemaphoreCreateBinary();
    usb_serial_jtag_driver_config_t ucfg = { .tx_buffer_size = 16384, .rx_buffer_size = 256 }; ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&ucfg));
    hop_radio_init(HOP_HOST_ADDR, false, true);   // not promiscuous: the hardware acks frames addressed to us
    static uint8_t asm_buf[256]; uint16_t asm_id = 0xffff; uint8_t asm_have = 0, asm_total = 0; uint16_t asm_len = 0; uint64_t asm_t = 0;
    rx_t r;
    while (1) {
        static int64_t t_rssi = 0;
        if (esp_timer_get_time() - t_rssi > RSSI_US) {
            t_rssi = esp_timer_get_time(); uint16_t n = rssi_n; int32_t sum = rssi_sum; int8_t mn = rssi_min, mx = rssi_max; rssi_n = 0; rssi_sum = 0; rssi_min = 127; rssi_max = -128;
            if (n) { uint8_t rec[20]; uint64_t t = (uint64_t)esp_timer_get_time(); memcpy(rec, "RSS1", 4); memcpy(rec + 4, &t, 8); memcpy(rec + 12, &n, 2); memcpy(rec + 14, &sum, 4); rec[18] = (uint8_t)mn; rec[19] = (uint8_t)mx; emit(rec, sizeof rec); }
        }
        if (xQueueReceive(q, &r, pdMS_TO_TICKS(10)) != pdTRUE) { poll_usb(); continue; }
        poll_usb();
        // r.d[0] = length incl. FCS; MHR at r.d[1..9]; payload after; the FCS is not delivered
        int plen = (int)r.d[0] - 2 - MHR_LEN; const uint8_t *p = r.d + 1 + MHR_LEN;
        if (plen < SUB_HDR || p[0] != 'S') continue;
        if (cmd_pending) send_cmd();   // the sender is listening right now
        // a retried sub frame that we acked but the sender did not hear arrives twice: same id, same idx
        static uint16_t last_id = 0xffff; static uint8_t last_idx = 0xff;
        uint16_t id = p[1] | (p[2] << 8); uint8_t idx = p[3], total = p[4]; int n = plen - SUB_HDR;
        if (id == last_id && idx == last_idx) continue;
        last_id = id; last_idx = idx;
        if (id != asm_id) { asm_id = id; asm_have = 0; asm_total = total; asm_len = 0; asm_t = r.t; }
        if (idx != asm_have || (size_t)idx * SUB_DATA + n > sizeof asm_buf) { asm_id = 0xffff; continue; }   // out of order: drop the payload
        memcpy(asm_buf + (size_t)idx * SUB_DATA, p + SUB_HDR, n); asm_len = (uint16_t)(idx * SUB_DATA + n); asm_have++;
        if (asm_have == asm_total) {
            uint8_t hdr[14]; memcpy(hdr, "ENF1", 4); memcpy(hdr + 4, &asm_t, 8); memcpy(hdr + 12, &asm_len, 2);
            usb_write_all(hdr, sizeof hdr); usb_write_all(asm_buf, asm_len); asm_id = 0xffff;
        }
    }
}

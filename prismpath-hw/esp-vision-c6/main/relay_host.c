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
#include "ppt_eval.h"
#include "fusion_policy.h"
// Fusion on the relay (A4): the two cameras' last routes and the relay's own receive clock are the facts; the room's
// verdict is a policy walk (room_fusion.md), and a camera that goes quiet is STALE, a state the policy decides on.
// "FUS1" | t u64 | route u16 | a_fresh b_fresh a_occ b_occ a_tamper b_tamper (u8 each) | a_seq u32 | b_seq u32 | a_age_ms u16 | b_age_ms u16
static void emit(const uint8_t *payload, uint16_t len);
#define FRESH_US 1500000
#define FUSION_TICK_US 250000
#define FUSION_RESEND_US 2000000
static struct { uint32_t seq; uint16_t node; int64_t t_rx; bool seen; } cam[2];
static bool fusion_ok = false;
static void fusion_note(const uint8_t *pl, uint16_t len)
{
    if (len < 30 || memcmp(pl, "RDG", 3) != 0 || pl[3] < '3') return;
    uint16_t nid = pl[4] | (pl[5] << 8); uint32_t seq; memcpy(&seq, pl + 8, 4); uint16_t node = pl[28] | (pl[29] << 8);
    int k = nid == FUSION_A ? 0 : nid == FUSION_B ? 1 : -1; if (k < 0) return;
    cam[k].seq = seq; cam[k].node = node; cam[k].t_rx = esp_timer_get_time(); cam[k].seen = true;
}
static void fusion_tick(void)
{
    static int64_t t_tick = 0, t_sent = 0; static uint16_t last_route = 0xffff; int64_t now = esp_timer_get_time();
    if (!fusion_ok || now - t_tick < FUSION_TICK_US) return;
    t_tick = now;
    int32_t f[2], o[2], tm[2]; uint16_t age[2];
    for (int k = 0; k < 2; k++) {
        int64_t a = cam[k].seen ? now - cam[k].t_rx : (int64_t)1 << 40; f[k] = cam[k].seen && a < FRESH_US;
        o[k] = f[k] && ((CAM_OCC_MASK >> cam[k].node) & 1); tm[k] = f[k] && ((CAM_TAMPER_MASK >> cam[k].node) & 1); age[k] = (uint16_t)(a / 1000 > 65535 ? 65535 : a / 1000);
    }
    memset(regs, 0, sizeof regs); set_reg(FREG_a_fresh, f[0]); set_reg(FREG_b_fresh, f[1]); set_reg(FREG_a_occ, o[0]); set_reg(FREG_b_occ, o[1]); set_reg(FREG_a_tamper, tm[0]); set_reg(FREG_b_tamper, tm[1]);
    uint16_t node = start_node, target = 0, steps = 0; uint8_t err = 0;
    while (steps < max_steps && node_edge_count(node) > 0) { int8_t e = evaluate(node, &target, &err); if (e < 0 || err) break; node = target; steps++; }
    if (node != last_route || now - t_sent > FUSION_RESEND_US) {
        uint8_t rec[36]; memcpy(rec, "FUS1", 4); uint64_t t = (uint64_t)now; memcpy(rec + 4, &t, 8); memcpy(rec + 12, &node, 2);
        rec[14] = f[0]; rec[15] = f[1]; rec[16] = o[0]; rec[17] = o[1]; rec[18] = tm[0]; rec[19] = tm[1];
        memcpy(rec + 20, &cam[0].seq, 4); memcpy(rec + 24, &cam[1].seq, 4); memcpy(rec + 28, &age[0], 2); memcpy(rec + 30, &age[1], 2); uint16_t st = steps; memcpy(rec + 32, &st, 2); rec[34] = 0; rec[35] = 0;
        emit(rec, sizeof rec); last_route = node; t_sent = now;
    }
}
typedef struct { uint64_t t; uint8_t len; uint8_t d[128]; } rx_t;
static QueueHandle_t q; static SemaphoreHandle_t txdone; static volatile bool last_acked;
// received signal strength on the hop, summed in the receive callback and emitted every two seconds as
// "RSS1" | t u64 | n u16 | sum i32 | min i8 | max i8, the instrument for range and attenuation tests
static volatile uint16_t rssi_n = 0; static volatile int32_t rssi_sum = 0; static volatile int8_t rssi_min = 127, rssi_max = -128;
#define RSSI_US 2000000
// a pending command: "CMD1" | nid u16 | len u8 | data[len] read from USB becomes 'C' | nid | data on the hop
static uint8_t cmd[32]; static uint8_t cmd_len = 0; static bool cmd_pending = false; static uint16_t cmd_tries = 0;
static int64_t mute_until = 0;
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
            if (ib_n >= 7 + len) {
                uint16_t nid = ib[4] | (ib[5] << 8);
                if (nid == HOP_HOST_ADDR && len >= 2 && ib[7] == 'm') { mute_until = esp_timer_get_time() + (int64_t)ib[8] * 1000000; esp_ieee802154_sleep(); }   // a bench hook: this relay goes deaf for N seconds so the air relay's policy meets a run of give ups
                else { cmd[0] = 'C'; cmd[1] = ib[4]; cmd[2] = ib[5]; memcpy(cmd + 3, ib + 7, len); cmd_len = (uint8_t)(3 + len); cmd_pending = true; cmd_tries = 0; }
                ib_n = 0;
            }
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
    memcpy(tbl, FUSION_TABLE, FUSION_TABLE_LEN); fusion_ok = (parse_table(FUSION_TABLE_LEN) == 0);
    static uint8_t asm_buf[256]; uint16_t asm_id = 0xffff; uint8_t asm_have = 0, asm_total = 0; uint16_t asm_len = 0; uint64_t asm_t = 0;
    rx_t r;
    while (1) {
        if (mute_until) { if (esp_timer_get_time() < mute_until) { poll_usb(); vTaskDelay(pdMS_TO_TICKS(10)); continue; } mute_until = 0; esp_ieee802154_receive(); }
        static int64_t t_rssi = 0;
        if (esp_timer_get_time() - t_rssi > RSSI_US) {
            t_rssi = esp_timer_get_time(); uint16_t n = rssi_n; int32_t sum = rssi_sum; int8_t mn = rssi_min, mx = rssi_max; rssi_n = 0; rssi_sum = 0; rssi_min = 127; rssi_max = -128;
            if (n) { uint8_t rec[20]; uint64_t t = (uint64_t)esp_timer_get_time(); memcpy(rec, "RSS1", 4); memcpy(rec + 4, &t, 8); memcpy(rec + 12, &n, 2); memcpy(rec + 14, &sum, 4); rec[18] = (uint8_t)mn; rec[19] = (uint8_t)mx; emit(rec, sizeof rec); }
        }
        fusion_tick();
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
            usb_write_all(hdr, sizeof hdr); usb_write_all(asm_buf, asm_len); fusion_note(asm_buf, asm_len); asm_id = 0xffff;
        }
    }
}

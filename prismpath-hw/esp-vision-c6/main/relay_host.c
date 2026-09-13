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
// "FUS2" | t u64 | route u16 | a_fresh b_fresh a_occ b_occ a_tamper b_tamper (u8 each) | a_seq u32 | b_seq u32 | a_age_ms u16 | b_age_ms u16 | steps u16 | flags u16 | a_occ_age_ms u16 | b_occ_age_ms u16
static void emit(const uint8_t *payload, uint16_t len);
#define FRESH_US 1500000
#define FUSION_TICK_US 250000
#define FUSION_RESEND_US 2000000
static struct {
    uint32_t seq;
    uint16_t node;
    int64_t t_rx, t_occ;
    bool seen;
} cam[2];  // t_occ: when the camera last said someone is there (the hold is the policy's)
static bool fusion_ok = false;
static void fusion_note(const uint8_t *pl, uint16_t len) {
    if (len < 30 || memcmp(pl, "RDG", 3) != 0 || pl[3] < '3')
        return;
    uint16_t nid = pl[4] | (pl[5] << 8);
    uint32_t seq;
    memcpy(&seq, pl + 8, 4);
    uint16_t node = pl[28] | (pl[29] << 8);
    int cam_index = nid == FUSION_A ? 0 : nid == FUSION_B ? 1 : -1;
    if (cam_index < 0)
        return;
    cam[cam_index].seq = seq;
    cam[cam_index].node = node;
    cam[cam_index].t_rx = esp_timer_get_time();
    cam[cam_index].seen = true;
    if ((CAM_OCC_MASK >> node) & 1)
        cam[cam_index].t_occ = cam[cam_index].t_rx;
}
static void fusion_tick(void) {
    static int64_t t_tick = 0, t_sent = 0;
    static uint16_t last_route = 0xffff;
    int64_t now = esp_timer_get_time();
    if (!fusion_ok || now - t_tick < FUSION_TICK_US)
        return;
    t_tick = now;
    int32_t fresh[2], occupied[2], tm[2];
    uint16_t age[2], occ_age[2];
    for (int cam_index = 0; cam_index < 2; cam_index++) {
        int64_t age_us = cam[cam_index].seen ? now - cam[cam_index].t_rx : (int64_t)1 << 40;
        fresh[cam_index] = cam[cam_index].seen && age_us < FRESH_US;
        int64_t oa = cam[cam_index].t_occ ? now - cam[cam_index].t_occ : (int64_t)1 << 40;
        occ_age[cam_index] = (uint16_t)(oa / 1000 > 65535 ? 65535 : oa / 1000);
        occupied[cam_index] = occ_age[cam_index];
        tm[cam_index] = fresh[cam_index] && ((CAM_TAMPER_MASK >> cam[cam_index].node) & 1);
        age[cam_index] = (uint16_t)(age_us / 1000 > 65535 ? 65535 : age_us / 1000);
    }
    memset(regs, 0, sizeof regs);
    set_reg(FREG_a_fresh, fresh[0]);
    set_reg(FREG_b_fresh, fresh[1]);
    set_reg(FREG_a_occ_age, occupied[0]);
    set_reg(FREG_b_occ_age, occupied[1]);
    set_reg(FREG_a_tamper, tm[0]);
    set_reg(FREG_b_tamper, tm[1]);
    uint16_t node = start_node, target = 0, steps = 0;
    uint8_t err = 0;
    while (steps < max_steps && node_edge_count(node) > 0) {
        int8_t matched_edge = evaluate(node, &target, &err);
        if (matched_edge < 0 || err)
            break;
        node = target;
        steps++;
    }
    if (node != last_route || now - t_sent > FUSION_RESEND_US) {
        uint8_t rec[40];
        memcpy(rec, "FUS2", 4);
        uint64_t t_us = (uint64_t)now;
        memcpy(rec + 4, &t_us, 8);
        memcpy(rec + 12, &node, 2);  // FUS2 = FUS1 with the two occupied ages appended
        rec[14] = fresh[0];
        rec[15] = fresh[1];
        rec[16] = occ_age[0] < 2000;
        rec[17] = occ_age[1] < 2000;
        rec[18] = tm[0];
        rec[19] = tm[1];
        memcpy(rec + 20, &cam[0].seq, 4);
        memcpy(rec + 24, &cam[1].seq, 4);
        memcpy(rec + 28, &age[0], 2);
        memcpy(rec + 30, &age[1], 2);
        uint16_t st = steps;
        memcpy(rec + 32, &st, 2);
        rec[34] = 0;
        rec[35] = 0;
        memcpy(rec + 36, &occ_age[0], 2);
        memcpy(rec + 38, &occ_age[1], 2);
        emit(rec, sizeof rec);
        last_route = node;
        t_sent = now;
    }
}
typedef struct {
    uint64_t t_us;
    uint8_t len;
    uint8_t data[128];
} rx_t;
static QueueHandle_t rx_queue;
static SemaphoreHandle_t txdone;
static volatile bool last_acked;
// received signal strength on the hop, summed in the receive callback and emitted every two seconds as
// "RSS1" | t u64 | n u16 | sum i32 | min i8 | max i8, the instrument for range and attenuation tests
static volatile uint16_t rssi_n = 0;
static volatile int32_t rssi_sum = 0;
static volatile int8_t rssi_min = 127, rssi_max = -128;
#define RSSI_US 2000000
// a pending command: "CMD1" | nid u16 | len u8 | data[len] read from USB becomes 'C' | nid | data on the hop
static uint8_t cmd[32];
static uint8_t cmd_len = 0;
static bool cmd_pending = false;
static uint16_t cmd_tries = 0;
static int64_t mute_until = 0;
#define CMD_MAX_TRIES 200
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *info) {
    rx_t received;
    received.t_us = (uint64_t)esp_timer_get_time();
    received.len = frame[0];
    memcpy(received.data, frame, frame[0] + 1);
    if (info) {
        rssi_n++;
        rssi_sum += info->rssi;
        if (info->rssi < rssi_min)
            rssi_min = info->rssi;
        if (info->rssi > rssi_max)
            rssi_max = info->rssi;
    }
    esp_ieee802154_receive_handle_done(frame);
    BaseType_t task_woken = pdFALSE;
    xQueueSendFromISR(rx_queue, &received, &task_woken);
}
void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_info) {
    (void)frame;
    (void)ack_info;
    last_acked = (ack != NULL);
    if (ack)
        esp_ieee802154_receive_handle_done(ack);
    BaseType_t task_woken = pdFALSE;
    xSemaphoreGiveFromISR(txdone, &task_woken);
}
void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) {
    (void)frame;
    (void)error;
    last_acked = false;
    BaseType_t task_woken = pdFALSE;
    xSemaphoreGiveFromISR(txdone, &task_woken);
}
static void usb_write_all(const uint8_t *bytes, size_t remaining) {
    while (remaining) {
        int written = usb_serial_jtag_write_bytes(bytes, remaining < 2048 ? remaining : 2048, pdMS_TO_TICKS(1000));
        if (written <= 0) {
            vTaskDelay(1);
            continue;
        }
        bytes += written;
        remaining -= written;
    }
}
static void emit(const uint8_t *payload, uint16_t len) {
    uint64_t t_us = (uint64_t)esp_timer_get_time();
    uint8_t hdr[14];
    memcpy(hdr, "ENF1", 4);
    memcpy(hdr + 4, &t_us, 8);
    memcpy(hdr + 12, &len, 2);
    usb_write_all(hdr, sizeof hdr);
    usb_write_all(payload, len);
}
static void poll_usb(void) {
    static uint8_t ib[64];
    static int ib_n = 0;
    uint8_t tmp[32];
    int read_count = usb_serial_jtag_read_bytes(tmp, sizeof tmp, 0);
    if (read_count <= 0)
        return;
    for (int byte_index = 0; byte_index < read_count; byte_index++) {
        if (ib_n < (int)sizeof ib)
            ib[ib_n++] = tmp[byte_index];
        if (ib_n >= 7 && memcmp(ib, "CMD1", 4) == 0) {
            int len = ib[6];
            if (ib_n >= 7 + len) {
                uint16_t nid = ib[4] | (ib[5] << 8);
                if (nid == HOP_HOST_ADDR && len >= 2 && ib[7] == 'm') {
                    mute_until = esp_timer_get_time() + (int64_t)ib[8] * 1000000;
                    esp_ieee802154_sleep();
                }  // a bench hook: this relay goes deaf for N seconds so the air relay's policy meets a run of give ups
                else {
                    cmd[0] = 'C';
                    cmd[1] = ib[4];
                    cmd[2] = ib[5];
                    memcpy(cmd + 3, ib + 7, len);
                    cmd_len = (uint8_t)(3 + len);
                    cmd_pending = true;
                    cmd_tries = 0;
                }
                ib_n = 0;
            }
        } else if (ib_n >= 4 && memcmp(ib, "CMD1", 4) != 0)
            ib_n = 0;  // resync on anything that is not a command
    }
}
// the air relay listens for a few milliseconds right after it hears our ack: send the pending command then
static void send_cmd(void) {
    static uint8_t frame[64];
    static uint8_t seq = 0;
    esp_rom_delay_us(400);  // let the hardware ack go out and the air relay open its window
    hop_build(frame, seq++, HOP_HOST_ADDR, HOP_AIR_ADDR, cmd, cmd_len);
    last_acked = false;
    if (esp_ieee802154_transmit(frame, false) != ESP_OK)
        return;
    if (xSemaphoreTake(txdone, pdMS_TO_TICKS(12)) == pdTRUE && last_acked) {
        uint8_t rec[9];
        memcpy(rec, "ACK1", 4);
        rec[4] = cmd[1];
        rec[5] = cmd[2];
        rec[6] = cmd[3];
        memcpy(rec + 7, &cmd_tries, 2);
        emit(rec, sizeof rec);
        cmd_pending = false;
    } else if (++cmd_tries >= CMD_MAX_TRIES) {
        uint8_t rec[9];
        memcpy(rec, "NAK1", 4);
        rec[4] = cmd[1];
        rec[5] = cmd[2];
        rec[6] = cmd[3];
        memcpy(rec + 7, &cmd_tries, 2);
        emit(rec, sizeof rec);
        cmd_pending = false;
    }
    esp_ieee802154_receive();
}
void app_main(void) {
    xiao_antenna_internal();
    rx_queue = xQueueCreate(64, sizeof(rx_t));
    txdone = xSemaphoreCreateBinary();
    usb_serial_jtag_driver_config_t ucfg = {.tx_buffer_size = 16384, .rx_buffer_size = 256};
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&ucfg));
    hop_radio_init(HOP_HOST_ADDR, false, true);  // not promiscuous: the hardware acks frames addressed to us
    memcpy(tbl, FUSION_TABLE, FUSION_TABLE_LEN);
    fusion_ok = (parse_table(FUSION_TABLE_LEN) == 0);
    static uint8_t asm_buf[256];
    uint16_t asm_id = 0xffff;
    uint8_t asm_have = 0, asm_total = 0;
    uint16_t asm_len = 0;
    uint64_t asm_t = 0;
    rx_t received;
    while (1) {
        if (mute_until) {
            if (esp_timer_get_time() < mute_until) {
                poll_usb();
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            mute_until = 0;
            esp_ieee802154_receive();
        }
        static int64_t t_rssi = 0;
        if (esp_timer_get_time() - t_rssi > RSSI_US) {
            t_rssi = esp_timer_get_time();
            uint16_t n = rssi_n;
            int32_t sum = rssi_sum;
            int8_t mn = rssi_min, mx = rssi_max;
            rssi_n = 0;
            rssi_sum = 0;
            rssi_min = 127;
            rssi_max = -128;
            if (n) {
                uint8_t rec[20];
                uint64_t t_us = (uint64_t)esp_timer_get_time();
                memcpy(rec, "RSS1", 4);
                memcpy(rec + 4, &t_us, 8);
                memcpy(rec + 12, &n, 2);
                memcpy(rec + 14, &sum, 4);
                rec[18] = (uint8_t)mn;
                rec[19] = (uint8_t)mx;
                emit(rec, sizeof rec);
            }
        }
        fusion_tick();
        if (xQueueReceive(rx_queue, &received, pdMS_TO_TICKS(10)) != pdTRUE) {
            poll_usb();
            continue;
        }
        poll_usb();
        // received.data[0] = length incl. FCS; MHR at received.data[1..9]; payload after; the FCS is not delivered
        int plen = (int)received.data[0] - 2 - MHR_LEN;
        const uint8_t *payload = received.data + 1 + MHR_LEN;
        if (plen < SUB_HDR || payload[0] != 'S')
            continue;
        if (cmd_pending)
            send_cmd();  // the sender is listening right now
        // a retried sub frame that we acked but the sender did not hear arrives twice: same id, same idx
        static uint16_t last_id = 0xffff;
        static uint8_t last_idx = 0xff;
        uint16_t id = payload[1] | (payload[2] << 8);
        uint8_t idx = payload[3], total = payload[4];
        int n = plen - SUB_HDR;
        if (id == last_id && idx == last_idx)
            continue;
        last_id = id;
        last_idx = idx;
        if (id != asm_id) {
            asm_id = id;
            asm_have = 0;
            asm_total = total;
            asm_len = 0;
            asm_t = received.t_us;
        }
        if (idx != asm_have || (size_t)idx * SUB_DATA + n > sizeof asm_buf) {
            asm_id = 0xffff;
            continue;
        }  // out of order: drop the payload
        memcpy(asm_buf + (size_t)idx * SUB_DATA, payload + SUB_HDR, n);
        asm_len = (uint16_t)(idx * SUB_DATA + n);
        asm_have++;
        if (asm_have == asm_total) {
            uint8_t hdr[14];
            memcpy(hdr, "ENF1", 4);
            memcpy(hdr + 4, &asm_t, 8);
            memcpy(hdr + 12, &asm_len, 2);
            usb_write_all(hdr, sizeof hdr);
            usb_write_all(asm_buf, asm_len);
            fusion_note(asm_buf, asm_len);
            asm_id = 0xffff;
        }
    }
}

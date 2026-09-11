// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// relay_air: the C6 brings up a bench access point; the S3 camera node joins it and sends its records as
// UDP datagrams (the same RDG1 and FRG1 payloads it broadcasts on ESP-NOW). Each datagram is forwarded
// as one or more 802.15.4 sub frames on the hop. Console on native USB. An open AP, on purpose: it is a
// bench link carrying decision symbols, and the policy's integrity story lives above the transport.
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "lwip/sockets.h"
#include "hop.h"
#include "esp_rom_sys.h"
static const char *TAG = "air";
#define HOP_SSID "prismpath-hop"
#define HOP_PORT 5050
#ifndef WINDOW_US
#define WINDOW_US 6000
#endif
typedef struct { uint16_t len; uint8_t d[250]; } msg_t;
static QueueHandle_t q, qbulk; static SemaphoreHandle_t txdone;   // readings first: bulk (keyframe and evidence fragments) waits while readings are pending
static uint32_t n_in = 0, n_sub = 0, n_fail = 0, n_retry = 0, n_given_up = 0; static volatile bool last_acked;
// the downlink: a command frame heard in the receive window goes to the camera whose node id it names
typedef struct { uint8_t len; uint8_t d[32]; } cmd_t;
static QueueHandle_t qcmd; static int usock = -1;
#define MAX_NODES 6
static struct { uint16_t nid; struct sockaddr_in addr; bool set; } nodes[MAX_NODES];
#define STATS_US 10000000
typedef struct __attribute__((packed)) { char magic[4]; uint64_t t; uint32_t n_in, n_sub, n_retry, n_given_up, n_fail; uint16_t q_wait, qbulk_wait; } sta_t;
void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_info) { (void)frame; (void)ack_info; last_acked = (ack != NULL); if (ack) esp_ieee802154_receive_handle_done(ack); BaseType_t w = pdFALSE; xSemaphoreGiveFromISR(txdone, &w); }
void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) { (void)frame; (void)error; last_acked = false; n_fail++; BaseType_t w = pdFALSE; xSemaphoreGiveFromISR(txdone, &w); }
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *info)
{
    (void)info; int plen = (int)frame[0] - 2 - MHR_LEN; const uint8_t *p = frame + 1 + MHR_LEN;
    if (plen >= 4 && p[0] == 'C' && plen <= (int)sizeof(((cmd_t *)0)->d)) { cmd_t c; c.len = (uint8_t)plen; memcpy(c.d, p, plen); BaseType_t w = pdFALSE; xQueueSendFromISR(qcmd, &c, &w); }
    esp_ieee802154_receive_handle_done(frame);
}
static void cmd_task(void *arg)
{
    cmd_t c;
    while (1) {
        if (xQueueReceive(qcmd, &c, portMAX_DELAY) != pdTRUE) continue;
        uint16_t nid = c.d[1] | (c.d[2] << 8); int sent = 0;
        for (int i = 0; i < MAX_NODES; i++) if (nodes[i].set && (nodes[i].nid == nid || nid == 0xffff)) { sendto(usock, c.d, c.len, 0, (struct sockaddr *)&nodes[i].addr, sizeof nodes[i].addr); sent++; }
        ESP_LOGI(TAG, "command '%c' for node %04x forwarded to %d camera(s)", c.d[3], nid, sent);
    }
}
static void on_wifi(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (id == WIFI_EVENT_AP_STACONNECTED) { wifi_event_ap_staconnected_t *e = data; ESP_LOGI(TAG, "station joined: %02x:%02x:%02x:%02x:%02x:%02x", e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5]); }
    else if (id == WIFI_EVENT_AP_STADISCONNECTED) ESP_LOGW(TAG, "station left");
}
static void udp_task(void *arg)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(HOP_PORT), .sin_addr.s_addr = htonl(INADDR_ANY) };
    bind(s, (struct sockaddr *)&a, sizeof a);
    usock = s; msg_t m; struct sockaddr_in from; socklen_t fl;
    while (1) {
        fl = sizeof from; int n = recvfrom(s, m.d, sizeof m.d, 0, (struct sockaddr *)&from, &fl); if (n <= 0) continue; m.len = (uint16_t)n;
        if (n >= 6) {   // RDG3, KEY3, EVD1 and FRG2 all carry the node id right after the magic: remember where that node speaks from
            uint16_t nid = m.d[4] | (m.d[5] << 8); int slot = -1;
            for (int i = 0; i < MAX_NODES; i++) { if (nodes[i].set && nodes[i].nid == nid) { slot = i; break; } if (!nodes[i].set && slot < 0) slot = i; }
            if (slot >= 0) { nodes[slot].nid = nid; nodes[slot].addr = from; nodes[slot].set = true; }
        }
        xQueueSend(memcmp(m.d, "FRG", 3) == 0 ? qbulk : q, &m, 0);
    }
}
void app_main(void)
{
    xiao_antenna_internal();
    q = xQueueCreate(64, sizeof(msg_t)); qbulk = xQueueCreate(160, sizeof(msg_t)); txdone = xSemaphoreCreateBinary(); qcmd = xQueueCreate(8, sizeof(cmd_t));   // readings never wait behind a keyframe burst
    esp_err_t e = nvs_flash_init(); if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) { nvs_flash_erase(); nvs_flash_init(); }
    esp_netif_init(); esp_event_loop_create_default(); esp_netif_create_default_wifi_ap();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT(); esp_wifi_init(&wc); esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi, NULL);
    wifi_config_t ap = { .ap = { .ssid = HOP_SSID, .ssid_len = strlen(HOP_SSID), .channel = 1, .authmode = WIFI_AUTH_OPEN, .max_connection = 4 } };
    esp_wifi_set_mode(WIFI_MODE_APSTA); esp_wifi_set_config(WIFI_IF_AP, &ap); esp_wifi_start();   // APSTA: the S3 associated only once the station interface was up too
#ifndef HOP_NO_154
    hop_radio_init(0x0001, false, false);
#endif
#ifdef WIFI_SCAN
    // receive path check: can this radio hear anything at all? APSTA so the AP stays up while the STA scans
    wifi_scan_config_t sc = { .show_hidden = true }; esp_wifi_scan_start(&sc, true);
    uint16_t n_ap = 20; static wifi_ap_record_t recs[20]; esp_wifi_scan_get_ap_records(&n_ap, recs);
    ESP_LOGI(TAG, "scan: %u access points heard", n_ap);
    for (int i = 0; i < n_ap; i++) ESP_LOGI(TAG, "  ch %2d rssi %4d %s", recs[i].primary, recs[i].rssi, (const char *)recs[i].ssid);
#endif
    xTaskCreate(udp_task, "udp", 4096, NULL, 10, NULL); xTaskCreate(cmd_task, "cmd", 4096, NULL, 9, NULL);   // above the forwarder, so datagrams are queued the moment they arrive
    uint8_t mac[6]; esp_wifi_get_mac(WIFI_IF_AP, mac);
    ESP_LOGI(TAG, "air relay %02x:%02x:%02x:%02x:%02x:%02x: AP '%s' open, UDP %d in, 802.15.4 channel %d out", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], HOP_SSID, HOP_PORT, HOP_CHANNEL);
    static uint8_t frame[130]; static uint8_t sub[SUB_HDR + SUB_DATA]; uint8_t seq = 0; uint16_t id = 0; int64_t t_log = esp_timer_get_time();
    msg_t m;
    while (1) {
        bool reading = (xQueueReceive(q, &m, 0) == pdTRUE);
        bool got = reading || (uxQueueMessagesWaiting(q) == 0 && xQueueReceive(qbulk, &m, pdMS_TO_TICKS(20)) == pdTRUE);
        if (got) {
            n_in++; uint8_t total = (uint8_t)((m.len + SUB_DATA - 1) / SUB_DATA); id++;
            for (uint8_t i = 0; i < total; i++) {
                uint16_t off = i * SUB_DATA, n = m.len - off < SUB_DATA ? m.len - off : SUB_DATA;
                sub[0] = 'S'; sub[1] = id & 0xff; sub[2] = id >> 8; sub[3] = i; sub[4] = total; memcpy(sub + SUB_HDR, m.d + off, n);
                hop_build(frame, seq++, HOP_AIR_ADDR, HOP_HOST_ADDR, sub, (uint8_t)(SUB_HDR + n));
#ifndef HOP_NO_154
                // acknowledged unicast: up to 4 attempts per sub frame, so a 3 percent air loss becomes a per frame loss near zero
                bool ok = false;
                for (int attempt = 0; attempt < 4 && !ok; attempt++) {
                    if (attempt) { n_retry++; vTaskDelay(pdMS_TO_TICKS(2 + attempt)); }
                    last_acked = false;
                    if (esp_ieee802154_transmit(frame, false) != ESP_OK) continue;
                    if (xSemaphoreTake(txdone, pdMS_TO_TICKS(12)) == pdTRUE) ok = last_acked;   // an ack arrives within a millisecond or not at all
                }
                if (ok) n_sub++; else n_given_up++;
                // the downlink window: after a reading's sub frame was acked, listen a few milliseconds for a command
                // frame from the host relay, then go quiet again so the access point keeps its airtime
                if (ok && reading) { esp_ieee802154_receive(); esp_rom_delay_us(WINDOW_US); esp_ieee802154_sleep(); }
#else
                n_sub++;
#endif
            }
        }
        if (esp_timer_get_time() - t_log > STATS_US) {
            // the counters also cross the hop, so a relay on a battery is still observed at the host
            msg_t sm; sta_t st = { {'S','T','A','1'}, (uint64_t)esp_timer_get_time(), n_in, n_sub, n_retry, n_given_up, n_fail, (uint16_t)uxQueueMessagesWaiting(q), (uint16_t)uxQueueMessagesWaiting(qbulk) };
            memcpy(sm.d, &st, sizeof st); sm.len = sizeof st; xQueueSend(q, &sm, 0);
            t_log = esp_timer_get_time(); ESP_LOGI(TAG, "in %lu, sub frames acked %lu, retries %lu, given up %lu, raw tx failures %lu", (unsigned long)n_in, (unsigned long)n_sub, (unsigned long)n_retry, (unsigned long)n_given_up, (unsigned long)n_fail); }
    }
}

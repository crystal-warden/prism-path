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
static const char *TAG = "air";
#define HOP_SSID "prismpath-hop"
#define HOP_PORT 5050
typedef struct { uint16_t len; uint8_t d[250]; } msg_t;
static QueueHandle_t q, qbulk; static SemaphoreHandle_t txdone;   // readings first: bulk (keyframe and evidence fragments) waits while readings are pending
static uint32_t n_in = 0, n_sub = 0, n_fail = 0, n_retry = 0, n_given_up = 0; static volatile bool last_acked;
void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_info) { (void)frame; (void)ack_info; last_acked = (ack != NULL); if (ack) esp_ieee802154_receive_handle_done(ack); BaseType_t w = pdFALSE; xSemaphoreGiveFromISR(txdone, &w); }
void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) { (void)frame; (void)error; last_acked = false; n_fail++; BaseType_t w = pdFALSE; xSemaphoreGiveFromISR(txdone, &w); }
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *info) { (void)info; esp_ieee802154_receive_handle_done(frame); }
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
    msg_t m;
    while (1) { int n = recv(s, m.d, sizeof m.d, 0); if (n <= 0) continue; m.len = (uint16_t)n; xQueueSend(memcmp(m.d, "FRG", 3) == 0 ? qbulk : q, &m, 0); }
}
void app_main(void)
{
    xiao_antenna_internal();
    q = xQueueCreate(64, sizeof(msg_t)); qbulk = xQueueCreate(160, sizeof(msg_t)); txdone = xSemaphoreCreateBinary();   // readings never wait behind a keyframe burst
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
    xTaskCreate(udp_task, "udp", 4096, NULL, 10, NULL);   // above the forwarder, so datagrams are queued the moment they arrive
    uint8_t mac[6]; esp_wifi_get_mac(WIFI_IF_AP, mac);
    ESP_LOGI(TAG, "air relay %02x:%02x:%02x:%02x:%02x:%02x: AP '%s' open, UDP %d in, 802.15.4 channel %d out", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], HOP_SSID, HOP_PORT, HOP_CHANNEL);
    static uint8_t frame[130]; static uint8_t sub[SUB_HDR + SUB_DATA]; uint8_t seq = 0; uint16_t id = 0; int64_t t_log = esp_timer_get_time();
    msg_t m;
    while (1) {
        bool got = (xQueueReceive(q, &m, 0) == pdTRUE) || (uxQueueMessagesWaiting(q) == 0 && xQueueReceive(qbulk, &m, pdMS_TO_TICKS(20)) == pdTRUE);
        if (got) {
            n_in++; uint8_t total = (uint8_t)((m.len + SUB_DATA - 1) / SUB_DATA); id++;
            for (uint8_t i = 0; i < total; i++) {
                uint16_t off = i * SUB_DATA, n = m.len - off < SUB_DATA ? m.len - off : SUB_DATA;
                sub[0] = 'S'; sub[1] = id & 0xff; sub[2] = id >> 8; sub[3] = i; sub[4] = total; memcpy(sub + SUB_HDR, m.d + off, n);
                hop_build(frame, seq++, 0x0001, sub, (uint8_t)(SUB_HDR + n));
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
#else
                n_sub++;
#endif
            }
        }
        if (esp_timer_get_time() - t_log > 10000000) { t_log = esp_timer_get_time(); ESP_LOGI(TAG, "in %lu, sub frames acked %lu, retries %lu, given up %lu, raw tx failures %lu", (unsigned long)n_in, (unsigned long)n_sub, (unsigned long)n_retry, (unsigned long)n_given_up, (unsigned long)n_fail); }
    }
}

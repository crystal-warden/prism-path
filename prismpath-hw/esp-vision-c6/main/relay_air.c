// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// relay_air: ESP-NOW in (from the S3 camera node), 802.15.4 out. Every ESP-NOW payload is forwarded as
// one or more sub frames on the hop, in order, one transmit at a time. Console on native USB.
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "hop.h"
static const char *TAG = "air";
typedef struct { uint16_t len; uint8_t d[250]; } msg_t;
static QueueHandle_t q; static SemaphoreHandle_t txdone; static uint32_t n_in = 0, n_sub = 0, n_fail = 0;
static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) { (void)info; if (len <= 0 || len > 250) return; msg_t m; m.len = len; memcpy(m.d, data, len); xQueueSend(q, &m, 0); }
void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_info) { (void)frame; (void)ack_info; if (ack) esp_ieee802154_receive_handle_done(ack); BaseType_t w = pdFALSE; xSemaphoreGiveFromISR(txdone, &w); }
void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) { (void)frame; (void)error; n_fail++; BaseType_t w = pdFALSE; xSemaphoreGiveFromISR(txdone, &w); }
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *info) { (void)info; esp_ieee802154_receive_handle_done(frame); }
void app_main(void)
{
    xiao_antenna_internal();
    q = xQueueCreate(32, sizeof(msg_t)); txdone = xSemaphoreCreateBinary();
    esp_err_t e = nvs_flash_init(); if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) { nvs_flash_erase(); nvs_flash_init(); }
    esp_netif_init(); esp_event_loop_create_default();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT(); esp_wifi_init(&wc); esp_wifi_set_storage(WIFI_STORAGE_RAM); esp_wifi_set_mode(WIFI_MODE_STA); esp_wifi_start();
    esp_now_init(); esp_now_register_recv_cb(on_recv);
    static const uint8_t BCAST[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    esp_now_peer_info_t peer = {0}; memcpy(peer.peer_addr, BCAST, 6); peer.ifidx = WIFI_IF_STA; peer.channel = 0; peer.encrypt = false; esp_now_add_peer(&peer);
    hop_radio_init(0x0001, false);
    uint8_t mac[6]; esp_wifi_get_mac(WIFI_IF_STA, mac);
    ESP_LOGI(TAG, "air relay %02x:%02x:%02x:%02x:%02x:%02x: ESP-NOW in, 802.15.4 channel %d out", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], HOP_CHANNEL);
    static uint8_t frame[130]; static uint8_t sub[SUB_HDR + SUB_DATA]; uint8_t seq = 0; uint16_t id = 0; int64_t t_log = esp_timer_get_time();
    msg_t m;
    while (1) {
        if (xQueueReceive(q, &m, pdMS_TO_TICKS(1000)) == pdTRUE) {
            n_in++; uint8_t total = (uint8_t)((m.len + SUB_DATA - 1) / SUB_DATA); id++;
            for (uint8_t i = 0; i < total; i++) {
                uint16_t off = i * SUB_DATA, n = m.len - off < SUB_DATA ? m.len - off : SUB_DATA;
                sub[0] = 'S'; sub[1] = id & 0xff; sub[2] = id >> 8; sub[3] = i; sub[4] = total; memcpy(sub + SUB_HDR, m.d + off, n);
                hop_build(frame, seq++, 0x0001, sub, (uint8_t)(SUB_HDR + n));
                if (esp_ieee802154_transmit(frame, false) == ESP_OK) { xSemaphoreTake(txdone, pdMS_TO_TICKS(50)); n_sub++; } else n_fail++;
            }
        }
        if (esp_timer_get_time() - t_log > 10000000) { t_log = esp_timer_get_time(); ESP_LOGI(TAG, "in %lu, sub frames %lu, tx failures %lu", (unsigned long)n_in, (unsigned long)n_sub, (unsigned long)n_fail); }
    }
}

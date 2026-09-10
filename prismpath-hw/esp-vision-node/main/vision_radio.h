// ESP-NOW plumbing shared by the camera node (transmit) and the relay (receive). Broadcast peer, STA
// mode, default channel. Payloads over 250 bytes (keyframes) travel as numbered fragments:
//   "FRG1" | id u16 | idx u16 | total u16 | data[]     reassembled by the host
#pragma once
#include <string.h>
#include "esp_wifi.h"
#include "esp_now.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
static const uint8_t BCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
#define ESPNOW_MAX 250
#define FRAG_DATA (ESPNOW_MAX - 10)
typedef struct __attribute__((packed)) { char magic[4]; uint16_t id, idx, total; } frag_hdr_t;
static void radio_init(esp_now_recv_cb_t on_recv)
{
    esp_err_t e = nvs_flash_init();
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) { nvs_flash_erase(); nvs_flash_init(); }
    esp_netif_init(); esp_event_loop_create_default();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT(); esp_wifi_init(&wc); esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA); esp_wifi_start();
    esp_now_init(); if (on_recv) esp_now_register_recv_cb(on_recv);
    esp_now_peer_info_t peer = {0}; memcpy(peer.peer_addr, BCAST, 6); peer.ifidx = WIFI_IF_STA; peer.channel = 0; peer.encrypt = false; esp_now_add_peer(&peer);
}
static void radio_send_fragmented(uint16_t id, const uint8_t *data, size_t len)
{
    uint16_t total = (uint16_t)((len + FRAG_DATA - 1) / FRAG_DATA); uint8_t pkt[ESPNOW_MAX];
    for (uint16_t i = 0; i < total; i++) {
        size_t off = (size_t)i * FRAG_DATA, n = len - off < FRAG_DATA ? len - off : FRAG_DATA;
        frag_hdr_t h = { {'F','R','G','1'}, id, i, total }; memcpy(pkt, &h, sizeof h); memcpy(pkt + sizeof h, data + off, n);
        while (esp_now_send(BCAST, pkt, sizeof h + n) != ESP_OK) vTaskDelay(1);
        vTaskDelay(pdMS_TO_TICKS(2));   // let the radio breathe; the keyframe is not latency critical
    }
}

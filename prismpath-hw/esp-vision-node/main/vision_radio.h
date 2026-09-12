// ESP-NOW plumbing shared by the camera node (transmit) and the relay (receive). Broadcast peer, STA
// mode, default channel. Payloads over 250 bytes (keyframes) travel as numbered fragments:
//   "FRG2" | nid u16 | id u16 | idx u16 | total u16 | data[]     reassembled by the host per node
#pragma once
#include <string.h>
#include "esp_wifi.h"
#include "esp_heap_caps.h"
#include "esp_now.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "lwip/sockets.h"
#define HOP_SSID "prismpath-hop"
#define HOP_PORT 5050
static int hop_sock = -1; static struct sockaddr_in hop_addr; static volatile bool hop_up = false;
static void hop_on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) esp_wifi_connect();
    else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) { hop_up = false; vTaskDelay(pdMS_TO_TICKS(500)); esp_wifi_connect(); }
    else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = data; printf("hop: joined %s, ip " IPSTR "\n", HOP_SSID, IP2STR(&e->ip_info.ip));
        hop_addr.sin_family = AF_INET; hop_addr.sin_port = htons(HOP_PORT); hop_addr.sin_addr.s_addr = e->ip_info.gw.addr;
        if (hop_sock < 0) hop_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        hop_up = true;
    }
}
// A burst of keyframe fragments can outrun the Wi-Fi transmit buffers; a failed send is retried after
// a short pause instead of being dropped silently (the first symptom was keyframes arriving with their
// tails missing, 2026-09-10).
static void hop_send(const uint8_t *d, size_t n)
{
    if (!(hop_up && hop_sock >= 0)) return;
    for (int attempt = 0; attempt < 8; attempt++) {
        if (sendto(hop_sock, d, n, 0, (struct sockaddr *)&hop_addr, sizeof hop_addr) == (int)n) return;
        vTaskDelay(pdMS_TO_TICKS(3));
    }
}
static const uint8_t BCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
#define ESPNOW_MAX 250
#define FRAG_DATA (ESPNOW_MAX - 12)
typedef struct __attribute__((packed)) { char magic[4]; uint16_t nid, id, idx, total; } frag_hdr_t;
static void radio_init(esp_now_recv_cb_t on_recv)
{
    esp_err_t e = nvs_flash_init();
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) { nvs_flash_erase(); nvs_flash_init(); }
    esp_netif_init(); esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT(); esp_wifi_init(&wc); esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, hop_on_event, NULL); esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, hop_on_event, NULL);
    wifi_config_t sta = { .sta = { .ssid = HOP_SSID, .threshold.authmode = WIFI_AUTH_OPEN } };
    esp_wifi_set_mode(WIFI_MODE_STA); esp_wifi_set_config(WIFI_IF_STA, &sta); esp_wifi_start();
    esp_now_init(); if (on_recv) esp_now_register_recv_cb(on_recv);
    esp_now_peer_info_t peer = {0}; memcpy(peer.peer_addr, BCAST, 6); peer.ifidx = WIFI_IF_STA; peer.channel = 0; peer.encrypt = false; esp_now_add_peer(&peer);
}
// the last few fragmented messages stay in PSRAM so a repair request ('r' | id u16 | n u8 | idx[n]) can resend
// exactly the fragments a receiver did not get; readings are acknowledged hop by hop, fragments are not
#define KEEP_MSGS 3
static struct { uint16_t id; uint8_t *data; size_t len; bool set; } kept[KEEP_MSGS]; static int kept_next = 0;
static void radio_send_one_fragment(uint16_t nid, uint16_t id, const uint8_t *data, size_t len, uint16_t i)
{
    uint16_t total = (uint16_t)((len + FRAG_DATA - 1) / FRAG_DATA); if (i >= total) return; uint8_t pkt[ESPNOW_MAX];
    size_t off = (size_t)i * FRAG_DATA, n = len - off < FRAG_DATA ? len - off : FRAG_DATA;
    frag_hdr_t h = { {'F','R','G','2'}, nid, id, i, total }; memcpy(pkt, &h, sizeof h); memcpy(pkt + sizeof h, data + off, n);
    hop_send(pkt, sizeof h + n);
}
static int radio_resend_fragments(uint16_t nid, uint16_t id, const uint8_t *idx, int n)
{
    for (int k = 0; k < KEEP_MSGS; k++) if (kept[k].set && kept[k].id == id) {
        for (int j = 0; j < n; j++) { radio_send_one_fragment(nid, id, kept[k].data, kept[k].len, idx[j]); vTaskDelay(pdMS_TO_TICKS(8)); }
        return n;
    }
    return -1;
}
static void radio_keep(uint16_t id, const uint8_t *data, size_t len)
{
    int k = kept_next; kept_next = (kept_next + 1) % KEEP_MSGS;
    if (kept[k].set) free(kept[k].data);
    kept[k].data = heap_caps_malloc(len, MALLOC_CAP_SPIRAM); if (!kept[k].data) { kept[k].set = false; return; }
    memcpy(kept[k].data, data, len); kept[k].len = len; kept[k].id = id; kept[k].set = true;
}
// keep = true: a message worth repairing (keyframe, evidence), kept for resend and framed FRG2; keep = false: a message the
// next frame supersedes (a refinement layer), framed FRG3 so the receiver never asks for its missing fragments
static void radio_send_fragmented_ex(uint16_t nid, uint16_t id, const uint8_t *data, size_t len, bool keep)
{
    if (keep) radio_keep(id, data, len);
    uint16_t total = (uint16_t)((len + FRAG_DATA - 1) / FRAG_DATA); uint8_t pkt[ESPNOW_MAX];
    for (uint16_t i = 0; i < total; i++) {
        size_t off = (size_t)i * FRAG_DATA, n = len - off < FRAG_DATA ? len - off : FRAG_DATA;
        frag_hdr_t h = { {'F','R','G', keep ? '2' : '3'}, nid, id, i, total }; memcpy(pkt, &h, sizeof h); memcpy(pkt + sizeof h, data + off, n);
        while (esp_now_send(BCAST, pkt, sizeof h + n) != ESP_OK) vTaskDelay(1);
        hop_send(pkt, sizeof h + n);
        vTaskDelay(pdMS_TO_TICKS(8));   // pace the burst: a keyframe is not latency critical and the transmit buffers are finite
    }
}
static void radio_send_fragmented(uint16_t nid, uint16_t id, const uint8_t *data, size_t len) { radio_send_fragmented_ex(nid, id, data, len, true); }

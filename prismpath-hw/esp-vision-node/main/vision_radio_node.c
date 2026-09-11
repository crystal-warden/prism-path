// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// radio node: the camera node deciding live, readings over ESP-NOW instead of USB. One reading per
// frame as one ESP-NOW frame ("RDG1" record, under 90 bytes); background keyframes as fragments.
// Streams from boot; nothing on USB. The UART console carries the log.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_camera.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "mbedtls/sha256.h"
#include "esp_log.h"
#include "driver/usb_serial_jtag.h"
#include "vision_policy.h"
#include "../../codec-bench/zeck.h"
#include "vision_core.h"
#include "vision_radio.h"
static const char *TAG = "radio";
#define CAM_XCLK 15
#define CAM_SIOD 4
#define CAM_SIOC 5
#define CAM_D7 16
#define CAM_D6 17
#define CAM_D5 18
#define CAM_D4 12
#define CAM_D3 10
#define CAM_D2 8
#define CAM_D1 9
#define CAM_D0 11
#define CAM_VSYNC 6
#define CAM_HREF 7
#define CAM_PCLK 13
#define KEY_QUALITY 75
#define KEY_RESEND_US 60000000ULL   // resend the background every minute so a receiver that joins late holds a normal
// RDG4: the reading carries the first eight bytes of the SHA-256 of the previous reading record (header and wire), a hash
// chain that binds the trail to the node: a receiver can tell a lost reading (a gap in sequence) from a spliced one
typedef struct __attribute__((packed)) { char magic[4]; uint16_t nid, norm; uint32_t seq; uint64_t t_cap, t_dec; uint16_t node, steps, wire_len; uint64_t prev; } rdg_hdr_t;
static uint64_t chain_prev = 0;
typedef struct __attribute__((packed)) { char magic[4]; uint16_t nid, norm; uint32_t seq; uint64_t t_cap; uint32_t len; } key_hdr_t;
typedef struct __attribute__((packed)) { char magic[4]; uint16_t nid, norm; uint32_t seq; uint64_t t_cap; uint16_t route; uint32_t len; } evd_hdr_t;
#define EVIDENCE_GAP_US 10000000ULL
static uint16_t node_id;
static uint8_t *last_sent; static uint16_t frag_id = 0;
static void send_keyframe(camera_fb_t *fb, uint32_t seq, uint64_t t_cap)
{
    // the keyframe is the normal itself, not the current frame: at adoption they are the same, at a resend or a request they are not
    uint8_t *jpg = NULL; size_t jlen = 0; camera_fb_t bg = *fb; bg.buf = background; bg.len = W * H;
    if (!frame2jpg(&bg, KEY_QUALITY, &jpg, &jlen)) { ESP_LOGE(TAG, "frame2jpg failed"); return; }
    uint8_t *msg = malloc(sizeof(key_hdr_t) + jlen); key_hdr_t kh = { {'K','E','Y','3'}, node_id, normal_id, seq, t_cap, (uint32_t)jlen };
    memcpy(msg, &kh, sizeof kh); memcpy(msg + sizeof kh, jpg, jlen); free(jpg);
    radio_send_fragmented(node_id, frag_id++, msg, sizeof kh + jlen); free(msg);
    memcpy(last_sent, fb->buf, W * H);
    ESP_LOGI(TAG, "keyframe %lu B in %u fragments, normal %04x", (unsigned long)(sizeof kh + jlen), (unsigned)((sizeof kh + jlen + FRAG_DATA - 1) / FRAG_DATA), normal_id);
}
static bool escalates(uint16_t node) { const char *n = POLICY_NODE_NAMES[node]; return !strcmp(n, "tamper") || !strcmp(n, "evidence") || !strcmp(n, "door") || !strcmp(n, "scene_changed"); }
static void send_evidence(camera_fb_t *fb, uint32_t seq, uint64_t t_cap, uint16_t route)
{
    uint8_t *jpg = NULL; size_t jlen = 0;
    if (!frame2jpg(fb, KEY_QUALITY, &jpg, &jlen)) return;
    uint8_t *msg = malloc(sizeof(evd_hdr_t) + jlen); evd_hdr_t eh = { {'E','V','D','1'}, node_id, normal_id, seq, t_cap, route, (uint32_t)jlen };
    memcpy(msg, &eh, sizeof eh); memcpy(msg + sizeof eh, jpg, jlen); free(jpg);
    radio_send_fragmented(node_id, frag_id++, msg, sizeof eh + jlen); free(msg);
    ESP_LOGI(TAG, "evidence for %s: %lu B", POLICY_NODE_NAMES[route], (unsigned long)(sizeof eh + jlen));
}
void app_main(void)
{
    vision_core_init(); last_sent = heap_caps_malloc(W * H, MALLOC_CAP_SPIRAM);
    camera_config_t c = {
        .pin_pwdn = -1, .pin_reset = -1, .pin_xclk = CAM_XCLK, .pin_sccb_sda = CAM_SIOD, .pin_sccb_scl = CAM_SIOC,
        .pin_d7 = CAM_D7, .pin_d6 = CAM_D6, .pin_d5 = CAM_D5, .pin_d4 = CAM_D4, .pin_d3 = CAM_D3, .pin_d2 = CAM_D2,
        .pin_d1 = CAM_D1, .pin_d0 = CAM_D0, .pin_vsync = CAM_VSYNC, .pin_href = CAM_HREF, .pin_pclk = CAM_PCLK,
        .xclk_freq_hz = 20000000, .ledc_timer = LEDC_TIMER_0, .ledc_channel = LEDC_CHANNEL_0,
        .pixel_format = PIXFORMAT_GRAYSCALE, .frame_size = (W == 640 ? FRAMESIZE_VGA : FRAMESIZE_QVGA), .jpeg_quality = 12,
        .fb_count = 3, .fb_location = CAMERA_FB_IN_PSRAM, .grab_mode = CAMERA_GRAB_LATEST,
    };
    ESP_ERROR_CHECK(esp_camera_init(&c));
    radio_init(NULL);
    uint8_t mac[6]; esp_wifi_get_mac(WIFI_IF_STA, mac); node_id = (uint16_t)((mac[4] << 8) | mac[5]);
    // exposure lock (T2): the bands were tuned on a locked sensor; let auto exposure and gain settle on the scene, then
    // freeze them, and only then start the front end, so the anchored normal is a settled frame
    vTaskDelay(pdMS_TO_TICKS(3000));
    { sensor_t *sen = esp_camera_sensor_get(); if (sen) { sen->set_exposure_ctrl(sen, 0); sen->set_gain_ctrl(sen, 0); ESP_LOGI(TAG, "exposure and gain locked: aec_value=%d agc_gain=%d", sen->status.aec_value, sen->status.agc_gain); } }
    ESP_LOGI(TAG, "radio node %02x:%02x:%02x:%02x:%02x:%02x streaming over ESP-NOW", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    uint32_t seq = 0; static uint8_t pkt[ESPNOW_MAX]; uint64_t t_key = 0, t_evd = 0; uint16_t last_normal = 0xffff; bool adopt_now = false, key_now = false;
    usb_serial_jtag_driver_config_t ucfg = { .tx_buffer_size = 16384, .rx_buffer_size = 256 }; bool usb_ok = usb_serial_jtag_driver_install(&ucfg) == ESP_OK;   // the operator sends n to adopt the current frame as the normal
    while (1) {
        uint8_t ch; if (usb_ok && usb_serial_jtag_read_bytes(&ch, 1, 0) == 1 && ch == 'n') { ESP_LOGI(TAG, "operator adopts the normal"); adopt_now = true; }
        // the same command over the air: the relay forwards 'C' | nid | data to the camera it names (0xffff = all)
        if (hop_up && hop_sock >= 0) {
            uint8_t cb[32]; int r = recv(hop_sock, cb, sizeof cb, MSG_DONTWAIT);
            if (r >= 4 && cb[0] == 'C') {
                uint16_t to = cb[1] | (cb[2] << 8);
                if (to == node_id || to == 0xffff) {
                    if (cb[3] == 'n') { ESP_LOGI(TAG, "adopt over the air"); adopt_now = true; }
                    else if (cb[3] == 'k') { ESP_LOGI(TAG, "keyframe requested over the air"); key_now = true; }   // a receiver that joined mid stream asks for the normal
                    else if (cb[3] == 'r' && r >= 7) {   // repair: 'r' | id u16 | n u8 | idx[n]
                        uint16_t id = cb[4] | (cb[5] << 8); int cnt = cb[6]; if (cnt > r - 7) cnt = r - 7;
                        int done = radio_resend_fragments(node_id, id, cb + 7, cnt);
                        ESP_LOGI(TAG, "repair for message %u: %d fragment(s) %s", id, cnt, done < 0 ? "no longer held" : "resent");
                    }
                }
            }
        }
        camera_fb_t *fb = esp_camera_fb_get(); if (!fb) continue;
        uint64_t t_cap = (uint64_t)fb->timestamp.tv_sec * 1000000ULL + (uint64_t)fb->timestamp.tv_usec;
        cur = fb->buf;
        if (adopt_now) { adopt_now = false; adopt_normal(); }
        int64_t t_fe0 = esp_timer_get_time();
        int32_t motion_cells, dark, step, door_hit, scene; front_end(&motion_cells, &dark, &step, &door_hit, &scene);
        { static int64_t fe_sum = 0, fe_max = 0, t_fe_log = 0; static int fe_n = 0; int64_t dt = esp_timer_get_time() - t_fe0; fe_sum += dt; fe_n++; if (dt > fe_max) fe_max = dt;
          if (esp_timer_get_time() - t_fe_log > 10000000) { ESP_LOGI(TAG, "front end %dx%d: mean %lld us, max %lld us over %d frames; free PSRAM %u B", W, H, (long long)(fe_sum / fe_n), (long long)fe_max, fe_n, (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM)); fe_sum = 0; fe_n = 0; fe_max = 0; t_fe_log = esp_timer_get_time(); } }
        uint16_t node, steps; decide(motion_cells, dark, step, door_hit, scene, &node, &steps);
        uint8_t wirebuf[128]; uint16_t wire_len = encode_reading(wirebuf, sizeof wirebuf);
        uint64_t t_dec = (uint64_t)esp_timer_get_time();
        rdg_hdr_t rh = { {'R','D','G','4'}, node_id, normal_id, seq, t_cap, t_dec, node, steps, wire_len, chain_prev };
        memcpy(pkt, &rh, sizeof rh); memcpy(pkt + sizeof rh, wirebuf, wire_len);
        esp_now_send(BCAST, pkt, sizeof rh + wire_len); hop_send(pkt, sizeof rh + wire_len);
        { uint8_t h[32]; mbedtls_sha256(pkt, sizeof rh + wire_len, h, 0); memcpy(&chain_prev, h, 8); }   // this record's hash is the next record's prev
        // a keyframe whenever the normal changed id (adoption, or the search for the first clean stretch ending), and every minute
        if (normal_set && (normal_id != last_normal || key_now || t_dec - t_key > KEY_RESEND_US)) { send_keyframe(fb, seq, t_cap); t_key = t_dec; last_normal = normal_id; key_now = false; }
        if (escalates(node) && t_dec - t_evd > EVIDENCE_GAP_US) { send_evidence(fb, seq, t_cap, node); t_evd = t_dec; }
        esp_camera_fb_return(fb); seq++;
    }
}

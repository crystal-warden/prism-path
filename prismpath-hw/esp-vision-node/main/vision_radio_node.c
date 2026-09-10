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
typedef struct __attribute__((packed)) { char magic[4]; uint16_t nid; uint32_t seq; uint64_t t_cap, t_dec; uint16_t node, steps, wire_len; } rdg_hdr_t;
typedef struct __attribute__((packed)) { char magic[4]; uint16_t nid; uint32_t seq; uint64_t t_cap; uint32_t len; } key_hdr_t;
static uint16_t node_id;
static uint8_t *last_sent; static uint16_t frag_id = 0;
static void send_keyframe(camera_fb_t *fb, uint32_t seq, uint64_t t_cap)
{
    uint8_t *jpg = NULL; size_t jlen = 0;
    if (!frame2jpg(fb, KEY_QUALITY, &jpg, &jlen)) { ESP_LOGE(TAG, "frame2jpg failed"); return; }
    uint8_t *msg = malloc(sizeof(key_hdr_t) + jlen); key_hdr_t kh = { {'K','E','Y','2'}, node_id, seq, t_cap, (uint32_t)jlen };
    memcpy(msg, &kh, sizeof kh); memcpy(msg + sizeof kh, jpg, jlen); free(jpg);
    radio_send_fragmented(node_id, frag_id++, msg, sizeof kh + jlen); free(msg);
    memcpy(last_sent, fb->buf, W * H);
    ESP_LOGI(TAG, "keyframe %lu B in %u fragments", (unsigned long)(sizeof kh + jlen), (unsigned)((sizeof kh + jlen + FRAG_DATA - 1) / FRAG_DATA));
}
void app_main(void)
{
    vision_core_init(); last_sent = heap_caps_malloc(W * H, MALLOC_CAP_SPIRAM);
    camera_config_t c = {
        .pin_pwdn = -1, .pin_reset = -1, .pin_xclk = CAM_XCLK, .pin_sccb_sda = CAM_SIOD, .pin_sccb_scl = CAM_SIOC,
        .pin_d7 = CAM_D7, .pin_d6 = CAM_D6, .pin_d5 = CAM_D5, .pin_d4 = CAM_D4, .pin_d3 = CAM_D3, .pin_d2 = CAM_D2,
        .pin_d1 = CAM_D1, .pin_d0 = CAM_D0, .pin_vsync = CAM_VSYNC, .pin_href = CAM_HREF, .pin_pclk = CAM_PCLK,
        .xclk_freq_hz = 20000000, .ledc_timer = LEDC_TIMER_0, .ledc_channel = LEDC_CHANNEL_0,
        .pixel_format = PIXFORMAT_GRAYSCALE, .frame_size = FRAMESIZE_QVGA, .jpeg_quality = 12,
        .fb_count = 3, .fb_location = CAMERA_FB_IN_PSRAM, .grab_mode = CAMERA_GRAB_LATEST,
    };
    ESP_ERROR_CHECK(esp_camera_init(&c));
    radio_init(NULL);
    uint8_t mac[6]; esp_wifi_get_mac(WIFI_IF_STA, mac); node_id = (uint16_t)((mac[4] << 8) | mac[5]);
    ESP_LOGI(TAG, "radio node %02x:%02x:%02x:%02x:%02x:%02x streaming over ESP-NOW", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    uint32_t seq = 0; static uint8_t pkt[ESPNOW_MAX]; uint64_t t_key = 0;
    while (1) {
        camera_fb_t *fb = esp_camera_fb_get(); if (!fb) continue;
        uint64_t t_cap = (uint64_t)fb->timestamp.tv_sec * 1000000ULL + (uint64_t)fb->timestamp.tv_usec;
        cur = fb->buf; bool first = (frame_n == 0);
        int32_t motion_cells, dark, step, door_hit; front_end(&motion_cells, &dark, &step, &door_hit);
        uint16_t node, steps; decide(motion_cells, dark, step, door_hit, &node, &steps);
        uint8_t wirebuf[128]; uint16_t wire_len = encode_reading(wirebuf, sizeof wirebuf);
        uint64_t t_dec = (uint64_t)esp_timer_get_time();
        rdg_hdr_t rh = { {'R','D','G','2'}, node_id, seq, t_cap, t_dec, node, steps, wire_len };
        memcpy(pkt, &rh, sizeof rh); memcpy(pkt + sizeof rh, wirebuf, wire_len);
        esp_now_send(BCAST, pkt, sizeof rh + wire_len); hop_send(pkt, sizeof rh + wire_len);
        if (first || (refreshed && background_moved(last_sent)) || (t_dec - t_key > KEY_RESEND_US)) { send_keyframe(fb, seq, t_cap); t_key = t_dec; }
        esp_camera_fb_return(fb); seq++;
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// live: the node deciding from its own camera. Front end, policy, quantize and encode on the board;
// only the reading crosses to the host, plus a background keyframe (JPEG) when the node's refresh
// actually moved the background. Records over native USB, little endian:
//   "RDG1" | seq u32 | t_cap u64 | t_dec u64 | node u16 | steps u16 | wire_len u16 | wire[]
//   "KEY1" | seq u32 | t_cap u64 | len u32 | jpeg[len]
// t_cap is the driver's capture timestamp, t_dec the moment the decision and wire bytes are ready,
// both on the node clock: t_dec - t_cap is capture to decision on the node.
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
#define VISION_NO_MAIN
#include "vision_core.h"

static const char *TAG = "live";
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

typedef struct __attribute__((packed)) { char magic[4]; uint32_t seq; uint64_t t_cap, t_dec; uint16_t node, steps, wire_len; } rdg_hdr_t;
typedef struct __attribute__((packed)) { char magic[4]; uint32_t seq; uint64_t t_cap; uint32_t len; } key_hdr_t;

static uint8_t *last_sent;

static void send_keyframe(camera_fb_t *fb, uint32_t seq, uint64_t t_cap)
{
    uint8_t *jpg = NULL; size_t jlen = 0;
    if (!frame2jpg(fb, KEY_QUALITY, &jpg, &jlen)) { ESP_LOGE(TAG, "frame2jpg failed"); return; }
    key_hdr_t kh = { {'K','E','Y','1'}, seq, t_cap, (uint32_t)jlen };
    usb_write_all((const uint8_t *)&kh, sizeof kh); usb_write_all(jpg, jlen); free(jpg);
    memcpy(last_sent, fb->buf, W * H);
}

void app_main(void)
{
    vision_core_init();
    last_sent = heap_caps_malloc(W * H, MALLOC_CAP_SPIRAM);
    camera_config_t c = {
        .pin_pwdn = -1, .pin_reset = -1, .pin_xclk = CAM_XCLK, .pin_sccb_sda = CAM_SIOD, .pin_sccb_scl = CAM_SIOC,
        .pin_d7 = CAM_D7, .pin_d6 = CAM_D6, .pin_d5 = CAM_D5, .pin_d4 = CAM_D4, .pin_d3 = CAM_D3, .pin_d2 = CAM_D2,
        .pin_d1 = CAM_D1, .pin_d0 = CAM_D0, .pin_vsync = CAM_VSYNC, .pin_href = CAM_HREF, .pin_pclk = CAM_PCLK,
        .xclk_freq_hz = 20000000, .ledc_timer = LEDC_TIMER_0, .ledc_channel = LEDC_CHANNEL_0,
        .pixel_format = PIXFORMAT_GRAYSCALE, .frame_size = FRAMESIZE_QVGA, .jpeg_quality = 12,
        .fb_count = 3, .fb_location = CAMERA_FB_IN_PSRAM, .grab_mode = CAMERA_GRAB_LATEST,
    };
    ESP_ERROR_CHECK(esp_camera_init(&c));
    usb_serial_jtag_driver_config_t ucfg = { .tx_buffer_size = 16384, .rx_buffer_size = 256 };
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&ucfg));
    ESP_LOGI(TAG, "live: %u B table, %u fields; g=stream x=stop", POLICY_TABLE_LEN, n_fields);
    bool streaming = false; uint32_t seq = 0; static uint8_t wirebuf[256];
    while (1) {
        uint8_t ch;
        if (usb_serial_jtag_read_bytes(&ch, 1, 0) == 1) {
            if (ch == 'g') { streaming = true; seq = 0; frame_n = 0; ESP_LOGI(TAG, "stream start"); }
            else if (ch == 'x') { streaming = false; ESP_LOGI(TAG, "stream stop"); }
        }
        if (!streaming) { vTaskDelay(pdMS_TO_TICKS(5)); continue; }
        camera_fb_t *fb = esp_camera_fb_get();
        if (!fb) continue;
        uint64_t t_cap = (uint64_t)fb->timestamp.tv_sec * 1000000ULL + (uint64_t)fb->timestamp.tv_usec;
        cur = fb->buf;
        bool first = (frame_n == 0);
        int32_t motion_cells, dark, step, door_hit, scene; front_end(&motion_cells, &dark, &step, &door_hit, &scene);
        uint16_t node, steps; decide(motion_cells, dark, step, door_hit, scene, &node, &steps);
        uint16_t wire_len = encode_reading(wirebuf, sizeof wirebuf);
        uint64_t t_dec = (uint64_t)esp_timer_get_time();
        rdg_hdr_t rh = { {'R','D','G','1'}, seq, t_cap, t_dec, node, steps, wire_len };
        usb_write_all((const uint8_t *)&rh, sizeof rh); usb_write_all(wirebuf, wire_len);
        // keyframe: at join, and whenever the refresh moved the background by a band anywhere
        if (first) send_keyframe(fb, seq, t_cap);
        else if (refreshed && background_moved(last_sent)) send_keyframe(fb, seq, t_cap);
        esp_camera_fb_return(fb);
        seq++;
    }
}

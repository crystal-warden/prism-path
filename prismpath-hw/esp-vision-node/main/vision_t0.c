// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// T0: the capture envelope of the camera node (FORIOT ESP32-S3-CAM, OV3660 over DVP).
// Walks a list of capture modes, holds each for T0_SECONDS, and prints one summary line per mode:
// achieved frames per second, frame interval min/mean/max, bytes per frame (JPEG modes vary), and
// free internal and PSRAM heap. Nothing is decided here; this is the measurement the design is
// re-parameterized against. The board pin map is prismpath-hw/../cw-strategy BOARD.md until it moves.
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_camera.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "t0";
#ifndef T0_SECONDS
#define T0_SECONDS 60
#endif

// FORIOT ESP32-S3-CAM pin map (vendor diagram; confirmed by the first capture that succeeds).
#define CAM_PWDN  -1
#define CAM_RESET -1
#define CAM_XCLK  15
#define CAM_SIOD  4
#define CAM_SIOC  5
#define CAM_D7    16   // Y9
#define CAM_D6    17   // Y8
#define CAM_D5    18   // Y7
#define CAM_D4    12   // Y6
#define CAM_D3    10   // Y5
#define CAM_D2    8    // Y4
#define CAM_D1    9    // Y3
#define CAM_D0    11   // Y2
#define CAM_VSYNC 6
#define CAM_HREF  7
#define CAM_PCLK  13

typedef struct {
    const char *name;
    pixformat_t fmt;
    framesize_t size;
    int jpeg_quality;      // esp32-camera scale, 0 best .. 63 worst; only for JPEG modes
    int xclk_hz;
} mode_t_;

static const mode_t_ MODES[] = {
    { "gray QVGA 320x240 xclk20",  PIXFORMAT_GRAYSCALE, FRAMESIZE_QVGA, 0,  20000000 },
    { "gray VGA 640x480 xclk20",   PIXFORMAT_GRAYSCALE, FRAMESIZE_VGA,  0,  20000000 },
    { "jpeg QVGA q10 xclk20",      PIXFORMAT_JPEG,      FRAMESIZE_QVGA, 10, 20000000 },
    { "jpeg QVGA q20 xclk20",      PIXFORMAT_JPEG,      FRAMESIZE_QVGA, 20, 20000000 },
    { "jpeg QVGA q4 xclk20",       PIXFORMAT_JPEG,      FRAMESIZE_QVGA, 4,  20000000 },
    { "gray QVGA 320x240 xclk10",  PIXFORMAT_GRAYSCALE, FRAMESIZE_QVGA, 0,  10000000 },
};

static esp_err_t cam_start(const mode_t_ *m)
{
    camera_config_t c = {
        .pin_pwdn = CAM_PWDN, .pin_reset = CAM_RESET, .pin_xclk = CAM_XCLK,
        .pin_sccb_sda = CAM_SIOD, .pin_sccb_scl = CAM_SIOC,
        .pin_d7 = CAM_D7, .pin_d6 = CAM_D6, .pin_d5 = CAM_D5, .pin_d4 = CAM_D4,
        .pin_d3 = CAM_D3, .pin_d2 = CAM_D2, .pin_d1 = CAM_D1, .pin_d0 = CAM_D0,
        .pin_vsync = CAM_VSYNC, .pin_href = CAM_HREF, .pin_pclk = CAM_PCLK,
        .xclk_freq_hz = m->xclk_hz,
        .ledc_timer = LEDC_TIMER_0, .ledc_channel = LEDC_CHANNEL_0,
        .pixel_format = m->fmt, .frame_size = m->size,
        .jpeg_quality = m->jpeg_quality ? m->jpeg_quality : 12,
        .fb_count = 2, .fb_location = CAMERA_FB_IN_PSRAM,
        .grab_mode = CAMERA_GRAB_LATEST,
    };
    esp_err_t err = esp_camera_init(&c);
    if (err != ESP_OK) return err;
    sensor_t *s = esp_camera_sensor_get();
    if (s) {
        ESP_LOGI(TAG, "sensor pid=0x%04x ver=0x%02x midl=0x%02x midh=0x%02x", s->id.PID, s->id.VER, s->id.MIDL, s->id.MIDH);
    }
    return ESP_OK;
}

static void run_mode(const mode_t_ *m)
{
    esp_err_t err = cam_start(m);
    if (err != ESP_OK) {
        printf("T0 mode=\"%s\" init_failed err=0x%x\n", m->name, err);
        return;
    }
    // Let exposure settle and the first frames flush.
    for (int i = 0; i < 5; i++) { camera_fb_t *fb = esp_camera_fb_get(); if (fb) esp_camera_fb_return(fb); }
    int64_t t_start = esp_timer_get_time(), t_prev = t_start, t_end = t_start + (int64_t)T0_SECONDS * 1000000;
    uint32_t frames = 0, fails = 0; int64_t dt_min = INT64_MAX, dt_max = 0; uint64_t bytes = 0, bmin = UINT64_MAX, bmax = 0;
    while (esp_timer_get_time() < t_end) {
        camera_fb_t *fb = esp_camera_fb_get();
        int64_t now = esp_timer_get_time();
        if (!fb) { fails++; continue; }
        int64_t dt = now - t_prev; t_prev = now;
        if (frames) { if (dt < dt_min) dt_min = dt; if (dt > dt_max) dt_max = dt; }
        bytes += fb->len; if (fb->len < bmin) bmin = fb->len; if (fb->len > bmax) bmax = fb->len;
        frames++;
        esp_camera_fb_return(fb);
    }
    double secs = (esp_timer_get_time() - t_start) / 1e6;
    printf("T0 mode=\"%s\" secs=%.1f frames=%lu fails=%lu fps=%.2f dt_ms_min=%.1f dt_ms_mean=%.1f dt_ms_max=%.1f "
           "bytes_mean=%.0f bytes_min=%llu bytes_max=%llu heap_free=%u psram_free=%u psram_total=%u\n",
           m->name, secs, (unsigned long)frames, (unsigned long)fails, frames / secs,
           dt_min / 1000.0, frames > 1 ? (secs * 1000.0) / frames : 0.0, dt_max / 1000.0,
           frames ? (double)bytes / frames : 0.0, (unsigned long long)(frames ? bmin : 0), (unsigned long long)bmax,
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
           (unsigned)heap_caps_get_total_size(MALLOC_CAP_SPIRAM));
    esp_camera_deinit();
    vTaskDelay(pdMS_TO_TICKS(300));
}

void app_main(void)
{
    printf("T0 boot psram_total=%u psram_free=%u heap_free=%u seconds_per_mode=%d\n",
           (unsigned)heap_caps_get_total_size(MALLOC_CAP_SPIRAM), (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), T0_SECONDS);
    for (size_t i = 0; i < sizeof(MODES) / sizeof(MODES[0]); i++) run_mode(&MODES[i]);
    printf("T0 done\n");
    while (1) vTaskDelay(pdMS_TO_TICKS(1000));
}

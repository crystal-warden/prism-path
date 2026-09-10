// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// snap: the aiming tool. Grayscale 320x240, camera held open; every 's' byte on the console captures one
// frame and dumps it base64 with a header line, the same framing T0 used, so the host can overlay the
// policy grid and show where the door zone lands. Build with -DVISION_SNAP to select this entry point.
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_camera.h"
#include "esp_log.h"
#include "mbedtls/base64.h"
#include "driver/uart.h"

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

static void dump(camera_fb_t *fb, const char *name)
{
    printf("T0 frame mode=\"%s\" fmt=%s w=%u h=%u len=%u\n", name,
           fb->format == PIXFORMAT_JPEG ? "jpeg" : "gray", (unsigned)fb->width, (unsigned)fb->height, (unsigned)fb->len);
    static char b64[4096];
    for (size_t off = 0; off < fb->len; off += 2400) {
        size_t chunk = fb->len - off < 2400 ? fb->len - off : 2400, olen = 0;
        if (mbedtls_base64_encode((unsigned char *)b64, sizeof b64, &olen, fb->buf + off, chunk) == 0) {
            fwrite(b64, 1, olen, stdout); fputc('\n', stdout);
        }
        vTaskDelay(1);
    }
    printf("T0 frame end\n");
    fflush(stdout);
}

void app_main(void)
{
    camera_config_t c = {
        .pin_pwdn = -1, .pin_reset = -1, .pin_xclk = CAM_XCLK, .pin_sccb_sda = CAM_SIOD, .pin_sccb_scl = CAM_SIOC,
        .pin_d7 = CAM_D7, .pin_d6 = CAM_D6, .pin_d5 = CAM_D5, .pin_d4 = CAM_D4, .pin_d3 = CAM_D3, .pin_d2 = CAM_D2,
        .pin_d1 = CAM_D1, .pin_d0 = CAM_D0, .pin_vsync = CAM_VSYNC, .pin_href = CAM_HREF, .pin_pclk = CAM_PCLK,
        .xclk_freq_hz = 20000000, .ledc_timer = LEDC_TIMER_0, .ledc_channel = LEDC_CHANNEL_0,
        .pixel_format = PIXFORMAT_GRAYSCALE, .frame_size = FRAMESIZE_QVGA, .jpeg_quality = 12,
        .fb_count = 2, .fb_location = CAMERA_FB_IN_PSRAM, .grab_mode = CAMERA_GRAB_LATEST,
    };
    ESP_ERROR_CHECK(esp_camera_init(&c));
    uart_driver_install(UART_NUM_0, 1024, 0, 0, NULL, 0);
    printf("snap ready: send 's' for a frame\n");
    uint8_t ch;
    while (1) {
        if (uart_read_bytes(UART_NUM_0, &ch, 1, pdMS_TO_TICKS(100)) == 1 && ch == 's') {
            // drop the buffered frames so the snap is current
            for (int i = 0; i < 2; i++) { camera_fb_t *fb = esp_camera_fb_get(); if (fb) esp_camera_fb_return(fb); }
            camera_fb_t *fb = esp_camera_fb_get();
            if (fb) { dump(fb, "snap gray QVGA"); esp_camera_fb_return(fb); }
        }
    }
}

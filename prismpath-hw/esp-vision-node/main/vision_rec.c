// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// rec: the corpus recorder. Grayscale 320x240 frames stream over the S3's native USB (the OTG port, the
// USB Serial JTAG peripheral) as binary records; the UART console keeps the logs. Commands arrive on the
// USB link: 'g' start streaming, 'x' stop, 's' one frame. Record framing, little endian:
//   "FRM2" magic (4) | seq u32 | t_cap_us u64 | t_send_us u64 | w u16 | h u16 | len u32 | payload[len]
// t_cap_us is the driver's capture timestamp (VSYNC of this frame), t_send_us the moment the header
// leaves; both on the node clock, so the host can split latency into capture to send and send to receive.
// The host (rec.py) syncs on the magic, checks seq for drops, and writes the frozen corpus.
// Exposure lock (T2): the sensor's auto exposure and gain settle for a few seconds after boot and are then
// frozen, so a reading means the same thing from one frame to the next and a dark room reads dark.
// Commands 'l' and 'u' lock and unlock again; 'e' prints what the sensor reports.
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_camera.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "driver/usb_serial_jtag.h"

static const char *TAG = "rec";
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

typedef struct __attribute__((packed)) {
    char magic[4]; uint32_t seq; uint64_t t_cap_us, t_send_us; uint16_t w, h; uint32_t len;
} frame_hdr_t;

// The driver hands each write to a ring buffer as one item, and an item larger than the buffer never
// fits, so a whole frame in one call blocks forever. Write in pieces well under the buffer size.
#define USB_PIECE 2048
static void usb_write_all(const uint8_t *p, size_t n)
{
    while (n) {
        size_t piece = n < USB_PIECE ? n : USB_PIECE;
        int w = usb_serial_jtag_write_bytes(p, piece, pdMS_TO_TICKS(1000));
        if (w <= 0) { vTaskDelay(1); continue; }
        p += w; n -= w;
    }
}

static bool send_frame(uint32_t seq, bool fresh)
{
    if (fresh) {   // a single frame on request must be current: drain what the driver queued while idle
        for (int i = 0; i < 3; i++) { camera_fb_t *old = esp_camera_fb_get(); if (old) esp_camera_fb_return(old); }
    }
    camera_fb_t *fb = esp_camera_fb_get();
    if (!fb) return false;
    uint64_t t_cap = (uint64_t)fb->timestamp.tv_sec * 1000000ULL + (uint64_t)fb->timestamp.tv_usec;
    frame_hdr_t h = { {'F','R','M','2'}, seq, t_cap, (uint64_t)esp_timer_get_time(), (uint16_t)fb->width, (uint16_t)fb->height, (uint32_t)fb->len };
    usb_write_all((const uint8_t *)&h, sizeof h);
    usb_write_all(fb->buf, fb->len);
    esp_camera_fb_return(fb);
    return true;
}

void app_main(void)
{
    camera_config_t c = {
        .pin_pwdn = -1, .pin_reset = -1, .pin_xclk = CAM_XCLK, .pin_sccb_sda = CAM_SIOD, .pin_sccb_scl = CAM_SIOC,
        .pin_d7 = CAM_D7, .pin_d6 = CAM_D6, .pin_d5 = CAM_D5, .pin_d4 = CAM_D4, .pin_d3 = CAM_D3, .pin_d2 = CAM_D2,
        .pin_d1 = CAM_D1, .pin_d0 = CAM_D0, .pin_vsync = CAM_VSYNC, .pin_href = CAM_HREF, .pin_pclk = CAM_PCLK,
        .xclk_freq_hz = 20000000, .ledc_timer = LEDC_TIMER_0, .ledc_channel = LEDC_CHANNEL_0,
#ifdef VISION_RGB565
        .pixel_format = PIXFORMAT_RGB565,       // a color take: 2 bytes per pixel, the host tool unpacks it
#else
        .pixel_format = PIXFORMAT_GRAYSCALE,
#endif
        .frame_size = FRAMESIZE_QVGA, .jpeg_quality = 12,
        .fb_count = 3, .fb_location = CAMERA_FB_IN_PSRAM, .grab_mode = CAMERA_GRAB_LATEST,
    };
    ESP_ERROR_CHECK(esp_camera_init(&c));
    usb_serial_jtag_driver_config_t ucfg = { .tx_buffer_size = 16384, .rx_buffer_size = 256 };
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&ucfg));
    vTaskDelay(pdMS_TO_TICKS(3000));                       // let auto exposure and gain settle on the scene
    sensor_t *sen = esp_camera_sensor_get();
    if (sen) { sen->set_exposure_ctrl(sen, 0); sen->set_gain_ctrl(sen, 0); ESP_LOGI(TAG, "exposure and gain locked: aec_value=%d agc_gain=%d", sen->status.aec_value, sen->status.agc_gain); }
    ESP_LOGI(TAG, "recorder ready on USB: g=stream x=stop s=one frame l=lock u=unlock");
    bool streaming = false; uint32_t seq = 0; int64_t t0 = 0; uint32_t sent = 0;
    while (1) {
        uint8_t ch;
        if (usb_serial_jtag_read_bytes(&ch, 1, 0) == 1) {
            if (ch == 'g') { streaming = true; seq = 0; sent = 0; t0 = esp_timer_get_time(); ESP_LOGI(TAG, "stream start"); }
            else if (ch == 'x') { streaming = false; double s = (esp_timer_get_time() - t0) / 1e6; ESP_LOGI(TAG, "stream stop: %lu frames in %.1f s = %.2f fps", (unsigned long)sent, s, sent / s); }
            else if (ch == 's') { send_frame(0xFFFFFFFF, true); }
            else if (ch == 'l' && sen) { sen->set_exposure_ctrl(sen, 0); sen->set_gain_ctrl(sen, 0); ESP_LOGI(TAG, "locked"); }
            else if (ch == 'u' && sen) { sen->set_exposure_ctrl(sen, 1); sen->set_gain_ctrl(sen, 1); ESP_LOGI(TAG, "unlocked"); }
        }
        if (streaming) { if (send_frame(seq++, false)) sent++; }
        else vTaskDelay(pdMS_TO_TICKS(5));
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// relay: receives every ESP-NOW frame and forwards it to the host over native USB, stamped with the
// relay's receive time: "ENF1" | t_relay u64 | len u16 | frame[len]. The host reassembles keyframe
// fragments and keeps the node's records as they were. Where a C6 hop goes later.
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "driver/usb_serial_jtag.h"
#include "vision_radio.h"
static const char *TAG = "relay";
typedef struct { uint64_t t; uint16_t len; uint8_t d[ESPNOW_MAX]; } rx_t;
static QueueHandle_t rxq;
static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    (void)info; if (len <= 0 || len > ESPNOW_MAX) return;
    rx_t m; m.t = (uint64_t)esp_timer_get_time(); m.len = (uint16_t)len; memcpy(m.d, data, len); xQueueSend(rxq, &m, 0);
}
static void usb_write_all(const uint8_t *p, size_t n) {
    while (n) { size_t piece = n < 2048 ? n : 2048; int w = usb_serial_jtag_write_bytes(p, piece, pdMS_TO_TICKS(1000)); if (w <= 0) { vTaskDelay(1); continue; } p += w; n -= w; }
}
void app_main(void)
{
    rxq = xQueueCreate(64, sizeof(rx_t));
    usb_serial_jtag_driver_config_t ucfg = { .tx_buffer_size = 16384, .rx_buffer_size = 256 };
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&ucfg));
    radio_init(on_recv);
    uint8_t mac[6]; esp_wifi_get_mac(WIFI_IF_STA, mac);
    ESP_LOGI(TAG, "relay %02x:%02x:%02x:%02x:%02x:%02x forwarding ESP-NOW to USB", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    rx_t m; uint32_t n = 0;
    while (1) {
        if (xQueueReceive(rxq, &m, portMAX_DELAY) != pdTRUE) continue;
        uint8_t hdr[14]; memcpy(hdr, "ENF1", 4); memcpy(hdr + 4, &m.t, 8); memcpy(hdr + 12, &m.len, 2);
        usb_write_all(hdr, sizeof hdr); usb_write_all(m.d, m.len);
        if (++n % 500 == 0) ESP_LOGI(TAG, "forwarded %lu frames", (unsigned long)n);
    }
}

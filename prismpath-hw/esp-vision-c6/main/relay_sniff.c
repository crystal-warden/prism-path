// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// relay_sniff: the independent witness (A8). Promiscuous on the hop's channel, no address, no policy, no acks, no part
// in any decision: every frame it hears goes to the host over native USB with its own timestamp and signal:
//   "SNF1" | t u64 | rssi i8 | lqi u8 | len u8 | frame[len]   (len counts the FCS as the radio reports it; FCS not delivered)
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_timer.h"
#include "driver/usb_serial_jtag.h"
#include "hop.h"
typedef struct { uint64_t t; int8_t rssi; uint8_t lqi, len; uint8_t d[128]; } rx_t;
static QueueHandle_t q;
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *info)
{
    rx_t r; r.t = (uint64_t)esp_timer_get_time(); r.rssi = info ? info->rssi : 0; r.lqi = info ? info->lqi : 0; r.len = frame[0]; memcpy(r.d, frame + 1, frame[0] > 127 ? 127 : frame[0]);
    esp_ieee802154_receive_handle_done(frame); BaseType_t w = pdFALSE; xQueueSendFromISR(q, &r, &w);
}
void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_info) { (void)frame; (void)ack_info; if (ack) esp_ieee802154_receive_handle_done(ack); }
void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) { (void)frame; (void)error; }
static void usb_write_all(const uint8_t *p, size_t n) { while (n) { int w = usb_serial_jtag_write_bytes(p, n < 2048 ? n : 2048, pdMS_TO_TICKS(1000)); if (w <= 0) { vTaskDelay(1); continue; } p += w; n -= w; } }
void app_main(void)
{
    xiao_antenna_internal(); q = xQueueCreate(128, sizeof(rx_t));
    usb_serial_jtag_driver_config_t ucfg = { .tx_buffer_size = 16384, .rx_buffer_size = 256 }; ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&ucfg));
    ESP_ERROR_CHECK(esp_ieee802154_enable()); esp_ieee802154_set_channel(HOP_CHANNEL); esp_ieee802154_set_promiscuous(true); esp_ieee802154_set_rx_when_idle(true); esp_ieee802154_receive();
    rx_t r;
    while (1) {
        if (xQueueReceive(q, &r, portMAX_DELAY) != pdTRUE) continue;
        uint8_t hdr[15]; memcpy(hdr, "SNF1", 4); memcpy(hdr + 4, &r.t, 8); hdr[12] = (uint8_t)r.rssi; hdr[13] = r.lqi; hdr[14] = r.len;
        usb_write_all(hdr, sizeof hdr); usb_write_all(r.d, r.len > 127 ? 127 : r.len);
    }
}

/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* relay_main.c: the ESP32-C6 relay of spec-policy-distribution.md B10. ESP-NOW frames heard on the mesh channel go
 * to UART0 for the PEP wired to it, and the PEP's frames (its state records) go out on ESP-NOW as a broadcast. The
 * forwarding is relay.c. This file only brings up the radio and the UART. No key is in the image: the relay is
 * part of the untrusted transport (B10), and the fleet harness runs it with capability `cannot`, never as a PEP. */
#include <string.h>

#include "driver/uart.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "relay.h"

#define RELAY_UART UART_NUM_0
#define RELAY_BAUD 57600 /* the Uno's side of the link (prismpath-hw/avr/ppt_uno_dist.c) */

static const uint8_t BCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static relay link_relay;

typedef struct {
    uint8_t len;
    uint8_t data[PP_LINK_MAX];
} heard;

static QueueHandle_t radio_queue;

static void to_uart(void *context, const uint8_t *bytes, size_t len) {
    (void)context;
    uart_write_bytes(RELAY_UART, bytes, len);
}

static void to_radio(void *context, const uint8_t *bytes, size_t len) {
    (void)context;
    esp_now_send(BCAST, bytes, len);
}

/* The radio callback runs in the Wi-Fi task, so a frame is queued and written to the UART from the main task. */
static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    (void)info;
    heard h;
    if (len <= 0 || len > PP_LINK_MAX) return;
    h.len = (uint8_t)len;
    memcpy(h.data, data, (size_t)len);
    xQueueSend(radio_queue, &h, 0);
}

void app_main(void) {
    esp_err_t err = nvs_flash_init(); /* Wi-Fi needs NVS for its own calibration, never for a key */
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    esp_netif_init();
    esp_event_loop_create_default();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wc);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    esp_now_init();
    esp_now_peer_info_t peer = {0};
    memcpy(peer.peer_addr, BCAST, 6);
    peer.channel = 0;
    peer.ifidx = WIFI_IF_STA;
    esp_now_add_peer(&peer);
    uart_config_t uc = {.baud_rate = RELAY_BAUD, .data_bits = UART_DATA_8_BITS, .parity = UART_PARITY_DISABLE,
                        .stop_bits = UART_STOP_BITS_1, .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
                        .source_clk = UART_SCLK_DEFAULT};
    uart_driver_install(RELAY_UART, 2048, 2048, 0, NULL, 0);
    uart_param_config(RELAY_UART, &uc);
    radio_queue = xQueueCreate(16, sizeof(heard));
    relay_init(&link_relay, to_uart, to_radio, NULL);
    esp_now_register_recv_cb(on_recv);
    uint8_t bytes[128];
    heard h;
    for (;;) {
        while (xQueueReceive(radio_queue, &h, 0) == pdTRUE) relay_from_radio(&link_relay, h.data, h.len);
        int n = uart_read_bytes(RELAY_UART, bytes, sizeof bytes, pdMS_TO_TICKS(5));
        if (n > 0) relay_from_uart(&link_relay, bytes, (size_t)n);
    }
}

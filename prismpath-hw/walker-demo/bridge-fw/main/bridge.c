// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* bridge.c - ESP-NOW -> UART courier for the walker demo's NATIVE fabric-decode path. This ESP32 hears
 * the walker's Facet band frames over ESP-NOW (zeck [class+1, tick+1, band+1], the spiral-mesh wire)
 * and FORWARDS THE RAW FRAME BYTES over UART1 TX (115200 8N1) straight to the FPGA. It does NOT decode
 * the wire: the fabric's zeck_frame_rx recovers the frame and the band entirely in the PL, feeds the
 * interpreter, and lights the RGB LED. The MCU is a dumb wireless-to-wire courier.
 *
 * Wire it:  UART1 TX (GPIO4 = "D4") -> Arty Z7-20 Pmod JA1 (Y18);  ESP32 GND -> a JA GND pin.
 *           Keep the walker and this bridge on the same WiFi channel (both default to 1 here).
 *
 * FORWARD_RAW_FRAME 1 (default) drives the ppt_datapath_zeck overlay (fabric decodes). Set it to 0 to
 * fall back to byte-mode: decode the band here and send ONE field byte for the ppt_datapath_uart
 * overlay (MCU decodes). Frames self-delimit by the idle gap between the walker's bursts, so raw mode
 * needs no framing protocol.
 */
#define FORWARD_RAW_FRAME 1

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#if !FORWARD_RAW_FRAME
#include "zeck.h"
#endif

#define TAG            "bridge"
#define FPGA_UART      UART_NUM_1
#define FPGA_TX_GPIO   4             /* UART1 TX = "D4" -> Arty Z7-20 Pmod JA1 (Y18); D4 is on the 30-pin devkit */
#define FPGA_BAUD      115200
#define WIFI_CH        1             /* must match the walker/mesh channel */
#define LED_GPIO       2             /* onboard LED: a double-blink heartbeat marks THIS board as the bridge */

static const uint8_t BCAST[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
/* Only the WALKER's frames drive the demo. The mesh fusion node also broadcasts Facet frames on the
 * same air; without this filter the fabric would decode those too and the LED would jitter. */
static const uint8_t WALKER_MAC[6] = { 0x68, 0x09, 0x47, 0xe0, 0x38, 0x00 };

#if !FORWARD_RAW_FRAME
static const uint8_t BAND_BYTE[5] = { 13, 31, 63, 113, 163 };   /* byte-mode: = round(BAND_POT/16) */
static volatile int  s_last_band  = -1;

/* Decode up to `want` Fibonacci codes from buf (MSB-first packing, matches zeck.h's encoder). */
static int zeck_decode(const uint8_t *buf, int nbytes, uint64_t *out, int want) {
    int total = nbytes * 8, bp = 0, got = 0;
    while (got < want && bp < total) {
        uint64_t val = 0;
        uint8_t  i = 0, prev = 0;
        int      complete = 0;
        while (bp < total) {
            int bit = (buf[bp >> 3] >> (7 - (bp & 7))) & 1;
            bp++;
            if (prev && bit) { complete = 1; break; }
            if (bit) val += fib_at(i);
            prev = (uint8_t)bit;
            if (++i >= 78) break;
        }
        if (!complete) break;
        out[got++] = val;
    }
    return got;
}
#endif

/* ESP-NOW receive (ESP-IDF v5 signature). */
static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    const uint8_t *m = info->src_addr;
    if (memcmp(m, WALKER_MAC, 6) != 0) return;    /* ignore the mesh nodes; only the walker lights the LED */
#if FORWARD_RAW_FRAME
    uart_write_bytes(FPGA_UART, (const char *)data, len);   /* the FABRIC decodes the wire */
    ESP_LOGI(TAG, "%02x:%02x:%02x:%02x:%02x:%02x frame %dB -> fabric",
             m[0], m[1], m[2], m[3], m[4], m[5], len);
#else
    uint64_t code[3];
    if (zeck_decode(data, len, code, 3) < 3) return;
    if ((uint32_t)code[0] - 1u != 1u) return;              /* class 1 = band tier */
    int band = (int)code[2] - 1;
    if (band < 0) band = 0;
    if (band > 4) band = 4;
    uint8_t byte = BAND_BYTE[band];
    uart_write_bytes(FPGA_UART, (const char *)&byte, 1);
    if (band != s_last_band) {
        ESP_LOGI(TAG, "%02x:%02x:%02x:%02x:%02x:%02x band=%d -> UART 0x%02x",
                 m[0], m[1], m[2], m[3], m[4], m[5], band, byte);
        s_last_band = band;
    }
#endif
}

void app_main(void) {
    /* ---- UART1 -> FPGA ---- */
    const uart_config_t uc = {
        .baud_rate = FPGA_BAUD, .data_bits = UART_DATA_8_BITS, .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1, .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_driver_install(FPGA_UART, 256, 256, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(FPGA_UART, &uc));
    ESP_ERROR_CHECK(uart_set_pin(FPGA_UART, FPGA_TX_GPIO, UART_PIN_NO_CHANGE,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

    /* ---- onboard LED (identify this board as the bridge) ---- */
    gpio_reset_pin(LED_GPIO);
    gpio_set_direction(LED_GPIO, GPIO_MODE_OUTPUT);

    /* ---- WiFi + ESP-NOW (same default channel as the walker/mesh) ---- */
    nvs_flash_init(); esp_netif_init(); esp_event_loop_create_default();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wc); esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA); esp_wifi_start();
    esp_wifi_set_channel(WIFI_CH, WIFI_SECOND_CHAN_NONE);
    uint8_t mac[6]; esp_wifi_get_mac(WIFI_IF_STA, mac);
    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_recv_cb(on_recv));
    esp_now_peer_info_t peer = { 0 };
    memcpy(peer.peer_addr, BCAST, 6); peer.ifidx = WIFI_IF_STA; peer.encrypt = false;
    esp_now_add_peer(&peer);
    ESP_LOGI(TAG, "up mac=%02x:%02x:%02x:%02x:%02x:%02x ch=%d - UART1 TX=GPIO%d @%d 8N1 -> FPGA JA1 (%s)",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], WIFI_CH, FPGA_TX_GPIO, FPGA_BAUD,
             FORWARD_RAW_FRAME ? "raw frames, fabric decodes" : "byte-mode, MCU decodes");

    /* The walker broadcasts continuously; the fabric latches the last band, so raw mode needs no
     * heartbeat. Byte-mode re-sends the last field byte periodically so a dropped byte self-heals. */
    while (1) {
        /* distinctive double-blink heartbeat: this is how you tell the bridge from the walker/mesh nodes */
        gpio_set_level(LED_GPIO, 1); vTaskDelay(pdMS_TO_TICKS(60));
        gpio_set_level(LED_GPIO, 0); vTaskDelay(pdMS_TO_TICKS(120));
        gpio_set_level(LED_GPIO, 1); vTaskDelay(pdMS_TO_TICKS(60));
        gpio_set_level(LED_GPIO, 0); vTaskDelay(pdMS_TO_TICKS(760));
#if !FORWARD_RAW_FRAME
        int b = s_last_band;
        if (b >= 0) { uint8_t byte = BAND_BYTE[b]; uart_write_bytes(FPGA_UART, (const char *)&byte, 1); }
#endif
    }
}

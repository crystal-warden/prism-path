// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* walker.c - BNO086 walker node. Reads linear acceleration via the CEVA SH-2 driver over the
 * i2c_master driver (0x4B, SDA=21, SCL=22, INT=25 gating reads; i2c_master rides the BNO08x clock
 * stretching), maps motion magnitude to a band symbol, and broadcasts it as a Facet frame
 * [class=1(band), tick, band] over ESP-NOW - the same zeck-encoded wire the spiral mesh speaks.
 * A fixed mesh node hears it; gx10 relays the band to the FPGA interpreter, which lights an LED.
 * Carried on a battery = live wireless motion into the fabric, no wire from the sensor to the FPGA. */
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/i2c_master.h"
#include "driver/gpio.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "sh2.h"
#include "sh2_SensorValue.h"
#include "sh2_err.h"
#include "zeck.h"

#define SDA_GPIO   21
#define SCL_GPIO   22
#define INT_GPIO   GPIO_NUM_25   /* BNO08x H_INTN: active-low, asserted = packet ready */
#define I2C_HZ     400000
#define BNO_ADDR   0x4B
#define XFER_MS    100
#define TICK_MS    200

static const uint8_t BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static i2c_master_dev_handle_t s_dev;
static sh2_Hal_t s_hal;
static volatile bool s_have = false;
static float s_x, s_y, s_z;

/* ---------- SH-2 HAL over i2c_master, INT-gated ---------- */
static int hal_open(sh2_Hal_t *s) { (void)s; return 0; }
static void hal_close(sh2_Hal_t *s) { (void)s; }
static uint32_t hal_time(sh2_Hal_t *s) { (void)s; return (uint32_t)esp_timer_get_time(); }
static int hal_read(sh2_Hal_t *s, uint8_t *buf, unsigned len, uint32_t *t) {
    (void)s; *t = (uint32_t)esp_timer_get_time();
    if (gpio_get_level(INT_GPIO) != 0) return 0;                 /* no packet ready */
    uint8_t h[4];
    if (i2c_master_receive(s_dev, h, 4, XFER_MS) != ESP_OK) return 0;
    uint16_t total = ((uint16_t)h[0] | ((uint16_t)h[1] << 8)) & 0x7FFF;
    if (total == 0) return 0;
    if (total > len) total = (uint16_t)len;
    if (i2c_master_receive(s_dev, buf, total, XFER_MS) != ESP_OK) return 0;
    return (int)total;
}
static int hal_write(sh2_Hal_t *s, uint8_t *buf, unsigned len) {
    (void)s;
    return i2c_master_transmit(s_dev, buf, len, XFER_MS) == ESP_OK ? (int)len : 0;
}
static void on_event(void *c, sh2_AsyncEvent_t *e) { (void)c; (void)e; }
static void on_sensor(void *c, sh2_SensorEvent_t *ev) {
    (void)c;
    sh2_SensorValue_t v;
    if (sh2_decodeSensorEvent(&v, ev) != SH2_OK) return;
    if (v.sensorId == SH2_LINEAR_ACCELERATION) {
        s_x = v.un.linearAcceleration.x; s_y = v.un.linearAcceleration.y; s_z = v.un.linearAcceleration.z;
        s_have = true;
    }
}
static int enable(sh2_SensorId_t id, uint32_t us) {
    sh2_SensorConfig_t c; memset(&c, 0, sizeof(c)); c.reportInterval_us = us;
    return sh2_setSensorConfig(id, &c);
}

/* ---------- motion magnitude (m/s^2, gravity removed) -> band symbol ---------- */
static uint32_t band_of(float mag) {
    if (mag < 0.30f) return 0;   /* still    */
    if (mag < 1.00f) return 1;   /* light    */
    if (mag < 3.00f) return 2;   /* move     */
    if (mag < 8.00f) return 3;   /* brisk    */
    return 4;                     /* vigorous */
}

/* ---------- Facet frame: zeck [class+1, tick+1, band+1] over ESP-NOW broadcast (binding v1) -------- */
static uint8_t s_tx[32];
static void tx_band(uint32_t tick, uint32_t band) {
    bitacc_t a = { s_tx, 0 };
    memset(s_tx, 0, sizeof(s_tx));
    zeck_encode(&a, 1u + 1u);          /* class 1 = band tier */
    zeck_encode(&a, tick + 1u);
    zeck_encode(&a, band + 1u);
    uint8_t n = (uint8_t)((a.bitpos + 7u) / 8u);
    esp_now_send(BCAST, s_tx, n);
}

void app_main(void) {
    /* ---- I2C + INT ---- */
    i2c_master_bus_config_t bc = { .clk_source = I2C_CLK_SRC_DEFAULT, .i2c_port = -1,
        .sda_io_num = SDA_GPIO, .scl_io_num = SCL_GPIO, .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true };
    i2c_master_bus_handle_t bus; ESP_ERROR_CHECK(i2c_new_master_bus(&bc, &bus));
    i2c_device_config_t dc = { .dev_addr_length = I2C_ADDR_BIT_LEN_7, .device_address = BNO_ADDR,
        .scl_speed_hz = I2C_HZ };
    ESP_ERROR_CHECK(i2c_master_bus_add_device(bus, &dc, &s_dev));
    gpio_config_t io = { .pin_bit_mask = 1ULL << INT_GPIO, .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE, .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE };
    gpio_config(&io);
    vTaskDelay(pdMS_TO_TICKS(100));

    /* ---- BNO08x via SH-2 ---- */
    s_hal.open = hal_open; s_hal.close = hal_close; s_hal.read = hal_read;
    s_hal.write = hal_write; s_hal.getTimeUs = hal_time;
    int rc = sh2_open(&s_hal, on_event, NULL);
    printf("[walker] sh2_open rc=%d %s\n", rc, rc == SH2_OK ? "OK" : "FAIL");
    sh2_setSensorCallback(on_sensor, NULL);
    for (int i = 0; i < 50; i++) { sh2_service(); vTaskDelay(pdMS_TO_TICKS(10)); }
    rc = enable(SH2_LINEAR_ACCELERATION, 50000);
    printf("[walker] enable linaccel rc=%d %s\n", rc, rc == SH2_OK ? "OK" : "FAIL");

    /* ---- WiFi + ESP-NOW (same default channel as the mesh) ---- */
    nvs_flash_init(); esp_netif_init(); esp_event_loop_create_default();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wc); esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA); esp_wifi_start();
    uint8_t mac[6]; esp_wifi_get_mac(WIFI_IF_STA, mac);
    esp_now_init();
    esp_now_peer_info_t peer = { 0 };
    memcpy(peer.peer_addr, BCAST, 6); peer.ifidx = WIFI_IF_STA; peer.encrypt = false;
    esp_now_add_peer(&peer);
    printf("[walker] ESP-NOW up mac=%02x:%02x:%02x:%02x:%02x:%02x - broadcasting band frames @%dms\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], TICK_MS);

    /* ---- loop: motion -> band -> broadcast ---- */
    uint32_t last = 0, tick = 0;
    while (1) {
        sh2_service();
        vTaskDelay(pdMS_TO_TICKS(5));
        uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
        if (now - last >= TICK_MS) {
            last = now;
            float mag = s_have ? sqrtf(s_x * s_x + s_y * s_y + s_z * s_z) : 0.0f;
            uint32_t band = band_of(mag);
            tx_band(tick, band);
            printf("[walker] TX tick=%lu |a|=%.2f band=%lu\n",
                   (unsigned long)tick, mag, (unsigned long)band);
            tick++;
        }
    }
}

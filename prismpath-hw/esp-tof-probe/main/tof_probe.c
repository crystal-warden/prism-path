/* tof_probe.c — throwaway ESP-IDF probe: I2C bus scan + VL53L0X ID check + live ranging on GPIO21/22.
 * Used to verify the three ToF sensors are wired to the three mesh ESP32s before folding the driver
 * into ppt_mesh.c. The VL53L0X init/ranging logic is a straight port of prismpath-hw/rp2350/vl53l0x.c
 * (Pololu-derived); only the six I2C helpers are rewritten for ESP-IDF's i2c driver. */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/i2c.h"
#include "esp_timer.h"

#define SDA_GPIO   21
#define SCL_GPIO   22
#define I2C_PORT   I2C_NUM_0
#define I2C_HZ     100000
#define TOF_ADDR   0x29
#define TO_TICKS   pdMS_TO_TICKS(100)

/* register addresses used (same as the Pico driver) */
#define SYSRANGE_START                              0x00
#define SYSTEM_SEQUENCE_CONFIG                       0x01
#define SYSTEM_INTERRUPT_CONFIG_GPIO                 0x0A
#define SYSTEM_INTERRUPT_CLEAR                       0x0B
#define RESULT_INTERRUPT_STATUS                      0x13
#define RESULT_RANGE_STATUS                          0x14
#define MSRC_CONFIG_CONTROL                          0x60
#define FINAL_RANGE_CONFIG_MIN_COUNT_RATE_RTN_LIMIT  0x44
#define GPIO_HV_MUX_ACTIVE_HIGH                      0x84
#define DYNAMIC_SPAD_NUM_REQUESTED_REF_SPAD          0x4E
#define DYNAMIC_SPAD_REF_EN_START_OFFSET             0x4F
#define GLOBAL_CONFIG_SPAD_ENABLES_REF_0             0xB0
#define GLOBAL_CONFIG_REF_EN_START_SELECT            0xB6
#define VHV_CONFIG_PAD_SCL_SDA__EXTSUP_HV            0x89

typedef struct { uint8_t addr; int io_timeout_ms; uint8_t stop_variable; bool did_timeout; } vl53l0x_t;

/* ---------------------------------------------------------------- I2C helpers (ESP-IDF) */
static void wr8(vl53l0x_t *s, uint8_t reg, uint8_t val) {
    uint8_t b[2] = {reg, val};
    i2c_master_write_to_device(I2C_PORT, s->addr, b, 2, TO_TICKS);
}
static uint8_t rd8(vl53l0x_t *s, uint8_t reg) {
    uint8_t v = 0;
    i2c_master_write_read_device(I2C_PORT, s->addr, &reg, 1, &v, 1, TO_TICKS);
    return v;
}
static void wr16(vl53l0x_t *s, uint8_t reg, uint16_t val) {
    uint8_t b[3] = {reg, (uint8_t)(val >> 8), (uint8_t)(val & 0xFF)};
    i2c_master_write_to_device(I2C_PORT, s->addr, b, 3, TO_TICKS);
}
static uint16_t rd16(vl53l0x_t *s, uint8_t reg) {
    uint8_t v[2] = {0, 0};
    i2c_master_write_read_device(I2C_PORT, s->addr, &reg, 1, v, 2, TO_TICKS);
    return ((uint16_t)v[0] << 8) | v[1];
}
static void wr_multi(vl53l0x_t *s, uint8_t reg, const uint8_t *src, uint8_t n) {
    uint8_t b[16];
    b[0] = reg;
    memcpy(b + 1, src, n);
    i2c_master_write_to_device(I2C_PORT, s->addr, b, n + 1, TO_TICKS);
}
static void rd_multi(vl53l0x_t *s, uint8_t reg, uint8_t *dst, uint8_t n) {
    i2c_master_write_read_device(I2C_PORT, s->addr, &reg, 1, dst, n, TO_TICKS);
}

/* ---------------------------------------------------------------- timeout (esp_timer) */
static int64_t s_deadline_us;
static void start_timeout(vl53l0x_t *s) { s_deadline_us = esp_timer_get_time() + (int64_t)s->io_timeout_ms * 1000; }
static bool timed_out(void) { return esp_timer_get_time() > s_deadline_us; }

/* ---------------------------------------------------------------- SPAD info */
static bool get_spad_info(vl53l0x_t *s, uint8_t *count, bool *type_is_aperture) {
    wr8(s, 0x80, 0x01); wr8(s, 0xFF, 0x01); wr8(s, 0x00, 0x00);
    wr8(s, 0xFF, 0x06);
    wr8(s, 0x83, rd8(s, 0x83) | 0x04);
    wr8(s, 0xFF, 0x07); wr8(s, 0x81, 0x01); wr8(s, 0x80, 0x01);
    wr8(s, 0x94, 0x6b); wr8(s, 0x83, 0x00);
    start_timeout(s);
    while (rd8(s, 0x83) == 0x00) { if (timed_out()) {
        printf("[tof-probe]   init: get_spad_info timed out — reg 0x83 stuck at 0 (SPAD/oscillator not starting)\n");
        return false; } }
    wr8(s, 0x83, 0x01);
    uint8_t tmp = rd8(s, 0x92);
    *count = tmp & 0x7f;
    *type_is_aperture = (tmp >> 7) & 0x01;
    wr8(s, 0x81, 0x00); wr8(s, 0xFF, 0x06);
    wr8(s, 0x83, rd8(s, 0x83) & ~0x04);
    wr8(s, 0xFF, 0x01); wr8(s, 0x00, 0x01); wr8(s, 0xFF, 0x00); wr8(s, 0x80, 0x00);
    return true;
}

static bool ref_calibration(vl53l0x_t *s, uint8_t vhv_init_byte) {
    wr8(s, SYSRANGE_START, 0x01 | vhv_init_byte);
    start_timeout(s);
    while ((rd8(s, RESULT_INTERRUPT_STATUS) & 0x07) == 0) { if (timed_out()) return false; }
    wr8(s, SYSTEM_INTERRUPT_CLEAR, 0x01);
    wr8(s, SYSRANGE_START, 0x00);
    return true;
}

/* ---------------------------------------------------------------- init */
static bool vl53l0x_init(vl53l0x_t *s, uint8_t addr) {
    s->addr = addr; s->io_timeout_ms = 500; s->did_timeout = false;
    if (rd8(s, 0xC0) != 0xEE) return false;                 /* model id sanity */

    wr8(s, VHV_CONFIG_PAD_SCL_SDA__EXTSUP_HV, rd8(s, VHV_CONFIG_PAD_SCL_SDA__EXTSUP_HV) | 0x01);
    wr8(s, 0x88, 0x00); wr8(s, 0x80, 0x01); wr8(s, 0xFF, 0x01); wr8(s, 0x00, 0x00);
    s->stop_variable = rd8(s, 0x91);
    wr8(s, 0x00, 0x01); wr8(s, 0xFF, 0x00); wr8(s, 0x80, 0x00);
    wr8(s, MSRC_CONFIG_CONTROL, rd8(s, MSRC_CONFIG_CONTROL) | 0x12);
    wr16(s, FINAL_RANGE_CONFIG_MIN_COUNT_RATE_RTN_LIMIT, (uint16_t)(0.25 * (1 << 7)));
    wr8(s, SYSTEM_SEQUENCE_CONFIG, 0xFF);

    uint8_t spad_count; bool spad_type_is_aperture;
    if (!get_spad_info(s, &spad_count, &spad_type_is_aperture)) { printf("[tof-probe]   init: FAILED at get_spad_info\n"); return false; }
    printf("[tof-probe]   init: SPAD count=%u aperture=%d (sane count is 1..44)\n", spad_count, spad_type_is_aperture);
    uint8_t ref_spad_map[6];
    rd_multi(s, GLOBAL_CONFIG_SPAD_ENABLES_REF_0, ref_spad_map, 6);
    wr8(s, 0xFF, 0x01); wr8(s, DYNAMIC_SPAD_REF_EN_START_OFFSET, 0x00);
    wr8(s, DYNAMIC_SPAD_NUM_REQUESTED_REF_SPAD, 0x2C);
    wr8(s, 0xFF, 0x00); wr8(s, GLOBAL_CONFIG_REF_EN_START_SELECT, 0xB4);
    uint8_t first_spad = spad_type_is_aperture ? 12 : 0, enabled = 0;
    for (uint8_t i = 0; i < 48; i++) {
        if (i < first_spad || enabled == spad_count) ref_spad_map[i / 8] &= ~(1 << (i % 8));
        else if ((ref_spad_map[i / 8] >> (i % 8)) & 0x1) enabled++;
    }
    wr_multi(s, GLOBAL_CONFIG_SPAD_ENABLES_REF_0, ref_spad_map, 6);

    static const uint8_t tuning[] = {
        0xFF,0x01, 0x00,0x00, 0xFF,0x00, 0x09,0x00, 0x10,0x00, 0x11,0x00, 0x24,0x01, 0x25,0xFF,
        0x75,0x00, 0xFF,0x01, 0x4E,0x2C, 0x48,0x00, 0x30,0x20, 0xFF,0x00, 0x30,0x09, 0x54,0x00,
        0x31,0x04, 0x32,0x03, 0x40,0x83, 0x46,0x25, 0x60,0x00, 0x27,0x00, 0x50,0x06, 0x51,0x00,
        0x52,0x96, 0x56,0x08, 0x57,0x30, 0x61,0x00, 0x62,0x00, 0x64,0x00, 0x65,0x00, 0x66,0xA0,
        0xFF,0x01, 0x22,0x32, 0x47,0x14, 0x49,0xFF, 0x4A,0x00, 0xFF,0x00, 0x7A,0x0A, 0x7B,0x00,
        0x78,0x21, 0xFF,0x01, 0x23,0x34, 0x42,0x00, 0x44,0xFF, 0x45,0x26, 0x46,0x05, 0x40,0x40,
        0x0E,0x06, 0x20,0x1A, 0x43,0x40, 0xFF,0x00, 0x34,0x03, 0x35,0x44, 0xFF,0x01, 0x31,0x04,
        0x4B,0x09, 0x4C,0x05, 0x4D,0x04, 0xFF,0x00, 0x44,0x00, 0x45,0x20, 0x47,0x08, 0x48,0x28,
        0x67,0x00, 0x70,0x04, 0x71,0x01, 0x72,0xFE, 0x76,0x00, 0x77,0x00, 0xFF,0x01, 0x0D,0x01,
        0xFF,0x00, 0x80,0x01, 0x01,0xF8, 0xFF,0x01, 0x8E,0x01, 0x00,0x01, 0xFF,0x00, 0x80,0x00,
    };
    for (size_t i = 0; i < sizeof(tuning); i += 2) wr8(s, tuning[i], tuning[i + 1]);

    wr8(s, SYSTEM_INTERRUPT_CONFIG_GPIO, 0x04);
    wr8(s, GPIO_HV_MUX_ACTIVE_HIGH, rd8(s, GPIO_HV_MUX_ACTIVE_HIGH) & ~0x10);
    wr8(s, SYSTEM_INTERRUPT_CLEAR, 0x01);

    wr8(s, SYSTEM_SEQUENCE_CONFIG, 0x01); if (!ref_calibration(s, 0x40)) { printf("[tof-probe]   init: FAILED at VHV ref_calibration\n"); return false; }
    wr8(s, SYSTEM_SEQUENCE_CONFIG, 0x02); if (!ref_calibration(s, 0x00)) { printf("[tof-probe]   init: FAILED at phase ref_calibration\n"); return false; }
    wr8(s, SYSTEM_SEQUENCE_CONFIG, 0xE8);
    return true;
}

static uint16_t read_range_single(vl53l0x_t *s) {
    wr8(s, 0x80, 0x01); wr8(s, 0xFF, 0x01); wr8(s, 0x00, 0x00);
    wr8(s, 0x91, s->stop_variable);
    wr8(s, 0x00, 0x01); wr8(s, 0xFF, 0x00); wr8(s, 0x80, 0x00);
    wr8(s, SYSRANGE_START, 0x01);
    start_timeout(s);
    while (rd8(s, SYSRANGE_START) & 0x01) { if (timed_out()) { s->did_timeout = true; return 65535; } }
    start_timeout(s);
    while ((rd8(s, RESULT_INTERRUPT_STATUS) & 0x07) == 0) { if (timed_out()) { s->did_timeout = true; return 65535; } }
    uint16_t range = rd16(s, RESULT_RANGE_STATUS + 10);
    wr8(s, SYSTEM_INTERRUPT_CLEAR, 0x01);
    return range;
}

/* ---------------------------------------------------------------- bus scan */
static bool i2c_probe(uint8_t addr) {
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (addr << 1) | I2C_MASTER_WRITE, true);
    i2c_master_stop(cmd);
    esp_err_t r = i2c_master_cmd_begin(I2C_PORT, cmd, pdMS_TO_TICKS(50));
    i2c_cmd_link_delete(cmd);
    return r == ESP_OK;
}

static const char *band(uint16_t mm) {
    if (mm >= 8000) return "far/none";
    if (mm < 100)   return "CONTACT";
    if (mm < 300)   return "near";
    if (mm < 800)   return "mid";
    return "far";
}

void app_main(void) {
    i2c_config_t conf = {
        .mode = I2C_MODE_MASTER, .sda_io_num = SDA_GPIO, .scl_io_num = SCL_GPIO,
        .sda_pullup_en = GPIO_PULLUP_ENABLE, .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = I2C_HZ,
    };
    i2c_param_config(I2C_PORT, &conf);
    i2c_driver_install(I2C_PORT, I2C_MODE_MASTER, 0, 0, 0);
    vTaskDelay(pdMS_TO_TICKS(100));

    printf("\n[tof-probe] I2C on SDA=GPIO%d SCL=GPIO%d @ %d Hz — scanning...\n", SDA_GPIO, SCL_GPIO, I2C_HZ);
    int found = 0;
    for (uint8_t a = 1; a < 0x78; a++) {
        if (i2c_probe(a)) { printf("[tof-probe]   device at 0x%02X%s\n", a, a == TOF_ADDR ? "  <- VL53L0X" : ""); found++; }
    }
    if (found == 0) { printf("[tof-probe] NO I2C DEVICES — check SDA/SCL/3V3/GND wiring\n"); }

    vl53l0x_t s;
    if (!i2c_probe(TOF_ADDR)) {
        printf("[tof-probe] RESULT: FAIL — nothing answers at 0x29. Sensor not wired/powered.\n");
        while (1) vTaskDelay(pdMS_TO_TICKS(1000));
    }
    uint8_t model = 0;
    { uint8_t reg = 0xC0; i2c_master_write_read_device(I2C_PORT, TOF_ADDR, &reg, 1, &model, 1, TO_TICKS); }
    printf("[tof-probe] 0x29 model id = 0x%02X (expect 0xEE)\n", model);

    if (!vl53l0x_init(&s, TOF_ADDR)) {
        printf("[tof-probe] RESULT: sensor answered but init FAILED (model=0x%02X)\n", model);
        while (1) vTaskDelay(pdMS_TO_TICKS(1000));
    }
    printf("[tof-probe] RESULT: OK — VL53L0X initialized. Streaming distance (wave a hand):\n");
    while (1) {
        uint16_t mm = read_range_single(&s);
        printf("[tof-probe] dist=%5u mm  band=%s\n", mm, band(mm));
        vTaskDelay(pdMS_TO_TICKS(250));
    }
}
